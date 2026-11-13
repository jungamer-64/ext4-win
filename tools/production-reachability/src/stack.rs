//! Kernel-stack budget of expanded-stack executor callouts.
//!
//! Every `KeExpandKernelStackAndCalloutEx` call must name a module-defined callout and a constant
//! size. The deepest chain of fixed Rust frames reachable from that callout, each with its return
//! address, must leave [`FOREIGN_CALLOUT_RESERVE`] bytes for everything outside the Rust module:
//! kernel routines, lower drivers and filters, native boundary objects and interrupts. The reactor
//! executor must run inside such a callout.
//!
//! Frames come from the signed image's unwind records; edges come from the release IR. Direct
//! calls are exact. A call through a value loaded from a trait-object vtable (rustc marks those
//! loads `!invariant.load`) resolves to the functions stored at that vtable offset with the call's
//! signature; any other indirect call conservatively reaches every address-taken function of its
//! signature. Tail calls are counted as ordinary calls. A cycle has no bound and is rejected.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::fmt;

use super::{
    Function, FunctionSignature, GateError, GateResult, IndirectCall, IrModule, Violation,
    parse_call_site, split_top_level, symbol_references,
};

/// Kernel routine that runs a callout on a stack of at least the requested size.
const STACK_EXPANSION_ROUTINE: &str = "KeExpandKernelStackAndCalloutEx";

/// Stack left for foreign code below the deepest Rust frame: one standard AMD64 kernel stack
/// (`KERNEL_STACK_SIZE`), the capacity any kernel routine or lower driver may assume on an
/// ordinary system thread.
const FOREIGN_CALLOUT_RESERVE: u64 = 24_576;

/// Return address pushed by every AMD64 call in addition to the callee's fixed frame.
const RETURN_ADDRESS_BYTES: u64 = 8;

/// The executor whose operation turns require an expanded stack.
const REACTOR_EXECUTOR: &str = "<ext4win::irp::reactor::CompletionReactor>::run";

/// Fixed prolog frames of the signed image, addressed by linked symbol.
#[derive(Debug)]
pub(crate) struct LinkedFrames {
    /// Runtime-function frames decoded from the image.
    table: pe_unwind::FrameTable,
    /// Image-relative address of each linked symbol; `None` when the map names it twice.
    symbols: BTreeMap<String, Option<u64>>,
}

impl LinkedFrames {
    /// Binds link-map symbols to the unwind records of the image they describe.
    ///
    /// # Errors
    ///
    /// Returns an artifact error when the image's runtime-function table cannot be decoded or a
    /// map address is not hexadecimal.
    pub(crate) fn parse(map: &str, image: &[u8]) -> GateResult<Self> {
        let table = pe_unwind::decode(image).map_err(|error| {
            GateError::InvalidArtifact(format!("signed driver unwind records: {error}"))
        })?;
        let mut symbols = BTreeMap::<String, Option<u64>>::new();
        for line in map.lines() {
            let mut fields = line.split_whitespace();
            if !fields.next().is_some_and(|value| value.contains(':')) {
                continue;
            }
            let (Some(name), Some(address)) = (fields.next(), fields.next()) else {
                continue;
            };
            if address.len() != 16 || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                continue;
            }
            let absolute = u64::from_str_radix(address, 16).map_err(|error| {
                GateError::InvalidArtifact(format!("link-map address {address}: {error}"))
            })?;
            // Absolute linker symbols such as `__AbsoluteZero` are not image locations.
            let Some(rva) = absolute.checked_sub(table.image_base) else {
                continue;
            };
            symbols
                .entry(name.to_owned())
                .and_modify(|known| {
                    if *known != Some(rva) {
                        *known = None;
                    }
                })
                .or_insert(Some(rva));
        }
        Ok(Self { table, symbols })
    }

    /// Returns the fixed frame of one linked function; a leaf without a prolog has none.
    ///
    /// # Errors
    ///
    /// Returns why the symbol has no unique function entry in the image.
    fn fixed_bytes(&self, symbol: &str) -> Result<u64, String> {
        match self.symbols.get(symbol.trim_matches('"')) {
            None => Err("absent from the link map".to_owned()),
            Some(None) => Err("linked at several addresses".to_owned()),
            Some(Some(rva)) => match self.table.entry(*rva) {
                Ok(Some(frame)) => Ok(frame.fixed_bytes),
                Ok(None) => Ok(0),
                Err(error) => Err(error.to_string()),
            },
        }
    }
}

/// Stack measured for one expanded-stack callout.
#[derive(Debug)]
pub(crate) struct ExpandedStack {
    /// Display name of the callout.
    callout: String,
    /// Stack bytes the expansion call guarantees.
    reserved: u64,
    /// Deepest chain of fixed Rust frames and return addresses.
    depth: u64,
}

impl fmt::Display for ExpandedStack {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "expanded stack {}: {} of {} bytes; foreign callout reserve {}",
            self.callout, self.depth, self.reserved, FOREIGN_CALLOUT_RESERVE
        )
    }
}

/// One call to the expansion routine with its constant contract.
#[derive(Debug)]
struct ExpansionSite {
    /// Module-defined callout symbol.
    callout: String,
    /// Requested stack bytes.
    reserved: u64,
}

/// A reachable fact that leaves the stack unbounded.
#[derive(Debug)]
struct StackFailure {
    /// Stable report category.
    category: &'static str,
    /// The failing fact, from its function inward.
    path: Vec<String>,
    /// Callers through which the failing function was reached, innermost first.
    callers: Vec<String>,
}

impl StackFailure {
    /// A failure observed inside one function before any caller is attached.
    fn new(category: &'static str, path: Vec<String>) -> Self {
        Self {
            category,
            path,
            callers: Vec::new(),
        }
    }

    /// The complete path from the outermost caller to the failing fact.
    fn into_path(self) -> Vec<String> {
        let mut path: Vec<String> = self.callers.into_iter().rev().collect();
        path.extend(self.path);
        path
    }
}

/// Memoized longest frame chain below one function entry.
#[derive(Clone, Debug)]
struct Depth {
    /// Bytes from this function's entry to the deepest Rust frame, including return addresses.
    bytes: u64,
    /// Callee continuing the deepest chain.
    next: Option<String>,
}

/// Longest-path traversal over the stack call graph.
struct StackWalk<'module> {
    /// Analyzed module.
    module: &'module IrModule,
    /// Linked frame sizes.
    frames: &'module LinkedFrames,
    /// Conservative targets of indirect calls that are not vtable dispatches.
    signatures: BTreeMap<FunctionSignature, Vec<String>>,
    /// Completed functions.
    memo: BTreeMap<String, Depth>,
    /// Functions on the current traversal path, in call order.
    active: Vec<String>,
}

impl IrModule {
    /// Measures every expanded-stack callout and reports budget, recursion and coverage failures.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when a call graph symbol cannot be resolved.
    pub(crate) fn audit_expanded_stacks(
        &self,
        frames: &LinkedFrames,
        violations: &mut Vec<Violation>,
    ) -> GateResult<Vec<ExpandedStack>> {
        let sites = self.expansion_sites(violations)?;
        let mut walk = StackWalk {
            module: self,
            frames,
            signatures: self.address_taken_by_signature(),
            memo: BTreeMap::new(),
            active: Vec::new(),
        };
        let mut measured = Vec::new();
        let mut executor_expanded = false;
        for site in sites {
            let depth = match walk.depth(&site.callout) {
                Ok(depth) => depth,
                Err(failure) => {
                    violations.push(Violation {
                        category: failure.category,
                        path: failure.into_path(),
                    });
                    continue;
                }
            };
            executor_expanded |= walk.reaches(&site.callout, REACTOR_EXECUTOR)?;
            let display = self.display(&site.callout);
            if depth
                .checked_add(FOREIGN_CALLOUT_RESERVE)
                .is_none_or(|required| required > site.reserved)
            {
                let mut path = walk.deepest_chain(&site.callout);
                path.push(format!(
                    "{depth} bytes of Rust frames + {FOREIGN_CALLOUT_RESERVE} reserved exceed {} expanded",
                    site.reserved
                ));
                violations.push(Violation {
                    category: "expanded stack budget",
                    path,
                });
            }
            measured.push(ExpandedStack {
                callout: display,
                reserved: site.reserved,
                depth,
            });
        }
        if !executor_expanded {
            violations.push(Violation {
                category: "executor outside expanded stack",
                path: vec![REACTOR_EXECUTOR.to_owned()],
            });
        }
        Ok(measured)
    }

    /// Collects each expansion call with a module-defined callout and constant size.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when a symbol boundary cannot be decoded.
    fn expansion_sites(&self, violations: &mut Vec<Violation>) -> GateResult<Vec<ExpansionSite>> {
        let mut sites = Vec::new();
        for function in self.functions.values() {
            for instruction in &function.body {
                let Some(call) = parse_call_site(instruction) else {
                    continue;
                };
                let Some(target) = call.direct_target.as_deref() else {
                    continue;
                };
                if self.function_reference(target)?.as_deref() != Some(STACK_EXPANSION_ROUTINE) {
                    continue;
                }
                let callout = match call.arguments.first() {
                    Some(argument) => match symbol_references(argument)?.first() {
                        Some(symbol) => self
                            .function_reference(symbol)?
                            .filter(|symbol| self.functions.get(symbol).is_some_and(|f| f.defined)),
                        None => None,
                    },
                    None => None,
                };
                let reserved = call
                    .arguments
                    .get(2)
                    .and_then(|argument| argument.split_whitespace().last())
                    .and_then(|size| size.parse::<u64>().ok());
                match (callout, reserved) {
                    (Some(callout), Some(reserved)) => {
                        sites.push(ExpansionSite { callout, reserved })
                    }
                    _ => violations.push(Violation {
                        category: "unbounded expanded stack",
                        path: vec![function.display.clone(), instruction.clone()],
                    }),
                }
            }
        }
        Ok(sites)
    }

    /// Returns the display name of a function symbol.
    fn display(&self, symbol: &str) -> String {
        self.functions
            .get(symbol)
            .map_or_else(|| symbol.to_owned(), |function| function.display.clone())
    }

    /// Resolves the module-defined callees one function can reach with a new frame.
    ///
    /// # Errors
    ///
    /// Returns a failure for an indirect call with no target, or an invalid alias.
    fn stack_callees(
        &self,
        function: &Function,
        signatures: &BTreeMap<FunctionSignature, Vec<String>>,
    ) -> Result<BTreeSet<String>, StackFailure> {
        let defined = |symbol: &String| self.functions.get(symbol).is_some_and(|f| f.defined);
        let mut callees: BTreeSet<String> = function
            .direct_calls
            .iter()
            .filter(|callee| defined(callee))
            .cloned()
            .collect();
        if function.indirect_calls.is_empty() {
            return Ok(callees);
        }
        let definitions = ssa_definitions(&function.body);
        for call in &function.indirect_calls {
            let targets = match vtable_offsets(&definitions, &call.callee, &mut BTreeSet::new()) {
                Some(offsets) => self.vtable_targets(&offsets, call)?,
                None => signatures
                    .get(&call.signature)
                    .map(|candidates| candidates.iter().filter(|c| defined(c)).cloned().collect())
                    .unwrap_or_default(),
            };
            if targets.is_empty() {
                return Err(StackFailure::new(
                    "unresolved stack edge",
                    vec![
                        function.display.clone(),
                        format!(
                            "indirect call at LLVM IR line {} [{}]",
                            call.line, call.signature
                        ),
                    ],
                ));
            }
            callees.extend(targets);
        }
        Ok(callees)
    }

    /// Functions stored at the given vtable offsets with the call's signature.
    ///
    /// # Errors
    ///
    /// Returns a failure for a cyclic alias among vtable entries.
    fn vtable_targets(
        &self,
        offsets: &BTreeSet<u64>,
        call: &IndirectCall,
    ) -> Result<BTreeSet<String>, StackFailure> {
        let mut targets = BTreeSet::new();
        for offset in offsets {
            for entry in self.vtable_slots.get(offset).into_iter().flatten() {
                let resolved = self.function_reference(entry).map_err(|error| {
                    StackFailure::new(
                        "unresolved stack edge",
                        vec![format!("vtable entry {entry}: {error}")],
                    )
                })?;
                if let Some(symbol) = resolved
                    && self.functions.get(&symbol).is_some_and(|function| {
                        function.defined && function.signature == call.signature
                    })
                {
                    targets.insert(symbol);
                }
            }
        }
        Ok(targets)
    }
}

impl StackWalk<'_> {
    /// Returns the deepest chain of frames from `symbol`'s entry.
    ///
    /// # Errors
    ///
    /// Returns a failure for recursion, an unlinked frame, or an unresolved indirect call.
    fn depth(&mut self, symbol: &str) -> Result<u64, StackFailure> {
        if let Some(depth) = self.memo.get(symbol) {
            return Ok(depth.bytes);
        }
        if let Some(start) = self.active.iter().position(|active| active == symbol) {
            let mut path: Vec<String> = self
                .active
                .get(start..)
                .unwrap_or_default()
                .iter()
                .map(|active| self.module.display(active))
                .collect();
            path.push(self.module.display(symbol));
            return Err(StackFailure::new("recursive stack growth", path));
        }
        let function = self.module.functions.get(symbol).ok_or_else(|| {
            StackFailure::new(
                "unresolved stack edge",
                vec![format!("{symbol} is not a module function")],
            )
        })?;
        let frame = self.frames.fixed_bytes(symbol).map_err(|reason| {
            StackFailure::new(
                "unlinked stack frame",
                vec![function.display.clone(), reason],
            )
        })?;
        let callees = self.module.stack_callees(function, &self.signatures)?;
        self.active.push(symbol.to_owned());
        let mut deepest = Depth {
            bytes: 0,
            next: None,
        };
        for callee in &callees {
            match self.depth(callee) {
                Ok(bytes) if bytes > deepest.bytes => {
                    deepest = Depth {
                        bytes,
                        next: Some(callee.clone()),
                    };
                }
                Ok(_) => {}
                Err(mut failure) => {
                    self.active.pop();
                    if failure.category != "recursive stack growth" {
                        failure.callers.push(function.display.clone());
                    }
                    return Err(failure);
                }
            }
        }
        self.active.pop();
        let bytes = frame
            .checked_add(RETURN_ADDRESS_BYTES)
            .and_then(|own| own.checked_add(deepest.bytes))
            .ok_or_else(|| {
                StackFailure::new(
                    "recursive stack growth",
                    vec![function.display.clone(), "frame sum overflows".to_owned()],
                )
            })?;
        self.memo.insert(
            symbol.to_owned(),
            Depth {
                bytes,
                next: deepest.next,
            },
        );
        Ok(bytes)
    }

    /// The memoized deepest chain below `symbol`, with each function's own bytes.
    fn deepest_chain(&self, symbol: &str) -> Vec<String> {
        let mut path = Vec::new();
        let mut current = Some(symbol.to_owned());
        while let Some(symbol) = current {
            let Some(depth) = self.memo.get(&symbol) else {
                break;
            };
            let below = depth
                .next
                .as_ref()
                .and_then(|next| self.memo.get(next))
                .map_or(0, |next| next.bytes);
            path.push(format!(
                "{} [{} B]",
                self.module.display(&symbol),
                depth.bytes.saturating_sub(below)
            ));
            current = depth.next.clone();
        }
        path
    }

    /// Whether a function with display name `display` is reachable from `root` on its stack.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when an already-measured edge can no longer be resolved.
    fn reaches(&self, root: &str, display: &str) -> GateResult<bool> {
        let mut seen = BTreeSet::from([root.to_owned()]);
        let mut pending = vec![root.to_owned()];
        while let Some(symbol) = pending.pop() {
            let Some(function) = self.module.functions.get(&symbol) else {
                continue;
            };
            if function.display == display {
                return Ok(true);
            }
            let callees = self
                .module
                .stack_callees(function, &self.signatures)
                .map_err(|failure| GateError::InvalidIr(failure.into_path().join(" -> ")))?;
            for callee in callees {
                if seen.insert(callee.clone()) {
                    pending.push(callee);
                }
            }
        }
        Ok(false)
    }
}

/// Maps each SSA value name, without its sigil, to its defining instruction.
fn ssa_definitions(body: &[String]) -> BTreeMap<&str, &str> {
    body.iter()
        .filter_map(|instruction| {
            let (name, definition) = instruction.strip_prefix('%')?.split_once(" = ")?;
            Some((name, definition))
        })
        .collect()
}

/// Recovers the vtable offsets a callee value is loaded from, when it is a vtable dispatch.
///
/// Returns `None` unless every source of the value is an `!invariant.load` of a vtable slot.
fn vtable_offsets(
    definitions: &BTreeMap<&str, &str>,
    value: &str,
    visiting: &mut BTreeSet<String>,
) -> Option<BTreeSet<u64>> {
    if !visiting.insert(value.to_owned()) {
        return Some(BTreeSet::new());
    }
    let definition = *definitions.get(value)?;
    if let Some(operand) = definition.strip_prefix("load ptr, ptr %") {
        if !definition.contains("!invariant.load") {
            return None;
        }
        let pointer = operand.split([',', ' ']).next()?;
        return match definitions.get(pointer) {
            Some(source) if source.starts_with("getelementptr") => {
                Some(BTreeSet::from([byte_offset(source)?]))
            }
            _ => Some(BTreeSet::from([0])),
        };
    }
    let incoming: Vec<&str> = if let Some(arms) = definition.strip_prefix("phi ptr ") {
        split_top_level(arms, ',')
            .into_iter()
            .map(|arm| {
                arm.trim()
                    .trim_start_matches('[')
                    .split(',')
                    .next()
                    .unwrap_or_default()
                    .trim()
            })
            .collect()
    } else {
        split_top_level(definition.strip_prefix("select ")?, ',')
            .into_iter()
            .skip(1)
            .map(|arm| arm.trim().trim_start_matches("ptr ").trim())
            .collect()
    };
    let mut offsets = BTreeSet::new();
    for source in incoming {
        offsets.extend(vtable_offsets(
            definitions,
            source.strip_prefix('%')?,
            visiting,
        )?);
    }
    Some(offsets)
}

/// Parses a constant byte offset `getelementptr [flags] i8, ptr %base, i64 OFFSET`.
fn byte_offset(definition: &str) -> Option<u64> {
    let mut operands = definition.strip_prefix("getelementptr ")?;
    while let Some(rest) = ["inbounds ", "nuw ", "nusw "]
        .iter()
        .find_map(|flag| operands.strip_prefix(flag))
    {
        operands = rest;
    }
    let operands = operands.strip_prefix("i8, ptr %")?;
    let (_base, offset) = operands.split_once(", i64 ")?;
    offset.split([',', ' ']).next()?.parse().ok()
}

/// Extracts function entries of one Rust trait-object vtable constant by byte offset.
///
/// # Errors
///
/// Returns an invalid-IR error for a vtable whose element layout is not modeled.
pub(crate) fn parse_vtable(line: &str) -> GateResult<Option<Vec<(u64, String)>>> {
    if !line.starts_with("@vtable.") {
        return Ok(None);
    }
    let Some((_, layout)) = line.split_once(" constant <{ ") else {
        return Ok(None);
    };
    let invalid = || GateError::InvalidIr(format!("unmodeled vtable constant: {line}"));
    let (types, values) = layout.split_once(" }> <{ ").ok_or_else(invalid)?;
    let types = split_top_level(types, ',');
    let values = constant_elements(values).ok_or_else(invalid)?;
    if types.len() != values.len() {
        return Err(invalid());
    }
    let mut offset = 0_u64;
    let mut slots = Vec::new();
    for (element_type, value) in types.into_iter().zip(values) {
        let element_type = element_type.trim();
        let size = if element_type == "ptr" {
            if let Some(symbol) = symbol_references(value)?.first() {
                slots.push((offset, symbol.clone()));
            }
            8
        } else if let Some(count) = element_type
            .strip_prefix('[')
            .and_then(|array| array.strip_suffix(" x i8]"))
        {
            count.parse::<u64>().map_err(|_| invalid())?
        } else {
            return Err(invalid());
        };
        offset = offset.checked_add(size).ok_or_else(invalid)?;
    }
    Ok(Some(slots))
}

/// Splits the elements of a packed constant up to its closing `}>`, outside string literals.
fn constant_elements(values: &str) -> Option<Vec<&str>> {
    let mut elements = Vec::new();
    let mut start = 0_usize;
    let mut in_string = false;
    let mut depth = 0_usize;
    let mut characters = values.char_indices().peekable();
    while let Some((position, character)) = characters.next() {
        if in_string {
            in_string = character != '"';
            continue;
        }
        match character {
            '"' => in_string = true,
            '[' | '(' | '<' => depth = depth.checked_add(1)?,
            ']' | ')' | '>' => depth = depth.checked_sub(1)?,
            '{' => depth = depth.checked_add(1)?,
            '}' if depth == 0 => {
                if characters.peek().map(|(_, next)| *next) != Some('>') {
                    return None;
                }
                elements.push(values.get(start..position)?.trim());
                return Some(elements);
            }
            '}' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                elements.push(values.get(start..position)?.trim());
                start = position.checked_add(1)?;
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use pe_unwind::{FrameTable, RuntimeFrame};

    /// Fails a fallible test with a stable message.
    /// # Errors
    /// Returns an invalid-IR error describing the unmet expectation.
    fn require(condition: bool, detail: &'static str) -> GateResult<()> {
        if condition {
            Ok(())
        } else {
            Err(GateError::InvalidIr(detail.to_owned()))
        }
    }

    /// Links each symbol at its own entry with the given fixed frame.
    fn frames(entries: &[(&str, u64)]) -> LinkedFrames {
        let mut table = Vec::new();
        let mut symbols = BTreeMap::new();
        let mut rva = 0x1000_u64;
        for (symbol, fixed_bytes) in entries {
            table.push(RuntimeFrame {
                begin: rva,
                end: rva.saturating_add(0x10),
                fixed_bytes: *fixed_bytes,
            });
            symbols.insert((*symbol).to_owned(), Some(rva));
            rva = rva.saturating_add(0x100);
        }
        LinkedFrames {
            table: FrameTable {
                image_base: 0,
                frames: table,
            },
            symbols,
        }
    }

    /// Expansion root dispatching one trait method through a vtable slot.
    fn dispatch_fixture(reserved: u64) -> String {
        format!(
            "@vtable.0 = private unnamed_addr constant <{{ ptr, [16 x i8], ptr }}> \
             <{{ ptr @drop, [16 x i8] c\"\\08,}}>\\00\\00\\00\\08\\00\\00\\00\\00\\00\\00\\00\\00\", ptr @advance }}>, align 8\n\
             define void @DriverEntry() {{\n  call void @thread(ptr null)\n  ret void\n}}\n\
             define internal void @thread(ptr %context) {{\n  \
             %status = tail call i32 @KeExpandKernelStackAndCalloutEx(ptr nonnull @callout, ptr %context, i64 noundef {reserved}, i8 0, ptr null)\n  \
             ret void\n}}\n\
             define internal void @callout(ptr %parameter) {{\n  call void @run(ptr %parameter)\n  ret void\n}}\n\
             ; <ext4win::irp::reactor::CompletionReactor>::run\n\
             define internal void @run(ptr %operation, ptr %vtable) {{\n  \
             %slot = getelementptr inbounds nuw i8, ptr %vtable, i64 24\n  \
             %method = load ptr, ptr %slot, align 8, !invariant.load !1\n  \
             call void %method(ptr %operation, i64 0)\n  ret void\n}}\n\
             define internal void @advance(ptr %self, i64 %flags) {{\n  ret void\n}}\n\
             define internal void @drop(ptr %self, i64 %flags) {{\n  call void @deep(ptr %self)\n  ret void\n}}\n\
             define internal void @deep(ptr %self) {{\n  ret void\n}}\n\
             declare i32 @KeExpandKernelStackAndCalloutEx(ptr, ptr, i64, i8, ptr)\n"
        )
    }

    /// Vtable dispatch reaches only its slot and the measured chain sums frames and returns.
    /// # Errors
    /// Returns malformed fixtures or an unexpected measurement.
    #[test]
    fn vtable_dispatch_is_measured_against_reserve() -> GateResult<()> {
        let module = IrModule::parse(&dispatch_fixture(71_680))?;
        let linked = frames(&[
            ("callout", 40),
            ("run", 2_000),
            ("advance", 100),
            ("drop", 50_000),
            ("deep", 50_000),
        ]);
        let mut violations = Vec::new();
        let measured = module.audit_expanded_stacks(&linked, &mut violations)?;
        require(violations.is_empty(), "within-budget callout was rejected")?;
        require(
            measured.len() == 1
                && measured
                    .first()
                    // Callout, executor and slot method frames, each with its return address.
                    .is_some_and(|stack| stack.depth == 2_164),
            "vtable dispatch reached a different slot or misreported depth",
        )
    }

    /// A chain that leaves less than one standard stack is reported with its deepest path.
    /// # Errors
    /// Returns malformed fixtures or a missing budget violation.
    #[test]
    fn exhausted_reserve_is_rejected() -> GateResult<()> {
        let module = IrModule::parse(&dispatch_fixture(26_000))?;
        let linked = frames(&[
            ("callout", 40),
            ("run", 2_000),
            ("advance", 100),
            ("drop", 0),
            ("deep", 0),
        ]);
        let mut violations = Vec::new();
        module.audit_expanded_stacks(&linked, &mut violations)?;
        require(
            violations.len() == 1
                && violations.first().is_some_and(|violation| {
                    violation.category == "expanded stack budget"
                        && violation
                            .path
                            .first()
                            .is_some_and(|step| step.starts_with("callout"))
                }),
            "exhausted expanded stack was accepted",
        )
    }

    /// Recursion, non-constant sizes and an executor outside every callout have no bound.
    /// # Errors
    /// Returns malformed fixtures or a missing violation.
    #[test]
    fn unbounded_stacks_are_rejected() -> GateResult<()> {
        let recursive = dispatch_fixture(71_680).replace(
            "define internal void @advance(ptr %self, i64 %flags) {\n  ret void",
            "define internal void @advance(ptr %self, i64 %flags) {\n  call void @run(ptr %self, ptr %self)\n  ret void",
        );
        let linked = frames(&[
            ("callout", 0),
            ("run", 0),
            ("advance", 0),
            ("drop", 0),
            ("deep", 0),
        ]);
        let mut violations = Vec::new();
        IrModule::parse(&recursive)?.audit_expanded_stacks(&linked, &mut violations)?;
        require(
            violations
                .iter()
                .any(|violation| violation.category == "recursive stack growth"),
            "recursive executor stack was accepted",
        )?;

        let dynamic = dispatch_fixture(71_680).replace("i64 noundef 71680", "i64 %size");
        let mut violations = Vec::new();
        IrModule::parse(&dynamic)?.audit_expanded_stacks(&linked, &mut violations)?;
        require(
            violations
                .iter()
                .any(|violation| violation.category == "unbounded expanded stack")
                && violations
                    .iter()
                    .any(|violation| violation.category == "executor outside expanded stack"),
            "non-constant expansion was accepted",
        )
    }

    /// A function pointer that is not a vtable load reaches every address-taken match.
    /// # Errors
    /// Returns malformed fixtures or an unexpected measurement.
    #[test]
    fn plain_function_pointers_use_signature_targets() -> GateResult<()> {
        let fixture = dispatch_fixture(71_680).replace(
            "%method = load ptr, ptr %slot, align 8, !invariant.load !1",
            "%method = load ptr, ptr %slot, align 8",
        );
        let linked = frames(&[
            ("callout", 0),
            ("run", 0),
            ("advance", 100),
            ("drop", 1_000),
            ("deep", 200),
        ]);
        let mut violations = Vec::new();
        let measured =
            IrModule::parse(&fixture)?.audit_expanded_stacks(&linked, &mut violations)?;
        require(
            violations.is_empty()
                && measured
                    .first()
                    // Drop and its callee below two empty frames, each with its return address.
                    .is_some_and(|stack| stack.depth == 1_232),
            "plain function pointer did not reach every signature match",
        )
    }
}
