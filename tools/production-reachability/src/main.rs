//! Production-root reachability gate for the release driver LLVM IR.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::fmt;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::ExitCode,
    time::SystemTime,
};

/// The exported driver entry point.
const DRIVER_ENTRY: &str = "DriverEntry";

/// The only production function permitted to invoke `KeBugCheckEx`.
const FATAL_BUGCHECK_ALLOWLIST: &[&str] =
    &["<ext4win::kernel::fatal::KernelWideInconsistency>::bugcheck"];

/// Maximum number of independent violation paths printed by one run.
const MAX_REPORTED_VIOLATIONS: usize = 64;

/// Result type used by the analyzer and its command-line boundary.
type GateResult<T> = Result<T, GateError>;

/// A deterministic analysis or artifact-discovery failure.
#[derive(Debug)]
enum GateError {
    /// A filesystem operation failed.
    Io {
        /// Operation being attempted.
        operation: &'static str,
        /// Path associated with the operation.
        path: PathBuf,
        /// Underlying operating-system error.
        source: io::Error,
    },
    /// The LLVM IR is not structurally usable by the gate.
    InvalidIr(String),
    /// No release LLVM IR artifact was found.
    ArtifactNotFound(PathBuf),
    /// The command-line arguments do not match the gate contract.
    InvalidArguments,
}

impl fmt::Display for GateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} {}: {source}", path.display()),
            Self::InvalidIr(detail) => write!(formatter, "invalid LLVM IR: {detail}"),
            Self::ArtifactNotFound(root) => write!(
                formatter,
                "release ext4win.ll was not found below {}",
                root.display()
            ),
            Self::InvalidArguments => write!(
                formatter,
                "usage: production-reachability [path-to-release-ext4win.ll]"
            ),
        }
    }
}

impl core::error::Error for GateError {}

/// A normalized opaque-pointer LLVM function signature.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FunctionSignature {
    /// LLVM return type.
    result: String,
    /// Top-level LLVM argument types.
    parameters: Vec<String>,
    /// Whether the function accepts a variable argument tail.
    variadic: bool,
}

impl fmt::Display for FunctionSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}(", self.result)?;
        let mut separator = "";
        for parameter in &self.parameters {
            write!(formatter, "{separator}{parameter}")?;
            separator = ", ";
        }
        if self.variadic {
            write!(formatter, "{separator}...")?;
        }
        formatter.write_str(")")
    }
}

/// One indirect call site awaiting conservative target expansion.
#[derive(Clone, Debug)]
struct IndirectCall {
    /// Normalized call-site signature.
    signature: FunctionSignature,
    /// One-based LLVM IR line number.
    line: usize,
}

/// A defined or declared LLVM function.
#[derive(Debug)]
struct Function {
    /// Human-readable name recovered from LLVM comments.
    display: String,
    /// Normalized function signature.
    signature: FunctionSignature,
    /// Direct calls and callback-address flows.
    edges: BTreeSet<String>,
    /// Indirect call sites in the function body.
    indirect_calls: Vec<IndirectCall>,
    /// Whether LLVM exposes the definition outside the module.
    externally_visible: bool,
}

/// Parsed production call graph inputs from one LLVM module.
#[derive(Debug)]
struct IrModule {
    /// All function definitions and declarations by LLVM symbol.
    functions: BTreeMap<String, Function>,
    /// Functions used as values rather than direct call targets.
    address_taken: BTreeSet<String>,
    /// Explicit production roots.
    roots: BTreeSet<String>,
}

/// A categorized path from a production root to a forbidden sink.
#[derive(Debug)]
struct Violation {
    /// Stable category printed before the path.
    category: &'static str,
    /// Human-readable root-to-sink path.
    path: Vec<String>,
}

/// Successful graph construction and its reachability findings.
#[derive(Debug)]
struct AnalysisReport {
    /// Number of functions in the LLVM module.
    function_count: usize,
    /// Number of functions reachable from production roots.
    reachable_count: usize,
    /// Number of address-taken targets used for indirect expansion.
    address_taken_count: usize,
    /// Forbidden or unresolved paths.
    violations: Vec<Violation>,
}

/// Classification for a forbidden production sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Sink {
    /// Rust panic, assertion, unwrap, or expect machinery.
    Panic,
    /// Bounds or slice-contract failure.
    Bounds,
    /// Length-mismatch copying helper.
    Copy,
    /// Standard-library sort machinery or comparator violation.
    Sort,
    /// Allocation failure terminal handler.
    OutOfMemory,
    /// Collection capacity overflow terminal handler.
    CapacityOverflow,
    /// Resumed async/Future execution.
    AsyncResume,
    /// Compiler trap or process abort.
    TrapOrAbort,
    /// Kernel-wide bugcheck boundary.
    KernelBugcheck,
}

impl Sink {
    /// Stable report category.
    const fn category(self) -> &'static str {
        match self {
            Self::Panic => "panic/assert/unwrap",
            Self::Bounds => "bounds/slice trap",
            Self::Copy => "copy trap",
            Self::Sort => "standard sort",
            Self::OutOfMemory => "OOM abort",
            Self::CapacityOverflow => "capacity overflow",
            Self::AsyncResume => "async/Future resume",
            Self::TrapOrAbort => "trap/abort",
            Self::KernelBugcheck => "KeBugCheckEx outside kernel::fatal",
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("production reachability gate error: {error}");
            ExitCode::from(2)
        }
    }
}

/// Executes artifact discovery, parsing, analysis, and reporting.
///
/// # Errors
///
/// Returns an artifact, I/O, or LLVM parsing error before a verdict can be
/// produced.
fn run() -> GateResult<bool> {
    let ir_path = command_line_ir_path()?;
    let ir = fs::read_to_string(&ir_path).map_err(|source| GateError::Io {
        operation: "read",
        path: ir_path.clone(),
        source,
    })?;
    let module = IrModule::parse(&ir)?;
    let report = module.analyze()?;

    println!("production reachability artifact: {}", ir_path.display());
    println!(
        "functions: {}, reachable: {}, address-taken: {}",
        report.function_count, report.reachable_count, report.address_taken_count
    );

    if report.violations.is_empty() {
        println!("production-root reachability gate: PASS");
        return Ok(true);
    }

    println!(
        "production-root reachability gate: FAIL ({} path(s))",
        report.violations.len()
    );
    for violation in &report.violations {
        println!("{}: {}", violation.category, violation.path.join(" -> "));
    }
    Ok(false)
}

/// Resolves an explicit IR argument or discovers the newest release artifact.
///
/// # Errors
///
/// Returns an error for an invalid argument count, current-directory failure,
/// or artifact-discovery failure.
fn command_line_ir_path() -> GateResult<PathBuf> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let explicit = arguments.next();
    if arguments.next().is_some() {
        return Err(GateError::InvalidArguments);
    }
    if let Some(path) = explicit {
        return Ok(PathBuf::from(path));
    }

    let current = env::current_dir().map_err(|source| GateError::Io {
        operation: "resolve current directory",
        path: PathBuf::from("."),
        source,
    })?;
    discover_release_ir(
        &current
            .join("target")
            .join("release")
            .join("build")
            .join("ext4win"),
    )
}

/// Finds the newest `ext4win.ll` below the WDK release output root.
///
/// # Errors
///
/// Returns an I/O error when the artifact tree cannot be enumerated, or an
/// artifact-not-found error when no release IR exists below `root`.
fn discover_release_ir(root: &Path) -> GateResult<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut newest: Option<(SystemTime, PathBuf)> = None;

    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| GateError::Io {
            operation: "enumerate",
            path: directory.clone(),
            source,
        })?;
        for entry_result in entries {
            let entry = entry_result.map_err(|source| GateError::Io {
                operation: "read directory entry below",
                path: directory.clone(),
                source,
            })?;
            let file_type = entry.file_type().map_err(|source| GateError::Io {
                operation: "inspect",
                path: entry.path(),
                source,
            })?;
            if file_type.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if entry.file_name() != "ext4win.ll" {
                continue;
            }
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .map_err(|source| GateError::Io {
                    operation: "read modification time for",
                    path: entry.path(),
                    source,
                })?;
            let replace = newest
                .as_ref()
                .is_none_or(|(current_modified, _)| modified > *current_modified);
            if replace {
                newest = Some((modified, entry.path()));
            }
        }
    }

    newest
        .map(|(_, path)| path)
        .ok_or_else(|| GateError::ArtifactNotFound(root.to_path_buf()))
}

impl IrModule {
    /// Parses function declarations first, then builds body edges and roots.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when a function header, graph edge, or the
    /// required `DriverEntry` root cannot be represented.
    fn parse(ir: &str) -> GateResult<Self> {
        let mut functions = BTreeMap::new();
        let mut pending_display: Option<String> = None;
        let mut inside_function = false;

        for (zero_based_line, line) in ir.lines().enumerate() {
            let trimmed = line.trim();
            if inside_function {
                if trimmed == "}" {
                    inside_function = false;
                }
                continue;
            }
            if let Some(comment) = function_name_comment(trimmed) {
                pending_display = Some(comment.to_owned());
                continue;
            }
            let definition = trimmed.starts_with("define ");
            let declaration = trimmed.starts_with("declare ");
            if !definition && !declaration {
                continue;
            }

            let symbol = function_symbol(trimmed).ok_or_else(|| {
                GateError::InvalidIr(format!(
                    "function without a symbol at line {}",
                    zero_based_line.saturating_add(1)
                ))
            })?;
            let signature = parse_function_signature(trimmed, &symbol).ok_or_else(|| {
                GateError::InvalidIr(format!(
                    "function signature could not be parsed for {symbol} at line {}",
                    zero_based_line.saturating_add(1)
                ))
            })?;
            let display = pending_display.take().unwrap_or_else(|| symbol.clone());
            let externally_visible = definition && definition_is_externally_visible(trimmed);
            functions.insert(
                symbol,
                Function {
                    display,
                    signature,
                    edges: BTreeSet::new(),
                    indirect_calls: Vec::new(),
                    externally_visible,
                },
            );
            inside_function = definition;
        }

        if !functions.contains_key(DRIVER_ENTRY) {
            return Err(GateError::InvalidIr(
                "DriverEntry definition is absent from the release module".to_owned(),
            ));
        }

        let mut module = Self {
            functions,
            address_taken: BTreeSet::new(),
            roots: BTreeSet::new(),
        };
        module.collect_edges(ir)?;
        module.collect_roots();
        Ok(module)
    }

    /// Collects direct calls, function-address flows, and indirect call sites.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when a symbol or function body boundary is
    /// malformed.
    fn collect_edges(&mut self, ir: &str) -> GateResult<()> {
        let mut current_function: Option<String> = None;
        let mut external_global = false;

        for (zero_based_line, line) in ir.lines().enumerate() {
            let trimmed = line.trim();
            if current_function.is_none() && trimmed.starts_with("define ") {
                current_function = function_symbol(trimmed);
                external_global = false;
                continue;
            }
            if current_function.is_none() && trimmed.starts_with("declare ") {
                external_global = false;
                continue;
            }
            if let Some(caller) = current_function.as_ref() {
                if trimmed == "}" {
                    current_function = None;
                    continue;
                }
                if trimmed.starts_with(';') {
                    continue;
                }
                self.collect_body_line(caller, line, zero_based_line.saturating_add(1))?;
                continue;
            }

            if trimmed.starts_with('@') && trimmed.contains(" = ") {
                external_global = !trimmed.contains(" private ")
                    && !trimmed.contains(" internal ")
                    && !trimmed.starts_with("@llvm.");
            } else if trimmed.is_empty()
                || trimmed.starts_with("declare ")
                || trimmed.starts_with("attributes ")
                || trimmed.starts_with('!')
                || trimmed.starts_with(';')
            {
                external_global = false;
            }

            let references = symbol_references(line)?;
            for reference in references {
                if !self.functions.contains_key(&reference) {
                    continue;
                }
                self.address_taken.insert(reference.clone());
                if external_global {
                    self.roots.insert(reference);
                }
            }
        }
        Ok(())
    }

    /// Adds graph facts recovered from one LLVM instruction line.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when `caller` is absent or a symbol boundary
    /// cannot be decoded.
    fn collect_body_line(
        &mut self,
        caller: &str,
        line: &str,
        line_number: usize,
    ) -> GateResult<()> {
        let call = parse_call_site(line);
        let direct_target = call.as_ref().and_then(|site| site.direct_target.as_ref());
        let references = symbol_references(line)?;
        let known_references: Vec<String> = references
            .into_iter()
            .filter(|reference| self.functions.contains_key(reference))
            .collect();

        let caller_node = self.functions.get_mut(caller).ok_or_else(|| {
            GateError::InvalidIr(format!("body found for unknown function {caller}"))
        })?;
        for reference in known_references {
            if direct_target == Some(&reference) {
                caller_node.edges.insert(reference);
            } else {
                caller_node.edges.insert(reference.clone());
                self.address_taken.insert(reference);
            }
        }
        if let Some(site) = call
            && site.direct_target.is_none()
        {
            caller_node.indirect_calls.push(IndirectCall {
                signature: site.signature,
                line: line_number,
            });
        }
        Ok(())
    }

    /// Adds exported definitions and the driver entry point as roots.
    fn collect_roots(&mut self) {
        self.roots.insert(DRIVER_ENTRY.to_owned());
        for (symbol, function) in &self.functions {
            if function.externally_visible {
                self.roots.insert(symbol.clone());
            }
        }
    }

    /// Resolves indirect calls and computes root-to-sink paths.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error if graph construction produced a missing or
    /// cyclic function node.
    fn analyze(mut self) -> GateResult<AnalysisReport> {
        let address_taken_by_signature = self.address_taken_by_signature();
        let mut unresolved = BTreeMap::<String, Vec<IndirectCall>>::new();

        for (caller, function) in &mut self.functions {
            for indirect in &function.indirect_calls {
                let candidates = address_taken_by_signature.get(&indirect.signature);
                if let Some(candidates) = candidates.filter(|candidates| !candidates.is_empty()) {
                    function.edges.extend(candidates.iter().cloned());
                } else {
                    unresolved
                        .entry(caller.clone())
                        .or_default()
                        .push(indirect.clone());
                }
            }
        }

        let mut predecessors = BTreeMap::<String, Option<String>>::new();
        let mut queue = VecDeque::<String>::new();
        for root in &self.roots {
            if self.functions.contains_key(root) && !predecessors.contains_key(root) {
                predecessors.insert(root.clone(), None);
                queue.push_back(root.clone());
            }
        }

        while let Some(caller) = queue.pop_front() {
            let function = self.functions.get(&caller).ok_or_else(|| {
                GateError::InvalidIr(format!("reachable function {caller} disappeared"))
            })?;
            for callee in &function.edges {
                if !predecessors.contains_key(callee) {
                    predecessors.insert(callee.clone(), Some(caller.clone()));
                    queue.push_back(callee.clone());
                }
            }
        }

        let mut violations = Vec::new();
        let mut reported_sort_callers = BTreeSet::<String>::new();
        for symbol in predecessors.keys() {
            if violations.len() >= MAX_REPORTED_VIOLATIONS {
                break;
            }
            let function = self.functions.get(symbol).ok_or_else(|| {
                GateError::InvalidIr(format!("reachable symbol {symbol} has no function node"))
            })?;
            let Some(sink) = classify_sink(symbol, &function.display) else {
                continue;
            };
            if predecessor_contains_forbidden_sink(symbol, &predecessors, &self.functions) {
                continue;
            }
            if sink == Sink::Sort {
                let caller = predecessors
                    .get(symbol)
                    .and_then(Option::as_ref)
                    .cloned()
                    .unwrap_or_else(|| symbol.clone());
                if !reported_sort_callers.insert(caller) {
                    continue;
                }
            }
            if sink == Sink::KernelBugcheck
                && bugcheck_predecessor_is_allowed(symbol, &predecessors, &self.functions)
            {
                continue;
            }
            violations.push(Violation {
                category: sink.category(),
                path: display_path(symbol, &predecessors, &self.functions)?,
            });
        }

        for (caller, calls) in unresolved {
            if violations.len() >= MAX_REPORTED_VIOLATIONS {
                break;
            }
            if !predecessors.contains_key(&caller) {
                continue;
            }
            for call in calls {
                if violations.len() >= MAX_REPORTED_VIOLATIONS {
                    break;
                }
                let mut path = display_path(&caller, &predecessors, &self.functions)?;
                path.push(format!(
                    "unresolved indirect call at LLVM IR line {} [{}]",
                    call.line, call.signature
                ));
                violations.push(Violation {
                    category: "unresolved indirect call",
                    path,
                });
            }
        }

        Ok(AnalysisReport {
            function_count: self.functions.len(),
            reachable_count: predecessors.len(),
            address_taken_count: self.address_taken.len(),
            violations,
        })
    }

    /// Groups address-taken functions by normalized LLVM signature.
    fn address_taken_by_signature(&self) -> BTreeMap<FunctionSignature, Vec<String>> {
        let mut grouped = BTreeMap::<FunctionSignature, Vec<String>>::new();
        for symbol in &self.address_taken {
            let Some(function) = self.functions.get(symbol) else {
                continue;
            };
            grouped
                .entry(function.signature.clone())
                .or_default()
                .push(symbol.clone());
        }
        grouped
    }
}

/// Intermediate representation of one direct or indirect call instruction.
#[derive(Debug)]
struct ParsedCallSite {
    /// Direct LLVM target, or `None` for an indirect call.
    direct_target: Option<String>,
    /// Normalized call-site signature.
    signature: FunctionSignature,
}

/// Parses a `call` or `invoke` instruction while tolerating LLVM attributes.
fn parse_call_site(line: &str) -> Option<ParsedCallSite> {
    let trimmed = line.trim();
    if trimmed.starts_with(';') {
        return None;
    }
    let (instruction_start, instruction_length) = call_instruction_start(line)?;
    let after_instruction = line.get(instruction_start.saturating_add(instruction_length)..)?;
    let direct = callable_symbol(after_instruction, '@');
    let indirect = callable_symbol(after_instruction, '%');
    let (callee_start, arguments_start, direct_target) = match (direct, indirect) {
        (Some((start, _arguments, _symbol)), Some((indirect_start, indirect_arguments, _)))
            if indirect_start < start =>
        {
            (indirect_start, indirect_arguments, None)
        }
        (Some((start, arguments, symbol)), _) => (start, arguments, Some(symbol)),
        (None, Some((start, arguments, _))) => (start, arguments, None),
        (None, None) => return None,
    };
    let arguments_end = matching_delimiter(after_instruction, arguments_start, '(', ')')?;
    let prefix = after_instruction.get(..callee_start)?;
    let arguments = after_instruction.get(arguments_start.saturating_add(1)..arguments_end)?;
    Some(ParsedCallSite {
        direct_target,
        signature: signature_from_parts(prefix, arguments),
    })
}

/// Locates the call-like instruction word and returns its byte range.
fn call_instruction_start(line: &str) -> Option<(usize, usize)> {
    let call = line.find("call ").map(|position| (position, "call ".len()));
    let invoke = line
        .find("invoke ")
        .map(|position| (position, "invoke ".len()));
    match (call, invoke) {
        (Some(call_site), Some(invoke_site)) if invoke_site.0 < call_site.0 => Some(invoke_site),
        (Some(call_site), _) => Some(call_site),
        (None, invoke_site) => invoke_site,
    }
}

/// Finds a symbol immediately followed by an argument list.
fn callable_symbol(input: &str, marker: char) -> Option<(usize, usize, String)> {
    for (position, character) in input.char_indices() {
        if character != marker {
            continue;
        }
        let symbol_start = position.saturating_add(marker.len_utf8());
        let tail = input.get(symbol_start..)?;
        let symbol_length = tail
            .char_indices()
            .take_while(|(_, candidate)| is_llvm_symbol_character(*candidate))
            .map(|(offset, candidate)| offset.saturating_add(candidate.len_utf8()))
            .last()?;
        let symbol_end = symbol_start.saturating_add(symbol_length);
        let after_symbol = input.get(symbol_end..)?.trim_start();
        if !after_symbol.starts_with('(') {
            continue;
        }
        let whitespace = input
            .get(symbol_end..)?
            .len()
            .saturating_sub(after_symbol.len());
        let arguments_start = symbol_end.saturating_add(whitespace);
        let symbol = input.get(symbol_start..symbol_end)?.to_owned();
        return Some((position, arguments_start, symbol));
    }
    None
}

/// Extracts a function symbol from a definition or declaration header.
fn function_symbol(header: &str) -> Option<String> {
    callable_symbol(header, '@').map(|(_, _, symbol)| symbol)
}

/// Parses the signature from a function header.
fn parse_function_signature(header: &str, symbol: &str) -> Option<FunctionSignature> {
    let marker = format!("@{symbol}");
    let symbol_start = header.find(&marker)?;
    let arguments_start = header
        .get(symbol_start.saturating_add(marker.len())..)?
        .find('(')?
        .saturating_add(symbol_start)
        .saturating_add(marker.len());
    let arguments_end = matching_delimiter(header, arguments_start, '(', ')')?;
    let prefix = header.get(..symbol_start)?;
    let arguments = header.get(arguments_start.saturating_add(1)..arguments_end)?;
    Some(signature_from_parts(prefix, arguments))
}

/// Normalizes a return prefix and a comma-separated argument list.
fn signature_from_parts(prefix: &str, arguments: &str) -> FunctionSignature {
    let result = last_llvm_type(prefix).unwrap_or_else(|| "?".to_owned());
    let mut parameters = Vec::new();
    let mut variadic = false;
    for argument in split_top_level(arguments, ',') {
        let trimmed = argument.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "..." {
            variadic = true;
            continue;
        }
        parameters.push(first_llvm_type(trimmed));
    }
    FunctionSignature {
        result,
        parameters,
        variadic,
    }
}

/// Returns the first top-level LLVM value type from an argument.
fn first_llvm_type(argument: &str) -> String {
    let trimmed = argument.trim_start();
    if trimmed.starts_with("ptr") {
        return "ptr".to_owned();
    }
    let token = trimmed.split_whitespace().next().unwrap_or("?");
    if is_scalar_llvm_type(token) {
        return token.to_owned();
    }
    if let Some(first) = trimmed.chars().next()
        && let Some(close) = matching_type_delimiter(first)
        && let Some(end) = matching_delimiter(trimmed, 0, first, close)
        && let Some(value_type) = trimmed.get(..=end)
    {
        return value_type.split_whitespace().collect();
    }
    "?".to_owned()
}

/// Returns the last scalar LLVM result type before a callee.
fn last_llvm_type(prefix: &str) -> Option<String> {
    prefix
        .split_whitespace()
        .rev()
        .map(|token| token.trim_matches(|character: char| character == ',' || character == ')'))
        .find(|token| is_scalar_llvm_type(token))
        .map(str::to_owned)
}

/// Recognizes scalar and opaque-pointer LLVM types used at ABI boundaries.
fn is_scalar_llvm_type(token: &str) -> bool {
    matches!(
        token,
        "void" | "ptr" | "half" | "bfloat" | "float" | "double" | "fp128" | "x86_fp80"
    ) || token.strip_prefix('i').is_some_and(|width| {
        !width.is_empty() && width.chars().all(|character| character.is_ascii_digit())
    })
}

/// Splits a string only at delimiters outside nested LLVM type/value groups.
fn split_top_level(input: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    for (position, character) in input.char_indices() {
        match character {
            '(' | '[' | '{' | '<' => depth = depth.saturating_add(1),
            ')' | ']' | '}' | '>' => depth = depth.saturating_sub(1),
            _ if character == delimiter && depth == 0 => {
                if let Some(part) = input.get(start..position) {
                    parts.push(part);
                }
                start = position.saturating_add(character.len_utf8());
            }
            _ => {}
        }
    }
    if let Some(part) = input.get(start..) {
        parts.push(part);
    }
    parts
}

/// Finds the matching close delimiter for a byte-positioned open delimiter.
fn matching_delimiter(input: &str, open_position: usize, open: char, close: char) -> Option<usize> {
    let tail = input.get(open_position..)?;
    let mut depth = 0usize;
    for (offset, character) in tail.char_indices() {
        if character == open {
            depth = depth.saturating_add(1);
        } else if character == close {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(open_position.saturating_add(offset));
            }
        }
    }
    None
}

/// Maps an aggregate type opener to its closer.
const fn matching_type_delimiter(open: char) -> Option<char> {
    match open {
        '[' => Some(']'),
        '{' => Some('}'),
        '<' => Some('>'),
        _ => None,
    }
}

/// Extracts all unquoted LLVM symbol references from one line.
///
/// # Errors
///
/// Returns an invalid-IR error if a UTF-8 symbol boundary cannot be advanced.
fn symbol_references(line: &str) -> GateResult<Vec<String>> {
    let mut symbols = Vec::new();
    let mut remaining = line;
    while let Some(marker_position) = remaining.find('@') {
        let after_marker = remaining
            .get(marker_position.saturating_add(1)..)
            .ok_or_else(|| GateError::InvalidIr("invalid symbol boundary".to_owned()))?;
        let symbol_length = after_marker
            .char_indices()
            .take_while(|(_, character)| is_llvm_symbol_character(*character))
            .map(|(offset, character)| offset.saturating_add(character.len_utf8()))
            .last()
            .unwrap_or(0);
        if symbol_length > 0
            && let Some(symbol) = after_marker.get(..symbol_length)
        {
            symbols.push(symbol.to_owned());
        }
        let consumed = marker_position
            .saturating_add(1)
            .saturating_add(symbol_length);
        remaining = remaining
            .get(consumed..)
            .ok_or_else(|| GateError::InvalidIr("invalid symbol scan boundary".to_owned()))?;
    }
    Ok(symbols)
}

/// LLVM's unquoted global identifier character set needed by Rust output.
fn is_llvm_symbol_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '$' | '-')
}

/// Recovers a demangled function name comment preceding a definition.
fn function_name_comment(trimmed: &str) -> Option<&str> {
    let comment = trimmed.strip_prefix("; ")?;
    if comment.starts_with("Function Attrs:")
        || comment.starts_with("ModuleID")
        || comment.starts_with("source_filename")
    {
        return None;
    }
    Some(comment)
}

/// Determines whether a definition has externally visible LLVM linkage.
fn definition_is_externally_visible(header: &str) -> bool {
    !header.starts_with("define internal ")
        && !header.starts_with("define private ")
        && !header.starts_with("define linkonce_odr ")
        && !header.starts_with("define available_externally ")
}

/// Classifies forbidden terminal or prohibited-runtime functions.
fn classify_sink(symbol: &str, display: &str) -> Option<Sink> {
    let identity = format!("{display}\n{symbol}").to_ascii_lowercase();
    if identity.contains("kebugcheckex") {
        return Some(Sink::KernelBugcheck);
    }
    if identity.contains("copy_from_slice") || identity.contains("clone_from_slice") {
        return Some(Sink::Copy);
    }
    if identity.contains("core::slice::sort::") || identity.contains("panic_on_ord_violation") {
        return Some(Sink::Sort);
    }
    if identity.contains("panic_bounds_check")
        || identity.contains("slice_start_index_len_fail")
        || identity.contains("slice_end_index_len_fail")
        || identity.contains("slice_index_order_fail")
    {
        return Some(Sink::Bounds);
    }
    if identity.contains("handle_alloc_error")
        || identity.contains("__rust_alloc_error_handler")
        || identity.contains("rust_oom")
    {
        return Some(Sink::OutOfMemory);
    }
    if identity.contains("capacity_overflow") {
        return Some(Sink::CapacityOverflow);
    }
    if identity.contains("future") && identity.contains("poll")
        || identity.contains("async_fn")
        || identity.contains("{async")
    {
        return Some(Sink::AsyncResume);
    }
    if identity.contains("llvm.trap")
        || identity.contains("llvm.ubsantrap")
        || identity.contains("__fastfail")
        || identity == "abort\nabort"
    {
        return Some(Sink::TrapOrAbort);
    }
    if identity.contains("core::panicking::")
        || identity.contains("rust_begin_unwind")
        || identity.contains("unwrap_failed")
        || identity.contains("expect_failed")
        || identity.contains("assert_failed")
        || identity.contains("panic_fmt")
        || identity.contains("begin_panic")
    {
        return Some(Sink::Panic);
    }
    None
}

/// Returns whether the selected shortest path already crossed a forbidden sink.
fn predecessor_contains_forbidden_sink(
    symbol: &str,
    predecessors: &BTreeMap<String, Option<String>>,
    functions: &BTreeMap<String, Function>,
) -> bool {
    let mut current = predecessors.get(symbol).and_then(Option::as_deref);
    let mut remaining = predecessors.len();
    while let Some(predecessor) = current {
        if remaining == 0 {
            return true;
        }
        remaining = remaining.saturating_sub(1);
        let Some(function) = functions.get(predecessor) else {
            return true;
        };
        if classify_sink(predecessor, &function.display).is_some() {
            return true;
        }
        current = predecessors.get(predecessor).and_then(Option::as_deref);
    }
    false
}

/// Checks the exact immediate caller of the kernel bugcheck import.
fn bugcheck_predecessor_is_allowed(
    bugcheck: &str,
    predecessors: &BTreeMap<String, Option<String>>,
    functions: &BTreeMap<String, Function>,
) -> bool {
    let Some(Some(caller)) = predecessors.get(bugcheck) else {
        return false;
    };
    let Some(function) = functions.get(caller) else {
        return false;
    };
    FATAL_BUGCHECK_ALLOWLIST.contains(&function.display.as_str())
}

/// Reconstructs a root-to-node path without unchecked indexing.
///
/// # Errors
///
/// Returns an invalid-IR error when the predecessor graph has a missing node or
/// a cycle.
fn display_path(
    terminal: &str,
    predecessors: &BTreeMap<String, Option<String>>,
    functions: &BTreeMap<String, Function>,
) -> GateResult<Vec<String>> {
    let mut reversed = Vec::new();
    let mut current = Some(terminal);
    let mut remaining = predecessors.len().saturating_add(1);
    while let Some(symbol) = current {
        if remaining == 0 {
            return Err(GateError::InvalidIr(
                "predecessor graph contains a cycle".to_owned(),
            ));
        }
        remaining = remaining.saturating_sub(1);
        let function = functions.get(symbol).ok_or_else(|| {
            GateError::InvalidIr(format!("path symbol {symbol} has no function node"))
        })?;
        reversed.push(function.display.clone());
        current = predecessors
            .get(symbol)
            .ok_or_else(|| GateError::InvalidIr(format!("path predecessor missing for {symbol}")))?
            .as_deref();
    }
    reversed.reverse();
    Ok(reversed)
}

#[cfg(test)]
mod tests {
    use super::{IrModule, Sink, classify_sink};

    /// Converts a failed test invariant into the analyzer's structured error.
    ///
    /// # Errors
    ///
    /// Returns an invalid-IR error when `condition` is false.
    fn require(condition: bool, detail: &'static str) -> Result<(), super::GateError> {
        if condition {
            Ok(())
        } else {
            Err(super::GateError::InvalidIr(detail.to_owned()))
        }
    }

    /// Unreachable language-item sinks must not fail the production graph.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or the invariant fails.
    #[test]
    fn unreachable_panic_is_allowed() -> Result<(), super::GateError> {
        let report = IrModule::parse(
            "; root\ndefine void @DriverEntry() {\n  ret void\n}\n\
             ; core::panicking::panic_fmt\ndefine internal void @panic_sink() {\n  ret void\n}\n",
        )?
        .analyze()?;
        require(
            report.violations.is_empty(),
            "unreachable panic was reported",
        )
    }

    /// A direct reachable panic reports the full root path.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or the expected path is
    /// absent.
    #[test]
    fn reachable_panic_reports_path() -> Result<(), super::GateError> {
        let report = IrModule::parse(
            "; root\ndefine void @DriverEntry() {\n  call void @work()\n  ret void\n}\n\
             ; work\ndefine internal void @work() {\n  call void @panic_sink()\n  ret void\n}\n\
             ; core::panicking::panic_fmt\ndefine internal void @panic_sink() {\n  ret void\n}\n",
        )?
        .analyze()?;
        let Some(violation) = report.violations.first() else {
            return Err(super::GateError::InvalidIr(
                "expected a reachable panic violation".to_owned(),
            ));
        };
        require(
            violation.path.join(" -> ") == "root -> work -> core::panicking::panic_fmt",
            "reachable panic path differed",
        )
    }

    /// Function addresses stored by a root become callback edges.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or the callback path is
    /// not reported exactly once.
    #[test]
    fn address_store_roots_callback() -> Result<(), super::GateError> {
        let report = IrModule::parse(
            "; root\ndefine void @DriverEntry(ptr %slot) {\n  store ptr @callback, ptr %slot\n  ret void\n}\n\
             ; callback\ndefine internal void @callback() {\n  call void @panic_sink()\n  ret void\n}\n\
             ; core::panicking::panic_fmt\ndefine internal void @panic_sink() {\n  ret void\n}\n",
        )?
        .analyze()?;
        require(
            report.violations.len() == 1,
            "stored callback did not produce one violation",
        )
    }

    /// Unknown indirect calls with no typed candidate fail closed.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or unresolved execution
    /// is not rejected.
    #[test]
    fn unresolved_indirect_call_fails_closed() -> Result<(), super::GateError> {
        let report = IrModule::parse(
            "; root\ndefine void @DriverEntry(ptr %callback) {\n  call i32 %callback(i64 1)\n  ret void\n}\n",
        )?
        .analyze()?;
        let Some(violation) = report.violations.first() else {
            return Err(super::GateError::InvalidIr(
                "expected an unresolved indirect violation".to_owned(),
            ));
        };
        require(
            violation.category == "unresolved indirect call",
            "indirect call did not fail closed",
        )
    }

    /// Indirect calls expand to every address-taken compatible function.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or the typed target is
    /// not connected.
    #[test]
    fn indirect_call_reaches_typed_address_target() -> Result<(), super::GateError> {
        let report = IrModule::parse(
            "; root\ndefine void @DriverEntry(ptr %slot, ptr %callback) {\n  store ptr @typed, ptr %slot\n  call void %callback(ptr null)\n  ret void\n}\n\
             ; typed\ndefine internal void @typed(ptr %value) {\n  call void @panic_sink()\n  ret void\n}\n\
             ; core::panicking::panic_fmt\ndefine internal void @panic_sink() {\n  ret void\n}\n",
        )?
        .analyze()?;
        require(
            report
                .violations
                .iter()
                .any(|violation| violation.category == Sink::Panic.category()),
            "typed indirect target was not reached",
        )
    }

    /// Only the enumerated fatal function may invoke the bugcheck import.
    ///
    /// # Errors
    ///
    /// Returns an error if a fixture cannot be parsed or the bugcheck allowlist
    /// admits the wrong caller.
    #[test]
    fn bugcheck_requires_enumerated_caller() -> Result<(), super::GateError> {
        let allowed = IrModule::parse(
            "; root\ndefine void @DriverEntry() {\n  call void @fatal()\n  ret void\n}\n\
             ; <ext4win::kernel::fatal::KernelWideInconsistency>::bugcheck\n\
             define internal void @fatal() {\n  call void @KeBugCheckEx()\n  ret void\n}\n\
             declare void @KeBugCheckEx()\n",
        )?
        .analyze()?;
        require(
            allowed.violations.is_empty(),
            "enumerated fatal caller was rejected",
        )?;

        let rejected = IrModule::parse(
            "; root\ndefine void @DriverEntry() {\n  call void @wrong()\n  ret void\n}\n\
             ; wrong\ndefine internal void @wrong() {\n  call void @KeBugCheckEx()\n  ret void\n}\n\
             declare void @KeBugCheckEx()\n",
        )?
        .analyze()?;
        require(
            rejected.violations.len() == 1,
            "non-fatal bugcheck caller was accepted",
        )
    }

    /// Sink classification includes the explicit non-panic terminal classes.
    ///
    /// # Errors
    ///
    /// Returns an error if a required sink class is absent.
    #[test]
    fn terminal_sink_classes_are_explicit() -> Result<(), super::GateError> {
        require(
            classify_sink("oom", "alloc::alloc::handle_alloc_error") == Some(Sink::OutOfMemory),
            "OOM sink class is absent",
        )?;
        require(
            classify_sink("copy", "core::slice::<impl [T]>::copy_from_slice") == Some(Sink::Copy),
            "copy sink class is absent",
        )?;
        require(
            classify_sink("sort", "core::slice::sort::stable::sort") == Some(Sink::Sort),
            "sort sink class is absent",
        )
    }

    /// Only the first forbidden node on a selected path is reported.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixture cannot be parsed or nested terminal
    /// machinery produces redundant paths.
    #[test]
    fn nested_sinks_report_frontier_only() -> Result<(), super::GateError> {
        let report = IrModule::parse(
            "; root\ndefine void @DriverEntry() {\n  call void @sort_entry()\n  ret void\n}\n\
             ; core::slice::sort::stable::driftsort_main\n\
             define internal void @sort_entry() {\n  call void @panic_sink()\n  ret void\n}\n\
             ; core::panicking::panic_fmt\ndefine internal void @panic_sink() {\n  ret void\n}\n",
        )?
        .analyze()?;
        require(
            report.violations.len() == 1
                && report
                    .violations
                    .first()
                    .is_some_and(|violation| violation.category == Sink::Sort.category()),
            "nested sinks were not collapsed to the frontier",
        )
    }
}
