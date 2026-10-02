//! A bounded control-flow proof of direct IRP context capture, marker installation and restore.
//!
//! Unknown instructions in a capture region fail closed. Aliases and indirect calls remain
//! outside this diagnostic, and this analysis does not prove runtime Filter Manager behavior.
use crate::invalid;
use alloc::collections::{BTreeMap, BTreeSet};
use serde_json::{Value, json};
use std::io;

/// One source-located instruction retained for evidence.
#[derive(Debug)]
struct Instruction {
    /// One-based artifact line number.
    line: usize,
    /// Trimmed IR spelling.
    text: String,
}
/// A function with stable ordered block identity and explicit branches.
#[derive(Debug)]
struct Function {
    /// LLVM symbol.
    name: String,
    /// First block, including an implicit entry block.
    entry: String,
    /// Ordered instruction sequences keyed by block identity.
    blocks: BTreeMap<String, Vec<Instruction>>,
}
/// Recognized instructions relevant to the context protocol.
#[derive(Debug)]
enum Operation {
    /// Capture of the prior marker.
    Capture(String),
    /// Marker write.
    Set(String),
    /// Nullness predicate.
    Compare(String, String, bool),
    /// Native completion of one IRP.
    Complete(String),
    /// Unconditional branch.
    Jump(String),
    /// Conditional branch on a previously established predicate.
    Branch(String, String, String),
    /// Instruction outside this model.
    Unknown,
}

/// Parses only function and basic-block structure, preserving every instruction for rejection.
/// # Errors
/// Returns malformed definitions or duplicate blocks.
fn parse(text: &str) -> io::Result<Vec<Function>> {
    let mut functions = Vec::new();
    let mut current: Option<Function> = None;
    let mut block = String::from("entry");
    for (index, line) in text.lines().enumerate() {
        let line_number = index
            .checked_add(1)
            .ok_or_else(|| invalid("IR line overflow"))?;
        if line.starts_with("define ") {
            if current.is_some() || !line.trim_end().ends_with('{') {
                return Err(invalid("unsupported function definition"));
            }
            let name = line
                .split_once('@')
                .and_then(|(_, tail)| tail.split_once('('))
                .map(|(name, _)| name)
                .ok_or_else(|| invalid("unsupported function symbol"))?;
            block = "entry".into();
            current = Some(Function {
                name: name.into(),
                entry: block.clone(),
                blocks: BTreeMap::new(),
            });
        } else if line == "}" {
            if let Some(function) = current.take() {
                functions.push(function);
            }
        } else if let Some(function) = &mut current {
            if let Some((label, _)) = line
                .split_once(':')
                .filter(|(label, _)| !label.is_empty() && !label.contains(char::is_whitespace))
            {
                block = label.into();
                if function.blocks.is_empty() {
                    function.entry = block.clone();
                }
                if function.blocks.insert(block.clone(), Vec::new()).is_some() {
                    return Err(invalid("duplicate IR basic block"));
                }
            } else if !line.trim().is_empty() && !line.trim_start().starts_with(';') {
                function
                    .blocks
                    .entry(block.clone())
                    .or_default()
                    .push(Instruction {
                        line: line_number,
                        text: line.trim().into(),
                    });
            }
        }
    }
    if current.is_some() {
        return Err(invalid("unterminated IR function"));
    }
    Ok(functions)
}

/// Finds direct calls by exact callee spelling, without treating comments as instructions.
fn calls(text: &str, name: &str) -> bool {
    text.split_whitespace()
        .any(|word| matches!(word, "call" | "invoke"))
        && text.contains(&format!("@{name}("))
}
/// Extracts the first pointer operand from a direct call.
fn operand(text: &str, name: &str) -> Option<String> {
    let (_, arguments) = text.split_once(&format!("@{name}("))?;
    let first = arguments.split([',', ')']).next()?;
    if !first.trim_start().starts_with("ptr ") {
        return None;
    }
    first
        .split_whitespace()
        .last()
        .filter(|word| *word == "null" || word.starts_with('%'))
        .map(str::to_owned)
}
/// Converts the supported context instructions into explicit semantic operations.
fn operation(text: &str) -> Operation {
    if calls(text, "IoGetTopLevelIrp") {
        return text
            .split_once(" = ")
            .filter(|(_, call)| call.contains(" ptr @IoGetTopLevelIrp()"))
            .map(|(value, _)| Operation::Capture(value.into()))
            .unwrap_or(Operation::Unknown);
    }
    if calls(text, "IoSetTopLevelIrp") {
        return operand(text, "IoSetTopLevelIrp")
            .filter(|_| text.contains("call void @IoSetTopLevelIrp"))
            .map(Operation::Set)
            .unwrap_or(Operation::Unknown);
    }
    if calls(text, "wdk_sys_IoCompleteRequest") {
        return operand(text, "wdk_sys_IoCompleteRequest")
            .filter(|_| text.contains("call void @wdk_sys_IoCompleteRequest"))
            .map(Operation::Complete)
            .unwrap_or(Operation::Unknown);
    }
    if let Some((value, comparison)) = text.split_once(" = icmp ") {
        let words: Vec<_> = comparison.split_whitespace().collect();
        if let [comparison, "ptr", pointer, null, ..] = words.as_slice()
            && matches!(*comparison, "eq" | "ne")
            && null.trim_end_matches(',') == "null"
        {
            return Operation::Compare(
                value.into(),
                pointer.trim_end_matches(',').into(),
                *comparison == "eq",
            );
        }
    }
    let words: Vec<_> = text.split_whitespace().collect();
    match words.as_slice() {
        ["br", "label", target, ..] => {
            Operation::Jump(target.trim_start_matches('%').trim_end_matches(',').into())
        }
        ["br", "i1", predicate, "label", yes, "label", no, ..] => Operation::Branch(
            predicate.trim_end_matches(',').into(),
            yes.trim_start_matches('%').trim_end_matches(',').into(),
            no.trim_start_matches('%').trim_end_matches(',').into(),
        ),
        _ => Operation::Unknown,
    }
}

/// Checks both possible initial contexts with finite instruction traversal and bypass analysis.
/// # Errors
/// Returns unprotected completion, unmodeled instructions, invalid control flow or budget errors.
pub(crate) fn check(text: &str, budget: usize) -> io::Result<Value> {
    if budget == 0 {
        return Err(invalid("block budget must be positive"));
    }
    let mut sites = BTreeSet::new();
    let mut covered = BTreeSet::new();
    let mut evidence = Vec::new();
    for function in parse(text)? {
        for (label, sequence) in &function.blocks {
            for (position, instruction) in sequence.iter().enumerate() {
                if calls(&instruction.text, "wdk_sys_IoCompleteRequest") {
                    sites.insert(instruction.line);
                }
                if !calls(&instruction.text, "IoGetTopLevelIrp") {
                    continue;
                }
                let Operation::Capture(previous) = operation(&instruction.text) else {
                    return Err(invalid("unsupported context capture"));
                };
                let mut region = BTreeSet::from([label.clone()]);
                for initially_null in [true, false] {
                    let mut marker = previous.clone();
                    let mut predicates = BTreeMap::new();
                    let mut visited = BTreeSet::new();
                    let mut next = (
                        label.clone(),
                        position
                            .checked_add(1)
                            .ok_or_else(|| invalid("instruction overflow"))?,
                    );
                    'walk: loop {
                        if visited.len() >= budget || !visited.insert(next.clone()) {
                            return Err(invalid("cycle or block budget exhausted"));
                        }
                        region.insert(next.0.clone());
                        let block = function
                            .blocks
                            .get(&next.0)
                            .ok_or_else(|| invalid("unknown branch target"))?;
                        for (index, candidate) in block.iter().enumerate().skip(next.1) {
                            match operation(&candidate.text) {
                                Operation::Compare(predicate, pointer, equals)
                                    if pointer == previous =>
                                {
                                    predicates.insert(predicate, initially_null == equals);
                                }
                                Operation::Set(value) => marker = value,
                                Operation::Complete(irp) => {
                                    if marker.as_str()
                                        != if initially_null {
                                            irp.as_str()
                                        } else {
                                            previous.as_str()
                                        }
                                    {
                                        return Err(invalid("incorrect completion marker"));
                                    }
                                    let following = block
                                        .get(
                                            index
                                                .checked_add(1)
                                                .ok_or_else(|| invalid("instruction overflow"))?,
                                        )
                                        .ok_or_else(|| {
                                            invalid("missing immediate context restoration")
                                        })?;
                                    if !matches!(operation(&following.text), Operation::Set(value) if value == previous)
                                    {
                                        return Err(invalid(
                                            "missing immediate context restoration",
                                        ));
                                    }
                                    covered.insert(candidate.line);
                                    evidence.push(json!({"function": function.name, "capture_line": instruction.line, "completion_line": candidate.line,
                                        "restore_line": following.line, "initial_context": if initially_null { "null" } else { "existing" }}));
                                    break 'walk;
                                }
                                Operation::Jump(target) => {
                                    next = (target, 0);
                                    continue 'walk;
                                }
                                Operation::Branch(predicate, yes, no) => {
                                    let selected = *predicates
                                        .get(&predicate)
                                        .ok_or_else(|| invalid("unmodeled branch predicate"))?;
                                    next = (if selected { yes } else { no }, 0);
                                    continue 'walk;
                                }
                                _ => {
                                    return Err(invalid(format!(
                                        "unmodeled instruction at line {}: {}",
                                        candidate.line, candidate.text
                                    )));
                                }
                            }
                        }
                        return Err(invalid("incomplete control flow after capture"));
                    }
                }
                region.remove(label);
                if region.contains(&function.entry) {
                    return Err(invalid("function entry bypasses context capture"));
                }
                for (predecessor, block) in &function.blocks {
                    let enters = block
                        .iter()
                        .any(|candidate| match operation(&candidate.text) {
                            Operation::Jump(target) => region.contains(&target),
                            Operation::Branch(_, yes, no) => {
                                region.contains(&yes) || region.contains(&no)
                            }
                            _ => false,
                        });
                    if enters
                        && (predecessor != label && !region.contains(predecessor)
                            || block.iter().enumerate().any(|(index, candidate)| {
                                (predecessor != label || index > position)
                                    && calls(&candidate.text, "wdk_sys_IoCompleteRequest")
                            }))
                    {
                        return Err(invalid("control flow bypasses context capture"));
                    }
                }
            }
        }
    }
    if sites.is_empty() || sites != covered {
        return Err(invalid("missing or unprotected native completion sites"));
    }
    Ok(
        json!({"completion_sites": sites.len(), "paths": evidence.len(), "evidence": evidence,
        "scope": "Generated IR direct completion context capture/install/restore; aliases, indirect calls and live behavior are unverified."}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Tests both initial contexts and independently malformed protocol paths.
    /// # Errors
    /// Returns unexpected parser or analysis failures.
    /// # Panics
    /// Panics if invalid completion protocols are admitted.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions fail the diagnostic contract test while preparation errors retain their context"
    )]
    fn completion_paths() -> io::Result<()> {
        let ir = "define void @complete(ptr %irp) {\nentry:\n %previous = tail call noundef ptr @IoGetTopLevelIrp() #0\n %is_null = icmp eq ptr %previous, null\n br i1 %is_null, label %install, label %complete\ninstall:\n tail call void @IoSetTopLevelIrp(ptr noundef nonnull %irp) #0\n br label %complete\ncomplete:\n tail call void @wdk_sys_IoCompleteRequest(ptr noundef nonnull %irp, i8 0) #0\n tail call void @IoSetTopLevelIrp(ptr noundef %previous) #0\n ret void\n}\n";
        assert_eq!(check(ir, 64)?.get("paths"), Some(&json!(2)));
        assert!(check(&ir.replace("ptr noundef %previous", "ptr null"), 64).is_err());
        assert!(check(&ir.replace("br label %complete", "br label %install"), 64).is_err());
        assert!(check(ir, 1).is_err());
        assert!(check(&ir.replace(" ret void", " br label %complete"), 64).is_err());
        Ok(())
    }
}
