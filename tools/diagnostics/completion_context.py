"""Check top-level context around direct native IRP completion calls in LLVM IR.

This deliberately recognizes only capture, null comparison, conditional marker
installation, completion and immediate restoration. Unknown effects, branches
or IR forms fail closed; aliases/indirect calls are outside this analysis.
This is not a general LLVM interpreter or live proof.
"""

from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Instruction:
    line: int
    text: str


def functions(text):
    result, current, block = [], None, None
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("define "):
            if current is not None or not line.rstrip().endswith("{"):
                raise ValueError(f"unsupported function definition at line {number}")
            current = (line.split("@", 1)[1].split("(", 1)[0], {})
            block = "entry"
        elif current is not None:
            if line == "}":
                result.append(current)
                current, block = None, None
            elif match := re.match(r"^([-\w.$]+):", line):
                block = match[1]
                if block in current[1]:
                    raise ValueError(f"duplicate block at line {number}")
                current[1][block] = []
            elif line.strip() and not line.lstrip().startswith(";"):
                current[1].setdefault(block, []).append(Instruction(number, line.strip()))
    if current is not None:
        raise ValueError("unterminated IR function")
    return result


def native_call(text, name):
    return re.search(r"\b(?:call|invoke)\b[^@]*@" + re.escape(name) + r"\(", text) is not None


def marker_argument(text):
    match = re.search(r"\bcall\s+void\s+@IoSetTopLevelIrp\(ptr(?:\s+\w+)*?\s+(%[-\w.$]+|null)\)", text)
    return match[1] if match else None


def check_completion(text, max_blocks=64):
    if max_blocks < 1:
        raise ValueError("block budget must be positive")
    sites, covered, records = set(), set(), []
    for name, blocks in functions(text):
        for label, instructions in blocks.items():
            for position, capture in enumerate(instructions):
                if native_call(capture.text, "wdk_sys_IoCompleteRequest"):
                    sites.add(capture.line)
                if not native_call(capture.text, "IoGetTopLevelIrp"):
                    continue
                get = re.match(r"^(%[-\w.$]+) = (?:tail |notail |musttail )?call\b[^@]*\bptr\s+@IoGetTopLevelIrp\(\)", capture.text)
                if not get:
                    raise ValueError(f"unsupported context capture at line {capture.line}")
                previous = get[1]
                region = {label}
                for originally_null in (True, False):
                    marker, predicates, visited = previous, {}, set()
                    block, index = label, position + 1
                    while True:
                        state = (block, index)
                        if state in visited or len(visited) >= max_blocks:
                            raise ValueError(f"cycle or block budget exhausted after line {capture.line}")
                        visited.add(state)
                        if block not in blocks:
                            raise ValueError(f"unknown branch target {block}")
                        region.add(block)
                        sequence = blocks[block]
                        completed, branched = False, False
                        for offset in range(index, len(sequence)):
                            instruction = sequence[offset]
                            value = instruction.text
                            comparison = re.match(r"^(%[-\w.$]+) = icmp (eq|ne) ptr (%[-\w.$]+), null(?:,.*)?$", value)
                            if comparison and comparison[3] == previous:
                                predicates[comparison[1]] = originally_null == (comparison[2] == "eq")
                                continue
                            setting = marker_argument(value)
                            if setting is not None:
                                marker = setting
                                continue
                            if native_call(value, "wdk_sys_IoCompleteRequest"):
                                argument = re.search(r"\bcall\s+void\s+@wdk_sys_IoCompleteRequest\(ptr(?:\s+\w+)*?\s+(%[-\w.$]+),", value)
                                if not argument or marker != (argument[1] if originally_null else previous):
                                    raise ValueError(f"incorrect completion marker at line {instruction.line}")
                                following = sequence[offset + 1:]
                                if not following or marker_argument(following[0].text) != previous:
                                    raise ValueError(f"missing immediate context restoration at line {instruction.line}")
                                covered.add(instruction.line)
                                records.append({"function": name, "capture_line": capture.line,
                                                "completion_line": instruction.line,
                                                "restore_line": following[0].line,
                                                "initial_context": "null" if originally_null else "existing"})
                                completed = True
                                break
                            unconditional = re.match(r"^br label %([-\w.$]+)(?:,.*)?$", value)
                            conditional = re.match(r"^br i1 (%[-\w.$]+), label %([-\w.$]+), label %([-\w.$]+)(?:,.*)?$", value)
                            if unconditional:
                                block = unconditional[1]
                            elif conditional and conditional[1] in predicates:
                                block = conditional[2] if predicates[conditional[1]] else conditional[3]
                            else:
                                raise ValueError(f"unmodeled instruction at line {instruction.line}: {value}")
                            index, branched = 0, True
                            break
                        if completed:
                            break
                        if not branched:
                            raise ValueError(f"incomplete control flow after line {capture.line}")
                # A completion path must not admit an entry bypassing capture,
                # including a loop after restoration that completes again.
                guarded = region - {label}
                if next(iter(blocks)) in guarded:
                    raise ValueError(f"function entry bypasses context capture at line {capture.line}")
                for predecessor, sequence in blocks.items():
                    targets = set(re.findall(r"\blabel %([-\w.$]+)", "\n".join(item.text for item in sequence)))
                    if not targets & guarded:
                        continue
                    before_branch = sequence[position + 1:] if predecessor == label else sequence
                    if predecessor not in region or any(native_call(item.text, "wdk_sys_IoCompleteRequest") for item in before_branch):
                        raise ValueError(f"control flow bypasses context capture at line {capture.line}")
    if not sites or sites != covered:
        raise ValueError(f"missing or unprotected native completion sites: {sorted(sites - covered)}")
    return {"completion_sites": len(sites), "paths": len(records), "evidence": records,
            "scope": "Generated IR direct completion context capture/install/restore; aliases, indirect calls and live behavior are unverified."}
