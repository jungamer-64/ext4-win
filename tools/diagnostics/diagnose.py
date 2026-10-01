"""Read-only developer diagnostics; run with --help for explicit inputs.

Results go to stdout. No artifact, source, service, registry or disk is modified.
The artifact commands inspect a historical snapshot chosen by the caller; use
the canonical production gate to generate evidence for the current source.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys

from artifact import read_bundle
from completion_context import check_completion
from extent_checksum import check_extent
from pe_stack import PeImage
from windows import service_identity, volume_information


def host_tools():
    environment = {name: os.environ.get(name) for name in (
        "CC", "CXX", "RUSTFLAGS", "RUSTC_LINKER", "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER", "LIBCLANG_PATH", "WDKContentRoot")}
    names = ("cargo", "rustc", "python", "cl", "clang-cl", "link", "lld-link",
             "llvm-readobj", "llvm-objdump", "llvm-symbolizer", "cdb", "kd", "wsl")
    tools = {name: shutil.which(name) for name in names}
    installed = set()
    if os.name == "nt":
        for variable in ("ProgramFiles", "ProgramFiles(x86)"):
            if base := os.environ.get(variable):
                sdk = Path(base) / "Windows Kits" / "10" / "Debuggers"
                for name in ("cdb.exe", "kd.exe"):
                    installed.update(str(path) for path in sdk.glob("*/" + name) if path.is_file())
                llvm = Path(base) / "LLVM" / "bin"
                installed.update(str(llvm / (name + ".exe")) for name in names
                                 if (llvm / (name + ".exe")).is_file())
    return {"platform": sys.platform, "build_environment": environment,
            "path_tools": tools, "installed_tools": sorted(installed)}


def wait_sections(text, terms, limit):
    """Retain complete matching debugger thread sections, marking truncation."""
    if limit < 1 or not terms or any(not term for term in terms):
        raise ValueError("positive section limit and nonempty match terms are required")
    sections = re.split(r"(?=^[ \t]*THREAD[ \t]+)", text, flags=re.MULTILINE)
    threads = [section for section in sections if re.match(r"^[ \t]*THREAD[ \t]+", section)]
    matches = [section for section in threads if any(term in section for term in terms)]
    return {"thread_sections": len(threads), "matching_sections": len(matches),
            "truncated": len(matches) > limit, "sections": matches[:limit],
            "debugger_quit_observed": "quit:" in text}


def positive(value):
    parsed = int(value, 0)
    if parsed < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return parsed


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    tasks = result.add_subparsers(dest="command", required=True)
    tasks.add_parser("host", help="locate build and debugger tools without launching them")
    service = tasks.add_parser("service", help="hash the configured Windows driver ImagePath")
    service.add_argument("--name", default="ext4win")
    volume = tasks.add_parser("volume", help="query native volume metadata (may block in the driver)")
    volume.add_argument("path", help="explicit file or directory path; no default drive")
    stack = tasks.add_parser("stack", help="rank AMD64 fixed prolog frames in a production bundle")
    stack.add_argument("bundle", type=Path)
    stack.add_argument("--limit", type=positive, default=20)
    stack.add_argument("--rva", type=lambda value: int(value, 0), action="append", default=[],
                       help="also locate an image-relative address within its function")
    completion = tasks.add_parser("completion", help="verify IRP completion context in a production bundle")
    completion.add_argument("bundle", type=Path)
    completion.add_argument("--max-blocks", type=positive, default=64)
    extent = tasks.add_parser("extent", help="check one captured external extent block checksum")
    extent.add_argument("--superblock", type=Path, required=True)
    extent.add_argument("--block", type=Path, required=True)
    extent.add_argument("--inode", type=positive, required=True)
    extent.add_argument("--generation", type=lambda value: int(value, 0), required=True)
    waits = tasks.add_parser("waits", help="extract matching debugger thread sections from a log")
    waits.add_argument("log", type=Path)
    waits.add_argument("--encoding", default="utf-8")
    waits.add_argument("--match", action="append", help="case-sensitive substring; repeat for alternatives")
    waits.add_argument("--limit", type=positive, default=20)
    return result


def execute(arguments):
    if arguments.command == "host":
        return host_tools(), True
    if arguments.command == "service":
        return service_identity(arguments.name), True
    if arguments.command == "volume":
        report = volume_information(arguments.path)
        return report, report["success"]
    if arguments.command in ("stack", "completion"):
        kinds = ("sys", "map") if arguments.command == "stack" else ("sys", "map", "ir")
        snapshot = read_bundle(arguments.bundle, kinds)
        if arguments.command == "stack":
            frames = PeImage(snapshot.contents["sys"]).frames(snapshot.contents["map"].decode("utf-8"))
            addresses = []
            for rva in arguments.rva:
                match = next((frame for frame in frames if frame["begin_rva"] <= rva < frame["end_rva"]), None)
                addresses.append({"rva": rva, "frame": match,
                                  "offset_in_function": rva - match["begin_rva"] if match else None})
            report = {"function_count": len(frames), "largest_frames": frames[:arguments.limit],
                      "addresses": addresses,
                      "scope": "Fixed prolog frames only; excludes return addresses, callees, dynamic allocation and interrupts."}
        else:
            report = check_completion(snapshot.contents["ir"].decode("utf-8"), arguments.max_blocks)
        return {"artifact_id": snapshot.identity, "recorded_source_sha256": snapshot.source_digest,
                "artifact_sha256": dict(snapshot.digests), **report}, True
    if arguments.command == "extent":
        superblock, block = arguments.superblock.read_bytes(), arguments.block.read_bytes()
        report = check_extent(superblock, arguments.inode, arguments.generation, block)
        return {"inode": arguments.inode, "generation": arguments.generation,
                "superblock_sha256": hashlib.sha256(superblock).hexdigest(),
                "block_sha256": hashlib.sha256(block).hexdigest(), **report}, report["matches"]
    text = arguments.log.read_text(encoding=arguments.encoding)
    terms = arguments.match or ["ext4win!", "FltpPerformPost", "FltpQueryInformation",
                                "CcCopyRead", "CcWaitFor", "FsRtlCheckOplock"]
    return wait_sections(text, terms, arguments.limit), True


def main():
    arguments = parser().parse_args()
    try:
        report, success = execute(arguments)
    except (OSError, ValueError, UnicodeError, LookupError) as error:
        print(json.dumps({"success": False, "error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps({"success": success, **report}, indent=2, ensure_ascii=True))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
