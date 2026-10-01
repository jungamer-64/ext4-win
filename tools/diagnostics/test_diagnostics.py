"""Contract tests with synthetic wire formats and independent checksum answers."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from artifact import read_bundle
from completion_context import check_completion
from diagnose import host_tools, parser, wait_sections
from extent_checksum import check_extent, crc32c
from pe_stack import PeImage
from windows import resolve_driver_path, service_identity, volume_information


def pe_fixture():
    """Two AMD64 functions, at a non-default image base, with fixed prologs."""
    data = bytearray(2048)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x8664, 2)
    struct.pack_into("<H", data, 0x94, 240)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 136, 0x2000, 24)
    section = optional + 240
    struct.pack_into("<IIII", data, section + 8, 512, 0x1000, 512, 512)
    struct.pack_into("<IIII", data, section + 48, 1024, 0x2000, 1024, 1024)
    struct.pack_into("<III", data, 1024, 0x1000, 0x1100, 0x2040)
    struct.pack_into("<III", data, 1036, 0x1100, 0x1200, 0x2050)
    # ALLOC_LARGE(32 * 8), PUSH_NONVOL: 264 bytes, three slots.
    data[1088:1098] = bytes([1, 8, 3, 0, 8, 1, 32, 0, 1, 0x30])
    # ALLOC_SMALL(info=2): 24 bytes.
    data[1104:1110] = bytes([1, 4, 1, 0, 4, 0x22])
    return data


def extent_fixture(size=4096, maximum=340, checksum=0x7A50AE35):
    superblock = bytearray(1024)
    struct.pack_into("<I", superblock, 24, {1024: 0, 2048: 1, 4096: 2}[size])
    struct.pack_into("<H", superblock, 56, 0xEF53)
    struct.pack_into("<I", superblock, 96, 0x2000)
    struct.pack_into("<I", superblock, 100, 0x400)
    struct.pack_into("<I", superblock, 0x270, 0x12345678)
    superblock[0x175] = 1
    block = bytearray(size)
    struct.pack_into("<HHHHI", block, 0, 0xF30A, 1, maximum, 0, 0)
    struct.pack_into("<IHHI", block, 12, 0, 3, 0, 0x10203)
    struct.pack_into("<I", block, 12 + maximum * 12, checksum)
    return superblock, block


CONTEXT_IR = """define void @complete(ptr %irp) {
entry:
  %previous = tail call noundef ptr @IoGetTopLevelIrp() #0
  %is_null = icmp eq ptr %previous, null
  br i1 %is_null, label %install, label %complete
install:
  tail call void @IoSetTopLevelIrp(ptr noundef nonnull %irp) #0
  br label %complete
complete:
  tail call void @wdk_sys_IoCompleteRequest(ptr noundef nonnull %irp, i8 0) #0
  tail call void @IoSetTopLevelIrp(ptr noundef %previous) #0
  ret void
}
"""


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.records = ["manifest_version=1", "artifact_id=" + "1" * 32,
                        "source_snapshot_sha256=" + "2" * 64]
        for kind, data in [("sys", bytes(pe_fixture())), ("map", b" 0001:00000000 first 0000000140001000 f\n"), ("ir", CONTEXT_IR.encode())]:
            (self.root / ("driver." + kind)).write_bytes(data)
            self.records.extend([f"artifact.{kind}.path=driver.{kind}",
                                 f"artifact.{kind}.sha256={hashlib.sha256(data).hexdigest()}"])
        self.write_manifest()

    def write_manifest(self):
        (self.root / "manifest-v1.txt").write_text("\n".join(self.records), encoding="utf-8")

    def test_reads_exact_verified_bytes(self):
        snapshot = read_bundle(self.root, ("sys", "map", "ir"))
        self.assertEqual(snapshot.contents["ir"], CONTEXT_IR.encode())
        (self.root / "driver.ir").write_bytes(b"later content")
        self.assertEqual(snapshot.contents["ir"], CONTEXT_IR.encode())
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            read_bundle(self.root, ("ir",))

    def test_manifest_rejects_ambiguity_and_path_escape(self):
        self.records.append("artifact_id=" + "3" * 32)
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            read_bundle(self.root, ("sys",))
        self.records.pop()
        self.records = [record.replace("path=driver.sys", "path=../driver.sys") for record in self.records]
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "bundle-relative"):
            read_bundle(self.root, ("sys",))

    def test_cli_from_another_directory_and_optimized_python(self):
        script = Path(__file__).with_name("diagnose.py").resolve()
        completed = subprocess.run([sys.executable, "-B", str(script), "stack", str(self.root), "--rva", "0x1010"],
                                   cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["addresses"][0]["offset_in_function"], 16)
        (self.root / "driver.sys").write_bytes(b"corrupt")
        rejected = subprocess.run([sys.executable, "-B", "-O", str(script), "stack", str(self.root)],
                                  cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("identity mismatch", rejected.stderr)

    def test_checksum_cli_preserves_mismatch_outcome(self):
        script = Path(__file__).with_name("diagnose.py").resolve()
        sb, block = extent_fixture()
        sb_path, block_path = self.root / "superblock.bin", self.root / "extent.bin"
        sb_path.write_bytes(sb)
        block[12] ^= 1
        block_path.write_bytes(block)
        result = subprocess.run([sys.executable, "-B", "-O", str(script), "extent",
                                 "--superblock", str(sb_path), "--block", str(block_path),
                                 "--inode", "0x1234", "--generation", "0x01020304"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertFalse(json.loads(result.stdout)["matches"])


class PeTests(unittest.TestCase):
    def test_fixed_frames_and_preferred_base(self):
        records = PeImage(pe_fixture()).frames(" 0001:00000000 first 0000000140001000 f\n")
        self.assertEqual([record["fixed_stack_bytes"] for record in records], [264, 24])
        self.assertEqual(records[0]["symbols"], ["first"])

    def test_chained_unwind_and_cycle(self):
        data = pe_fixture()
        data[1104:1108] = bytes([1 | (4 << 3), 0, 0, 0])
        struct.pack_into("<III", data, 1108, 0x1000, 0x1100, 0x2040)
        self.assertEqual(PeImage(data).frames("")[1]["fixed_stack_bytes"], 264)
        struct.pack_into("<I", data, 1116, 0x2050)
        with self.assertRaisesRegex(ValueError, "chained"):
            PeImage(data).frames("")

    def test_truncated_operands_and_unsupported_encoding(self):
        data = pe_fixture()
        data[1090] = 1
        with self.assertRaisesRegex(ValueError, "truncated"):
            PeImage(data).frames("")
        data = pe_fixture()
        data[1104] = 3
        with self.assertRaisesRegex(ValueError, "unsupported"):
            PeImage(data).frames("")
        with self.assertRaisesRegex(ValueError, "truncated"):
            PeImage(bytes(pe_fixture()[:300]))

    def test_version_two_epilog_descriptors_do_not_allocate(self):
        data = pe_fixture()
        data[1104:1114] = bytes([2, 4, 3, 0, 1, 6, 3, 6, 4, 0x22])
        self.assertEqual(PeImage(data).frames("")[1]["fixed_stack_bytes"], 24)


class CompletionTests(unittest.TestCase):
    def test_context_preservation_for_both_initial_states(self):
        report = check_completion(CONTEXT_IR)
        self.assertEqual(report["completion_sites"], 1)
        self.assertEqual(report["paths"], 2)
        self.assertEqual({item["initial_context"] for item in report["evidence"]}, {"null", "existing"})
        self.assertEqual(check_completion(CONTEXT_IR.replace("tail call noundef ptr", "call ptr"))["paths"], 2)

    def test_missing_marker_restoration_and_unknown_effect(self):
        for changed, reason in [
            (CONTEXT_IR.replace("@IoSetTopLevelIrp(ptr noundef nonnull %irp)", "@IoSetTopLevelIrp(ptr null)"), "marker"),
            (CONTEXT_IR.replace("@IoSetTopLevelIrp(ptr noundef %previous)", "@IoSetTopLevelIrp(ptr null)"), "restoration"),
            (CONTEXT_IR.replace("%is_null =", "call void @unknown()\n  %is_null ="), "unmodeled"),
        ]:
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                check_completion(changed)

    def test_unprotected_completion_and_cycles_are_not_success(self):
        with self.assertRaisesRegex(ValueError, "unprotected"):
            check_completion("define void @bare(ptr %irp) {\nentry:\n  call void @wdk_sys_IoCompleteRequest(ptr %irp, i8 0)\n  ret void\n}\n")
        with self.assertRaisesRegex(ValueError, "cycle|budget"):
            check_completion(CONTEXT_IR.replace("br label %complete", "br label %install"))
        with self.assertRaisesRegex(ValueError, "budget"):
            check_completion(CONTEXT_IR, max_blocks=1)

    def test_repeated_completion_requires_fresh_context_capture(self):
        ir = CONTEXT_IR.replace("ptr %irp)", "ptr %irp, i1 %again)", 1)
        ir = ir.replace("  ret void", "  br i1 %again, label %complete, label %done\ndone:\n  ret void")
        with self.assertRaisesRegex(ValueError, "bypasses"):
            check_completion(ir)
        # Reentering the capture block establishes a fresh completion context.
        self.assertEqual(check_completion(ir.replace("label %complete, label %done", "label %entry, label %done"))["paths"], 2)


class ExtentTests(unittest.TestCase):
    def test_standard_crc_and_fixed_extent_vectors(self):
        self.assertEqual(crc32c(0xFFFFFFFF, b"123456789") ^ 0xFFFFFFFF, 0xE3069283)
        for size, maximum, answer in [(1024, 84, 0x992A6622), (2048, 169, 0x0DE5C751),
                                      (4096, 340, 0x7A50AE35), (4096, 1, 0xB6CF3F8E)]:
            with self.subTest(size=size, maximum=maximum):
                sb, block = extent_fixture(size, maximum, answer)
                self.assertTrue(check_extent(sb, 0x1234, 0x01020304, block)["matches"])
                block[12] ^= 1
                self.assertFalse(check_extent(sb, 0x1234, 0x01020304, block)["matches"])

    def test_tail_is_capacity_based_and_padding_is_excluded(self):
        sb, block = extent_fixture(4096, 1, 0xB6CF3F8E)
        block[-1] = 42
        self.assertTrue(check_extent(sb, 0x1234, 0x01020304, block)["matches"])
        struct.pack_into("<H", block, 4, 341)
        with self.assertRaisesRegex(ValueError, "tail"):
            check_extent(sb, 8, 0, block)

    def test_uuid_seed_and_invalid_geometry(self):
        sb, block = extent_fixture()
        struct.pack_into("<I", sb, 96, 0)
        # Fixed zero-UUID answer obtained from the e2fsprogs CRC32C oracle.
        struct.pack_into("<I", block, 4092, 0xFB541659)
        report = check_extent(sb, 0x1234, 0x01020304, block)
        self.assertTrue(report["matches"])
        for inode, generation in [(0, 0), (1, -1), (1, 0x100000000)]:
            with self.assertRaisesRegex(ValueError, "range"):
                check_extent(sb, inode, generation, block)
        with self.assertRaisesRegex(ValueError, "geometry"):
            check_extent(sb, 1, 0, block[:-1])


class DiagnosticTests(unittest.TestCase):
    def test_host_inventory_and_explicit_inputs(self):
        self.assertIn("cargo", host_tools()["path_tools"])
        self.assertEqual(parser().parse_args(["volume", "C:\\"]).path, "C:\\")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser().parse_args(["stack", "bundle", "--limit", "0"])

    def test_wait_sections_preserve_matches_and_report_truncation(self):
        text = "header\n\n        THREAD aaa\n ext4win!one\n\n        THREAD bbb\n unrelated\n        THREAD ccc\n ext4win!two\nquit:\n"
        report = wait_sections(text, ["ext4win!"], 1)
        self.assertEqual((report["thread_sections"], report["matching_sections"]), (3, 2))
        self.assertTrue(report["truncated"])
        self.assertTrue(report["debugger_quit_observed"])
        self.assertIn("aaa", report["sections"][0])

    def test_driver_path_normalization(self):
        expected = r"D:\Windows\System32\drivers\sample.sys"
        for path in (r"\SystemRoot\System32\drivers\sample.sys", r"\??\D:\Windows\System32\drivers\sample.sys",
                     r"System32\drivers\sample.sys", '"' + expected + '"'):
            with self.subTest(path=path):
                self.assertEqual(str(resolve_driver_path(path, r"D:\Windows")), expected)
        with self.assertRaisesRegex(ValueError, "absolute"):
            resolve_driver_path("C:relative.sys", r"D:\Windows")

    @unittest.skipUnless(os.name == "nt", "native volume query requires Windows")
    def test_native_queries_on_host_temporary_directory(self):
        report = volume_information(tempfile.gettempdir())
        self.assertTrue(report["success"], report)
        self.assertEqual(len(report["queries"]), 5)

    @unittest.skipUnless(os.name == "nt", "service registry requires Windows")
    def test_missing_service_is_a_failure(self):
        with self.assertRaises(OSError):
            service_identity("ext4win-diagnostic-absent-" + "0" * 32)


if __name__ == "__main__":
    unittest.main()
