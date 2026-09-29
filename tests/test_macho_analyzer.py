"""Tests for Mach-O Analyzer (MobiAttack V2)."""

from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest

from src.ios.macho_analyzer import analyze_macho_executable, validate_macho_magic


def _build_synthetic_macho_64_arm64(linked_dylib: str = "/usr/lib/libSystem.B.dylib") -> bytes:
    """Builds a minimal synthetic Mach-O 64-bit arm64 binary with LC_LOAD_DYLIB and LC_UUID."""
    magic = 0xFEEDFACF  # MH_MAGIC_64 (big-endian)
    cputype = 0x0100000C  # CPU_TYPE_ARM64
    cpusubtype = 0
    filetype = 0x2  # MH_EXECUTE
    ncmds = 2
    flags = 0x00200085
    reserved = 0

    # Command 1: LC_LOAD_DYLIB (cmd=0xC)
    cmd1_type = 0xC
    # string offset is 24 bytes from start of load command
    dylib_name_bytes = linked_dylib.encode("utf-8") + b"\x00"
    # pad to 8-byte boundary
    pad_len = (8 - (len(dylib_name_bytes) % 8)) % 8
    dylib_payload = dylib_name_bytes + (b"\x00" * pad_len)
    cmd1_size = 24 + len(dylib_payload)
    cmd1 = struct.pack(">IIIIII", cmd1_type, cmd1_size, 24, 0, 0, 0) + dylib_payload

    # Command 2: LC_UUID (cmd=0x1B, size=24, uuid=16 bytes)
    cmd2_type = 0x1B
    cmd2_size = 24
    dummy_uuid = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    cmd2 = struct.pack(">II", cmd2_type, cmd2_size) + dummy_uuid

    sizeofcmds = len(cmd1) + len(cmd2)
    header = struct.pack(">IIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags) + struct.pack(">I", reserved)

    return header + cmd1 + cmd2


def _build_synthetic_fat_binary() -> bytes:
    """Builds a minimal synthetic FAT binary with arm64 and x86_64 arch headers."""
    magic = 0xCAFEBABE
    nfat = 2
    header = struct.pack(">II", magic, nfat)

    # Arch 1: arm64
    arch1 = struct.pack(">IIIII", 0x0100000C, 0, 4096, 1024, 14)
    # Arch 2: x86_64
    arch2 = struct.pack(">IIIII", 0x01000007, 3, 8192, 1024, 12)

    return header + arch1 + arch2 + (b"\x00" * 8192)


class TestMachoAnalyzer(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_validate_magic_non_macho(self):
        non_macho = self.temp_path / "not_macho.txt"
        non_macho.write_bytes(b"This is just plain text")
        res = validate_macho_magic(non_macho)
        self.assertFalse(res["is_macho"])

    def test_synthetic_macho_64_arm64(self):
        macho_bytes = _build_synthetic_macho_64_arm64("/System/Library/Frameworks/UIKit.framework/UIKit")
        macho_file = self.temp_path / "AppBinary"
        macho_file.write_bytes(macho_bytes)

        res = analyze_macho_executable(macho_file, use_system_tools=False)
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["is_macho"])
        self.assertEqual(res["architectures"], ["arm64"])
        self.assertEqual(res["bitness"], 64)
        self.assertEqual(res["file_type"], "Mach-O executable")
        self.assertIn("/System/Library/Frameworks/UIKit.framework/UIKit", res["linked_libraries"])
        self.assertEqual(res["uuid"], "01020304-0506-0708-090A-0B0C0D0E0F10")

    def test_synthetic_fat_binary(self):
        fat_bytes = _build_synthetic_fat_binary()
        fat_file = self.temp_path / "FatBinary"
        fat_file.write_bytes(fat_bytes)

        res = analyze_macho_executable(fat_file, use_system_tools=False)
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["is_macho"])
        self.assertIn("arm64", res["architectures"])
        self.assertIn("x86_64", res["architectures"])
        self.assertEqual(res["bitness"], 64)

    def test_missing_binary(self):
        res = analyze_macho_executable(self.temp_path / "nonexistent_bin")
        self.assertEqual(res["status"], "not_found")
        self.assertFalse(res["is_macho"])

    def test_macho_encryption_info_factual_property(self):
        # Build Mach-O 64-bit with LC_ENCRYPTION_INFO_64 (cmd=0x2C, size=20, cryptoff, cryptsize, cryptid)
        magic = 0xFEEDFACF
        cputype = 0x0100000C
        cpusubtype = 0
        filetype = 0x2
        ncmds = 1
        flags = 0x00200085
        reserved = 0

        # LC_ENCRYPTION_INFO_64 (0x2C)
        cmd_type = 0x2C
        cmd_size = 20
        cryptoff = 0x4000
        cryptsize = 0x8000
        cryptid = 1
        cmd_bytes = struct.pack(">IIIII", cmd_type, cmd_size, cryptoff, cryptsize, cryptid)

        header = struct.pack(">IIIIIII", magic, cputype, cpusubtype, filetype, ncmds, len(cmd_bytes), flags) + struct.pack(">I", reserved)
        macho_file = self.temp_path / "EncryptedBinary"
        macho_file.write_bytes(header + cmd_bytes)

        res = analyze_macho_executable(macho_file, use_system_tools=False)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["cryptid"], 1)
        self.assertEqual(res["encryption_state"], "encrypted")
        enc = res["encryption_info"]
        self.assertIsNotNone(enc)
        self.assertEqual(enc["load_command"], "LC_ENCRYPTION_INFO_64")
        self.assertEqual(enc["evidence"]["nature"], "factual_binary_property")
        # Ensure it is purely factual binary evidence and not flagged as a failure
        self.assertNotIn("vulnerability", res)
        self.assertNotIn("verdict", res)


if __name__ == "__main__":
    unittest.main()
