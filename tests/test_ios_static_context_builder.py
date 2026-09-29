"""Tests for iOS Static Context Builder (MobiAttack V2)."""

from __future__ import annotations

from pathlib import Path
import plistlib
import struct
import tempfile
import unittest

from src.ios.ios_static_context_builder import build_ios_static_context


def _build_synthetic_macho_bytes() -> bytes:
    magic = 0xFEEDFACF
    cputype = 0x0100000C  # arm64
    cpusubtype = 0
    filetype = 0x2
    ncmds = 1
    flags = 0
    reserved = 0
    cmd = struct.pack(">IIIIII", 0xC, 24, 24, 0, 0, 0)
    sizeofcmds = len(cmd)
    header = struct.pack(">IIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags) + struct.pack(">I", reserved)
    return header + cmd


class TestIosStaticContextBuilder(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.app_dir = self.temp_path / "Payload" / "DemoApp.app"
        self.app_dir.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_build_ios_static_context_full(self):
        # 1. Info.plist
        info_plist = {
            "CFBundleIdentifier": "com.example.demoapp",
            "CFBundleName": "DemoApp",
            "CFBundleExecutable": "DemoBinary",
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "100",
            "MinimumOSVersion": "16.0",
            "NSCameraUsageDescription": "Camera required.",
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoads": False,
            },
        }
        with open(self.app_dir / "Info.plist", "wb") as f:
            plistlib.dump(info_plist, f, fmt=plistlib.FMT_XML)

        # 2. Executable
        (self.app_dir / "DemoBinary").write_bytes(_build_synthetic_macho_bytes())

        # 3. Resource & config
        (self.app_dir / "config.json").write_text('{"api": "https://api.demo.com/v1"}')

        ctx = build_ios_static_context(
            app_bundle_dir=self.app_dir,
            relative_bundle_path="Payload/DemoApp.app",
            ipa_metadata={"filename": "demo.ipa", "sha256": "abcdef123456", "size_bytes": 1024},
            use_system_tools=False,
        )

        self.assertEqual(ctx["platform"], "ios")

        # Application
        app = ctx["application"]
        self.assertEqual(app["bundle_identifier"], "com.example.demoapp")
        self.assertEqual(app["executable"], "DemoBinary")
        self.assertEqual(app["version"], "1.0.0")
        self.assertEqual(app["filename"], "demo.ipa")

        # Configuration
        config = ctx["configuration"]
        self.assertEqual(len(config["usage_descriptions"]), 1)
        self.assertEqual(config["usage_descriptions"][0]["key"], "NSCameraUsageDescription")
        self.assertEqual(config["ats"]["status"], "extracted")

        # Structure
        struct_data = ctx["structure"]
        self.assertTrue(struct_data["has_executable"])
        self.assertEqual(struct_data["executable"]["file_type"], "Mach-O executable")

        # Network indicators
        urls = [u["value"] for u in ctx["network_indicators"]["network_urls"]]
        self.assertIn("https://api.demo.com/v1", urls)

        # Invariant: api_candidates strictly empty
        self.assertEqual(ctx["api_candidates"], [])

        # Evidence
        self.assertGreater(len(ctx["evidence"]), 0)

    def test_missing_app_dir(self):
        with self.assertRaises(NotADirectoryError):
            build_ios_static_context(self.temp_path / "NonExistent.app")


if __name__ == "__main__":
    unittest.main()
