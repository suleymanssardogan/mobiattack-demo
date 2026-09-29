"""Tests for iOS Structure Extractor (MobiAttack V2)."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from src.ios.ios_structure_extractor import extract_ios_structure


class TestIosStructureExtractor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.app_dir = self.temp_path / "Payload" / "Sample.app"
        self.app_dir.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_structure_extraction(self):
        # Create app elements
        (self.app_dir / "Info.plist").write_bytes(b"<plist/>")
        (self.app_dir / "SampleExe").write_bytes(b"\xca\xfe\xba\xbe")

        # Create Frameworks
        fw_dir = self.app_dir / "Frameworks"
        fw_dir.mkdir()
        (fw_dir / "Alamofire.framework").mkdir()
        (fw_dir / "libcrypto.dylib").write_bytes(b"\xcf\xfa\xed\xfe")

        # Create PlugIns
        plugins_dir = self.app_dir / "PlugIns"
        plugins_dir.mkdir()
        (plugins_dir / "ShareExtension.appex").mkdir()

        # Create Resources
        (self.app_dir / "config.json").write_text('{"env": "prod"}')
        (self.app_dir / "settings.plist").write_bytes(b"<plist/>")
        (self.app_dir / "Assets.car").write_bytes(b"BOMArchive")
        (self.app_dir / "en.lproj").mkdir()
        (self.app_dir / "tr.lproj").mkdir()

        res = extract_ios_structure(
            app_bundle_dir=self.app_dir,
            executable_name="SampleExe",
            relative_bundle_path="Payload/Sample.app",
        )

        self.assertEqual(res["app_bundle_path"], "Payload/Sample.app")
        self.assertTrue(res["has_info_plist"])
        self.assertTrue(res["has_executable"])
        self.assertEqual(res["executable_path"], "Payload/Sample.app/SampleExe")

        # Frameworks
        self.assertEqual(res["framework_count"], 2)
        fw_names = [f["name"] for f in res["frameworks"]]
        self.assertIn("Alamofire.framework", fw_names)
        self.assertIn("libcrypto.dylib", fw_names)

        # Extensions
        self.assertEqual(res["extension_count"], 1)
        self.assertEqual(res["extensions"][0]["name"], "ShareExtension.appex")

        # Resources
        res_info = res["resources"]
        self.assertIn("config.json", res_info["json_files"])
        self.assertIn("settings.plist", res_info["plist_files"])
        self.assertIn("Assets.car", res_info["asset_catalogs"])
        self.assertEqual(res_info["json_count"], 1)
        self.assertEqual(res_info["plist_count"], 1)

    def test_missing_app_directory(self):
        with self.assertRaises(NotADirectoryError):
            extract_ios_structure(self.temp_path / "NonExistent.app")


if __name__ == "__main__":
    unittest.main()
