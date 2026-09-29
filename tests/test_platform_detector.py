"""Tests for Platform Detector (MobiAttack V2)."""

from __future__ import annotations

import io
from pathlib import Path
import tempfile
import unittest
import zipfile

from src.platform_detector import detect_platform


def _create_synthetic_zip(entries: dict[str, bytes]) -> bytes:
    """Helper to create an in-memory ZIP archive from a dict of relative paths -> content."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


class TestPlatformDetector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_file_not_found(self):
        res = detect_platform(self.temp_path / "nonexistent.ipa")
        self.assertEqual(res["platform"], "unknown")
        self.assertFalse(res["valid"])
        self.assertIn("does not exist", res["reason"])

    def test_not_a_zip_archive(self):
        dummy_file = self.temp_path / "test.ipa"
        dummy_file.write_bytes(b"Not a zip file at all")
        res = detect_platform(dummy_file)
        self.assertEqual(res["platform"], "unknown")
        self.assertFalse(res["valid"])
        self.assertEqual(res["reason"], "File is not a valid ZIP archive.")

    def test_valid_android_apk(self):
        apk_bytes = _create_synthetic_zip({
            "AndroidManifest.xml": b"<manifest/>",
            "classes.dex": b"DEX035",
            "classes2.dex": b"DEX035",
            "res/values/strings.xml": b"<resources/>",
        })
        apk_path = self.temp_path / "sample.apk"
        apk_path.write_bytes(apk_bytes)

        res = detect_platform(apk_path)
        self.assertEqual(res["platform"], "android")
        self.assertTrue(res["valid"])
        self.assertEqual(res["dex_count"], 2)
        self.assertIn("android_manifest", res["detected_by"])

    def test_invalid_android_apk_missing_dex(self):
        apk_bytes = _create_synthetic_zip({
            "AndroidManifest.xml": b"<manifest/>",
            "res/values/strings.xml": b"<resources/>",
        })
        apk_path = self.temp_path / "sample.apk"
        apk_path.write_bytes(apk_bytes)

        res = detect_platform(apk_path)
        self.assertEqual(res["platform"], "android")
        self.assertFalse(res["valid"])
        self.assertIn("missing classes*.dex", res["reason"])

    def test_valid_ios_ipa(self):
        ipa_bytes = _create_synthetic_zip({
            "Payload/": b"",
            "Payload/DemoApp.app/": b"",
            "Payload/DemoApp.app/Info.plist": b"<?xml version='1.0'?><plist/>",
            "Payload/DemoApp.app/DemoApp": b"\xca\xfe\xba\xbe",
        })
        ipa_path = self.temp_path / "sample.ipa"
        ipa_path.write_bytes(ipa_bytes)

        res = detect_platform(ipa_path)
        self.assertEqual(res["platform"], "ios")
        self.assertTrue(res["valid"])
        self.assertEqual(res["app_bundle"], "Payload/DemoApp.app")
        self.assertTrue(res["has_info_plist"])
        self.assertIn("payload_directory", res["detected_by"])
        self.assertIn("app_bundle", res["detected_by"])
        self.assertIn("info_plist", res["detected_by"])

    def test_invalid_ios_ipa_missing_payload(self):
        zip_bytes = _create_synthetic_zip({
            "DemoApp.app/Info.plist": b"<plist/>",
        })
        ipa_path = self.temp_path / "missing_payload.ipa"
        ipa_path.write_bytes(zip_bytes)

        res = detect_platform(ipa_path)
        self.assertEqual(res["platform"], "ios")
        self.assertFalse(res["valid"])
        self.assertIn("invalid_ipa_structure", res["reason"])

    def test_invalid_ios_ipa_missing_app_bundle(self):
        zip_bytes = _create_synthetic_zip({
            "Payload/": b"",
            "Payload/some_other_dir/file.txt": b"hello",
        })
        ipa_path = self.temp_path / "no_app.ipa"
        ipa_path.write_bytes(zip_bytes)

        res = detect_platform(ipa_path)
        self.assertEqual(res["platform"], "ios")
        self.assertFalse(res["valid"])
        self.assertIn("missing_app_bundle", res["reason"])

    def test_ambiguous_multiple_app_bundles(self):
        zip_bytes = _create_synthetic_zip({
            "Payload/AppOne.app/Info.plist": b"<plist/>",
            "Payload/AppTwo.app/Info.plist": b"<plist/>",
        })
        ipa_path = self.temp_path / "multi_app.ipa"
        ipa_path.write_bytes(zip_bytes)

        res = detect_platform(ipa_path)
        self.assertEqual(res["platform"], "ios")
        self.assertFalse(res["valid"])
        self.assertIn("ambiguous_multiple_app_bundles", res["reason"])
        self.assertEqual(len(res["app_bundles"]), 2)

    def test_unrecognized_zip(self):
        zip_bytes = _create_synthetic_zip({
            "documents/readme.txt": b"Hello world",
        })
        zip_path = self.temp_path / "random.zip"
        zip_path.write_bytes(zip_bytes)

        res = detect_platform(zip_path)
        self.assertEqual(res["platform"], "unknown")
        self.assertFalse(res["valid"])
        self.assertIn("unrecognized_archive_structure", res["reason"])


if __name__ == "__main__":
    unittest.main()
