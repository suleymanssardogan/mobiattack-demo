"""Tests for Safe IPA Extractor (MobiAttack V2)."""

from __future__ import annotations

import io
from pathlib import Path
import tempfile
import unittest
import zipfile

from src.ios.ipa_extractor import IpaExtractionError, extract_ipa


def _create_synthetic_zip(entries: dict[str, bytes]) -> bytes:
    """Helper to create an in-memory ZIP archive from a dict of relative paths -> content."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


class TestIpaExtractor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.output_dir = self.temp_path / "output"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_safe_ipa_extraction_success(self):
        ipa_bytes = _create_synthetic_zip({
            "Payload/Demo.app/Info.plist": b"<?xml version='1.0'?><plist/>",
            "Payload/Demo.app/Demo": b"\xca\xfe\xba\xbe",
            "Payload/Demo.app/resource.json": b'{"key": "val"}',
            "Payload/Demo.app/Frameworks/Test.dylib": b"\xcf\xfa\xed\xfe",
        })
        ipa_file = self.temp_path / "valid.ipa"
        ipa_file.write_bytes(ipa_bytes)

        res = extract_ipa(ipa_file, self.output_dir)

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["app_bundle"], "Payload/Demo.app")
        self.assertTrue(Path(res["app_bundle_dir"]).is_dir())
        self.assertTrue((Path(res["app_bundle_dir"]) / "Info.plist").is_file())
        self.assertTrue((Path(res["app_bundle_dir"]) / "Demo").is_file())
        self.assertTrue(res["has_info_plist"])
        self.assertGreater(res["extracted_files"], 0)
        self.assertEqual(len(res["sha256"]), 64)

    def test_zip_slip_rejection(self):
        # Create an archive with directory traversal
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("Payload/Demo.app/Info.plist", b"<plist/>")
            zf.writestr("Payload/Demo.app/../../evil.txt", b"malicious content")
        ipa_file = self.temp_path / "zip_slip.ipa"
        ipa_file.write_bytes(buf.getvalue())

        with self.assertRaises(IpaExtractionError) as ctx:
            extract_ipa(ipa_file, self.output_dir)
        self.assertIn("Zip-slip", str(ctx.exception))

    def test_absolute_path_rejection(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("Payload/Demo.app/Info.plist", b"<plist/>")
            zf.writestr("/evil.txt", b"malicious content")
        ipa_file = self.temp_path / "abs_path.ipa"
        ipa_file.write_bytes(buf.getvalue())

        with self.assertRaises(IpaExtractionError) as ctx:
            extract_ipa(ipa_file, self.output_dir)
        self.assertIn("Unsafe absolute path", str(ctx.exception))

    def test_missing_ipa_file(self):
        with self.assertRaises(IpaExtractionError) as ctx:
            extract_ipa(self.temp_path / "missing.ipa", self.output_dir)
        self.assertIn("does not exist", str(ctx.exception))

    def test_invalid_ipa_structure_rejection(self):
        # A zip that is not an IPA
        ipa_bytes = _create_synthetic_zip({
            "not_payload/some_file.txt": b"content",
        })
        ipa_file = self.temp_path / "invalid_struct.ipa"
        ipa_file.write_bytes(ipa_bytes)

        with self.assertRaises(IpaExtractionError) as ctx:
            extract_ipa(ipa_file, self.output_dir)
        self.assertIn("structural validation failed", str(ctx.exception))

    def test_multiple_app_bundles_rejection(self):
        ipa_bytes = _create_synthetic_zip({
            "Payload/One.app/Info.plist": b"<plist/>",
            "Payload/Two.app/Info.plist": b"<plist/>",
        })
        ipa_file = self.temp_path / "multi_app.ipa"
        ipa_file.write_bytes(ipa_bytes)

        with self.assertRaises(IpaExtractionError) as ctx:
            extract_ipa(ipa_file, self.output_dir)
        self.assertIn("ambiguous_multiple_app_bundles", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
