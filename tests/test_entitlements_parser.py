"""Tests for Entitlements Parser (MobiAttack V2)."""

from __future__ import annotations

from pathlib import Path
import plistlib
import tempfile
import unittest

from src.ios.entitlements_parser import extract_entitlements


def _build_synthetic_mobileprovision(entitlements: dict) -> bytes:
    """Builds a synthetic .mobileprovision byte sequence containing embedded XML plist."""
    plist_dict = {
        "AppIDName": "TestApp",
        "TeamName": "TestTeam",
        "Entitlements": entitlements,
    }
    plist_xml = plistlib.dumps(plist_dict, fmt=plistlib.FMT_XML)

    prefix_der = b"\x30\x82\x02\x10\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"
    suffix_der = b"\x00\x00\x00\x00\x04\x82\x01\x23"

    return prefix_der + plist_xml + suffix_der


class TestEntitlementsParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.app_dir = self.temp_path / "Payload" / "Sample.app"
        self.app_dir.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_extract_from_embedded_mobileprovision(self):
        sample_ents = {
            "application-identifier": "TEAM123.com.example.sample",
            "aps-environment": "production",
            "keychain-access-groups": ["TEAM123.com.example.sample"],
            "com.apple.developer.associated-domains": ["applinks:example.com"],
            "get-task-allow": False,
        }
        prov_bytes = _build_synthetic_mobileprovision(sample_ents)
        (self.app_dir / "embedded.mobileprovision").write_bytes(prov_bytes)

        res = extract_entitlements(
            app_bundle_dir=self.app_dir,
            relative_bundle_path="Payload/Sample.app",
            use_system_tools=False,
        )

        self.assertEqual(res["status"], "extracted")
        self.assertEqual(res["item_count"], 5)
        self.assertEqual(res["extraction_method"], "embedded_mobileprovision_plist")
        self.assertEqual(res["source"], "Payload/Sample.app/embedded.mobileprovision")
        self.assertEqual(res["source_type"], "embedded_mobileprovision")
        self.assertIn("embedded_mobileprovision", res.get("sources", {}))
        self.assertEqual(len(res.get("records", [])), 5)
        self.assertEqual(res["records"][0]["source_type"], "embedded_mobileprovision")
        self.assertIn("not automatically equivalent to effective runtime behavior", res.get("runtime_note", ""))

        items = res["items"]
        self.assertEqual(items["application-identifier"], "TEAM123.com.example.sample")
        self.assertEqual(items["aps-environment"], "production")
        self.assertEqual(items["com.apple.developer.associated-domains"], ["applinks:example.com"])
        self.assertFalse(items["get-task-allow"])

    def test_missing_mobileprovision_and_tools_disabled(self):
        res = extract_entitlements(
            app_bundle_dir=self.app_dir,
            relative_bundle_path="Payload/Sample.app",
            use_system_tools=False,
        )
        self.assertEqual(res["status"], "not_found")
        self.assertEqual(res["item_count"], 0)

    def test_nonexistent_bundle_dir(self):
        res = extract_entitlements(
            app_bundle_dir=self.temp_path / "NonExistent.app",
            use_system_tools=False,
        )
        self.assertEqual(res["status"], "not_found")


if __name__ == "__main__":
    unittest.main()
