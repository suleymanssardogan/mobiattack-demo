"""Tests for Info.plist Parser (MobiAttack V2)."""

from __future__ import annotations

from pathlib import Path
import plistlib
import tempfile
import unittest

from src.ios.plist_parser import PlistParseError, parse_info_plist, parse_plist_file


class TestPlistParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_xml_plist_parsing(self):
        sample_data = {
            "CFBundleIdentifier": "com.example.testapp",
            "CFBundleName": "TestApp",
            "CFBundleDisplayName": "Test Application",
            "CFBundleExecutable": "TestApp",
            "CFBundleShortVersionString": "2.1.0",
            "CFBundleVersion": "42",
            "MinimumOSVersion": "15.0",
            "CFBundleSupportedPlatforms": ["iPhoneOS"],
            "UIDeviceFamily": [1, 2],
            "NSCameraUsageDescription": "Camera is required to scan QR codes.",
            "NSLocationWhenInUseUsageDescription": "Location is needed for navigation.",
            "CFBundleURLTypes": [
                {
                    "CFBundleURLName": "com.example.testapp",
                    "CFBundleURLSchemes": ["testapp", "testapp-auth"],
                }
            ],
            "LSApplicationQueriesSchemes": ["whatsapp", "twitter"],
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoads": False,
                "NSAllowsLocalNetworking": True,
                "NSExceptionDomains": {
                    "api.example.com": {
                        "NSIncludesSubdomains": True,
                        "NSExceptionAllowsInsecureHTTPLoads": True,
                    }
                },
            },
        }

        plist_file = self.temp_path / "Info.plist"
        with open(plist_file, "wb") as f:
            plistlib.dump(sample_data, f, fmt=plistlib.FMT_XML)

        res = parse_info_plist(plist_file, relative_source_path="Payload/TestApp.app/Info.plist")

        self.assertEqual(res["bundle_identifier"], "com.example.testapp")
        self.assertEqual(res["display_name"], "Test Application")
        self.assertEqual(res["executable"], "TestApp")
        self.assertEqual(res["version"], "2.1.0")
        self.assertEqual(res["build"], "42")
        self.assertEqual(res["minimum_os_version"], "15.0")
        self.assertEqual(res["device_family"], ["iPhone", "iPad"])

        # Usage descriptions
        usage_keys = [u["key"] for u in res["usage_descriptions"]]
        self.assertIn("NSCameraUsageDescription", usage_keys)
        self.assertIn("NSLocationWhenInUseUsageDescription", usage_keys)
        for u in res["usage_descriptions"]:
            self.assertEqual(u["classification"], "declared_usage_description")
            self.assertEqual(u["evidence"]["source_file"], "Payload/TestApp.app/Info.plist")

        # URL Schemes
        schemes = [s["scheme"] for s in res["url_schemes"]]
        self.assertIn("testapp", schemes)
        self.assertIn("testapp-auth", schemes)
        self.assertEqual(res["queries_schemes"], ["whatsapp", "twitter"])

        # ATS Configuration
        ats = res["ats"]
        self.assertEqual(ats["status"], "extracted")
        self.assertFalse(ats["allows_arbitrary_loads"])
        self.assertTrue(ats["allows_local_networking"])
        self.assertEqual(len(ats["exception_domains"]), 1)
        self.assertEqual(ats["exception_domains"][0]["domain"], "api.example.com")
        self.assertTrue(ats["exception_domains"][0]["allows_insecure_http_loads"])

    def test_binary_plist_parsing(self):
        sample_data = {
            "CFBundleIdentifier": "com.example.binapp",
            "CFBundleExecutable": "BinApp",
            "CFBundleShortVersionString": "1.0",
        }
        plist_file = self.temp_path / "BinaryInfo.plist"
        with open(plist_file, "wb") as f:
            plistlib.dump(sample_data, f, fmt=plistlib.FMT_BINARY)

        res = parse_info_plist(plist_file)
        self.assertEqual(res["bundle_identifier"], "com.example.binapp")
        self.assertEqual(res["executable"], "BinApp")
        self.assertEqual(res["version"], "1.0")

    def test_missing_plist_file(self):
        with self.assertRaises(FileNotFoundError):
            parse_info_plist(self.temp_path / "nonexistent.plist")

    def test_corrupted_plist_file(self):
        corrupt_file = self.temp_path / "Corrupt.plist"
        corrupt_file.write_bytes(b"This is not valid XML or binary plist bytes.")
        with self.assertRaises(PlistParseError):
            parse_info_plist(corrupt_file)

    def test_root_not_dict(self):
        list_plist = self.temp_path / "List.plist"
        with open(list_plist, "wb") as f:
            plistlib.dump(["item1", "item2"], f, fmt=plistlib.FMT_XML)
        with self.assertRaises(PlistParseError):
            parse_info_plist(list_plist)


if __name__ == "__main__":
    unittest.main()
