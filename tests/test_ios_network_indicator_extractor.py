"""Tests for iOS Network Indicator Extractor (MobiAttack V2)."""

from __future__ import annotations

from pathlib import Path
import plistlib
import tempfile
import unittest

from src.ios.ios_network_indicator_extractor import extract_ios_network_indicators


class TestIosNetworkIndicatorExtractor(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.app_dir = self.temp_path / "Payload" / "Test.app"
        self.app_dir.mkdir(parents=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_indicator_extraction_from_plist_and_json(self):
        # 1. Info.plist with URLs, schemas to ignore, and domains
        plist_data = {
            "APIEndpoint": "https://api.example.com/v1/auth",
            "SecondaryHost": "auth.example.net",
            "IgnoredSchema": "http://www.apple.com/DTDs/PropertyList-1.0.dtd",
            "ServerIP": "192.168.1.100",
        }
        with open(self.app_dir / "Info.plist", "wb") as f:
            plistlib.dump(plist_data, f, fmt=plistlib.FMT_XML)

        # 2. config.json with local file URL and API path
        json_content = """
        {
            "local_doc": "file:///var/mobile/Containers/Data/local.txt",
            "route": "/v1/users/profile",
            "other_url": "http://metrics.example.org:8080/report"
        }
        """
        (self.app_dir / "config.json").write_text(json_content)

        # 3. Dummy binary with embedded strings
        dummy_bin = b"some prefix padding https://binary-update.example.com/check more padding /api/telemetry null null"
        (self.app_dir / "TestBinary").write_bytes(dummy_bin)

        res = extract_ios_network_indicators(
            app_bundle_dir=self.app_dir,
            relative_bundle_path="Payload/Test.app",
            main_executable_name="TestBinary",
        )

        urls = [u["value"] for u in res["network_urls"]]
        self.assertIn("https://api.example.com/v1/auth", urls)
        self.assertIn("http://metrics.example.org:8080/report", urls)
        self.assertIn("https://binary-update.example.com/check", urls)
        # Verify Apple DTD is ignored
        self.assertNotIn("http://www.apple.com/DTDs/PropertyList-1.0.dtd", urls)

        # Verify domains
        domains = [d["value"] for d in res["domains"]]
        self.assertTrue(any("auth.example.net" in d for d in domains))

        # Verify IP addresses
        ips = [ip["value"] for ip in res["ip_addresses"]]
        self.assertIn("192.168.1.100", ips)

        # Verify local file URLs
        local_files = [f["value"] for f in res["local_file_urls"]]
        self.assertIn("file:///var/mobile/Containers/Data/local.txt", local_files)

        # Verify path candidates
        paths = [p["value"] for p in res["path_candidates"]]
        self.assertIn("/v1/users/profile", paths)
        self.assertIn("/api/telemetry", paths)

        # Verify evidence provenance
        for u in res["network_urls"]:
            self.assertIn("source_file", u)
            self.assertIn("extraction_method", u)
            self.assertIn("source_type", u)

    def test_domain_false_positive_rejection(self):
        """Tests that obvious file extensions, SF Symbols, and code tokens are rejected as domains."""
        invalid_candidates = [
            "Screen.storyboard",
            "eye.fill",
            "eye.slash.fill",
            "person.fill",
            "xmark.circle.fill",
            "checkmark.circle.fill",
            "document.write",
            "document.location",
            "arm64-apple-ios.swiftinterface",
            "envelope.fill",
        ]
        test_file = self.app_dir / "symbols.txt"
        test_file.write_text("\n".join(invalid_candidates))

        res = extract_ios_network_indicators(
            app_bundle_dir=self.app_dir,
            relative_bundle_path="Payload/Test.app",
        )
        extracted_domains = [d["value"] for d in res["domains"]]
        for invalid in invalid_candidates:
            self.assertNotIn(
                invalid,
                extracted_domains,
                f"Expected '{invalid}' to be rejected as a network domain false positive",
            )

    def test_valid_domain_preservation(self):
        """Tests that real, valid internet hostnames and domains are preserved."""
        valid_domains = [
            "www.github.com",
            "twitter.com",
            "payatu.com",
            "payatu.io",
            "hackersden.in",
        ]
        test_file = self.app_dir / "hosts.txt"
        test_file.write_text("\n".join(valid_domains))

        res = extract_ios_network_indicators(
            app_bundle_dir=self.app_dir,
            relative_bundle_path="Payload/Test.app",
        )
        extracted_domains = [d["value"] for d in res["domains"]]
        for valid in valid_domains:
            self.assertIn(
                valid,
                extracted_domains,
                f"Expected valid domain '{valid}' to be extracted",
            )

    def test_url_components_are_not_repeated_as_weaker_indicators(self):
        (self.app_dir / "config.txt").write_text(
            "https://api.example.com/v1/users 192.168.1.10"
        )

        res = extract_ios_network_indicators(self.app_dir)

        self.assertEqual([item["value"] for item in res["network_urls"]], ["https://api.example.com/v1/users"])
        self.assertNotIn("api.example.com", [item["value"] for item in res["domains"]])
        self.assertNotIn("/v1/users", [item["value"] for item in res["path_candidates"]])
        self.assertIn("192.168.1.10", [item["value"] for item in res["ip_addresses"]])

    def test_embedded_macho_keeps_source_and_offset_provenance(self):
        framework_binary = self.app_dir / "Frameworks" / "SDK.framework" / "SDK"
        framework_binary.parent.mkdir(parents=True)
        framework_binary.write_bytes(
            b"\xfe\xed\xfa\xcf" + b"\x00" * 32 + b"https://sdk.example.com/config\x00"
        )

        res = extract_ios_network_indicators(self.app_dir, relative_bundle_path="Payload/Test.app")

        indicator = next(item for item in res["network_urls"] if item["value"] == "https://sdk.example.com/config")
        self.assertEqual(indicator["source_file"], "Payload/Test.app/Frameworks/SDK.framework/SDK")
        self.assertIsInstance(indicator["offset"], int)


if __name__ == "__main__":
    unittest.main()
