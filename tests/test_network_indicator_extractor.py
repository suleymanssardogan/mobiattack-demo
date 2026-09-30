"""Unit and integration tests for Static String / Network Indicator Extractor."""

from pathlib import Path
import tempfile
import unittest

from src.network_indicator_extractor import extract_network_indicators


class TestNetworkIndicatorExtractorUnit(unittest.TestCase):
    """Synthetic unit tests for network indicator extraction."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_file(self, rel_path: str, content: str, encoding="utf-8") -> Path:
        target = self.root_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding=encoding)
        return target

    def _write_bytes(self, rel_path: str, content: bytes) -> Path:
        target = self.root_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def test_01_http_url_detection(self):
        self._write_file("test.txt", 'target = "http://example.com/api"')
        res = extract_network_indicators(self.root_path)
        self.assertEqual(len(res["network_urls"]), 1)
        self.assertEqual(res["network_urls"][0]["value"], "http://example.com/api")
        self.assertEqual(res["network_urls"][0]["type"], "network_url")

    def test_02_https_url_detection(self):
        self._write_file("config.json", '{"endpoint": "https://secure.api.org/v2/auth"}')
        res = extract_network_indicators(self.root_path)
        self.assertEqual(len(res["network_urls"]), 1)
        self.assertEqual(res["network_urls"][0]["value"], "https://secure.api.org/v2/auth")

    def test_03_url_with_ip_port_path(self):
        self._write_file("app.smali", 'const-string v0, "http://192.168.1.10:8080/api/v1"')
        res = extract_network_indicators(self.root_path)
        self.assertEqual(len(res["network_urls"]), 1)
        self.assertEqual(res["network_urls"][0]["value"], "http://192.168.1.10:8080/api/v1")
        # IPv4 should be suppressed on the same line since it is inside the network_url
        self.assertEqual(len(res["ip_addresses"]), 0)

    def test_04_bare_domain_detection(self):
        # Includes international ccTLDs (.tr, .de, .uk) and gTLDs
        content = """
        api.company.com
        service.backend.de
        auth.gateway.tr
        portal.service.uk
        """
        self._write_file("domains.txt", content)
        res = extract_network_indicators(self.root_path)
        vals = [d["value"] for d in res["domains"]]
        self.assertIn("api.company.com", vals)
        self.assertIn("service.backend.de", vals)
        self.assertIn("auth.gateway.tr", vals)
        self.assertIn("portal.service.uk", vals)

    def test_smali_descriptors_and_local_files_do_not_look_like_network_targets(self):
        self._write_file("classes.smali", """
        .class public Lcom/google/android/api/internal/Client;
        const-string v0, "com.google.android.youtube.tv"
        const-string v1, "CharMatcher.is"
        const-string v2, "/databases/Expressions.db"
        const-string v3, "https://api.example.com/v1/users"
        const-string v4, "/signup"
        """)
        result = extract_network_indicators(self.root_path)
        self.assertEqual([item["value"] for item in result["network_urls"]], ["https://api.example.com/v1/users"])
        self.assertEqual(result["domains"], [])
        self.assertEqual([item["value"] for item in result["path_candidates"]], ["/signup"])

    def test_05_ipv4_detection(self):
        self._write_file("network.conf", "server_ip = 10.0.2.2\ngateway = 127.0.0.1")
        res = extract_network_indicators(self.root_path)
        vals = [ip["value"] for ip in res["ip_addresses"]]
        self.assertIn("10.0.2.2", vals)
        self.assertIn("127.0.0.1", vals)

    def test_06_path_candidate_detection(self):
        self._write_file("routes.smali", 'const-string v0, "/signup"\nconst-string v1, "/api/v1/users"')
        res = extract_network_indicators(self.root_path)
        vals = [p["value"] for p in res["path_candidates"]]
        self.assertIn("/signup", vals)
        self.assertIn("/api/v1/users", vals)

    def test_07_local_file_url_detection(self):
        self._write_file(
            "activity.smali",
            'const-string v0, "file:///android_asset/unsafe_content.html"\nconst-string v1, "file:///data/local/tmp/test.txt"',
        )
        res = extract_network_indicators(self.root_path)
        vals = [f["value"] for f in res["local_file_urls"]]
        self.assertIn("file:///android_asset/unsafe_content.html", vals)
        self.assertIn("file:///data/local/tmp/test.txt", vals)

    def test_08_file_url_must_not_become_network_url(self):
        self._write_file("test.smali", 'const-string v0, "file:///android_asset/page.html"')
        res = extract_network_indicators(self.root_path)
        self.assertEqual(len(res["network_urls"]), 0)
        self.assertEqual(len(res["local_file_urls"]), 1)

    def test_09_android_resource_path_filtering(self):
        content = """
        const-string v0, "/android_asset/something"
        const-string v1, "/res/layout/main.xml"
        const-string v2, "/drawable/icon.png"
        const-string v3, "/layout/activity.xml"
        const-string v4, "/mipmap/ic_launcher"
        const-string v5, "/assets/fonts/font.ttf"
        const-string v6, "/data/local/tmp"
        const-string v7, "/real/api/route"
        """
        self._write_file("res_paths.smali", content)
        res = extract_network_indicators(self.root_path)
        vals = [p["value"] for p in res["path_candidates"]]
        self.assertNotIn("/android_asset/something", vals)
        self.assertNotIn("/res/layout/main.xml", vals)
        self.assertNotIn("/drawable/icon.png", vals)
        self.assertNotIn("/layout/activity.xml", vals)
        self.assertNotIn("/mipmap/ic_launcher", vals)
        self.assertNotIn("/assets/fonts/font.ttf", vals)
        self.assertNotIn("/data/local/tmp", vals)
        self.assertIn("/real/api/route", vals)

    def test_10_noise_text_ignored(self):
        content = """
        Welcome to the mobile application.
        This is a normal sentence without network indicators.
        Click button below to proceed.
        Total items: 42
        """
        self._write_file("strings.txt", content)
        res = extract_network_indicators(self.root_path)
        self.assertEqual(res["network_urls"], [])
        self.assertEqual(res["domains"], [])
        self.assertEqual(res["ip_addresses"], [])
        self.assertEqual(res["path_candidates"], [])
        self.assertEqual(res["local_file_urls"], [])

    def test_11_nested_asset_text_files(self):
        self._write_file("assets/sub/deep/config.json", '{"api_url": "https://nested.example.com"}')
        res = extract_network_indicators(self.root_path)
        self.assertEqual(len(res["network_urls"]), 1)
        self.assertEqual(res["network_urls"][0]["value"], "https://nested.example.com")
        self.assertEqual(res["network_urls"][0]["source_file"], "assets/sub/deep/config.json")

    def test_12_smali_string_detection(self):
        content = """
        .method public onCreate()V
            const-string v0, "http://127.0.0.1"
            const-string v1, "/signup"
            return-void
        .end method
        """
        self._write_file("smali/Activity.smali", content)
        res = extract_network_indicators(self.root_path)
        self.assertEqual(len(res["network_urls"]), 1)
        self.assertEqual(res["network_urls"][0]["value"], "http://127.0.0.1")
        self.assertEqual(len(res["path_candidates"]), 1)
        self.assertEqual(res["path_candidates"][0]["value"], "/signup")

    def test_13_xml_string_detection(self):
        content = """<?xml version="1.0" encoding="utf-8"?>
        <resources>
            <string name="base_url">https://xml.example.org</string>
            <string name="login_path">/auth/login</string>
        </resources>"""
        self._write_file("res/values/strings.xml", content)
        res = extract_network_indicators(self.root_path)
        self.assertEqual(res["network_urls"][0]["value"], "https://xml.example.org")
        self.assertEqual(res["path_candidates"][0]["value"], "/auth/login")

    def test_14_json_text_config_detection(self):
        content = '{"host": "gateway.internal.net", "timeout": 5000}'
        self._write_file("config.json", content)
        res = extract_network_indicators(self.root_path)
        self.assertEqual(res["domains"][0]["value"], "gateway.internal.net")

    def test_15_binary_unsupported_file_ignored_safely(self):
        self._write_bytes("lib/arm64-v8a/libfoo.so", b"\x7fELF\x02http://evil.com/leak")
        self._write_bytes("classes.dex", b"dex\n035\x00http://ignore.com")
        self._write_bytes("res/drawable/icon.png", b"\x89PNG\r\n\x1a\n")
        res = extract_network_indicators(self.root_path)
        self.assertEqual(res["network_urls"], [])

    def test_16_invalid_utf8_file_skipped_safely(self):
        # Write invalid UTF-8 bytes to a supported text extension
        self._write_bytes("bad_encoding.txt", b"\xff\xfe\x00\x00invalid http://fail.com")
        res = extract_network_indicators(self.root_path)
        # Should not crash, and should not produce findings
        self.assertEqual(res["network_urls"], [])

    def test_17_deterministic_sorting(self):
        # Create un-sorted content
        content = """
        const-string v0, "https://zebra.com"
        const-string v1, "https://apple.com"
        const-string v2, "https://banana.com"
        """
        self._write_file("unsorted.smali", content)
        res = extract_network_indicators(self.root_path)
        vals = [u["value"] for u in res["network_urls"]]
        self.assertEqual(vals, ["https://apple.com", "https://banana.com", "https://zebra.com"])

    def test_18_duplicate_prevention(self):
        # Same URL repeated on identical or different lines
        content = """
        const-string v0, "http://duplicate.com"
        const-string v1, "http://duplicate.com"
        """
        self._write_file("dup.smali", content)
        res = extract_network_indicators(self.root_path)
        # Line 2 and Line 3 should have distinct line numbers (tracked per line)
        self.assertEqual(len(res["network_urls"]), 2)
        self.assertEqual(res["network_urls"][0]["line_number"], 2)
        self.assertEqual(res["network_urls"][1]["line_number"], 3)

    def test_19_source_file_relative_paths(self):
        self._write_file("sub/folder/file.smali", 'const-string v0, "https://rel.com"')
        res = extract_network_indicators(self.root_path)
        self.assertEqual(res["network_urls"][0]["source_file"], "sub/folder/file.smali")

    def test_20_one_based_line_numbers(self):
        content = "\n\nconst-string v0, \"http://line3.com\"\n"
        self._write_file("line_test.smali", content)
        res = extract_network_indicators(self.root_path)
        self.assertEqual(res["network_urls"][0]["line_number"], 3)

    def test_schema_namespaces_ignored(self):
        content = """
        xmlns:android="http://schemas.android.com/apk/res/android"
        xmlns:app="http://schemas.android.com/apk/res-auto"
        xmlns:tools="http://schemas.android.com/tools"
        target="http://schemas.microsoft.com/expression/blend/2008"
        """
        self._write_file("layout.xml", content)
        res = extract_network_indicators(self.root_path)
        self.assertEqual(res["network_urls"], [])


class TestRealOwaspNetworkIndicatorIntegration(unittest.TestCase):
    """Integration test against actual OWASP apktool_out directory."""

    def test_owasp_ground_truth(self):
        repo_root = Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.parent / "MSTG-Android-Kotlin.apk").is_file() else Path(__file__).resolve().parent.parent.parent
        apktool_dir = repo_root / "apk_lab" / "apktool_out"
        self.assertTrue(apktool_dir.is_dir(), f"apktool_out not found at {apktool_dir}")

        result = extract_network_indicators(apktool_dir)

        # 1. Assert ground truth network URL
        urls = [u["value"] for u in result["network_urls"]]
        self.assertIn("http://127.0.0.1", urls)
        target_url = next(u for u in result["network_urls"] if u["value"] == "http://127.0.0.1")
        self.assertEqual(
            target_url["source_file"],
            "smali/sg/vantagepoint/mstgkotlin/RegisterActivity$onCreate$2.smali",
        )
        self.assertEqual(target_url["line_number"], 97)

        # 2. Assert ground truth path candidate
        paths = [p["value"] for p in result["path_candidates"]]
        self.assertIn("/signup", paths)
        target_path = next(p for p in result["path_candidates"] if p["value"] == "/signup")
        self.assertEqual(
            target_path["source_file"],
            "smali/sg/vantagepoint/mstgkotlin/RegisterActivity$onCreate$2.smali",
        )
        self.assertEqual(target_path["line_number"], 102)

        # 3. Assert ground truth local file URL
        local_urls = [f["value"] for f in result["local_file_urls"]]
        self.assertIn("file:///android_asset/unsafe_content.html", local_urls)
        local_files = [
            f["source_file"]
            for f in result["local_file_urls"]
            if f["value"] == "file:///android_asset/unsafe_content.html"
        ]
        self.assertIn("smali/sg/vantagepoint/mstgkotlin/SecureWebViewActivity.smali", local_files)
        self.assertIn("smali/sg/vantagepoint/mstgkotlin/InsecureWebViewActivity.smali", local_files)


if __name__ == "__main__":
    unittest.main()
