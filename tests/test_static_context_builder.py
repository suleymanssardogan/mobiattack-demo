"""Unit and integration tests for Deterministic Static Context Builder."""

from pathlib import Path
import tempfile
import unittest

from src.static_context_builder import build_static_context


class TestStaticContextBuilderUnit(unittest.TestCase):
    """Synthetic unit tests for static context builder."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root_path = Path(self.temp_dir.name)

        # Set up synthetic minimal structure
        self.raw_apk = self.root_path / "raw_apk"
        self.apktool = self.root_path / "apktool_out"
        self.raw_apk.mkdir()
        self.apktool.mkdir()

        # Write manifest
        self.manifest_path = self.apktool / "AndroidManifest.xml"
        manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
            <uses-permission android:name="android.permission.INTERNET" />
            <application>
                <activity android:name=".MainActivity">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>
                <activity android:name=".SecondActivity" />
            </application>
        </manifest>"""
        self.manifest_path.write_text(manifest_xml.strip(), encoding="utf-8")

        # Write raw_apk files
        (self.raw_apk / "classes.dex").write_text("dummy", encoding="utf-8")
        assets_dir = self.raw_apk / "assets"
        assets_dir.mkdir()
        (assets_dir / "app_config.json").write_text('{"env": "test"}', encoding="utf-8")

        # Write apktool files including Smali code
        smali_dir = self.apktool / "smali" / "com" / "test"
        smali_dir.mkdir(parents=True)
        smali_code = """
        .class public Lcom/test/TestActivity;
        .super Ljava/lang/Object;

        .method public test()V
            .locals 2
            const-string v0, "http://10.0.0.1"
            invoke-virtual {v1, v0}, Lcom/github/kittinunf/fuel/core/FuelManager;->setBasePath(Ljava/lang/String;)V
            const-string v0, "/api/data"
            invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
            return-void
        .end method
        """
        (smali_dir / "TestActivity.smali").write_text(smali_code.strip(), encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_manifest_output_included(self):
        ctx = build_static_context(self.manifest_path, self.raw_apk, self.apktool)
        self.assertEqual(ctx["app"]["package_name"], "com.test.app")
        self.assertEqual(ctx["app"]["launcher_activity"], "com.test.app.MainActivity")
        self.assertEqual(ctx["permissions"], ["android.permission.INTERNET"])
        self.assertEqual(
            ctx["activities"],
            ["com.test.app.MainActivity", "com.test.app.SecondActivity"],
        )

    def test_02_structure_output_included(self):
        ctx = build_static_context(self.manifest_path, self.raw_apk, self.apktool)
        st = ctx["structure"]
        self.assertEqual(st["dex_files"], ["classes.dex"])
        self.assertEqual(st["dex_count"], 1)
        self.assertFalse(st["is_multidex"])
        self.assertEqual(st["assets"], ["assets/app_config.json"])
        self.assertEqual(st["smali_roots"], ["smali"])

    def test_03_network_indicator_output_included(self):
        ctx = build_static_context(self.manifest_path, self.raw_apk, self.apktool)
        ni = ctx["network_indicators"]
        urls = [u["value"] for u in ni["network_urls"]]
        self.assertIn("http://10.0.0.1", urls)
        paths = [p["value"] for p in ni["path_candidates"]]
        self.assertIn("/api/data", paths)

    def test_04_api_candidate_output_included(self):
        ctx = build_static_context(self.manifest_path, self.raw_apk, self.apktool)
        self.assertEqual(len(ctx["api_candidates"]), 1)
        c = ctx["api_candidates"][0]
        self.assertEqual(c["method"], "GET")
        self.assertEqual(c["path"], "/api/data")
        self.assertEqual(c["base_url"], "http://10.0.0.1")
        self.assertEqual(c["full_url"], "http://10.0.0.1/api/data")
        self.assertEqual(c["framework"], "Fuel")

    def test_05_source_file_canonical_relative_to_apktool_root(self):
        ctx = build_static_context(self.manifest_path, self.raw_apk, self.apktool)
        c = ctx["api_candidates"][0]
        # Must start with smali/ relative to apktool_root
        self.assertTrue(c["source_file"].startswith("smali/"))
        self.assertEqual(c["source_file"], "smali/com/test/TestActivity.smali")

    def test_06_task_03_source_paths_remain_correct(self):
        ctx = build_static_context(self.manifest_path, self.raw_apk, self.apktool)
        target_url = next(u for u in ctx["network_indicators"]["network_urls"] if u["value"] == "http://10.0.0.1")
        self.assertEqual(target_url["source_file"], "smali/com/test/TestActivity.smali")

    def test_07_static_api_candidate_status_preserved(self):
        ctx = build_static_context(self.manifest_path, self.raw_apk, self.apktool)
        self.assertEqual(ctx["api_candidates"][0]["status"], "static_api_candidate")

    def test_08_evidence_line_numbers_preserved(self):
        ctx = build_static_context(self.manifest_path, self.raw_apk, self.apktool)
        ev = ctx["api_candidates"][0]["evidence"]
        self.assertIsInstance(ev["path_line"], int)
        self.assertIsInstance(ev["request_call_line"], int)
        self.assertGreater(ev["path_line"], 0)
        self.assertGreater(ev["request_call_line"], 0)

    def test_09_no_new_semantic_fields_invented(self):
        ctx = build_static_context(self.manifest_path, self.raw_apk, self.apktool)
        top_keys = set(ctx.keys())
        expected_top_keys = {
            "app", "permissions", "activities", "structure", "network_indicators", "api_candidates"
        }
        self.assertEqual(top_keys, expected_top_keys)
        app_keys = set(ctx["app"].keys())
        self.assertEqual(app_keys, {"package_name", "launcher_activity"})

    def test_10_deterministic_output(self):
        ctx1 = build_static_context(self.manifest_path, self.raw_apk, self.apktool)
        ctx2 = build_static_context(self.manifest_path, self.raw_apk, self.apktool)
        self.assertEqual(ctx1, ctx2)

    def test_11_missing_manifest_path_raises_error(self):
        missing = self.apktool / "non_existent_manifest.xml"
        with self.assertRaises(FileNotFoundError):
            build_static_context(missing, self.raw_apk, self.apktool)

    def test_12_missing_raw_apk_directory_raises_error(self):
        missing = self.root_path / "non_existent_raw"
        with self.assertRaises(FileNotFoundError):
            build_static_context(self.manifest_path, missing, self.apktool)

    def test_13_missing_apktool_directory_raises_error(self):
        missing = self.root_path / "non_existent_apktool"
        with self.assertRaises(FileNotFoundError):
            build_static_context(self.manifest_path, self.raw_apk, missing)


class TestRealOwaspStaticContextIntegration(unittest.TestCase):
    """Integration test against actual OWASP sample files."""

    def test_owasp_ground_truth_context(self):
        repo_root = Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.parent / "MSTG-Android-Kotlin.apk").is_file() else Path(__file__).resolve().parent.parent.parent
        manifest_path = repo_root / "apk_lab" / "apktool_out" / "AndroidManifest.xml"
        raw_apk_root = repo_root / "apk_lab" / "raw_apk"
        apktool_root = repo_root / "apk_lab" / "apktool_out"

        self.assertTrue(manifest_path.is_file(), f"Manifest not found: {manifest_path}")
        self.assertTrue(raw_apk_root.is_dir(), f"raw_apk not found: {raw_apk_root}")
        self.assertTrue(apktool_root.is_dir(), f"apktool_out not found: {apktool_root}")

        ctx = build_static_context(manifest_path, raw_apk_root, apktool_root)

        # 1. App metadata
        self.assertEqual(ctx["app"]["package_name"], "sg.vantagepoint.mstgkotlin")
        self.assertEqual(ctx["app"]["launcher_activity"], "sg.vantagepoint.mstgkotlin.MainActivity")

        # 2. Permissions
        self.assertIn("android.permission.INTERNET", ctx["permissions"])

        # 3. Structure
        st = ctx["structure"]
        self.assertEqual(st["dex_count"], 1)
        self.assertFalse(st["is_multidex"])
        self.assertFalse(st["has_native_code"])
        self.assertIn("assets/unsafe_content.html", st["assets"])
        self.assertEqual(st["smali_roots"], ["smali"])

        # 4. Network indicators
        ni = ctx["network_indicators"]
        urls = [u["value"] for u in ni["network_urls"]]
        self.assertIn("http://127.0.0.1", urls)
        paths = [p["value"] for p in ni["path_candidates"]]
        self.assertIn("/signup", paths)
        local_urls = [l["value"] for l in ni["local_file_urls"]]
        self.assertIn("file:///android_asset/unsafe_content.html", local_urls)

        # 5. API Candidates
        self.assertEqual(len(ctx["api_candidates"]), 1)
        c = ctx["api_candidates"][0]
        self.assertEqual(c["framework"], "Fuel")
        self.assertEqual(c["method"], "POST")
        self.assertEqual(c["base_url"], "http://127.0.0.1")
        self.assertEqual(c["path"], "/signup")
        self.assertEqual(c["full_url"], "http://127.0.0.1/signup")
        self.assertEqual(c["status"], "static_api_candidate")
        self.assertEqual(c["source_file"], "smali/sg/vantagepoint/mstgkotlin/RegisterActivity$onCreate$2.smali")
        self.assertEqual(c["request_line"], 214)

        # Evidence block
        ev = c["evidence"]
        self.assertEqual(ev["path_value"], "/signup")
        self.assertEqual(ev["path_register"], "v0")
        self.assertEqual(ev["path_line"], 102)
        self.assertEqual(ev["request_call_line"], 214)
        self.assertEqual(ev["base_url_value"], "http://127.0.0.1")
        self.assertEqual(ev["base_url_register"], "v1")
        self.assertEqual(ev["base_url_line"], 97)
        self.assertEqual(ev["base_url_call_line"], 99)


if __name__ == "__main__":
    unittest.main()
