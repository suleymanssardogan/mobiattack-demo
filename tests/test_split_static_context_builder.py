"""Unit and Integration Tests for Unified Split Static Context Builder (Task 14 Phase C)."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.split_static_context_builder import build_split_static_context


class TestSplitStaticContextBuilder(unittest.TestCase):
    """Test suite verifying provenance preservation and independent split static analysis."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.processed_dir = self.root / "processed"
        self.unified_dir = self.root / "unified_analysis"

        # Setup mock base directory
        self.base_raw = self.processed_dir / "base" / "raw_apk"
        self.base_apktool = self.processed_dir / "base" / "apktool_out"
        self.base_raw.mkdir(parents=True, exist_ok=True)
        self.base_apktool.mkdir(parents=True, exist_ok=True)

        # Base files: manifest, classes.dex, smali with Fuel call
        (self.base_raw / "classes.dex").write_bytes(b"dex\n035\x00")
        (self.base_raw / "classes2.dex").write_bytes(b"dex\n035\x00")
        (self.base_apktool / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="apps.r.flashlight">'
            '<uses-permission android:name="android.permission.CAMERA"/>'
            '<application>'
            '<activity android:name=".MainActivity">'
            '<intent-filter>'
            '<action android:name="android.intent.action.MAIN"/>'
            '<category android:name="android.intent.category.LAUNCHER"/>'
            '</intent-filter>'
            '</activity>'
            '</application>'
            '</manifest>'
        )
        smali_dir = self.base_apktool / "smali" / "com" / "example"
        smali_dir.mkdir(parents=True, exist_ok=True)
        (smali_dir / "Net.smali").write_text(
            '.class public Lcom/example/Net;\n'
            '.method public static test()V\n'
            '    const-string v0, "https://api.shared.com/v1"\n'
            '    const-string v1, "/status"\n'
            '    invoke-static {v1}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;\n'
            '    return-void\n'
            '.end method\n'
        )

        # Setup mock locale split directory (DEX-less, contains shared URL)
        self.en_raw = self.processed_dir / "split_config.en" / "raw_apk"
        self.en_apktool = self.processed_dir / "split_config.en" / "apktool_out"
        self.en_raw.mkdir(parents=True, exist_ok=True)
        self.en_apktool.mkdir(parents=True, exist_ok=True)

        (self.en_apktool / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="apps.r.flashlight" split="config.en">'
            '<uses-permission android:name="android.permission.INTERNET"/>'
            '</manifest>'
        )
        en_res = self.en_apktool / "res" / "values-en"
        en_res.mkdir(parents=True, exist_ok=True)
        (en_res / "strings.xml").write_text(
            '<resources>'
            '<string name="shared_url">https://api.shared.com/v1</string>'
            '<string name="locale_url">https://locale.en.service.net/v2</string>'
            '</resources>'
        )

        # Setup mock density split directory (DEX-less)
        self.density_raw = self.processed_dir / "split_config.xxhdpi" / "raw_apk"
        self.density_apktool = self.processed_dir / "split_config.xxhdpi" / "apktool_out"
        self.density_raw.mkdir(parents=True, exist_ok=True)
        self.density_apktool.mkdir(parents=True, exist_ok=True)

        (self.density_apktool / "AndroidManifest.xml").write_text(
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="apps.r.flashlight" split="config.xxhdpi"/>'
        )
        density_res = self.density_apktool / "res" / "drawable-xxhdpi"
        density_res.mkdir(parents=True, exist_ok=True)
        (density_res / "icon.png").write_bytes(b"\x89PNG\r\n\x1a\n")

        # Construct package_set.json
        self.package_set = {
            "package_name": "apps.r.flashlight",
            "package_layout": "split",
            "split_count": 3,
            "components": [
                {
                    "filename": "base.apk",
                    "role": "base",
                    "has_dex": True,
                    "dex_count": 2,
                    "dex_files": ["classes.dex", "classes2.dex"],
                    "size_bytes": 1000000,
                    "sha256": "aaaa",
                    "preprocessing": {
                        "raw_extract_status": "success",
                        "apktool_status": "success",
                        "jadx_status": "success",
                        "raw_apk_dir": str(self.base_raw),
                        "apktool_dir": str(self.base_apktool),
                    },
                },
                {
                    "filename": "split_config.en.apk",
                    "role": "config_locale",
                    "has_dex": False,
                    "dex_count": 0,
                    "dex_files": [],
                    "size_bytes": 20000,
                    "sha256": "bbbb",
                    "preprocessing": {
                        "raw_extract_status": "success",
                        "apktool_status": "success",
                        "jadx_status": "skipped_no_dex",
                        "raw_apk_dir": str(self.en_raw),
                        "apktool_dir": str(self.en_apktool),
                    },
                },
                {
                    "filename": "split_config.xxhdpi.apk",
                    "role": "config_density",
                    "has_dex": False,
                    "dex_count": 0,
                    "dex_files": [],
                    "size_bytes": 50000,
                    "sha256": "cccc",
                    "preprocessing": {
                        "raw_extract_status": "success",
                        "apktool_status": "success_with_warnings",
                        "jadx_status": "skipped_no_dex",
                        "raw_apk_dir": str(self.density_raw),
                        "apktool_dir": str(self.density_apktool),
                    },
                },
            ],
        }
        self.pkg_set_file = self.root / "package_set" / "package_set.json"
        self.pkg_set_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.pkg_set_file, "w") as f:
            json.dump(self.package_set, f, indent=2)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_full_split_static_context_build(self):
        ctx = build_split_static_context(
            package_set_input=self.pkg_set_file,
            unified_analysis_root=self.unified_dir,
        )

        # 1. Package layout facts
        self.assertEqual(ctx["package_name"], "apps.r.flashlight")
        self.assertEqual(ctx["package_layout"], "split")
        self.assertEqual(ctx["split_count"], 3)
        self.assertEqual(ctx["app"]["launcher_activity"], "apps.r.flashlight.MainActivity")

        # 2. Manifest evidence per split
        evidence_apks = [e["source_apk"] for e in ctx["manifest_evidence"]]
        self.assertIn("base.apk", evidence_apks)
        self.assertIn("split_config.en.apk", evidence_apks)
        self.assertIn("split_config.xxhdpi.apk", evidence_apks)

        # 3. Structure provenance per component
        struct_components = ctx["structure"]["components"]
        self.assertEqual(len(struct_components), 3)

        base_struct = next(s for s in struct_components if s["source_apk"] == "base.apk")
        self.assertEqual(base_struct["dex_count"], 2)
        self.assertTrue(base_struct["is_multidex"])
        self.assertIn("smali", base_struct["smali_roots"])

        en_struct = next(s for s in struct_components if s["source_apk"] == "split_config.en.apk")
        self.assertEqual(en_struct["dex_count"], 0)
        self.assertFalse(en_struct["is_multidex"])

        # 4. Total DEX count
        self.assertEqual(ctx["structure"]["total_dex_count"], 2)

        # 5. Network indicators with provenance
        urls = ctx["network_indicators"]["network_urls"]
        self.assertTrue(len(urls) >= 3)
        for u in urls:
            self.assertIn("source_apk", u)
            self.assertIn("source_file", u)
            self.assertIn("line_number", u)

        # 6. Same URL in two splits preserves BOTH provenance records
        shared_records = [u for u in urls if u["value"] == "https://api.shared.com/v1"]
        self.assertEqual(len(shared_records), 2, "Shared URL must retain both provenance records without collapsing")
        shared_sources = {r["source_apk"] for r in shared_records}
        self.assertEqual(shared_sources, {"base.apk", "split_config.en.apk"})

        # 7. API candidates with source_apk
        cands = ctx["api_candidates"]
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["source_apk"], "base.apk")
        self.assertEqual(cands[0]["status"], "static_api_candidate")

        # 8. Deterministic file created on disk
        saved_file = self.unified_dir / "static_context.json"
        self.assertTrue(saved_file.is_file())
        with open(saved_file, "r") as f:
            disk_data = json.load(f)
        self.assertEqual(disk_data["package_layout"], "split")
        self.assertEqual(disk_data["aggregation_counts"]["total_dex_count"], 2)
        self.assertEqual(disk_data["aggregation_counts"]["api_candidate_count"], 1)

    def test_dex_less_splits_skip_api_candidate_extractor(self):
        # Package set with only DEX-less split
        dexless_set = {
            "package_name": "com.dexless",
            "package_layout": "split",
            "components": [
                {
                    "filename": "split_config.en.apk",
                    "role": "config_locale",
                    "has_dex": False,
                    "preprocessing": {
                        "apktool_status": "success",
                        "apktool_dir": str(self.en_apktool),
                        "raw_apk_dir": str(self.en_raw),
                    },
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, 'authoritative base'):
            build_split_static_context(dexless_set, unified_analysis_root=self.unified_dir)

    def test_failed_split_recorded_as_warning_without_crashing(self):
        failed_set = {
            "package_name": "apps.r.flashlight",
            "package_layout": "split",
            "components": [
                {
                    "filename": "base.apk",
                    "role": "base",
                    "has_dex": True,
                    "preprocessing": {
                        "apktool_status": "success",
                        "apktool_dir": str(self.base_apktool),
                        "raw_apk_dir": str(self.base_raw),
                    },
                },
                {
                    "filename": "split_corrupt.apk",
                    "role": "unknown",
                    "has_dex": False,
                    "preprocessing": {
                        "apktool_status": "failed",
                        "apktool_dir": None,
                        "raw_apk_dir": None,
                    },
                },
            ],
        }
        ctx = build_split_static_context(failed_set, unified_analysis_root=self.unified_dir)
        self.assertEqual(ctx["package_name"], "apps.r.flashlight")
        self.assertEqual(len(ctx["structure"]["components"]), 2)
        corrupt_struct = next(s for s in ctx["structure"]["components"] if s["source_apk"] == "split_corrupt.apk")
        self.assertEqual(corrupt_struct["status"], "unavailable")
        self.assertTrue(any("split_corrupt.apk" in w for w in ctx["analysis_warnings"]))

    def test_monolithic_single_apk_regression(self):
        monolithic_set = {
            "package_name": "apps.r.flashlight",
            "package_layout": "monolithic",
            "components": [
                {
                    "filename": "base.apk",
                    "role": "base",
                    "has_dex": True,
                    "dex_count": 2,
                    "preprocessing": {
                        "apktool_status": "success",
                        "apktool_dir": str(self.base_apktool),
                        "raw_apk_dir": str(self.base_raw),
                    },
                }
            ],
        }
        ctx = build_split_static_context(monolithic_set, unified_analysis_root=self.unified_dir)
        self.assertEqual(ctx["package_layout"], "monolithic")
        self.assertEqual(ctx["split_count"], 1)
        self.assertEqual(len(ctx["structure"]["components"]), 1)
        self.assertEqual(ctx["structure"]["components"][0]["source_apk"], "base.apk")



    def test_no_cross_split_api_inference(self):
        # Create a feature split that has a Fuel call without its own base URL
        feature_apktool = self.processed_dir / "split_feature_x" / "apktool_out"
        feature_raw = self.processed_dir / "split_feature_x" / "raw_apk"
        feature_apktool.mkdir(parents=True, exist_ok=True)
        feature_raw.mkdir(parents=True, exist_ok=True)
        (feature_raw / "classes.dex").write_bytes(b"dex_bytes")
        
        feature_smali = feature_apktool / "smali" / "com" / "feature"
        feature_smali.mkdir(parents=True, exist_ok=True)
        (feature_smali / "Feat.smali").write_text(
            ".class public Lcom/feature/Feat;\n"
            ".method public static doCall()V\n"
            "    const-string v0, \"/feature/endpoint\"\n"
            "    invoke-static {v0}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;\n"
            "    return-void\n"
            ".end method\n"
        )

        pkg_set_cross = {
            "package_name": "apps.r.flashlight",
            "package_layout": "split",
            "components": [
                {
                    "filename": "base.apk",
                    "role": "base",
                    "has_dex": True,
                    "preprocessing": {
                        "apktool_status": "success",
                        "apktool_dir": str(self.base_apktool),
                        "raw_apk_dir": str(self.base_raw),
                    },
                },
                {
                    "filename": "split_feature_x.apk",
                    "role": "feature",
                    "has_dex": True,
                    "preprocessing": {
                        "apktool_status": "success",
                        "apktool_dir": str(feature_apktool),
                        "raw_apk_dir": str(feature_raw),
                    },
                },
            ],
        }

        ctx = build_split_static_context(pkg_set_cross, unified_analysis_root=self.unified_dir)
        cands = ctx["api_candidates"]
        base_cands = [c for c in cands if c["source_apk"] == "base.apk"]
        feat_cands = [c for c in cands if c["source_apk"] == "split_feature_x.apk"]

        self.assertEqual(len(base_cands), 1)
        self.assertEqual(len(feat_cands), 1)
        self.assertIsNone(feat_cands[0]["base_url"], "Cross-split base URL leakage must not occur")

    def test_success_with_warnings_split_contributes_evidence(self):
        warn_set = {
            "package_name": "apps.r.flashlight",
            "package_layout": "split",
            "components": [
                {
                    "filename": "base.apk",
                    "role": "base",
                    "has_dex": True,
                    "preprocessing": {
                        "apktool_status": "success",
                        "apktool_dir": str(self.base_apktool),
                        "raw_apk_dir": str(self.base_raw),
                    },
                },
                {
                    "filename": "split_config.xxhdpi.apk",
                    "role": "config_density",
                    "has_dex": False,
                    "preprocessing": {
                        "apktool_status": "success_with_warnings",
                        "apktool_dir": str(self.density_apktool),
                        "raw_apk_dir": str(self.density_raw),
                    },
                },
            ],
        }
        ctx = build_split_static_context(warn_set, unified_analysis_root=self.unified_dir)
        density_struct = next(s for s in ctx["structure"]["components"] if s["source_apk"] == "split_config.xxhdpi.apk")
        self.assertEqual(density_struct["status"], "success")


if __name__ == "__main__":
    unittest.main()

