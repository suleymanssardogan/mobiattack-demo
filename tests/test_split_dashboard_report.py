"""Comprehensive Phase D Test Suite for Split APK Dashboard & Report Integration.

Validates all 18 requirements specified for Phase D:
1. split package dashboard overview
2. component inventory rendering
3. base component statuses
4. DEX-less skipped_no_dex rendering
5. split structure grouped by source_apk
6. network source_apk column
7. Source APK filter
8. network pagination/bounded rendering
9. zero API candidates remains valid
10. API candidate source_apk rendering
11. report.json preserves full split evidence
12. report.html includes component inventory
13. report.html bounded indicator display
14. JADX warning preserved
15. installed-splits limitation note visible
16. split orchestrator path completes
17. monolithic regression
18. direct APK regression
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.demo_orchestrator import run_demo
from src.demo_web_server import DemoWebServer
from src.report_generator import build_report_dict, generate_reports, render_html_report


class TestSplitDashboardAndReport(unittest.TestCase):
    def setUp(self):
        # Sample split package execution result (mimics live apps.r.flashlight)
        self.split_pipeline_result = {
            "input": {
                "url": "https://play.google.com/store/apps/details?id=apps.r.flashlight",
                "platform": "android",
                "source_type": "play_store",
                "package_name": "apps.r.flashlight",
                "adb_serial": "127.0.0.1:5555",
                "reinstall": False,
                "grant_permissions": False,
            },
            "acquisition": {
                "platform": "android",
                "source_type": "play_store",
                "package_name": "apps.r.flashlight",
                "package_layout": "split",
                "split_count": 3,
                "installed_on_device": True,
                "components": [
                    {
                        "filename": "base.apk",
                        "role": "base",
                        "size_bytes": 24792837,
                        "sha256": "1d3ceed81356f18b8e56973ff2a398f911ef8dc5d9e83b8fb8ade9b2861c9c73",
                        "dex_count": 3,
                        "has_dex": True,
                        "preprocessing": {
                            "raw_extract_status": "success",
                            "apktool_status": "success_with_warnings",
                            "jadx_status": "success_with_warnings",
                            "warnings": ["JADX exited with warnings (code 3) for 'base.apk'"],
                        },
                    },
                    {
                        "filename": "split_config.en.apk",
                        "role": "config_locale",
                        "size_bytes": 37273,
                        "sha256": "64b6388a0f72ef3e017bd01a07220af441183d6d2d6d1fc2b9e71b87f558b4e7",
                        "dex_count": 0,
                        "has_dex": False,
                        "preprocessing": {
                            "raw_extract_status": "success",
                            "apktool_status": "success",
                            "jadx_status": "skipped_no_dex",
                            "warnings": [],
                        },
                    },
                    {
                        "filename": "split_config.xxhdpi.apk",
                        "role": "config_density",
                        "size_bytes": 312560,
                        "sha256": "3b12cd81356f18b8e56973ff2a398f911ef8dc5d9e83b8fb8ade9b2861c9c73",
                        "dex_count": 0,
                        "has_dex": False,
                        "preprocessing": {
                            "raw_extract_status": "success",
                            "apktool_status": "success",
                            "jadx_status": "skipped_no_dex",
                            "warnings": [],
                        },
                    },
                ],
            },
            "preprocessing": {
                "status": "success_with_warnings",
                "component_count": 3,
                "components": [
                    {
                        "filename": "base.apk",
                        "role": "base",
                        "size_bytes": 24792837,
                        "sha256": "1d3ceed81356f18b8e56973ff2a398f911ef8dc5d9e83b8fb8ade9b2861c9c73",
                        "dex_count": 3,
                        "preprocessing": {
                            "raw_extract_status": "success",
                            "apktool_status": "success_with_warnings",
                            "jadx_status": "success_with_warnings",
                            "warnings": ["JADX exited with warnings (code 3) for 'base.apk'"],
                        },
                    },
                    {
                        "filename": "split_config.en.apk",
                        "role": "config_locale",
                        "size_bytes": 37273,
                        "sha256": "64b6388a0f72ef3e017bd01a07220af441183d6d2d6d1fc2b9e71b87f558b4e7",
                        "dex_count": 0,
                        "preprocessing": {
                            "raw_extract_status": "success",
                            "apktool_status": "success",
                            "jadx_status": "skipped_no_dex",
                            "warnings": [],
                        },
                    },
                    {
                        "filename": "split_config.xxhdpi.apk",
                        "role": "config_density",
                        "size_bytes": 312560,
                        "sha256": "3b12cd81356f18b8e56973ff2a398f911ef8dc5d9e83b8fb8ade9b2861c9c73",
                        "dex_count": 0,
                        "preprocessing": {
                            "raw_extract_status": "success",
                            "apktool_status": "success",
                            "jadx_status": "skipped_no_dex",
                            "warnings": [],
                        },
                    },
                ],
            },
            "static_analysis": {
                "package_name": "apps.r.flashlight",
                "package_layout": "split",
                "split_count": 3,
                "app": {
                    "package_name": "apps.r.flashlight",
                    "launcher_activity": "apps.r.flashlight.MainActivity",
                },
                "structure": {
                    "total_dex_count": 3,
                    "dex_count": 3,
                    "is_multidex": True,
                    "components": [
                        {
                            "source_apk": "base.apk",
                            "role": "base",
                            "dex_files": ["classes.dex", "classes2.dex", "classes3.dex"],
                            "dex_count": 3,
                            "is_multidex": True,
                            "smali_roots": ["smali", "smali_classes2", "smali_classes3"],
                            "assets": ["assets/audience_network.dex"],
                            "native_libraries": ["lib/arm64-v8a/libfoo.so"],
                            "has_native_code": True,
                            "has_kotlin_metadata": True,
                        },
                        {
                            "source_apk": "split_config.en.apk",
                            "role": "config_locale",
                            "dex_files": [],
                            "dex_count": 0,
                            "is_multidex": False,
                            "smali_roots": [],
                            "assets": [],
                            "native_libraries": [],
                            "has_native_code": False,
                            "has_kotlin_metadata": False,
                        },
                        {
                            "source_apk": "split_config.xxhdpi.apk",
                            "role": "config_density",
                            "dex_files": [],
                            "dex_count": 0,
                            "is_multidex": False,
                            "smali_roots": [],
                            "assets": [],
                            "native_libraries": [],
                            "has_native_code": False,
                            "has_kotlin_metadata": False,
                        },
                    ],
                },
                "permissions": ["android.permission.CAMERA", "android.permission.FLASHLIGHT"],
                "activities": ["apps.r.flashlight.MainActivity", "apps.r.flashlight.SettingsActivity"],
                "network_indicators": {
                    "network_urls": [
                        {
                            "value": "https://api.example.com/v1/config",
                            "type": "network_url",
                            "source_apk": "base.apk",
                            "source_file": "smali/com/example/Network.smali",
                            "line_number": 42,
                        }
                    ],
                    "domains": [
                        {
                            "value": f"domain{i}.example.com",
                            "type": "domain",
                            "source_apk": "split_config.en.apk" if i % 2 == 0 else "base.apk",
                            "source_file": "res/values-en/strings.xml" if i % 2 == 0 else "smali/com/example/Foo.smali",
                            "line_number": 100 + i,
                        }
                        for i in range(150)  # Over 100 to test HTML table bounding!
                    ],
                    "ip_addresses": [
                        {
                            "value": "192.168.1.1",
                            "type": "ip_address",
                            "source_apk": "base.apk",
                            "source_file": "smali/com/example/Config.smali",
                            "line_number": 88,
                        }
                    ],
                    "path_candidates": [],
                    "local_file_urls": [],
                },
                "api_candidates": [],
            },
            "runtime": {
                "status": "runtime_launch_verified",
                "adb": {"serial": "127.0.0.1:5555"},
                "install": {"success": True, "skipped": True},
                "launch": {"component": "apps.r.flashlight/apps.r.flashlight.MainActivity"},
                "runtime": {
                    "pid": 1234,
                    "observed_package": "apps.r.flashlight",
                    "observed_activity": "apps.r.flashlight.MainActivity",
                    "foreground_verified": True,
                },
            },
            "demo_status": "completed",
        }

    def test_01_split_package_dashboard_overview(self):
        """Requirement 1 & 3: Overview values reflect split layout, component counts, DEX, indicators."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        self.assertEqual(report["package_layout"], "split")
        self.assertEqual(report["split_count"], 3)
        self.assertEqual(len(report["apk_components"]), 3)
        self.assertEqual(report["structure"]["dex_count"], 3)
        self.assertEqual(report["runtime"]["status"], "runtime_launch_verified")

    def test_02_component_inventory_rendering_in_html(self):
        """Requirement 2 & 5: Component inventory table rendered with proper columns."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        html_out = render_html_report(report)

        self.assertIn("APK Component Inventory", html_out)
        self.assertIn("base.apk", html_out)
        self.assertIn("split_config.en.apk", html_out)
        self.assertIn("split_config.xxhdpi.apk", html_out)
        self.assertIn("config_locale", html_out)
        self.assertIn("config_density", html_out)

    def test_03_base_component_statuses(self):
        """Requirement 3 & 11: Base component preserves warnings, shown with warning badge."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        html_out = render_html_report(report)

        self.assertIn("success_with_warnings", html_out)
        self.assertIn("JADX exited with warnings (code 3)", html_out)

    def test_04_dexless_skipped_no_dex_rendering(self):
        """Requirement 4 & 11: DEX-less split components render skipped_no_dex as informational, not error."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        html_out = render_html_report(report)

        self.assertIn("skipped_no_dex", html_out)
        self.assertIn("DEX-less splits (e.g. config splits) intentionally skip JADX decompilation", html_out)

    def test_05_split_structure_grouped_by_source_apk(self):
        """Requirement 6: Structure tab groups evidence per Source APK, showing smali roots, native, assets."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        html_out = render_html_report(report)

        self.assertIn("Source APK: <code>base.apk</code>", html_out)
        self.assertIn("Source APK: <code>split_config.en.apk</code>", html_out)
        self.assertIn("Source APK: <code>split_config.xxhdpi.apk</code>", html_out)
        self.assertIn("smali_classes2", html_out)
        self.assertIn("libfoo.so", html_out)
        self.assertIn("audience_network.dex", html_out)

    def test_06_network_source_apk_column(self):
        """Requirement 6 & 8: Network indicator table includes Source APK column."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        html_out = render_html_report(report)

        self.assertIn("<th>Source APK</th>", html_out)
        self.assertIn("<code>base.apk</code>", html_out)
        self.assertIn("<code>split_config.en.apk</code>", html_out)

    def test_07_source_apk_filter_and_pagination_in_dashboard_ui(self):
        """Requirement 7 & 8: Dashboard HTML includes netSearchInput, netSourceApkSelect, pagination."""
        from src.demo_web_server import HTML_PAGE
        html = HTML_PAGE

        self.assertIn('id="netSearchInput"', html)
        self.assertIn('id="netSourceApkSelect"', html)
        self.assertIn('id="networkTotalCountTag"', html)
        self.assertIn('class="pagination-bar"', html)
        self.assertIn('changeNetPage', html)
        self.assertIn('setNetCategory', html)

    def test_08_network_pagination_bounded_rendering_in_html(self):
        """Requirement 8 & 14: HTML report bounds indicators to first 100 with clear count notice."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        html_out = render_html_report(report)

        # There were 150 domains in our test data
        self.assertIn("Showing first 100 of 150 domains indicators.", html_out)
        self.assertIn("domain0.example.com", html_out)
        self.assertIn("domain99.example.com", html_out)
        # 100th-150th should not appear in HTML report table to prevent huge HTML
        self.assertNotIn("domain120.example.com", html_out)

    def test_09_zero_api_candidates_remains_valid(self):
        """Requirement 9 & 10: Zero API candidates displays informational notice, not failure."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        self.assertEqual(len(report["api_candidates"]), 0)
        self.assertEqual(report["demo_status"], "completed")

        html_out = render_html_report(report)
        self.assertIn("No API candidates were identified by the current call-context extractor.", html_out)
        self.assertIn("Zero candidates does not mean the application has no APIs.", html_out)

    def test_10_api_candidate_source_apk_rendering(self):
        """Requirement 10: When API candidates exist, source_apk is rendered in column."""
        cand_result = dict(self.split_pipeline_result)
        cand_result["static_analysis"] = dict(self.split_pipeline_result["static_analysis"])
        cand_result["static_analysis"]["api_candidates"] = [
            {
                "method": "GET",
                "base_url": "https://api.example.com",
                "path": "/v1/status",
                "full_url": "https://api.example.com/v1/status",
                "framework": "Fuel",
                "source_apk": "base.apk",
                "source_file": "smali/com/example/Api.smali",
                "request_line": 25,
                "status": "static_api_candidate",
            }
        ]
        report = build_report_dict("run_cand_001", cand_result)
        html_out = render_html_report(report)

        self.assertIn("<th>Source APK</th>", html_out)
        self.assertIn("<code>base.apk</code>", html_out)
        self.assertIn("https://api.example.com/v1/status", html_out)

    def test_11_report_json_preserves_full_split_evidence(self):
        """Requirement 11 & 14: report.json retains ALL 150 indicators without truncation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run_test"
            json_path, _ = generate_reports(run_dir, "run_001", self.split_pipeline_result)

            with open(json_path, "r", encoding="utf-8") as f:
                saved = json.load(f)

            self.assertEqual(saved["package_layout"], "split")
            self.assertEqual(saved["split_count"], 3)
            self.assertEqual(len(saved["apk_components"]), 3)
            # Full 150 domains preserved in report.json!
            self.assertEqual(len(saved["network_indicators"]["domains"]), 150)
            self.assertEqual(saved["network_indicators"]["domains"][149]["value"], "domain149.example.com")
            self.assertEqual(saved["network_indicators"]["domains"][149]["source_apk"], "base.apk")

    def test_12_report_html_includes_component_inventory(self):
        """Requirement 12: report.html includes component inventory table."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        html_out = render_html_report(report)

        self.assertIn("APK Component Inventory", html_out)
        self.assertIn("split_config.xxhdpi.apk", html_out)
        self.assertIn("config_density", html_out)

    def test_13_report_html_bounded_indicator_display(self):
        """Requirement 13: report.html bounded indicator display prevents DOM bloat."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        html_out = render_html_report(report)

        self.assertIn("Showing first 100 of 150 domains indicators.", html_out)

    def test_14_jadx_warning_preserved(self):
        """Requirement 14: JADX warning is preserved in analysis notes and status."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        html_out = render_html_report(report)

        self.assertIn("JADX exited with warnings (code 3)", html_out)

    def test_15_installed_splits_limitation_note_visible(self):
        """Requirement 15: Limitation note explicitly clarifies installed pm path boundary."""
        report = build_report_dict("run_split_001", self.split_pipeline_result)
        html_out = render_html_report(report)

        expected_note = "Split package analysis: only installed splits returned by pm path on the device were analyzed."
        self.assertIn(expected_note, html_out)
        self.assertIn(expected_note, report["analysis_notes"])

    def test_16_split_orchestrator_path_completes(self):
        """Requirement 16: Orchestrator routes split packages to split preprocessor and static builder."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspaces_dir = Path(tmpdir) / "workspaces"
            downloads_dir = Path(tmpdir) / "downloads"

            # Mock acquire_apk to return split package_set
            mock_acq = {
                "source_type": "play_store",
                "package_name": "apps.r.flashlight",
                "package_layout": "split",
                "split_count": 2,
                "package_set_path": str(workspaces_dir / "package_set" / "package_set.json"),
                "components": [
                    {"filename": "base.apk", "role": "base", "dex_count": 1},
                    {"filename": "split_config.en.apk", "role": "config_locale", "dex_count": 0},
                ],
            }

            mock_prep = {
                "status": "success",
                "component_count": 2,
                "package_set_path": str(workspaces_dir / "package_set" / "package_set.json"),
                "components": mock_acq["components"],
            }

            mock_static = {
                "package_name": "apps.r.flashlight",
                "package_layout": "split",
                "split_count": 2,
                "app": {"package_name": "apps.r.flashlight", "launcher_activity": "MainActivity"},
                "structure": {"dex_count": 1, "components": []},
                "network_indicators": {"network_urls": [], "domains": []},
                "api_candidates": [],
            }

            mock_runtime = {
                "status": "runtime_launch_verified",
                "install": {"success": True, "skipped": True},
                "runtime": {"pid": 9999, "observed_package": "apps.r.flashlight"},
            }

            with patch("src.demo_orchestrator.get_connected_devices", return_value=["emulator-5554"]), \
                 patch("src.demo_orchestrator.acquire_play_store_app", return_value=mock_acq), \
                 patch("src.demo_orchestrator.preprocess_package_set", return_value=mock_prep) as mock_p, \
                 patch("src.demo_orchestrator.build_split_static_context", return_value=mock_static) as mock_s, \
                 patch("src.demo_orchestrator.launch_android_app", return_value=mock_runtime) as mock_r:

                res = run_demo(
                    url="https://play.google.com/store/apps/details?id=apps.r.flashlight",
                    output_root=workspaces_dir,
                )

                mock_p.assert_called_once()
                mock_s.assert_called_once()
                mock_r.assert_called_once()
                self.assertEqual(res["acquisition"]["package_layout"], "split")
                self.assertEqual(res["demo_status"], "completed")

    def test_17_monolithic_regression(self):
        """Requirement 17: Monolithic packages continue showing Single APK without split presentation."""
        monolithic_result = {
            "input": {"url": "https://play.google.com/store/apps/details?id=com.mono.app", "platform": "android"},
            "acquisition": {
                "platform": "android",
                "source_type": "play_store",
                "package_name": "com.mono.app",
                "package_layout": "monolithic",
                "filename": "com.mono.app.apk",
                "sha256": "abcdef123456",
                "size_bytes": 5000000,
            },
            "preprocessing": {
                "raw_apk": {"file_count": 20},
                "apktool": {"status": "success", "returncode": 0},
                "jadx": {"status": "success", "returncode": 0},
            },
            "static_analysis": {
                "package_name": "com.mono.app",
                "package_layout": "monolithic",
                "app": {"package_name": "com.mono.app", "launcher_activity": "MainActivity"},
                "structure": {"dex_count": 1, "is_multidex": False},
                "network_indicators": {"network_urls": [], "domains": []},
                "api_candidates": [],
            },
            "runtime": {"status": "runtime_launch_verified"},
            "demo_status": "completed",
        }
        report = build_report_dict("run_mono_001", monolithic_result)
        self.assertEqual(report["package_layout"], "monolithic")
        self.assertEqual(report["split_count"], 1)

        html_out = render_html_report(report)
        self.assertIn("Single APK", html_out)
        self.assertNotIn("APK Component Inventory", html_out)

    def test_18_direct_apk_regression(self):
        """Requirement 18: Direct APK URL continues showing Single APK without split artifacts."""
        direct_result = {
            "input": {"url": "https://example.com/app.apk", "platform": "android"},
            "acquisition": {
                "platform": "android",
                "source_type": "direct_apk",
                "filename": "app.apk",
                "sha256": "9876543210fedcba",
                "size_bytes": 1000000,
            },
            "preprocessing": {
                "raw_apk": {"file_count": 15},
                "apktool": {"status": "success"},
                "jadx": {"status": "success"},
            },
            "static_analysis": {
                "package_name": "org.example.direct",
                "app": {"package_name": "org.example.direct", "launcher_activity": "MainActivity"},
                "structure": {"dex_count": 1, "is_multidex": False},
                "network_indicators": {"network_urls": [], "domains": []},
                "api_candidates": [],
            },
            "runtime": {"status": "runtime_launch_verified"},
            "demo_status": "completed",
        }
        report = build_report_dict("run_direct_001", direct_result)
        self.assertEqual(report["package_layout"], "monolithic")

        html_out = render_html_report(report)
        self.assertIn("Single APK", html_out)
        self.assertNotIn("APK Component Inventory", html_out)


if __name__ == "__main__":
    unittest.main()
