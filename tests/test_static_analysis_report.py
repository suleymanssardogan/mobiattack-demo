"""Unit tests for Canonical Static Analysis Report Contract (Task 2.1)."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from src.report_generator import (
    build_report_dict,
    build_static_analysis_report,
    generate_reports,
    save_static_analysis_report,
)


class TestStaticAnalysisReportContract(unittest.TestCase):

    def setUp(self):
        self.sample_result = {
            "input": {
                "url": "https://example.com/test.apk",
                "adb_serial": "127.0.0.1:5555",
                "reinstall": True,
                "grant_permissions": True,
            },
            "acquisition": {
                "input_url": "https://example.com/test.apk",
                "final_url": "https://example.com/test.apk",
                "status_code": 200,
                "content_type": "application/vnd.android.package-archive",
                "filename": "test_app.apk",
                "saved_path": "downloads/test_app.apk",
                "size_bytes": 2048000,
                "sha256": "86c059775aa09e4794defd40f81e69751a81019b1b1f285b30b8f7c5bb5e8b68",
                "package_type": "apk",
                "platform": "android",
                "source_type": "direct_apk",
                "validation": {"is_valid_apk": True, "has_android_manifest": True, "has_dex": True},
            },
            "preprocessing": {
                "apk_path": "downloads/test_app.apk",
                "workspace": "workspaces/test_app",
                "raw_apk": {"output_dir": "workspaces/test_app/raw", "file_count": 120},
                "apktool": {"status": "success", "returncode": 0, "output_dir": "workspaces/test_app/apktool_out"},
                "jadx": {"status": "success", "returncode": 0, "output_dir": "workspaces/test_app/jadx_out"},
            },
            "static_analysis": {
                "app": {
                    "package_name": "com.example.securitytest",
                    "launcher_activity": "com.example.securitytest.MainActivity",
                },
                "permissions": ["android.permission.INTERNET", "android.permission.CAMERA"],
                "activities": ["com.example.securitytest.MainActivity", "com.example.securitytest.SettingsActivity"],
                "structure": {
                    "dex_files": ["classes.dex"],
                    "dex_count": 1,
                    "is_multidex": False,
                    "native_libraries": ["lib/arm64-v8a/libnative.so"],
                    "has_native_code": True,
                    "assets": ["assets/secret.txt"],
                    "smali_roots": ["smali"],
                    "has_kotlin_metadata": True,
                },
                "network_indicators": {
                    "network_urls": [
                        {"type": "network_url", "value": "https://api.example.com/v1", "source_file": "smali/Net.smali", "line_number": 24}
                    ],
                    "domains": [
                        {"type": "domain", "value": "api.example.com", "source_file": "smali/Net.smali", "line_number": 24}
                    ],
                    "ip_addresses": [
                        {"type": "ip_address", "value": "10.0.2.2", "source_file": "res/values/strings.xml", "line_number": 5}
                    ],
                    "path_candidates": [
                        {"type": "path_candidate", "value": "/v1/auth", "source_file": "smali/Net.smali", "line_number": 30}
                    ],
                    "local_file_urls": [
                        {"type": "local_file_url", "value": "file:///android_asset/web.html", "source_file": "smali/Web.smali", "line_number": 12}
                    ],
                },
                "api_candidates": [
                    {
                        "framework": "Fuel",
                        "method": "POST",
                        "base_url": "https://api.example.com",
                        "path": "/v1/auth",
                        "full_url": "https://api.example.com/v1/auth",
                        "status": "static_api_candidate",
                        "source_file": "smali/Net.smali",
                        "request_line": 35,
                        "evidence": {"path_value": "/v1/auth", "base_url_value": "https://api.example.com"},
                    }
                ],
            },
            "runtime": {
                "adb": {"serial": "emulator-5554"},
                "status": "runtime_launch_verified",
                "runtime": {
                    "pid": 4321,
                    "observed_package": "com.example.securitytest",
                    "observed_activity": "com.example.securitytest.MainActivity",
                },
            },
            "connectivity_probe": {"reachable": True, "probe_status": "ok"},
            "demo_status": "completed",
        }

    def test_static_analysis_report_generation_and_schema(self):
        """Verifies generate_reports outputs a valid static_analysis_report.json matching contract."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run_test_001"
            json_path, html_path = generate_reports(
                run_dir=run_dir,
                run_id="run_test_001",
                pipeline_result=self.sample_result,
            )

            # 1. Verify static_analysis_report.json is created
            static_path = run_dir / "static_analysis_report.json"
            self.assertTrue(static_path.is_file(), "static_analysis_report.json must be created in run_dir")

            # 2. Verify valid JSON
            with open(static_path, "r", encoding="utf-8") as f:
                report = json.load(f)

            # 3. Verify run_id
            self.assertEqual(report.get("run_id"), "run_test_001")

            # 4. Verify application identity
            app = report.get("application", {})
            self.assertEqual(app.get("package_name"), "com.example.securitytest")
            self.assertEqual(app.get("launcher_activity"), "com.example.securitytest.MainActivity")
            self.assertEqual(app.get("sha256"), "86c059775aa09e4794defd40f81e69751a81019b1b1f285b30b8f7c5bb5e8b68")

            # 5. Verify acquisition metadata
            acq = report.get("acquisition", {})
            self.assertEqual(acq.get("input_url"), "https://example.com/test.apk")
            self.assertEqual(acq.get("status_code"), 200)
            self.assertEqual(acq.get("filename"), "test_app.apk")

            # 6. Verify static findings / vulnerabilities
            self.assertIn("vulnerabilities", report)
            vulns = report["vulnerabilities"]
            self.assertIn("risk_score", vulns)
            self.assertIn("summary", vulns)
            self.assertIn("findings", vulns)
            self.assertIsInstance(vulns["findings"], list)

            # 7. Verify API and network candidate data
            net = report.get("network_indicators", {})
            self.assertEqual(len(net.get("network_urls", [])), 1)
            self.assertEqual(net["network_urls"][0]["value"], "https://api.example.com/v1")
            api = report.get("api_candidates", [])
            self.assertEqual(len(api), 1)
            self.assertEqual(api[0]["full_url"], "https://api.example.com/v1/auth")

            # 8. Verify artifact identity indicates static analysis
            self.assertEqual(report.get("report_type"), "static_analysis")
            self.assertEqual(report.get("report_version"), "1.0")
            self.assertEqual(report.get("status"), "completed")

            # 9. Verify runtime and connectivity domain are explicitly excluded
            self.assertNotIn("runtime", report, "Canonical static analysis report must not contain runtime domain")
            self.assertNotIn("connectivity_probe", report, "Canonical static analysis report must not contain connectivity probe domain")

            # 10. Verify legacy report.json is still intact and valid
            self.assertTrue(json_path.is_file())
            self.assertTrue(html_path.is_file())
            with open(json_path, "r", encoding="utf-8") as f:
                legacy_report = json.load(f)
            self.assertIn("runtime", legacy_report, "Legacy report.json must retain runtime block for backwards compatibility")
            self.assertIn("connectivity_probe", legacy_report)

            # 11. Task 2.1.1: Verify limitations and notes clean static boundary
            for lim in report.get("limitations", []):
                self.assertNotIn("process/activity foreground observation", lim.lower())
                self.assertNotIn("emulator connectivity", lim.lower())
            for note in report.get("analysis_notes", []):
                self.assertNotIn("process was observed", note.lower())
                self.assertNotIn("runtime execution", note.lower())
                self.assertNotIn("connectivity probe", note.lower())

    def test_static_boundary_limitations_language(self):
        """Verifies limitations are rephrased to pure static heuristics without process observation."""
        report = build_static_analysis_report("run_boundary", pipeline_result=self.sample_result)
        limitations = report.get("limitations", [])
        self.assertTrue(any("static heuristics on decoded package contents" in lim for lim in limitations))
        for lim in limitations:
            self.assertNotIn("basic process/activity foreground observation", lim)
            self.assertNotIn("emulator connectivity", lim)

    def test_static_artifact_generation_failure_is_not_silently_swallowed(self):
        """Verifies that an unexpected failure during static report generation emits a warning and is not silent."""
        from unittest.mock import patch
        import logging

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run_fail_test"
            with patch("src.report_generator.build_static_analysis_report", side_effect=RuntimeError("Forced static report error")):
                with self.assertWarns(RuntimeWarning) as warning_cm:
                    with self.assertLogs("src.report_generator", level=logging.ERROR) as log_cm:
                        json_path, html_path = generate_reports(
                            run_dir=run_dir,
                            run_id="run_fail_test",
                            pipeline_result=self.sample_result,
                        )

            # 1. Warning was emitted with error detail
            self.assertIn("Forced static report error", str(warning_cm.warning))
            # 2. Error was logged with exc_info
            self.assertTrue(any("Failed to generate canonical static_analysis_report.json" in rec.getMessage() for rec in log_cm.records))
            # 3. Legacy report.json and report.html are still created
            self.assertTrue(json_path.is_file())
            self.assertTrue(html_path.is_file())

    def test_partial_failure_later_stage_preserves_static_report(self):
        """Verifies that if pipeline fails at runtime, static_analysis_report is still preserved as completed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run_test_fail_runtime"
            failed_pipeline = dict(self.sample_result)
            failed_pipeline["demo_status"] = "failed"
            failed_pipeline["failed_stage"] = "runtime"
            failed_pipeline["failure_reason"] = "ADB device connection dropped during launch"

            generate_reports(
                run_dir=run_dir,
                run_id="run_test_fail_runtime",
                pipeline_result=failed_pipeline,
                error="ADB device connection dropped during launch",
                current_stage="runtime",
            )

            static_path = run_dir / "static_analysis_report.json"
            self.assertTrue(static_path.is_file())
            with open(static_path, "r", encoding="utf-8") as f:
                report = json.load(f)

            # Static analysis was finished before runtime failed
            self.assertEqual(report["report_type"], "static_analysis")
            self.assertEqual(report["status"], "completed")
            self.assertEqual(report["application"]["package_name"], "com.example.securitytest")
            self.assertNotIn("runtime", report)

    def test_early_acquisition_failure_marks_static_report_failed(self):
        """Verifies that if pipeline fails during acquisition without static data, status is failed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run_test_fail_acq"
            early_fail = {
                "input": {"url": "https://invalid.com/not_an_apk.txt"},
                "demo_status": "failed",
                "acquisition": {"input_url": "https://invalid.com/not_an_apk.txt"},
            }

            generate_reports(
                run_dir=run_dir,
                run_id="run_test_fail_acq",
                pipeline_result=early_fail,
                error="Downloaded content is not a valid Android APK",
                current_stage="acquisition",
            )

            static_path = run_dir / "static_analysis_report.json"
            self.assertTrue(static_path.is_file())
            with open(static_path, "r", encoding="utf-8") as f:
                report = json.load(f)

            self.assertEqual(report["report_type"], "static_analysis")
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["failed_stage"], "acquisition")
            self.assertIn("not a valid Android APK", report["failure_reason"])

    def test_partial_preprocessing_marks_status_partial(self):
        """Verifies that JADX returncode 3 (success_with_warnings) yields status partial."""
        partial_result = dict(self.sample_result)
        partial_result["preprocessing"] = {
            "apktool": {"status": "success"},
            "jadx": {"status": "success_with_warnings", "returncode": 3},
        }
        report = build_static_analysis_report("run_partial", pipeline_result=partial_result)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["report_type"], "static_analysis")

    def test_canonical_static_report_sanitization_policy(self):
        """Task 2.2: Verifies host paths, executables, and workspaces are sanitized while preserving application evidence and network URLs."""
        synthetic_input = {
            "input": {
                "url": "https://example.com/test_synthetic.apk",
            },
            "acquisition": {
                "input_url": "https://example.com/test_synthetic.apk",
                "final_url": "https://example.com/test_synthetic.apk",
                "status_code": 200,
                "content_type": "application/vnd.android.package-archive",
                "filename": "synthetic_app.apk",
                "saved_path": "/Users/example/workspace/mobiattack/demo_runs/run_syn/downloads/synthetic_app.apk",
                "size_bytes": 1048576,
                "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "package_type": "apk",
                "platform": "android",
                "source_type": "direct_apk",
                "validation": {"is_valid_apk": True, "has_android_manifest": True, "has_dex": True},
            },
            "preprocessing": {
                "apk_path": "/Users/example/workspace/mobiattack/demo_runs/run_syn/downloads/synthetic_app.apk",
                "workspace": "/Users/example/workspace/mobiattack/demo_runs/run_syn/workspaces/app",
                "raw_apk": {
                    "output_dir": "/Users/example/workspace/mobiattack/demo_runs/run_syn/workspaces/app/raw",
                    "file_count": 55,
                    "warnings": ["Warning during extraction of /home/example/temp_bundle.apk"],
                },
                "apktool": {
                    "status": "success",
                    "executable": "/opt/homebrew/bin/apktool",
                    "output_dir": "/Users/example/workspace/mobiattack/demo_runs/run_syn/workspaces/app/apktool_out",
                    "returncode": 0,
                    "warnings": [],
                },
                "jadx": {
                    "status": "success_with_warnings",
                    "executable": "/opt/homebrew/bin/jadx",
                    "output_dir": "/Users/example/workspace/mobiattack/demo_runs/run_syn/workspaces/app/jadx_out",
                    "returncode": 3,
                    "warnings": ["JADX warnings on /opt/homebrew/Cellar/jadx/bin/jadx"],
                },
            },
            "static_analysis": {
                "app": {
                    "package_name": "com.synthetic.sample",
                    "launcher_activity": "com.synthetic.sample.MainActivity",
                },
                "permissions": ["android.permission.INTERNET"],
                "activities": ["com.synthetic.sample.MainActivity"],
                "structure": {
                    "dex_files": ["classes.dex"],
                    "dex_count": 1,
                    "is_multidex": False,
                    "native_libraries": [],
                    "has_native_code": False,
                    "assets": ["assets/config.json"],
                    "smali_roots": ["smali"],
                    "has_kotlin_metadata": False,
                },
                "network_indicators": {
                    "network_urls": [
                        {
                            "type": "network_url",
                            "value": "https://api.synthetic.org/v1/auth",
                            "source_file": "/Users/example/workspace/smali/com/synthetic/sample/AuthActivity.smali",
                            "line_number": 42,
                        },
                        {
                            "type": "network_url",
                            "value": "http://127.0.0.1:8080/debug",
                            "source_file": "smali/com/synthetic/sample/DebugNet.smali",
                            "line_number": 88,
                        },
                    ],
                    "domains": [
                        {
                            "type": "domain",
                            "value": "api.synthetic.org",
                            "source_file": "/home/example/build/smali/com/synthetic/sample/AuthActivity.smali",
                            "line_number": 42,
                        }
                    ],
                },
                "api_candidates": [
                    {
                        "base_url": "http://127.0.0.1:8080",
                        "path": "/debug",
                        "full_url": "http://127.0.0.1:8080/debug",
                        "source_file": "/Users/example/workspace/smali/com/synthetic/sample/DebugNet.smali",
                        "detection_method": "call_context_register_flow",
                    }
                ],
            },
            "vulnerabilities": {
                "risk_score": "HIGH",
                "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "total": 1},
                "findings": [
                    {
                        "id": "SEC-NET-01",
                        "title": "Cleartext HTTP Traffic Permitted",
                        "severity": "HIGH",
                        "description": "Cleartext HTTP communication detected",
                        "evidence": "Discovered plaintext HTTP URL http://127.0.0.1:8080/debug",
                        "affected_items": [
                            "http://127.0.0.1:8080/debug",
                            "AndroidManifest.xml: android:debuggable=\"true\"",
                            "/sbin/su",
                            "/Users/example/workspace/smali/com/synthetic/sample/DebugNet.smali",
                        ],
                    }
                ],
            },
            "runtime": {
                "adb": {"serial": "emulator-5554"},
                "status": "runtime_launch_verified",
            },
            "connectivity_probe": {"reachable": True},
            "demo_status": "completed",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run_syn_001"
            json_path, _ = generate_reports(
                run_dir=run_dir,
                run_id="run_syn_001",
                pipeline_result=synthetic_input,
            )

            static_path = run_dir / "static_analysis_report.json"
            self.assertTrue(static_path.is_file())

            with open(static_path, "r", encoding="utf-8") as f:
                canonical_report = json.load(f)
            with open(json_path, "r", encoding="utf-8") as f:
                legacy_report = json.load(f)

            # 1. Canonical report does not contain /Users/
            # 2. Canonical report does not contain /home/
            # 3. Canonical report does not contain /opt/homebrew/
            serialized_canonical = json.dumps(canonical_report)
            self.assertNotIn("/Users/", serialized_canonical)
            self.assertNotIn("/home/", serialized_canonical)
            self.assertNotIn("/opt/homebrew/", serialized_canonical)
            self.assertNotIn("/tmp/", serialized_canonical)
            self.assertNotIn("/private/", serialized_canonical)

            # 4. apktool.executable is absent in canonical report
            self.assertNotIn("executable", canonical_report["preprocessing"].get("apktool", {}))

            # 5. jadx.executable is absent in canonical report
            self.assertNotIn("executable", canonical_report["preprocessing"].get("jadx", {}))

            # 6. Host workspace / output paths are absent in canonical report
            self.assertNotIn("workspace", canonical_report["preprocessing"])
            self.assertNotIn("apk_path", canonical_report["preprocessing"])
            self.assertNotIn("output_dir", canonical_report["preprocessing"]["raw_apk"])
            self.assertNotIn("output_dir", canonical_report["preprocessing"]["apktool"])
            self.assertNotIn("output_dir", canonical_report["preprocessing"]["jadx"])

            # Acquisition saved_path is product-safe relative representation
            self.assertEqual(canonical_report["acquisition"]["saved_path"], "downloads/synthetic_app.apk")

            # 7. Application-relative source_file evidence is preserved
            net_urls = canonical_report["network_indicators"]["network_urls"]
            self.assertEqual(net_urls[0]["source_file"], "smali/com/synthetic/sample/AuthActivity.smali")
            self.assertEqual(net_urls[1]["source_file"], "smali/com/synthetic/sample/DebugNet.smali")

            domains = canonical_report["network_indicators"]["domains"]
            self.assertEqual(domains[0]["source_file"], "smali/com/synthetic/sample/AuthActivity.smali")

            api_cands = canonical_report["api_candidates"]
            self.assertEqual(api_cands[0]["source_file"], "smali/com/synthetic/sample/DebugNet.smali")

            # 8. AndroidManifest.xml evidence is preserved
            # C2 revalidates cached findings; URL strings alone are not findings.
            self.assertEqual(canonical_report["vulnerabilities"]["findings"], [])
            # Verify the path sanitizer independently with the legacy payload.
            from src.report_generator import sanitize_vulnerabilities_for_canonical_report
            finding = sanitize_vulnerabilities_for_canonical_report(synthetic_input["vulnerabilities"])["findings"][0]
            self.assertIn("AndroidManifest.xml: android:debuggable=\"true\"", finding["affected_items"])

            # Device-side inspection paths (/sbin/su) are preserved as target evidence
            self.assertIn("/sbin/su", finding["affected_items"])

            # Host path in affected_items is sanitized to application relative
            self.assertIn("smali/com/synthetic/sample/DebugNet.smali", finding["affected_items"])

            # 9. https://... URL evidence is preserved
            self.assertEqual(net_urls[0]["value"], "https://api.synthetic.org/v1/auth")

            # 10. http://127.0.0.1/... API candidate URLs are preserved
            self.assertEqual(api_cands[0]["full_url"], "http://127.0.0.1:8080/debug")
            self.assertEqual(api_cands[0]["base_url"], "http://127.0.0.1:8080")
            self.assertEqual(net_urls[1]["value"], "http://127.0.0.1:8080/debug")

            # 11. Legacy report.json internal path contract is preserved intact
            self.assertEqual(legacy_report["preprocessing"]["apktool"]["executable"], "/opt/homebrew/bin/apktool")
            self.assertEqual(legacy_report["preprocessing"]["jadx"]["executable"], "/opt/homebrew/bin/jadx")
            self.assertEqual(legacy_report["preprocessing"]["workspace"], "/Users/example/workspace/mobiattack/demo_runs/run_syn/workspaces/app")
            self.assertEqual(legacy_report["acquisition"]["saved_path"], "/Users/example/workspace/mobiattack/demo_runs/run_syn/downloads/synthetic_app.apk")
            self.assertIn("/Users/example/", json.dumps(legacy_report))

    def test_canonical_split_and_ios_sanitization(self):
        """Task 2.2: Verifies split APK package sets and iOS Mach-O linked libraries are properly sanitized."""
        # 1. Split APK
        split_dict = {
            "acquisition": {
                "package_layout": "split",
                "package_set_path": "/Users/example/demo_runs/run_1/downloads/package_set/package_set.json",
                "components": [
                    {
                        "filename": "base.apk",
                        "local_path": "/Users/example/demo_runs/run_1/downloads/package_set/apks/base.apk",
                        "device_path": "/data/app/~~test/base.apk",
                    }
                ],
                "package_set": {
                    "components": [
                        {
                            "filename": "base.apk",
                            "local_path": "/Users/example/demo_runs/run_1/downloads/package_set/apks/base.apk",
                        }
                    ]
                }
            },
            "preprocessing": {
                "package_set_path": "/Users/example/demo_runs/run_1/downloads/package_set/package_set.json",
                "processed_root": "/Users/example/demo_runs/run_1/workspaces/processed",
                "components": [
                    {
                        "filename": "base.apk",
                        "role": "base",
                        "raw_extract_status": "success",
                        "apktool_status": "success",
                        "workspace": "/Users/example/demo_runs/run_1/workspaces/processed/base",
                        "raw_apk_dir": "/Users/example/demo_runs/run_1/workspaces/processed/base/raw",
                    }
                ]
            },
            "apk_components": [
                {
                    "filename": "base.apk",
                    "role": "base",
                    "local_path": "/Users/example/demo_runs/run_1/downloads/package_set/apks/base.apk",
                    "workspace": "/Users/example/demo_runs/run_1/workspaces/processed/base",
                    "preprocessing": {
                        "workspace": "/Users/example/demo_runs/run_1/workspaces/processed/base",
                        "apktool_status": "success",
                    }
                }
            ]
        }
        report = build_static_analysis_report("split_run", report_dict=split_dict)
        report_json_str = json.dumps(report)
        self.assertNotIn("/Users/", report_json_str)
        self.assertEqual(report["acquisition"]["package_set_path"], "downloads/package_set/package_set.json")
        self.assertEqual(report["acquisition"]["components"][0]["local_path"], "downloads/package_set/apks/base.apk")
        self.assertEqual(report["acquisition"]["components"][0]["device_path"], "/data/app/~~test/base.apk")
        self.assertEqual(report["apk_components"][0]["local_path"], "downloads/package_set/apks/base.apk")
        self.assertNotIn("workspace", report["apk_components"][0])
        self.assertNotIn("workspace", report["preprocessing"]["components"][0])

        # 2. iOS IPA
        ios_dict = {
            "platform": "ios",
            "acquisition": {
                "filename": "App.ipa",
                "ipa_path": "/home/example/downloads/App.ipa",
            },
            "preprocessing": {
                "platform": "ios",
                "app_bundle": "Payload/App.app",
                "app_bundle_dir": "/home/example/workspaces/Payload/App.app",
                "extracted_files": 20,
            },
            "structure": {
                "macho_analysis": {
                    "linked_libraries": [
                        "/home/example/workspaces/Payload/App.app/App (architecture arm64):",
                        "@rpath/Alamofire.framework/Alamofire",
                        "/usr/lib/libSystem.B.dylib",
                    ]
                }
            }
        }
        ios_report = build_static_analysis_report("ios_run", report_dict=ios_dict)
        ios_json_str = json.dumps(ios_report)
        self.assertNotIn("/home/", ios_json_str)
        self.assertEqual(ios_report["acquisition"]["saved_path"], "downloads/App.ipa")
        self.assertNotIn("ipa_path", ios_report["acquisition"])
        self.assertNotIn("app_bundle_dir", ios_report["preprocessing"])
        # Header line with /home/ was stripped, valid libraries preserved
        self.assertEqual(ios_report["structure"]["macho_analysis"]["linked_libraries"], [
            "@rpath/Alamofire.framework/Alamofire",
            "/usr/lib/libSystem.B.dylib",
        ])
        self.assertEqual(ios_report["structure"]["macho_analysis"]["linked_library_count"], 2)

    def test_preset_canonical_reports_are_fully_sanitized(self):
        """Task 2.2: Verifies all canonical preset static_analysis_report.json artifacts contain no host environment leaks."""
        presets = [
            "preset_android_monolithic",
            "preset_android_split",
            "preset_ios_ipa",
        ]
        forbidden_prefixes = ("/Users/", "/home/", "/opt/homebrew/", "/private/", "/tmp/")
        repo_root = Path(__file__).resolve().parent.parent

        for preset in presets:
            preset_file = repo_root / "demo_runs" / preset / "static_analysis_report.json"
            if not preset_file.is_file():
                continue
            with open(preset_file, "r", encoding="utf-8") as f:
                content = f.read()

            for forbidden in forbidden_prefixes:
                self.assertNotIn(
                    forbidden,
                    content,
                    f"Forbidden host path {forbidden} found in preset artifact: {preset_file}",
                )

            report = json.loads(content)
            self.assertEqual(report.get("report_type"), "static_analysis")
            self.assertNotIn("runtime", report)
            self.assertNotIn("connectivity_probe", report)
            prep = report.get("preprocessing", {})
            self.assertNotIn("workspace", prep)
            self.assertNotIn("output_dir", prep.get("raw_apk", {}))
            self.assertNotIn("output_dir", prep.get("apktool", {}))
            self.assertNotIn("output_dir", prep.get("jadx", {}))
            self.assertNotIn("executable", prep.get("apktool", {}))
            self.assertNotIn("executable", prep.get("jadx", {}))


if __name__ == "__main__":
    unittest.main()

