"""Unit tests for src/report_generator.py."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from src.report_generator import build_report_dict, generate_reports, render_html_report


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.sample_result = {
            "input": {
                "url": "https://example.com/test.apk",
                "adb_serial": "127.0.0.1:5555",
                "reinstall": True,
                "grant_permissions": True,
            },
            "acquisition": {
                "filename": "MSTG-Android-Kotlin.apk",
                "saved_path": "downloads/MSTG-Android-Kotlin.apk",
                "size_bytes": 1048576,
                "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                "validation": {"is_valid_apk": True},
            },
            "preprocessing": {
                "raw_apk": {"output_dir": "workspaces/raw", "file_count": 42},
                "apktool": {"status": "success", "returncode": 0},
                "jadx": {"status": "success_with_warnings", "returncode": 3},
            },
            "static_analysis": {
                "app": {
                    "package_name": "org.owasp.mastestapp",
                    "launcher_activity": "org.owasp.mastestapp.MainActivity",
                },
                "permissions": ["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"],
                "activities": ["org.owasp.mastestapp.MainActivity", "org.owasp.mastestapp.DetailActivity"],
                "structure": {
                    "dex_files": ["classes.dex", "classes2.dex", "classes3.dex"],
                    "dex_count": 3,
                    "is_multidex": True,
                    "native_libraries": ["lib/arm64-v8a/libnative.so"],
                    "has_native_code": True,
                    "assets": ["assets/config.json"],
                    "smali_roots": ["smali", "smali_classes2", "smali_classes3"],
                    "has_kotlin_metadata": True,
                },
                "network_indicators": {
                    "network_urls": [
                        {"value": "https://example.com/api", "source_file": "smali/Example.smali", "line_number": 142}
                    ],
                    "domains": [
                        {"value": "example.com", "source_file": "smali/Example.smali", "line_number": 142}
                    ],
                    "ip_addresses": [
                        {"value": "192.168.1.1", "source_file": "res/values/strings.xml", "line_number": 12}
                    ],
                    "path_candidates": [
                        {"value": "/api/v1/login", "source_file": "smali/Auth.smali", "line_number": 55}
                    ],
                    "local_file_urls": [
                        {"value": "file:///android_asset/page.html", "source_file": "smali/Web.smali", "line_number": 88}
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
                        "source_file": "smali/AuthTask.smali",
                        "request_line": 99,
                        "evidence": {"path_value": "/v1/auth", "base_url_value": "https://api.example.com"},
                    }
                ],
            },
            "runtime": {
                "adb": {"serial": "127.0.0.1:5555"},
                "install": {"success": True, "reinstall": True, "grant_permissions": True},
                "launch": {"success": True, "component": "org.owasp.mastestapp/.MainActivity"},
                "runtime": {
                    "process_running": True,
                    "pid": 8402,
                    "observed_package": "org.owasp.mastestapp",
                    "observed_activity": "org.owasp.mastestapp.MainActivity",
                    "foreground_verified": True,
                },
                "status": "runtime_launch_verified",
            },
            "demo_status": "completed",
        }

    def test_report_dict_top_level_schema(self):
        report = build_report_dict("run_test_001", self.sample_result)
        expected_keys = {
            "report_version",
            "run_id",
            "demo_status",
            "application",
            "acquisition",
            "preprocessing",
            "structure",
            "permissions",
            "activities",
            "network_indicators",
            "api_candidates",
            "runtime",
            "connectivity_probe",
            "analysis_notes",
            "limitations",
        }
        self.assertTrue(expected_keys.issubset(set(report.keys())))
        self.assertEqual(report["report_version"], "1.0")
        self.assertEqual(report["run_id"], "run_test_001")
        self.assertEqual(report["demo_status"], "completed")
        self.assertEqual(report["application"]["package_name"], "org.owasp.mastestapp")
        self.assertEqual(report["application"]["sha256"], "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
        self.assertEqual(report["structure"]["dex_count"], 3)
        self.assertTrue(report["structure"]["is_multidex"])
        self.assertTrue(report["structure"]["has_native_code"])
        self.assertTrue(report["structure"]["has_kotlin_metadata"])

    def test_html_report_contains_14_numbered_sections(self):
        report = build_report_dict("run_test_001", self.sample_result)
        html_out = render_html_report(report)

        for i in range(1, 15):
            self.assertIn(f"{i}. ", html_out)

        self.assertIn("1. MobiAttack Android Demo Analysis Report", html_out)
        self.assertIn("2. Run Information", html_out)
        self.assertIn("3. Application Overview", html_out)
        self.assertIn("4. APK Acquisition", html_out)
        self.assertIn("5. Preprocessing", html_out)
        self.assertIn("6. Application Structure", html_out)
        self.assertIn("7. Permissions", html_out)
        self.assertIn("8. Activities", html_out)
        self.assertIn("9. Static Network Indicators", html_out)
        self.assertIn("10. Static API Candidates", html_out)
        self.assertIn("11. Runtime Evidence", html_out)
        self.assertIn("12. HTML Connectivity Probe", html_out)
        self.assertIn("13. Analysis Notes", html_out)
        self.assertIn("14. Limitations", html_out)

    def test_zero_api_candidates_explanation_in_json_and_html(self):
        zero_res = dict(self.sample_result)
        zero_res["static_analysis"] = dict(self.sample_result["static_analysis"])
        zero_res["static_analysis"]["api_candidates"] = []

        report = build_report_dict("run_test_zero", zero_res)
        html_out = render_html_report(report)

        # Must not fail the demo
        self.assertEqual(report["demo_status"], "completed")

        sentence_1 = "No API candidates were identified by the current call-context extractor."
        sentence_2 = "Zero candidates does not mean the application has no APIs."

        # Verify in notes of JSON
        notes_text = " ".join(report["analysis_notes"])
        self.assertIn(sentence_1, notes_text)
        self.assertIn(sentence_2, notes_text)

        # Verify in HTML
        self.assertIn(sentence_1, html_out)
        self.assertIn(sentence_2, html_out)

    def test_strict_api_candidate_status(self):
        report = build_report_dict("run_test_001", self.sample_result)
        html_out = render_html_report(report)

        self.assertEqual(report["api_candidates"][0]["status"], "static_api_candidate")
        self.assertIn("static_api_candidate", html_out)
        self.assertNotIn("confirmed endpoint", html_out)
        self.assertNotIn("validated endpoint", html_out)
        self.assertNotIn("vulnerable endpoint", html_out)

    def test_jadx_warning_preserved(self):
        report = build_report_dict("run_test_001", self.sample_result)
        html_out = render_html_report(report)

        self.assertIn("success_with_warnings", html_out)
        notes_text = " ".join(report["analysis_notes"])
        self.assertIn("JADX completed with warnings", notes_text)

    def test_no_security_verdicts_introduced(self):
        report = build_report_dict("run_test_001", self.sample_result)
        json_str = json.dumps(report)
        html_out = render_html_report(report)

        forbidden_phrases = [
            "Application Secure",
            "Application Insecure",
            "Security Score",
            "Risk Score",
            "Pentest Passed",
            "Security Passed",
            "Security Failed",
            "CVSS",
        ]
        for phrase in forbidden_phrases:
            self.assertNotIn(phrase, json_str)
            self.assertNotIn(phrase, html_out)

    def test_runtime_evidence_and_foreground_description(self):
        report = build_report_dict("run_test_001", self.sample_result)
        html_out = render_html_report(report)

        desc = "The application process was observed and the expected package/activity was detected in the foreground."
        self.assertIn(desc, html_out)
        self.assertEqual(report["runtime"]["install"]["reinstall"], True)
        self.assertEqual(report["runtime"]["install"]["grant_permissions"], True)
        self.assertIn("runtime_launch_verified", html_out)

    def test_static_network_indicators_semantic_warning(self):
        report = build_report_dict("run_test_001", self.sample_result)
        html_out = render_html_report(report)

        warning = "Static network indicators are extracted from application content and do not by themselves prove runtime network usage."
        self.assertIn(warning, html_out)

    def test_partial_failed_run_preserves_evidence(self):
        failed_res = {
            "input": {"url": "https://example.com/fail.apk"},
            "acquisition": {"filename": "fail.apk", "sha256": "12345"},
            "preprocessing": {"raw_apk": {"file_count": 10}},
        }
        report = build_report_dict(
            run_id="run_fail_001",
            pipeline_result=failed_res,
            error="Apktool decompilation crashed",
            current_stage="preprocessing",
        )
        self.assertEqual(report["demo_status"], "failed")
        self.assertEqual(report["failed_stage"], "preprocessing")
        self.assertIn("Apktool decompilation crashed", report["failure_reason"])
        self.assertEqual(report["acquisition"]["filename"], "fail.apk")

        html_out = render_html_report(report)
        self.assertIn("Run Failure:", html_out)
        self.assertIn("preprocessing", html_out)

    def test_generate_reports_writes_files_on_disk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / "run_001"
            json_path, html_path = generate_reports(
                run_dir=run_dir,
                run_id="run_001",
                pipeline_result=self.sample_result,
            )
            self.assertTrue(json_path.exists())
            self.assertTrue(html_path.exists())

            with open(json_path, "r", encoding="utf-8") as f:
                loaded_json = json.load(f)
            self.assertEqual(loaded_json["run_id"], "run_001")
            self.assertEqual(loaded_json["application"]["package_name"], "org.owasp.mastestapp")

            html_text = html_path.read_text(encoding="utf-8")
            self.assertIn("MobiAttack Android Demo Analysis Report", html_text)
            self.assertIn("org.owasp.mastestapp", html_text)


if __name__ == "__main__":
    unittest.main()


class TestCompactReportSummary(unittest.TestCase):
    """Presentation must preserve coverage truth and leave evidence untouched."""

    def setUp(self):
        from src.web.report_summary import build_report_summary, load_report_summary
        self.build = build_report_summary
        self.load = load_report_summary
        self.root = Path(__file__).resolve().parents[1]
        self.fixture = self.root / 'examples/auth_standards_report_d13'
        self.dynamic = json.loads((self.fixture / 'dynamic_analysis_report.json').read_text())

    def test_static_selected_fields_and_indicator_counts(self):
        source = json.loads((self.root / 'demo_runs/preset_android_monolithic/static_analysis_report.json').read_text())
        result = self.build(source)['static_summary']
        self.assertEqual(result['package'], 'sg.vantagepoint.mstgkotlin')
        self.assertEqual(result['api_candidates_count'], 1)
        self.assertEqual(result['frameworks_detected'], ['Fuel'])
        self.assertIn('INTERNET', result['key_permissions'])
        self.assertEqual(result['network_indicators']['ips'], len(source['network_indicators']['ip_addresses']))
        self.assertEqual(result['status'], 'partial')

    def test_projection_excludes_secrets_provenance_and_tool_paths(self):
        source = {'application': {'package_name': 'training.app', 'filename': '/Users/dev/private.apk'},
                  'permissions': ['android.permission.INTERNET'],
                  'api_candidates': [{'framework': 'Fuel', 'source': '/tmp/private.smali', 'token': 'secret-marker'}],
                  'network_indicators': {'network_urls': ['https://example.com/profile?token=secret-marker',
                                                        'https://user:secret-marker@private.example.com/']},
                  'acquisition': {'token': 'secret-marker'}, 'limitations': ['password=secret-marker']}
        result = self.build(source)
        encoded = json.dumps(result)
        for forbidden in ['secret-marker', 'private.smali', '/Users/', 'private.example.com', 'acquisition']:
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(result['static_summary']['network_indicators']['hosts'], ['example.com'])

    def test_auth_enforcement_summary_has_only_six_fields(self):
        result = self.load(self.fixture)
        row = result['security_validation_summary'][0]
        self.assertEqual(set(row), {'endpoint', 'test_category', 'outcome', 'reason_code', 'standard_mapping', 'evidence_available'})
        self.assertEqual(row['outcome'], 'validated')
        self.assertEqual(row['reason_code'], 'AUTH_ENFORCEMENT_CONFIRMED')
        self.assertEqual(row['evidence_available'], 'YES')
        self.assertIn(':18081/profile', row['endpoint'])
        self.assertIn('MASVS-AUTH-1', row['standard_mapping'])
        self.assertIn('not a vulnerability finding', result['security_note'])
        self.assertNotIn('finding', row)

    def test_blocked_inconclusive_rejected_are_visible(self):
        import copy
        source = copy.deepcopy(self.dynamic)
        row = source['security_results']['results'][0]
        source['security_results']['results'] = []
        for outcome in ['blocked', 'inconclusive', 'rejected']:
            item = copy.deepcopy(row)
            item['validation_outcome'] = outcome
            item['execution_status'] = 'blocked'
            source['security_results']['results'].append(item)
        result = self.build(dynamic_report=source)
        self.assertEqual([r['outcome'] for r in result['security_validation_summary']], ['blocked', 'inconclusive', 'rejected'])
        self.assertEqual(result['dynamic_summary']['security_tests_executed'], 0)
        self.assertEqual(result['dynamic_summary']['validation_outcomes']['inconclusive'], 1)

    def test_partial_https_and_unknown_launch_remain_explicit(self):
        dynamic = self.load(self.fixture)['dynamic_summary']
        self.assertEqual(dynamic['status'], 'partial')
        self.assertEqual(dynamic['launch_status'], 'Unknown')
        self.assertEqual(dynamic['traffic_visibility']['https_visibility'], 'unavailable')
        self.assertIn('Runtime observation is unavailable.', dynamic['coverage_limitations'])

    def test_zero_observations_never_means_secure(self):
        import copy
        source = copy.deepcopy(self.dynamic)
        source['endpoint_context_summary']['runtime_observed_count'] = 0
        source['security_results']['results'] = []
        result = self.build(dynamic_report=source)['dynamic_summary']
        self.assertEqual(result['observed_endpoints'], 0)
        self.assertTrue(any('does not establish absence' in text for text in result['coverage_limitations']))
        self.assertTrue(any('security was not established' in text for text in result['coverage_limitations']))
        self.assertNotEqual(result['status'], 'secure')

    def test_missing_reports_remain_unknown_not_success(self):
        result = self.build()
        self.assertIsNone(result['static_summary']['api_candidates_count'])
        self.assertIsNone(result['dynamic_summary']['observed_endpoints'])
        self.assertEqual(result['dynamic_summary']['status'], 'unavailable')

    def test_canonical_artifacts_byte_identical_after_summary(self):
        before = {p: p.read_bytes() for p in self.fixture.rglob('*') if p.is_file()}
        first = self.load(self.fixture)
        self.assertEqual(first, self.load(self.fixture))
        self.assertEqual(before, {p: p.read_bytes() for p in self.fixture.rglob('*') if p.is_file()})

    def test_missing_source_evidence_is_not_reported_available(self):
        import shutil
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / self.fixture.name
            shutil.copytree(self.fixture, copied)
            (copied / 'dynamic/security_results.json').unlink()
            report = (copied / 'dynamic_analysis_report.json').read_bytes()
            result = self.load(copied)
            self.assertEqual(result['security_validation_summary'][0]['evidence_available'], 'NO')
            self.assertIn('Some linked security evidence is unavailable.', result['dynamic_summary']['coverage_limitations'])
            self.assertEqual(report, (copied / 'dynamic_analysis_report.json').read_bytes())

    def test_endpoint_query_values_are_not_displayed(self):
        import copy
        source = copy.deepcopy(self.dynamic)
        endpoint = next(r for r in source['endpoint_contexts'] if r['endpoint_context_id'] == source['security_results']['results'][0]['endpoint_context_id'])
        endpoint['path'] = '/profile?token=secret-marker'
        result = self.build(dynamic_report=source)
        self.assertNotIn('secret-marker', json.dumps(result))
        self.assertTrue(result['security_validation_summary'][0]['endpoint'].endswith('/profile'))

    def test_summary_preserves_scheme_and_nondefault_port(self):
        context_id = self.dynamic['security_results']['results'][0]['endpoint_context_id']
        context = {'scheme': 'http', 'host': 'example.com', 'port': 443, 'path': '/profile', 'methods': ['GET']}
        result = self.build(dynamic_report=self.dynamic, contexts={context_id: context})
        self.assertEqual(result['security_validation_summary'][0]['endpoint'], 'GET http://example.com:443/profile')
        context.update(scheme='https', port=443)
        result = self.build(dynamic_report=self.dynamic, contexts={context_id: context})
        self.assertEqual(result['security_validation_summary'][0]['endpoint'], 'GET https://example.com/profile')

    def test_static_canonical_bytes_are_preserved(self):
        import shutil
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory) / 'static_lab'
            run.mkdir()
            canonical = run / 'static_analysis_report.json'
            shutil.copyfile(self.root / 'demo_runs/preset_android_monolithic/static_analysis_report.json', canonical)
            before = canonical.read_bytes()
            summary = self.load(run)
            self.assertTrue(summary['canonical_artifacts']['static'])
            self.assertEqual(summary['static_summary']['api_candidates_count'], 1)
            self.assertEqual(before, canonical.read_bytes())
