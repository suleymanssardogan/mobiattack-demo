"""Unit tests for MobiAttack-v1 Local Web Demo Dashboard."""

import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
import urllib.request
import urllib.error

from src.demo_web_server import DemoWebServer
from src.demo_orchestrator import DemoOrchestrationError


class TestDemoWebServerDiskStatus(unittest.TestCase):
    """Tests disk-backed status rendering without binding a local HTTP port."""

    def test_ios_disk_report_marks_unimplemented_runtime_as_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            runs_root = Path(temp_dir)
            run_id = "ios-static-only"
            run_dir = runs_root / run_id
            run_dir.mkdir()
            (run_dir / "report.json").write_text(
                json.dumps(
                    {
                        "platform": "ios",
                        "runtime": {
                            "status": "not_implemented",
                            "message": "Runtime launch verification is not implemented for iOS in Phase 1.",
                        },
                    }
                ),
                encoding="utf-8",
            )

            server = DemoWebServer(host="127.0.0.1", port=0, runs_root=runs_root)
            status = server.get_run_status(run_id)

            self.assertIsNotNone(status)
            self.assertEqual(status["stages"]["runtime"]["state"], "skipped")
            self.assertEqual(status["stages"]["runtime"]["message"], "iOS runtime analysis is not implemented.")


class TestDemoWebServer(unittest.TestCase):
    """Test suite for DemoWebServer, HTTP endpoints, progression tracking, and reporting."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.runs_root = Path(self.temp_dir.name)
        # Port 0 lets OS assign a free port
        self.server = DemoWebServer(host="127.0.0.1", port=0, runs_root=self.runs_root)
        self.server.start()

    def tearDown(self):
        self.server.stop()
        self.temp_dir.cleanup()

    def _get(self, path: str) -> tuple[int, bytes, dict]:
        url = f"{self.server.base_url}{path}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as err:
            return err.code, err.read(), dict(err.headers)

    def _get_json(self, path: str) -> tuple[int, dict]:
        status, body, _ = self._get(path)
        try:
            return status, json.loads(body.decode("utf-8"))
        except Exception:
            return status, {}

    def _post(self, path: str, payload: dict) -> tuple[int, dict]:
        url = f"{self.server.base_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return resp.status, body
        except urllib.error.HTTPError as err:
            body = json.loads(err.read().decode("utf-8"))
            return err.code, body

    def test_canonical_report_routes(self):
        from src.dynamic.report.models import save_dynamic_analysis_report
        from tests.test_dynamic_analysis_report import sources, report

        run_id = "run_test"
        run_dir = self.runs_root / run_id
        run_dir.mkdir()
        static = {"report_type": "static_analysis", "scan_id": run_id}
        (run_dir / "static_analysis_report.json").write_text(json.dumps(static))
        status, body = self._get_json(f"/reports/{run_id}/static_analysis_report.json")
        self.assertEqual((status, body), (200, static))
        path = f"/reports/{run_id}/dynamic_analysis_report.json"
        self.assertEqual(self._get_json(path)[0], 404)
        dynamic = report(sources.__wrapped__())
        save_dynamic_analysis_report(run_dir, dynamic)
        self.assertEqual(self._get_json(path), (200, dynamic))
        (run_dir / "dynamic_analysis_report.json").write_text("{corrupt")
        self.assertEqual(self._get_json(path)[0], 404)
        (run_dir / "dynamic_analysis_report.json").write_text(json.dumps({"scan_id": run_id}))
        self.assertEqual(self._get_json(path)[0], 404)

    def test_index_page_returns_200_and_contains_dashboard_elements(self):
        status, body, headers = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        html = body.decode("utf-8")
        # Pipeline controls & stages
        self.assertIn("Analysis workspace", html)
        self.assertIn("Target Application", html)
        self.assertIn("START DEMO", html)
        self.assertIn("1. Application Acquisition", html)
        self.assertIn("2. Static Analysis", html)
        self.assertIn("3. Dynamic Analysis", html)
        self.assertIn("4. Agent Analysis", html)
        self.assertIn("5. Report Generation", html)
        self.assertIn('id="msg-agent_analysis">Not available in this scan', html)
        self.assertIn("Connectivity Probe", html)
        self.assertIn("Emulator connectivity only — not application navigation.", html)
        self.assertNotIn('id="grantPermissions"', html)
        self.assertIn('id="quickTargetsAndroid"', html)
        self.assertIn('id="quickTargetsIos"', html)
        self.assertIn('id="androidAnalysisOptions"', html)
        self.assertIn('id="overviewRiskVal">Not evaluated', html)
        self.assertIn("com.google.android.calculator", html)
        self.assertIn("MSTG-JWT.ipa", html)
        self.assertNotIn("com.sec.android.app.popupcalculator", html)
        self.assertNotIn('id="adbSerial"', html)
        self.assertIn('window.location.hostname === "mobiattack-demo.vercel.app"', html)
        self.assertIn('localPage.searchParams.set("target", url)', html)
        self.assertIn('id="presentationNotice"', html)

        # Analysis Results & Tabs
        self.assertIn("Analysis Results", html)
        self.assertIn("tab-btn-overview", html)
        self.assertIn("tab-btn-application", html)
        self.assertIn("tab-btn-structure", html)
        self.assertIn("tab-btn-network", html)
        self.assertIn("tab-btn-api_candidates", html)
        self.assertIn("tab-btn-runtime", html)
        self.assertIn("tab-btn-notes", html)
        self.assertIn("tab-btn-report", html)

        # Action Buttons
        self.assertIn("View HTML Report", html)
        self.assertIn("Download JSON", html)
        self.assertIn("Open in New Tab", html)

        # Text requirements
        self.assertIn("Static network indicators do not prove runtime network use.", html)
        self.assertIn("API candidates are static call-context candidates only.", html)
        self.assertIn("Zero API candidates does not mean no APIs exist.", html)

    def test_api_run_validation_missing_or_invalid_url(self):
        # Empty payload
        status, body = self._post("/api/run", {})
        self.assertEqual(status, 400)
        self.assertEqual(body.get("status"), "error")

        # Invalid protocol
        status, body = self._post("/api/run", {"url": "ftp://example.com/app.apk"})
        self.assertEqual(status, 400)
        self.assertIn("valid http:// or https:// URL", body.get("message", ""))

    @patch("src.demo_web_server.run_demo")
    def test_api_run_success_spawns_run_and_updates_status(self, mock_run_demo):
        def fake_run(url, output_root, platform="android", adb_serial=None, reinstall=True, grant_permissions=False, timeout_seconds=300.0, progress_callback=None, **kwargs):
            if progress_callback:
                progress_callback("acquisition", "running", "Downloading...")
                progress_callback("acquisition", "success", "Downloaded", {"filename": "test.apk", "size_bytes": 100})
                progress_callback("preprocessing", "running", "Preprocessing...")
                progress_callback("preprocessing", "success", "Preprocessed")
                progress_callback("static_analysis", "running", "Analyzing...")
                progress_callback("static_analysis", "success", "Analyzed")
                progress_callback("runtime", "running", "Launching...")
                progress_callback("runtime", "success", "Launched")
                progress_callback("demo", "completed", "Demo completed", {
                    "demo_status": "completed",
                    "acquisition": {"filename": "test.apk", "sha256": "abc"},
                    "static_analysis": {"app": {"package_name": "com.test", "launcher_activity": ".Main"}},
                })
            return {"demo_status": "completed"}

        mock_run_demo.side_effect = fake_run

        status, body = self._post("/api/run", {
            "url": "https://example.com/test.apk",
            "adb_serial": "some-other-device",
            "reinstall": True,
            "grant_permissions": True,
        })
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")
        run_id = body.get("run_id")
        self.assertIsNotNone(run_id)

        # Allow background thread to finish
        time.sleep(0.4)
        self.assertIsNone(mock_run_demo.call_args.kwargs["adb_serial"])
        self.assertEqual(mock_run_demo.call_args.kwargs["install_mode"], "ui_automation")
        self.assertTrue(mock_run_demo.call_args.kwargs["grant_permissions"])

        status, s_body = self._get_json(f"/api/status/{run_id}")
        self.assertEqual(status, 200)
        self.assertEqual(s_body.get("overall_status"), "completed")
        self.assertIsNotNone(s_body.get("result"))

    def test_concurrent_runs_rejected(self):
        with self.server._lock:
            self.server._active_run_id = "existing_run"

        status, body = self._post("/api/run", {"url": "https://example.com/test.apk"})
        self.assertEqual(status, 409)
        self.assertEqual(body.get("status"), "error")
        self.assertIn("already running", body.get("message", ""))

        with self.server._lock:
            self.server._active_run_id = None

    def test_status_endpoint_returns_404_for_unknown_run(self):
        status, body = self._get_json("/api/status/non_existent_run_123")
        self.assertEqual(status, 404)
        self.assertEqual(body.get("status"), "error")

    @patch("src.demo_web_server.run_demo")
    def test_stage_failure_halts_subsequent_stages(self, mock_run_demo):
        def failing_run(*args, progress_callback=None, **kwargs):
            if progress_callback:
                progress_callback("acquisition", "running", "Downloading...")
                progress_callback("acquisition", "failed", "Network 404 Not Found")
            raise DemoOrchestrationError("Network 404 Not Found", stage="acquisition")

        mock_run_demo.side_effect = failing_run

        status, body = self._post("/api/run", {"url": "https://example.com/missing.apk"})
        self.assertEqual(status, 200)
        run_id = body.get("run_id")

        time.sleep(0.4)

        s_status, s_body = self._get_json(f"/api/status/{run_id}")
        self.assertEqual(s_status, 200)
        self.assertEqual(s_body.get("overall_status"), "failed")
        self.assertEqual(s_body.get("stages", {}).get("acquisition", {}).get("state"), "failed")
        self.assertEqual(s_body.get("stages", {}).get("preprocessing", {}).get("state"), "pending")
        self.assertEqual(s_body.get("stages", {}).get("static_analysis", {}).get("state"), "pending")
        self.assertEqual(s_body.get("stages", {}).get("runtime", {}).get("state"), "pending")

    @patch("src.demo_web_server.run_demo")
    def test_jadx_warning_representation_in_preprocessing(self, mock_run_demo):
        def warning_run(*args, progress_callback=None, **kwargs):
            if progress_callback:
                progress_callback("acquisition", "success", "Acquired")
                progress_callback("preprocessing", "warning", "Completed with warnings", {
                    "jadx": {"status": "success_with_warnings", "returncode": 3}
                })
                progress_callback("demo", "completed", "Done", {"demo_status": "completed"})
            return {"demo_status": "completed"}

        mock_run_demo.side_effect = warning_run

        status, body = self._post("/api/run", {"url": "https://example.com/sample.apk"})
        run_id = body.get("run_id")
        time.sleep(0.4)

        s_status, s_body = self._get_json(f"/api/status/{run_id}")
        self.assertEqual(s_body.get("stages", {}).get("preprocessing", {}).get("state"), "warning")
        self.assertEqual(
            s_body.get("stages", {}).get("preprocessing", {}).get("data", {}).get("jadx", {}).get("status"),
            "success_with_warnings",
        )

    @patch("src.demo_web_server.select_target_device", return_value="test-device")
    @patch("src.demo_web_server.configure_adb_reverse")
    @patch("src.demo_web_server.trigger_device_browser")
    @patch("src.demo_web_server.remove_adb_reverse")
    @patch("src.demo_web_server.ProbeServer")
    def test_optional_probe_endpoint(self, mock_probe_cls, mock_remove, mock_trigger, mock_reverse, mock_device):
        mock_instance = MagicMock()
        mock_instance.port = 54321
        mock_instance.get_probe_url.return_value = "http://127.0.0.1:54321/probe/test_123"
        mock_instance.get_status.return_value = {"hit": True, "hit_count": 1}
        mock_probe_cls.return_value = mock_instance

        status, body = self._post("/api/probe", {"adb_serial": "some-other-device"})
        self.assertEqual(status, 200)
        self.assertTrue(body.get("hit"))
        self.assertEqual(mock_reverse.call_args.kwargs["adb_serial"], "test-device")
        self.assertEqual(body.get("hit_count"), 1)
        self.assertEqual(body.get("connectivity_probe"), "verified")
        self.assertIn("Emulator connectivity only", body.get("disclaimer", ""))

    def test_report_routes_and_file_serving(self):
        # Create a mock run directory with report.json and report.html
        run_id = "test_run_serving_001"
        run_dir = self.runs_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        sample_report = {
            "report_version": "1.0",
            "run_id": run_id,
            "demo_status": "completed",
            "application": {"package_name": "org.owasp.mastestapp", "sha256": "abcdef"},
        }
        (run_dir / "report.json").write_text(json.dumps(sample_report), encoding="utf-8")
        (run_dir / "report.html").write_text("<html><body>Test Report</body></html>", encoding="utf-8")

        # 1. GET /api/report/<run_id>
        status, body = self._get_json(f"/api/report/{run_id}")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("run_id"), run_id)
        self.assertEqual(body.get("application", {}).get("package_name"), "org.owasp.mastestapp")

        # 2. GET /reports/<run_id>/report.html
        status, body_bytes, headers = self._get(f"/reports/{run_id}/report.html")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn("Test Report", body_bytes.decode("utf-8"))

        # 3. GET /reports/<run_id>/report.json
        status, body_bytes, headers = self._get(f"/reports/{run_id}/report.json")
        self.assertEqual(status, 200)
        self.assertIn("application/json", headers.get("Content-Type", ""))
        self.assertIn("attachment", headers.get("Content-Disposition", ""))
        data = json.loads(body_bytes.decode("utf-8"))
        self.assertEqual(data.get("run_id"), run_id)

    def test_report_routes_path_traversal_rejection(self):
        # Traversal attempts should be blocked
        traversal_paths = [
            "/api/report/../../etc/passwd",
            "/api/report/..",
            "/reports/../../secret/report.html",
            "/reports/../report.json",
        ]
        for p in traversal_paths:
            status, _, _ = self._get(p)
            self.assertIn(status, (400, 404))

    def test_report_routes_missing_reports_return_404(self):
        status, body = self._get_json("/api/report/non_existent_run_404")
        self.assertEqual(status, 404)

        status, _, _ = self._get("/reports/non_existent_run_404/report.html")
        self.assertEqual(status, 404)

        status, _, _ = self._get("/reports/non_existent_run_404/report.json")
        self.assertEqual(status, 404)

    def test_platform_selector_and_modular_url_html(self):
        status, body, _ = self._get("/")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        self.assertIn("Platform", html)
        self.assertIn("platform-android", html)
        self.assertIn("platform-ios", html)
        self.assertIn("iOS static analysis accepts direct or local IPA artifacts.", html)
        self.assertIn("urlClassificationBadge", html)
        self.assertIn("Target Application", html)

    @patch("src.demo_web_server.DemoWebServer.start_run", return_value="ui_r1_run")
    def test_web_run_normalizes_identity_and_forces_automatic_workflow(self, start):
        status, body = self._post("/api/run", {
            "url": "https://play.google.com/store/apps/details?id=com.example.app&hl=tr&utm_source=demo",
            "install_mode": "manual", "grant_permissions": False, "adb_serial": "untrusted-device",
        })
        self.assertEqual(status, 200)
        self.assertEqual(start.call_args.kwargs["url"], "https://play.google.com/store/apps/details?id=com.example.app")
        self.assertEqual(start.call_args.kwargs["install_mode"], "ui_automation")
        self.assertTrue(start.call_args.kwargs["grant_permissions"])
        self.assertIsNone(start.call_args.kwargs["adb_serial"])

    @patch("src.demo_web_server.DemoWebServer.start_run")
    def test_unsupported_android_input_never_starts_acquisition(self, start):
        for url in ("https://example.com/page", "https:///app.apk", "https://example.com:bad/app.apk"):
            status, body = self._post("/api/run", {"url": url})
            self.assertEqual(status, 400)
            self.assertEqual(body["message"], "Unsupported Android application URL. Use a direct APK URL or Google Play Store application URL.")
        start.assert_not_called()

    def test_api_classify_direct_apk(self):
        status, body = self._post("/api/classify", {
            "platform": "android",
            "url": "https://example.com/test.apk",
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["type"], "direct_apk")
        self.assertEqual(body["platform"], "android")

    def test_api_classify_play_store(self):
        status, body = self._post("/api/classify", {
            "platform": "android",
            "url": "https://play.google.com/store/apps/details?id=com.example.app",
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["type"], "play_store")
        self.assertEqual(body["package_name"], "com.example.app")

    def test_api_classify_ios(self):
        status, body = self._post("/api/classify", {
            "platform": "ios",
            "url": "https://example.com/app.apk",
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["type"], "not_implemented")
        self.assertTrue(any(s in body.get("message", "") for s in ("iOS static analysis requires a direct .ipa", "iOS analysis is not implemented in V1.")))

    def test_api_classify_unsupported(self):
        status, body = self._post("/api/classify", {
            "platform": "android",
            "url": "https://example.com/some/page",
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["type"], "unsupported")

    def test_api_run_rejection_for_ios(self):
        status, body = self._post("/api/run", {
            "platform": "ios",
            "url": "https://example.com/app.apk",
        })
        self.assertEqual(status, 400)
        self.assertTrue(any(s in body.get("error", "") for s in ("iOS static analysis requires a direct .ipa", "iOS analysis is not implemented in V1.")))

    @patch("src.demo_web_server.select_target_device", return_value="test-device")
    @patch("src.demo_web_server.open_play_store_on_device")
    def test_api_open_store(self, mock_open, mock_device):
        mock_open.return_value = {"success": True, "serial": "emulator-5554"}
        status, body = self._post("/api/open_store", {
            "package_name": "owasp.sat.agoat",
            "adb_serial": "some-other-device",
        })
        self.assertEqual(status, 200)
        self.assertTrue(body["success"])
        mock_open.assert_called_once()
        self.assertEqual(mock_open.call_args.kwargs["serial"], "test-device")

    def test_api_classify_direct_ipa(self):
        status, body = self._post("/api/classify", {
            "platform": "ios",
            "url": "https://example.com/test.ipa",
        })
        self.assertEqual(status, 200)
        self.assertEqual(body["type"], "direct_ipa")
        self.assertEqual(body["platform"], "ios")

    @patch("src.demo_web_server.run_demo")
    def test_api_run_success_for_ios(self, mock_run_demo):
        mock_run_demo.return_value = {
            "platform": "ios",
            "demo_status": "completed",
            "application": {"bundle_identifier": "com.example.test"},
        }
        status, body = self._post("/api/run", {
            "platform": "ios",
            "url": "https://example.com/test.ipa",
        })
        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "ok")
        self.assertIsNotNone(body.get("run_id"))

    def test_ios_ui_and_terminology_elements_in_html(self):
        """Tests that HTML dashboard contains required iOS-specific elements and terminology."""
        status, body, _ = self._get("/")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")

        # 1. Connectivity probe panel has id for conditional hiding
        self.assertIn('id="probeCard"', html)

        # 2. Application section subtitle headers have IDs for platform customization
        self.assertIn('id="appPermsHeader"', html)
        self.assertIn('id="appActsHeader"', html)

        # 3. iOS-specific section labels in script
        self.assertIn('"Declared URL Schemes"', html)
        self.assertIn('"Declared Usage Descriptions"', html)

        # 4. URL scheme string rendering without [object Object]
        self.assertIn("s.scheme", html)

        # 5. Network table platform-aware terminology
        self.assertIn('"Source Artifact"', html)
        self.assertIn('"All Source Artifacts"', html)

        # 6. Extraction count fallback without malformed '- files'
        self.assertIn("'Not reported'", html)

        # 7. Probe card hidden on iOS
        self.assertIn('probeCard.style.display = isIos ? "none" : "block"', html)


if __name__ == "__main__":
    unittest.main()


class TestCompactSummaryPresentation(unittest.TestCase):
    """Read-only summary endpoint tests without sockets or scan execution."""

    def test_summary_api_returns_projection_without_running_scan(self):
        from src.demo_web_server import _DemoRequestHandler
        root = Path(__file__).resolve().parents[1]
        server = MagicMock()
        server.get_run_dir.return_value = root / 'examples/auth_standards_report_d13'
        handler = object.__new__(_DemoRequestHandler)
        handler._send_json = MagicMock()
        handler._handle_summary_api('auth_standards_report_d13', server)
        code, payload = handler._send_json.call_args.args
        self.assertEqual(code, 200)
        self.assertEqual(payload['security_validation_summary'][0]['evidence_available'], 'YES')
        self.assertNotIn('evidence_refs', json.dumps(payload))
        server.start_run.assert_not_called()

    def test_missing_run_returns_clean_404(self):
        from src.demo_web_server import _DemoRequestHandler
        server = MagicMock()
        server.get_run_dir.return_value = None
        handler = object.__new__(_DemoRequestHandler)
        handler._send_json = MagicMock()
        handler._handle_summary_api('absent', server)
        self.assertEqual(handler._send_json.call_args.args[0], 404)

    def test_malformed_summary_does_not_expose_internal_error(self):
        from src.demo_web_server import _DemoRequestHandler
        server = MagicMock()
        handler = object.__new__(_DemoRequestHandler)
        handler._send_json = MagicMock()
        with patch('src.web.report_summary.load_report_summary', side_effect=ValueError('/tmp/secret-path')):
            handler._handle_summary_api('broken', server)
        self.assertEqual(handler._send_json.call_args.args, (500, {'status': 'error', 'message': 'Summary unavailable.'}))

    def test_compact_dashboard_renders_coverage_and_pages_without_secret_markup(self):
        import shutil
        import subprocess
        from src.web.report_summary import load_report_summary
        if not shutil.which('node'):
            self.skipTest('Node is unavailable for focused UI rendering check')
        root = Path(__file__).resolve().parents[1]
        html = (root / 'src/templates/dashboard.html').read_text()
        script = html.split('    let compactSummaryRequest = 0;', 1)[1].split('    function renderAnalysisResults(', 1)[0]
        summary = load_report_summary(root / 'examples/auth_standards_report_d13')
        summary['security_validation_summary'] *= 11
        summary['static_summary']['app'] = '<script>unsafe</script>'
        harness = '''
const assert = require('assert');
const elements = {compactReportSummary: {}, summaryPrevious: {}, summaryNext: {}};
global.document = {getElementById: id => elements[id]};
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function backendUrl(path) { return path; }
'''
        harness += script + '\ncompactSummaryData = ' + json.dumps(summary) + ';\nrenderCompactSummary("lab");\n'
        harness += '''
assert(elements.compactReportSummary.innerHTML.includes('Validated — auth enforcement confirmed'));
assert(elements.compactReportSummary.innerHTML.includes('HTTPS visibility is unavailable.'));
assert(elements.compactReportSummary.innerHTML.includes('Showing 1–10 of 11'));
assert(!elements.compactReportSummary.innerHTML.includes('<script>unsafe</script>'));
assert(elements.compactReportSummary.innerHTML.includes('Full dynamic evidence (JSON)'));
assert(elements.summaryPrevious.disabled);
elements.summaryNext.onclick();
assert(elements.compactReportSummary.innerHTML.includes('Showing 11–11 of 11'));
assert(elements.summaryNext.disabled);
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'summary.js'
            path.write_text(harness)
            checked = subprocess.run(['node', str(path)], capture_output=True, text=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_compact_summary_is_default_with_details_collapsed(self):
        from html.parser import HTMLParser
        class Tabs(HTMLParser):
            def __init__(self):
                super().__init__()
                self.items = {}
            def handle_starttag(self, tag, attrs):
                attributes = dict(attrs)
                if attributes.get('id') in {'tab-btn-summary', 'tab-pane-summary', 'tab-pane-overview', 'detailedReportNavigation'}:
                    self.items[attributes['id']] = attributes
        parser = Tabs()
        parser.feed((Path(__file__).resolve().parents[1] / 'src/templates/dashboard.html').read_text())
        self.assertIn('active', parser.items['tab-btn-summary']['class'])
        self.assertIn('active', parser.items['tab-pane-summary']['class'])
        self.assertNotIn('active', parser.items['tab-pane-overview']['class'])
        self.assertNotIn('open', parser.items['detailedReportNavigation'])
