"""Unit and real end-to-end integration tests for Demo Orchestrator module."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

from src.demo_orchestrator import (
    DemoOrchestrationError,
    format_demo_summary,
    run_demo,
)


class TestDemoOrchestratorUnit(unittest.TestCase):
    """Unit tests for demo orchestration with mocked pipeline stages."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    # --- 1. Successful Pipeline Orchestration & Data Flow ---

    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_01_full_successful_pipeline_data_flow(
        self, mock_acq, mock_prep, mock_static, mock_runtime
    ):
        # 1. Mock acquisition
        apk_file = self.output_root / "downloads" / "test_app.apk"
        apk_file.parent.mkdir(parents=True, exist_ok=True)
        apk_file.write_bytes(b"DUMMY_APK")
        mock_acq.return_value = {
            "filename": "test_app.apk",
            "saved_path": str(apk_file),
            "size_bytes": 100,
            "sha256": "abc123hash",
            "validation": {"is_valid_apk": True},
        }

        # 2. Mock preprocessing
        raw_dir = self.output_root / "workspaces" / "test_app" / "raw_apk"
        apktool_dir = self.output_root / "workspaces" / "test_app" / "apktool_out"
        jadx_dir = self.output_root / "workspaces" / "test_app" / "jadx_out"
        raw_dir.mkdir(parents=True, exist_ok=True)
        apktool_dir.mkdir(parents=True, exist_ok=True)
        jadx_dir.mkdir(parents=True, exist_ok=True)
        (apktool_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

        mock_prep.return_value = {
            "apk_path": str(apk_file),
            "workspace": str(self.output_root / "workspaces" / "test_app"),
            "raw_apk": {"output_dir": str(raw_dir), "file_count": 10},
            "apktool": {"status": "success", "output_dir": str(apktool_dir), "returncode": 0},
            "jadx": {"status": "success_with_warnings", "output_dir": str(jadx_dir), "returncode": 3},
        }

        # 3. Mock static analysis
        mock_static.return_value = {
            "app": {
                "package_name": "com.example.app",
                "launcher_activity": "com.example.app.MainActivity",
            },
            "permissions": ["android.permission.INTERNET"],
            "activities": ["com.example.app.MainActivity"],
            "structure": {"dex_count": 1, "is_multidex": False},
            "network_indicators": {"network_urls": ["http://api.example.com"]},
            "api_candidates": [
                {"method": "POST", "full_url": "http://api.example.com/login", "status": "static_api_candidate"}
            ],
        }

        # 4. Mock runtime
        mock_runtime.return_value = {
            "adb": {"serial": "emulator-5554"},
            "install": {"success": True, "reinstall": True},
            "launch": {"success": True, "component": "com.example.app/com.example.app.MainActivity"},
            "runtime": {
                "process_running": True,
                "pid": 9999,
                "observed_package": "com.example.app",
                "observed_activity": "com.example.app.MainActivity",
                "foreground_verified": True,
            },
            "status": "runtime_launch_verified",
        }

        # Execute orchestrator
        result = run_demo(
            url="http://example.com/app.apk",
            output_root=self.output_root,
            adb_serial="emulator-5554",
            reinstall=True,
        )

        # Assert correct calls and argument flow:
        # Acquisition called with downloads dir
        mock_acq.assert_called_once_with(
            url="http://example.com/app.apk",
            output_dir=(self.output_root / "downloads").resolve(),
            timeout=60.0,
        )

        # Preprocessing received exact acquired APK path
        mock_prep.assert_called_once_with(
            apk_path=apk_file.resolve(),
            output_root=(self.output_root / "workspaces").resolve(),
            timeout_seconds=300.0,
        )

        # Static context received preprocessing output paths
        mock_static.assert_called_once_with(
            manifest_path=(apktool_dir / "AndroidManifest.xml").resolve(),
            raw_apk_root=raw_dir.resolve(),
            apktool_root=apktool_dir.resolve(),
        )

        # Runtime launcher received exact APK, package, activity, serial, reinstall
        mock_runtime.assert_called_once_with(
            apk_path=apk_file.resolve(),
            package_name="com.example.app",
            launcher_activity="com.example.app.MainActivity",
            adb_serial="emulator-5554",
            reinstall=True,
            grant_permissions=False,
            timeout_seconds=60.0,
        )

        # Assert final result schema
        self.assertEqual(result["demo_status"], "completed")
        self.assertEqual(result["input"]["url"], "http://example.com/app.apk")
        self.assertEqual(result["input"]["adb_serial"], "emulator-5554")
        self.assertTrue(result["input"]["reinstall"])
        self.assertEqual(result["acquisition"]["filename"], "test_app.apk")
        self.assertEqual(result["preprocessing"]["apktool"]["status"], "success")
        self.assertEqual(result["static_analysis"]["app"]["package_name"], "com.example.app")
        self.assertEqual(result["runtime"]["status"], "runtime_launch_verified")

        # Verify summary formatter does not crash
        summary_text = format_demo_summary(result)
        self.assertIn("MOBYATTACK-V1 DEMO EXECUTION SUMMARY", summary_text)
        self.assertIn("DEMO STATUS:      completed", summary_text)

    # --- 2. Fail-Fast Error Propagation Tests ---

    @patch("src.demo_orchestrator.acquire_apk", side_effect=ValueError("Download failed: 404 Not Found"))
    def test_02_acquisition_failure_stops_pipeline(self, mock_acq):
        with self.assertRaises(DemoOrchestrationError) as ctx:
            run_demo("http://example.com/app.apk", self.output_root)
        self.assertEqual(ctx.exception.stage, "acquisition")
        self.assertIn("Download failed: 404", str(ctx.exception))

    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk", side_effect=ValueError("Apktool failed"))
    def test_03_preprocessing_failure_stops_pipeline(self, mock_prep, mock_acq):
        apk_file = self.output_root / "downloads" / "app.apk"
        apk_file.parent.mkdir(parents=True, exist_ok=True)
        apk_file.write_bytes(b"APK")
        mock_acq.return_value = {"filename": "app.apk", "saved_path": str(apk_file)}

        with self.assertRaises(DemoOrchestrationError) as ctx:
            run_demo("http://example.com/app.apk", self.output_root)
        self.assertEqual(ctx.exception.stage, "preprocessing")
        self.assertIn("Apktool failed", str(ctx.exception))

    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context", side_effect=ValueError("Corrupt XML"))
    def test_04_static_analysis_failure_stops_runtime(self, mock_static, mock_prep, mock_acq):
        apk_file = self.output_root / "downloads" / "app.apk"
        apk_file.parent.mkdir(parents=True, exist_ok=True)
        apk_file.write_bytes(b"APK")
        mock_acq.return_value = {"filename": "app.apk", "saved_path": str(apk_file)}

        raw_dir = self.output_root / "workspaces" / "app" / "raw_apk"
        apktool_dir = self.output_root / "workspaces" / "app" / "apktool_out"
        raw_dir.mkdir(parents=True, exist_ok=True)
        apktool_dir.mkdir(parents=True, exist_ok=True)
        (apktool_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

        mock_prep.return_value = {
            "raw_apk": {"output_dir": str(raw_dir)},
            "apktool": {"output_dir": str(apktool_dir)},
        }

        with self.assertRaises(DemoOrchestrationError) as ctx:
            run_demo("http://example.com/app.apk", self.output_root)
        self.assertEqual(ctx.exception.stage, "static_analysis")
        self.assertIn("Corrupt XML", str(ctx.exception))

    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context")
    def test_05_missing_package_name_stops_before_runtime(self, mock_static, mock_prep, mock_acq):
        apk_file = self.output_root / "downloads" / "app.apk"
        apk_file.parent.mkdir(parents=True, exist_ok=True)
        apk_file.write_bytes(b"APK")
        mock_acq.return_value = {"filename": "app.apk", "saved_path": str(apk_file)}

        raw_dir = self.output_root / "workspaces" / "app" / "raw_apk"
        apktool_dir = self.output_root / "workspaces" / "app" / "apktool_out"
        raw_dir.mkdir(parents=True, exist_ok=True)
        apktool_dir.mkdir(parents=True, exist_ok=True)
        (apktool_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

        mock_prep.return_value = {
            "raw_apk": {"output_dir": str(raw_dir)},
            "apktool": {"output_dir": str(apktool_dir)},
        }

        # Intentionally empty package_name
        mock_static.return_value = {
            "app": {"package_name": "", "launcher_activity": "com.example.MainActivity"}
        }

        with self.assertRaises(DemoOrchestrationError) as ctx:
            run_demo("http://example.com/app.apk", self.output_root)
        self.assertEqual(ctx.exception.stage, "static_analysis")
        self.assertIn("package_name", str(ctx.exception))

    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context")
    def test_06_missing_launcher_activity_stops_before_runtime(self, mock_static, mock_prep, mock_acq):
        apk_file = self.output_root / "downloads" / "app.apk"
        apk_file.parent.mkdir(parents=True, exist_ok=True)
        apk_file.write_bytes(b"APK")
        mock_acq.return_value = {"filename": "app.apk", "saved_path": str(apk_file)}

        raw_dir = self.output_root / "workspaces" / "app" / "raw_apk"
        apktool_dir = self.output_root / "workspaces" / "app" / "apktool_out"
        raw_dir.mkdir(parents=True, exist_ok=True)
        apktool_dir.mkdir(parents=True, exist_ok=True)
        (apktool_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

        mock_prep.return_value = {
            "raw_apk": {"output_dir": str(raw_dir)},
            "apktool": {"output_dir": str(apktool_dir)},
        }

        # Intentionally missing launcher_activity
        mock_static.return_value = {
            "app": {"package_name": "com.example.app", "launcher_activity": None}
        }

        with self.assertRaises(DemoOrchestrationError) as ctx:
            run_demo("http://example.com/app.apk", self.output_root)
        self.assertEqual(ctx.exception.stage, "static_analysis")
        self.assertIn("launcher_activity", str(ctx.exception))

    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.launch_android_app", side_effect=ValueError("Install failed"))
    def test_07_runtime_failure_surfaced(self, mock_runtime, mock_static, mock_prep, mock_acq):
        apk_file = self.output_root / "downloads" / "app.apk"
        apk_file.parent.mkdir(parents=True, exist_ok=True)
        apk_file.write_bytes(b"APK")
        mock_acq.return_value = {"filename": "app.apk", "saved_path": str(apk_file)}

        raw_dir = self.output_root / "workspaces" / "app" / "raw_apk"
        apktool_dir = self.output_root / "workspaces" / "app" / "apktool_out"
        raw_dir.mkdir(parents=True, exist_ok=True)
        apktool_dir.mkdir(parents=True, exist_ok=True)
        (apktool_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

        mock_prep.return_value = {
            "raw_apk": {"output_dir": str(raw_dir)},
            "apktool": {"output_dir": str(apktool_dir)},
        }
        mock_static.return_value = {
            "app": {"package_name": "com.example.app", "launcher_activity": "com.example.app.MainActivity"}
        }

        with self.assertRaises(DemoOrchestrationError) as ctx:
            run_demo("http://example.com/app.apk", self.output_root)
        self.assertEqual(ctx.exception.stage, "runtime")
        self.assertIn("Install failed", str(ctx.exception))

    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.launch_android_app")
    def test_08_progress_callback_lifecycle(self, mock_runtime, mock_static, mock_prep, mock_acq):
        apk_file = self.output_root / "downloads" / "app.apk"
        apk_file.parent.mkdir(parents=True, exist_ok=True)
        apk_file.write_bytes(b"APK")
        mock_acq.return_value = {"filename": "app.apk", "saved_path": str(apk_file), "size_bytes": 500}

        raw_dir = self.output_root / "workspaces" / "app" / "raw_apk"
        apktool_dir = self.output_root / "workspaces" / "app" / "apktool_out"
        raw_dir.mkdir(parents=True, exist_ok=True)
        apktool_dir.mkdir(parents=True, exist_ok=True)
        (apktool_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

        mock_prep.return_value = {
            "raw_apk": {"output_dir": str(raw_dir)},
            "apktool": {"output_dir": str(apktool_dir), "status": "success"},
            "jadx": {"status": "success_with_warnings", "returncode": 3},
        }
        mock_static.return_value = {
            "app": {"package_name": "com.example.app", "launcher_activity": "com.example.app.MainActivity"},
            "api_candidates": [],
        }
        mock_runtime.return_value = {"status": "runtime_launch_verified", "runtime": {"pid": 1234}}

        events = []

        def tracker(stage, state, message, data=None):
            events.append((stage, state))

        run_demo("http://example.com/app.apk", self.output_root, progress_callback=tracker)

        self.assertEqual(events[:8], [
            ("acquisition", "running"),
            ("acquisition", "success"),
            ("preprocessing", "running"),
            ("preprocessing", "warning"),
            ("static_analysis", "running"),
            ("static_analysis", "success"),
            ("runtime", "running"),
            ("runtime", "success"),
        ])
        self.assertIn(("dynamic_analysis", "running"), events)
        self.assertEqual(events[-1], ("demo", "completed"))

    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.launch_android_app")
    def test_09_grant_permissions_passed_to_runtime(self, mock_runtime, mock_static, mock_prep, mock_acq):
        apk_file = self.output_root / "downloads" / "app.apk"
        apk_file.parent.mkdir(parents=True, exist_ok=True)
        apk_file.write_bytes(b"APK")
        mock_acq.return_value = {"filename": "app.apk", "saved_path": str(apk_file), "size_bytes": 500}

        raw_dir = self.output_root / "workspaces" / "app" / "raw_apk"
        apktool_dir = self.output_root / "workspaces" / "app" / "apktool_out"
        raw_dir.mkdir(parents=True, exist_ok=True)
        apktool_dir.mkdir(parents=True, exist_ok=True)
        (apktool_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

        mock_prep.return_value = {
            "raw_apk": {"output_dir": str(raw_dir)},
            "apktool": {"output_dir": str(apktool_dir), "status": "success"},
            "jadx": {"status": "success", "returncode": 0},
        }
        mock_static.return_value = {
            "app": {"package_name": "com.example.app", "launcher_activity": "com.example.app.MainActivity"},
            "api_candidates": [],
        }
        mock_runtime.return_value = {
            "install": {"success": True, "reinstall": True, "grant_permissions": True},
            "status": "runtime_launch_verified",
            "runtime": {"pid": 1234},
        }

        res = run_demo(
            "http://example.com/app.apk",
            self.output_root,
            reinstall=True,
            grant_permissions=True,
        )
        self.assertTrue(res["input"]["grant_permissions"])
        self.assertTrue(res["input"]["reinstall"])
        mock_runtime.assert_called_once()
        _, kwargs = mock_runtime.call_args
        self.assertTrue(kwargs.get("grant_permissions"))
        self.assertTrue(kwargs.get("reinstall"))

    def test_10_ios_platform_rejection(self):
        with self.assertRaises(DemoOrchestrationError) as ctx:
            run_demo(
                "https://example.com/app.apk",
                self.output_root,
                platform="ios",
            )
        self.assertEqual(ctx.exception.stage, "acquisition")
        self.assertTrue(any(s in str(ctx.exception) for s in ("iOS static analysis requires a direct .ipa", "iOS analysis is not implemented in V1.")))

    def test_11_unsupported_url_rejection(self):
        with self.assertRaises(DemoOrchestrationError) as ctx:
            run_demo(
                "https://github.com/OWASP/Android-InsecureBankv2",
                self.output_root,
                platform="android",
            )
        self.assertEqual(ctx.exception.stage, "acquisition")
        self.assertIn("Unsupported Android URL", str(ctx.exception))

    @patch("src.demo_orchestrator.get_connected_devices", return_value=["emulator-5554"])
    @patch("src.demo_orchestrator.acquire_play_store_app")
    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.launch_android_app")
    def test_12_play_store_url_routing(
        self, mock_runtime, mock_static, mock_prep, mock_acq, mock_play_acq, mock_devices
    ):
        apk_file = self.output_root / "downloads" / "com.test.app.apk"
        apk_file.parent.mkdir(parents=True, exist_ok=True)
        apk_file.write_bytes(b"APK")

        mock_play_acq.return_value = {
            "input_url": "https://play.google.com/store/apps/details?id=com.test.app",
            "platform": "android",
            "source_type": "play_store",
            "package_name": "com.test.app",
            "installed_on_device": True,
            "package_layout": "monolithic",
            "filename": "com.test.app.apk",
            "saved_path": str(apk_file),
            "size_bytes": 500,
            "sha256": "dummyhash",
            "validation": {"is_valid_apk": True},
        }

        raw_dir = self.output_root / "workspaces" / "com.test.app" / "raw_apk"
        apktool_dir = self.output_root / "workspaces" / "com.test.app" / "apktool_out"
        raw_dir.mkdir(parents=True, exist_ok=True)
        apktool_dir.mkdir(parents=True, exist_ok=True)
        (apktool_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")

        mock_prep.return_value = {
            "raw_apk": {"output_dir": str(raw_dir)},
            "apktool": {"output_dir": str(apktool_dir), "status": "success"},
            "jadx": {"status": "success", "returncode": 0},
        }
        mock_static.return_value = {
            "app": {"package_name": "com.test.app", "launcher_activity": "com.test.app.MainActivity"},
            "api_candidates": [],
        }
        mock_runtime.return_value = {
            "install": {"success": True, "reinstall": False, "grant_permissions": False},
            "status": "runtime_launch_verified",
            "runtime": {"pid": 9999},
        }

        res = run_demo(
            "https://play.google.com/store/apps/details?id=com.test.app",
            self.output_root,
            platform="android",
        )

        mock_acq.assert_not_called()
        mock_play_acq.assert_called_once()
        self.assertEqual(res["input"]["platform"], "android")
        self.assertEqual(res["input"]["source_type"], "play_store")
        self.assertEqual(res["acquisition"]["package_layout"], "monolithic")
        self.assertEqual(res["demo_status"], "completed")



class TestRealEndToEndMumuIntegration(unittest.TestCase):
    """Real full-pipeline integration test: HTTP URL -> Acquisition -> Preprocessing -> Static -> MuMu Runtime."""

    def test_real_full_pipeline_run(self):
        repo_root = Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.parent / "MSTG-Android-Kotlin.apk").is_file() else Path(__file__).resolve().parent.parent.parent
        owasp_apk = repo_root / "MSTG-Android-Kotlin.apk"
        if not owasp_apk.is_file():
            self.skipTest(f"OWASP APK not found at {owasp_apk}")

        # Check external binaries
        if not shutil.which("apktool") or not shutil.which("jadx") or not shutil.which("adb"):
            self.skipTest("apktool, jadx, or adb binary not installed on system PATH")

        # Check connected ADB device
        from src.android_runtime_launcher import get_connected_devices, AndroidRuntimeError
        try:
            devices = get_connected_devices()
        except AndroidRuntimeError:
            self.skipTest("ADB server not running or device check failed")
        if "127.0.0.1:5555" not in devices:
            self.skipTest("Device 127.0.0.1:5555 is not connected in 'device' state")

        apk_bytes = owasp_apk.read_bytes()

        # Spin up local in-process HTTP server serving OWASP APK
        class OwaspHttpServer(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.android.package-archive")
                self.send_header("Content-Disposition", 'attachment; filename="MSTG-Android-Kotlin.apk"')
                self.send_header("Content-Length", str(len(apk_bytes)))
                self.end_headers()
                self.wfile.write(apk_bytes)

        server = HTTPServer(("127.0.0.1", 0), OwaspHttpServer)
        port = server.server_port
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        temp_demo_dir = tempfile.TemporaryDirectory()
        output_root = Path(temp_demo_dir.name)

        try:
            demo_url = f"http://127.0.0.1:{port}/MSTG-Android-Kotlin.apk"
            result = run_demo(
                url=demo_url,
                output_root=output_root,
                adb_serial="127.0.0.1:5555",
                reinstall=True,
                timeout_seconds=300.0,
            )

            # --- Ground Truth Assertions ---
            # 1. Acquisition assertions
            self.assertTrue(result["acquisition"]["validation"]["is_valid_apk"])
            self.assertEqual(result["acquisition"]["filename"], "MSTG-Android-Kotlin.apk")
            self.assertEqual(result["acquisition"]["size_bytes"], len(apk_bytes))

            # 2. Preprocessing assertions
            self.assertTrue(result["preprocessing"]["raw_apk"]["success"])
            self.assertEqual(result["preprocessing"]["apktool"]["status"], "success")
            self.assertIn(
                result["preprocessing"]["jadx"]["status"],
                ("success", "success_with_warnings"),
            )

            # 3. Static analysis assertions
            self.assertEqual(
                result["static_analysis"]["app"]["package_name"],
                "sg.vantagepoint.mstgkotlin",
            )
            self.assertEqual(
                result["static_analysis"]["app"]["launcher_activity"],
                "sg.vantagepoint.mstgkotlin.MainActivity",
            )

            # Static API candidate check
            cands = result["static_analysis"]["api_candidates"]
            signup_candidates = [
                c for c in cands
                if c.get("method") == "POST" and c.get("full_url") == "http://127.0.0.1/signup"
            ]
            self.assertGreaterEqual(len(signup_candidates), 1)
            self.assertEqual(signup_candidates[0]["status"], "static_api_candidate")

            # 4. Runtime assertions
            self.assertEqual(result["runtime"]["status"], "runtime_launch_verified")
            self.assertTrue(result["runtime"]["runtime"]["foreground_verified"])
            self.assertEqual(
                result["runtime"]["runtime"]["observed_package"],
                "sg.vantagepoint.mstgkotlin",
            )
            self.assertEqual(
                result["runtime"]["runtime"]["observed_activity"],
                "sg.vantagepoint.mstgkotlin.MainActivity",
            )

            # 5. Overall demo status
            self.assertEqual(result["demo_status"], "completed")

        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2.0)
            temp_demo_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
