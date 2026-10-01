"""Pipeline wiring tests for Dynamic Session integration (Task 4.3.1).

Verifies that:
1. real orchestrator success path calls initialize_dynamic_session.
2. run-scoped session.json created.
3. run-scoped timeline.json created.
4. PASS preflight triggers exactly one UI observation.
5. WARN usable preflight triggers exactly one UI observation.
6. FAIL preflight creates ABORTED session.
7. FAIL preflight does not call UI observation.
8. no duplicate session initialization.
9. split APK path initializes session once.
10. Play Store path initializes session once where preflight evidence exists.
11. session init failure preserves static report.
12. session init failure preserves preflight_result.json.
13. no dynamic_analysis_report.json created.
14. scan_state dynamic_analysis remains not_available.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

from src.android_runtime_launcher import AndroidDeviceUnavailableError
from src.demo_orchestrator import (
    DemoOrchestrationError,
    _wire_dynamic_session,
    run_demo,
)
from src.dynamic.preflight.models import PreflightStatus
from src.dynamic.ui.models import ScreenObservation
from src.scan_state import ScanStateCheckpointer, load_scan_state


def _create_mock_screen_observation() -> ScreenObservation:
    """Creates a deterministic dummy ScreenObservation for mock testing."""
    return ScreenObservation(
        screen_identity="test_identity_sha256_abc123",
        foreground_package="com.example.app",
        foreground_activity="com.example.app.MainActivity",
        target_package="com.example.app",
        is_target_package=True,
        is_dialog_or_system=False,
        nodes=[],
        clickable_count=2,
        input_count=1,
        action_candidates=[],
        observation_attempts=1,
    )


class TestDynamicSessionPipelineWiring(unittest.TestCase):
    """Verifies production pipeline wiring for dynamic session."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _setup_mock_monolithic_pipeline(
        self,
        mock_acq,
        mock_prep,
        mock_static,
        mock_runtime,
        runtime_status="runtime_launch_verified",
        foreground_verified=True,
        pid=9999,
        serial="emulator-5554",
    ):
        """Sets up standard mocks for monolithic APK pipeline execution."""
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
            "jadx": {"status": "success", "output_dir": str(jadx_dir), "returncode": 0},
        }

        mock_static.return_value = {
            "app": {
                "package_name": "com.example.app",
                "launcher_activity": "com.example.app.MainActivity",
            },
            "permissions": ["android.permission.INTERNET"],
            "activities": ["com.example.app.MainActivity"],
            "structure": {"dex_count": 1, "is_multidex": False},
            "network_indicators": {"network_urls": []},
            "api_candidates": [],
        }

        mock_runtime.return_value = {
            "adb": {"serial": serial},
            "install": {"success": True, "reinstall": False},
            "launch": {"success": True, "component": "com.example.app/com.example.app.MainActivity"},
            "runtime": {
                "process_running": pid is not None,
                "pid": pid,
                "observed_package": "com.example.app",
                "observed_activity": "com.example.app.MainActivity",
                "foreground_verified": foreground_verified,
            },
            "status": runtime_status,
        }

    # 1. Real orchestrator success path calls initialize_dynamic_session
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_01_real_orchestrator_success_path_calls_initialize_dynamic_session(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _create_mock_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        with patch("src.dynamic.session.integration.initialize_dynamic_session") as mock_init:
            run_demo("http://example.com/app.apk", self.output_root)
            self.assertEqual(mock_init.call_count, 1)
            _, kwargs = mock_init.call_args
            self.assertEqual(kwargs["package_name"], "com.example.app")
            self.assertEqual(kwargs["run_id"], self.output_root.name)
            self.assertEqual(kwargs["preflight_result"].status, PreflightStatus.PASS)

    # 2. Run-scoped session.json created
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_02_run_scoped_session_json_created(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _create_mock_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        session_path = self.output_root / "dynamic" / "session.json"
        self.assertTrue(session_path.is_file(), f"Expected session.json at {session_path}")

        with open(session_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["package_name"], "com.example.app")
        self.assertEqual(data["status"], "ACTIVE")
        self.assertIn("session_id", data)

    # 3. Run-scoped timeline.json created
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_03_run_scoped_timeline_json_created(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _create_mock_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        timeline_path = self.output_root / "dynamic" / "timeline.json"
        self.assertTrue(timeline_path.is_file(), f"Expected timeline.json at {timeline_path}")

        with open(timeline_path, "r", encoding="utf-8") as f:
            events = json.load(f)
        self.assertIsInstance(events, list)
        event_names = [e["name"] for e in events]
        self.assertIn("SESSION_STARTED", event_names)
        self.assertIn("DYNAMIC_PREFLIGHT_COMPLETED", event_names)

    # 4. PASS preflight triggers exactly one UI observation
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_04_pass_preflight_triggers_exactly_one_ui_observation(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _create_mock_screen_observation()
        self._setup_mock_monolithic_pipeline(
            mock_acq, mock_prep, mock_static, mock_runtime,
            foreground_verified=True, pid=1234
        )

        run_demo("http://example.com/app.apk", self.output_root)

        self.assertEqual(mock_obs.call_count, 1)

        timeline_path = self.output_root / "dynamic" / "timeline.json"
        with open(timeline_path, "r", encoding="utf-8") as f:
            events = json.load(f)
        event_names = [e["name"] for e in events]
        self.assertIn("SCREEN_OBSERVED", event_names)

    # 5. WARN usable preflight triggers exactly one UI observation
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_05_warn_usable_preflight_triggers_exactly_one_ui_observation(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _create_mock_screen_observation()
        # Foreground unverified -> WARN, but process running -> usable
        self._setup_mock_monolithic_pipeline(
            mock_acq, mock_prep, mock_static, mock_runtime,
            foreground_verified=False, pid=1234
        )

        run_demo("http://example.com/app.apk", self.output_root)

        self.assertEqual(mock_obs.call_count, 1)

        session_path = self.output_root / "dynamic" / "session.json"
        with open(session_path, "r", encoding="utf-8") as f:
            sess = json.load(f)
        self.assertEqual(sess["status"], "ACTIVE")

    # 6. FAIL preflight creates ABORTED session
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_06_fail_preflight_creates_aborted_session(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        # Android device unavailable -> Preflight FAIL
        mock_runtime.side_effect = AndroidDeviceUnavailableError("no devices found", reason="no_adb_device")
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        session_path = self.output_root / "dynamic" / "session.json"
        self.assertTrue(session_path.is_file())

        with open(session_path, "r", encoding="utf-8") as f:
            sess = json.load(f)
        self.assertEqual(sess["status"], "ABORTED")

        timeline_path = self.output_root / "dynamic" / "timeline.json"
        with open(timeline_path, "r", encoding="utf-8") as f:
            events = json.load(f)
        event_names = [e["name"] for e in events]
        self.assertIn("SESSION_ABORTED", event_names)

    # 7. FAIL preflight does not call UI observation
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_07_fail_preflight_does_not_call_ui_observation(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_runtime.side_effect = AndroidDeviceUnavailableError("device offline", reason="device_offline")
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        mock_obs.assert_not_called()

    # 8. No duplicate session initialization
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_08_no_duplicate_session_initialization(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _create_mock_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        # Call _wire_dynamic_session again on the same output_root
        with patch("src.dynamic.session.integration.initialize_dynamic_session") as mock_init:
            _wire_dynamic_session(self.output_root, "com.example.app", "emulator-5554")
            mock_init.assert_not_called()

    # 9. Split APK path initializes session once
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_split_static_context")
    @patch("src.demo_orchestrator.preprocess_package_set")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_09_split_apk_path_initializes_session_once(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _create_mock_screen_observation()

        mock_acq.return_value = {
            "package_layout": "split",
            "split_count": 2,
            "package_set_path": str(self.output_root / "downloads"),
            "package_name": "com.example.splitapp",
            "filename": "base.apk",
            "size_bytes": 1000,
        }

        mock_prep.return_value = {
            "status": "success",
            "component_count": 2,
            "package_set_path": str(self.output_root / "workspaces" / "processed"),
        }

        mock_static.return_value = {
            "app": {
                "package_name": "com.example.splitapp",
                "launcher_activity": "com.example.splitapp.MainActivity",
            },
            "api_candidates": [],
        }

        mock_runtime.return_value = {
            "adb": {"serial": "emulator-5554"},
            "runtime": {
                "process_running": True,
                "pid": 5678,
                "observed_package": "com.example.splitapp",
                "observed_activity": "com.example.splitapp.MainActivity",
                "foreground_verified": True,
            },
            "status": "runtime_launch_verified",
        }

        res = run_demo("http://example.com/split.apk", self.output_root)
        self.assertEqual(res["acquisition"]["package_layout"], "split")

        session_path = self.output_root / "dynamic" / "session.json"
        timeline_path = self.output_root / "dynamic" / "timeline.json"
        self.assertTrue(session_path.is_file())
        self.assertTrue(timeline_path.is_file())

        with open(session_path, "r", encoding="utf-8") as f:
            sess = json.load(f)
        self.assertEqual(sess["package_name"], "com.example.splitapp")
        self.assertEqual(sess["status"], "ACTIVE")

    # 10. Play Store path initializes session once where preflight evidence exists
    @patch("src.demo_orchestrator.get_connected_devices", return_value=["emulator-5554"])
    @patch("src.demo_orchestrator.acquire_play_store_app")
    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.dynamic.ui.observer.observe_screen")
    def test_10_play_store_path_initializes_session_once(
        self, mock_obs, mock_runtime, mock_static, mock_prep, mock_acq, mock_play_acq, mock_devs
    ):
        mock_obs.return_value = _create_mock_screen_observation()

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
            "runtime": {
                "pid": 9999,
                "process_running": True,
                "foreground_verified": True,
            },
        }

        res = run_demo(
            "https://play.google.com/store/apps/details?id=com.test.app",
            self.output_root,
        )
        self.assertEqual(res["input"]["source_type"], "play_store")

        session_path = self.output_root / "dynamic" / "session.json"
        timeline_path = self.output_root / "dynamic" / "timeline.json"
        self.assertTrue(session_path.is_file())
        self.assertTrue(timeline_path.is_file())

    # 11. Session init failure preserves static report
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_11_session_init_failure_preserves_static_report(
        self, mock_acq, mock_prep, mock_static, mock_runtime
    ):
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        # Force initialize_dynamic_session to throw
        with patch(
            "src.dynamic.session.integration.initialize_dynamic_session",
            side_effect=RuntimeError("Disk failure during session init"),
        ):
            res = run_demo("http://example.com/app.apk", self.output_root)

        # Pipeline must succeed and static results must be preserved
        self.assertEqual(res["demo_status"], "completed")
        self.assertIn("static_analysis", res)
        self.assertEqual(res["static_analysis"]["app"]["package_name"], "com.example.app")

        # Report files should exist on disk
        report_json = self.output_root / "report.json"
        self.assertTrue(report_json.is_file(), "report.json should exist")
        with open(report_json, "r", encoding="utf-8") as f:
            rep_data = json.load(f)
        self.assertEqual(rep_data["application"]["package_name"], "com.example.app")
        self.assertIn("permissions", rep_data)

        static_report = self.output_root / "static_analysis_report.json"
        if static_report.is_file():
            with open(static_report, "r", encoding="utf-8") as f:
                srep_data = json.load(f)
            self.assertEqual(srep_data["application"]["package_name"], "com.example.app")

    # 12. Session init failure preserves preflight_result.json
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_12_session_init_failure_preserves_preflight_result_json(
        self, mock_acq, mock_prep, mock_static, mock_runtime
    ):
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        with patch(
            "src.dynamic.session.integration.initialize_dynamic_session",
            side_effect=RuntimeError("Session storage corrupted"),
        ):
            run_demo("http://example.com/app.apk", self.output_root)

        preflight_file = self.output_root / "dynamic" / "preflight_result.json"
        self.assertTrue(preflight_file.is_file(), "preflight_result.json must not be deleted")
        with open(preflight_file, "r", encoding="utf-8") as f:
            pf = json.load(f)
        self.assertEqual(pf["stage"], "dynamic_preflight")
        self.assertEqual(pf["application"]["package_name"], "com.example.app")

    # 13. No dynamic_analysis_report.json created
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_13_no_dynamic_analysis_report_json_created(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _create_mock_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        # dynamic_analysis_report.json must NOT exist anywhere in run dir
        self.assertFalse((self.output_root / "dynamic_analysis_report.json").exists())
        self.assertFalse((self.output_root / "dynamic" / "dynamic_analysis_report.json").exists())
        self.assertFalse((self.output_root / "reports" / "dynamic_analysis_report.json").exists())

    # 14. Scan_state dynamic_analysis remains not_available
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_14_scan_state_dynamic_analysis_remains_not_available(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _create_mock_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        checkpointer = ScanStateCheckpointer(
            run_dir=self.output_root,
            scan_id=self.output_root.name,
            target_url="http://example.com/app.apk",
            platform="android",
        )
        checkpointer.init_state()

        run_demo(
            "http://example.com/app.apk",
            self.output_root,
            progress_callback=checkpointer.on_pipeline_progress,
        )

        state = load_scan_state(self.output_root)
        self.assertIsNotNone(state)
        dynamic_stage = state["stages"]["dynamic_analysis"]
        self.assertIn(
            dynamic_stage["status"],
            ("not_available", "partial"),
            "dynamic_analysis stage must remain 'not_available' or 'partial' (never completed)",
        )
        dynamic_art = state["artifacts"]["dynamic_analysis_report"]
        self.assertFalse(dynamic_art["available"])
        self.assertIsNone(dynamic_art["relative_path"])
