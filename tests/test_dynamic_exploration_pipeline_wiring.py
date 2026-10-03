"""Pipeline wiring tests for Dynamic UI Exploration (Week 1 — Day 5 Task 5.4).

Verifies that:
1. PASS preflight invokes run_exploration once.
2. usable WARN invokes exploration once.
3. FAIL preflight does not invoke exploration.
4. monolithic APK invokes exploration once.
5. split APK invokes exploration once.
6. Play Store path invokes exploration once.
7. session is reused, not recreated.
8. route graph uses existing session_id.
9. route_graph.json written under run dynamic dir.
10. exploration_result.json written.
11. dynamic stage changes not_available → running when exploration starts.
12. exploration evidence permits completion after canonical report persistence.
13. exploration no-evidence fatal failure can mark dynamic failed.
14. dynamic stage completes only with a canonical report.
15. canonical dynamic report is created at run root.
16. dynamic report artifact is registered after persistence.
17. report_generation remains partial.
18. static artifact preserved on exploration failure.
19. preflight/session/timeline preserved on exploration failure.
20. external package boundary honored.
21. blocked system UI policy honored.
22. destructive filter still honored.
23. input actions not auto-executed.
24. no duplicate exploration call.
25. iOS path does not run Android exploration.
26. host paths absent from exploration_result.json.
27. scan_state writes remain atomic via existing helpers.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

from src.demo_orchestrator import (
    _wire_dynamic_exploration,
    _wire_dynamic_session,
    run_demo,
)
from src.dynamic.action.models import ActionExecutionResult, ActionExecutionStatus
from src.dynamic.exploration.models import (
    ExplorationLimits,
    ExplorationResult,
    ExplorationStatus,
    StopReason,
)
from src.dynamic.preflight.models import (
    ApplicationInfo,
    DeviceInfo,
    NetworkInfo,
    PreflightResult,
    PreflightStatus,
    RuntimeBaseline,
)
from src.dynamic.preflight.service import save_preflight_result
from src.dynamic.ui.models import ActionCandidate, ScreenObservation
from src.scan_state import (
    ScanStateCheckpointer,
    create_initial_scan_state,
    load_scan_state,
    save_scan_state,
)


def _make_candidate(
    node_id: str = "node_1",
    text: str = "Click Me",
    action_type: str = "click",
    bounds: tuple[int, int, int, int] = (10, 10, 100, 50),
    center_x: int = 55,
    center_y: int = 30,
) -> ActionCandidate:
    return ActionCandidate(
        node_id=node_id,
        resource_id=f"com.example.app:id/{node_id}",
        class_name="android.widget.Button",
        text=text,
        content_desc="Open informational screen",
        bounds=bounds,
        center_x=center_x,
        center_y=center_y,
        action_type=action_type,
    )


def _make_screen_observation(
    screen_identity: str = "test_screen_ident_123",
    pkg: str = "com.example.app",
    activity: str = "com.example.app.MainActivity",
    is_target_pkg: bool = True,
    is_dialog: bool = False,
    actions: list[ActionCandidate] | None = None,
) -> ScreenObservation:
    action_list = actions if actions is not None else [_make_candidate()]
    return ScreenObservation(
        screen_identity=screen_identity,
        foreground_package=pkg,
        foreground_activity=activity,
        target_package="com.example.app",
        is_target_package=is_target_pkg,
        is_dialog_or_system=is_dialog,
        nodes=[],
        clickable_count=len(action_list),
        input_count=0,
        action_candidates=action_list,
        observation_attempts=1,
    )


class TestDynamicExplorationPipelineWiring(unittest.TestCase):
    """Verifies all Task 5.4 pipeline wiring and production integration requirements."""

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
        pid=1234,
        serial="emulator-5554",
    ):
        apk_file = self.output_root / "downloads" / "test_app.apk"
        apk_file.parent.mkdir(parents=True, exist_ok=True)
        apk_file.write_bytes(b"DUMMY_APK")
        mock_acq.return_value = {
            "filename": "test_app.apk",
            "saved_path": str(apk_file),
            "size_bytes": 100,
            "sha256": "abc123hash",
            "validation": {"is_valid_apk": True},
            "source_type": "direct_apk",
            "package_name": "com.example.app",
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
            "status": "success",
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

    # 1. PASS preflight invokes run_exploration once
    @patch("src.demo_orchestrator.run_exploration")
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_01_pass_preflight_invokes_run_exploration_once(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs, mock_explore
    ):
        mock_obs.return_value = _make_screen_observation()
        mock_explore.return_value = ExplorationResult(
            status=ExplorationStatus.COMPLETED.value,
            stop_reason=StopReason.COMPLETED.value,
            steps_attempted=1,
            actions_succeeded=1,
            screens_observed=1,
        )
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        self.assertEqual(mock_explore.call_count, 1)

    # 2. usable WARN invokes exploration once
    @patch("src.demo_orchestrator.run_exploration")
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_02_usable_warn_invokes_exploration_once(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs, mock_explore
    ):
        mock_obs.return_value = _make_screen_observation()
        mock_explore.return_value = ExplorationResult(
            status=ExplorationStatus.COMPLETED.value,
            stop_reason=StopReason.COMPLETED.value,
            steps_attempted=1,
            actions_succeeded=1,
            screens_observed=1,
        )
        # Foreground unverified -> WARN, but PID exists -> usable
        self._setup_mock_monolithic_pipeline(
            mock_acq, mock_prep, mock_static, mock_runtime, foreground_verified=False, pid=9999
        )

        run_demo("http://example.com/app.apk", self.output_root)

        self.assertEqual(mock_explore.call_count, 1)

    # 3. FAIL preflight does not invoke exploration
    @patch("src.demo_orchestrator.run_exploration")
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_03_fail_preflight_does_not_invoke_exploration(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs, mock_explore
    ):
        mock_obs.return_value = _make_screen_observation()
        # Process dead -> FAIL
        self._setup_mock_monolithic_pipeline(
            mock_acq, mock_prep, mock_static, mock_runtime,
            runtime_status="runtime_process_missing", foreground_verified=False, pid=None
        )

        run_demo("http://example.com/app.apk", self.output_root)

        mock_explore.assert_not_called()

    # 4. monolithic APK invokes exploration once
    @patch("src.demo_orchestrator.run_exploration")
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_04_monolithic_apk_invokes_exploration_once(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs, mock_explore
    ):
        mock_obs.return_value = _make_screen_observation()
        mock_explore.return_value = ExplorationResult(
            status=ExplorationStatus.COMPLETED.value,
            stop_reason=StopReason.COMPLETED.value,
        )
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        self.assertEqual(mock_explore.call_count, 1)

    # 5. split APK invokes exploration once
    @patch("src.demo_orchestrator.run_exploration")
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_split_static_context")
    @patch("src.demo_orchestrator.preprocess_package_set")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_05_split_apk_invokes_exploration_once(
        self, mock_acq, mock_split_prep, mock_split_static, mock_runtime, mock_obs, mock_explore
    ):
        mock_obs.return_value = _make_screen_observation()
        mock_explore.return_value = ExplorationResult(
            status=ExplorationStatus.COMPLETED.value,
            stop_reason=StopReason.COMPLETED.value,
        )

        mock_acq.return_value = {
            "package_layout": "split",
            "split_count": 2,
            "package_set_path": str(self.output_root / "downloads"),
            "package_name": "com.example.split",
            "filename": "base.apk",
            "size_bytes": 1000,
        }
        mock_split_prep.return_value = {
            "component_count": 2,
            "status": "success",
            "package_set_path": str(self.output_root / "workspaces" / "processed"),
        }
        mock_split_static.return_value = {
            "app": {"package_name": "com.example.split", "launcher_activity": "com.example.split.MainActivity"},
            "api_candidates": [],
        }
        mock_runtime.return_value = {
            "adb": {"serial": "emulator-5554"},
            "runtime": {
                "process_running": True,
                "pid": 5555,
                "observed_package": "com.example.split",
                "observed_activity": "com.example.split.MainActivity",
                "foreground_verified": True,
            },
            "status": "runtime_launch_verified",
        }

        run_demo("http://example.com/split.apk", self.output_root)

        self.assertEqual(mock_explore.call_count, 1)

    # 6. Play Store path invokes exploration once
    @patch("src.demo_orchestrator.run_exploration")
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_play_store_app")
    @patch("src.demo_orchestrator.classify_input_url")
    def test_06_play_store_path_invokes_exploration_once(
        self, mock_classify, mock_acq_ps, mock_prep, mock_static, mock_runtime, mock_obs, mock_explore
    ):
        mock_obs.return_value = _make_screen_observation()
        mock_explore.return_value = ExplorationResult(
            status=ExplorationStatus.COMPLETED.value,
            stop_reason=StopReason.COMPLETED.value,
        )

        base_apk = self.output_root / "downloads" / "base.apk"
        base_apk.parent.mkdir(parents=True, exist_ok=True)
        base_apk.write_bytes(b"APK")

        mock_classify.return_value = {
            "platform": "android",
            "type": "play_store",
            "package_name": "com.example.storeapp",
        }
        mock_acq_ps.return_value = {
            "package_name": "com.example.storeapp",
            "source_type": "play_store",
            "saved_path": str(base_apk),
            "filename": "base.apk",
            "validation": {"is_valid_apk": True},
        }
        self._setup_mock_monolithic_pipeline(
            MagicMock(), mock_prep, mock_static, mock_runtime
        )

        run_demo("https://play.google.com/store/apps/details?id=com.example.storeapp", self.output_root, adb_serial="emulator-5554")

        self.assertEqual(mock_explore.call_count, 1)

    # 7. session is reused, not recreated
    @patch("src.demo_orchestrator.run_exploration")
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_07_session_is_reused_not_recreated(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs, mock_explore
    ):
        mock_obs.return_value = _make_screen_observation()
        mock_explore.return_value = ExplorationResult(
            status=ExplorationStatus.COMPLETED.value,
            stop_reason=StopReason.COMPLETED.value,
        )
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        # Check session.json before and after
        session_file = self.output_root / "dynamic" / "session.json"
        self.assertTrue(session_file.is_file())
        with open(session_file, "r", encoding="utf-8") as f:
            session_data = json.load(f)
        session_id = session_data["session_id"]

        # Call _wire_dynamic_session again -> must NOT overwrite with new session
        _wire_dynamic_session(self.output_root, "com.example.app", "emulator-5554")
        with open(session_file, "r", encoding="utf-8") as f:
            session_data_2 = json.load(f)
        self.assertEqual(session_data_2["session_id"], session_id)

    # 8. route graph uses existing session_id
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_08_route_graph_uses_existing_session_id(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        obs = _make_screen_observation()
        mock_obs.return_value = obs
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        with open(self.output_root / "dynamic" / "session.json", "r", encoding="utf-8") as f:
            sess = json.load(f)
        expected_session_id = sess["session_id"]

        with open(self.output_root / "dynamic" / "route_graph.json", "r", encoding="utf-8") as f:
            graph_data = json.load(f)
        self.assertEqual(graph_data["session_id"], expected_session_id)

    # 9. route_graph.json written under run dynamic dir
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_09_route_graph_json_written_under_run_dynamic_dir(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        obs = _make_screen_observation()
        mock_obs.return_value = obs
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        graph_file = self.output_root / "dynamic" / "route_graph.json"
        self.assertTrue(graph_file.is_file())
        with open(graph_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["schema_version"], "1.0")

    # 10. exploration_result.json written
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_10_exploration_result_json_written(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        obs = _make_screen_observation()
        mock_obs.return_value = obs
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        res_file = self.output_root / "dynamic" / "exploration_result.json"
        self.assertTrue(res_file.is_file())
        with open(res_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("status", data)
        self.assertIn("stop_reason", data)
        self.assertIn("screens_observed", data)

    # 11. dynamic stage changes not_available -> running when exploration starts
    def test_11_dynamic_stage_changes_not_available_to_running(self):
        # Create scan_state
        init_st = create_initial_scan_state(
            scan_id=self.output_root.name,
            target_url="http://example.com/app.apk",
            platform="android",
        )
        save_scan_state(self.output_root, init_st)
        self.assertEqual(load_scan_state(self.output_root)["stages"]["dynamic_analysis"]["status"], "not_available")

        # Set up dummy preflight and session
        dyn_dir = self.output_root / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        pref = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", state="device"),
            application=ApplicationInfo(package_name="com.example.app", installed=True, process_running=True),
            runtime=RuntimeBaseline(launch_success=True),
            network=NetworkInfo(),
            status=PreflightStatus.PASS,
        )
        save_preflight_result(pref, self.output_root)
        (dyn_dir / "session.json").write_text(json.dumps({"session_id": "sess_11", "status": "active"}), encoding="utf-8")

        observed_states = []

        def spy_observer(*args, **kwargs):
            # Check scan_state while exploration is running
            st = load_scan_state(self.output_root)
            observed_states.append(st["stages"]["dynamic_analysis"]["status"])
            observed_states.append(st["current_stage"])
            return _make_screen_observation()

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=spy_observer):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        self.assertIn("running", observed_states)
        self.assertIn("dynamic_analysis", observed_states)

    # 12. exploration with evidence ends dynamic stage as partial
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_12_exploration_with_evidence_persists_report_before_completion(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _make_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        checkpointer = ScanStateCheckpointer(
            run_dir=self.output_root,
            scan_id=self.output_root.name,
            target_url="http://example.com/app.apk",
            platform="android",
        )
        checkpointer.init_state()

        run_demo("http://example.com/app.apk", self.output_root, progress_callback=checkpointer.on_pipeline_progress)

        st = load_scan_state(self.output_root)
        self.assertEqual(st["stages"]["dynamic_analysis"]["status"], "completed")

    # 13. exploration no-evidence fatal failure can mark dynamic failed
    def test_13_observation_failure_preserves_preflight_runtime_as_partial(self):
        init_st = create_initial_scan_state(
            scan_id=self.output_root.name,
            target_url="http://example.com/app.apk",
            platform="android",
        )
        save_scan_state(self.output_root, init_st)

        dyn_dir = self.output_root / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        pref = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", state="device"),
            application=ApplicationInfo(package_name="com.example.app", installed=True, process_running=True),
            runtime=RuntimeBaseline(launch_success=True),
            network=NetworkInfo(),
            status=PreflightStatus.PASS,
        )
        save_preflight_result(pref, self.output_root)
        (dyn_dir / "session.json").write_text(json.dumps({"session_id": "sess_13", "status": "active"}), encoding="utf-8")

        # Observer throws immediately on initial observation
        with patch("src.dynamic.ui.observer.observe_screen", side_effect=RuntimeError("ADB UI Dump died")):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        st = load_scan_state(self.output_root)
        self.assertEqual(st["stages"]["dynamic_analysis"]["status"], "partial")
        result = json.loads((dyn_dir / "exploration_result.json").read_text())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["stop_reason"], "observation_failed")

    # 14. dynamic stage never becomes completed
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_14_dynamic_stage_completes_with_canonical_report(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _make_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        checkpointer = ScanStateCheckpointer(
            run_dir=self.output_root,
            scan_id=self.output_root.name,
            target_url="http://example.com/app.apk",
            platform="android",
        )
        checkpointer.init_state()

        run_demo("http://example.com/app.apk", self.output_root, progress_callback=checkpointer.on_pipeline_progress)

        st = load_scan_state(self.output_root)
        self.assertTrue((self.output_root / "dynamic_analysis_report.json").is_file())
        self.assertEqual(st["stages"]["dynamic_analysis"]["status"], "completed")

    # 15. no dynamic_analysis_report.json created
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_15_root_dynamic_analysis_report_json_created(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _make_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        self.assertTrue((self.output_root / "dynamic_analysis_report.json").exists())
        self.assertFalse((self.output_root / "dynamic" / "dynamic_analysis_report.json").exists())

    # 16. dynamic report artifact remains unavailable
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_16_dynamic_report_artifact_registered(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _make_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        checkpointer = ScanStateCheckpointer(
            run_dir=self.output_root,
            scan_id=self.output_root.name,
            target_url="http://example.com/app.apk",
            platform="android",
        )
        checkpointer.init_state()

        run_demo("http://example.com/app.apk", self.output_root, progress_callback=checkpointer.on_pipeline_progress)

        st = load_scan_state(self.output_root)
        dyn_art = st["artifacts"]["dynamic_analysis_report"]
        self.assertTrue(dyn_art["available"])
        self.assertEqual(dyn_art["relative_path"], "dynamic_analysis_report.json")

    # 17. report_generation remains partial
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_17_report_generation_remains_partial(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _make_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        checkpointer = ScanStateCheckpointer(
            run_dir=self.output_root,
            scan_id=self.output_root.name,
            target_url="http://example.com/app.apk",
            platform="android",
        )
        checkpointer.init_state()

        run_demo("http://example.com/app.apk", self.output_root, progress_callback=checkpointer.on_pipeline_progress)

        st = load_scan_state(self.output_root)
        self.assertEqual(st["stages"]["report_generation"]["status"], "partial")

    # 18. static artifact preserved on exploration failure
    def test_18_static_artifact_preserved_on_exploration_failure(self):
        # Create static report
        static_file = self.output_root / "static_analysis_report.json"
        static_file.write_text(json.dumps({"status": "completed", "findings": []}), encoding="utf-8")

        dyn_dir = self.output_root / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        pref = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", state="device"),
            application=ApplicationInfo(package_name="com.example.app", installed=True, process_running=True),
            runtime=RuntimeBaseline(launch_success=True),
            network=NetworkInfo(),
            status=PreflightStatus.PASS,
        )
        save_preflight_result(pref, self.output_root)
        (dyn_dir / "session.json").write_text(json.dumps({"session_id": "sess_18", "status": "active"}), encoding="utf-8")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=Exception("Exploration crashed")):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        # Static report must still exist and be intact
        self.assertTrue(static_file.is_file())
        with open(static_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["status"], "completed")

    # 19. preflight/session/timeline preserved on exploration failure
    def test_19_preflight_session_timeline_preserved_on_exploration_failure(self):
        dyn_dir = self.output_root / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        pref = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", state="device"),
            application=ApplicationInfo(package_name="com.example.app", installed=True, process_running=True),
            runtime=RuntimeBaseline(launch_success=True),
            network=NetworkInfo(),
            status=PreflightStatus.PASS,
        )
        save_preflight_result(pref, self.output_root)
        (dyn_dir / "session.json").write_text(json.dumps({"session_id": "sess_19", "status": "active"}), encoding="utf-8")
        (dyn_dir / "timeline.json").write_text(json.dumps([{"type": "system_event", "name": "INIT"}]), encoding="utf-8")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=RuntimeError("Exploration fatal")):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        self.assertTrue((dyn_dir / "preflight_result.json").is_file())
        self.assertTrue((dyn_dir / "session.json").is_file())
        self.assertTrue((dyn_dir / "timeline.json").is_file())

    # 20. external package boundary honored
    @patch("src.dynamic.action.executor.ActionExecutor.click")
    @patch("src.dynamic.ui.observer.observe_screen")
    def test_20_external_package_boundary_honored(self, mock_obs, mock_click):
        mock_click.return_value = ActionExecutionResult(
            action_id="act_ext", action_type="click", status=ActionExecutionStatus.SUCCEEDED.value,
            started_at="2026-10-01T10:00:00+00:00", completed_at="2026-10-01T10:00:01+00:00",
        )
        obs_app = _make_screen_observation(screen_identity="s_app_home")
        obs_ext = _make_screen_observation(screen_identity="s_chrome", pkg="com.android.chrome", is_target_pkg=False, is_dialog=False)
        mock_obs.side_effect = [obs_ext]

        dyn_dir = self.output_root / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        pref = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", state="device"),
            application=ApplicationInfo(package_name="com.example.app", installed=True, process_running=True),
            runtime=RuntimeBaseline(launch_success=True),
            network=NetworkInfo(),
            status=PreflightStatus.PASS,
        )
        save_preflight_result(pref, self.output_root)
        (dyn_dir / "session.json").write_text(json.dumps({"session_id": "sess_20", "status": "active"}), encoding="utf-8")

        res = _wire_dynamic_exploration(
            self.output_root, "com.example.app", "emulator-5554",
            initial_observation=obs_app,
        )

        self.assertIsNotNone(res)
        self.assertEqual(res.stop_reason, StopReason.EXTERNAL_PACKAGE.value)

    # 21. blocked system UI policy honored
    @patch("src.dynamic.action.executor.ActionExecutor.click")
    @patch("src.dynamic.ui.observer.observe_screen")
    def test_21_blocked_system_ui_policy_honored(self, mock_obs, mock_click):
        mock_click.return_value = ActionExecutionResult(
            action_id="act_settings", action_type="click", status=ActionExecutionStatus.SUCCEEDED.value,
            started_at="2026-10-01T10:00:00+00:00", completed_at="2026-10-01T10:00:01+00:00",
        )
        obs_app = _make_screen_observation(screen_identity="s_app_settings_btn")
        obs_settings = _make_screen_observation(screen_identity="s_settings", pkg="com.android.settings", is_target_pkg=False, is_dialog=True)
        mock_obs.side_effect = [obs_settings]

        dyn_dir = self.output_root / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        pref = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", state="device"),
            application=ApplicationInfo(package_name="com.example.app", installed=True, process_running=True),
            runtime=RuntimeBaseline(launch_success=True),
            network=NetworkInfo(),
            status=PreflightStatus.PASS,
        )
        save_preflight_result(pref, self.output_root)
        (dyn_dir / "session.json").write_text(json.dumps({"session_id": "sess_21", "status": "active"}), encoding="utf-8")

        res = _wire_dynamic_exploration(
            self.output_root, "com.example.app", "emulator-5554",
            initial_observation=obs_app,
        )

        self.assertIsNotNone(res)
        self.assertEqual(res.stop_reason, StopReason.SYSTEM_UI_BOUNDARY.value)

    # 22. destructive filter still honored
    @patch("src.dynamic.action.executor.ActionExecutor.click")
    def test_22_destructive_filter_still_honored(self, mock_click):
        btn_del = _make_candidate(node_id="btn_delete", text="Delete Account")
        obs_danger = _make_screen_observation(actions=[btn_del])

        dyn_dir = self.output_root / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        pref = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", state="device"),
            application=ApplicationInfo(package_name="com.example.app", installed=True, process_running=True),
            runtime=RuntimeBaseline(launch_success=True),
            network=NetworkInfo(),
            status=PreflightStatus.PASS,
        )
        save_preflight_result(pref, self.output_root)
        (dyn_dir / "session.json").write_text(json.dumps({"session_id": "sess_22", "status": "active"}), encoding="utf-8")

        res = _wire_dynamic_exploration(
            self.output_root, "com.example.app", "emulator-5554",
            initial_observation=obs_danger,
        )

        mock_click.assert_not_called()
        self.assertEqual(res.stop_reason, StopReason.UNSAFE_ACTION_BOUNDARY.value)

    # 23. input actions not auto-executed
    @patch("src.dynamic.action.executor.ActionExecutor.click")
    def test_23_input_actions_not_auto_executed(self, mock_click):
        inp = _make_candidate(node_id="inp_email", text="Email", action_type="input")
        obs_input = _make_screen_observation(actions=[inp])

        dyn_dir = self.output_root / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        pref = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", state="device"),
            application=ApplicationInfo(package_name="com.example.app", installed=True, process_running=True),
            runtime=RuntimeBaseline(launch_success=True),
            network=NetworkInfo(),
            status=PreflightStatus.PASS,
        )
        save_preflight_result(pref, self.output_root)
        (dyn_dir / "session.json").write_text(json.dumps({"session_id": "sess_23", "status": "active"}), encoding="utf-8")

        res = _wire_dynamic_exploration(
            self.output_root, "com.example.app", "emulator-5554",
            initial_observation=obs_input,
        )

        mock_click.assert_not_called()
        self.assertEqual(res.steps_attempted, 0)

    # 24. no duplicate exploration call
    @patch("src.dynamic.exploration.loop.run_exploration")
    def test_24_no_duplicate_exploration_call(self, mock_run_exp):
        dyn_dir = self.output_root / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        pref = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", state="device"),
            application=ApplicationInfo(package_name="com.example.app", installed=True, process_running=True),
            runtime=RuntimeBaseline(launch_success=True),
            network=NetworkInfo(),
            status=PreflightStatus.PASS,
        )
        save_preflight_result(pref, self.output_root)
        (dyn_dir / "session.json").write_text(json.dumps({"session_id": "sess_24", "status": "active"}), encoding="utf-8")

        # Simulate existing exploration_result.json
        (dyn_dir / "exploration_result.json").write_text(json.dumps({"status": "completed"}), encoding="utf-8")

        res = _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")
        self.assertIsNone(res)
        mock_run_exp.assert_not_called()

    # 25. iOS path does not run Android exploration
    @patch("src.demo_orchestrator._wire_dynamic_exploration")
    @patch("src.demo_orchestrator._run_ios_pipeline")
    @patch("src.demo_orchestrator.classify_input_url")
    def test_25_ios_path_does_not_run_android_exploration(
        self, mock_classify, mock_ios_pipe, mock_wire_exp
    ):
        mock_classify.return_value = {
            "platform": "ios",
            "type": "direct_ipa",
        }
        mock_ios_pipe.return_value = {"status": "success", "platform": "ios"}

        run_demo("http://example.com/app.ipa", self.output_root, platform="ios")

        mock_wire_exp.assert_not_called()

    # 26. host paths absent from exploration_result.json
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_26_host_paths_absent_from_exploration_result_json(
        self, mock_acq, mock_prep, mock_static, mock_runtime, mock_obs
    ):
        mock_obs.return_value = _make_screen_observation()
        self._setup_mock_monolithic_pipeline(mock_acq, mock_prep, mock_static, mock_runtime)

        run_demo("http://example.com/app.apk", self.output_root)

        res_path = self.output_root / "dynamic" / "exploration_result.json"
        self.assertTrue(res_path.is_file())
        raw_text = res_path.read_text(encoding="utf-8")

        for forbidden in ("/Users/", "/home/", "/private/tmp", "/opt/homebrew"):
            self.assertNotIn(forbidden, raw_text, f"Host path '{forbidden}' leaked in exploration_result.json")

    # 27. scan_state writes remain atomic via existing helpers
    def test_27_scan_state_writes_remain_atomic_via_existing_helpers(self):
        init_st = create_initial_scan_state(
            scan_id=self.output_root.name,
            target_url="http://example.com/app.apk",
            platform="android",
        )
        save_scan_state(self.output_root, init_st)

        dyn_dir = self.output_root / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        pref = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", state="device"),
            application=ApplicationInfo(package_name="com.example.app", installed=True, process_running=True),
            runtime=RuntimeBaseline(launch_success=True),
            network=NetworkInfo(),
            status=PreflightStatus.PASS,
        )
        save_preflight_result(pref, self.output_root)
        (dyn_dir / "session.json").write_text(json.dumps({"session_id": "sess_27", "status": "active"}), encoding="utf-8")

        with patch("src.dynamic.ui.observer.observe_screen", return_value=_make_screen_observation()):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        # scan_state.json must be valid JSON and have no lingering .tmp files
        state_file = self.output_root / "scan_state.json"
        self.assertTrue(state_file.is_file())
        loaded = load_scan_state(self.output_root)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["stages"]["dynamic_analysis"]["status"], "completed")

        tmp_files = list(self.output_root.glob(".tmp_*"))
        self.assertEqual(tmp_files, [], "No temporary atomic write files should linger")


    @patch("src.dynamic.traffic.service.DynamicTrafficService")
    @patch("src.demo_orchestrator.run_exploration")
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("src.demo_orchestrator.launch_android_app")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.acquire_apk")
    def test_capture_port_reaches_readiness_and_backend(
        self, acq, prep, static, runtime, observe, explore, service_class
    ):
        self._setup_mock_monolithic_pipeline(acq, prep, static, runtime)
        observe.return_value = _make_screen_observation()
        explore.return_value = ExplorationResult(status="completed", stop_reason="completed", screens_observed=1)
        service = service_class.return_value
        service.check_readiness.return_value.backend_available = True
        service.check_readiness.return_value.adb_available = True
        service.captured_transactions = []
        service.active_capture = None
        run_demo("http://example.com/app.apk", self.output_root, traffic_proxy_port=18080)
        self.assertEqual(service.check_readiness.call_args.kwargs["proxy_port"], 18080)
        self.assertEqual(service.start_capture.call_args.kwargs["proxy_port"], 18080)
        service.stop_capture.assert_called_once()
        events = json.loads((self.output_root / "dynamic" / "timeline.json").read_text())
        self.assertIn("18080", json.dumps(events))

    @patch("src.demo_orchestrator.acquire_apk")
    def test_invalid_capture_port_rejected_before_acquisition(self, acquire):
        for port in (True, 0, 65536, "18080"):
            with self.assertRaises(ValueError):
                run_demo("http://example.com/app.apk", self.output_root, traffic_proxy_port=port)
        acquire.assert_not_called()


class TestTask541SemanticsCleanup(unittest.TestCase):
    """Verifies Task 5.4.1 canonical status vocabulary, stop reason mapping, and scan_state semantics."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_root = Path(self.temp_dir.name)
        (self.output_root / "dynamic").mkdir(parents=True, exist_ok=True)
        # Seed valid preflight and session
        pref = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", state="device"),
            application=ApplicationInfo(package_name="com.example.app", installed=True, process_running=True),
            runtime=RuntimeBaseline(launch_success=True),
            network=NetworkInfo(),
            status=PreflightStatus.PASS,
        )
        save_preflight_result(pref, self.output_root)
        (self.output_root / "dynamic" / "session.json").write_text(
            json.dumps({"session_id": "sess_541", "status": "active"}),
            encoding="utf-8",
        )
        # Seed initial scan_state
        init_st = create_initial_scan_state(
            scan_id=self.output_root.name,
            target_url="http://example.com/app.apk",
            platform="android",
        )
        save_scan_state(self.output_root, init_st)

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. max_steps persists status=partial
    def test_541_01_max_steps_persists_status_partial(self):
        res = ExplorationResult(
            status=ExplorationStatus.PARTIAL.value,
            stop_reason=StopReason.MAX_STEPS.value,
            steps_attempted=10,
            screens_observed=3,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        data = json.loads((self.output_root / "dynamic" / "exploration_result.json").read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "partial")
        self.assertEqual(data["stop_reason"], "max_steps")

    # 2. max_depth persists status=partial
    def test_541_02_max_depth_persists_status_partial(self):
        res = ExplorationResult(
            status=ExplorationStatus.PARTIAL.value,
            stop_reason=StopReason.MAX_DEPTH.value,
            steps_attempted=5,
            screens_observed=3,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        data = json.loads((self.output_root / "dynamic" / "exploration_result.json").read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "partial")
        self.assertEqual(data["stop_reason"], "max_depth")

    # 3. deadline persists status=partial
    def test_541_03_deadline_persists_status_partial(self):
        res = ExplorationResult(
            status=ExplorationStatus.PARTIAL.value,
            stop_reason=StopReason.DEADLINE.value,
            steps_attempted=4,
            screens_observed=2,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        data = json.loads((self.output_root / "dynamic" / "exploration_result.json").read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "partial")
        self.assertEqual(data["stop_reason"], "deadline")

    # 4. external_package persists status=partial when evidence exists
    def test_541_04_external_package_persists_status_partial(self):
        res = ExplorationResult(
            status=ExplorationStatus.PARTIAL.value,
            stop_reason=StopReason.EXTERNAL_PACKAGE.value,
            screens_observed=2,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        data = json.loads((self.output_root / "dynamic" / "exploration_result.json").read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "partial")
        self.assertEqual(data["stop_reason"], "external_package")

    # 5. system_ui_boundary persists status=partial when evidence exists
    def test_541_05_system_ui_boundary_persists_status_partial(self):
        res = ExplorationResult(
            status=ExplorationStatus.PARTIAL.value,
            stop_reason=StopReason.SYSTEM_UI_BOUNDARY.value,
            screens_observed=1,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        data = json.loads((self.output_root / "dynamic" / "exploration_result.json").read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "partial")
        self.assertEqual(data["stop_reason"], "system_ui_boundary")

    # 6. natural no_actions completion can persist status=completed
    def test_541_06_natural_no_actions_completion_persists_status_completed(self):
        res = ExplorationResult(
            status=ExplorationStatus.COMPLETED.value,
            stop_reason=StopReason.NO_ACTIONS.value,
            steps_attempted=3,
            actions_succeeded=3,
            screens_observed=2,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        data = json.loads((self.output_root / "dynamic" / "exploration_result.json").read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["stop_reason"], "no_actions")

    # 7. fatal no-evidence failure persists status=failed
    def test_541_07_fatal_no_evidence_failure_persists_status_failed(self):
        res = ExplorationResult(
            status=ExplorationStatus.FAILED.value,
            stop_reason=StopReason.OBSERVATION_FAILED.value,
            steps_attempted=0,
            screens_observed=0,
            error="Device disconnected immediately",
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        data = json.loads((self.output_root / "dynamic" / "exploration_result.json").read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "failed")
        self.assertEqual(data["stop_reason"], "observation_failed")

    # 8. stopped is never persisted as exploration status
    def test_541_08_stopped_is_never_persisted_as_exploration_status(self):
        for stop_r in StopReason:
            res = ExplorationResult(
                status=ExplorationStatus.PARTIAL.value if stop_r not in (StopReason.COMPLETED, StopReason.NO_ACTIONS) else ExplorationStatus.COMPLETED.value,
                stop_reason=stop_r.value,
                screens_observed=1,
            )
            with patch("src.demo_orchestrator.run_exploration", return_value=res):
                _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")
            data = json.loads((self.output_root / "dynamic" / "exploration_result.json").read_text(encoding="utf-8"))
            self.assertNotEqual(data["status"], "stopped")
            self.assertIn(data["status"], ("completed", "partial", "failed"))
            (self.output_root / "dynamic" / "exploration_result.json").unlink()

    # 9. canonical StopReason strings are preserved exactly
    def test_541_09_canonical_stop_reason_strings_preserved_exactly(self):
        expected_values = {
            "completed",
            "no_actions",
            "unsafe_action_boundary",
            "repeated_state",
            "max_steps",
            "max_depth",
            "deadline",
            "external_package",
            "system_ui_boundary",
            "observation_failed",
            "executor_failed",
        }
        enum_values = {e.value for e in StopReason}
        self.assertEqual(enum_values, expected_values)
        self.assertNotIn("blocked_external", enum_values)

    # 10. exploration_result uses canonical ExplorationResult field names
    def test_541_10_exploration_result_uses_canonical_field_names(self):
        res = ExplorationResult(
            status=ExplorationStatus.PARTIAL.value,
            stop_reason=StopReason.MAX_STEPS.value,
            root_node_id="root_screen_hex_123",
            current_node_id="curr_screen_hex_456",
            steps_attempted=5,
            screens_observed=2,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        data = json.loads((self.output_root / "dynamic" / "exploration_result.json").read_text(encoding="utf-8"))
        self.assertIn("schema_version", data)
        self.assertIn("root_node_id", data)
        self.assertIn("current_node_id", data)
        self.assertNotIn("root_screen_identity", data)
        self.assertNotIn("current_screen_identity", data)
        self.assertEqual(data["root_node_id"], "root_screen_hex_123")
        self.assertEqual(data["current_node_id"], "curr_screen_hex_456")

    # Task 8.1: report completion is independent of exploration coverage.
    def test_541_11_dynamic_analysis_report_completed_for_completed_exploration(self):
        res = ExplorationResult(
            status=ExplorationStatus.COMPLETED.value,
            stop_reason=StopReason.COMPLETED.value,
            screens_observed=2,
            actions_succeeded=2,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        st = load_scan_state(self.output_root)
        self.assertEqual(st["stages"]["dynamic_analysis"]["status"], "completed")

    # Task 8.1: partial exploration may produce a completed canonical report.
    def test_541_12_dynamic_analysis_report_completed_with_partial_coverage(self):
        res = ExplorationResult(
            status=ExplorationStatus.PARTIAL.value,
            stop_reason=StopReason.MAX_STEPS.value,
            screens_observed=2,
            actions_succeeded=1,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        st = load_scan_state(self.output_root)
        self.assertEqual(st["stages"]["dynamic_analysis"]["status"], "completed")

    # Task 8.1: completion is backed by the canonical artifact.
    def test_541_13_dynamic_analysis_completes_with_canonical_report(self):
        res = ExplorationResult(
            status=ExplorationStatus.COMPLETED.value,
            stop_reason=StopReason.COMPLETED.value,
            screens_observed=5,
            actions_succeeded=5,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        st = load_scan_state(self.output_root)
        self.assertTrue((self.output_root / "dynamic_analysis_report.json").is_file())
        self.assertEqual(st["stages"]["dynamic_analysis"]["status"], "completed")

    # Task 8.1: dynamic artifact is registered after persistence.
    def test_541_14_dynamic_report_artifact_registered(self):
        res = ExplorationResult(
            status=ExplorationStatus.PARTIAL.value,
            stop_reason=StopReason.MAX_STEPS.value,
            screens_observed=2,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        st = load_scan_state(self.output_root)
        self.assertTrue(st["artifacts"]["dynamic_analysis_report"]["available"])
        self.assertEqual(st["artifacts"]["dynamic_analysis_report"].get("relative_path"), "dynamic_analysis_report.json")

    # 15. report_generation remains partial
    def test_541_15_report_generation_remains_partial(self):
        (self.output_root / "static_analysis_report.json").write_text(
            json.dumps({"status": "completed"}), encoding="utf-8"
        )
        res = ExplorationResult(
            status=ExplorationStatus.PARTIAL.value,
            stop_reason=StopReason.MAX_STEPS.value,
            screens_observed=2,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        st = load_scan_state(self.output_root)
        self.assertEqual(st["stages"]["report_generation"]["status"], "partial")

    # 16. final current_stage is not stale if pipeline has already moved past dynamic exploration
    def test_541_16_final_current_stage_is_not_stale(self):
        res = ExplorationResult(
            status=ExplorationStatus.PARTIAL.value,
            stop_reason=StopReason.MAX_STEPS.value,
            screens_observed=2,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        st = load_scan_state(self.output_root)
        self.assertNotEqual(st["current_stage"], "dynamic_analysis")
        self.assertEqual(st["current_stage"], "report_generation")

    # 17. overall_status semantics remain consistent with established pipeline behavior
    def test_541_17_overall_status_semantics_remain_consistent(self):
        res = ExplorationResult(
            status=ExplorationStatus.PARTIAL.value,
            stop_reason=StopReason.MAX_STEPS.value,
            screens_observed=2,
        )
        with patch("src.demo_orchestrator.run_exploration", return_value=res):
            _wire_dynamic_exploration(self.output_root, "com.example.app", "emulator-5554")

        (self.output_root / "static_analysis_report.json").write_text(
            json.dumps({"status": "completed"}), encoding="utf-8"
        )
        init_st = load_scan_state(self.output_root)
        init_st["overall_status"] = "completed"
        save_scan_state(self.output_root, init_st)

        from src.demo_orchestrator import _finalize_scan_state_post_run
        _finalize_scan_state_post_run(self.output_root)

        st = load_scan_state(self.output_root)
        self.assertEqual(st["overall_status"], "completed")
        self.assertEqual(st["current_stage"], "completed")
        self.assertEqual(st["stages"]["dynamic_analysis"]["status"], "completed")
        self.assertEqual(st["stages"]["report_generation"]["status"], "partial")
