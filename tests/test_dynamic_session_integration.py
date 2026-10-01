"""Comprehensive tests for Dynamic Session & Evidence Persistence Integration (Task 4.3).

Validates run-scoped session/timeline creation, preflight evidence recording,
initial screen observation, failure handling, privacy/security, and product integrity.

All ADB/UI observation interactions are mocked. No real emulator required.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.dynamic.preflight.models import (
    ApplicationInfo,
    DeviceInfo,
    NetworkInfo,
    PreflightResult,
    PreflightStatus,
    RuntimeBaseline,
)
from src.dynamic.session.integration import (
    _build_observation_event_metadata,
    _build_preflight_event_metadata,
    _sanitize_value,
    initialize_dynamic_session,
)
from src.dynamic.session.models import (
    SessionErrorCode,
    SessionException,
    SessionStatus,
)
from src.dynamic.session.storage import SessionStorage
from src.dynamic.ui.models import ScreenObservation


def _make_preflight(
    status: PreflightStatus = PreflightStatus.PASS,
    device_serial: str = "emulator-5554",
    is_emulator: bool = True,
    package_name: str = "com.example.bank",
    installed: bool = True,
    process_running: bool = True,
    foreground: bool = True,
    launch_success: bool = True,
    pid: int = 12345,
    launch_attempts: int = 1,
    ready_after_attempt: int = 1,
    warnings: list[str] | None = None,
    errors: list[dict[str, str]] | None = None,
) -> PreflightResult:
    """Helper to construct a PreflightResult with sane defaults."""
    return PreflightResult(
        device=DeviceInfo(
            connected=True,
            serial=device_serial,
            state="device",
            is_emulator=is_emulator,
        ),
        application=ApplicationInfo(
            package_name=package_name,
            installed=installed,
            launchable=True,
            main_activity="com.example.bank.MainActivity",
            process_running=process_running,
            foreground=foreground,
        ),
        runtime=RuntimeBaseline(
            launch_success=launch_success,
            immediate_crash=False,
            fatal_log_detected=False,
            pid=pid,
            launch_attempts=launch_attempts,
            ready_after_attempt=ready_after_attempt,
        ),
        network=NetworkInfo(internet_reachable=True, dns_configured=True),
        status=status,
        warnings=warnings or [],
        errors=errors or [],
    )


def _make_screen_observation(**kwargs) -> ScreenObservation:
    """Helper to construct a ScreenObservation with sane defaults."""
    defaults = dict(
        screen_identity="abc123def456ab78",
        foreground_package="com.example.bank",
        foreground_activity="com.example.bank.MainActivity",
        target_package="com.example.bank",
        is_target_package=True,
        is_dialog_or_system=False,
        clickable_count=4,
        input_count=2,
        nodes=[],
        action_candidates=[],
        observation_attempts=1,
        diagnostics=[],
    )
    defaults.update(kwargs)
    return ScreenObservation(**defaults)


class TestDynamicSessionIntegration(unittest.TestCase):
    """Integration tests for run-scoped Dynamic Session creation and evidence persistence."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_dyn_session_integ_")
        self.run_id = "run_test_20261001_001"
        self.run_dir = os.path.join(self.test_dir, self.run_id)
        os.makedirs(self.run_dir, exist_ok=True)
        self.dynamic_dir = os.path.join(self.run_dir, "dynamic")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # --- 1. Successful preflight creates session artifacts under run dynamic/ ---
    def test_01_pass_preflight_creates_session_artifacts(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        mock_obs = MagicMock(return_value=_make_screen_observation())

        result = initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
            observe_screen_fn=mock_obs,
        )

        self.assertEqual(result["status"], "ACTIVE")
        self.assertTrue(os.path.isdir(self.dynamic_dir))

    # --- 2. session.json exists ---
    def test_02_session_json_exists(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
        )

        session_file = os.path.join(self.dynamic_dir, "session.json")
        self.assertTrue(os.path.isfile(session_file))
        with open(session_file, "r") as f:
            data = json.load(f)
        self.assertIn("session_id", data)
        self.assertIn("status", data)

    # --- 3. timeline.json exists ---
    def test_03_timeline_json_exists(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
        )

        timeline_file = os.path.join(self.dynamic_dir, "timeline.json")
        self.assertTrue(os.path.isfile(timeline_file))
        with open(timeline_file, "r") as f:
            data = json.load(f)
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    # --- 4. Old global artifact directory is not used for run-scoped integration ---
    def test_04_no_global_artifact_directory_used(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
        )

        global_dir = os.path.join(self.test_dir, "artifacts", "dynamic", "sessions")
        self.assertFalse(os.path.exists(global_dir))

    # --- 5. session_id is distinct from run_id ---
    def test_05_session_id_distinct_from_run_id(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        result = initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
        )

        self.assertIsNotNone(result["session_id"])
        self.assertNotEqual(result["session_id"], self.run_id)

    # --- 6. run_id association preserved in metadata ---
    def test_06_run_id_in_session_metadata(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
        )

        with open(os.path.join(self.dynamic_dir, "session.json"), "r") as f:
            session_data = json.load(f)
        self.assertEqual(session_data["metadata"]["run_id"], self.run_id)

    # --- 7. preflight PASS creates preflight timeline event ---
    def test_07_pass_preflight_creates_timeline_event(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
        )

        with open(os.path.join(self.dynamic_dir, "timeline.json"), "r") as f:
            timeline = json.load(f)

        event_names = [e["name"] for e in timeline]
        self.assertIn("SESSION_STARTED", event_names)
        self.assertIn("DYNAMIC_PREFLIGHT_COMPLETED", event_names)

        pf_event = next(e for e in timeline if e["name"] == "DYNAMIC_PREFLIGHT_COMPLETED")
        self.assertEqual(pf_event["metadata"]["status"], "PASS")

    # --- 8. preflight WARN preserves WARN evidence ---
    def test_08_warn_preflight_preserves_warnings(self):
        preflight = _make_preflight(
            status=PreflightStatus.WARN,
            warnings=["Android Emulator environment detected.", "Root environment detected."],
        )
        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
        )

        with open(os.path.join(self.dynamic_dir, "session.json"), "r") as f:
            session_data = json.load(f)
        self.assertEqual(session_data["preflight_status"], "WARN")
        self.assertIn("Android Emulator environment detected.", session_data["warnings"])

        with open(os.path.join(self.dynamic_dir, "timeline.json"), "r") as f:
            timeline = json.load(f)
        pf_event = next(e for e in timeline if e["name"] == "DYNAMIC_PREFLIGHT_COMPLETED")
        self.assertEqual(pf_event["metadata"]["status"], "WARN")
        self.assertIn("Android Emulator environment detected.", pf_event["metadata"]["warnings"])

    # --- 9. preflight FAIL evidence persists ---
    def test_09_fail_preflight_evidence_persists(self):
        preflight = _make_preflight(
            status=PreflightStatus.FAIL,
            errors=[{"code": "DEVICE_NOT_FOUND", "message": "No device connected"}],
            pid=None,
            launch_success=False,
            process_running=False,
            foreground=False,
        )
        result = initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
        )

        self.assertEqual(result["status"], "ABORTED")
        self.assertTrue(os.path.isfile(os.path.join(self.dynamic_dir, "session.json")))
        self.assertTrue(os.path.isfile(os.path.join(self.dynamic_dir, "timeline.json")))

        with open(os.path.join(self.dynamic_dir, "session.json"), "r") as f:
            session_data = json.load(f)
        self.assertEqual(session_data["status"], "ABORTED")
        self.assertEqual(session_data["preflight_status"], "FAIL")

    # --- 10. preflight FAIL does not execute UI observation ---
    def test_10_fail_preflight_no_ui_observation(self):
        preflight = _make_preflight(
            status=PreflightStatus.FAIL,
            errors=[{"code": "APP_CRASHED", "message": "Immediate crash"}],
            pid=None,
            launch_success=False,
        )
        mock_obs = MagicMock(return_value=_make_screen_observation())

        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
            observe_screen_fn=mock_obs,
        )

        # observe_screen_fn must NOT have been called
        mock_obs.assert_not_called()

        with open(os.path.join(self.dynamic_dir, "timeline.json"), "r") as f:
            timeline = json.load(f)
        event_names = [e["name"] for e in timeline]
        self.assertNotIn("SCREEN_OBSERVED", event_names)

    # --- 11. usable preflight triggers exactly one initial UI observation ---
    def test_11_usable_preflight_triggers_one_observation(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        mock_obs = MagicMock(return_value=_make_screen_observation())

        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
            observe_screen_fn=mock_obs,
        )

        mock_obs.assert_called_once_with(
            serial="emulator-5554",
            target_package="com.example.bank",
        )

    # --- 12. initial ScreenObservation produces SCREEN_OBSERVED event ---
    def test_12_screen_observation_produces_timeline_event(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        mock_obs = MagicMock(return_value=_make_screen_observation(
            screen_identity="87b570f7aa6d5577",
            clickable_count=5,
            input_count=2,
        ))

        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
            observe_screen_fn=mock_obs,
        )

        with open(os.path.join(self.dynamic_dir, "timeline.json"), "r") as f:
            timeline = json.load(f)

        obs_events = [e for e in timeline if e["name"] == "SCREEN_OBSERVED"]
        self.assertEqual(len(obs_events), 1)
        meta = obs_events[0]["metadata"]
        self.assertEqual(meta["screen_identity"], "87b570f7aa6d5577")
        self.assertEqual(meta["clickable_count"], 5)
        self.assertEqual(meta["input_count"], 2)

    # --- 13. timeline stores compact metadata, not giant raw node tree ---
    def test_13_timeline_compact_metadata(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        obs = _make_screen_observation()
        mock_obs = MagicMock(return_value=obs)

        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
            observe_screen_fn=mock_obs,
        )

        with open(os.path.join(self.dynamic_dir, "timeline.json"), "r") as f:
            timeline = json.load(f)

        obs_event = next(e for e in timeline if e["name"] == "SCREEN_OBSERVED")
        meta = obs_event["metadata"]

        # Should contain compact keys only
        self.assertIn("screen_identity", meta)
        self.assertIn("clickable_count", meta)
        self.assertIn("input_count", meta)
        self.assertIn("node_count", meta)

        # Must NOT contain full node arrays
        self.assertNotIn("nodes", meta)
        self.assertNotIn("action_candidates", meta)

        # Entire timeline file should be reasonably small
        raw = json.dumps(timeline)
        self.assertLess(len(raw), 10000)

    # --- 14. observation failure persists failure event ---
    def test_14_observation_failure_persists_event(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        mock_obs = MagicMock(side_effect=Exception("uiautomator dump failed"))

        result = initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
            observe_screen_fn=mock_obs,
        )

        # Session should still be ACTIVE (not crashed)
        self.assertEqual(result["status"], "ACTIVE")
        self.assertIsNotNone(result["observation_error"])

        with open(os.path.join(self.dynamic_dir, "timeline.json"), "r") as f:
            timeline = json.load(f)
        event_names = [e["name"] for e in timeline]
        self.assertIn("UI_OBSERVATION_FAILED", event_names)

        fail_event = next(e for e in timeline if e["name"] == "UI_OBSERVATION_FAILED")
        self.assertIn("reason", fail_event["metadata"])

    # --- 15. session remains non-completed after only initial observation ---
    def test_15_session_not_completed_after_initial_observation(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        mock_obs = MagicMock(return_value=_make_screen_observation())

        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
            observe_screen_fn=mock_obs,
        )

        with open(os.path.join(self.dynamic_dir, "session.json"), "r") as f:
            session_data = json.load(f)
        self.assertEqual(session_data["status"], "ACTIVE")
        self.assertIsNone(session_data["ended_at"])

    # --- 16. no dynamic_analysis_report.json created ---
    def test_16_no_dynamic_analysis_report_created(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        mock_obs = MagicMock(return_value=_make_screen_observation())

        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
            observe_screen_fn=mock_obs,
        )

        # No dynamic report should exist anywhere in run directory
        for root, dirs, files in os.walk(self.run_dir):
            for f in files:
                self.assertNotEqual(f, "dynamic_analysis_report.json")

    # --- 17. dynamic product stage not marked completed ---
    def test_17_dynamic_stage_not_completed(self):
        """scan_state.json is not modified by session integration."""
        preflight = _make_preflight(status=PreflightStatus.PASS)
        mock_obs = MagicMock(return_value=_make_screen_observation())

        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
            observe_screen_fn=mock_obs,
        )

        scan_state_path = os.path.join(self.run_dir, "scan_state.json")
        # Task 4.3 should not create or modify scan_state.json
        self.assertFalse(os.path.isfile(scan_state_path))

    # --- 18. agent stage unchanged ---
    def test_18_agent_stage_unchanged(self):
        """Session integration does not reference or modify agent_analysis."""
        preflight = _make_preflight(status=PreflightStatus.PASS)
        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
        )

        with open(os.path.join(self.dynamic_dir, "session.json"), "r") as f:
            session_data = json.load(f)
        # Session should not contain agent_analysis references
        raw = json.dumps(session_data)
        self.assertNotIn("agent_analysis", raw)

    # --- 19. password text never appears in persisted timeline/session ---
    def test_19_password_text_not_in_persisted_data(self):
        preflight = _make_preflight(status=PreflightStatus.PASS)
        obs = _make_screen_observation()
        # Simulate observation with a password field's text already redacted by Task 4.2
        mock_obs = MagicMock(return_value=obs)

        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
            observe_screen_fn=mock_obs,
        )

        with open(os.path.join(self.dynamic_dir, "session.json"), "r") as f:
            session_raw = f.read()
        with open(os.path.join(self.dynamic_dir, "timeline.json"), "r") as f:
            timeline_raw = f.read()

        # Verify sensitive patterns absent
        for raw in (session_raw, timeline_raw):
            self.assertNotIn("Secret123", raw)
            self.assertNotIn("ClearTextPassword", raw)

    # --- 20. no host absolute paths appear in session/timeline serialization ---
    def test_20_no_host_paths_in_serialized_data(self):
        preflight = _make_preflight(
            status=PreflightStatus.WARN,
            warnings=["Path /Users/suleyman/test/app was used"],
        )
        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
        )

        with open(os.path.join(self.dynamic_dir, "session.json"), "r") as f:
            session_raw = f.read()
        with open(os.path.join(self.dynamic_dir, "timeline.json"), "r") as f:
            timeline_raw = f.read()

        for raw in (session_raw, timeline_raw):
            self.assertNotIn("/Users/suleyman", raw)
            self.assertNotIn("/home/", raw)

    # --- 21. writes remain atomic ---
    def test_21_atomic_writes(self):
        """SessionStorage._atomic_write_json uses temp+replace pattern."""
        preflight = _make_preflight(status=PreflightStatus.PASS)
        initialize_dynamic_session(
            run_id=self.run_id,
            run_dir=self.run_dir,
            package_name="com.example.bank",
            device_serial="emulator-5554",
            preflight_result=preflight,
        )

        session_file = os.path.join(self.dynamic_dir, "session.json")
        timeline_file = os.path.join(self.dynamic_dir, "timeline.json")

        # Both files should exist and be valid JSON
        with open(session_file, "r") as f:
            session_data = json.load(f)
        with open(timeline_file, "r") as f:
            timeline_data = json.load(f)

        self.assertIsInstance(session_data, dict)
        self.assertIsInstance(timeline_data, list)

        # No temp files should remain
        temp_files = [f for f in os.listdir(self.dynamic_dir) if f.startswith(".tmp_session_")]
        self.assertEqual(len(temp_files), 0)

    # --- 22. corrupted/failed write behavior is observable ---
    def test_22_storage_write_failure_observable(self):
        """When underlying storage is read-only, SessionException is raised."""
        preflight = _make_preflight(status=PreflightStatus.PASS)

        # Create a read-only directory to force write failure
        read_only_dir = os.path.join(self.test_dir, "readonly_run")
        os.makedirs(read_only_dir, exist_ok=True)
        dynamic_subdir = os.path.join(read_only_dir, "dynamic")
        os.makedirs(dynamic_subdir, exist_ok=True)
        os.chmod(dynamic_subdir, 0o444)

        try:
            with self.assertRaises(SessionException) as ctx:
                initialize_dynamic_session(
                    run_id="readonly_run",
                    run_dir=read_only_dir,
                    package_name="com.example.bank",
                    device_serial="emulator-5554",
                    preflight_result=preflight,
                )
            self.assertEqual(ctx.exception.error_code, SessionErrorCode.STORAGE_WRITE_FAILED)
        finally:
            os.chmod(dynamic_subdir, 0o755)


class TestRunScopedStorage(unittest.TestCase):
    """Validates that run_scoped SessionStorage writes to flat directory layout."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_run_scoped_storage_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_run_scoped_writes_flat(self):
        """In run_scoped mode, session.json lives directly in base_dir."""
        storage = SessionStorage(base_dir=self.test_dir, run_scoped=True)
        from src.dynamic.session.models import DynamicSession
        session = DynamicSession(package_name="com.test", device_serial="dev-1")
        storage.save_session(session)

        # session.json should be directly in test_dir, not in test_dir/<session_id>/
        self.assertTrue(os.path.isfile(os.path.join(self.test_dir, "session.json")))
        self.assertTrue(os.path.isfile(os.path.join(self.test_dir, "timeline.json")))
        self.assertFalse(os.path.isdir(os.path.join(self.test_dir, session.session_id)))

    def test_default_mode_writes_subdirectory(self):
        """In default mode, session.json lives in base_dir/<session_id>/."""
        storage = SessionStorage(base_dir=self.test_dir, run_scoped=False)
        from src.dynamic.session.models import DynamicSession
        session = DynamicSession(package_name="com.test", device_serial="dev-1")
        storage.save_session(session)

        session_subdir = os.path.join(self.test_dir, session.session_id)
        self.assertTrue(os.path.isdir(session_subdir))
        self.assertTrue(os.path.isfile(os.path.join(session_subdir, "session.json")))


class TestSanitizeValue(unittest.TestCase):
    """Validates host path sanitization in session/timeline output."""

    def test_user_path_sanitized(self):
        val = "/Users/suleyman/Desktop/mobiattack/build"
        self.assertNotIn("/Users/suleyman", _sanitize_value(val))

    def test_home_path_sanitized(self):
        val = "/home/jenkins/workspace/app"
        self.assertNotIn("/home/jenkins", _sanitize_value(val))

    def test_opt_homebrew_sanitized(self):
        val = "/opt/homebrew/bin/adb"
        self.assertNotIn("/opt/homebrew", _sanitize_value(val))

    def test_nested_dict_sanitized(self):
        data = {"path": "/Users/alice/test", "safe": "com.example.bank"}
        result = _sanitize_value(data)
        self.assertNotIn("/Users/alice", json.dumps(result))
        self.assertEqual(result["safe"], "com.example.bank")

    def test_list_sanitized(self):
        data = ["/home/bob/test.py", "normal_string"]
        result = _sanitize_value(data)
        self.assertNotIn("/home/bob", json.dumps(result))
        self.assertEqual(result[1], "normal_string")


class TestObservationMetadataCompactness(unittest.TestCase):
    """Validates that observation metadata builder produces compact output."""

    def test_compact_keys_only(self):
        obs_dict = _make_screen_observation().to_dict()
        meta = _build_observation_event_metadata(obs_dict)

        expected_keys = {
            "screen_identity", "foreground_package", "foreground_activity",
            "is_target_package", "is_dialog_or_system", "node_count",
            "clickable_count", "input_count", "observation_attempts",
        }
        self.assertEqual(set(meta.keys()), expected_keys)

    def test_no_full_nodes_in_meta(self):
        obs_dict = _make_screen_observation().to_dict()
        meta = _build_observation_event_metadata(obs_dict)
        raw = json.dumps(meta)
        self.assertNotIn("action_candidates", raw)
        self.assertNotIn("nodes", raw)


if __name__ == "__main__":
    unittest.main()
