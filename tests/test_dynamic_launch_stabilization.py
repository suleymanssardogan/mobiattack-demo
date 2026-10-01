"""Tests for Dynamic Preflight Integration & Launch Stabilization Loop (Week 1 — Day 4 Task 4.1)."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.dynamic.preflight.app_launcher import launch_application
from src.dynamic.preflight.models import (
    ApplicationInfo,
    DeviceInfo,
    ErrorCode,
    NetworkInfo,
    PreflightResult,
    PreflightStatus,
    RuntimeBaseline,
)
from src.dynamic.preflight.runtime_health import (
    DEFAULT_LAUNCH_DEADLINE_SECONDS,
    DEFAULT_LAUNCH_MAX_ATTEMPTS,
    DEFAULT_LAUNCH_POLL_INTERVAL,
    check_runtime_health,
)
from src.dynamic.preflight.service import (
    DynamicPreflightService,
    run_dynamic_preflight,
    sanitize_preflight_dict,
    save_preflight_result,
)


class TestDynamicLaunchStabilization(unittest.TestCase):
    """Verifies condition-based bounded polling loop and preflight stabilization."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Slow launch scenario: PID appears late, then foreground verified -> PASS
    @patch("src.dynamic.preflight.runtime_health._scan_recent_fatal_logs", return_value=(False, []))
    @patch("src.dynamic.preflight.runtime_health._check_foreground_status")
    @patch("src.dynamic.preflight.runtime_health._find_process_pid")
    def test_01_slow_launch_succeeds_adaptive_polling(
        self, mock_pid, mock_fg, mock_logs
    ):
        # Attempt 1: pid=None
        # Attempt 2: pid=1234, fg=False
        # Attempt 3: pid=1234, fg=True
        mock_pid.side_effect = [None, 1234, 1234]
        mock_fg.side_effect = [False, True]

        sleeper_mock = MagicMock()
        baseline, is_fg, err_code, err_msg = check_runtime_health(
            adb_bin="/mock/adb",
            serial="emulator-5554",
            package_name="com.example.app",
            max_attempts=5,
            poll_interval=0.1,
            deadline_seconds=5.0,
            sleeper=sleeper_mock,
        )

        self.assertTrue(baseline.launch_success)
        self.assertFalse(baseline.immediate_crash)
        self.assertFalse(baseline.fatal_log_detected)
        self.assertEqual(baseline.pid, 1234)
        self.assertTrue(is_fg)
        self.assertIsNone(err_code)
        self.assertEqual(baseline.ready_after_attempt, 3)
        self.assertEqual(sleeper_mock.call_count, 2)

    # 2. Delayed foreground: PID immediate, foreground late -> PASS
    @patch("src.dynamic.preflight.runtime_health._scan_recent_fatal_logs", return_value=(False, []))
    @patch("src.dynamic.preflight.runtime_health._check_foreground_status")
    @patch("src.dynamic.preflight.runtime_health._find_process_pid", return_value=5678)
    def test_02_delayed_foreground_succeeds(
        self, mock_pid, mock_fg, mock_logs
    ):
        # Attempt 1: fg=False, Attempt 2: fg=True
        mock_fg.side_effect = [False, True]

        sleeper_mock = MagicMock()
        baseline, is_fg, err_code, err_msg = check_runtime_health(
            adb_bin="/mock/adb",
            serial="emulator-5554",
            package_name="com.example.app",
            max_attempts=5,
            poll_interval=0.1,
            deadline_seconds=5.0,
            sleeper=sleeper_mock,
        )

        self.assertTrue(baseline.launch_success)
        self.assertTrue(is_fg)
        self.assertEqual(baseline.pid, 5678)
        self.assertEqual(baseline.ready_after_attempt, 2)
        self.assertIsNone(err_code)

    # 3. Never opens: PID never appears -> bounded fail with APP_LAUNCH_FAILED
    @patch("src.dynamic.preflight.runtime_health._scan_recent_fatal_logs", return_value=(False, []))
    @patch("src.dynamic.preflight.runtime_health._find_process_pid", return_value=None)
    def test_03_never_opens_fails_boundedly(
        self, mock_pid, mock_logs
    ):
        sleeper_mock = MagicMock()
        baseline, is_fg, err_code, err_msg = check_runtime_health(
            adb_bin="/mock/adb",
            serial="emulator-5554",
            package_name="com.example.app",
            max_attempts=4,
            poll_interval=0.1,
            deadline_seconds=5.0,
            sleeper=sleeper_mock,
        )

        self.assertFalse(baseline.launch_success)
        self.assertFalse(is_fg)
        self.assertEqual(err_code, ErrorCode.APP_LAUNCH_FAILED)
        self.assertIn("did not start within", err_msg)
        self.assertEqual(baseline.launch_attempts, 4)
        # Should have slept 3 times between 4 attempts
        self.assertEqual(sleeper_mock.call_count, 3)

    # 4. Immediate crash: Fatal exception in logcat exits early without waiting deadline
    @patch("src.dynamic.preflight.runtime_health._find_process_pid", return_value=9999)
    @patch("src.dynamic.preflight.runtime_health._scan_recent_fatal_logs")
    def test_04_immediate_crash_exits_early_without_waiting_deadline(
        self, mock_logs, mock_pid
    ):
        mock_logs.return_value = (True, ["FATAL EXCEPTION: main NullPointerException"])

        sleeper_mock = MagicMock()
        baseline, is_fg, err_code, err_msg = check_runtime_health(
            adb_bin="/mock/adb",
            serial="emulator-5554",
            package_name="com.example.app",
            max_attempts=10,
            poll_interval=0.1,
            deadline_seconds=10.0,
            sleeper=sleeper_mock,
        )

        self.assertTrue(baseline.immediate_crash)
        self.assertTrue(baseline.fatal_log_detected)
        self.assertEqual(err_code, ErrorCode.APP_CRASHED)
        self.assertIn("Fatal exception or crash detected", err_msg)
        self.assertEqual(baseline.launch_attempts, 1)
        # Did not sleep because it terminated immediately on attempt 1!
        self.assertEqual(sleeper_mock.call_count, 0)

    # 5. Process dies after launch: PID present at attempt 1, disappears at attempt 2
    @patch("src.dynamic.preflight.runtime_health._scan_recent_fatal_logs", return_value=(False, []))
    @patch("src.dynamic.preflight.runtime_health._check_foreground_status", return_value=False)
    @patch("src.dynamic.preflight.runtime_health._find_process_pid")
    def test_05_process_dies_after_pid_exits_early(
        self, mock_pid, mock_fg, mock_logs
    ):
        # Attempt 1: PID exists, Attempt 2: PID is gone
        mock_pid.side_effect = [3333, None]

        sleeper_mock = MagicMock()
        baseline, is_fg, err_code, err_msg = check_runtime_health(
            adb_bin="/mock/adb",
            serial="emulator-5554",
            package_name="com.example.app",
            max_attempts=6,
            poll_interval=0.1,
            deadline_seconds=5.0,
            sleeper=sleeper_mock,
        )

        self.assertTrue(baseline.immediate_crash)
        self.assertFalse(baseline.launch_success)
        self.assertEqual(err_code, ErrorCode.APP_CRASHED)
        self.assertIn("died immediately after launch", err_msg)
        self.assertEqual(baseline.launch_attempts, 2)

    # 6. Maximum attempts strictly enforced
    @patch("src.dynamic.preflight.runtime_health._scan_recent_fatal_logs", return_value=(False, []))
    @patch("src.dynamic.preflight.runtime_health._find_process_pid", return_value=None)
    def test_06_maximum_attempts_enforced(
        self, mock_pid, mock_logs
    ):
        sleeper_mock = MagicMock()
        baseline, _, err_code, _ = check_runtime_health(
            adb_bin="/mock/adb",
            serial="emulator-5554",
            package_name="com.example.app",
            max_attempts=3,
            poll_interval=0.01,
            deadline_seconds=10.0,
            sleeper=sleeper_mock,
        )

        self.assertEqual(baseline.launch_attempts, 3)
        self.assertEqual(err_code, ErrorCode.APP_LAUNCH_FAILED)

    # 7. Controlled single relaunch triggered if not foreground by attempt 2
    @patch("src.dynamic.preflight.runtime_health._scan_recent_fatal_logs", return_value=(False, []))
    @patch("src.dynamic.preflight.runtime_health._check_foreground_status", return_value=False)
    @patch("src.dynamic.preflight.runtime_health._find_process_pid", return_value=1234)
    def test_07_controlled_single_relaunch_triggered(
        self, mock_pid, mock_fg, mock_logs
    ):
        relaunch_mock = MagicMock()
        sleeper_mock = MagicMock()
        baseline, is_fg, err_code, _ = check_runtime_health(
            adb_bin="/mock/adb",
            serial="emulator-5554",
            package_name="com.example.app",
            max_attempts=4,
            poll_interval=0.01,
            deadline_seconds=5.0,
            sleeper=sleeper_mock,
            relaunch_fn=relaunch_mock,
        )

        # Relaunch called exactly once
        self.assertEqual(relaunch_mock.call_count, 1)
        # Finished after 4 attempts with presence verified
        self.assertEqual(baseline.launch_attempts, 4)
        self.assertTrue(baseline.launch_success)
        self.assertFalse(is_fg)
        self.assertIsNone(err_code)

    # 8. Monotonic deadline strictly enforced
    @patch("src.dynamic.preflight.runtime_health._scan_recent_fatal_logs", return_value=(False, []))
    @patch("src.dynamic.preflight.runtime_health._find_process_pid", return_value=None)
    def test_08_deadline_seconds_enforced(
        self, mock_pid, mock_logs
    ):
        # Fake clock advancing by 4 seconds per check
        clock_values = [0.0, 1.0, 5.5, 9.0]
        clock_mock = MagicMock(side_effect=clock_values)

        sleeper_mock = MagicMock()
        baseline, _, err_code, _ = check_runtime_health(
            adb_bin="/mock/adb",
            serial="emulator-5554",
            package_name="com.example.app",
            max_attempts=20,
            deadline_seconds=5.0,
            clock=clock_mock,
            sleeper=sleeper_mock,
        )

        # Loop must stop because clock exceeded 5.0 seconds
        self.assertLess(baseline.launch_attempts, 5)
        self.assertEqual(err_code, ErrorCode.APP_LAUNCH_FAILED)

    # 9. Presence-only verified when foreground cannot be confirmed
    @patch("src.dynamic.preflight.runtime_health._scan_recent_fatal_logs", return_value=(False, []))
    @patch("src.dynamic.preflight.runtime_health._check_foreground_status", return_value=False)
    @patch("src.dynamic.preflight.runtime_health._find_process_pid", return_value=4321)
    def test_09_presence_only_verified_when_foreground_missing(
        self, mock_pid, mock_fg, mock_logs
    ):
        sleeper_mock = MagicMock()
        baseline, is_fg, err_code, _ = check_runtime_health(
            adb_bin="/mock/adb",
            serial="emulator-5554",
            package_name="com.example.app",
            max_attempts=3,
            poll_interval=0.01,
            deadline_seconds=2.0,
            sleeper=sleeper_mock,
        )

        self.assertTrue(baseline.launch_success)
        self.assertFalse(is_fg)
        self.assertIsNone(err_code)
        self.assertEqual(baseline.pid, 4321)

    # 10. Monkey fallback in launch_application when main activity cannot be resolved
    @patch("src.dynamic.preflight.app_launcher.resolve_launchable_activity", return_value=None)
    @patch("src.dynamic.preflight.app_launcher.run_adb_cmd")
    def test_10_monkey_fallback_when_activity_not_resolved(
        self, mock_run, mock_resolve
    ):
        mock_run.return_value = (0, "Events injected: 1", "")

        ok, act, err_code, err_msg = launch_application(
            adb_bin="/mock/adb",
            serial="dev1",
            package_name="com.example.app",
        )

        self.assertTrue(ok)
        self.assertIsNone(err_code)
        self.assertIsNone(act)

    # 11. Preflight result atomic persistence to demo_runs/<run_id>/dynamic/preflight_result.json
    def test_11_preflight_artifact_atomic_persistence(self):
        pref = PreflightResult(
            stage="dynamic_preflight",
            device=DeviceInfo(connected=True, serial="test-serial", state="device"),
            application=ApplicationInfo(package_name="com.test.app", installed=True, launchable=True),
            runtime=RuntimeBaseline(launch_success=True, pid=1234, launch_attempts=3, ready_after_attempt=3),
            network=NetworkInfo(internet_reachable=True),
            status=PreflightStatus.PASS,
        )

        saved_path = save_preflight_result(pref, self.run_dir)
        self.assertTrue(saved_path.is_file())
        self.assertEqual(saved_path.name, "preflight_result.json")
        self.assertEqual(saved_path.parent.name, "dynamic")

        with open(saved_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["stage"], "dynamic_preflight")
        self.assertEqual(data["status"], "PASS")
        self.assertEqual(data["runtime"]["launch_attempts"], 3)
        self.assertEqual(data["runtime"]["ready_after_attempt"], 3)

    # 12. Preflight artifact sanitization removes host paths
    def test_12_preflight_artifact_sanitization(self):
        raw_dict = {
            "host_tool": "/opt/homebrew/bin/adb",
            "host_workspace": "/Users/suleymansardogan/Desktop/mobiattack-v2/workspaces/app",
            "device_apk": "/data/app/com.test-1/base.apk",
            "warnings": [
                "Tool at /Users/suleymansardogan/tool executed",
                "Connected to device",
            ],
        }

        sanitized = sanitize_preflight_dict(raw_dict)
        self.assertEqual(sanitized["host_tool"], "adb")
        self.assertEqual(sanitized["host_workspace"], "<host_path>")
        # Device path must be preserved!
        self.assertEqual(sanitized["device_apk"], "/data/app/com.test-1/base.apk")
        self.assertNotIn("suleymansardogan", sanitized["warnings"][0])
        self.assertEqual(sanitized["warnings"][1], "Connected to device")

    # 13. Product State Integrity: preflight PASS does NOT mark dynamic_analysis as completed
    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    @patch("src.dynamic.preflight.service.inspect_package")
    @patch("src.dynamic.preflight.service.check_network_readiness")
    @patch("src.dynamic.preflight.service.launch_application")
    @patch("src.dynamic.preflight.service.check_runtime_health")
    def test_13_preflight_pass_does_not_mark_dynamic_analysis_completed(
        self, mock_health, mock_launch, mock_net, mock_pkg, mock_dev, _
    ):
        mock_dev.return_value = (DeviceInfo(connected=True, serial="dev1", state="device"), None, None)
        mock_pkg.return_value = (ApplicationInfo(package_name="com.test", installed=True), None, None)
        mock_net.return_value = (NetworkInfo(internet_reachable=True), None, None)
        mock_launch.return_value = (True, "com.test.MainActivity", None, None)
        mock_health.return_value = (
            RuntimeBaseline(launch_success=True, pid=9999, launch_attempts=1, ready_after_attempt=1),
            True,
            None,
            None,
        )

        service = DynamicPreflightService()
        result = service.run_preflight("com.test")
        self.assertEqual(result.status, PreflightStatus.PASS)

        # Dynamic analysis report must NOT be created by preflight!
        dynamic_report = self.run_dir / "dynamic_analysis_report.json"
        self.assertFalse(dynamic_report.exists())

        # Save preflight result
        saved_file = save_preflight_result(result, self.run_dir)
        self.assertTrue(saved_file.exists())
        self.assertFalse(dynamic_report.exists())

    # 14. Preflight failure still persists preflight_result.json
    def test_14_preflight_failure_persists_artifact(self):
        pref = PreflightResult(
            stage="dynamic_preflight",
            device=DeviceInfo(connected=False, state="not_found"),
            application=ApplicationInfo(package_name="com.crash.app"),
            runtime=RuntimeBaseline(immediate_crash=True, fatal_log_detected=True),
            status=PreflightStatus.FAIL,
            errors=[{"code": "APP_CRASHED", "message": "App crashed on launch"}],
        )

        saved = save_preflight_result(pref, self.run_dir)
        self.assertTrue(saved.is_file())

        with open(saved, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["status"], "FAIL")
        self.assertEqual(data["errors"][0]["code"], "APP_CRASHED")


    # 15. No device -> Preflight FAIL with DEVICE_NOT_FOUND
    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    def test_15_no_device_returns_preflight_fail_with_device_not_found(
        self, mock_dev, _
    ):
        mock_dev.return_value = (
            DeviceInfo(connected=False, state="not_found"),
            ErrorCode.DEVICE_NOT_FOUND,
            "No devices found",
        )
        service = DynamicPreflightService()
        result = service.run_preflight("com.example.app")
        self.assertEqual(result.status, PreflightStatus.FAIL)
        self.assertEqual(result.errors[0]["code"], ErrorCode.DEVICE_NOT_FOUND.value)

    # 16. Unauthorized device -> Preflight FAIL with DEVICE_UNAUTHORIZED
    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    def test_16_unauthorized_device_returns_preflight_fail_with_device_unauthorized(
        self, mock_dev, _
    ):
        mock_dev.return_value = (
            DeviceInfo(connected=False, serial="dev1", state="unauthorized"),
            ErrorCode.DEVICE_UNAUTHORIZED,
            "Device unauthorized",
        )
        service = DynamicPreflightService()
        result = service.run_preflight("com.example.app")
        self.assertEqual(result.status, PreflightStatus.FAIL)
        self.assertEqual(result.errors[0]["code"], ErrorCode.DEVICE_UNAUTHORIZED.value)

    # 17. Offline device -> Preflight FAIL with DEVICE_OFFLINE
    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    def test_17_offline_device_returns_preflight_fail_with_device_offline(
        self, mock_dev, _
    ):
        mock_dev.return_value = (
            DeviceInfo(connected=False, serial="dev1", state="offline"),
            ErrorCode.DEVICE_OFFLINE,
            "Device offline",
        )
        service = DynamicPreflightService()
        result = service.run_preflight("com.example.app")
        self.assertEqual(result.status, PreflightStatus.FAIL)
        self.assertEqual(result.errors[0]["code"], ErrorCode.DEVICE_OFFLINE.value)

    # 18. Network probe fails but execution-ready app -> WARN (not FAIL)
    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    @patch("src.dynamic.preflight.service.inspect_package")
    @patch("src.dynamic.preflight.service.check_network_readiness")
    @patch("src.dynamic.preflight.service.launch_application")
    @patch("src.dynamic.preflight.service.check_runtime_health")
    def test_18_network_unavailable_results_in_warn_not_fail(
        self, mock_health, mock_launch, mock_net, mock_pkg, mock_dev, _
    ):
        mock_dev.return_value = (DeviceInfo(connected=True, serial="dev1", state="device"), None, None)
        mock_pkg.return_value = (ApplicationInfo(package_name="com.test", installed=True), None, None)
        mock_net.return_value = (
            NetworkInfo(internet_reachable=False, dns_configured=False),
            ErrorCode.NETWORK_UNAVAILABLE,
            "No route to host",
        )
        mock_launch.return_value = (True, "com.test.MainActivity", None, None)
        mock_health.return_value = (RuntimeBaseline(launch_success=True, pid=1234), True, None, None)

        service = DynamicPreflightService()
        result = service.run_preflight("com.test")
        # Exploration can begin, but capability is limited -> WARN
        self.assertEqual(result.status, PreflightStatus.WARN)
        self.assertEqual(len(result.errors), 0)
        self.assertTrue(any("Network unavailable" in w for w in result.warnings))

    # 19. PID exists but foreground unconfirmed -> WARN (not FAIL)
    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    @patch("src.dynamic.preflight.service.inspect_package")
    @patch("src.dynamic.preflight.service.check_network_readiness")
    @patch("src.dynamic.preflight.service.launch_application")
    @patch("src.dynamic.preflight.service.check_runtime_health")
    def test_19_pid_exists_foreground_unconfirmed_results_in_warn(
        self, mock_health, mock_launch, mock_net, mock_pkg, mock_dev, _
    ):
        mock_dev.return_value = (DeviceInfo(connected=True, serial="dev1", state="device"), None, None)
        mock_pkg.return_value = (ApplicationInfo(package_name="com.test", installed=True), None, None)
        mock_net.return_value = (NetworkInfo(internet_reachable=True, dns_configured=True), None, None)
        mock_launch.return_value = (True, "com.test.MainActivity", None, None)
        mock_health.return_value = (RuntimeBaseline(launch_success=True, pid=1234), False, None, None)

        service = DynamicPreflightService()
        result = service.run_preflight("com.test")
        self.assertEqual(result.status, PreflightStatus.WARN)
        self.assertEqual(len(result.errors), 0)
        self.assertTrue(any("foreground window could not be verified" in w for w in result.warnings))


if __name__ == "__main__":
    unittest.main()
