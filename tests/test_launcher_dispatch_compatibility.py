"""Focused tests for canonical launcher dispatch and intent-filter mismatch classification."""

from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch
import pytest

from src.dynamic.preflight.app_launcher import launch_application
from src.dynamic.preflight.models import ErrorCode
from src.android_runtime_launcher import launch_activity, AndroidRuntimeError


def test_canonical_launcher_command_includes_action_and_category():
    with patch("src.dynamic.preflight.app_launcher.run_adb_cmd") as mock_cmd, \
         patch("src.dynamic.preflight.app_launcher.resolve_launchable_activity") as mock_resolve:
        mock_resolve.return_value = "com.test.MainActivity"
        mock_cmd.return_value = (0, "Status: ok\nActivity: com.test/.MainActivity", "")

        success, activity, err_code, err_msg = launch_application(
            adb_bin="/bin/adb",
            serial="emulator-5554",
            package_name="com.test",
        )
        assert success is True
        assert activity == "com.test.MainActivity"
        assert err_code is None

        # Verify command arguments include canonical launcher flags
        cmd_args = mock_cmd.call_args[0][1]
        assert cmd_args == [
            "shell", "am", "start", "-W",
            "-a", "android.intent.action.MAIN",
            "-c", "android.intent.category.LAUNCHER",
            "-n", "com.test/com.test.MainActivity",
        ]
        # Verified single execution (no duplicate launch attempt)
        assert mock_cmd.call_count == 1


def test_generic_non_launcher_activity_preserves_bare_semantics():
    with patch("src.dynamic.preflight.app_launcher.run_adb_cmd") as mock_cmd:
        mock_cmd.return_value = (0, "Status: ok\nActivity: com.test/.InternalActivity", "")

        success, activity, err_code, err_msg = launch_application(
            adb_bin="/bin/adb",
            serial="emulator-5554",
            package_name="com.test",
            activity_name="com.test.InternalActivity",
            is_launcher=False,
        )
        assert success is True
        assert activity == "com.test.InternalActivity"

        cmd_args = mock_cmd.call_args[0][1]
        assert cmd_args == [
            "shell", "am", "start", "-W",
            "-n", "com.test/com.test.InternalActivity",
        ]
        assert "-a" not in cmd_args
        assert "-c" not in cmd_args
        assert mock_cmd.call_count == 1


def test_failure_classification_detects_intent_filter_mismatch_directly():
    with patch("src.dynamic.preflight.app_launcher.run_adb_cmd") as mock_cmd, \
         patch("src.dynamic.preflight.app_launcher.resolve_launchable_activity") as mock_resolve:
        mock_resolve.return_value = "com.test.MainActivity"
        mock_cmd.return_value = (
            1,
            "Error: Intent does not match component intent filter",
            "Access blocked: ComponentInfo{com.test/com.test.MainActivity}",
        )

        success, activity, err_code, err_msg = launch_application(
            adb_bin="/bin/adb",
            serial="emulator-5554",
            package_name="com.test",
        )
        assert success is False
        assert err_code == ErrorCode.INTENT_FILTER_MISMATCH
        assert "Intent does not match component intent filter" in err_msg


def test_android_runtime_launcher_classifies_intent_filter_mismatch_from_logcat():
    with patch("subprocess.run") as mock_run:
        # 1st call: am start failing with Activity class does not exist
        # 2nd call: logcat showing intent does not match component's intent filter
        mock_run.side_effect = [
            subprocess.CompletedProcess(
                args=[], returncode=1,
                stdout="Error type 3\nError: Activity class {com.test/com.test.MainActivity} does not exist.\n",
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="W PackageManager: Intent does not match component's intent filter\nW PackageManager: Access blocked\n",
                stderr="",
            ),
        ]

        with pytest.raises(AndroidRuntimeError) as exc_info:
            launch_activity(
                adb_bin="/bin/adb",
                serial="emulator-5554",
                component="com.test/com.test.MainActivity",
                is_launcher=True,
            )

        assert exc_info.value.reason_code == "INTENT_FILTER_MISMATCH"
