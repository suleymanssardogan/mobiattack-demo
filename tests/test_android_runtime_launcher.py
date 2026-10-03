"""Unit and integration tests for Android Runtime Launcher module."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.android_runtime_launcher import (
    AndroidRuntimeError,
    get_connected_devices,
    get_current_activity,
    install_apk,
    launch_activity,
    launch_android_app,
    normalize_component_name,
    parse_dumpsys_foreground_activity,
    query_process_pid,
    resolve_adb_executable,
    select_target_device,
)


class TestAndroidRuntimeLauncherUnit(unittest.TestCase):
    """Unit tests for ADB execution, device selection, installation, launch, and polling."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.dummy_apk = self.base_dir / "sample.apk"
        self.dummy_apk.write_bytes(b"PK_DUMMY_BYTES")

    def tearDown(self):
        self.temp_dir.cleanup()

    # --- 1. Executable & Device Discovery Tests ---

    @patch("shutil.which", return_value=None)
    def test_01_missing_adb_executable_raises_error(self, mock_which):
        with self.assertRaises(AndroidRuntimeError) as ctx:
            resolve_adb_executable()
        self.assertIn("adb' not found", str(ctx.exception))

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/adb")
    def test_02_no_connected_devices_raises_error(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["adb", "devices"],
            returncode=0,
            stdout="List of devices attached\n\n",
            stderr="",
        )
        with self.assertRaises(AndroidRuntimeError) as ctx:
            select_target_device()
        self.assertEqual(ctx.exception.reason, "no_devices")

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/adb")
    def test_03_offline_and_unauthorized_devices_ignored(self, mock_which, mock_run):
        stdout = (
            "List of devices attached\n"
            "emulator-5554\toffline\n"
            "emulator-5556\tunauthorized\n"
            "emulator-5558\tunknown\n"
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["adb", "devices"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )
        devices = get_connected_devices()
        self.assertEqual(devices, [])

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/adb")
    def test_04_single_usable_device_auto_selected(self, mock_which, mock_run):
        stdout = (
            "List of devices attached\n"
            "emulator-5554\tdevice\n"
            "emulator-5556\tunauthorized\n"
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["adb", "devices"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )
        with self.assertRaises(AndroidRuntimeError) as ctx:
            select_target_device()
        self.assertEqual(ctx.exception.reason, 'multiple_devices')
        selected = select_target_device(adb_serial='emulator-5554')
        self.assertEqual(selected, 'emulator-5554')

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/adb")
    def test_05_multiple_devices_require_explicit_serial(self, mock_which, mock_run):
        stdout = (
            "List of devices attached\n"
            "emulator-5554\tdevice\n"
            "127.0.0.1:16384\tdevice\n"
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["adb", "devices"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )
        with self.assertRaises(AndroidRuntimeError) as ctx:
            select_target_device()
        self.assertEqual(ctx.exception.reason, "multiple_devices")

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/adb")
    def test_06_explicit_valid_serial_selected(self, mock_which, mock_run):
        stdout = (
            "List of devices attached\n"
            "emulator-5554\tdevice\n"
            "127.0.0.1:16384\tdevice\n"
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["adb", "devices"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )
        selected = select_target_device(adb_serial="127.0.0.1:16384")
        self.assertEqual(selected, "127.0.0.1:16384")

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/adb")
    def test_07_explicit_invalid_serial_rejected(self, mock_which, mock_run):
        stdout = (
            "List of devices attached\n"
            "emulator-5554\tdevice\n"
        )
        mock_run.return_value = subprocess.CompletedProcess(
            args=["adb", "devices"],
            returncode=0,
            stdout=stdout,
            stderr="",
        )
        with self.assertRaises(AndroidRuntimeError) as ctx:
            select_target_device(adb_serial="nonexistent-serial")
        self.assertEqual(ctx.exception.reason, "device_not_ready")

    # --- 2. Input Validation & Component Normalization ---

    def test_08_missing_apk_path_rejected(self):
        with self.assertRaises(AndroidRuntimeError) as ctx:
            install_apk("/bin/adb", "emulator-5554", self.base_dir / "nonexistent.apk")
        self.assertIn("APK file not found", str(ctx.exception))

    def test_09_empty_package_name_rejected(self):
        with self.assertRaises(AndroidRuntimeError) as ctx:
            normalize_component_name("", "MainActivity")
        self.assertIn("Package name must be a non-empty string", str(ctx.exception))

    def test_10_empty_launcher_activity_rejected(self):
        with self.assertRaises(AndroidRuntimeError) as ctx:
            normalize_component_name("com.example", "")
        self.assertIn("Launcher activity must be a non-empty string", str(ctx.exception))

    def test_11_component_normalization(self):
        # Fully qualified
        self.assertEqual(
            normalize_component_name("com.example", "com.example.MainActivity"),
            "com.example/com.example.MainActivity",
        )
        # Leading dot shorthand
        self.assertEqual(
            normalize_component_name("com.example", ".MainActivity"),
            "com.example/com.example.MainActivity",
        )
        # Plain name without dot
        self.assertEqual(
            normalize_component_name("com.example", "MainActivity"),
            "com.example/com.example.MainActivity",
        )

    # --- 3. Installation Command & Failure Handling ---

    @patch("subprocess.run")
    def test_12_install_command_arguments_and_no_shell(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Success\n", stderr=""
        )
        res = install_apk("/bin/adb", "emulator-5554", self.dummy_apk, reinstall=False)
        self.assertTrue(res["success"])
        self.assertFalse(res["reinstall"])

        call_args = mock_run.call_args[0][0]
        self.assertEqual(call_args, ["/bin/adb", "-s", "emulator-5554", "install", str(self.dummy_apk)])
        self.assertNotIn("shell", mock_run.call_args[1])

    @patch("subprocess.run")
    def test_13_install_failure_aborts(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="Failure [INSTALL_FAILED_INVALID_APK]\n", stderr=""
        )
        with self.assertRaises(AndroidRuntimeError) as ctx:
            install_apk("/bin/adb", "emulator-5554", self.dummy_apk)
        self.assertIn("APK installation failed", str(ctx.exception))
        self.assertIn("INSTALL_FAILED_INVALID_APK", str(ctx.exception))

    @patch("subprocess.run")
    def test_14_install_already_exists_error_clarity(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="Failure [INSTALL_FAILED_ALREADY_EXISTS]\n", stderr=""
        )
        with self.assertRaises(AndroidRuntimeError) as ctx:
            install_apk("/bin/adb", "emulator-5554", self.dummy_apk, reinstall=False)
        self.assertIn("INSTALL_FAILED_ALREADY_EXISTS", str(ctx.exception))

    @patch("subprocess.run")
    def test_15_install_reinstall_flag_passes_dash_r(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Success\n", stderr=""
        )
        res = install_apk("/bin/adb", "emulator-5554", self.dummy_apk, reinstall=True)
        self.assertTrue(res["reinstall"])
        self.assertFalse(res["grant_permissions"])

        call_args = mock_run.call_args[0][0]
        self.assertEqual(call_args, ["/bin/adb", "-s", "emulator-5554", "install", "-r", str(self.dummy_apk)])

    @patch("subprocess.run")
    def test_15b_install_grant_permissions_flag_passes_dash_g(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Success\n", stderr=""
        )
        res = install_apk("/bin/adb", "emulator-5554", self.dummy_apk, grant_permissions=True)
        self.assertFalse(res["reinstall"])
        self.assertTrue(res["grant_permissions"])

        call_args = mock_run.call_args[0][0]
        self.assertEqual(call_args, ["/bin/adb", "-s", "emulator-5554", "install", "-g", str(self.dummy_apk)])

    @patch("subprocess.run")
    def test_15c_install_grant_permissions_and_reinstall(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Success\n", stderr=""
        )
        res = install_apk("/bin/adb", "emulator-5554", self.dummy_apk, reinstall=True, grant_permissions=True)
        self.assertTrue(res["reinstall"])
        self.assertTrue(res["grant_permissions"])

        call_args = mock_run.call_args[0][0]
        self.assertEqual(call_args, ["/bin/adb", "-s", "emulator-5554", "install", "-g", "-r", str(self.dummy_apk)])

    # --- 4. Launch Command & Error Handling ---

    @patch("subprocess.run")
    def test_16_launch_command_arguments(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Starting: Intent { cmp=com.example/.MainActivity }\n", stderr=""
        )
        res = launch_activity("/bin/adb", "emulator-5554", "com.example/com.example.MainActivity")
        self.assertTrue(res["success"])
        self.assertEqual(res["component"], "com.example/com.example.MainActivity")

        call_args = mock_run.call_args[0][0]
        self.assertEqual(
            call_args,
            ["/bin/adb", "-s", "emulator-5554", "shell", "am", "start", "-n", "com.example/com.example.MainActivity"],
        )

    @patch("subprocess.run")
    def test_17_launch_am_failure_handled(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="Error: Activity class {com.example/com.example.Fake} does not exist.\n",
            stderr="",
        )
        with self.assertRaises(AndroidRuntimeError) as ctx:
            launch_activity("/bin/adb", "emulator-5554", "com.example/com.example.Fake")
        self.assertIn("Failed to start activity", str(ctx.exception))
        self.assertIn("Error:", str(ctx.exception))

    # --- 5. Process Detection & Fallback ---

    @patch("subprocess.run")
    def test_18_pidof_process_detected(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="5060\n", stderr=""
        )
        pid = query_process_pid("/bin/adb", "emulator-5554", "com.example")
        self.assertEqual(pid, 5060)

    @patch("subprocess.run")
    def test_19_pidof_fallback_to_ps(self, mock_run):
        # First call (pidof) returns empty/failure, second call (ps -A) returns process list
        ps_output = (
            "USER       PID  PPID     VSZ    RSS WCHAN            ADDR S NAME\n"
            "root         1     0   22308   3124 0                   0 S init\n"
            "u0_a88    7821   450 1489240  89124 0                   0 S com.example.other\n"
            "u0_a89    7830   450 1489240  89124 0                   0 S com.example\n"
        )
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout=ps_output, stderr=""),
        ]
        pid = query_process_pid("/bin/adb", "emulator-5554", "com.example")
        # Must match exact "com.example", NOT "com.example.other"
        self.assertEqual(pid, 7830)

    # --- 6. Foreground Activity Parsing ---

    def test_20_dumpsys_activity_parsing_resumed_patterns(self):
        # Format 1: ResumedActivity with ActivityRecord
        sample1 = (
            "  ResumedActivity: ActivityRecord{42ab123 u0 sg.vantagepoint.mstgkotlin/.MainActivity t12}\n"
        )
        pkg1, act1 = parse_dumpsys_foreground_activity(sample1)
        self.assertEqual(pkg1, "sg.vantagepoint.mstgkotlin")
        self.assertEqual(act1, "sg.vantagepoint.mstgkotlin.MainActivity")

        # Format 2: mResumedActivity
        sample2 = (
            "  mResumedActivity: ActivityRecord{84bc345 u0 com.demo.app/com.demo.app.HomeActivity t15}\n"
        )
        pkg2, act2 = parse_dumpsys_foreground_activity(sample2)
        self.assertEqual(pkg2, "com.demo.app")
        self.assertEqual(act2, "com.demo.app.HomeActivity")

        # Format 3: mCurrentFocus window
        sample3 = "  mCurrentFocus=Window{778899 u0 org.sample.app/.view.LoginView}\n"
        pkg3, act3 = parse_dumpsys_foreground_activity(sample3)
        self.assertEqual(pkg3, "org.sample.app")
        self.assertEqual(act3, "org.sample.app.view.LoginView")

    def test_21_dumpsys_empty_returns_none(self):
        pkg, act = parse_dumpsys_foreground_activity("")
        self.assertIsNone(pkg)
        self.assertIsNone(act)

    # --- 7. End-to-End Orchestration & Status Semantics ---

    @patch("src.android_runtime_launcher.get_current_activity")
    @patch("src.android_runtime_launcher.query_process_pid")
    @patch("src.android_runtime_launcher.launch_activity")
    @patch("src.android_runtime_launcher.install_apk")
    @patch("src.android_runtime_launcher.select_target_device", return_value="emulator-5554")
    @patch("shutil.which", return_value="/bin/adb")
    def test_22_foreground_package_match_gives_runtime_launch_verified(
        self, mock_which, mock_dev, mock_inst, mock_launch, mock_pid, mock_act
    ):
        mock_inst.return_value = {"success": True, "reinstall": False}
        mock_launch.return_value = {"success": True, "component": "com.pkg/com.pkg.Main"}
        mock_pid.return_value = 1234
        mock_act.return_value = {"observed_package": "com.pkg", "observed_activity": "com.pkg.Main"}

        meta = launch_android_app(
            apk_path=self.dummy_apk,
            package_name="com.pkg",
            launcher_activity="com.pkg.Main",
        )

        self.assertEqual(meta["status"], "runtime_launch_verified")
        self.assertTrue(meta["runtime"]["foreground_verified"])
        self.assertEqual(meta["runtime"]["pid"], 1234)
        self.assertEqual(meta["runtime"]["observed_package"], "com.pkg")
        self.assertEqual(meta["runtime"]["observed_activity"], "com.pkg.Main")

    @patch("src.android_runtime_launcher.get_current_activity")
    @patch("src.android_runtime_launcher.query_process_pid")
    @patch("src.android_runtime_launcher.launch_activity")
    @patch("src.android_runtime_launcher.install_apk")
    @patch("src.android_runtime_launcher.select_target_device", return_value="emulator-5554")
    @patch("shutil.which", return_value="/bin/adb")
    def test_23_foreground_mismatch_gives_runtime_presence_verified(
        self, mock_which, mock_dev, mock_inst, mock_launch, mock_pid, mock_act
    ):
        mock_inst.return_value = {"success": True, "reinstall": False}
        mock_launch.return_value = {"success": True, "component": "com.pkg/com.pkg.Main"}
        mock_pid.return_value = 1234
        # Process is running, but foreground is launcher or another app
        mock_act.return_value = {
            "observed_package": "com.android.launcher3",
            "observed_activity": "com.android.launcher3.Launcher",
        }

        meta = launch_android_app(
            apk_path=self.dummy_apk,
            package_name="com.pkg",
            launcher_activity="com.pkg.Main",
            max_wait_seconds=0.1,
            poll_interval=0.05,
        )

        self.assertEqual(meta["status"], "runtime_presence_verified")
        self.assertFalse(meta["runtime"]["foreground_verified"])
        self.assertEqual(meta["runtime"]["pid"], 1234)

    @patch("src.android_runtime_launcher.query_process_pid", return_value=None)
    @patch("src.android_runtime_launcher.launch_activity")
    @patch("src.android_runtime_launcher.install_apk")
    @patch("src.android_runtime_launcher.select_target_device", return_value="emulator-5554")
    @patch("shutil.which", return_value="/bin/adb")
    def test_24_process_never_starts_raises_error(
        self, mock_which, mock_dev, mock_inst, mock_launch, mock_pid
    ):
        mock_inst.return_value = {"success": True, "reinstall": False}
        mock_launch.return_value = {"success": True, "component": "com.pkg/com.pkg.Main"}

        with self.assertRaises(AndroidRuntimeError) as ctx:
            launch_android_app(
                apk_path=self.dummy_apk,
                package_name="com.pkg",
                launcher_activity="com.pkg.Main",
                max_wait_seconds=0.1,
                poll_interval=0.05,
            )
        self.assertIn("did not start on device", str(ctx.exception))

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/adb")
    def test_25_get_current_activity_helper(self, mock_which, mock_run):
        dumpsys_out = "ResumedActivity: ActivityRecord{123 u0 com.app/.SecondActivity}\n"
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=dumpsys_out, stderr=""
        )
        res = get_current_activity(adb_serial="emulator-5554")
        self.assertEqual(res["observed_package"], "com.app")
        self.assertEqual(res["observed_activity"], "com.app.SecondActivity")


class TestRealMumuIntegration(unittest.TestCase):
    """Integration test against actual connected ADB device (e.g. MuMu Player) if running."""

    def test_real_device_install_and_launch(self):
        adb_bin = shutil.which("adb")
        if not adb_bin:
            self.skipTest("ADB binary not found on system PATH")

        try:
            devices = get_connected_devices(adb_bin)
        except AndroidRuntimeError:
            self.skipTest("ADB server not running or device check failed")
        if not devices:
            self.skipTest("No ADB device connected in 'device' state (e.g. MuMu emulator is closed)")

        repo_root = Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.parent / "MSTG-Android-Kotlin.apk").is_file() else Path(__file__).resolve().parent.parent.parent
        owasp_apk = repo_root / "MSTG-Android-Kotlin.apk"
        if not owasp_apk.is_file():
            self.skipTest(f"OWASP APK not found at {owasp_apk}")

        # If a live device is present, run real launch with reinstall=True
        target_serial = devices[0]
        meta = launch_android_app(
            apk_path=owasp_apk,
            package_name="sg.vantagepoint.mstgkotlin",
            launcher_activity="sg.vantagepoint.mstgkotlin.MainActivity",
            adb_serial=target_serial,
            reinstall=True,
            max_wait_seconds=10.0,
        )

        self.assertIn(meta["status"], ("runtime_launch_verified", "runtime_presence_verified"))
        self.assertTrue(meta["install"]["success"])
        self.assertTrue(meta["launch"]["success"])
        self.assertTrue(meta["runtime"]["process_running"])
        self.assertIsInstance(meta["runtime"]["pid"], int)


if __name__ == "__main__":
    unittest.main()
