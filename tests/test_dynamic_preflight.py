"""Unit and integration tests for Dynamic Preflight / Runtime Readiness module."""

import unittest
from unittest.mock import MagicMock, patch

from src.dynamic.preflight.models import (
    ApplicationInfo,
    DeviceInfo,
    ErrorCode,
    NetworkInfo,
    PreflightResult,
    PreflightStatus,
    RuntimeBaseline,
)
from src.dynamic.preflight.service import DynamicPreflightService, run_dynamic_preflight


class TestDynamicPreflightUnit(unittest.TestCase):

    def test_01_models_to_dict_matches_exact_normalized_schema(self):
        result = PreflightResult(
            stage="dynamic_preflight",
            device=DeviceInfo(
                connected=True,
                serial="emulator-5554",
                state="device",
                is_emulator=True,
                root_detected=False,
            ),
            application=ApplicationInfo(
                package_name="com.example.app",
                installed=True,
                launchable=True,
                main_activity="com.example.MainActivity",
                process_running=True,
                foreground=True,
                version_name="1.0",
                version_code=1,
                target_sdk=35,
            ),
            runtime=RuntimeBaseline(
                launch_success=True,
                immediate_crash=False,
                fatal_log_detected=False,
            ),
            network=NetworkInfo(
                internet_reachable=True,
                dns_configured=True,
            ),
            status=PreflightStatus.PASS,
            warnings=[],
            errors=[],
        )

        d = result.to_dict()
        self.assertEqual(d["stage"], "dynamic_preflight")
        self.assertEqual(d["status"], "PASS")
        self.assertTrue(d["device"]["connected"])
        self.assertEqual(d["device"]["serial"], "emulator-5554")
        self.assertTrue(d["device"]["is_emulator"])
        self.assertFalse(d["device"]["root_detected"])
        self.assertEqual(d["application"]["package_name"], "com.example.app")
        self.assertTrue(d["application"]["installed"])
        self.assertTrue(d["application"]["launchable"])
        self.assertEqual(d["application"]["version_code"], 1)
        self.assertEqual(d["application"]["target_sdk"], 35)
        self.assertTrue(d["runtime"]["launch_success"])
        self.assertFalse(d["runtime"]["immediate_crash"])
        self.assertTrue(d["network"]["internet_reachable"])

    @patch("src.dynamic.preflight.service.find_adb_binary", return_value=None)
    def test_02_adb_not_found_returns_fail(self, mock_find_adb):
        service = DynamicPreflightService(adb_bin="non_existent_adb")
        res = service.run_preflight("com.example.app")
        self.assertEqual(res.status, PreflightStatus.FAIL)
        self.assertEqual(len(res.errors), 1)
        self.assertEqual(res.errors[0]["code"], ErrorCode.ADB_NOT_FOUND.value)

    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    def test_03_device_not_found_returns_fail(self, mock_dev_check, _):
        mock_dev_check.return_value = (
            DeviceInfo(connected=False, state="not_found"),
            ErrorCode.DEVICE_NOT_FOUND,
            "No devices found",
        )
        service = DynamicPreflightService()
        res = service.run_preflight("com.example.app")
        self.assertEqual(res.status, PreflightStatus.FAIL)
        self.assertEqual(res.errors[0]["code"], ErrorCode.DEVICE_NOT_FOUND.value)

    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    def test_04_device_unauthorized_returns_fail(self, mock_dev_check, _):
        mock_dev_check.return_value = (
            DeviceInfo(connected=False, serial="device1", state="unauthorized"),
            ErrorCode.DEVICE_UNAUTHORIZED,
            "Device unauthorized",
        )
        service = DynamicPreflightService()
        res = service.run_preflight("com.example.app")
        self.assertEqual(res.status, PreflightStatus.FAIL)
        self.assertEqual(res.errors[0]["code"], ErrorCode.DEVICE_UNAUTHORIZED.value)

    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    def test_05_device_offline_returns_fail(self, mock_dev_check, _):
        mock_dev_check.return_value = (
            DeviceInfo(connected=False, serial="device1", state="offline"),
            ErrorCode.DEVICE_OFFLINE,
            "Device offline",
        )
        service = DynamicPreflightService()
        res = service.run_preflight("com.example.app")
        self.assertEqual(res.status, PreflightStatus.FAIL)
        self.assertEqual(res.errors[0]["code"], ErrorCode.DEVICE_OFFLINE.value)

    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    @patch("src.dynamic.preflight.service.inspect_package")
    def test_06_app_not_installed_no_apk_returns_fail(self, mock_pkg, mock_dev, _):
        mock_dev.return_value = (DeviceInfo(connected=True, serial="dev1", state="device"), None, None)
        mock_pkg.return_value = (ApplicationInfo(package_name="com.test"), ErrorCode.APP_NOT_INSTALLED, "Not installed")

        service = DynamicPreflightService()
        res = service.run_preflight("com.test", auto_install=False)
        self.assertEqual(res.status, PreflightStatus.FAIL)
        self.assertEqual(res.errors[0]["code"], ErrorCode.APP_NOT_INSTALLED.value)

    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    @patch("src.dynamic.preflight.service.inspect_package")
    @patch("src.dynamic.preflight.service.check_network_readiness")
    @patch("src.dynamic.preflight.service.launch_application")
    def test_07_launch_failed_returns_fail(self, mock_launch, mock_net, mock_pkg, mock_dev, _):
        mock_dev.return_value = (DeviceInfo(connected=True, serial="dev1", state="device"), None, None)
        mock_pkg.return_value = (ApplicationInfo(package_name="com.test", installed=True), None, None)
        mock_net.return_value = (NetworkInfo(internet_reachable=True), None, None)
        mock_launch.return_value = (False, None, ErrorCode.APP_LAUNCH_FAILED, "Permission denied")

        service = DynamicPreflightService()
        res = service.run_preflight("com.test")
        self.assertEqual(res.status, PreflightStatus.FAIL)
        self.assertEqual(res.errors[0]["code"], ErrorCode.APP_LAUNCH_FAILED.value)

    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    @patch("src.dynamic.preflight.service.inspect_package")
    @patch("src.dynamic.preflight.service.check_network_readiness")
    @patch("src.dynamic.preflight.service.launch_application")
    @patch("src.dynamic.preflight.service.check_runtime_health")
    def test_08_runtime_crash_returns_fail(self, mock_health, mock_launch, mock_net, mock_pkg, mock_dev, _):
        mock_dev.return_value = (DeviceInfo(connected=True, serial="dev1", state="device"), None, None)
        mock_pkg.return_value = (ApplicationInfo(package_name="com.test", installed=True), None, None)
        mock_net.return_value = (NetworkInfo(internet_reachable=True), None, None)
        mock_launch.return_value = (True, "com.test.MainActivity", None, None)
        mock_health.return_value = (
            RuntimeBaseline(immediate_crash=True, fatal_log_detected=True),
            False,
            ErrorCode.APP_CRASHED,
            "Fatal exception",
        )

        service = DynamicPreflightService()
        res = service.run_preflight("com.test")
        self.assertEqual(res.status, PreflightStatus.FAIL)
        self.assertEqual(res.errors[0]["code"], ErrorCode.APP_CRASHED.value)

    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    @patch("src.dynamic.preflight.service.inspect_package")
    @patch("src.dynamic.preflight.service.check_network_readiness")
    @patch("src.dynamic.preflight.service.launch_application")
    @patch("src.dynamic.preflight.service.check_runtime_health")
    def test_09_emulator_and_root_warn_status(self, mock_health, mock_launch, mock_net, mock_pkg, mock_dev, _):
        mock_dev.return_value = (
            DeviceInfo(
                connected=True,
                serial="emulator-5554",
                state="device",
                is_emulator=True,
                root_detected=True,
                root_signals=["su binary at /system/bin/su"],
            ),
            None,
            None,
        )
        mock_pkg.return_value = (ApplicationInfo(package_name="com.test", installed=True), None, None)
        mock_net.return_value = (NetworkInfo(internet_reachable=True), None, None)
        mock_launch.return_value = (True, "com.test.MainActivity", None, None)
        mock_health.return_value = (RuntimeBaseline(launch_success=True, pid=1234), True, None, None)

        service = DynamicPreflightService()
        res = service.run_preflight("com.test")
        self.assertEqual(res.status, PreflightStatus.WARN)
        self.assertTrue(any("Emulator" in w for w in res.warnings))
        self.assertTrue(any("Root" in w for w in res.warnings))
        self.assertEqual(len(res.errors), 0)

    @patch("src.dynamic.preflight.service.find_adb_binary", return_value="/mock/adb")
    @patch("src.dynamic.preflight.service.check_connected_device")
    @patch("src.dynamic.preflight.service.inspect_package")
    @patch("src.dynamic.preflight.service.check_network_readiness")
    @patch("src.dynamic.preflight.service.launch_application")
    @patch("src.dynamic.preflight.service.check_runtime_health")
    def test_10_clean_environment_pass_status(self, mock_health, mock_launch, mock_net, mock_pkg, mock_dev, _):
        mock_dev.return_value = (
            DeviceInfo(
                connected=True,
                serial="physical_device_1",
                state="device",
                is_emulator=False,
                root_detected=False,
            ),
            None,
            None,
        )
        mock_pkg.return_value = (
            ApplicationInfo(
                package_name="com.test",
                installed=True,
                version_name="2.1.0",
                version_code=42,
                target_sdk=35,
            ),
            None,
            None,
        )
        mock_net.return_value = (NetworkInfo(internet_reachable=True, dns_configured=True), None, None)
        mock_launch.return_value = (True, "com.test.MainActivity", None, None)
        mock_health.return_value = (RuntimeBaseline(launch_success=True, pid=9999), True, None, None)

        d = run_dynamic_preflight("com.test")
        self.assertEqual(d["status"], "PASS")
        self.assertEqual(d["warnings"], [])
        self.assertEqual(d["errors"], [])
        self.assertEqual(d["application"]["version_code"], 42)


if __name__ == "__main__":
    unittest.main()
