"""Tests verifying ADB / Emulator is optional for Demo 3 Deterministic Static Analysis.

Covers the 6 required scenarios:
1. ADB unavailable -> static analysis still runs, report generated, launch skipped.
2. ADB available but no device -> static analysis still runs, launch skipped.
3. Device offline -> static analysis still runs, launch skipped.
4. Usable device available -> launch verification proceeds normally.
5. Real static analysis failure -> still reports FAILED/PARTIAL correctly.
6. Schema validation failure -> must not be hidden.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.android_runtime_launcher import (
    AndroidDeviceUnavailableError,
    check_device_availability,
    resolve_adb_executable,
    select_target_device,
)
from src.demo_orchestrator import DemoOrchestrationError, run_demo
from src.demo3.baseline_reporter import build_baseline_report
from src.demo3.schema_validator import SchemaValidationError, validate_baseline_report


class TestDemo3AdbOptional(unittest.TestCase):
    """Ensures deterministic static analysis never fails because of missing ADB or devices."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_root = Path(self.temp_dir.name)

        # Setup standard mock pipeline files
        self.apk_file = self.output_root / "downloads" / "test_app.apk"
        self.apk_file.parent.mkdir(parents=True, exist_ok=True)
        self.apk_file.write_bytes(b"PK\x03\x04synthetic_apk_content")

        self.raw_dir = self.output_root / "workspaces" / "test_app" / "raw_apk"
        self.apktool_dir = self.output_root / "workspaces" / "test_app" / "apktool_out"
        self.jadx_dir = self.output_root / "workspaces" / "test_app" / "jadx_out"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.apktool_dir.mkdir(parents=True, exist_ok=True)
        self.jadx_dir.mkdir(parents=True, exist_ok=True)
        (self.apktool_dir / "AndroidManifest.xml").write_text(
            '<manifest package="org.owasp.mastg"><application android:name=".App"/></manifest>',
            encoding="utf-8",
        )
        smali_file = self.apktool_dir / "smali" / "ApiClient.smali"
        smali_file.parent.mkdir(parents=True, exist_ok=True)
        smali_file.write_text(
            'const-string v0, "https://api.example.com/v1/auth"\nreturn-void',
            encoding="utf-8",
        )

        self.mock_acq_meta = {
            "source_type": "direct_apk",
            "filename": "test_app.apk",
            "saved_path": str(self.apk_file),
            "size_bytes": 100,
            "sha256": "1111222233334444555566667777888811112222333344445555666677778888",
            "validation": {"is_valid_apk": True},
        }

        self.mock_prep_meta = {
            "apk_path": str(self.apk_file),
            "workspace": str(self.output_root / "workspaces" / "test_app"),
            "raw_apk": {"output_dir": str(self.raw_dir), "file_count": 5},
            "apktool": {"status": "success", "output_dir": str(self.apktool_dir), "returncode": 0},
            "jadx": {"status": "success", "output_dir": str(self.jadx_dir), "returncode": 0},
        }

        self.mock_static_meta = {
            "app": {
                "package_name": "org.owasp.mastg",
                "launcher_activity": "org.owasp.mastg.MainActivity",
            },
            "permissions": ["android.permission.INTERNET"],
            "activities": ["org.owasp.mastg.MainActivity"],
            "structure": {"dex_count": 1, "is_multidex": False},
            "network_indicators": {"network_urls": ["https://api.example.com/v1/auth"]},
            "api_candidates": [
                {
                    "method": "POST",
                    "full_url": "https://api.example.com/v1/auth",
                    "status": "static_api_candidate",
                }
            ],
        }

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # --- TEST 1: ADB unavailable -> static analysis completes, launch skipped ---
    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.android_runtime_launcher.shutil.which", return_value=None)
    def test_01_adb_unavailable_skips_launch_and_completes_static_report(
        self, mock_which, mock_static, mock_prep, mock_acq
    ) -> None:
        mock_acq.return_value = self.mock_acq_meta
        mock_prep.return_value = self.mock_prep_meta
        mock_static.return_value = self.mock_static_meta

        tracker_events = []

        def tracker(stage, state, msg, data=None):
            tracker_events.append((stage, state, msg))

        result = run_demo(
            url="http://example.com/test_app.apk",
            output_root=self.output_root,
            adb_serial="127.0.0.1:5555",
            progress_callback=tracker,
        )

        # 1. Pipeline succeeds overall
        self.assertEqual(result.get("demo_status"), "completed")

        # 2. Runtime stage was skipped (not failed)
        rt = result.get("runtime", {})
        self.assertEqual(rt.get("status"), "skipped")
        self.assertEqual(rt.get("reason"), "adb_not_found")
        self.assertIn("No connected Android device", rt.get("message", ""))

        # 3. Static analysis and Demo 3 artifacts were assembled
        demo3_scan = result.get("demo3_scan")
        self.assertIsNotNone(demo3_scan)
        self.assertTrue(len(demo3_scan.get("candidates", [])) >= 1)

        # 4. Progress tracker emitted 'skipped' for runtime
        runtime_events = [e for e in tracker_events if e[0] == "runtime"]
        self.assertTrue(any(e[1] == "skipped" for e in runtime_events))
        self.assertFalse(any(e[1] == "failed" for e in runtime_events))

        # 5. baseline_report.json generated and validated
        baseline_file = self.output_root / "baseline_report.json"
        self.assertTrue(baseline_file.exists())
        with open(baseline_file, encoding="utf-8") as bf:
            baseline_data = json.load(bf)
        self.assertEqual(baseline_data.get("schema_version"), "1.0.0")
        self.assertEqual(baseline_data.get("scan", {}).get("status"), "completed")

    # --- TEST 2: ADB available but no device -> launch skipped, static report completes ---
    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.android_runtime_launcher.get_connected_devices", return_value=[])
    def test_02_no_connected_devices_skips_launch_and_completes_static_report(
        self, mock_get_devices, mock_static, mock_prep, mock_acq
    ) -> None:
        mock_acq.return_value = self.mock_acq_meta
        mock_prep.return_value = self.mock_prep_meta
        mock_static.return_value = self.mock_static_meta

        result = run_demo(
            url="http://example.com/test_app.apk",
            output_root=self.output_root,
            adb_serial=None,
        )

        self.assertEqual(result.get("demo_status"), "completed")
        rt = result.get("runtime", {})
        self.assertEqual(rt.get("status"), "skipped")
        self.assertEqual(rt.get("reason"), "no_devices")

    # --- TEST 3: Device offline / unauthorized -> launch skipped, static report completes ---
    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.android_runtime_launcher.get_connected_devices", return_value=["emulator-5556"])
    def test_03_device_offline_skips_launch_and_completes_static_report(
        self, mock_get_devices, mock_static, mock_prep, mock_acq
    ) -> None:
        mock_acq.return_value = self.mock_acq_meta
        mock_prep.return_value = self.mock_prep_meta
        mock_static.return_value = self.mock_static_meta

        # User specified 127.0.0.1:5555, but only emulator-5556 is connected
        result = run_demo(
            url="http://example.com/test_app.apk",
            output_root=self.output_root,
            adb_serial="127.0.0.1:5555",
        )

        self.assertEqual(result.get("demo_status"), "completed")
        rt = result.get("runtime", {})
        self.assertEqual(rt.get("status"), "skipped")
        self.assertEqual(rt.get("reason"), "device_not_ready")

    # --- TEST 4: Usable device available -> launches normally ---
    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context")
    @patch("src.demo_orchestrator.launch_android_app")
    def test_04_usable_device_available_launches_normally(
        self, mock_launch, mock_static, mock_prep, mock_acq
    ) -> None:
        mock_acq.return_value = self.mock_acq_meta
        mock_prep.return_value = self.mock_prep_meta
        mock_static.return_value = self.mock_static_meta
        mock_launch.return_value = {
            "adb": {"serial": "127.0.0.1:5555"},
            "install": {"success": True},
            "launch": {"success": True, "component": "org.owasp.mastg/org.owasp.mastg.MainActivity"},
            "runtime": {"pid": 12345, "foreground_verified": True},
            "status": "runtime_launch_verified",
        }

        result = run_demo(
            url="http://example.com/test.apk",
            output_root=self.output_root,
            adb_serial="127.0.0.1:5555",
        )

        mock_launch.assert_called_once()
        self.assertEqual(result.get("demo_status"), "completed")
        rt = result.get("runtime", {})
        self.assertEqual(rt.get("status"), "runtime_launch_verified")
        self.assertEqual(rt.get("runtime", {}).get("pid"), 12345)

    # --- TEST 5: Real static analysis failure -> still reports FAILED correctly ---
    @patch("src.demo_orchestrator.acquire_apk")
    @patch("src.demo_orchestrator.preprocess_apk")
    @patch("src.demo_orchestrator.build_static_context", side_effect=ValueError("Corrupt DEX bytecode"))
    def test_05_static_analysis_failure_propagates_failed_status(
        self, mock_static, mock_prep, mock_acq
    ) -> None:
        mock_acq.return_value = self.mock_acq_meta
        mock_prep.return_value = self.mock_prep_meta

        with self.assertRaises(DemoOrchestrationError) as ctx:
            run_demo(
                url="http://example.com/test_app.apk",
                output_root=self.output_root,
            )
        self.assertEqual(ctx.exception.stage, "static_analysis")
        self.assertIn("Corrupt DEX bytecode", str(ctx.exception))

    # --- TEST 6: Schema validation failure must NOT be hidden ---
    def test_06_schema_validation_failure_not_hidden(self) -> None:
        invalid_report = {
            "schema_version": "1.0.0",
            # missing required "scan", "artifact", "inventory", etc.
        }
        with self.assertRaises(SchemaValidationError):
            validate_baseline_report(invalid_report)

    # --- Helper check_device_availability unit test ---
    @patch("src.android_runtime_launcher.get_connected_devices")
    def test_07_check_device_availability_helper(self, mock_get_devices) -> None:
        mock_get_devices.return_value = ["emulator-5554"]
        avail, reason, serial = check_device_availability(adb_serial="emulator-5554")
        self.assertTrue(avail)
        self.assertEqual(reason, "ready")
        self.assertEqual(serial, "emulator-5554")

        mock_get_devices.return_value = []
        avail, reason, serial = check_device_availability(adb_serial="emulator-5554")
        self.assertFalse(avail)
        self.assertEqual(reason, "device_not_ready")
        self.assertIsNone(serial)
