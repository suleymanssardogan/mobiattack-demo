"""Comprehensive Unit and Integration Tests for Task 15 Play Store Acquisition."""

import os
import zipfile
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch
import xml.etree.ElementTree as ET

from src.url_classifier import classify_input_url
from src.play_store_acquirer import (
    PlayStoreAcquisitionError,
    acquire_play_store_app,
    acquire_play_store_package,
    open_play_store_on_device,
    verify_play_store_foreground,
    wait_for_device_installation,
)
from src.play_store_ui_automator import (
    attempt_play_store_ui_install,
    inspect_play_store_hierarchy,
    parse_node_bounds,
)



def _fake_pull(adb_bin, serial, remote_path, local_path, timeout_seconds=60.0):
    with zipfile.ZipFile(local_path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        zf.writestr("classes.dex", b"dex\n035\x00")

class TestPlayStoreAcquisitionV2(unittest.TestCase):
    """24+ Test Cases for Task 15 robust Play Store Acquisition."""

    # -------------------------------------------------------------
    # 1. URL Parsing & Validation
    # -------------------------------------------------------------

    def test_01_play_store_url_with_id_only(self):
        url = "https://play.google.com/store/apps/details?id=com.example.app"
        res = classify_input_url(url=url, platform="android")
        self.assertEqual(res["type"], "play_store")
        self.assertEqual(res["package_name"], "com.example.app")

    def test_02_play_store_url_with_id_and_hl(self):
        url = "https://play.google.com/store/apps/details?id=com.sec.android.app.popupcalculator&hl=en"
        res = classify_input_url(url=url, platform="android")
        self.assertEqual(res["type"], "play_store")
        self.assertEqual(res["package_name"], "com.sec.android.app.popupcalculator")

    def test_03_play_store_url_with_id_hl_and_gl(self):
        url = "https://play.google.com/store/apps/details?id=com.splendapps.torch&hl=tr&gl=TR"
        res = classify_input_url(url=url, platform="android")
        self.assertEqual(res["type"], "play_store")
        self.assertEqual(res["package_name"], "com.splendapps.torch")

    def test_04_malformed_package_id_rejected(self):
        url = "https://play.google.com/store/apps/details?id=invalid..package!"
        res = classify_input_url(url=url, platform="android")
        self.assertEqual(res["type"], "unsupported")

    # -------------------------------------------------------------
    # 2. Device Installation & Intent Resolution
    # -------------------------------------------------------------

    @patch("src.play_store_acquirer.query_package_paths")
    @patch("src.play_store_acquirer.open_play_store_on_device")
    @patch("src.play_store_acquirer.pull_device_apk")
    @patch("src.play_store_acquirer.validate_apk_structure")
    def test_05_already_installed_package_skips_store_open(
        self, mock_val, mock_pull, mock_open, mock_query
    ):
        mock_query.return_value = ["/data/app/~~xyz/com.example.app/base.apk"]
        mock_val.return_value = {"is_valid_apk": True}
        mock_pull.side_effect = _fake_pull

        with tempfile.TemporaryDirectory() as tmpdir:
            res = acquire_play_store_package(
                package_name="com.example.app",
                output_dir=tmpdir,
                serial="127.0.0.1:5555",
                adb_bin="adb",
            )
            # Store open should NOT be called if already installed
            mock_open.assert_not_called()
            self.assertTrue(res["initially_installed"])
            self.assertEqual(res["install_status"], "already_installed")
            self.assertEqual(res["play_store_open_status"], "skipped")

    @patch("src.play_store_acquirer.query_package_paths")
    @patch("src.play_store_acquirer.open_play_store_on_device")
    @patch("src.play_store_acquirer.wait_for_device_installation")
    @patch("src.play_store_acquirer.pull_device_apk")
    @patch("src.play_store_acquirer.validate_apk_structure")
    def test_06_non_installed_package_triggers_acquisition_flow(
        self, mock_val, mock_pull, mock_wait, mock_open, mock_query
    ):
        # 1st call: not installed.
        mock_query.return_value = []
        mock_open.return_value = {
            "success": True,
            "open_status": "success",
            "open_method": "market_uri",
            "play_store_foreground_verified": True,
            "url": "market://details?id=com.example.app",
        }
        mock_wait.return_value = ["/data/app/~~xyz/com.example.app/base.apk"]
        mock_val.return_value = {"is_valid_apk": True}
        mock_pull.side_effect = _fake_pull

        with tempfile.TemporaryDirectory() as tmpdir:
            res = acquire_play_store_package(
                package_name="com.example.app",
                output_dir=tmpdir,
                serial="127.0.0.1:5555",
                adb_bin="adb",
                install_mode="manual",
            )
            mock_open.assert_called_once()
            mock_wait.assert_called_once()
            self.assertFalse(res["initially_installed"])
            self.assertEqual(res["install_status"], "installed_via_manual")
            self.assertEqual(res["play_store_open_status"], "success")
            self.assertEqual(res["play_store_open_method"], "market_uri")

    @patch("src.play_store_acquirer.verify_play_store_foreground")
    @patch("subprocess.run")
    def test_07_market_uri_primary_open(self, mock_run, mock_foreground):
        mock_run.return_value = MagicMock(returncode=0, stdout="Starting: Intent...", stderr="")
        mock_foreground.return_value = True

        res = open_play_store_on_device(
            serial="127.0.0.1:5555",
            package_name="com.example.app",
            adb_bin="adb",
            verify_foreground=True,
            prefer_market_uri=True,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["open_method"], "market_uri")
        self.assertTrue(res["play_store_foreground_verified"])
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("market://details?id=com.example.app", called_cmd)

    @patch("src.play_store_acquirer.verify_play_store_foreground")
    @patch("subprocess.run")
    def test_08_https_fallback_when_market_fails(self, mock_run, mock_foreground):
        # 1st attempt: returncode 0 but foreground check fails. 2nd attempt: foreground check succeeds.
        mock_run.return_value = MagicMock(returncode=0, stdout="Starting: Intent...", stderr="")
        mock_foreground.side_effect = [False, True]

        res = open_play_store_on_device(
            serial="127.0.0.1:5555",
            package_name="com.example.app",
            adb_bin="adb",
            verify_foreground=True,
            prefer_market_uri=True,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["open_method"], "https_fallback")
        self.assertTrue(res["play_store_foreground_verified"])

    # -------------------------------------------------------------
    # 3. Manual Installation Mode
    # -------------------------------------------------------------

    @patch("src.play_store_acquirer.query_package_paths")
    def test_09_manual_mode_enters_waiting_state(self, mock_query):
        # Package detected on second poll
        mock_query.side_effect = [[], ["/data/app/base.apk"]]
        progress_events = []

        def callback(stage, state, message, data=None):
            progress_events.append((stage, state, message, data))

        res = wait_for_device_installation(
            serial="127.0.0.1:5555",
            package_name="com.example.app",
            timeout_seconds=5.0,
            poll_interval=0.01,
            adb_bin="adb",
            progress_callback=callback,
        )

        self.assertEqual(res, ["/data/app/base.apk"])
        # Verified waiting_for_installation emitted
        waiting_events = [e for e in progress_events if e[1] == "waiting_for_installation"]
        self.assertGreaterEqual(len(waiting_events), 1)
        self.assertEqual(waiting_events[0][3]["package_name"], "com.example.app")

    @patch("src.play_store_acquirer.query_package_paths")
    def test_10_installation_detected_during_polling(self, mock_query):
        mock_query.side_effect = [[], [], ["/data/app/com.app/base.apk"]]
        paths = wait_for_device_installation(
            serial="127.0.0.1:5555",
            package_name="com.app",
            timeout_seconds=5.0,
            poll_interval=0.01,
            adb_bin="adb",
        )
        self.assertEqual(paths, ["/data/app/com.app/base.apk"])

    @patch("src.play_store_acquirer.query_package_paths")
    def test_11_installation_timeout_raises_clear_error(self, mock_query):
        mock_query.return_value = []
        with self.assertRaises(PlayStoreAcquisitionError) as ctx:
            wait_for_device_installation(
                serial="127.0.0.1:5555",
                package_name="com.timeout.app",
                timeout_seconds=0.05,
                poll_interval=0.01,
                adb_bin="adb",
            )
        self.assertEqual(ctx.exception.reason_code, "installation_timeout")
        self.assertIn("timeout", str(ctx.exception).lower())

    # -------------------------------------------------------------
    # 4. Safety & Block Detection
    # -------------------------------------------------------------

    def test_12_sign_in_required_detection(self):
        xml = '''<hierarchy>
            <node package="com.android.vending" text="Sign in to your Google Account" bounds="[100,100][500,200]" />
        </hierarchy>'''
        root = ET.fromstring(xml)
        res = inspect_play_store_hierarchy(root, package_name="com.test.app")
        self.assertTrue(res.is_blocked)
        self.assertEqual(res.block_reason, "sign_in_required")

    def test_13_download_failure_detection(self):
        xml = '''<hierarchy>
            <node package="com.android.vending" text="Can't download com.test.app" bounds="[100,100][500,200]" />
        </hierarchy>'''
        root = ET.fromstring(xml)
        res = inspect_play_store_hierarchy(root, package_name="com.test.app")
        self.assertTrue(res.is_blocked)
        self.assertEqual(res.block_reason, "download_failed")

    def test_14_device_incompatible_detection(self):
        xml = '''<hierarchy>
            <node package="com.android.vending" text="Your device isn't compatible with this version." bounds="[100,100][500,200]" />
        </hierarchy>'''
        root = ET.fromstring(xml)
        res = inspect_play_store_hierarchy(root, package_name="com.sec.android.app.popupcalculator")
        self.assertTrue(res.is_blocked)
        self.assertEqual(res.block_reason, "device_not_compatible")

    @patch("src.play_store_acquirer.open_play_store_on_device")
    @patch("src.play_store_acquirer.query_package_paths")
    def test_15_play_store_not_available(self, mock_query, mock_open):
        mock_query.return_value = []
        mock_open.return_value = {
            "success": False,
            "open_status": "failed",
            "open_method": "failed",
            "play_store_foreground_verified": False,
            "error": "Google Play Store was not detected in foreground after market URI and HTTPS fallback",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(PlayStoreAcquisitionError) as ctx:
                acquire_play_store_package(
                    package_name="com.unknown.app",
                    output_dir=tmpdir,
                    serial="127.0.0.1:5555",
                    adb_bin="adb",
                )
            self.assertEqual(ctx.exception.reason_code, "play_store_not_available")

    # -------------------------------------------------------------
    # 5. UI Automation & Guardrails
    # -------------------------------------------------------------

    def test_16_ui_automation_detects_english_install_button(self):
        xml = '''<hierarchy>
            <node package="com.android.vending" text="About this app" bounds="[0,0][100,100]" />
            <node package="com.android.vending" text="Install" bounds="[500,300][700,380]" clickable="true" />
        </hierarchy>'''
        root = ET.fromstring(xml)
        res = inspect_play_store_hierarchy(root, package_name="com.example.app")
        self.assertFalse(res.is_blocked)
        self.assertEqual(res.install_button_bounds, (500, 300, 700, 380))
        self.assertEqual(res.install_button_label, "Install")

    def test_17_ui_automation_detects_turkish_yukle_button(self):
        xml = '''<hierarchy>
            <node package="com.android.vending" text="Bu uygulama hakkında" bounds="[0,0][100,100]" />
            <node package="com.android.vending" text="Yükle" bounds="[400,250][600,320]" clickable="true" />
        </hierarchy>'''
        root = ET.fromstring(xml)
        res = inspect_play_store_hierarchy(root, package_name="com.example.app")
        self.assertFalse(res.is_blocked)
        self.assertEqual(res.install_button_bounds, (400, 250, 600, 320))
        self.assertEqual(res.install_button_label, "Yükle")

    def test_18_ui_automation_disabled_by_default(self):
        # Default parameter in acquire_play_store_package must be 'manual'
        import inspect
        sig = inspect.signature(acquire_play_store_package)
        self.assertEqual(sig.parameters["install_mode"].default, "manual")

    def test_18b_ui_automation_never_clicks_update(self):
        # RULE: Do not use Update as Install. If Update is on screen, app is already installed!
        xml = '''<hierarchy>
            <node package="com.android.vending" text="About this app" bounds="[0,0][100,100]" />
            <node package="com.android.vending" text="Update" bounds="[500,300][700,380]" clickable="true" />
        </hierarchy>'''
        root = ET.fromstring(xml)
        res = inspect_play_store_hierarchy(root, package_name="com.example.app")
        self.assertTrue(res.is_installed)
        self.assertIsNone(res.install_button_bounds)

    def test_18c_ui_automation_never_clicks_guncelle(self):
        xml = '''<hierarchy>
            <node package="com.android.vending" text="Bu uygulama hakkında" bounds="[0,0][100,100]" />
            <node package="com.android.vending" text="Güncelle" bounds="[500,300][700,380]" clickable="true" />
        </hierarchy>'''
        root = ET.fromstring(xml)
        res = inspect_play_store_hierarchy(root, package_name="com.example.app")
        self.assertTrue(res.is_installed)
        self.assertIsNone(res.install_button_bounds)

    # -------------------------------------------------------------
    # 6. Pipeline Integration & Regressions
    # -------------------------------------------------------------

    @patch("src.play_store_acquirer.query_package_paths")
    @patch("src.play_store_acquirer.open_play_store_on_device")
    @patch("src.play_store_acquirer.wait_for_device_installation")
    @patch("src.play_store_acquirer.pull_device_apk")
    @patch("src.play_store_acquirer.validate_apk_structure")
    def test_19_successful_monolithic_acquisition_after_install(
        self, mock_val, mock_pull, mock_wait, mock_open, mock_query
    ):
        mock_query.return_value = []
        mock_open.return_value = {
            "success": True,
            "open_status": "success",
            "open_method": "market_uri",
            "play_store_foreground_verified": True,
            "url": "market://details?id=com.single.app",
        }
        mock_wait.return_value = ["/data/app/~~xyz/com.single.app/base.apk"]
        mock_val.return_value = {"is_valid_apk": True}
        mock_pull.side_effect = _fake_pull

        with tempfile.TemporaryDirectory() as tmpdir:
            res = acquire_play_store_package(
                package_name="com.single.app",
                output_dir=tmpdir,
                serial="127.0.0.1:5555",
                adb_bin="adb",
                install_mode="manual",
            )
            self.assertEqual(res["package_layout"], "monolithic")
            self.assertEqual(res["install_status"], "installed_via_manual")

    @patch("src.play_store_acquirer.query_package_paths")
    @patch("src.play_store_acquirer.open_play_store_on_device")
    @patch("src.play_store_acquirer.wait_for_device_installation")
    @patch("src.split_acquirer.acquire_split_package_set")
    def test_20_successful_split_acquisition_after_install(
        self, mock_split_acq, mock_wait, mock_open, mock_query
    ):
        mock_query.return_value = []
        mock_open.return_value = {
            "success": True,
            "open_status": "success",
            "open_method": "market_uri",
            "play_store_foreground_verified": True,
            "url": "market://details?id=com.split.app",
        }
        mock_wait.return_value = [
            "/data/app/~~xyz/com.split.app/base.apk",
            "/data/app/~~xyz/com.split.app/split_config.xxhdpi.apk",
        ]
        mock_split_acq.return_value = {
            "package_name": "com.split.app",
            "package_layout": "split",
            "split_count": 2,
            "components": [{"filename": "base.apk"}, {"filename": "split_config.xxhdpi.apk"}],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            res = acquire_play_store_package(
                package_name="com.split.app",
                output_dir=tmpdir,
                serial="127.0.0.1:5555",
                adb_bin="adb",
                install_mode="manual",
            )
            self.assertEqual(res["package_layout"], "split")
            self.assertEqual(res["split_count"], 2)
            self.assertEqual(res["install_status"], "installed_via_manual")

    def test_21_direct_apk_regression(self):
        url = "https://github.com/OWASP/MSTG-Android-Kotlin.apk"
        res = classify_input_url(url=url, platform="android")
        self.assertEqual(res["type"], "direct_apk")
        self.assertEqual(res["platform"], "android")

    @patch("src.play_store_acquirer.query_package_paths")
    @patch("src.play_store_acquirer.pull_device_apk")
    @patch("src.play_store_acquirer.validate_apk_structure")
    def test_22_existing_installed_play_store_regression(
        self, mock_val, mock_pull, mock_query
    ):
        mock_query.return_value = ["/data/app/~~xyz/com.installed.app/base.apk"]
        mock_val.return_value = {"is_valid_apk": True}
        mock_pull.side_effect = _fake_pull

        with tempfile.TemporaryDirectory() as tmpdir:
            res = acquire_play_store_package(
                package_name="com.installed.app",
                output_dir=tmpdir,
                serial="127.0.0.1:5555",
                adb_bin="adb",
            )
            self.assertTrue(res["initially_installed"])
            self.assertEqual(res["install_status"], "already_installed")
            self.assertEqual(res["play_store_open_status"], "skipped")


if __name__ == "__main__":
    unittest.main()
