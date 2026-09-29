"""Tests for Play Store Device Acquisition Module."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

from src.play_store_acquirer import (
    PlayStoreAcquisitionError,
    acquire_play_store_app,
    detect_package_layout,
    open_play_store_on_device,
    parse_pm_path_output,
    pull_device_apk,
    query_package_paths,
)


class TestPlayStoreAcquirer(unittest.TestCase):
    def test_parse_pm_path_output(self):
        output = (
            "package:/data/app/~~a/com.test.app-b/base.apk\n"
            "package:/data/app/~~a/com.test.app-b/split_config.arm64_v8a.apk\n"
        )
        paths = parse_pm_path_output(output)
        self.assertEqual(
            paths,
            [
                "/data/app/~~a/com.test.app-b/base.apk",
                "/data/app/~~a/com.test.app-b/split_config.arm64_v8a.apk",
            ],
        )

    def test_parse_pm_path_empty_output(self):
        self.assertEqual(parse_pm_path_output(""), [])
        self.assertEqual(parse_pm_path_output("   \n\n"), [])

    def test_detect_package_layout(self):
        self.assertEqual(detect_package_layout([]), "none")
        self.assertEqual(
            detect_package_layout(["/data/app/base.apk"]),
            "monolithic",
        )
        self.assertEqual(
            detect_package_layout(["/data/app/base.apk", "/data/app/split.apk"]),
            "split",
        )

    @patch("subprocess.run")
    def test_query_package_paths(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="package:/data/app/owasp.sat.agoat/base.apk\n",
            stderr="",
        )
        paths = query_package_paths(
            adb_bin="adb",
            serial="127.0.0.1:5555",
            package_name="owasp.sat.agoat",
        )
        self.assertEqual(paths, ["/data/app/owasp.sat.agoat/base.apk"])

    @patch("src.play_store_acquirer.query_package_paths")
    def test_acquire_not_installed_error(self, mock_query):
        mock_query.return_value = []
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(PlayStoreAcquisitionError) as ctx:
                acquire_play_store_app(
                    package_name="com.not.installed",
                    output_dir=tmpdir,
                    serial="127.0.0.1:5555",
                    adb_bin="adb",
                )
            self.assertIn("not installed", str(ctx.exception))
            self.assertFalse(ctx.exception.installed_on_device)
            self.assertEqual(ctx.exception.package_layout, "none")

    @patch("src.play_store_acquirer.query_package_paths")
    def test_acquire_split_apk_error(self, mock_query):
        mock_query.return_value = [
            "/data/app/com.big.app/base.apk",
            "/data/app/com.big.app/split_config.xxhdpi.apk",
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(PlayStoreAcquisitionError) as ctx:
                acquire_play_store_app(
                    package_name="com.big.app",
                    output_dir=tmpdir,
                    serial="127.0.0.1:5555",
                    adb_bin="adb",
                )
            self.assertIn("Split APK package detected", str(ctx.exception))
            self.assertTrue(ctx.exception.installed_on_device)
            self.assertEqual(ctx.exception.package_layout, "split")

    @patch("src.play_store_acquirer.pull_device_apk")
    @patch("src.play_store_acquirer.query_package_paths")
    def test_acquire_monolithic_success(self, mock_query, mock_pull):
        mock_query.return_value = ["/data/app/owasp.sat.agoat/base.apk"]

        def fake_pull(adb_bin, serial, remote_path, local_path, timeout_seconds):
            # Create a valid minimal APK zip with classes.dex and AndroidManifest.xml
            with zipfile.ZipFile(local_path, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
                zf.writestr("classes.dex", b"dex\n035\x00")

        mock_pull.side_effect = fake_pull

        with tempfile.TemporaryDirectory() as tmpdir:
            result = acquire_play_store_app(
                package_name="owasp.sat.agoat",
                output_dir=tmpdir,
                serial="127.0.0.1:5555",
                adb_bin="adb",
            )
            self.assertEqual(result["platform"], "android")
            self.assertEqual(result["source_type"], "play_store")
            self.assertEqual(result["package_name"], "owasp.sat.agoat")
            self.assertTrue(result["installed_on_device"])
            self.assertEqual(result["package_layout"], "monolithic")
            self.assertTrue(result["validation"]["is_valid_apk"])
            self.assertTrue(Path(tmpdir, "owasp.sat.agoat.apk").exists())

    @patch("subprocess.run")
    def test_open_play_store_on_device(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="Starting: Intent ...", stderr="")
        res = open_play_store_on_device(
            serial="127.0.0.1:5555",
            package_name="com.example.app",
            adb_bin="adb",
        )
        self.assertTrue(res["success"])
        self.assertIn("play.google.com", res["url"])
        mock_run.assert_called_once()
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("android.intent.action.VIEW", called_cmd)
        self.assertIn("https://play.google.com/store/apps/details?id=com.example.app", called_cmd)


if __name__ == "__main__":
    unittest.main()
