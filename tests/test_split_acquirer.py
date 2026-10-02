"""Unit and Integration Tests for Split APK Acquisition & Inventory (Task 14 Phase A)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

from src.play_store_acquirer import (
    PlayStoreAcquisitionError,
    acquire_play_store_app,
    acquire_play_store_package,
    detect_package_layout,
    parse_pm_path_output,
)
from src.split_acquirer import (
    acquire_split_package_set,
    build_package_set_model,
    classify_split_component,
    compute_file_sha256,
    validate_split_apk,
    write_package_set_json,
)


def _create_mock_apk(
    path: Path,
    has_manifest: bool = True,
    dex_names: list[str] | None = None,
    extra_files: list[str] | None = None,
    corrupt_zip: bool = False,
) -> None:
    """Helper to synthesize mock APK archives for testing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if corrupt_zip:
        path.write_bytes(b"PK\x03\x04corrupted_payload_not_a_valid_zip")
        return

    with zipfile.ZipFile(path, "w") as zf:
        if has_manifest:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00\x00\x00mock_manifest")
        if dex_names:
            for d in dex_names:
                zf.writestr(d, b"dex\n035\x00mock_dex_bytes")
        if extra_files:
            for ef in extra_files:
                zf.writestr(ef, b"extra_content")


class TestSplitAcquirer(unittest.TestCase):
    """Test suite covering all Task 14 Phase A split APK requirements."""

    def test_single_apk_pm_path(self):
        output = "package:/data/app/~~xyz/com.test.single-123/base.apk\n"
        paths = parse_pm_path_output(output)
        self.assertEqual(paths, ["/data/app/~~xyz/com.test.single-123/base.apk"])
        self.assertEqual(detect_package_layout(paths), "monolithic")

    def test_multi_apk_pm_path(self):
        output = (
            "package:/data/app/~~xyz/com.test.split-123/base.apk\n"
            "package:/data/app/~~xyz/com.test.split-123/split_config.arm64_v8a.apk\n"
            "package:/data/app/~~xyz/com.test.split-123/split_config.xxhdpi.apk\n"
        )
        paths = parse_pm_path_output(output)
        self.assertEqual(len(paths), 3)
        self.assertEqual(detect_package_layout(paths), "split")

    def test_base_and_abi_split_classification(self):
        self.assertEqual(classify_split_component("base.apk"), "base")
        self.assertEqual(classify_split_component("base_1.apk"), "base")
        self.assertEqual(classify_split_component("split_config.arm64_v8a.apk"), "config_abi")
        self.assertEqual(classify_split_component("split_config.x86_64.apk"), "config_abi")
        self.assertEqual(classify_split_component("split_config.armeabi_v7a.apk"), "config_abi")

    def test_base_and_locale_split_classification(self):
        self.assertEqual(classify_split_component("split_config.en.apk"), "config_locale")
        self.assertEqual(classify_split_component("split_config.tr.apk"), "config_locale")
        self.assertEqual(classify_split_component("split_config.es.apk"), "config_locale")
        self.assertEqual(classify_split_component("split_config.pt_BR.apk"), "config_locale")
        self.assertEqual(classify_split_component("split_config.zh_CN.apk"), "config_locale")

    def test_base_and_density_split_classification(self):
        self.assertEqual(classify_split_component("split_config.xxhdpi.apk"), "config_density")
        self.assertEqual(classify_split_component("split_config.hdpi.apk"), "config_density")
        self.assertEqual(classify_split_component("split_config.xhdpi.apk"), "config_density")
        self.assertEqual(classify_split_component("split_config.mdpi.apk"), "config_density")
        self.assertEqual(classify_split_component("split_config.anydpi.apk"), "config_density")

    def test_feature_split_classification(self):
        self.assertEqual(classify_split_component("split_checkout.apk"), "feature")
        self.assertEqual(classify_split_component("split_extra_feature.apk"), "feature")

    def test_unknown_split_classification(self):
        # Opaque or unidentifiable config split names fall back to unknown
        self.assertEqual(classify_split_component("split_config.opaque_bundle_123.apk"), "unknown")
        self.assertEqual(classify_split_component("random_name.apk"), "unknown")
        self.assertEqual(classify_split_component("unknown_split.apk"), "unknown")

    def test_sha256_computation(self):
        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b"Hello MobiAttack V2 Split APK Testing")
            tmp.flush()
            expected = hashlib.sha256(b"Hello MobiAttack V2 Split APK Testing").hexdigest()
            actual = compute_file_sha256(Path(tmp.name))
            self.assertEqual(actual, expected)

    def test_zip_validation_per_component(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_apk = Path(tmpdir) / "base.apk"
            _create_mock_apk(base_apk, has_manifest=True, dex_names=["classes.dex", "classes2.dex"])
            v = validate_split_apk(base_apk, role="base")
            self.assertTrue(v["is_valid_zip"])
            self.assertTrue(v["has_android_manifest"])
            self.assertTrue(v["has_dex"])
            self.assertEqual(v["dex_count"], 2)
            self.assertEqual(v["dex_files"], ["classes.dex", "classes2.dex"])
            self.assertTrue(v["is_valid"])
            self.assertIsNone(v["error"])

    def test_dex_less_split_accepted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            abi_apk = Path(tmpdir) / "split_config.arm64_v8a.apk"
            _create_mock_apk(
                abi_apk,
                has_manifest=True,
                dex_names=[],
                extra_files=["lib/arm64-v8a/libnative.so"],
            )
            v = validate_split_apk(abi_apk, role="config_abi")
            self.assertTrue(v["is_valid_zip"])
            self.assertTrue(v["has_android_manifest"])
            self.assertFalse(v["has_dex"])
            self.assertEqual(v["dex_count"], 0)
            self.assertTrue(v["is_valid"], "DEX-less config split must be accepted as valid")

    def test_base_without_dex_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_base = Path(tmpdir) / "base.apk"
            _create_mock_apk(bad_base, has_manifest=True, dex_names=[])
            v = validate_split_apk(bad_base, role="base")
            self.assertFalse(v["is_valid"])
            self.assertIn("Base APK does not contain any valid DEX", v["error"])

    def test_malformed_pulled_apk_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            corrupt = Path(tmpdir) / "split_corrupt.apk"
            _create_mock_apk(corrupt, corrupt_zip=True)
            v = validate_split_apk(corrupt, role="unknown")
            self.assertFalse(v["is_valid_zip"])
            self.assertFalse(v["is_valid"])

    @patch("src.play_store_acquirer.pull_device_apk")
    def test_all_apks_pulled_and_package_set_json_written(self, mock_pull):
        def fake_pull(adb_bin, serial, remote_path, local_path, timeout_seconds):
            name = Path(remote_path).name
            if name == "base.apk":
                _create_mock_apk(local_path, has_manifest=True, dex_names=["classes.dex"])
            elif "arm64" in name:
                _create_mock_apk(local_path, has_manifest=True, dex_names=[], extra_files=["lib/arm64-v8a/liba.so"])
            else:
                _create_mock_apk(local_path, has_manifest=True, dex_names=[])

        mock_pull.side_effect = fake_pull

        remote_paths = [
            "/data/app/~~xyz/com.example.splitapp/base.apk",
            "/data/app/~~xyz/com.example.splitapp/split_config.arm64_v8a.apk",
            "/data/app/~~xyz/com.example.splitapp/split_config.en.apk",
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            out_root = Path(tmpdir)
            result = acquire_split_package_set(
                package_name="com.example.splitapp",
                output_dir=out_root,
                serial="127.0.0.1:5555",
                adb_bin="adb",
                remote_paths=remote_paths,
            )

            # Check return structure
            self.assertEqual(result["package_name"], "com.example.splitapp")
            self.assertEqual(result["package_layout"], "split")
            self.assertEqual(result["split_count"], 3)
            self.assertEqual(len(result["components"]), 3)

            # Verify files on disk
            apks_dir = out_root / "package_set" / "apks"
            self.assertTrue((apks_dir / "base.apk").is_file())
            self.assertTrue((apks_dir / "split_config.arm64_v8a.apk").is_file())
            self.assertTrue((apks_dir / "split_config.en.apk").is_file())

            # Verify package_set.json
            json_file = out_root / "package_set" / "package_set.json"
            self.assertTrue(json_file.is_file())
            with open(json_file, "r") as f:
                saved = json.load(f)
            self.assertEqual(saved["package_name"], "com.example.splitapp")
            self.assertEqual(saved["package_layout"], "split")
            self.assertEqual(len(saved["components"]), 3)

            # Verify individual components
            c_base = next(c for c in result["components"] if c["filename"] == "base.apk")
            self.assertEqual(c_base["role"], "base")
            self.assertTrue(c_base["has_dex"])
            self.assertTrue(c_base["is_valid"])

            c_abi = next(c for c in result["components"] if c["filename"] == "split_config.arm64_v8a.apk")
            self.assertEqual(c_abi["role"], "config_abi")
            self.assertFalse(c_abi["has_dex"])
            self.assertTrue(c_abi["is_valid"])

            c_en = next(c for c in result["components"] if c["filename"] == "split_config.en.apk")
            self.assertEqual(c_en["role"], "config_locale")
            self.assertTrue(c_en["is_valid"])

    @patch("src.play_store_acquirer.pull_device_apk")
    def test_duplicate_filename_rejected_without_partial_artifacts(self, mock_pull):
        from src.play_store_acquirer import PlayStoreAcquisitionError
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(PlayStoreAcquisitionError) as error:
                acquire_split_package_set('com.example.collision', tmpdir, 'device', adb_bin='adb',
                    remote_paths=['/data/app/one/split_module.apk', '/data/app/two/split_module.apk'])
            self.assertEqual(error.exception.reason_code, 'SPLIT_SET_INCOMPLETE')
            self.assertFalse((Path(tmpdir)/'package_set').exists())
            mock_pull.assert_not_called()

    @patch("src.play_store_acquirer.pull_device_apk")
    def test_malformed_apk_in_package_set_raises_error(self, mock_pull):
        def fake_pull(adb_bin, serial, remote_path, local_path, timeout_seconds):
            # Create a corrupted zip
            _create_mock_apk(local_path, corrupt_zip=True)

        mock_pull.side_effect = fake_pull
        remote_paths = ["/data/app/com.test/corrupted_split.apk"]

        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(PlayStoreAcquisitionError) as ctx:
                acquire_split_package_set(
                    package_name="com.test",
                    output_dir=tmpdir,
                    serial="127.0.0.1:5555",
                    adb_bin="adb",
                    remote_paths=remote_paths,
                )
            self.assertIn("failed structural validation", str(ctx.exception))

    @patch("src.play_store_acquirer.pull_device_apk")
    @patch("src.play_store_acquirer.query_package_paths")
    def test_acquire_play_store_package_split_integration(self, mock_query, mock_pull):
        mock_query.return_value = [
            "/data/app/~~p/com.pkg-1/base.apk",
            "/data/app/~~p/com.pkg-1/split_config.xxhdpi.apk",
        ]

        def fake_pull(adb_bin, serial, remote_path, local_path, timeout_seconds):
            name = Path(remote_path).name
            if name == "base.apk":
                _create_mock_apk(local_path, has_manifest=True, dex_names=["classes.dex"])
            else:
                _create_mock_apk(local_path, has_manifest=True, dex_names=[])

        mock_pull.side_effect = fake_pull

        with tempfile.TemporaryDirectory() as tmpdir:
            res = acquire_play_store_package(
                package_name="com.pkg",
                output_dir=tmpdir,
                serial="127.0.0.1:5555",
                adb_bin="adb",
            )
            self.assertEqual(res["package_layout"], "split")
            self.assertEqual(res["split_count"], 2)
            self.assertTrue(Path(res["package_set_path"]).is_file())


if __name__ == "__main__":
    unittest.main()
