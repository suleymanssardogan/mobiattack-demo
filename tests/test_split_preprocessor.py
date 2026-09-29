"""Unit and Integration Tests for Isolated Per-Split Preprocessing (Task 14 Phase B)."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

from src.apk_preprocessor import ApkPreprocessingError
from src.split_preprocessor import (
    preprocess_package_set,
    validate_split_apktool_output,
)


def _create_test_apk(
    path: Path,
    has_manifest: bool = True,
    dex_names: list[str] | None = None,
    extra_files: dict[str, bytes] | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        if has_manifest:
            zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00\x00\x00mock_manifest")
        if dex_names:
            for d in dex_names:
                zf.writestr(d, b"dex\n035\x00mock_dex_bytes")
        if extra_files:
            for fname, content in extra_files.items():
                zf.writestr(fname, content)


class TestSplitPreprocessor(unittest.TestCase):
    """Test suite verifying isolated decomposition, DEX-less handling, and failure semantics."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)
        self.apks_dir = self.root / "package_set" / "apks"
        self.apks_dir.mkdir(parents=True, exist_ok=True)

        # Create sample mock APKs
        self.base_apk = self.apks_dir / "base.apk"
        _create_test_apk(
            self.base_apk,
            has_manifest=True,
            dex_names=["classes.dex"],
            extra_files={"res/values/strings.xml": b"<resources/>"},
        )

        self.locale_apk = self.apks_dir / "split_config.en.apk"
        _create_test_apk(
            self.locale_apk,
            has_manifest=True,
            dex_names=[],
            extra_files={"res/values-en/strings.xml": b"<resources><string name='app'>Flashlight</string></resources>"},
        )

        self.density_apk = self.apks_dir / "split_config.xxhdpi.apk"
        _create_test_apk(
            self.density_apk,
            has_manifest=True,
            dex_names=[],
            extra_files={"res/drawable-xxhdpi/icon.png": b"\x89PNG\r\n\x1a\n"},
        )

        self.package_set = {
            "package_name": "apps.r.flashlight",
            "package_layout": "split",
            "split_count": 3,
            "components": [
                {
                    "filename": "base.apk",
                    "role": "base",
                    "local_path": str(self.base_apk),
                    "has_dex": True,
                    "dex_count": 1,
                    "dex_files": ["classes.dex"],
                    "is_valid": True,
                },
                {
                    "filename": "split_config.en.apk",
                    "role": "config_locale",
                    "local_path": str(self.locale_apk),
                    "has_dex": False,
                    "dex_count": 0,
                    "dex_files": [],
                    "is_valid": True,
                },
                {
                    "filename": "split_config.xxhdpi.apk",
                    "role": "config_density",
                    "local_path": str(self.density_apk),
                    "has_dex": False,
                    "dex_count": 0,
                    "dex_files": [],
                    "is_valid": True,
                },
            ],
        }
        self.pkg_set_file = self.root / "package_set" / "package_set.json"
        with open(self.pkg_set_file, "w") as f:
            json.dump(self.package_set, f, indent=2)

    def tearDown(self):
        self.tmpdir.cleanup()

    @patch("subprocess.run")
    def test_full_package_set_preprocessing_success(self, mock_subproc):
        def fake_run(cmd, capture_output=True, text=True, timeout=None):
            # cmd is like ['apktool', 'd', apk, '-o', out_dir] or ['jadx', '-d', jadx_dir, apk]
            tool = Path(cmd[0]).name
            if tool == "apktool":
                out_dir = Path(cmd[4])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "AndroidManifest.xml").write_text("<manifest/>")
                (out_dir / "apktool.yml").write_text("version: 2.9.0")
                if "base.apk" in cmd[2]:
                    (out_dir / "smali").mkdir(parents=True, exist_ok=True)
                    (out_dir / "smali" / "Main.smali").write_text(".class LMain;")
                else:
                    (out_dir / "res").mkdir(parents=True, exist_ok=True)
                return MagicMock(returncode=0, stdout="I: Built", stderr="")
            elif tool == "jadx":
                jadx_dir = Path(cmd[2])
                sources = jadx_dir / "sources" / "com" / "example"
                sources.mkdir(parents=True, exist_ok=True)
                (sources / "Main.java").write_text("package com.example; public class Main {}")
                return MagicMock(returncode=0, stdout="INFO: done", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_subproc.side_effect = fake_run

        result = preprocess_package_set(
            package_set_input=self.pkg_set_file,
            apktool_executable="apktool",
            jadx_executable="jadx",
        )

        # 1. Check top-level result
        self.assertEqual(result["package_name"], "apps.r.flashlight")
        self.assertEqual(result["package_layout"], "split")
        self.assertEqual(result["component_count"], 3)
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["components"]), 3)

        # 2. Check base component (JADX executed)
        base_comp = next(c for c in result["components"] if c["filename"] == "base.apk")
        self.assertEqual(base_comp["raw_extract_status"], "success")
        self.assertEqual(base_comp["apktool_status"], "success")
        self.assertEqual(base_comp["jadx_status"], "success")
        self.assertIsNotNone(base_comp["jadx_dir"])
        self.assertTrue(Path(base_comp["raw_apk_dir"]).is_dir())
        self.assertTrue(Path(base_comp["apktool_dir"]).is_dir())
        self.assertTrue(Path(base_comp["jadx_dir"]).is_dir())

        # 3. Check locale split (JADX skipped_no_dex)
        en_comp = next(c for c in result["components"] if c["filename"] == "split_config.en.apk")
        self.assertEqual(en_comp["raw_extract_status"], "success")
        self.assertEqual(en_comp["apktool_status"], "success")
        self.assertEqual(en_comp["jadx_status"], "skipped_no_dex")
        self.assertIsNone(en_comp["jadx_dir"])
        self.assertTrue(Path(en_comp["raw_apk_dir"]).is_dir())
        self.assertTrue(Path(en_comp["apktool_dir"]).is_dir())

        # 4. Check density split (JADX skipped_no_dex)
        xxhdpi_comp = next(c for c in result["components"] if c["filename"] == "split_config.xxhdpi.apk")
        self.assertEqual(xxhdpi_comp["raw_extract_status"], "success")
        self.assertEqual(xxhdpi_comp["apktool_status"], "success")
        self.assertEqual(xxhdpi_comp["jadx_status"], "skipped_no_dex")
        self.assertIsNone(xxhdpi_comp["jadx_dir"])

        # 5. Verify isolated directory layout (no flattening)
        processed_dir = self.root / "processed"
        self.assertTrue((processed_dir / "base" / "apktool_out").is_dir())
        self.assertTrue((processed_dir / "split_config.en" / "apktool_out").is_dir())
        self.assertTrue((processed_dir / "split_config.xxhdpi" / "apktool_out").is_dir())

        # 6. Verify package_set.json updated on disk
        with open(self.pkg_set_file, "r") as f:
            updated_pkg_set = json.load(f)
        for c in updated_pkg_set["components"]:
            self.assertIn("preprocessing", c)
            self.assertIn("raw_extract_status", c["preprocessing"])
            self.assertIn("apktool_status", c["preprocessing"])
            self.assertIn("jadx_status", c["preprocessing"])

    @patch("subprocess.run")
    def test_jadx_never_invoked_for_dex_less_splits(self, mock_subproc):
        called_tools = []

        def fake_run(cmd, capture_output=True, text=True, timeout=None):
            tool = Path(cmd[0]).name
            called_tools.append((tool, cmd[-1]))
            if tool == "apktool":
                out_dir = Path(cmd[4])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "AndroidManifest.xml").write_text("<manifest/>")
                (out_dir / "res").mkdir(parents=True, exist_ok=True)
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_subproc.side_effect = fake_run

        # Package set with only DEX-less splits
        dexless_pkg_set = {
            "package_name": "com.dexless",
            "package_layout": "split",
            "components": [
                {
                    "filename": "split_config.en.apk",
                    "role": "config_locale",
                    "local_path": str(self.locale_apk),
                    "has_dex": False,
                }
            ],
        }

        res = preprocess_package_set(
            package_set_input=dexless_pkg_set,
            processed_root=self.root / "processed_custom",
            apktool_executable="apktool",
            jadx_executable="jadx",
        )

        jadx_calls = [c for c in called_tools if c[0] == "jadx"]
        self.assertEqual(len(jadx_calls), 0, "JADX must NEVER be called when has_dex is False")
        self.assertEqual(res["components"][0]["jadx_status"], "skipped_no_dex")

    @patch("subprocess.run")
    def test_base_failure_aborts_phase_b(self, mock_subproc):
        # Apktool fails on base.apk
        mock_subproc.return_value = MagicMock(returncode=1, stdout="", stderr="Fatal apktool error on base")

        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_package_set(
                package_set_input=self.pkg_set_file,
                apktool_executable="apktool",
                jadx_executable="jadx",
            )
        self.assertIn("Base APK preprocessing failed", str(ctx.exception))

    @patch("subprocess.run")
    def test_config_split_failure_becomes_warning_and_continues(self, mock_subproc):
        def fake_run(cmd, capture_output=True, text=True, timeout=None):
            tool = Path(cmd[0]).name
            if any("base.apk" in str(arg) for arg in cmd):
                if tool == "apktool":
                    out_dir = Path(cmd[4])
                    out_dir.mkdir(parents=True, exist_ok=True)
                    (out_dir / "AndroidManifest.xml").write_text("<manifest/>")
                    (out_dir / "smali").mkdir(parents=True, exist_ok=True)
                    (out_dir / "smali" / "Main.smali").write_text(".class LMain;")
                    return MagicMock(returncode=0, stdout="", stderr="")
                elif tool == "jadx":
                    jadx_dir = Path(cmd[2])
                    sources = jadx_dir / "sources"
                    sources.mkdir(parents=True, exist_ok=True)
                    (sources / "A.java").write_text("class A{}")
                    return MagicMock(returncode=0, stdout="", stderr="")
            else:
                # Optional split apktool fails
                return MagicMock(returncode=1, stdout="", stderr="Resource decode error")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_subproc.side_effect = fake_run

        result = preprocess_package_set(
            package_set_input=self.pkg_set_file,
            apktool_executable="apktool",
            jadx_executable="jadx",
        )

        # Pipeline did not crash; status reflects warnings
        self.assertEqual(result["status"], "success_with_warnings")
        self.assertTrue(len(result["warnings"]) > 0)

        # Base succeeded
        base_comp = next(c for c in result["components"] if c["filename"] == "base.apk")
        self.assertEqual(base_comp["apktool_status"], "success")

        # Config split failed apktool but was retained
        en_comp = next(c for c in result["components"] if c["filename"] == "split_config.en.apk")
        self.assertEqual(en_comp["apktool_status"], "failed")
        self.assertTrue(len(en_comp["warnings"]) > 0)



    @patch("subprocess.run")
    def test_dex_less_locale_and_density_splits(self, mock_subproc):
        def fake_run(cmd, capture_output=True, text=True, timeout=None):
            tool = Path(cmd[0]).name
            if tool == "apktool":
                out_dir = Path(cmd[4])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "AndroidManifest.xml").write_text("<manifest/>")
                (out_dir / "res").mkdir(parents=True, exist_ok=True)
                return MagicMock(returncode=0, stdout="", stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_subproc.side_effect = fake_run

        locale_density_pkg_set = {
            "package_name": "apps.r.flashlight",
            "package_layout": "split",
            "components": [
                {
                    "filename": "split_config.en.apk",
                    "role": "config_locale",
                    "local_path": str(self.locale_apk),
                    "has_dex": False,
                },
                {
                    "filename": "split_config.xxhdpi.apk",
                    "role": "config_density",
                    "local_path": str(self.density_apk),
                    "has_dex": False,
                },
            ],
        }

        res = preprocess_package_set(
            package_set_input=locale_density_pkg_set,
            processed_root=self.root / "processed_splits_only",
            apktool_executable="apktool",
            jadx_executable="jadx",
        )

        for c in res["components"]:
            self.assertEqual(c["raw_extract_status"], "success")
            self.assertEqual(c["apktool_status"], "success")
            self.assertEqual(c["jadx_status"], "skipped_no_dex")
            self.assertIsNone(c["jadx_dir"])

    @patch("subprocess.run")
    def test_separate_directories_prevent_filename_collisions(self, mock_subproc):
        def fake_run(cmd, capture_output=True, text=True, timeout=None):
            tool = Path(cmd[0]).name
            if tool == "apktool":
                out_dir = Path(cmd[4])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "AndroidManifest.xml").write_text("<manifest/>")
                (out_dir / "apktool.yml").write_text("version: 2.9.0")
                if any("base.apk" in str(arg) for arg in cmd):
                    (out_dir / "smali").mkdir(parents=True, exist_ok=True)
                    (out_dir / "smali" / "A.smali").write_text(".class LA;")
                else:
                    (out_dir / "res").mkdir(parents=True, exist_ok=True)
            elif tool == "jadx":
                jadx_dir = Path(cmd[2])
                sources = jadx_dir / "sources"
                sources.mkdir(parents=True, exist_ok=True)
                (sources / "A.java").write_text("class A{}")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_subproc.side_effect = fake_run

        res = preprocess_package_set(
            package_set_input=self.pkg_set_file,
            processed_root=self.root / "collision_test_processed",
            apktool_executable="apktool",
            jadx_executable="jadx",
        )

        base_dir = Path(res["components"][0]["workspace"])
        en_dir = Path(res["components"][1]["workspace"])
        xxhdpi_dir = Path(res["components"][2]["workspace"])

        self.assertNotEqual(base_dir, en_dir)
        self.assertNotEqual(en_dir, xxhdpi_dir)
        self.assertEqual(base_dir.name, "base")
        self.assertEqual(en_dir.name, "split_config.en")
        self.assertEqual(xxhdpi_dir.name, "split_config.xxhdpi")

if __name__ == "__main__":
    unittest.main()
