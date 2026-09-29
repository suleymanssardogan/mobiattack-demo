"""Unit and integration tests for APK Preprocessor module."""

import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import zipfile

from src.apk_preprocessor import (
    ApkPreprocessingError,
    extract_raw_apk_safely,
    preprocess_apk,
    sanitize_workspace_name,
    validate_apktool_output,
    validate_jadx_output,
)


def create_mock_apk_file(
    path: Path,
    dex_names: list[str] | None = None,
    include_manifest: bool = True,
    extra_files: dict[str, bytes] | None = None,
) -> Path:
    """Creates a synthetic APK ZIP archive on disk."""
    if dex_names is None:
        dex_names = ["classes.dex"]
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        if include_manifest:
            zf.writestr("AndroidManifest.xml", b"<manifest></manifest>")
        for dex in dex_names:
            zf.writestr(dex, b"dex_dummy_bytes")
        if extra_files:
            for fname, fdata in extra_files.items():
                zf.writestr(fname, fdata)
    return path


class TestApkPreprocessorUnit(unittest.TestCase):
    """Unit tests for apk_preprocessor with mocked subprocesses and filesystem checks."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.output_root = self.base_dir / "workspaces"
        self.output_root.mkdir()
        self.dummy_apk = self.base_dir / "sample_app.apk"
        create_mock_apk_file(self.dummy_apk)

    def tearDown(self):
        self.temp_dir.cleanup()

    # --- 1. Basic Path & Executable Validation ---

    def test_01_missing_apk_path_raises_error(self):
        non_existent = self.base_dir / "missing.apk"
        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(non_existent, self.output_root)
        self.assertIn("not found", str(ctx.exception).lower())

    def test_02_apk_path_is_directory_raises_error(self):
        dir_path = self.base_dir / "dir_as_apk"
        dir_path.mkdir()
        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(dir_path, self.output_root)
        self.assertIn("not a file", str(ctx.exception).lower())

    @patch("shutil.which", return_value=None)
    def test_03_missing_apktool_executable_raises_error(self, mock_which):
        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(self.dummy_apk, self.output_root)
        self.assertIn("apktool' not found", str(ctx.exception))

    @patch("shutil.which")
    def test_04_missing_jadx_executable_raises_error(self, mock_which):
        # apktool exists, jadx does not
        def fake_which(cmd):
            return "/bin/apktool" if cmd == "apktool" else None
        mock_which.side_effect = fake_which

        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(self.dummy_apk, self.output_root)
        self.assertIn("jadx' not found", str(ctx.exception))

    # --- 2. Workspace Naming & Collision Defense ---

    def test_05_safe_workspace_naming_and_sanitization(self):
        self.assertEqual(sanitize_workspace_name("MyApp.apk"), "MyApp")
        self.assertEqual(sanitize_workspace_name("../../evil.apk"), "evil")
        self.assertEqual(sanitize_workspace_name("..\\..\\windows.apk"), "windows")
        self.assertEqual(sanitize_workspace_name("\x00weird.apk"), "weird")
        self.assertEqual(sanitize_workspace_name("///"), "unnamed_apk")
        self.assertEqual(sanitize_workspace_name(""), "unnamed_apk")

    @patch("shutil.which", return_value="/bin/tool")
    def test_06_collision_handling_existing_workspace_fails(self, mock_which):
        # Pre-create target workspace directory
        existing_ws = self.output_root / "sample_app"
        existing_ws.mkdir()
        (existing_ws / "important_data.txt").write_text("DO NOT DELETE", encoding="utf-8")

        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(self.dummy_apk, self.output_root)

        self.assertIn("already exists", str(ctx.exception).lower())
        # Verify user data was preserved and not deleted
        self.assertTrue((existing_ws / "important_data.txt").exists())

    # --- 3. Subprocess Execution & Argument Validation ---

    @patch("src.apk_preprocessor.validate_jadx_output", return_value=True)
    @patch("src.apk_preprocessor.validate_apktool_output", return_value=True)
    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/mock_tool")
    def test_07_apktool_and_jadx_command_arguments_and_no_shell(
        self, mock_which, mock_run, mock_val_apktool, mock_val_jadx
    ):
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
        ]

        meta = preprocess_apk(self.dummy_apk, self.output_root)

        self.assertEqual(mock_run.call_count, 2)
        call_apktool = mock_run.call_args_list[0]
        call_jadx = mock_run.call_args_list[1]

        # Verify command argument lists
        cmd_apktool = call_apktool[0][0]
        self.assertEqual(cmd_apktool[0], "/bin/mock_tool")
        self.assertEqual(cmd_apktool[1], "d")
        self.assertEqual(cmd_apktool[2], str(self.dummy_apk))
        self.assertEqual(cmd_apktool[3], "-o")
        self.assertTrue(cmd_apktool[4].endswith("apktool_out"))

        cmd_jadx = call_jadx[0][0]
        self.assertEqual(cmd_jadx[0], "/bin/mock_tool")
        self.assertEqual(cmd_jadx[1], "-d")
        self.assertTrue(cmd_jadx[2].endswith("jadx_out"))
        self.assertEqual(cmd_jadx[3], str(self.dummy_apk))

        # Verify shell=True is never used
        self.assertNotIn("shell", call_apktool[1])
        self.assertNotIn("shell", call_jadx[1])

        self.assertEqual(meta["apktool"]["status"], "success")
        self.assertEqual(meta["jadx"]["status"], "success")

    # --- 4. Subprocess Failures & Timeouts ---

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/mock_tool")
    def test_08_apktool_nonzero_exit_rolls_back(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="I: Apktool error occurred"
        )

        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(self.dummy_apk, self.output_root)

        self.assertIn("apktool failed with exit code 1", str(ctx.exception))
        # Verify rollback cleaned up the created workspace
        ws = self.output_root / "sample_app"
        self.assertFalse(ws.exists())

    @patch("src.apk_preprocessor.validate_apktool_output", return_value=True)
    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/mock_tool")
    def test_09_jadx_fatal_nonzero_exit_rolls_back(self, mock_which, mock_run, mock_val_apktool):
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="FATAL: OutOfMemory"),
        ]

        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(self.dummy_apk, self.output_root)

        self.assertIn("jadx failed with fatal exit code 1", str(ctx.exception))
        self.assertFalse((self.output_root / "sample_app").exists())

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/mock_tool")
    def test_10_apktool_timeout_rolls_back(self, mock_which, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="apktool", timeout=10)

        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(self.dummy_apk, self.output_root, timeout_seconds=10)

        self.assertIn("apktool timed out after 10 seconds", str(ctx.exception))
        self.assertFalse((self.output_root / "sample_app").exists())

    @patch("src.apk_preprocessor.validate_apktool_output", return_value=True)
    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/mock_tool")
    def test_11_jadx_timeout_rolls_back(self, mock_which, mock_run, mock_val_apktool):
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.TimeoutExpired(cmd="jadx", timeout=15),
        ]

        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(self.dummy_apk, self.output_root, timeout_seconds=15)

        self.assertIn("jadx timed out after 15 seconds", str(ctx.exception))
        self.assertFalse((self.output_root / "sample_app").exists())

    # --- 5. Artifact Validation & JADX Status Semantics ---

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/mock_tool")
    def test_12_apktool_missing_manifest_rejected(self, mock_which, mock_run):
        def fake_run(cmd, *args, **kwargs):
            if "d" in cmd:
                out_dir = Path(cmd[4])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "smali").mkdir(exist_ok=True)
                # Intentionally omit AndroidManifest.xml
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run

        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(self.dummy_apk, self.output_root)

        self.assertIn("missing AndroidManifest.xml or valid Smali root", str(ctx.exception))
        self.assertFalse((self.output_root / "sample_app").exists())

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/mock_tool")
    def test_13_apktool_missing_smali_root_rejected(self, mock_which, mock_run):
        def fake_run(cmd, *args, **kwargs):
            if "d" in cmd:
                out_dir = Path(cmd[4])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
                # Intentionally omit smali/ directories
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run

        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(self.dummy_apk, self.output_root)

        self.assertIn("missing AndroidManifest.xml or valid Smali root", str(ctx.exception))
        self.assertFalse((self.output_root / "sample_app").exists())

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/mock_tool")
    def test_14_jadx_returncode_3_with_valid_sources_gives_success_with_warnings(
        self, mock_which, mock_run
    ):
        def fake_run(cmd, *args, **kwargs):
            if cmd[1] == "d":
                # apktool
                out_dir = Path(cmd[4])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
                (out_dir / "smali").mkdir(exist_ok=True)
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            elif cmd[1] == "-d":
                # jadx returning 3
                out_dir = Path(cmd[2])
                sources = out_dir / "sources" / "com" / "example"
                sources.mkdir(parents=True, exist_ok=True)
                (sources / "MainActivity.java").write_text("class MainActivity {}", encoding="utf-8")
                return subprocess.CompletedProcess(
                    args=cmd, returncode=3, stdout="ERROR - finished with errors", stderr=""
                )

        mock_run.side_effect = fake_run

        meta = preprocess_apk(self.dummy_apk, self.output_root)
        self.assertEqual(meta["jadx"]["status"], "success_with_warnings")
        self.assertEqual(meta["jadx"]["returncode"], 3)
        self.assertTrue((self.output_root / "sample_app").exists())

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/mock_tool")
    def test_15_jadx_returncode_3_with_empty_sources_fails(self, mock_which, mock_run):
        def fake_run(cmd, *args, **kwargs):
            if cmd[1] == "d":
                out_dir = Path(cmd[4])
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
                (out_dir / "smali").mkdir(exist_ok=True)
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            elif cmd[1] == "-d":
                out_dir = Path(cmd[2])
                # Empty sources directory
                (out_dir / "sources").mkdir(parents=True, exist_ok=True)
                return subprocess.CompletedProcess(args=cmd, returncode=3, stdout="", stderr="")

        mock_run.side_effect = fake_run

        with self.assertRaises(ApkPreprocessingError) as ctx:
            preprocess_apk(self.dummy_apk, self.output_root)

        self.assertIn("missing or empty sources directory", str(ctx.exception))
        self.assertFalse((self.output_root / "sample_app").exists())

    # --- 6. Raw APK Safe Extraction & Security Defenses ---

    def test_16_raw_apk_safe_extraction_success(self):
        target_dir = self.base_dir / "raw_out"
        count = extract_raw_apk_safely(self.dummy_apk, target_dir)
        self.assertGreater(count, 0)
        self.assertTrue((target_dir / "AndroidManifest.xml").is_file())
        self.assertTrue((target_dir / "classes.dex").is_file())

    def test_17_zip_slip_traversal_rejected_and_aborted(self):
        malicious_apk = self.base_dir / "zip_slip.apk"
        with zipfile.ZipFile(malicious_apk, "w") as zf:
            zf.writestr("normal.txt", b"safe")
            zf.writestr("../../escape.txt", b"evil")

        target_dir = self.base_dir / "raw_slip"
        with self.assertRaises(ApkPreprocessingError) as ctx:
            extract_raw_apk_safely(malicious_apk, target_dir)

        self.assertIn("Zip Slip path traversal", str(ctx.exception))
        self.assertFalse((self.base_dir / "escape.txt").exists())

    def test_18_absolute_zip_member_rejected(self):
        malicious_apk = self.base_dir / "abs_path.apk"
        with zipfile.ZipFile(malicious_apk, "w") as zf:
            zf.writestr("/tmp/evil.txt", b"evil")

        target_dir = self.base_dir / "raw_abs"
        with self.assertRaises(ApkPreprocessingError) as ctx:
            extract_raw_apk_safely(malicious_apk, target_dir)

        self.assertIn("Unsafe absolute", str(ctx.exception))

    def test_19_symbolic_link_member_rejected(self):
        malicious_apk = self.base_dir / "symlink.apk"
        with zipfile.ZipFile(malicious_apk, "w") as zf:
            info = zipfile.ZipInfo("symlink_entry")
            # Unix file mode for symlink is S_IFLNK (0o120000)
            info.external_attr = 0o120777 << 16
            zf.writestr(info, b"/etc/passwd")

        target_dir = self.base_dir / "raw_sym"
        with self.assertRaises(ApkPreprocessingError) as ctx:
            extract_raw_apk_safely(malicious_apk, target_dir)

        self.assertIn("Symbolic link member rejected", str(ctx.exception))

    def test_20_uncompressed_size_limit_aborts_early(self):
        oversized_apk = self.base_dir / "bomb.apk"
        with zipfile.ZipFile(oversized_apk, "w") as zf:
            # 10 KB file
            zf.writestr("big.bin", b"0" * 10240)

        target_dir = self.base_dir / "raw_bomb"
        with self.assertRaises(ApkPreprocessingError) as ctx:
            extract_raw_apk_safely(oversized_apk, target_dir, max_uncompressed_bytes=1000)

        self.assertIn("exceeds maximum limit", str(ctx.exception))


class TestRealOwaspPreprocessingIntegration(unittest.TestCase):
    """Integration test using real installed apktool and jadx against MSTG-Android-Kotlin.apk."""

    def setUp(self):
        repo_root = Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.parent / "MSTG-Android-Kotlin.apk").is_file() else Path(__file__).resolve().parent.parent.parent
        self.owasp_apk = repo_root / "MSTG-Android-Kotlin.apk"
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_real_owasp_preprocessing(self):
        if not self.owasp_apk.is_file():
            self.skipTest(f"OWASP APK not found at {self.owasp_apk}")

        apktool_bin = shutil.which("apktool")
        jadx_bin = shutil.which("jadx")
        if not apktool_bin or not jadx_bin:
            self.skipTest("apktool or jadx binary not installed on system PATH")

        meta = preprocess_apk(self.owasp_apk, self.output_root, timeout_seconds=180.0)

        # 1. Verify workspace structure
        ws_dir = self.output_root / "MSTG-Android-Kotlin"
        self.assertTrue(ws_dir.is_dir())

        raw_dir = ws_dir / "raw_apk"
        self.assertTrue(raw_dir.is_dir())
        self.assertTrue((raw_dir / "classes.dex").is_file())
        self.assertTrue((raw_dir / "AndroidManifest.xml").is_file())

        apktool_dir = ws_dir / "apktool_out"
        self.assertTrue(apktool_dir.is_dir())
        self.assertTrue((apktool_dir / "AndroidManifest.xml").is_file())
        self.assertTrue((apktool_dir / "smali").is_dir())

        jadx_dir = ws_dir / "jadx_out"
        self.assertTrue(jadx_dir.is_dir())
        self.assertTrue((jadx_dir / "sources").is_dir())

        # 2. Verify returned metadata schema & status
        self.assertEqual(meta["apktool"]["status"], "success")
        self.assertEqual(meta["apktool"]["returncode"], 0)
        self.assertEqual(meta["jadx"]["status"], "success_with_warnings")
        self.assertEqual(meta["jadx"]["returncode"], 3)
        self.assertTrue(meta["raw_apk"]["success"])
        self.assertGreater(meta["raw_apk"]["file_count"], 0)


if __name__ == "__main__":
    unittest.main()
