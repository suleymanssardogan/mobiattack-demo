"""Unit tests for Persistent Scan State Model (Task 3.1)."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.scan_state import (
    CANONICAL_ARTIFACTS,
    CANONICAL_STAGES,
    CANONICAL_STATUSES,
    SCHEMA_VERSION,
    STATE_FILENAME,
    ScanStateCorruptionError,
    ScanStateError,
    ScanStateValidationError,
    create_initial_scan_state,
    load_scan_state,
    mark_artifact_available,
    save_scan_state,
    set_overall_status,
    update_stage_status,
    validate_artifact_relative_path,
    validate_scan_state,
)


class TestScanStateModel(unittest.TestCase):
    """Tests scan_state.py creation, validation, atomic persistence, and integrity rules."""

    def setUp(self):
        self.sample_scan_id = "run_1790699486_de126b"
        self.sample_url = "https://github.com/OWASP/MASTG-Hacking-Playground/releases/download/1.0/MSTG-Android-Kotlin.apk"
        self.sample_platform = "android"

    # -------------------------------------------------------------
    # 1. CREATION TESTS (Requirements 1-9)
    # -------------------------------------------------------------

    def test_01_initial_state_is_valid(self):
        """1. Initial state created by factory is valid against schema rules."""
        state = create_initial_scan_state(
            scan_id=self.sample_scan_id,
            target_url=self.sample_url,
            platform=self.sample_platform,
        )
        self.assertEqual(state["schema_version"], SCHEMA_VERSION)
        self.assertEqual(state["overall_status"], "running")
        self.assertIsNone(state["error"])
        # Does not raise validation error
        validate_scan_state(state)

    def test_02_scan_id_preserved(self):
        """2. scan_id is preserved exactly in state."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        self.assertEqual(state["scan_id"], self.sample_scan_id)

    def test_03_target_url_preserved(self):
        """3. Target URL is preserved exactly in state without filesystem confusion."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        self.assertEqual(state["target"]["url"], self.sample_url)

    def test_04_platform_preserved(self):
        """4. Platform is normalized and preserved."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url, platform="Android")
        self.assertEqual(state["target"]["platform"], "android")

        ios_state = create_initial_scan_state(self.sample_scan_id, "https://example.com/app.ipa", platform="ios")
        self.assertEqual(ios_state["target"]["platform"], "ios")

        with self.assertRaises(ScanStateValidationError):
            create_initial_scan_state(self.sample_scan_id, self.sample_url, platform="windows")

    def test_05_app_acquisition_is_running(self):
        """5. Initial stage app_acquisition status is running."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        self.assertEqual(state["stages"]["app_acquisition"]["status"], "running")
        self.assertEqual(state["current_stage"], "app_acquisition")
        self.assertIsNotNone(state["stages"]["app_acquisition"]["started_at"])

    def test_06_static_analysis_is_pending(self):
        """6. Initial stage static_analysis status is pending."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        self.assertEqual(state["stages"]["static_analysis"]["status"], "pending")
        self.assertIsNone(state["stages"]["static_analysis"]["started_at"])

    def test_07_dynamic_analysis_is_not_available(self):
        """7. Initial stage dynamic_analysis status is not_available (scheduled for Day 4+)."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        self.assertEqual(state["stages"]["dynamic_analysis"]["status"], "not_available")
        self.assertIn("subsequent milestone", state["stages"]["dynamic_analysis"]["message"])

    def test_08_agent_analysis_is_not_available(self):
        """8. Initial stage agent_analysis status is not_available with product-safe wording."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        self.assertEqual(state["stages"]["agent_analysis"]["status"], "not_available")
        self.assertEqual(state["stages"]["agent_analysis"]["message"], "Not available in this scan")

    def test_09_report_generation_is_pending(self):
        """9. Initial stage report_generation status is pending."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        self.assertEqual(state["stages"]["report_generation"]["status"], "pending")

    # -------------------------------------------------------------
    # 2. VOCABULARY TESTS (Requirements 10-11)
    # -------------------------------------------------------------

    def test_10_unsupported_stage_status_rejected(self):
        """10. Unsupported arbitrary stage status is rejected by validation."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        state["stages"]["static_analysis"]["status"] = "in_progress"  # Invalid! Must be "running"
        with self.assertRaises(ScanStateValidationError) as cm:
            validate_scan_state(state)
        self.assertIn("Invalid status 'in_progress'", str(cm.exception))

    def test_11_all_valid_statuses_accepted(self):
        """11. All canonical statuses are accepted by validator."""
        for status in CANONICAL_STATUSES:
            state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
            state["overall_status"] = status
            state["stages"]["static_analysis"]["status"] = status
            validate_scan_state(state)

    # -------------------------------------------------------------
    # 3. ARTIFACT SAFETY TESTS (Requirements 12-17)
    # -------------------------------------------------------------

    def test_12_initial_artifacts_unavailable(self):
        """12. All canonical artifacts are initially unavailable with null paths."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        for art in CANONICAL_ARTIFACTS:
            self.assertFalse(state["artifacts"][art]["available"])
            self.assertIsNone(state["artifacts"][art]["relative_path"])

    def test_13_relative_artifact_path_accepted(self):
        """13. Clean relative artifact path is accepted."""
        validate_artifact_relative_path("static_analysis_report.json")
        validate_artifact_relative_path("reports/static_analysis_report.json")

        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        mark_artifact_available(state, "static_analysis_report", "static_analysis_report.json")
        self.assertTrue(state["artifacts"]["static_analysis_report"]["available"])
        self.assertEqual(state["artifacts"]["static_analysis_report"]["relative_path"], "static_analysis_report.json")

    def test_14_absolute_unix_path_rejected(self):
        """14. Absolute Unix scanner paths (/Users/..., /home/..., /tmp/...) are rejected."""
        with self.assertRaises(ScanStateValidationError):
            validate_artifact_relative_path("/Users/test/workspace/report.json")
        with self.assertRaises(ScanStateValidationError):
            validate_artifact_relative_path("/home/user/report.json")
        with self.assertRaises(ScanStateValidationError):
            validate_artifact_relative_path("/tmp/report.json")
        with self.assertRaises(ScanStateValidationError):
            validate_artifact_relative_path("/opt/homebrew/report.json")

    def test_15_windows_absolute_path_rejected(self):
        """15. Windows drive letter paths (C:\\..., D:/...) are rejected."""
        with self.assertRaises(ScanStateValidationError):
            validate_artifact_relative_path("C:\\Users\\test\\report.json")
        with self.assertRaises(ScanStateValidationError):
            validate_artifact_relative_path("D:/reports/report.json")

    def test_16_path_traversal_rejected(self):
        """16. Path traversal ('..') is strictly rejected."""
        with self.assertRaises(ScanStateValidationError):
            validate_artifact_relative_path("../secret.json")
        with self.assertRaises(ScanStateValidationError):
            validate_artifact_relative_path("reports/../../etc/passwd")

    def test_17_available_artifact_cannot_have_null_path(self):
        """17. An artifact marked available=True must have a non-null valid relative path."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        state["artifacts"]["static_analysis_report"]["available"] = True
        state["artifacts"]["static_analysis_report"]["relative_path"] = None

        with self.assertRaises(ScanStateValidationError):
            validate_scan_state(state)

    # -------------------------------------------------------------
    # 4. PERSISTENCE & LOAD TESTS (Requirements 18-22)
    # -------------------------------------------------------------

    def test_18_save_scan_state_creates_file(self):
        """18. save_scan_state writes scan_state.json into run_dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / self.sample_scan_id
            state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
            saved_path = save_scan_state(run_dir, state)

            self.assertTrue(saved_path.is_file())
            self.assertEqual(saved_path.name, STATE_FILENAME)

    def test_19_saved_file_is_valid_json(self):
        """19. Saved scan_state.json contains valid, parseable JSON matching state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / self.sample_scan_id
            state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
            save_scan_state(run_dir, state)

            with open(run_dir / STATE_FILENAME, "r", encoding="utf-8") as f:
                loaded_raw = json.load(f)

            self.assertEqual(loaded_raw["scan_id"], self.sample_scan_id)
            self.assertEqual(loaded_raw["schema_version"], SCHEMA_VERSION)

    def test_20_load_scan_state_round_trip(self):
        """20. load_scan_state faithfully round-trips state with updates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / self.sample_scan_id
            state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
            update_stage_status(state, "static_analysis", "running", "Decompiling bytecode...")
            mark_artifact_available(state, "static_analysis_report", "static_analysis_report.json")
            save_scan_state(run_dir, state)

            loaded = load_scan_state(run_dir)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["stages"]["static_analysis"]["status"], "running")
            self.assertEqual(loaded["stages"]["static_analysis"]["message"], "Decompiling bytecode...")
            self.assertTrue(loaded["artifacts"]["static_analysis_report"]["available"])
            self.assertEqual(loaded["artifacts"]["static_analysis_report"]["relative_path"], "static_analysis_report.json")

    def test_21_missing_file_returns_none(self):
        """21. load_scan_state cleanly returns None if file does not exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_dir = Path(tmpdir) / "empty_run"
            empty_dir.mkdir()
            self.assertIsNone(load_scan_state(empty_dir))

    def test_22_corrupted_json_raises_corruption_error(self):
        """22. Corrupted JSON file raises ScanStateCorruptionError (distinguishable from missing)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / self.sample_scan_id
            run_dir.mkdir()
            (run_dir / STATE_FILENAME).write_text("{ unclosed json: ", encoding="utf-8")

            with self.assertRaises(ScanStateCorruptionError):
                load_scan_state(run_dir)

            # Also verify empty file is treated as corrupted
            (run_dir / STATE_FILENAME).write_text("", encoding="utf-8")
            with self.assertRaises(ScanStateCorruptionError):
                load_scan_state(run_dir)

    # -------------------------------------------------------------
    # 5. ATOMICITY TESTS (Requirements 23-24)
    # -------------------------------------------------------------

    def test_23_atomic_save_leaves_no_temp_files(self):
        """23. Atomic persistence does not leave dangling temporary files after saving."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / self.sample_scan_id
            state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
            save_scan_state(run_dir, state)

            # Check that only scan_state.json exists in run_dir
            entries = list(run_dir.iterdir())
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].name, STATE_FILENAME)

    def test_24_existing_state_preserved_if_write_fails(self):
        """24. If replacement fails during atomic write, the prior valid state file is preserved intact."""
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir) / self.sample_scan_id
            state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
            save_scan_state(run_dir, state)

            # Verify existing valid content
            pre_load = load_scan_state(run_dir)
            self.assertEqual(pre_load["overall_status"], "running")

            # Simulate failure during os.replace
            new_state = dict(state)
            new_state["overall_status"] = "failed"
            with patch("os.replace", side_effect=OSError("Disk write simulated failure")):
                with self.assertRaises(OSError):
                    save_scan_state(run_dir, new_state)

            # Existing state file is undamaged and still contains original valid JSON
            post_load = load_scan_state(run_dir)
            self.assertEqual(post_load["overall_status"], "running")

    # -------------------------------------------------------------
    # 6. INTEGRITY RULES (Requirements 25-27)
    # -------------------------------------------------------------

    def test_25_initial_state_never_marks_dynamic_completed(self):
        """25. Initial state never marks dynamic analysis completed (Integrity Rule #1)."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        self.assertNotEqual(state["stages"]["dynamic_analysis"]["status"], "completed")

        # Directly setting dynamic_analysis=completed without available dynamic report fails validation
        state["stages"]["dynamic_analysis"]["status"] = "completed"
        with self.assertRaises(ScanStateValidationError) as cm:
            validate_scan_state(state)
        self.assertIn("Integrity Rule #1", str(cm.exception))

    def test_26_initial_state_never_marks_agent_completed(self):
        """26. Initial state never marks agent analysis completed."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        self.assertEqual(state["stages"]["agent_analysis"]["status"], "not_available")

    def test_27_static_only_cannot_mark_report_generation_completed(self):
        """27. Static-only report availability cannot mark report_generation completed (Integrity Rule #2)."""
        state = create_initial_scan_state(self.sample_scan_id, self.sample_url)
        mark_artifact_available(state, "static_analysis_report", "static_analysis_report.json")

        # When only static report exists, report_generation cannot be 'completed'
        state["stages"]["report_generation"]["status"] = "completed"
        with self.assertRaises(ScanStateValidationError) as cm:
            validate_scan_state(state)
        self.assertIn("Integrity Rule #2", str(cm.exception))

        # But 'partial' is valid and accepted
        state["stages"]["report_generation"]["status"] = "partial"
        validate_scan_state(state)


if __name__ == "__main__":
    unittest.main()
