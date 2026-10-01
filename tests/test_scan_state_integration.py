"""Integration tests for Persistent Scan State Model & Pipeline Checkpoints (Task 3.2)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.scan_state import (
    STATE_FILENAME,
    ScanStateCheckpointer,
    load_scan_state,
    save_scan_state,
)


class TestScanStatePipelineIntegration(unittest.TestCase):
    """Verifies all Task 3.2 pipeline checkpoint integration requirements."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temp_dir.name) / "run_test_integration_01"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.scan_id = "run_test_integration_01"
        self.target_url = "https://github.com/OWASP/MASTG-Hacking-Playground/releases/download/1.0/MSTG-Android-Kotlin.apk"
        self.platform = "android"

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # 1. New scan creates scan_state.json
    def test_01_new_scan_creates_scan_state_file(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()

        state_file = self.run_dir / STATE_FILENAME
        self.assertTrue(state_file.is_file(), "scan_state.json must exist immediately upon scan initialization")
        loaded = load_scan_state(self.run_dir)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["scan_id"], self.scan_id)

    # 2. Initial state acquisition running
    def test_02_initial_state_acquisition_running(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()

        loaded = load_scan_state(self.run_dir)
        self.assertEqual(loaded["overall_status"], "running")
        self.assertEqual(loaded["current_stage"], "app_acquisition")
        self.assertEqual(loaded["stages"]["app_acquisition"]["status"], "running")
        self.assertEqual(loaded["stages"]["static_analysis"]["status"], "pending")
        self.assertEqual(loaded["stages"]["dynamic_analysis"]["status"], "not_available")
        self.assertEqual(loaded["stages"]["agent_analysis"]["status"], "not_available")
        self.assertEqual(loaded["stages"]["report_generation"]["status"], "pending")

    # 3. Acquisition success persists completed
    def test_03_acquisition_success_persists_completed(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()
        checkpointer.on_pipeline_progress("acquisition", "running", "Downloading APK...")
        checkpointer.on_pipeline_progress(
            "acquisition",
            "success",
            "Acquired 'sample.apk' cleanly.",
            {"package_name": "sg.vantage.mstg"},
        )

        loaded = load_scan_state(self.run_dir)
        self.assertEqual(loaded["stages"]["app_acquisition"]["status"], "completed")
        self.assertIsNotNone(loaded["stages"]["app_acquisition"]["completed_at"])
        self.assertEqual(loaded["target"]["package_name"], "sg.vantage.mstg")

    # 4. Static begins after acquisition
    def test_04_static_begins_after_acquisition(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()
        checkpointer.on_pipeline_progress("acquisition", "success", "Acquisition finished.")

        loaded = load_scan_state(self.run_dir)
        self.assertEqual(loaded["stages"]["app_acquisition"]["status"], "completed")
        self.assertEqual(loaded["stages"]["static_analysis"]["status"], "running")
        self.assertEqual(loaded["current_stage"], "static_analysis")

    # 5. Static success persists completed
    def test_05_static_success_persists_completed(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()
        checkpointer.on_pipeline_progress("acquisition", "success", "Acquisition done.")
        checkpointer.on_pipeline_progress("preprocessing", "running", "Decompiling Dalvik bytecode...")
        checkpointer.on_pipeline_progress("preprocessing", "success", "Decompilation succeeded.")
        checkpointer.on_pipeline_progress("static_analysis", "running", "Extracting indicators...")
        checkpointer.on_pipeline_progress(
            "static_analysis",
            "success",
            "Static context generated for 'sg.vantage.mstg'.",
            {"app": {"package_name": "sg.vantage.mstg"}},
        )

        loaded = load_scan_state(self.run_dir)
        self.assertEqual(loaded["stages"]["static_analysis"]["status"], "completed")
        self.assertIsNotNone(loaded["stages"]["static_analysis"]["completed_at"])

    # 6. static_analysis_report artifact availability only set after file exists
    def test_06_artifact_availability_only_set_after_file_exists(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()

        # Before file exists on disk
        checkpointer.on_reports_generated()
        loaded = load_scan_state(self.run_dir)
        self.assertFalse(loaded["artifacts"]["static_analysis_report"]["available"])
        self.assertIsNone(loaded["artifacts"]["static_analysis_report"]["relative_path"])

        # Now simulate report generator writing static_analysis_report.json
        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")

        checkpointer.on_reports_generated()
        loaded = load_scan_state(self.run_dir)
        self.assertTrue(loaded["artifacts"]["static_analysis_report"]["available"])
        self.assertEqual(loaded["artifacts"]["static_analysis_report"]["relative_path"], "static_analysis_report.json")

    # 7. Static artifact makes report_generation partial, not completed
    def test_07_static_artifact_makes_report_generation_partial(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()

        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")

        checkpointer.on_reports_generated()
        loaded = load_scan_state(self.run_dir)
        self.assertEqual(loaded["stages"]["report_generation"]["status"], "partial")
        self.assertNotEqual(loaded["stages"]["report_generation"]["status"], "completed")
        self.assertEqual(
            loaded["stages"]["report_generation"]["message"],
            "Static analysis report available; additional analysis reports pending.",
        )

    # 8. Runtime success does NOT complete dynamic_analysis
    def test_08_runtime_success_does_not_complete_dynamic_analysis(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()
        checkpointer.on_pipeline_progress("acquisition", "success", "Acquired.")
        checkpointer.on_pipeline_progress("static_analysis", "success", "Analyzed.")
        checkpointer.on_pipeline_progress("runtime", "running", "Launching foreground activity...")
        checkpointer.on_pipeline_progress("runtime", "success", "App successfully launched (PID 1234).")

        loaded = load_scan_state(self.run_dir)
        # CRITICAL INTEGRITY RULE #1
        self.assertEqual(loaded["stages"]["dynamic_analysis"]["status"], "not_available")
        self.assertNotEqual(loaded["stages"]["dynamic_analysis"]["status"], "completed")

    # 9. Runtime failure does NOT fail/erase completed static_analysis
    def test_09_runtime_failure_does_not_erase_completed_static(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()
        checkpointer.on_pipeline_progress("acquisition", "success", "Acquired.")
        checkpointer.on_pipeline_progress("static_analysis", "success", "Analyzed.")
        checkpointer.on_pipeline_progress("runtime", "running", "Attempting launch...")
        checkpointer.on_pipeline_progress("runtime", "failed", "ADB device offline")

        loaded = load_scan_state(self.run_dir)
        self.assertEqual(loaded["stages"]["app_acquisition"]["status"], "completed")
        self.assertEqual(loaded["stages"]["static_analysis"]["status"], "completed")
        self.assertEqual(loaded["stages"]["dynamic_analysis"]["status"], "not_available")
        self.assertEqual(loaded["overall_status"], "failed")

    # 10. Runtime failure does NOT remove static artifact availability
    def test_10_runtime_failure_does_not_remove_static_artifact_availability(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()
        checkpointer.on_pipeline_progress("acquisition", "success", "Acquired.")
        checkpointer.on_pipeline_progress("static_analysis", "success", "Analyzed.")

        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")
        checkpointer.on_reports_generated()

        # Preflight launch fails
        checkpointer.on_failure("runtime", "Runtime launch verification failed")

        loaded = load_scan_state(self.run_dir)
        self.assertTrue(loaded["artifacts"]["static_analysis_report"]["available"])
        self.assertEqual(loaded["artifacts"]["static_analysis_report"]["relative_path"], "static_analysis_report.json")
        self.assertEqual(loaded["stages"]["static_analysis"]["status"], "completed")
        self.assertEqual(loaded["stages"]["report_generation"]["status"], "partial")

    # 11. Agent remains not_available
    def test_11_agent_remains_not_available(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()
        checkpointer.on_pipeline_progress("acquisition", "success", "Done")
        checkpointer.on_pipeline_progress("static_analysis", "success", "Done")
        checkpointer.on_pipeline_progress("runtime", "success", "Done")
        checkpointer.on_pipeline_progress("demo", "completed", "Done")

        loaded = load_scan_state(self.run_dir)
        self.assertEqual(loaded["stages"]["agent_analysis"]["status"], "not_available")

    # 12. Pipeline terminal success can set overall_status completed without marking unavailable product stages completed
    def test_12_terminal_success_sets_overall_status_completed(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()
        checkpointer.on_pipeline_progress("acquisition", "success", "Done")
        checkpointer.on_pipeline_progress("static_analysis", "success", "Done")
        checkpointer.on_pipeline_progress("runtime", "success", "Done")

        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")
        checkpointer.on_reports_generated()
        checkpointer.on_demo_completed()

        loaded = load_scan_state(self.run_dir)
        self.assertEqual(loaded["overall_status"], "completed")
        self.assertEqual(loaded["current_stage"], "completed")
        self.assertIsNotNone(loaded["timestamps"]["completed_at"])

        # Honest representation: unavailable stages are NOT completed!
        self.assertEqual(loaded["stages"]["dynamic_analysis"]["status"], "not_available")
        self.assertEqual(loaded["stages"]["agent_analysis"]["status"], "not_available")
        self.assertEqual(loaded["stages"]["report_generation"]["status"], "partial")

    # 13. Acquisition failure persists failed state
    def test_13_acquisition_failure_persists_failed_state(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()
        checkpointer.on_pipeline_progress("acquisition", "running", "Downloading...")
        checkpointer.on_pipeline_progress("acquisition", "failed", "HTTP 404: Package not found")

        loaded = load_scan_state(self.run_dir)
        self.assertEqual(loaded["overall_status"], "failed")
        self.assertEqual(loaded["current_stage"], "app_acquisition")
        self.assertEqual(loaded["stages"]["app_acquisition"]["status"], "failed")
        self.assertEqual(loaded["stages"]["static_analysis"]["status"], "pending")
        self.assertFalse(loaded["artifacts"]["static_analysis_report"]["available"])

    # 14. Static failure persists failed state
    def test_14_static_failure_persists_failed_state(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()
        checkpointer.on_pipeline_progress("acquisition", "success", "Acquired.")
        checkpointer.on_pipeline_progress("preprocessing", "failed", "Apktool failed to decode resources")

        loaded = load_scan_state(self.run_dir)
        self.assertEqual(loaded["overall_status"], "failed")
        self.assertEqual(loaded["current_stage"], "static_analysis")
        self.assertEqual(loaded["stages"]["app_acquisition"]["status"], "completed")
        self.assertEqual(loaded["stages"]["static_analysis"]["status"], "failed")

    # 15. scan_state contains no absolute artifact paths
    def test_15_scan_state_contains_no_absolute_artifact_paths(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()
        checkpointer.on_pipeline_progress("acquisition", "success", "Acquired.")
        checkpointer.on_pipeline_progress("static_analysis", "success", "Done.")

        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")
        checkpointer.on_reports_generated()
        checkpointer.on_demo_completed()

        raw_state_text = (self.run_dir / STATE_FILENAME).read_text(encoding="utf-8")
        state_dict = json.loads(raw_state_text)

        for art_key, art_obj in state_dict["artifacts"].items():
            rel_path = art_obj.get("relative_path")
            if rel_path is not None:
                self.assertFalse(rel_path.startswith("/"), f"Artifact {art_key} path must not start with /")
                self.assertNotIn("Users", rel_path)
                self.assertNotIn("home", rel_path)
                self.assertNotIn("..", rel_path)

    # 16. checkpoint persistence failure is observable, not silently swallowed
    def test_16_persistence_failure_is_observable(self) -> None:
        checkpointer = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id=self.scan_id,
            target_url=self.target_url,
            platform=self.platform,
        )
        checkpointer.init_state()

        # Simulate disk error during checkpoint save
        with patch("src.scan_state.save_scan_state", side_effect=OSError("Read-only filesystem simulation")):
            with self.assertLogs("src.scan_state", level="ERROR") as log_cm:
                checkpointer.on_pipeline_progress("acquisition", "running", "Downloading APK...")

            self.assertTrue(any("Failed to persist scan_state.json checkpoint" in log for log in log_cm.output))
            self.assertIsNotNone(checkpointer.last_save_error)
            self.assertIsInstance(checkpointer.last_save_error, OSError)


if __name__ == "__main__":
    unittest.main()
