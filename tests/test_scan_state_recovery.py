"""Unit and Integration tests for Restart / Crash Recovery & Persistent Status Fallback (Task 3.3)."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from src.demo_web_server import DemoWebServer
from src.scan_state import (
    STATE_FILENAME,
    create_initial_scan_state,
    load_scan_state,
    mark_artifact_available,
    recover_scan_state,
    save_scan_state,
    update_stage_status,
)


class TestScanStateRecovery(unittest.TestCase):
    """Verifies all Task 3.3 recovery requirements without external network/process bindings."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.runs_root = Path(self.temp_dir.name).resolve()
        self.server = DemoWebServer(host="127.0.0.1", port=0, runs_root=self.runs_root)

        self.sample_run_id = "run_crash_recovery_01"
        self.sample_url = "https://github.com/OWASP/MASTG-Hacking-Playground/releases/download/1.0/MSTG-Android-Kotlin.apk"
        self.run_dir = self.runs_root / self.sample_run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    # 1. Live run uses memory state, not disk fallback
    def test_01_live_run_uses_memory_state(self) -> None:
        with self.server._lock:
            self.server._runs[self.sample_run_id] = {
                "run_id": self.sample_run_id,
                "overall_status": "running",
                "current_stage": "acquisition",
                "stages": {
                    "acquisition": {"state": "running", "message": "In memory live acquisition..."},
                },
            }

        # Even if disk has a different state
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        disk_state["overall_status"] = "failed"
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        self.assertIsNotNone(status)
        self.assertEqual(status["overall_status"], "running")
        self.assertFalse(status.get("recovered", False))

    # 2. Missing live run + completed disk state returns recovered status
    def test_02_missing_live_run_completed_disk_state_recovered(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        update_stage_status(disk_state, "app_acquisition", "completed")
        update_stage_status(disk_state, "static_analysis", "completed")
        disk_state["overall_status"] = "completed"
        disk_state["current_stage"] = "completed"

        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")
        mark_artifact_available(disk_state, "static_analysis_report", "static_analysis_report.json")
        save_scan_state(self.run_dir, disk_state)

        # Server has no in-memory record for this run
        self.assertNotIn(self.sample_run_id, self.server._runs)

        status = self.server.get_run_status(self.sample_run_id)
        self.assertIsNotNone(status)
        self.assertEqual(status["overall_status"], "completed")
        self.assertTrue(status.get("recovered"))
        self.assertEqual(status.get("state_source"), "disk")

    # 3. Missing live run + running disk state becomes interrupted
    def test_03_missing_live_run_running_disk_state_becomes_interrupted(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        disk_state["overall_status"] = "running"
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        self.assertIsNotNone(status)
        self.assertEqual(status["overall_status"], "interrupted")
        self.assertEqual(status["current_stage"], "interrupted")
        self.assertIn("interrupted", status.get("error", "").lower())

    # 4. Interrupted state is persisted back to disk
    def test_04_interrupted_state_persisted_back_to_disk(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        disk_state["overall_status"] = "running"
        save_scan_state(self.run_dir, disk_state)

        # Triggers recovery
        self.server.get_run_status(self.sample_run_id)

        # Inspect disk file directly
        loaded = load_scan_state(self.run_dir)
        self.assertEqual(loaded["overall_status"], "interrupted")
        self.assertEqual(loaded["current_stage"], "interrupted")

    # 5. Completed static stage survives recovery
    def test_05_completed_static_stage_survives_recovery(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        update_stage_status(disk_state, "app_acquisition", "completed")
        update_stage_status(disk_state, "static_analysis", "completed", "Static context generated.")
        disk_state["overall_status"] = "running"  # Was in runtime when crashed
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        self.assertEqual(status["overall_status"], "interrupted")
        # Stages in scan_state must remain completed
        scan_st = status["scan_state"]
        self.assertEqual(scan_st["stages"]["app_acquisition"]["status"], "completed")
        self.assertEqual(scan_st["stages"]["static_analysis"]["status"], "completed")

    # 6. Static artifact availability survives recovery
    def test_06_static_artifact_availability_survives_recovery(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        update_stage_status(disk_state, "static_analysis", "completed")

        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")
        mark_artifact_available(disk_state, "static_analysis_report", "static_analysis_report.json")
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        art = status["scan_state"]["artifacts"]["static_analysis_report"]
        self.assertTrue(art["available"])
        self.assertEqual(art["relative_path"], "static_analysis_report.json")

    # 7. static report exists but artifact checkpoint missing → availability reconciled
    def test_07_static_report_exists_checkpoint_missing_reconciled(self) -> None:
        # Crash window: file was written to disk, but scan_state.json not yet updated!
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        disk_state["artifacts"]["static_analysis_report"]["available"] = False
        disk_state["artifacts"]["static_analysis_report"]["relative_path"] = None
        save_scan_state(self.run_dir, disk_state)

        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")

        status = self.server.get_run_status(self.sample_run_id)
        art = status["scan_state"]["artifacts"]["static_analysis_report"]
        self.assertTrue(art["available"], "Should reconcile available=True when file is physically on disk")
        self.assertEqual(art["relative_path"], "static_analysis_report.json")
        self.assertEqual(status["scan_state"]["stages"]["report_generation"]["status"], "partial")

    # 8. artifact marked available but file missing → availability corrected
    def test_08_artifact_marked_available_file_missing_corrected(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        # Force state to claim available=True without file existing
        disk_state["artifacts"]["static_analysis_report"]["available"] = True
        disk_state["artifacts"]["static_analysis_report"]["relative_path"] = "static_analysis_report.json"
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        art = status["scan_state"]["artifacts"]["static_analysis_report"]
        self.assertFalse(art["available"], "Should correct available=False when file does not exist on disk")
        self.assertIsNone(art["relative_path"])

    # 9. report_generation remains partial with only static artifact
    def test_09_report_generation_remains_partial_with_only_static_artifact(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        rep_gen = status["scan_state"]["stages"]["report_generation"]
        self.assertEqual(rep_gen["status"], "partial")
        self.assertNotEqual(rep_gen["status"], "completed")

    # 10. dynamic remains not_available
    def test_10_dynamic_remains_not_available(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        dyn = status["scan_state"]["stages"]["dynamic_analysis"]
        self.assertEqual(dyn["status"], "not_available")

    # 11. agent remains not_available
    def test_11_agent_remains_not_available(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        agent = status["scan_state"]["stages"]["agent_analysis"]
        self.assertEqual(agent["status"], "not_available")

    # 12. recovery never maps runtime to dynamic completed
    def test_12_recovery_never_maps_runtime_to_dynamic_completed(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        # Even if legacy report.json had runtime success
        rep_json = self.run_dir / "report.json"
        rep_json.write_text(json.dumps({"runtime": {"status": "success", "pid": 1234}}), encoding="utf-8")
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        dyn = status["scan_state"]["stages"]["dynamic_analysis"]
        self.assertEqual(dyn["status"], "not_available")
        self.assertNotEqual(dyn["status"], "completed")

    # 13. corrupted scan_state does not crash server
    def test_13_corrupted_scan_state_does_not_crash_server(self) -> None:
        state_file = self.run_dir / STATE_FILENAME
        state_file.write_text("{ corrupt json: ", encoding="utf-8")

        # Must not raise unhandled exception
        status = self.server.get_run_status(self.sample_run_id)
        # Without static report, returns None (404 response) safely
        self.assertIsNone(status)

        # Now test corrupted scan_state WITH existing static report
        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed", "metadata": {"target_url": self.sample_url}}), encoding="utf-8")

        recovered_status = self.server.get_run_status(self.sample_run_id)
        self.assertIsNotNone(recovered_status)
        self.assertEqual(recovered_status["overall_status"], "interrupted")
        self.assertTrue(recovered_status["scan_state"]["artifacts"]["static_analysis_report"]["available"])

    # 14. unknown run with no disk state/artifacts returns 404 / None
    def test_14_unknown_run_returns_none(self) -> None:
        status = self.server.get_run_status("non_existent_run_99999")
        self.assertIsNone(status)

    # 15. canonical static report endpoint works after simulated restart
    def test_15_canonical_static_report_path_resolves_after_restart(self) -> None:
        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"report_type": "canonical_static_analysis"}), encoding="utf-8")

        run_dir_found = self.server.get_run_dir(self.sample_run_id)
        self.assertIsNotNone(run_dir_found)
        self.assertTrue((run_dir_found / "static_analysis_report.json").is_file())

    # 16. recovery response contains no absolute host path
    def test_16_recovery_response_contains_no_absolute_host_path(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        status_text = json.dumps(status)
        self.assertNotIn("/Users/", status_text)
        self.assertNotIn("/home/", status_text)
        self.assertNotIn("/tmp/", status_text)

    # 17. completed scan remains completed; do NOT turn terminal completed scan into interrupted
    def test_17_completed_scan_remains_completed(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        disk_state["overall_status"] = "completed"
        disk_state["current_stage"] = "completed"
        update_stage_status(disk_state, "app_acquisition", "completed")
        update_stage_status(disk_state, "static_analysis", "completed")

        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")
        mark_artifact_available(disk_state, "static_analysis_report", "static_analysis_report.json")
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        self.assertEqual(status["overall_status"], "completed")
        self.assertNotEqual(status["overall_status"], "interrupted")

    # 18. failed scan remains failed
    def test_18_failed_scan_remains_failed(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        disk_state["overall_status"] = "failed"
        disk_state["error"] = "Network 404 package not found"
        update_stage_status(disk_state, "app_acquisition", "failed")
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        self.assertEqual(status["overall_status"], "failed")
        self.assertNotEqual(status["overall_status"], "interrupted")

    # 19. partial scan remains partial if already terminal
    def test_19_partial_scan_remains_partial_if_already_terminal(self) -> None:
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        disk_state["overall_status"] = "partial"
        update_stage_status(disk_state, "app_acquisition", "completed")
        update_stage_status(disk_state, "static_analysis", "partial")

        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "partial"}), encoding="utf-8")
        mark_artifact_available(disk_state, "static_analysis_report", "static_analysis_report.json")
        save_scan_state(self.run_dir, disk_state)

        status = self.server.get_run_status(self.sample_run_id)
        self.assertEqual(status["overall_status"], "partial")
        self.assertNotEqual(status["overall_status"], "interrupted")

    # 20. Explicit Day 3 Crash Test (Section 18)
    def test_20_explicit_day_3_crash_acceptance_scenario(self) -> None:
        """Explicit crash scenario:
        scan_state:
          overall_status = running
          app_acquisition = completed
          static_analysis = completed
          static artifact = available
          report_generation = partial
        remove live registry entry
        GET status
        Assert:
          overall_status = interrupted
          static_analysis = completed
          static artifact = available
          report_generation = partial
          dynamic = not_available
          agent = not_available
        """
        disk_state = create_initial_scan_state(self.sample_run_id, self.sample_url)
        disk_state["overall_status"] = "running"
        update_stage_status(disk_state, "app_acquisition", "completed")
        update_stage_status(disk_state, "static_analysis", "completed")

        rep_file = self.run_dir / "static_analysis_report.json"
        rep_file.write_text(json.dumps({"status": "completed"}), encoding="utf-8")
        mark_artifact_available(disk_state, "static_analysis_report", "static_analysis_report.json")
        disk_state["stages"]["report_generation"]["status"] = "partial"
        save_scan_state(self.run_dir, disk_state)

        # Live registry entry is absent
        with self.server._lock:
            self.server._runs.pop(self.sample_run_id, None)

        # GET status
        status = self.server.get_run_status(self.sample_run_id)

        self.assertIsNotNone(status)
        self.assertEqual(status["overall_status"], "interrupted")
        scan_st = status["scan_state"]
        self.assertEqual(scan_st["stages"]["app_acquisition"]["status"], "completed")
        self.assertEqual(scan_st["stages"]["static_analysis"]["status"], "completed")
        self.assertTrue(scan_st["artifacts"]["static_analysis_report"]["available"])
        self.assertEqual(scan_st["stages"]["report_generation"]["status"], "partial")
        self.assertEqual(scan_st["stages"]["dynamic_analysis"]["status"], "not_available")
        self.assertEqual(scan_st["stages"]["agent_analysis"]["status"], "not_available")


if __name__ == "__main__":
    unittest.main()
