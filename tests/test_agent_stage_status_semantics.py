"""Focused tests for Agent stage status semantics in the UI and scan state.

Tests the four distinct states:
- Completed (zero executions allowed)
- Partial (insufficient evidence, policy block, or post-start provider error)
- Not Available (provider unavailable before start, or runtime unavailable)
- Not Run (skipped due to lack of grounded EndpointContext)
And verifies user-facing reason wording with no raw reason codes.
"""

import json
from pathlib import Path
import tempfile
import unittest

from src.scan_state import (
    CANONICAL_STATUSES,
    create_initial_scan_state,
    sync_agent_stage_and_artifacts,
    validate_scan_state,
)


class TestAgentStageStatusSemantics(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_state(self):
        state = create_initial_scan_state(
            scan_id=self.run_dir.name,
            target_url="https://example.com/app.apk",
            platform="android",
        )
        return state

    def test_01_not_run_in_canonical_statuses(self):
        """01. not_run is a valid canonical status in CANONICAL_STATUSES."""
        self.assertIn("not_run", CANONICAL_STATUSES)
        state = self._create_state()
        state["stages"]["agent_analysis"]["status"] = "not_run"
        state["stages"]["agent_analysis"]["message"] = "No grounded endpoint context was available for Agent analysis."
        validate_scan_state(state)

    def test_02_completed_with_zero_executions_no_relevant_tests(self):
        """02. Completed: planning completed with zero executions."""
        trace = {
            "schema_version": "1.0",
            "status": "no_relevant_tests",
            "agent_state": "available",
            "reason_codes": [],
            "planner": {"status": "no_relevant_tests", "proposals": []},
            "executions": [],
            "security_report": {"coverage": "available", "results": []},
        }
        (self.run_dir / "agent_trace.json").write_text(json.dumps(trace))

        state = self._create_state()
        result = sync_agent_stage_and_artifacts(state, self.run_dir)
        self.assertTrue(result)
        stage = state["stages"]["agent_analysis"]
        self.assertEqual(stage["status"], "completed")
        self.assertIn("Planning completed; no relevant security tests were applicable.", stage["message"])
        self.assertTrue(state["artifacts"]["agent_report"]["available"])
        self.assertNotIn("NO_RELEVANT_TESTS", stage["message"])

    def test_03_completed_with_executions(self):
        """03. Completed: planning and executions completed cleanly."""
        trace = {
            "schema_version": "1.0",
            "status": "completed",
            "agent_state": "available",
            "reason_codes": [],
            "planner": {"status": "completed", "proposals": [{"proposal_id": "p1"}]},
            "executions": [{"execution_id": "e1", "execution_status": "completed"}],
            "security_report": {"coverage": "available", "results": []},
        }
        (self.run_dir / "agent_trace.json").write_text(json.dumps(trace))

        state = self._create_state()
        sync_agent_stage_and_artifacts(state, self.run_dir)
        stage = state["stages"]["agent_analysis"]
        self.assertEqual(stage["status"], "completed")
        self.assertIn("Planning and security validation completed", stage["message"])

    def test_04_partial_when_policy_needs_evidence(self):
        """04. Partial: Agent ran but evidence was insufficient (policy needs evidence)."""
        trace = {
            "schema_version": "1.0",
            "status": "needs_evidence",
            "agent_state": "partial",
            "reason_codes": ["POLICY_NEEDS_EVIDENCE", "MISSING_REQUIRED_CONTEXT"],
            "analyst": {"status": "completed"},
            "planner": {"status": "completed"},
            "policy": {"status": "evaluated", "needs_evidence_count": 2},
            "executions": [],
            "security_report": {"coverage": "partial", "results": []},
        }
        (self.run_dir / "agent" / "validation_trace.json").parent.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "agent" / "validation_trace.json").write_text(json.dumps(trace))

        state = self._create_state()
        sync_agent_stage_and_artifacts(state, self.run_dir)
        stage = state["stages"]["agent_analysis"]
        self.assertEqual(stage["status"], "partial")
        self.assertIn("Planning completed, but runtime evidence was insufficient for validation.", stage["message"])
        # No raw reason codes in user-facing message
        self.assertNotIn("POLICY_NEEDS_EVIDENCE", stage["message"])
        self.assertNotIn("MISSING_REQUIRED_CONTEXT", stage["message"])

    def test_05_partial_when_provider_fails_after_stage_start(self):
        """05. Partial: Provider timed out after analyst stage started."""
        trace = {
            "schema_version": "1.0",
            "status": "stopped",
            "agent_state": "partial",
            "reason_codes": ["ANALYST_TIMEOUT"],
            "analyst": {"status": "completed"},
            "planner": None,
            "executions": [],
            "security_report": {"coverage": "unavailable"},
        }
        (self.run_dir / "agent_trace.json").write_text(json.dumps(trace))

        state = self._create_state()
        sync_agent_stage_and_artifacts(state, self.run_dir)
        stage = state["stages"]["agent_analysis"]
        self.assertEqual(stage["status"], "partial")
        self.assertIn("Agent analysis partially completed; provider error encountered.", stage["message"])
        self.assertNotIn("ANALYST_TIMEOUT", stage["message"])

    def test_06_not_available_when_provider_unavailable_before_start(self):
        """06. Not Available: Agent stage could not start; model provider unavailable."""
        trace = {
            "schema_version": "1.0",
            "status": "stopped",
            "agent_state": "unavailable",
            "reason_codes": ["ANALYST_UNAVAILABLE_OR_INVALID"],
            "analyst": {"status": "model_error"},
            "planner": None,
            "executions": [],
            "security_report": {"coverage": "unavailable"},
        }
        (self.run_dir / "agent_trace.json").write_text(json.dumps(trace))

        state = self._create_state()
        sync_agent_stage_and_artifacts(state, self.run_dir)
        stage = state["stages"]["agent_analysis"]
        self.assertEqual(stage["status"], "not_available")
        self.assertIn("Agent stage could not start; model provider is unavailable.", stage["message"])
        self.assertNotIn("ANALYST_UNAVAILABLE_OR_INVALID", stage["message"])

    def test_07_not_run_when_endpoint_context_is_empty_or_missing(self):
        """07. Not Run: Intentionally skipped because no grounded EndpointContext existed."""
        dynamic_dir = self.run_dir / "dynamic"
        dynamic_dir.mkdir(parents=True, exist_ok=True)
        (dynamic_dir / "endpoint_contexts.json").write_text(json.dumps({
            "schema_version": "1.0",
            "endpoint_contexts": [],
            "summary": {"total_contexts": 0},
        }))

        state = self._create_state()
        state["stages"]["dynamic_analysis"]["status"] = "completed"
        sync_agent_stage_and_artifacts(state, self.run_dir)
        stage = state["stages"]["agent_analysis"]
        self.assertEqual(stage["status"], "not_run")
        self.assertEqual(stage["message"], "No grounded endpoint context was available for Agent analysis.")
        self.assertFalse(state["artifacts"]["agent_report"]["available"])

    def test_08_not_available_when_dynamic_was_unavailable(self):
        """08. Not Available: Dynamic was unavailable, so no runtime existed."""
        state = self._create_state()
        state["stages"]["dynamic_analysis"]["status"] = "not_available"
        sync_agent_stage_and_artifacts(state, self.run_dir)
        stage = state["stages"]["agent_analysis"]
        self.assertEqual(stage["status"], "not_available")
        self.assertIn("Agent runtime is unavailable in this scan.", stage["message"])

    def test_09_bitwarden_run_status_mapping(self):
        """09. Bitwarden run: 0 endpoints maps to 'Not Run — No grounded endpoint context was available for Agent analysis.'"""
        from src.scan_state import recover_scan_state
        bitwarden_run = Path("demo_runs/run_1791309532_4ef99e")
        if bitwarden_run.is_dir():
            state = recover_scan_state(bitwarden_run)
            self.assertIsNotNone(state)
            stage = state["stages"]["agent_analysis"]
            self.assertEqual(stage["status"], "not_run")
            self.assertEqual(stage["message"], "No grounded endpoint context was available for Agent analysis.")
            ui_label = "Not Run" if stage["status"] == "not_run" else "Not Available"
            self.assertEqual(f"{ui_label} — {stage['message']}", "Not Run — No grounded endpoint context was available for Agent analysis.")

    def test_10_checkpointer_syncs_agent_stage_on_artifacts_update(self):
        """10. Checkpointer syncs agent analysis to not_run when dynamic finishes with 0 endpoints."""
        from src.scan_state import ScanStateCheckpointer
        cp = ScanStateCheckpointer(
            run_dir=self.run_dir,
            scan_id="test_cp",
            target_url="https://example.com/app",
        )
        cp.init_state()
        dynamic_dir = self.run_dir / "dynamic"
        dynamic_dir.mkdir(parents=True, exist_ok=True)
        (dynamic_dir / "endpoint_contexts.json").write_text(json.dumps({
            "schema_version": "1.0",
            "endpoints": [],
            "summary": {"endpoint_context_count": 0},
        }))
        cp.on_pipeline_progress("dynamic_analysis", "completed", "Dynamic analysis completed.")
        cp.on_reports_generated()
        st = cp.get_state()
        stage = st["stages"]["agent_analysis"]
        self.assertEqual(stage["status"], "not_run")
        self.assertEqual(stage["message"], "No grounded endpoint context was available for Agent analysis.")


if __name__ == "__main__":
    unittest.main()
