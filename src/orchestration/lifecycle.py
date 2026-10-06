"""Lifecycle responsibilities for the demo pipeline."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import logging

logger = logging.getLogger(__name__)


def _update_scan_state_dynamic_stage(
    root_path: Path,
    status: str,
    message: str,
    current_stage: str | None = None,
) -> None:
    """Updates scan_state.json dynamically using atomic scan_state helpers."""
    try:
        from src.scan_state import (
            load_scan_state,
            mark_artifact_available,
            save_scan_state,
            update_stage_status,
            sync_dynamic_report_artifact,
        )
        st = load_scan_state(root_path, validate_artifacts=False)
        if not st:
            return

        # Product integrity: dynamic_analysis cannot be completed without canonical dynamic_analysis_report
        was_registered = st["artifacts"]["dynamic_analysis_report"].get("available", False)
        available = sync_dynamic_report_artifact(st, root_path, complete_stage=False)
        if available and not was_registered:
            save_scan_state(root_path, st)
        sync_dynamic_report_artifact(st, root_path)
        actual_stat = ("completed" if available else "partial") if status in ("partial", "completed") else status
        update_stage_status(st, "dynamic_analysis", actual_stat, message)
        if current_stage:
            st["current_stage"] = current_stage
        elif status == "running":
            st["current_stage"] = "dynamic_analysis"
        elif st.get("current_stage") == "dynamic_analysis":
            st["current_stage"] = "report_generation"

        # Maintain report_generation partial state if static_analysis_report is available
        static_report = root_path / "static_analysis_report.json"
        if static_report.is_file():
            mark_artifact_available(st, "static_analysis_report", "static_analysis_report.json")
            update_stage_status(
                st,
                "report_generation",
                "partial",
                "Static analysis report available; additional analysis reports pending.",
            )

        save_scan_state(root_path, st)
    except Exception as exc:
        logger.warning("Failed to update scan_state for dynamic_analysis: %s", exc)


def _finalize_scan_state_post_run(root_path: Path) -> None:
    """Updates scan_state.json after report generation to ensure current_stage and artifacts are consistent."""
    try:
        from src.scan_state import (
            load_scan_state,
            save_scan_state,
            mark_artifact_available,
            update_stage_status,
        )
        st = load_scan_state(root_path)
        if not st:
            return
        static_report = root_path / "static_analysis_report.json"
        if static_report.is_file():
            mark_artifact_available(st, "static_analysis_report", "static_analysis_report.json")
            update_stage_status(
                st,
                "report_generation",
                "partial",
                "Static analysis report available; additional analysis reports pending.",
            )
        # Avoid stale current_stage: truthful representation of latest reached stage
        if st.get("overall_status") == "completed":
            st["current_stage"] = "completed"
        elif st.get("current_stage") == "dynamic_analysis":
            st["current_stage"] = "report_generation"
        save_scan_state(root_path, st)
    except Exception as exc:
        logger.debug("Failed to finalize scan_state post-run: %s", exc)


def _wire_dynamic_analysis_report(root_path: Path) -> Any | None:
    """Report-only generation; persistence and validation precede state registration."""
    try:
        from src.report_generator import generate_dynamic_analysis_report
        from src.scan_state import load_scan_state, save_scan_state, sync_dynamic_report_artifact
        state = load_scan_state(root_path, validate_artifacts=False)
        report = generate_dynamic_analysis_report(root_path, state.get("target", {}) if state else {})
        if state:
            # Checkpoint availability first. Completion is a subsequent persisted transition.
            state["artifacts"]["dynamic_analysis_report"] = {"available": True, "relative_path": "dynamic_analysis_report.json"}
            save_scan_state(root_path, state)
            sync_dynamic_report_artifact(state, root_path)
            save_scan_state(root_path, state)
        return report
    except Exception as exc:
        logger.warning("Canonical dynamic report generation failed (isolated): %s", exc)
        return None
