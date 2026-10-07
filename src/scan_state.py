"""Persistent Scan State Model for MobiAttack.

Provides deterministic creation, validation, atomic persistence, and recovery
of product-level scan lifecycle state (scan_state.json) without internal pipeline dumps.
"""

from __future__ import annotations

from src.persistence import write_json_atomic

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import threading
from typing import Any, Callable

logger = logging.getLogger(__name__)


SCHEMA_VERSION: str = "1.0"
STATE_FILENAME: str = "scan_state.json"

CANONICAL_STAGES: tuple[str, ...] = (
    "app_acquisition",
    "static_analysis",
    "dynamic_analysis",
    "agent_analysis",
    "report_generation",
)

CANONICAL_STATUSES: tuple[str, ...] = (
    "pending",
    "running",
    "completed",
    "partial",
    "failed",
    "interrupted",
    "not_available",
    "not_run",
)

CANONICAL_ARTIFACTS: tuple[str, ...] = (
    "static_analysis_report",
    "dynamic_analysis_report",
    "agent_report",
)

FORBIDDEN_PATH_PREFIXES: tuple[str, ...] = (
    "/Users/",
    "/home/",
    "/private/",
    "/tmp/",
    "/opt/",
)


class ScanStateError(ValueError):
    """Base exception for scan state operations."""


class ScanStateValidationError(ScanStateError):
    """Raised when scan state fails schema, vocabulary, or integrity rules."""


class ScanStateCorruptionError(ScanStateError):
    """Raised when scan_state.json exists on disk but is corrupted or unparseable."""


def _utc_now_iso() -> str:
    """Returns the current UTC timestamp formatted as ISO-8601 (YYYY-MM-DDTHH:MM:SSZ)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_artifact_relative_path(path: str | None) -> None:
    """Validates that an artifact path is strictly relative to the run directory.

    Rejects absolute paths, Windows drive letters, path traversal (..), and forbidden host paths.
    """
    if path is None:
        raise ScanStateValidationError("Artifact relative_path cannot be None when artifact is available.")
    if not isinstance(path, str) or not path.strip():
        raise ScanStateValidationError("Artifact relative_path must be a non-empty string.")

    cleaned = path.strip()

    # Reject Unix absolute paths
    if cleaned.startswith("/"):
        raise ScanStateValidationError(f"Absolute Unix path is forbidden for artifact: '{cleaned}'")

    # Reject Windows drive letters (e.g. C:\... or C:/...)
    if re.match(r"^[a-zA-Z]:[/\\]", cleaned):
        raise ScanStateValidationError(f"Windows absolute path is forbidden for artifact: '{cleaned}'")

    # Reject path traversal (..)
    parts = re.split(r"[/\\]", cleaned)
    if ".." in parts:
        raise ScanStateValidationError(f"Path traversal ('..') is forbidden in artifact path: '{cleaned}'")

    # Reject known host prefixes if embedded
    if any(cleaned.startswith(p) for p in FORBIDDEN_PATH_PREFIXES):
        raise ScanStateValidationError(f"Host path prefix forbidden in artifact path: '{cleaned}'")


def create_initial_scan_state(
    scan_id: str,
    target_url: str,
    platform: str = "android",
    package_name: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Factory creating a valid canonical product-level initial scan state.

    Integrity rules enforced:
    - app_acquisition: running
    - static_analysis: pending
    - dynamic_analysis: not_available (scheduled for subsequent milestone)
    - agent_analysis: not_available (not available in this scan)
    - report_generation: pending
    - all artifacts: available=False, relative_path=None
    """
    if not scan_id or not isinstance(scan_id, str):
        raise ScanStateValidationError("scan_id must be a non-empty string.")
    if not target_url or not isinstance(target_url, str):
        raise ScanStateValidationError("target_url must be a non-empty string.")

    norm_platform = str(platform).strip().lower()
    if norm_platform not in ("android", "ios"):
        raise ScanStateValidationError(f"Unsupported platform '{platform}'. Expected 'android' or 'ios'.")

    now = created_at or _utc_now_iso()

    state: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan_id.strip(),
        "target": {
            "url": target_url.strip(),
            "platform": norm_platform,
            "package_name": package_name.strip() if (package_name and isinstance(package_name, str)) else None,
        },
        "overall_status": "running",
        "current_stage": "app_acquisition",
        "timestamps": {
            "created_at": now,
            "updated_at": now,
            "completed_at": None,
        },
        "stages": {
            "app_acquisition": {
                "status": "running",
                "message": "Acquiring package and verifying structure...",
                "started_at": now,
                "completed_at": None,
            },
            "static_analysis": {
                "status": "pending",
                "message": "Waiting for package acquisition...",
                "started_at": None,
                "completed_at": None,
            },
            "dynamic_analysis": {
                "status": "not_available",
                "message": "Scheduled for subsequent milestone",
                "started_at": None,
                "completed_at": None,
            },
            "agent_analysis": {
                "status": "not_available",
                "message": "Not available in this scan",
                "started_at": None,
                "completed_at": None,
            },
            "report_generation": {
                "status": "pending",
                "message": "Waiting for analysis stages...",
                "started_at": None,
                "completed_at": None,
            },
        },
        "artifacts": {
            "static_analysis_report": {"available": False, "relative_path": None},
            "dynamic_analysis_report": {"available": False, "relative_path": None},
            "agent_report": {"available": False, "relative_path": None},
        },
        "error": None,
    }

    validate_scan_state(state)
    return state


def validate_scan_state(state: dict[str, Any], run_dir: str | Path | None = None) -> None:
    """Validates structural schema, stage vocabulary, artifact safety, and product integrity rules."""
    if not isinstance(state, dict):
        raise ScanStateValidationError("Scan state must be a dictionary.")

    # 1. Schema version
    if state.get("schema_version") != SCHEMA_VERSION:
        raise ScanStateValidationError(f"Invalid schema_version '{state.get('schema_version')}'. Expected '{SCHEMA_VERSION}'.")

    # 2. Identity & Target
    scan_id = state.get("scan_id")
    if not scan_id or not isinstance(scan_id, str):
        raise ScanStateValidationError("Missing or invalid scan_id in state.")

    target = state.get("target")
    if not isinstance(target, dict) or not target.get("url"):
        raise ScanStateValidationError("Missing or invalid target specification in state.")

    # 3. Overall status & Current stage
    overall = state.get("overall_status")
    if overall not in CANONICAL_STATUSES:
        raise ScanStateValidationError(f"Invalid overall_status '{overall}'. Expected one of {CANONICAL_STATUSES}.")

    curr_stage = state.get("current_stage")
    if curr_stage is not None and curr_stage not in CANONICAL_STAGES and curr_stage not in ("completed", "interrupted"):
        raise ScanStateValidationError(f"Invalid current_stage '{curr_stage}'. Expected one of {CANONICAL_STAGES}, 'completed', 'interrupted', or None.")

    # 4. Stages
    stages = state.get("stages")
    if not isinstance(stages, dict):
        raise ScanStateValidationError("Missing stages dictionary in scan state.")

    for canonical_stage in CANONICAL_STAGES:
        if canonical_stage not in stages:
            raise ScanStateValidationError(f"Missing required canonical stage '{canonical_stage}' in stages.")
        stage_obj = stages[canonical_stage]
        if not isinstance(stage_obj, dict):
            raise ScanStateValidationError(f"Stage '{canonical_stage}' must be an object.")
        st_status = stage_obj.get("status")
        if st_status not in CANONICAL_STATUSES:
            raise ScanStateValidationError(
                f"Invalid status '{st_status}' for stage '{canonical_stage}'. Expected one of {CANONICAL_STATUSES}."
            )

    # 5. Artifacts
    artifacts = state.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ScanStateValidationError("Missing artifacts dictionary in scan state.")

    for art_key in CANONICAL_ARTIFACTS:
        if art_key not in artifacts:
            raise ScanStateValidationError(f"Missing required canonical artifact '{art_key}'.")
        art_obj = artifacts[art_key]
        if not isinstance(art_obj, dict):
            raise ScanStateValidationError(f"Artifact entry '{art_key}' must be an object.")
        avail = art_obj.get("available")
        if not isinstance(avail, bool):
            raise ScanStateValidationError(f"Artifact '{art_key}' 'available' flag must be boolean.")
        rel_path = art_obj.get("relative_path")
        if avail:
            validate_artifact_relative_path(rel_path)
        elif rel_path is not None:
            validate_artifact_relative_path(rel_path)

    # 6. Integrity Rules
    # Rule 1: dynamic_analysis cannot be completed unless explicitly supported with available dynamic report
    dyn_status = stages.get("dynamic_analysis", {}).get("status")
    dyn_art = artifacts.get("dynamic_analysis_report", {})
    if dyn_status == "completed" and not dyn_art.get("available"):
        raise ScanStateValidationError(
            "Integrity Rule #1 Violation: dynamic_analysis cannot be 'completed' without available dynamic_analysis_report."
        )

    if dyn_art.get("available"):
        if dyn_art.get("relative_path") != "dynamic_analysis_report.json":
            raise ScanStateValidationError("Dynamic report must reference the root canonical filename.")
        if run_dir is not None:
            from src.dynamic.report.models import DynamicReportError, load_dynamic_analysis_report
            try:
                report = load_dynamic_analysis_report(run_dir, state["scan_id"])
                if dyn_status == 'completed' and report.get('runtime_availability', {}).get('status') == 'unavailable':
                    raise ScanStateValidationError('Unavailable runtime cannot complete Dynamic analysis.')
            except DynamicReportError as exc:
                raise ScanStateValidationError("Dynamic report availability requires a valid canonical file.") from exc

    # Rule 2: full report_generation cannot be completed if only static report is available
    rep_status = stages.get("report_generation", {}).get("status")
    static_avail = artifacts.get("static_analysis_report", {}).get("available", False)
    dyn_avail = artifacts.get("dynamic_analysis_report", {}).get("available", False)
    agent_avail = artifacts.get("agent_report", {}).get("available", False)

    if rep_status == "completed":
        if not (static_avail and dyn_avail and agent_avail):
            raise ScanStateValidationError(
                "Integrity Rule #2 Violation: report_generation cannot be 'completed' when only a subset of canonical reports exist (use 'partial' instead)."
            )


def update_stage_status(
    state: dict[str, Any],
    stage_name: str,
    status: str,
    message: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
) -> dict[str, Any]:
    """Updates a single stage status and timestamps in-place, returning the state."""
    if stage_name not in CANONICAL_STAGES:
        raise ScanStateValidationError(f"Unknown stage '{stage_name}'. Expected one of {CANONICAL_STAGES}.")
    if status not in CANONICAL_STATUSES:
        raise ScanStateValidationError(f"Unknown status '{status}'. Expected one of {CANONICAL_STATUSES}.")

    now = _utc_now_iso()
    st_obj = state.setdefault("stages", {}).setdefault(stage_name, {})
    st_obj["status"] = status
    if message is not None:
        st_obj["message"] = str(message)

    if status == "running" and not st_obj.get("started_at"):
        st_obj["started_at"] = started_at or now

    if status in ("completed", "partial", "failed", "interrupted"):
        st_obj["completed_at"] = completed_at or now

    state.setdefault("timestamps", {})["updated_at"] = now
    validate_scan_state(state)
    return state


def mark_artifact_available(
    state: dict[str, Any],
    artifact_name: str,
    relative_path: str,
) -> dict[str, Any]:
    """Marks a canonical artifact as available with validated relative path."""
    if artifact_name not in CANONICAL_ARTIFACTS:
        raise ScanStateValidationError(f"Unknown artifact '{artifact_name}'. Expected one of {CANONICAL_ARTIFACTS}.")

    validate_artifact_relative_path(relative_path)

    art_dict = state.setdefault("artifacts", {}).setdefault(artifact_name, {})
    art_dict["available"] = True
    art_dict["relative_path"] = relative_path.strip()

    state.setdefault("timestamps", {})["updated_at"] = _utc_now_iso()
    validate_scan_state(state)
    return state


def set_overall_status(
    state: dict[str, Any],
    status: str,
    current_stage: str | None = None,
    error: str | None = None,
    completed_at: str | None = None,
) -> dict[str, Any]:
    """Sets top-level overall_status, optional current_stage, and error."""
    if status not in CANONICAL_STATUSES:
        raise ScanStateValidationError(f"Invalid overall_status '{status}'. Expected one of {CANONICAL_STATUSES}.")

    now = _utc_now_iso()
    state["overall_status"] = status
    if current_stage is not None:
        state["current_stage"] = current_stage
    if error is not None:
        state["error"] = str(error)

    timestamps = state.setdefault("timestamps", {})
    timestamps["updated_at"] = now
    if status in ("completed", "partial", "failed", "interrupted"):
        timestamps["completed_at"] = completed_at or now

    validate_scan_state(state)
    return state


def save_scan_state(run_dir: str | Path, state: dict[str, Any]) -> Path:
    """Atomically persists scan_state.json into run_dir.

    Validates state before write, writes to temporary file in run_dir,
    and replaces target destination via os.replace to guarantee atomic persistence.
    """
    dest_dir = Path(run_dir).resolve()
    validate_scan_state(state, dest_dir)

    dest_dir.mkdir(parents=True, exist_ok=True)
    target_file = dest_dir / STATE_FILENAME

    write_json_atomic(target_file, state, durable=True)

    return target_file


def load_scan_state(run_dir: str | Path, *, validate_artifacts: bool = True) -> dict[str, Any] | None:
    """Loads and validates scan_state.json from run_dir.

    Returns:
        dict if scan_state.json exists and is valid.
        None if scan_state.json does not exist.

    Raises:
        ScanStateCorruptionError if file exists but contains invalid JSON or corrupted content.
        ScanStateValidationError if JSON is valid but violates the scan state contract.
    """
    dest_dir = Path(run_dir).resolve()
    state_file = dest_dir / STATE_FILENAME

    if not state_file.is_file():
        return None

    try:
        with open(state_file, "r", encoding="utf-8") as f:
            content = f.read()
            if not content.strip():
                raise ScanStateCorruptionError(f"Corrupted scan_state.json: file is empty at '{state_file}'")
            data = json.loads(content)
    except json.JSONDecodeError as err:
        raise ScanStateCorruptionError(f"Corrupted scan_state.json: invalid JSON syntax ({err}) at '{state_file}'") from err
    except OSError as err:
        raise ScanStateCorruptionError(f"Failed to read scan_state.json at '{state_file}': {err}") from err

    validate_scan_state(data, dest_dir if validate_artifacts else None)
    return data


def sync_dynamic_report_artifact(state: dict[str, Any], run_dir: str | Path, *, complete_stage: bool = True) -> bool:
    """Reconcile physical integrity before registering or completing the dynamic stage."""
    from src.dynamic.report.models import DynamicReportError, load_dynamic_analysis_report
    try:
        report = load_dynamic_analysis_report(run_dir, state["scan_id"])
        available = True
    except DynamicReportError:
        available = False
    state["artifacts"]["dynamic_analysis_report"] = {
        "available": available, "relative_path": "dynamic_analysis_report.json" if available else None,
    }
    stage = state["stages"]["dynamic_analysis"]
    if available and complete_stage and report.get('runtime_availability', {}).get('status') == 'unavailable':
        stage['status'] = 'not_available' if report['report_status'] == 'unavailable' else 'partial'
        stage['completed_at'] = None
        stage['message'] = report['runtime_availability']['message']
        state['stages']['report_generation']['status'] = 'partial'
    elif available and complete_stage:
        stage["status"] = "completed"
        stage["completed_at"] = stage.get("completed_at") or _utc_now_iso()
        stage["message"] = "Canonical dynamic report generated and validated; coverage is described in the report."
        state["stages"]["report_generation"]["status"] = "partial"
        state["stages"]["report_generation"]["message"] = "Canonical dynamic report available; additional analysis reports pending."
    elif not available and stage.get("status") == "completed":
        stage["status"] = "partial"
        stage["message"] = "Canonical dynamic report is missing or invalid; completion is unavailable."
        if state["stages"]["report_generation"].get("status") == "completed":
            state["stages"]["report_generation"]["status"] = "partial"
    return available


def sync_agent_stage_and_artifacts(state: dict[str, Any], run_dir: str | Path) -> bool:
    """Reconciles Agent Analysis stage status and artifacts based on evidence.

    Distinct canonical states supported:
    - completed: Agent planning completed, valid result/trace produced, zero executions allowed.
    - partial: Agent ran but evidence was insufficient, policy blocked execution,
               or model failed after stage start.
    - not_available: Agent stage could not start (provider or runtime environment unavailable).
    - not_run: Agent intentionally skipped because no grounded EndpointContext or prerequisite evidence existed.
    """
    dest_path = Path(run_dir)
    agent_artifact_candidates = (
        "agent_report.json",
        "agent_trace.json",
        "agent/validation_trace.json",
        "agent/matrix_planning.json",
        "agent/agent_trace.json",
    )
    found_artifact: Path | None = None
    relative_path: str | None = None
    for rel in agent_artifact_candidates:
        candidate = dest_path / rel
        if candidate.is_file():
            found_artifact = candidate
            relative_path = rel
            break

    stage = state["stages"]["agent_analysis"]
    if found_artifact is not None:
        state["artifacts"]["agent_report"] = {
            "available": True,
            "relative_path": relative_path,
        }
        trace_data: dict[str, Any] = {}
        try:
            with open(found_artifact, "r", encoding="utf-8") as af:
                trace_data = json.load(af)
        except Exception:
            pass

        st = str(trace_data.get("status") or "").lower()
        reason_codes = [str(r).upper() for r in trace_data.get("reason_codes", ())]
        policy_data = trace_data.get("policy") or {}
        policy_status = str(policy_data.get("status") or "").lower() if isinstance(policy_data, dict) else ""
        needs_evidence_cnt = policy_data.get("needs_evidence_count", 0) if isinstance(policy_data, dict) else 0

        has_policy_block = (
            any("POLICY" in r or "DISALLOWED" in r or "NEEDS_EVIDENCE" in r for r in reason_codes)
            or needs_evidence_cnt > 0
            or policy_status == "needs_evidence"
        )
        has_provider_error = any("TIMEOUT" in r or "MODEL_ERROR" in r or "UNAVAILABLE" in r for r in reason_codes)

        if st in ("completed", "no_relevant_tests") and not has_policy_block and not has_provider_error:
            stage["status"] = "completed"
            stage["message"] = (
                "Planning completed; no relevant security tests were applicable."
                if (st == "no_relevant_tests" or not trace_data.get("executions"))
                else "Planning and security validation completed."
            )
            stage["completed_at"] = stage.get("completed_at") or _utc_now_iso()
        elif has_policy_block or st in ("partial", "needs_evidence", "evaluated") or (st in ("completed", "no_relevant_tests") and has_policy_block):
            stage["status"] = "partial"
            stage["message"] = "Planning completed, but runtime evidence was insufficient for validation."
            stage["completed_at"] = stage.get("completed_at") or _utc_now_iso()
        elif has_provider_error or st in ("stopped", "model_error"):
            analyst_data = trace_data.get("analyst") or {}
            analyst_status = analyst_data.get("status") if isinstance(analyst_data, dict) else None
            if analyst_status == "completed" or trace_data.get("planner") is not None:
                stage["status"] = "partial"
                stage["message"] = "Agent analysis partially completed; provider error encountered."
            else:
                stage["status"] = "not_available"
                stage["message"] = "Agent stage could not start; model provider is unavailable."
            stage["completed_at"] = None
        else:
            stage["status"] = "partial"
            stage["message"] = "Planning completed with partial coverage."
            stage["completed_at"] = stage.get("completed_at") or _utc_now_iso()
        return True

    state["artifacts"]["agent_report"] = {
        "available": False,
        "relative_path": None,
    }
    stage["completed_at"] = None

    dynamic_status = state.get("stages", {}).get("dynamic_analysis", {}).get("status")
    if dynamic_status == "running":
        return False

    ep_file = dest_path / "dynamic" / "endpoint_contexts.json"
    if not ep_file.is_file():
        ep_file = dest_path / "endpoint_contexts.json"

    ep_count = 0
    ep_file_exists = ep_file.is_file()
    if ep_file_exists:
        try:
            with open(ep_file, "r", encoding="utf-8") as ef:
                ep_data = json.load(ef)
                endpoints = ep_data.get("endpoints") or ep_data.get("endpoint_contexts") or []
                if isinstance(endpoints, list):
                    ep_count = len(endpoints)
                else:
                    ep_count = ep_data.get("summary", {}).get("endpoint_context_count", 0)
        except Exception:
            ep_count = 0

    if ep_file_exists:
        stage["status"] = "not_run"
        if ep_count == 0:
            stage["message"] = "No grounded endpoint context was available for Agent analysis."
        else:
            stage["message"] = "Agent analysis was skipped."
    elif dynamic_status in ("not_available", "failed", "interrupted"):
        stage["status"] = "not_available"
        stage["message"] = "Agent runtime is unavailable in this scan."
    else:
        stage["status"] = "not_run"
        stage["message"] = "No grounded endpoint context was available for Agent analysis."

    return False


class ScanStateCheckpointer:
    """Coordinates product-level scan state checkpoints with pipeline execution."""

    def __init__(
        self,
        run_dir: str | Path,
        scan_id: str,
        target_url: str,
        platform: str = "android",
        package_name: str | None = None,
    ) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.scan_id = str(scan_id).strip()
        self.target_url = str(target_url).strip()
        self.platform = str(platform).strip().lower()
        self.package_name = str(package_name).strip() if package_name else None
        self._lock = threading.Lock()
        self._state: dict[str, Any] | None = None
        self._has_preprocessing_warning: bool = False
        self._demo_completed: bool = False
        self.last_save_error: Exception | None = None

    def init_state(self) -> dict[str, Any]:
        """Creates and atomically persists the initial scan state."""
        with self._lock:
            self._state = create_initial_scan_state(
                scan_id=self.scan_id,
                target_url=self.target_url,
                platform=self.platform,
                package_name=self.package_name,
            )
            self._safe_save()
            return self._state

    def get_state(self) -> dict[str, Any] | None:
        """Returns the in-memory state or loads from disk if None."""
        with self._lock:
            if self._state is None:
                self._state = load_scan_state(self.run_dir)
            return self._state

    def _ensure_state(self) -> dict[str, Any]:
        """Ensures a valid state dictionary exists in memory."""
        if self._state is None:
            loaded = load_scan_state(self.run_dir)
            if loaded is not None:
                self._state = loaded
            else:
                self._state = create_initial_scan_state(
                    scan_id=self.scan_id,
                    target_url=self.target_url,
                    platform=self.platform,
                    package_name=self.package_name,
                )
        return self._state

    def on_pipeline_progress(
        self,
        stage: str,
        state: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        """Maps an internal pipeline progress event to canonical product scan_state."""
        with self._lock:
            st = self._ensure_state()
            safe_msg = self._clean_message(message)

            if stage == "acquisition":
                if state == "running":
                    update_stage_status(st, "app_acquisition", "running", safe_msg)
                    st["current_stage"] = "app_acquisition"
                elif state == "success":
                    update_stage_status(st, "app_acquisition", "completed", safe_msg)
                    if data and isinstance(data, dict):
                        pkg = data.get("package_name") or data.get("app", {}).get("package_name")
                        if pkg and not st["target"].get("package_name"):
                            st["target"]["package_name"] = str(pkg).strip()
                    # Transition to static_analysis
                    update_stage_status(
                        st,
                        "static_analysis",
                        "running",
                        "Starting static analysis and resource decoding...",
                    )
                    st["current_stage"] = "static_analysis"
                elif state == "failed":
                    update_stage_status(st, "app_acquisition", "failed", safe_msg)
                    set_overall_status(
                        st,
                        "failed",
                        current_stage="app_acquisition",
                        error=safe_msg,
                    )

            elif stage == "preprocessing":
                # Preprocessing is part of product-level static_analysis
                if state == "running":
                    update_stage_status(st, "static_analysis", "running", safe_msg)
                    st["current_stage"] = "static_analysis"
                elif state == "warning":
                    self._has_preprocessing_warning = True
                    update_stage_status(st, "static_analysis", "running", safe_msg)
                elif state == "success":
                    update_stage_status(st, "static_analysis", "running", safe_msg)
                elif state == "failed":
                    update_stage_status(st, "static_analysis", "failed", safe_msg)
                    set_overall_status(
                        st,
                        "failed",
                        current_stage="static_analysis",
                        error=safe_msg,
                    )

            elif stage == "static_analysis":
                if state == "running":
                    update_stage_status(st, "static_analysis", "running", safe_msg)
                    st["current_stage"] = "static_analysis"
                elif state == "success":
                    static_stat = "partial" if self._has_preprocessing_warning else "completed"
                    if data and isinstance(data, dict):
                        pkg = data.get("app", {}).get("package_name") or data.get("package_name")
                        if pkg and not st["target"].get("package_name"):
                            st["target"]["package_name"] = str(pkg).strip()
                    update_stage_status(st, "static_analysis", static_stat, safe_msg)
                elif state == "failed":
                    update_stage_status(st, "static_analysis", "failed", safe_msg)
                    set_overall_status(
                        st,
                        "failed",
                        current_stage="static_analysis",
                        error=safe_msg,
                    )

            elif stage == "runtime":
                # CRITICAL RULE: Runtime is launch/preflight, NOT dynamic analysis.
                # dynamic_analysis MUST remain "not_available" until exploration starts.
                # Later runtime failure does NOT fail or erase completed static_analysis.
                if state in {'failed', 'skipped'}:
                    update_stage_status(st, 'dynamic_analysis', 'not_available', 'Runtime analysis unavailable.')
                    st['current_stage'] = 'report_generation'
                    if state == 'failed':
                        set_overall_status(st, 'running', current_stage='report_generation')

            elif stage == "dynamic_analysis":
                # Week 1 — Day 5: Dynamic UI Exploration execution
                if state == "running":
                    update_stage_status(st, "dynamic_analysis", "running", safe_msg)
                    st["current_stage"] = "dynamic_analysis"
                elif state in ("partial", "completed"):
                    self._sync_artifacts()
                    completed = st["stages"]["dynamic_analysis"]["status"] == "completed"
                    update_stage_status(st, "dynamic_analysis", "completed" if completed else "partial", safe_msg)
                    if st.get("current_stage") == "dynamic_analysis":
                        st["current_stage"] = "report_generation"
                elif state == "failed":
                    update_stage_status(st, "dynamic_analysis", "failed", safe_msg)
                    if st.get("current_stage") == "dynamic_analysis":
                        st["current_stage"] = "report_generation"
                    self._sync_artifacts()

            elif stage == "demo" and state == "completed":
                self._demo_completed = True
                self._sync_artifacts()
                set_overall_status(st, "completed", current_stage="completed")

            self._safe_save()

    def on_reports_generated(self) -> None:
        """Called after report generation to check for and mark canonical static report artifact."""
        with self._lock:
            self._ensure_state()
            self._sync_artifacts()
            self._safe_save()

    def on_demo_completed(self) -> None:
        """Called upon successful completion of the demo pipeline."""
        with self._lock:
            st = self._ensure_state()
            self._demo_completed = True
            self._sync_artifacts()
            set_overall_status(st, "completed", current_stage="completed")
            self._safe_save()

    def on_dynamic_exploration_started(self, message: str = "Dynamic UI exploration in progress...") -> None:
        """Called when dynamic exploration loop starts."""
        with self._lock:
            st = self._ensure_state()
            clean_msg = self._clean_message(message)
            update_stage_status(st, "dynamic_analysis", "running", clean_msg)
            st["current_stage"] = "dynamic_analysis"
            self._safe_save()

    def on_dynamic_exploration_finished(
        self,
        status: str = "partial",
        message: str = "Dynamic exploration produced partial runtime evidence.",
    ) -> None:
        """Called when dynamic exploration loop finishes."""
        with self._lock:
            st = self._ensure_state()
            clean_msg = self._clean_message(message)
            self._sync_artifacts()
            completed = st["stages"]["dynamic_analysis"]["status"] == "completed"
            actual_stat = ("completed" if completed else "partial") if status in ("partial", "completed") else status
            update_stage_status(st, "dynamic_analysis", actual_stat, clean_msg)
            if st.get("current_stage") == "dynamic_analysis":
                st["current_stage"] = "report_generation"
            self._safe_save()

    def on_failure(self, stage: str, error: str) -> None:
        """Called on pipeline failure to persist terminal failure state."""
        with self._lock:
            st = self._ensure_state()
            clean_err = self._clean_message(error)
            self._sync_artifacts()

            if stage == "acquisition":
                update_stage_status(st, "app_acquisition", "failed", clean_err)
                set_overall_status(st, "failed", current_stage="app_acquisition", error=clean_err)
            elif stage in ("preprocessing", "static_analysis"):
                update_stage_status(st, "static_analysis", "failed", clean_err)
                set_overall_status(st, "failed", current_stage="static_analysis", error=clean_err)
            elif stage == "runtime":
                # Runtime availability cannot invalidate completed Static evidence.
                update_stage_status(st, 'dynamic_analysis', 'not_available', 'Runtime analysis unavailable.')
                set_overall_status(st, "completed" if st['stages']['static_analysis']['status'] == 'completed' else "running",
                                   current_stage='report_generation')
            else:
                set_overall_status(st, "failed", error=clean_err)

            self._safe_save()

    def as_progress_callback(
        self,
        chain: Callable[[str, str, str, dict[str, Any] | None], None] | None = None,
    ) -> Callable[[str, str, str, dict[str, Any] | None], None]:
        """Returns a progress_callback function suitable for run_demo."""
        def _cb(stage: str, state: str, message: str, data: dict[str, Any] | None = None) -> None:
            self.on_pipeline_progress(stage, state, message, data)
            if chain:
                chain(stage, state, message, data)
        return _cb

    def _sync_artifacts(self) -> None:
        """Checks disk for canonical artifacts and updates availability and report_generation stage."""
        if self._state is None:
            return
        st = self._state
        try:
            checkpointed = load_scan_state(self.run_dir)
            was_registered = bool(checkpointed and checkpointed["artifacts"]["dynamic_analysis_report"].get("available"))
        except (ScanStateValidationError, ScanStateCorruptionError):
            was_registered = False
        available = sync_dynamic_report_artifact(st, self.run_dir, complete_stage=False)
        if available and not was_registered:
            # Persist availability before upgrading the product stage.
            self._safe_save()
            if self.last_save_error is not None:
                return
        sync_dynamic_report_artifact(st, self.run_dir)
        sync_agent_stage_and_artifacts(st, self.run_dir)
        static_report_path = self.run_dir / "static_analysis_report.json"

        if static_report_path.is_file():
            report_status = "completed"
            try:
                with open(static_report_path, "r", encoding="utf-8") as f:
                    rep_json = json.load(f)
                    report_status = rep_json.get("status", "completed")
            except Exception:
                pass

            if report_status == "partial":
                if st["stages"]["static_analysis"]["status"] != "failed":
                    st["stages"]["static_analysis"]["status"] = "partial"

            mark_artifact_available(st, "static_analysis_report", "static_analysis_report.json")
            if not st["stages"]["report_generation"].get("started_at"):
                st["stages"]["report_generation"]["started_at"] = _utc_now_iso()
            update_stage_status(
                st,
                "report_generation",
                "partial",
                "Static analysis report available; additional analysis reports pending.",
            )

    def _clean_message(self, msg: str | None) -> str:
        """Sanitizes user-facing stage messages against raw host paths or traceback lines."""
        if not msg:
            return ""
        text = str(msg).strip()
        if "\n" in text:
            text = text.split("\n", 1)[0].strip()
        text = re.sub(r"/(?:Users|home|private|tmp|opt)/[^\s'\"]+", "[host_path]", text)
        return text

    def _safe_save(self) -> None:
        """Atomically persists scan state with observability on failure."""
        if self._state is None:
            return
        try:
            save_scan_state(self.run_dir, self._state)
            self.last_save_error = None
        except Exception as exc:
            self.last_save_error = exc
            logger.error(
                "Failed to persist scan_state.json checkpoint for scan '%s' in '%s': %s",
                self.scan_id,
                self.run_dir,
                exc,
                exc_info=True,
            )


def recover_scan_state(
    run_dir: str | Path,
    live_run_ids: set[str] | list[str] | None = None,
) -> dict[str, Any] | None:
    """Recovers, reconciles, and returns persistent product-level scan state for a run directory.

    Lookup & Recovery Rules:
    1. Loads scan_state.json if it exists and is valid.
    2. If scan_state.json was running but the scan is no longer in live_run_ids,
       it classifies overall_status as 'interrupted'.
    3. Preserves completed stages (never rolls back completed/partial static analysis).
    4. Reconciles artifact availability against physical files on disk:
       - If static_analysis_report.json exists, available=True and report_generation='partial'.
       - If static_analysis_report.json is missing, available=False.
    5. In crash edge cases where scan_state.json is corrupted or missing, but
       static_analysis_report.json exists on disk, reconstructs minimal product-safe state.
    6. Does not turn terminal completed/failed/partial scans into interrupted.
    7. Reconciles dynamic completion against validated reports; agent remains unavailable.
    8. Atomically persists recovered updates to prevent repeated reconciliation.
    """
    dest_dir = Path(run_dir).resolve()
    state_file = dest_dir / STATE_FILENAME
    static_report_file = dest_dir / "static_analysis_report.json"
    live_set = set(live_run_ids) if live_run_ids is not None else set()

    state: dict[str, Any] | None = None
    is_corrupted = False

    # 1. Attempt to load existing scan_state.json
    if state_file.is_file():
        try:
            state = load_scan_state(dest_dir, validate_artifacts=False)
        except ScanStateCorruptionError:
            is_corrupted = True
            logger.warning("Corrupted scan_state.json in '%s', checking for recoverable artifacts", dest_dir)
        except Exception as exc:
            is_corrupted = True
            logger.warning("Failed loading scan_state.json in '%s': %s", dest_dir, exc)

    # 2. Reconstruct from existing canonical evidence after state loss/corruption.
    if state is None:
        recovered_dynamic = None
        from src.dynamic.report.models import DynamicReportError, load_dynamic_analysis_report
        try:
            recovered_dynamic = load_dynamic_analysis_report(dest_dir, dest_dir.name)
        except DynamicReportError:
            if (dest_dir / "dynamic_analysis_report.json").is_file():
                logger.warning("Invalid canonical dynamic report cannot support recovery")
        if static_report_file.is_file() or recovered_dynamic is not None:
            rep_status = "completed"
            target_url = "https://unknown.target/app.apk"
            package_name = (recovered_dynamic or {}).get("target", {}).get("package_name")
            try:
                with open(static_report_file, "r", encoding="utf-8") as rf:
                    sdata = json.load(rf)
                    rep_status = sdata.get("status", "completed")
                    target_url = (
                        sdata.get("metadata", {}).get("target_url")
                        or sdata.get("input", {}).get("url")
                        or target_url
                    )
                    package_name = (
                        sdata.get("application", {}).get("package_name")
                        or sdata.get("package_name")
                        or package_name
                    )
            except Exception:
                pass

            state = create_initial_scan_state(
                scan_id=dest_dir.name,
                target_url=target_url,
                platform=(recovered_dynamic or {}).get("target", {}).get("platform", "android"),
                package_name=package_name,
            )
            state["overall_status"] = "interrupted"
            state["current_stage"] = "interrupted"
            state["error"] = "Scan state recovered from canonical analysis artifacts after interruption."
            now = _utc_now_iso()
            state["timestamps"]["updated_at"] = now
            state["timestamps"]["completed_at"] = now

            state["stages"]["app_acquisition"]["status"] = "completed"
            state["stages"]["app_acquisition"]["message"] = "Acquisition completed prior to interruption."
            state["stages"]["static_analysis"]["status"] = rep_status
            state["stages"]["static_analysis"]["message"] = "Static analysis recovered from disk artifact."

            if static_report_file.is_file():
                mark_artifact_available(state, "static_analysis_report", "static_analysis_report.json")
            else:
                state["stages"]["static_analysis"]["status"] = "not_available"
                state["stages"]["static_analysis"]["message"] = "Static report unavailable during recovery."
            sync_dynamic_report_artifact(state, dest_dir)
            sync_agent_stage_and_artifacts(state, dest_dir)
            if not state["stages"]["report_generation"].get("started_at"):
                state["stages"]["report_generation"]["started_at"] = now
            update_stage_status(
                state,
                "report_generation",
                "partial",
                "Canonical analysis reports available; additional analysis reports pending.",
            )
            try:
                save_scan_state(dest_dir, state)
            except Exception:
                pass
            return state

        elif is_corrupted:
            logger.error("Unrecoverable corrupted scan_state.json with no static report in '%s'", dest_dir)
            return None
        else:
            return None

    # 3. We have an existing valid state. Perform classification & reconciliation.
    scan_id = state.get("scan_id") or dest_dir.name
    is_live = scan_id in live_set
    needs_save = False

    # Interrupted classification: running in state, but not live in memory registry
    if state.get("overall_status") == "running" and not is_live:
        state["overall_status"] = "interrupted"
        state["current_stage"] = "interrupted"
        state["error"] = "Scan execution was interrupted before completion."
        now = _utc_now_iso()
        state["timestamps"]["updated_at"] = now
        state["timestamps"]["completed_at"] = now

        # Stages: if running when crashed, mark interrupted (never roll back completed)
        if state["stages"]["app_acquisition"].get("status") == "running":
            state["stages"]["app_acquisition"]["status"] = "interrupted"
            state["stages"]["app_acquisition"]["message"] = "Acquisition was interrupted before completion."
            state["stages"]["app_acquisition"]["completed_at"] = now

        if state["stages"]["static_analysis"].get("status") == "running":
            state["stages"]["static_analysis"]["status"] = "interrupted"
            state["stages"]["static_analysis"]["message"] = "Static analysis was interrupted before completion."
            state["stages"]["static_analysis"]["completed_at"] = now

        needs_save = True

    # 4. Artifact Reconciliation
    static_avail = state.get("artifacts", {}).get("static_analysis_report", {}).get("available", False)
    if static_report_file.is_file():
        rep_status = "completed"
        try:
            with open(static_report_file, "r", encoding="utf-8") as rf:
                sdata = json.load(rf)
                rep_status = sdata.get("status", "completed")
        except Exception:
            pass

        if not static_avail or state["artifacts"]["static_analysis_report"].get("relative_path") != "static_analysis_report.json":
            mark_artifact_available(state, "static_analysis_report", "static_analysis_report.json")
            needs_save = True

        if state["stages"]["report_generation"].get("status") != "partial":
            state["stages"]["report_generation"]["status"] = "partial"
            state["stages"]["report_generation"]["message"] = "Static analysis report available; additional analysis reports pending."
            if not state["stages"]["report_generation"].get("started_at"):
                state["stages"]["report_generation"]["started_at"] = _utc_now_iso()
            needs_save = True

        if rep_status == "partial" and state["stages"]["static_analysis"].get("status") != "failed":
            if state["stages"]["static_analysis"].get("status") != "partial":
                state["stages"]["static_analysis"]["status"] = "partial"
                needs_save = True

    else:
        if static_avail:
            state["artifacts"]["static_analysis_report"]["available"] = False
            state["artifacts"]["static_analysis_report"]["relative_path"] = None
            if state["stages"]["report_generation"].get("status") in ("completed", "partial"):
                state["stages"]["report_generation"]["status"] = "pending" if state["overall_status"] != "interrupted" else "interrupted"
            needs_save = True

    # Recover dynamic availability from canonical integrity, never from execution status alone.
    before_dynamic = json.dumps({"artifacts": state["artifacts"], "stages": state["stages"]}, sort_keys=True)
    sync_dynamic_report_artifact(state, dest_dir)
    sync_agent_stage_and_artifacts(state, dest_dir)
    if before_dynamic != json.dumps({"artifacts": state["artifacts"], "stages": state["stages"]}, sort_keys=True):
        needs_save = True

    if needs_save:
        try:
            state["timestamps"]["updated_at"] = _utc_now_iso()
            validate_scan_state(state)
            save_scan_state(dest_dir, state)
        except Exception as exc:
            logger.error("Failed persisting recovered scan_state.json in '%s': %s", dest_dir, exc, exc_info=True)

    validate_scan_state(state)
    return state


