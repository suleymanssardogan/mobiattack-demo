"""Canonical dynamic product report integrity and atomic persistence."""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import tempfile
from typing import Any

REPORT_FILENAME = "dynamic_analysis_report.json"
COVERAGE_STATES = {"available", "partial", "unavailable", "not_observed", "unknown"}


class DynamicReportError(ValueError):
    """Invalid canonical report or source evidence."""


class DynamicReportUnavailable(DynamicReportError):
    """Insufficient dynamic execution evidence for a canonical report."""


def _validate_dynamic_analysis_report(report: dict[str, Any], scan_id: str | None = None) -> None:
    if not isinstance(report, dict):
        raise DynamicReportError("Dynamic report must be an object")
    if report.get("schema_version") != "1.0" or report.get("report_type") != "dynamic_analysis":
        raise DynamicReportError("Unsupported dynamic report schema")
    if report.get("report_status") != "completed" or not isinstance(report.get("scan_id"), str) or not report["scan_id"]:
        raise DynamicReportError("Invalid dynamic report identity/status")
    if scan_id is not None and report["scan_id"] != scan_id:
        raise DynamicReportError("Dynamic report scan identity mismatch")
    if report.get("analysis_coverage") not in {"complete", "partial"}:
        raise DynamicReportError("Invalid analysis coverage")
    for section in ("target", "coverage", "preflight", "session", "exploration", "routes", "runtime", "traffic",
                    "traffic_correlation", "api_correlation", "endpoint_context_summary", "evidence", "evidence_status"):
        if not isinstance(report.get(section), dict):
            raise DynamicReportError(f"Invalid dynamic report section: {section}")
    expected_capabilities = {"ui_exploration", "runtime_observation", "http_visibility", "https_visibility", "api_correlation", "endpoint_contexts"}
    if set(report["coverage"]) != expected_capabilities or any(v not in COVERAGE_STATES for v in report["coverage"].values()):
        raise DynamicReportError("Invalid capability coverage")
    exploration = report["exploration"]
    if exploration.get("status") not in {"completed", "partial", "failed"} or not report["session"].get("session_id"):
        raise DynamicReportError("Missing minimum execution evidence")
    for key in ("steps_attempted", "actions_succeeded", "actions_failed", "screens_observed", "transitions_recorded"):
        value = exploration.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise DynamicReportError("Invalid exploration counts")
    if not any(exploration[k] > 0 for k in ("steps_attempted", "actions_succeeded", "screens_observed", "transitions_recorded")):
        raise DynamicReportError("No dynamic execution evidence")
    if not isinstance(report.get("endpoint_contexts"), list) or any(not isinstance(row, dict) or not row.get("endpoint_context_id") for row in report["endpoint_contexts"]):
        raise DynamicReportError("Invalid endpoint rows")
    if 'security_results' in report:
        from src.dynamic.security.reporting import validate_security_section
        try:
            validate_security_section(report['security_results'], report['session']['session_id'],
                                      {row['endpoint_context_id'] for row in report['endpoint_contexts']})
        except ValueError as exc:
            raise DynamicReportError('Invalid security results section') from exc
        if report['security_results']['coverage'] != 'available' and report['analysis_coverage'] != 'partial':
            raise DynamicReportError('Incomplete security coverage cannot be complete')
    count_fields = {
        "routes": ("node_count", "edge_count", "action_count", "self_loop_count", "system_boundary_count", "external_boundary_count"),
        "runtime": ("action_evidence_count", "correlated_action_count", "pid_change_count", "process_death_count", "activity_change_count", "fatal_count", "crash_count"),
        "traffic": ("total_transactions", "http_count", "https_count", "hosts_count"),
        "traffic_correlation": ("actions_with_evidence", "transaction_correlated_action_count", "partial_correlation_count", "unavailable_correlation_count"),
        "api_correlation": ("static_candidate_count", "dynamic_endpoint_count", "correlated_count", "static_only_count", "dynamic_only_count", "exact_count", "template_count", "method_mismatch_count"),
        "endpoint_context_summary": ("endpoint_context_count", "runtime_observed_count", "static_only_count", "dynamic_only_count"),
    }
    for section, fields in count_fields.items():
        for field in fields:
            value = report[section].get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise DynamicReportError("Invalid dynamic summary count")
    if report["endpoint_context_summary"]["endpoint_context_count"] != len(report["endpoint_contexts"]):
        raise DynamicReportError("Endpoint count mismatch")
    duration = exploration.get("duration_seconds")
    if duration is not None and (not isinstance(duration, (int, float)) or isinstance(duration, bool) or not math.isfinite(duration) or duration < 0):
        raise DynamicReportError("Invalid exploration duration")
    if not isinstance(report.get("generated_at"), str) or not report["generated_at"]:
        raise DynamicReportError("Missing generation timestamp")
    for row in report["endpoint_contexts"]:
        if (not isinstance(row.get("host"), str) or not isinstance(row.get("path"), str)
                or row.get("match_type") not in {"exact", "template", "host_path", "method_mismatch", "static_only", "dynamic_only"}
                or row.get("confidence") not in {"high", "medium", "low", None}
                or not isinstance(row.get("auth"), dict) or not isinstance(row.get("evidence_refs"), dict)):
            raise DynamicReportError("Invalid endpoint row schema")
        if any(value is not None and not isinstance(value, bool) for value in row["auth"].values()):
            raise DynamicReportError("Auth metadata must contain presence flags only")
    for key, path in report["evidence"].items():
        if not isinstance(path, str) or not path.startswith("dynamic/") or ".." in path.split("/") or Path(path).is_absolute():
            raise DynamicReportError("Unsafe evidence reference")
    forbidden = {"body", "headers", "authorization", "cookie", "token", "access_token", "refresh_token", "api_key", "secret", "raw_logs", "log_events", "compact_new_events", "password", "is_vulnerable",
                 "vulnerability", "vulnerabilities", "findings", "severity", "risk_score", "auth_broken", "bola_detected", "idor_detected", "agent_analysis"}
    def check(value: Any) -> None:
        if isinstance(value, dict):
            if forbidden & value.keys():
                raise DynamicReportError("Forbidden payload in dynamic report")
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
    check(report)


def validate_dynamic_analysis_report(report: dict[str, Any], scan_id: str | None = None) -> None:
    """Explicitly reject invalid JSON structures rather than allowing accidental availability."""
    try:
        _validate_dynamic_analysis_report(report, scan_id)
    except (TypeError, KeyError, AttributeError) as exc:
        raise DynamicReportError("Invalid dynamic report schema") from exc


def load_dynamic_analysis_report(run_dir: str | Path, scan_id: str | None = None) -> dict[str, Any]:
    try:
        report = json.loads((Path(run_dir) / REPORT_FILENAME).read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise DynamicReportError("Canonical dynamic report missing or corrupt") from exc
    validate_dynamic_analysis_report(report, scan_id)
    return report


def save_dynamic_analysis_report(run_dir: str | Path, report: dict[str, Any]) -> Path:
    validate_dynamic_analysis_report(report)
    directory = Path(run_dir)
    directory.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=directory, prefix=".tmp_dynamic_report_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, directory / REPORT_FILENAME)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return directory / REPORT_FILENAME
