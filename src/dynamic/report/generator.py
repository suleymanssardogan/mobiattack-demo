"""Pure projection of finalized canonical artifacts into a dynamic product report."""
from __future__ import annotations
from src.dynamic.exploration.frontier import exploration_summary

from collections import Counter
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
from typing import Any

from src.dynamic.correlation.api_correlator import normalize_host, normalize_path
from src.dynamic.correlation.models import sanitize_provenance_paths
from .models import (COVERAGE_STATES, DynamicReportError, DynamicReportUnavailable,
                     verified_startup, validate_dynamic_analysis_report, save_dynamic_analysis_report, load_dynamic_analysis_report)

ARTIFACTS = {"preflight": "preflight_result.json", "session": "session.json", "exploration": "exploration_result.json",
             "routes": "route_graph.json", "runtime": "runtime_evidence.json", "traffic": "traffic.json",
             "traffic_correlation": "traffic_evidence.json", "api_correlation": "api_correlation.json",
             "endpoint_contexts": "endpoint_contexts.json", "security_results": "security_results.json", "runtime_availability": "runtime_availability.json"}
LIST_FIELDS = {"routes": ("nodes", "edges"), "runtime": ("actions",), "traffic": ("transactions",),
               "traffic_correlation": ("actions",), "api_correlation": ("correlations",), "endpoint_contexts": ("endpoints",)}


def _safe(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    # Do not carry query values, credentials or free-form diagnostics through string fields.
    text = sanitize_provenance_paths(value).split("?", 1)[0].split("#", 1)[0][:256]
    text = re.sub(r"(?i)bearer\s+\S+", "[REDACTED]", text)
    text = re.sub(r"(?i)(password|passwd|token|secret|api[_-]?key|authorization|cookie|session_id)\s*[:=]\s*\S+", "[REDACTED]", text)
    return text


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _states(value: Any) -> str:
    return value if value in COVERAGE_STATES else "unavailable"


def _validate_source(name: str, value: Any) -> None:
    if not isinstance(value, dict):
        raise DynamicReportError("Source artifact must be an object")
    for field in LIST_FIELDS.get(name, ()):
        if not isinstance(value.get(field), list) or any(not isinstance(item, dict) for item in value[field]):
            raise DynamicReportError("Invalid source artifact collection")
    if "schema_version" in value and value["schema_version"] != "1.0":
        raise DynamicReportError("Unsupported source schema")
    if name == "preflight":
        if value.get("status") not in {"PASS", "WARN", "FAIL"}:
            raise DynamicReportError("Invalid preflight status")
        for field in ("application", "runtime", "device"):
            if field in value and not isinstance(value[field], dict):
                raise DynamicReportError("Invalid preflight metadata")
    if name in {"runtime", "traffic_correlation"}:
        for action in value["actions"]:
            if action.get("correlation_status", "available") not in {"available", "partial", "unavailable"}:
                raise DynamicReportError("Invalid action correlation status")
            if name == "runtime" and any(field in action and not isinstance(action[field], bool) for field in (
                    "pid_changed", "process_died", "activity_changed", "fatal_appeared", "crash_appeared")):
                raise DynamicReportError("Invalid runtime observation flag")
            if name == "traffic_correlation" and not isinstance(action.get("transaction_ids", []), list):
                raise DynamicReportError("Invalid transaction references")
    if name == "traffic":
        for field in ("http_visibility", "https_visibility"):
            if field in value and value[field] not in COVERAGE_STATES:
                raise DynamicReportError("Invalid traffic visibility")
    if name in {"api_correlation", "endpoint_contexts"}:
        if not isinstance(value.get("summary"), dict):
            raise DynamicReportError("Invalid source summary")
        for key, count in value["summary"].items():
            if key.endswith("_count") and (not isinstance(count, int) or isinstance(count, bool) or count < 0):
                raise DynamicReportError("Invalid summary count")
    if name == "traffic":
        for transaction in value["transactions"]:
            if not isinstance(transaction.get("request"), dict):
                raise DynamicReportError("Invalid request metadata")
            if any(transaction["request"].get(key) is not None and not isinstance(transaction["request"][key], str) for key in ("host", "scheme")):
                raise DynamicReportError("Invalid request identity")
            if transaction.get("response") is not None and not isinstance(transaction["response"], dict):
                raise DynamicReportError("Invalid response metadata")
    if name == "routes" and any(not isinstance(node.get("actions", []), list) for node in value["nodes"]):
        raise DynamicReportError("Invalid route action collection")
    if name == "api_correlation":
        for entry in value["correlations"]:
            if entry.get("match_type") not in {"exact", "template", "host_path", "method_mismatch", "static_only", "dynamic_only"}:
                raise DynamicReportError("Invalid match type")
            if entry.get("confidence") not in {"high", "medium", "low", None}:
                raise DynamicReportError("Invalid correlation confidence")
    if name == "endpoint_contexts":
        for endpoint in value["endpoints"]:
            for key in ("static", "dynamic", "auth", "evidence_refs"):
                if not isinstance(endpoint.get(key, {}), dict):
                    raise DynamicReportError("Invalid endpoint metadata")
            if endpoint.get("static", {}).get("confidence") not in {"high", "medium", "low", None}:
                raise DynamicReportError("Invalid endpoint confidence")
            for key in ("observed_methods", "observed_status_codes"):
                if not isinstance(endpoint.get("dynamic", {}).get(key, []), list):
                    raise DynamicReportError("Invalid endpoint observations")
            if any(not isinstance(refs, list) for refs in endpoint.get("evidence_refs", {}).values()):
                raise DynamicReportError("Invalid endpoint references")
    if name == "session":
        if not isinstance(value.get("session_id"), str) or not value["session_id"] or str(value.get("status", "")).upper() not in {"ACTIVE", "COMPLETED", "FAILED", "ABORTED"}:
            raise DynamicReportError("Invalid executed session")
    if name == "exploration":
        duration = value.get("duration_seconds")
        if duration is not None and (isinstance(duration, bool) or not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration < 0):
            raise DynamicReportError("Invalid exploration duration")
        if value.get("status") not in {"completed", "partial", "failed"}:
            raise DynamicReportError("Invalid exploration status")
        for key in ("steps_attempted", "actions_succeeded", "actions_failed", "screens_observed", "transitions_recorded"):
            if key in value and (not isinstance(value[key], int) or isinstance(value[key], bool) or value[key] < 0):
                raise DynamicReportError("Invalid exploration counts")
    if name in {"api_correlation", "endpoint_contexts"} and not isinstance(value.get("summary"), dict):
        raise DynamicReportError("Invalid source summary")
    if name == "endpoint_contexts" and any(not e.get("endpoint_context_id") for e in value["endpoints"]):
        raise DynamicReportError("Invalid endpoint identity")
    if name in {"preflight", "traffic"}:
        for field in (("application", "runtime", "device") if name == "preflight" else ("summary", "capture")):
            if value.get(field) is not None and not isinstance(value[field], dict):
                raise DynamicReportError("Invalid source metadata")


def _unavailable_report(scan_id, record, target, generated_at):
    """Coverage report only: no fabricated session or execution evidence."""
    report = {'schema_version': '1.0', 'report_type': 'dynamic_analysis', 'scan_id': scan_id,
        'generated_at': generated_at or datetime.now(timezone.utc).isoformat(), 'report_status': 'unavailable',
        'analysis_coverage': 'partial', 'target': {'platform': 'android'}, 'runtime_availability': record,
        'coverage': {key: 'unavailable' for key in ('ui_exploration', 'runtime_observation', 'http_visibility',
            'https_visibility', 'api_correlation', 'endpoint_contexts')},
        'preflight': {'status': 'FAIL', 'launch_success': False}, 'session': {},
        'exploration': {'status': 'unavailable', **{key: 0 for key in ('steps_attempted', 'actions_succeeded',
            'actions_failed', 'screens_observed', 'transitions_recorded')}},
        'routes': {}, 'runtime': {}, 'traffic': {}, 'traffic_correlation': {}, 'api_correlation': {},
        'endpoint_context_summary': {}, 'endpoint_contexts': [], 'evidence': {'runtime_availability': 'dynamic/runtime_availability.json'},
        'evidence_status': {'runtime_availability': 'available'},
        'limitations': ['Runtime analysis unavailable on the current execution environment.', record['message']]}
    validate_dynamic_analysis_report(report, scan_id)
    return report


def build_dynamic_analysis_report(scan_id: str, artifacts: dict[str, dict], target: dict | None = None,
                                  generated_at: str | None = None, source_errors: dict[str, str] | None = None) -> dict:
    """Pure summarization; source dicts retain their existing canonical schemas."""
    source_errors = dict(source_errors or {})
    valid = {}
    for name in ARTIFACTS:
        if name in artifacts:
            try:
                _validate_source(name, artifacts[name])
                valid[name] = artifacts[name]
            except (DynamicReportError, TypeError, AttributeError):
                source_errors[name] = "invalid_schema"
    record = artifacts.get('runtime_availability')
    if record is not None:
        from src.dynamic.runtime.availability import validate_availability
        try:
            validate_availability(record)
        except ValueError as exc:
            raise DynamicReportError('Invalid runtime availability evidence') from exc
        if record['status'] == 'unavailable' and not any(_count(valid.get('exploration', {}).get(k)) for k in
            ('steps_attempted', 'actions_succeeded', 'screens_observed', 'transitions_recorded')):
            return _unavailable_report(scan_id, record, target, generated_at)
    security_only = False
    if 'session' in valid and 'exploration' not in valid and 'security_results' in valid:
        # A recorded local security execution is not UI exploration. Revalidate
        # its source first; zero UI counts and unavailable UI coverage stay honest.
        from src.dynamic.security.reporting import build_security_section
        section = build_security_section(valid['security_results'], valid['session']['session_id'],
                                         valid.get('endpoint_contexts', {}).get('endpoints', []))
        security_only = any(row['execution_status']=='completed' and (row['validation_outcome']=='validated' or
                            (row['test_category'],row['reason_codes']) in [('object_authorization',['OBJECT_AUTHORIZATION_NOT_ENFORCED']),('function_authorization',['FUNCTION_AUTHORIZATION_NOT_ENFORCED']),('session_handling',['SESSION_INVALIDATION_NOT_ENFORCED'])])
                            for row in section['results'])
        if not security_only and section['results']:
            from src.dynamic.security.reporting import session_observation_complete
            security_only=session_observation_complete(valid['security_results'],valid['session']['session_id'],valid.get('endpoint_contexts',{}).get('endpoints',[]))
        if security_only:
            valid['exploration'] = {'status':'partial','stop_reason':'security_validation_only',
                **{key:0 for key in ('steps_attempted','actions_succeeded','actions_failed','screens_observed','transitions_recorded')}}
    if not {"session", "exploration"} <= valid.keys():
        raise DynamicReportUnavailable("Session and exploration evidence are required")
    session, exploration = valid["session"], valid["exploration"]
    has_ui_execution = any(_count(exploration.get(k)) for k in
                           ("steps_attempted", "actions_succeeded", "screens_observed", "transitions_recorded"))
    runtime_only = (not has_ui_execution and exploration.get('stop_reason') == 'observation_failed'
                    and verified_startup(record, session.get('package_name') or
                                         valid.get('preflight', {}).get('application', {}).get('package_name')))
    if not security_only and not has_ui_execution and not runtime_only:
        raise DynamicReportUnavailable("No dynamic execution observed")
    preflight = valid.get("preflight", {})
    routes = valid.get("routes", {})
    runtime = valid.get("runtime", {})
    traffic = valid.get("traffic", {})
    traffic_corr = valid.get("traffic_correlation", {})
    api = valid.get("api_correlation", {})
    contexts = valid.get("endpoint_contexts", {})
    runtime_actions = runtime.get("actions", [])
    usable = [a for a in runtime_actions if a.get("correlation_status", "available") in {"available", "partial"}]
    runtime_coverage = "unavailable" if "runtime" not in valid else "not_observed" if not usable else "partial" if any(a.get("correlation_status", "available") != "available" for a in runtime_actions) else "available"
    if runtime_only:
        runtime_coverage = "partial"  # Startup observed; action/runtime interval unavailable.
    txs = traffic.get("transactions", [])
    http_vis = _states(traffic.get("http_visibility", "unavailable"))
    https_vis = _states(traffic.get("https_visibility", "unavailable"))
    exploration_metadata = exploration.get('metadata')
    exploration_frontier = exploration_metadata.get('frontier') if isinstance(exploration_metadata, dict) else None
    concise_exploration = exploration_summary(exploration['status'], exploration.get('stop_reason'), exploration_frontier, exploration_metadata.get('budget') if isinstance(exploration_metadata, dict) else None)
    auth_events = exploration_metadata.get('auth_interventions', []) if isinstance(exploration_metadata, dict) else []
    from src.dynamic.session.auth_intervention import STATES, MESSAGES
    auth_events = [e for e in auth_events if isinstance(e, dict) and e.get('state') in STATES
                   and e.get('session_id') == session['session_id']] if isinstance(auth_events, list) else []
    if auth_events:
        auth_state = auth_events[-1]['state']
        concise_exploration['authentication'] = {'state':auth_state, 'message':MESSAGES[auth_state]}
        concise_exploration['note'] += ' ' + MESSAGES[auth_state]
    exploration_complete = (exploration['status'] == 'completed' and concise_exploration['safe_frontier_exhausted'] is True
                            and exploration.get('stop_reason') not in {'max_steps', 'hard_step_ceiling', 'frontier_stagnated', 'runtime_unavailable', 'max_depth', 'deadline', 'observation_failed', 'executor_failed'})
    reported_exploration_status = "partial" if exploration["status"] == "completed" and not exploration_complete else exploration["status"]
    if runtime_only:
        reported_exploration_status = "partial"
        concise_exploration['note'] = "UI observation unavailable; verified application startup evidence preserved. No UI actions or screens observed."
    coverage = {"ui_exploration": "unavailable" if security_only or runtime_only else "available" if exploration_complete else "partial",
                "runtime_observation": runtime_coverage, "http_visibility": http_vis, "https_visibility": https_vis,
                "api_correlation": "available" if "api_correlation" in valid else "unavailable",
                "endpoint_contexts": "available" if "endpoint_contexts" in valid else "unavailable"}
    target = target or {}
    target_summary = {"package_name": _safe(session.get("package_name") or preflight.get("application", {}).get("package_name") or target.get("package_name")),
                      "platform": target.get("platform") if target.get("platform") in {"android", "ios"} else "android"}
    if target.get("source_type") in {"direct_url", "google_play", "local_file", "apk", "ipa", "split_apk"}:
        target_summary["source_type"] = target["source_type"]
    runtime_summary = {"action_evidence_count": len(runtime_actions), "correlated_action_count": len(usable)}
    for out, field in (("pid_change_count", "pid_changed"), ("process_death_count", "process_died"),
                       ("activity_change_count", "activity_changed"), ("fatal_count", "fatal_appeared"), ("crash_count", "crash_appeared")):
        runtime_summary[out] = sum(a.get(field) is True for a in usable)
    nodes, edges = routes.get("nodes", []), routes.get("edges", [])
    hosts = sorted({_safe(normalize_host((t.get("request") or {}).get("host"))) for t in txs if (t.get("request") or {}).get("host")})
    hosts = [host for host in hosts if host]
    traffic_summary = {"backend": {'mitmproxy': 'mitmproxy', 'MitmproxyCaptureBackend': 'mitmproxy',
                       'NativeProxyCaptureBackend': 'native_http', 'native_http': 'native_http', 'unknown': 'unknown'}.get(traffic.get('backend')), "total_transactions": len(txs),
                       "http_count": sum((t.get("request") or {}).get("scheme") == "http" for t in txs),
                       "https_count": sum((t.get("request") or {}).get("scheme") == "https" for t in txs),
                       "hosts": hosts, "hosts_count": len(hosts), "http_visibility": http_vis, "https_visibility": https_vis,
                       "http_visibility_reason": _safe(traffic.get("http_visibility_reason")),
                       "https_visibility_reason": _safe(traffic.get("https_visibility_reason")),
                       "proxy_restored": traffic.get("proxy_restored") if isinstance(traffic.get("proxy_restored"), bool) else None}
    from src.dynamic.traffic.https_compatibility import validate_compatibility_metadata
    try:
        compatibility = validate_compatibility_metadata(traffic.get('https_compatibility'), session['session_id'])
    except ValueError as exc:
        raise DynamicReportError(str(exc)) from exc
    if compatibility:
        if session.get('package_name') and compatibility['package_name'] != session['package_name']:
            raise DynamicReportError('HTTPS compatibility application mismatch')
        if (https_vis != compatibility['visibility'] or
                traffic.get('https_visibility_reason') != compatibility['reason_code']):
            # Backend failure can supersede a prior scoped compatibility result.
            if traffic.get('https_visibility_reason') not in {'capture_backend_failure', 'capture_backend_unavailable'}:
                raise DynamicReportError('HTTPS coverage contradicts compatibility evidence')
        traffic_summary['https_compatibility'] = compatibility
    if http_vis != "available" or https_vis != "available":
        traffic_summary["visibility_note"] = "Traffic visibility is incomplete; unobserved requests may exist."
    actions = traffic_corr.get("actions", [])
    traffic_correlation_summary = {"actions_with_evidence": len(actions),
                                   "transaction_correlated_action_count": sum(bool(a.get("transaction_ids")) for a in actions),
                                   "partial_correlation_count": sum(a.get("correlation_status") == "partial" for a in actions),
                                   "unavailable_correlation_count": sum(a.get("correlation_status") == "unavailable" for a in actions)}
    api_summary = {key: _count(api.get("summary", {}).get(key)) for key in ("static_candidate_count", "dynamic_endpoint_count", "correlated_count", "static_only_count", "dynamic_only_count")}
    match_counts = Counter(c.get("match_type") for c in api.get("correlations", []))
    api_summary.update({f"{key}_count": match_counts[key] for key in ("exact", "template", "method_mismatch")})
    api_summary["visibility_note"] = _safe(api.get("summary", {}).get("visibility_note"))
    rows = []
    correlations = {c.get("correlation_id"): c for c in api.get("correlations", [])}
    for endpoint in contexts.get("endpoints", []):
        static, dynamic = endpoint.get("static") or {}, endpoint.get("dynamic") or {}
        refs = endpoint.get("evidence_refs") or {}
        correlation = next((correlations[c] for c in refs.get("correlation_ids", []) if c in correlations), {})
        row = {"endpoint_context_id": _safe(endpoint["endpoint_context_id"]), "host": _safe(normalize_host(endpoint.get("host"))),
               "path": _safe(normalize_path(endpoint.get("path"))), "static_method": _safe(static.get("static_method")),
               "observed_methods": sorted({_safe(m) for m in dynamic.get("observed_methods", []) if isinstance(m, str)}),
               "match_type": correlation.get("match_type") or static.get("match_type") or "dynamic_only",
               "confidence": correlation.get("confidence") or static.get("confidence"),
               "observation_count": _count(dynamic.get("observation_count")),
               "observed_status_codes": sorted({code for code in dynamic.get("observed_status_codes", []) if isinstance(code, int) and not isinstance(code, bool)}),
               "auth": {key: value for key, value in (endpoint.get("auth") or {}).items() if key in {
                   "authorization_header_present", "bearer_token_present", "cookie_present", "session_cookie_present", "api_key_header_present"} and (value is None or isinstance(value, bool))},
               "evidence_refs": {key: sorted({_safe(v) for v in refs.get(key, []) if isinstance(v, str)}) for key in sorted({
                   "static_candidate_ids", "correlation_ids", "transaction_ids", "action_ids", "runtime_action_ids"})}}
        row["action_ids"] = row["evidence_refs"]["action_ids"]
        rows.append(row)
    rows.sort(key=lambda e: (e["host"] or "", e["path"] or "", e["static_method"] or "", e["endpoint_context_id"]))
    context_summary = {"endpoint_context_count": len(rows), "runtime_observed_count": sum(bool(e.get("dynamic", {}).get("observed")) for e in contexts.get("endpoints", [])),
                       "static_only_count": sum(r["match_type"] == "static_only" for r in rows), "dynamic_only_count": sum(r["match_type"] == "dynamic_only" for r in rows)}
    # Diagnostics are known error codes only, never arbitrary command/log messages.
    from src.dynamic.preflight.models import ErrorCode
    diagnostic_codes = sorted({e.get("code") for e in preflight.get("errors", []) if isinstance(e, dict) and e.get("code") in {c.value for c in ErrorCode}})
    report = {"schema_version": "1.0", "report_type": "dynamic_analysis", "scan_id": scan_id,
              "generated_at": generated_at or datetime.now(timezone.utc).isoformat(), "report_status": "completed",
              "analysis_coverage": "complete" if all(v == "available" for v in coverage.values()) and not source_errors else "partial",
              "target": target_summary, "coverage": coverage,
              "preflight": {"status": preflight.get("status") if preflight.get("status") in {"PASS", "WARN", "FAIL"} else "unavailable",
                            "launch_success": preflight.get("runtime", {}).get("launch_success") if isinstance(preflight.get("runtime", {}).get("launch_success"), bool) else None,
                            "process_running": preflight.get("application", {}).get("process_running") if isinstance(preflight.get("application", {}).get("process_running"), bool) else None,
                            "diagnostic_codes": diagnostic_codes},
              "session": {"session_id": _safe(session["session_id"]), "status": str(session["status"]).upper(),
                          "started_at": _safe(session.get("started_at")), "ended_at": _safe(session.get("ended_at"))},
              "exploration": {"status": reported_exploration_status, "stop_reason": _safe(exploration.get("stop_reason")),
                              **{k: _count(exploration.get(k)) for k in ("steps_attempted", "actions_succeeded", "actions_failed", "screens_observed", "transitions_recorded")},
                              "duration_seconds": exploration.get("duration_seconds") if isinstance(exploration.get("duration_seconds"), (int, float)) else None,
                              **concise_exploration},
              "routes": {"node_count": len(nodes), "edge_count": len(edges), "root_node_id": _safe(routes.get("root_node_id")),
                         "current_node_id": _safe(routes.get("current_node_id")), "action_count": sum(len(n.get("actions", [])) for n in nodes),
                         "self_loop_count": sum(e.get("source_node_id") == e.get("target_node_id") and bool(e.get("source_node_id")) for e in edges),
                         "system_boundary_count": sum(n.get("is_dialog_or_system") is True for n in nodes),
                         "external_boundary_count": sum(n.get("is_target_package") is False and n.get("is_dialog_or_system") is not True for n in nodes)},
              "runtime": runtime_summary, "traffic": traffic_summary, "traffic_correlation": traffic_correlation_summary,
              "api_correlation": api_summary, "endpoint_context_summary": context_summary, "endpoint_contexts": rows,
              "evidence": {name: f"dynamic/{ARTIFACTS[name]}" for name in sorted(valid) if not (security_only and name=='exploration')},
              "evidence_status": {name: "missing" if security_only and name=='exploration' else "available" if name in valid else "corrupt" if name in source_errors else "missing" for name in sorted(ARTIFACTS) if name != 'runtime_availability' or name in artifacts}}
    if 'security_results' in artifacts or 'security_results' in source_errors:
        from src.dynamic.security.reporting import build_security_section, unavailable_security_section
        security = (build_security_section(valid['security_results'], session['session_id'], contexts.get('endpoints', []))
                    if 'security_results' in valid else unavailable_security_section('SECURITY_SOURCE_INVALID'))
        report['security_results'] = security
        if security['coverage'] != 'available':
            report['analysis_coverage'] = 'partial'
        if 'security_results' in valid and security['limitations'] == ['SECURITY_SOURCE_INVALID']:
            report['evidence_status']['security_results'] = 'corrupt'
    if record is not None:
        report['runtime_availability'] = record
        if record['status'] != 'available':
            report['analysis_coverage'] = 'partial'
    validate_dynamic_analysis_report(report)
    return report


def generate_dynamic_analysis_report(run_dir: str | Path, target: dict | None = None) -> dict:
    """Load finalized sources, persist root report, then read and validate it."""
    run_dir = Path(run_dir)
    artifacts, errors = {}, {}
    for name, filename in ARTIFACTS.items():
        path = run_dir / "dynamic" / filename
        if path.is_file():
            try:
                artifacts[name] = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                errors[name] = "invalid_json"
    report = build_dynamic_analysis_report(run_dir.name, artifacts, target, source_errors=errors)
    from src.dynamic.runtime.execution_target import load_target, environment_summary
    selected = load_target(run_dir)
    if selected:
        if report.get('runtime_availability', {}).get('execution_target_id') not in {None, selected.target_id}:
            raise DynamicReportError('Mismatched execution target evidence')
        report['execution_environment'] = environment_summary(selected)
    save_dynamic_analysis_report(run_dir, report)
    return load_dynamic_analysis_report(run_dir, run_dir.name)
