"""Task 8.1 synthetic canonical reporting, integrity, recovery and API tests."""
import copy
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.dynamic.report import (build_dynamic_analysis_report, generate_dynamic_analysis_report,
    save_dynamic_analysis_report, load_dynamic_analysis_report, validate_dynamic_analysis_report,
    DynamicReportError, DynamicReportUnavailable)
from src.dynamic.report.generator import ARTIFACTS
from src.scan_state import (create_initial_scan_state, save_scan_state, load_scan_state,
    recover_scan_state, ScanStateCheckpointer, ScanStateValidationError, validate_scan_state)


@pytest.fixture
def sources():
    endpoints = []
    correlations = []
    for index, match in enumerate(["exact", "template", "static_only", "dynamic_only", "method_mismatch"]):
        observed = match != "static_only"
        cid, sid, txid = f"corr_{index}", None if match == "dynamic_only" else f"cand_{index}", f"tx{index}"
        correlations.append({"correlation_id": cid, "match_type": match, "confidence": "high" if match == "exact" else "medium"})
        endpoints.append({"endpoint_context_id": f"ctx_{index}", "host": "api.example.com", "path": f"/path/{index}",
                          "static": {"static_candidate_id": sid, "static_method": "GET", "match_type": match},
                          "dynamic": {"observed": observed, "observation_count": 1 if observed else 0,
                                      "observed_methods": ["POST"] if match == "method_mismatch" else ["GET"] if observed else [],
                                      "observed_status_codes": [500, 200, 200] if observed else []},
                          "auth": {"authorization_header_present": True, "bearer_token_present": None,
                                   "cookie_present": True, "session_cookie_present": None, "api_key_header_present": True,
                                   "token": "TOKEN_SECRET"},
                          "request": {"body": {"password": "PASSWORD_SECRET"}}, "response": {"body": "RESPONSE_SECRET"},
                          "evidence_refs": {"correlation_ids": [cid], "static_candidate_ids": [sid] if sid else [],
                                            "transaction_ids": [txid] if observed else [], "action_ids": ["act_2", "act_1"],
                                            "runtime_action_ids": ["act_1"]}})
    return {
        "preflight": {"status": "WARN", "application": {"package_name": "com.example.app", "process_running": True,
                      "install_path": "/Users/alice/work/app.apk"}, "runtime": {"launch_success": True, "fatal_log_snippets": ["LOG_SECRET"]},
                      "device": {"adb_path": "/opt/homebrew/bin/adb"}, "errors": [{"code": "NETWORK_UNAVAILABLE", "message": "Bearer TOKEN_SECRET"}]},
        "session": {"session_id": "session-test", "package_name": "com.example.app", "status": "COMPLETED", "started_at": "2026-10-01T12:00:00Z",
                    "ended_at": "2026-10-01T12:01:00Z", "flows": [{"secret": "SESSION_SECRET"}]},
        "exploration": {"status": "partial", "stop_reason": "max_steps", "steps_attempted": 10, "actions_succeeded": 8,
                        "actions_failed": 2, "screens_observed": 4, "transitions_recorded": 8, "duration_seconds": 60.0,
                        "metadata": {"workspace": "/Users/alice/work"}, "error": "Bearer EXPLORATION_SECRET"},
        "routes": {"root_node_id": "node_1", "current_node_id": "node_2", "nodes": [
                   {"is_target_package": True, "actions": [{"text": "PASSWORD_SECRET"}]},
                   {"is_target_package": False, "is_dialog_or_system": True, "actions": []},
                   {"is_target_package": False, "is_dialog_or_system": False, "actions": []}],
                   "edges": [{"source_node_id": "node_1", "target_node_id": "node_1"}, {"source_node_id": "node_1", "target_node_id": "node_2"}]},
        "runtime": {"actions": [{"action_id": "act_1", "correlation_status": "available", "pid_changed": True, "process_died": True,
                                 "activity_changed": True, "fatal_appeared": True, "crash_appeared": True,
                                 "compact_new_events": [{"message": "LOGCAT_SECRET"}]},
                                {"action_id": "act_2", "correlation_status": "partial", "activity_changed": True},
                                {"action_id": "act_3", "correlation_status": "unavailable", "crash_appeared": True}]},
        "traffic": {"backend": "mitmproxy", "http_visibility": "available", "https_visibility": "partial", "https_visibility_reason": "pinning_suspected",
                    "proxy_restored": True, "transactions": [
                        {"transaction_id": "tx0", "request": {"host": "API.EXAMPLE.COM", "scheme": "http", "headers": {"authorization": "Bearer BEARER_SECRET"},
                                                                  "body": "BODY_SECRET" * 1000, "query": {"q": "QUERY_SECRET"}}},
                        {"transaction_id": "tx1", "request": {"host": "admin.example.com", "scheme": "https", "headers": {"cookie": "sid=COOKIE_SECRET", "x-api-key": "APIKEY_SECRET"}}},
                        {"transaction_id": "tx3", "request": {"host": "api.example.com", "scheme": "https"}}]},
        "traffic_correlation": {"actions": [{"action_id": "act_1", "transaction_ids": ["tx0"], "correlation_status": "available"},
                                           {"action_id": "act_2", "transaction_ids": [], "correlation_status": "partial"},
                                           {"action_id": "act_3", "transaction_ids": [], "correlation_status": "unavailable"}]},
        "api_correlation": {"summary": {"static_candidate_count": 4, "dynamic_endpoint_count": 4, "correlated_count": 3,
                                         "static_only_count": 1, "dynamic_only_count": 1, "visibility_note": "HTTPS visibility is partial."},
                            "correlations": correlations},
        "endpoint_contexts": {"summary": {"endpoint_context_count": 5, "runtime_observed_count": 4}, "endpoints": endpoints},
    }


def report(sources, scan_id="run_test"):
    return build_dynamic_analysis_report(scan_id, sources, {"platform": "android", "source_type": "apk"}, generated_at="2026-10-01T12:02:00Z")


def write_sources(directory, sources):
    dyn = directory / "dynamic"; dyn.mkdir(parents=True, exist_ok=True)
    for key, filename in ARTIFACTS.items():
        if key in sources:
            (dyn / filename).write_text(json.dumps(sources[key]))
    (directory / "static_analysis_report.json").write_text('{"status":"completed","application":{"package_name":"com.example.app"}}')
    return dyn


def init_state(directory):
    state = create_initial_scan_state(directory.name, "https://example.com/app.apk", package_name="com.example.app")
    state["overall_status"] = "completed"; state["current_stage"] = "completed"
    state["stages"]["static_analysis"]["status"] = "completed"
    state["stages"]["dynamic_analysis"]["status"] = "partial"
    save_scan_state(directory, state)
    return state


def test_complete_evidence_builds_valid_report(sources):
    result = report(sources)
    validate_dynamic_analysis_report(result)
    assert result["schema_version"] == "1.0"
    assert result["report_type"] == "dynamic_analysis"
    assert result["report_status"] == "completed"
    assert result["analysis_coverage"] == "partial"
    assert result["target"] == {"package_name": "com.example.app", "platform": "android", "source_type": "apk"}


def test_preflight_and_session_safe(sources):
    result = report(sources)
    assert result["preflight"] == {"status": "WARN", "launch_success": True, "process_running": True,
                                  "diagnostic_codes": ["NETWORK_UNAVAILABLE"]}
    assert result["session"]["status"] == "COMPLETED"
    assert result["session"]["ended_at"] == "2026-10-01T12:01:00Z"


def test_exploration_semantics(sources):
    e = report(sources)["exploration"]
    assert {k: e[k] for k in ("status", "stop_reason", "steps_attempted", "actions_succeeded", "actions_failed", "screens_observed", "transitions_recorded", "duration_seconds")} == {"status": "partial", "stop_reason": "max_steps", "steps_attempted": 10, "actions_succeeded": 8,
                 "actions_failed": 2, "screens_observed": 4, "transitions_recorded": 8, "duration_seconds": 60.0}


def test_route_summary_not_full_graph(sources):
    e = report(sources)["routes"]
    assert (e["node_count"], e["edge_count"], e["action_count"], e["self_loop_count"]) == (3, 2, 1, 1)
    assert (e["system_boundary_count"], e["external_boundary_count"]) == (1, 1)
    assert "nodes" not in e and "edges" not in e


@pytest.mark.parametrize("key,value", [("correlated_action_count", 2), ("pid_change_count", 1), ("process_death_count", 1),
                                      ("activity_change_count", 2), ("fatal_count", 1), ("crash_count", 1)])
def test_runtime_counts_target_evidence_only(sources, key, value):
    assert report(sources)["runtime"][key] == value


def test_traffic_counts_and_visibility(sources):
    traffic = report(sources)["traffic"]
    assert (traffic["total_transactions"], traffic["http_count"], traffic["https_count"]) == (3, 1, 2)
    assert traffic["hosts"] == ["admin.example.com", "api.example.com"]
    assert traffic["hosts_count"] == 2
    assert traffic["https_visibility"] == "partial"
    assert traffic["https_visibility_reason"] == "pinning_suspected"
    assert traffic["proxy_restored"] is True


def test_zero_traffic_does_not_claim_no_activity(sources):
    sources["traffic"]["transactions"] = []
    r = report(sources)
    assert r["traffic"]["total_transactions"] == 0
    assert "incomplete" in r["traffic"]["visibility_note"]
    assert "no network activity" not in json.dumps(r).lower()


def test_traffic_correlation_summary(sources):
    assert report(sources)["traffic_correlation"] == {"actions_with_evidence": 3, "transaction_correlated_action_count": 1,
                                                      "partial_correlation_count": 1, "unavailable_correlation_count": 1}


@pytest.mark.parametrize("key,value", [("exact_count", 1), ("template_count", 1), ("static_only_count", 1),
                                      ("dynamic_only_count", 1), ("method_mismatch_count", 1), ("correlated_count", 3)])
def test_api_counts_preserved(sources, key, value):
    assert report(sources)["api_correlation"][key] == value


def test_endpoint_rows_and_summary(sources):
    r = report(sources)
    assert r["endpoint_context_summary"] == {"endpoint_context_count": 5, "runtime_observed_count": 4,
                                             "static_only_count": 1, "dynamic_only_count": 1}
    row = next(e for e in r["endpoint_contexts"] if e["match_type"] == "method_mismatch")
    assert row["static_method"] == "GET" and row["observed_methods"] == ["POST"]
    assert row["observed_status_codes"] == [200, 500]
    assert row["action_ids"] == ["act_1", "act_2"]
    assert row["auth"]["bearer_token_present"] is None


@pytest.mark.parametrize("secret", ["TOKEN_SECRET", "BEARER_SECRET", "COOKIE_SECRET", "PASSWORD_SECRET", "APIKEY_SECRET", "SESSION_SECRET",
                                    "BODY_SECRET", "RESPONSE_SECRET", "LOGCAT_SECRET", "LOG_SECRET", "QUERY_SECRET", "/Users/alice", "/opt/homebrew"])
def test_privacy(sources, secret):
    assert secret not in json.dumps(report(sources))


@pytest.mark.parametrize("missing,capability", [("traffic", "http_visibility"), ("runtime", "runtime_observation"),
                                              ("api_correlation", "api_correlation"), ("endpoint_contexts", "endpoint_contexts")])
def test_missing_optional_evidence_partial(sources, missing, capability):
    del sources[missing]
    r = report(sources)
    assert r["report_status"] == "completed"
    assert r["analysis_coverage"] == "partial"
    assert r["coverage"][capability] == "unavailable"
    assert r["evidence_status"][missing] == "missing"


@pytest.mark.parametrize("missing", ["session", "exploration"])
def test_minimum_required_evidence(sources, missing):
    del sources[missing]
    with pytest.raises(DynamicReportUnavailable):
        report(sources)


def test_zero_execution_no_misleading_report(sources, tmp_path):
    for key in ("steps_attempted", "screens_observed", "actions_succeeded", "transitions_recorded"):
        sources["exploration"][key] = 0
    write_sources(tmp_path, sources)
    with pytest.raises(DynamicReportUnavailable):
        generate_dynamic_analysis_report(tmp_path)
    assert not (tmp_path / "dynamic_analysis_report.json").exists()


def test_failed_exploration_stays_failed_in_completed_report(sources):
    sources["exploration"]["status"] = "failed"
    r = report(sources)
    assert r["report_status"] == "completed"
    assert r["exploration"]["status"] == "failed"
    assert r["coverage"]["ui_exploration"] == "partial"


def test_endpoint_and_evidence_order_deterministic(sources):
    a = report(sources)
    sources["endpoint_contexts"]["endpoints"].reverse()
    sources["traffic"]["transactions"].reverse()
    sources["api_correlation"]["correlations"].reverse()
    assert report(sources) == a
    assert list(a["evidence"]) == sorted(a["evidence"])
    assert all(not Path(p).is_absolute() and p.startswith("dynamic/") for p in a["evidence"].values())


def test_atomic_write_and_validate(sources, tmp_path):
    r = report(sources, tmp_path.name)
    path = save_dynamic_analysis_report(tmp_path, r)
    assert path == tmp_path / "dynamic_analysis_report.json"
    assert load_dynamic_analysis_report(tmp_path) == r
    assert not list(tmp_path.glob(".tmp_dynamic_report_*"))
    assert not (tmp_path / "dynamic/dynamic_analysis_report.json").exists()


def test_atomic_failure_preserves_existing(sources, tmp_path):
    path = tmp_path / "dynamic_analysis_report.json"; path.write_text("previous")
    with patch("src.dynamic.report.models.os.replace", side_effect=OSError("synthetic")):
        with pytest.raises(OSError):
            save_dynamic_analysis_report(tmp_path, report(sources))
    assert path.read_text() == "previous"
    assert not list(tmp_path.glob(".tmp_dynamic_report_*"))


def test_corrupt_optional_source_explicit(sources, tmp_path):
    dyn = write_sources(tmp_path, sources)
    (dyn / "traffic.json").write_text("{corrupt")
    r = generate_dynamic_analysis_report(tmp_path)
    assert r["evidence_status"]["traffic"] == "corrupt"
    assert r["coverage"]["http_visibility"] == "unavailable"
    assert "traffic" not in r["evidence"]
    assert (dyn / "traffic.json").read_text() == "{corrupt"


def test_corrupt_required_source_blocks_report(sources, tmp_path):
    dyn = write_sources(tmp_path, sources)
    (dyn / "session.json").write_text("[]")
    with pytest.raises(DynamicReportUnavailable):
        generate_dynamic_analysis_report(tmp_path)


def test_no_findings_or_agents(sources):
    r = json.dumps(report(sources))
    for field in ("vulnerability", "findings", "severity", "risk_score", "is_vulnerable", "agent_analysis", "agent_report"):
        assert field not in r


def test_sources_unchanged_in_memory_and_disk(sources, tmp_path):
    before = copy.deepcopy(sources)
    report(sources)
    write_sources(tmp_path, sources)
    files = {p: p.read_bytes() for p in tmp_path.rglob("*.json")}
    generate_dynamic_analysis_report(tmp_path)
    assert sources == before
    assert all(p.read_bytes() == content for p, content in files.items())


def test_no_execution_or_llm_dependencies(sources, tmp_path):
    write_sources(tmp_path, sources)
    with patch("urllib.request.urlopen") as network, patch("subprocess.run") as process, patch("http.client.HTTPConnection") as http:
        generate_dynamic_analysis_report(tmp_path)
        network.assert_not_called(); process.assert_not_called(); http.assert_not_called()
    for path in Path("src/dynamic/report").glob("*.py"):
        for forbidden in ("import openai", "import anthropic", "import google", "import requests", "import subprocess", "resolve_adb"):
            assert forbidden not in path.read_text()


def test_wiring_registers_after_persistence(sources, tmp_path):
    from src.demo_orchestrator import _wire_dynamic_analysis_report
    write_sources(tmp_path, sources); init_state(tmp_path)
    seen = []
    original = save_scan_state
    def checkpoint(directory, state):
        assert (tmp_path / "dynamic_analysis_report.json").is_file()
        load_dynamic_analysis_report(tmp_path)
        seen.append(copy.deepcopy(state))
        return original(directory, state)
    with patch("src.scan_state.save_scan_state", side_effect=checkpoint):
        assert _wire_dynamic_analysis_report(tmp_path)
    assert seen[0]["artifacts"]["dynamic_analysis_report"] == {"available": True, "relative_path": "dynamic_analysis_report.json"}
    assert seen[0]["stages"]["dynamic_analysis"]["status"] == "partial"
    st = load_scan_state(tmp_path)
    assert st["stages"]["dynamic_analysis"]["status"] == "completed"
    assert st["stages"]["report_generation"]["status"] == "partial"
    assert st["stages"]["agent_analysis"]["status"] == "not_available"
    assert st["artifacts"]["agent_report"]["available"] is False
    assert st["overall_status"] == "completed"
    assert not (tmp_path / "agent_report.json").exists()


@pytest.mark.parametrize("raw", [None, "{corrupt", "{}"])
def test_completion_blocked_without_valid_file(sources, tmp_path, raw):
    state = init_state(tmp_path)
    state["artifacts"]["dynamic_analysis_report"] = {"available": True, "relative_path": "dynamic_analysis_report.json"}
    state["stages"]["dynamic_analysis"]["status"] = "completed"
    if raw is not None:
        (tmp_path / "dynamic_analysis_report.json").write_text(raw)
    with pytest.raises(ScanStateValidationError):
        save_scan_state(tmp_path, state)
    from src.demo_orchestrator import _update_scan_state_dynamic_stage
    _update_scan_state_dynamic_stage(tmp_path, "completed", "test")
    assert load_scan_state(tmp_path)["stages"]["dynamic_analysis"]["status"] == "partial"


def test_recovery_recognizes_existing_report(sources, tmp_path):
    write_sources(tmp_path, sources); init_state(tmp_path)
    generate_dynamic_analysis_report(tmp_path)
    state = load_scan_state(tmp_path)
    state["stages"]["agent_analysis"]["message"] = "Scheduled for subsequent milestone"
    save_scan_state(tmp_path, state)
    st = recover_scan_state(tmp_path)
    assert st["stages"]["agent_analysis"]["message"] == "Not available in this scan"
    assert st["stages"]["agent_analysis"]["status"] == "not_available"
    assert not st["artifacts"]["agent_report"]["available"]
    assert st["stages"]["report_generation"]["status"] == "partial"
    assert st["artifacts"]["dynamic_analysis_report"]["available"]
    assert st["stages"]["dynamic_analysis"]["status"] == "completed"
    assert load_scan_state(tmp_path)["artifacts"]["dynamic_analysis_report"]["available"]


@pytest.mark.parametrize("corrupt", [False, True])
def test_recovery_rejects_stale_availability(sources, tmp_path, corrupt):
    from src.demo_orchestrator import _wire_dynamic_analysis_report
    write_sources(tmp_path, sources); init_state(tmp_path)
    assert _wire_dynamic_analysis_report(tmp_path)
    path = tmp_path / "dynamic_analysis_report.json"
    if corrupt:
        path.write_text("{corrupt")
    else:
        path.unlink()
    with pytest.raises(ScanStateValidationError):
        load_scan_state(tmp_path)
    st = recover_scan_state(tmp_path)
    assert not st["artifacts"]["dynamic_analysis_report"]["available"]
    assert st["stages"]["dynamic_analysis"]["status"] == "partial"
    assert load_scan_state(tmp_path)["stages"]["dynamic_analysis"]["status"] == "partial"


def test_recovery_without_state(sources, tmp_path):
    write_sources(tmp_path, sources)
    generate_dynamic_analysis_report(tmp_path)
    assert recover_scan_state(tmp_path)["stages"]["dynamic_analysis"]["status"] == "completed"


def test_checkpointer_guard_is_artifact_aware(sources, tmp_path):
    cp = ScanStateCheckpointer(tmp_path, tmp_path.name, "https://example.com/app.apk")
    cp.init_state()
    cp.on_dynamic_exploration_finished("completed")
    assert load_scan_state(tmp_path)["stages"]["dynamic_analysis"]["status"] == "partial"
    write_sources(tmp_path, sources); generate_dynamic_analysis_report(tmp_path)
    cp.on_pipeline_progress("dynamic_analysis", "completed", "Report generated")
    assert load_scan_state(tmp_path)["stages"]["dynamic_analysis"]["status"] == "completed"
    cp.on_demo_completed()
    assert load_scan_state(tmp_path)["stages"]["report_generation"]["status"] == "partial"


def test_failed_generation_does_not_complete(sources, tmp_path):
    from src.demo_orchestrator import _wire_dynamic_analysis_report
    write_sources(tmp_path, sources); init_state(tmp_path)
    with patch("src.report_generator.generate_dynamic_analysis_report", side_effect=OSError("synthetic")):
        assert _wire_dynamic_analysis_report(tmp_path) is None
    assert load_scan_state(tmp_path)["stages"]["dynamic_analysis"]["status"] == "partial"
    assert not (tmp_path / "dynamic_analysis_report.json").exists()


def test_report_integrity_rejects_unsafe_fields(sources):
    r = report(sources)
    r["findings"] = []
    with pytest.raises(DynamicReportError):
        validate_dynamic_analysis_report(r)
    del r["findings"]
    r["evidence"]["traffic"] = "/Users/alice/traffic.json"
    with pytest.raises(DynamicReportError):
        validate_dynamic_analysis_report(r)


@pytest.mark.parametrize("exists", [True, False])
def test_read_only_api_route(sources, tmp_path, exists):
    from src.demo_web_server import _DemoRequestHandler
    # Exercise route dispatch without opening a server or sending a request.
    handler = MagicMock()
    handler.path = "/reports/run_test/dynamic_analysis_report.json"
    handler._extract_status_run_id.return_value = None
    handler.web_server.get_run_dir.return_value = tmp_path
    if exists:
        save_dynamic_analysis_report(tmp_path, report(sources))
    with patch("src.web.request_helpers.send_json") as response:
        _DemoRequestHandler.do_GET(handler)
    _, status, body = response.call_args.args
    assert status == (200 if exists else 404)
    if exists:
        assert body["report_type"] == "dynamic_analysis"


@pytest.mark.parametrize("section,bad", [("traffic", {"transactions": [{"request": "corrupt"}]}),
                                        ("runtime", {"actions": "corrupt"}),
                                        ("endpoint_contexts", {"summary": {}, "endpoints": [{"endpoint_context_id": "ctx_bad", "dynamic": "corrupt"}]}),
                                        ("api_correlation", {"summary": {}, "correlations": [{"match_type": {"corrupt": True}}]})])
def test_invalid_optional_schema_is_explicitly_unavailable(sources, section, bad):
    sources[section] = bad
    r = report(sources)
    assert r["evidence_status"][section] == "corrupt"
    assert section not in r["evidence"]


@pytest.mark.parametrize("section,key,bad", [("traffic", "https_count", "wrong"), ("runtime", "crash_count", -1),
                                            ("coverage", "http_visibility", {}), ("exploration", "duration_seconds", float("nan"))])
def test_corrupt_report_structure_cannot_complete(sources, tmp_path, section, key, bad):
    r = report(sources, tmp_path.name); r[section][key] = bad
    (tmp_path / "dynamic_analysis_report.json").write_text(json.dumps(r))
    with pytest.raises(DynamicReportError):
        load_dynamic_analysis_report(tmp_path)
    init_state(tmp_path)
    assert not recover_scan_state(tmp_path)["artifacts"]["dynamic_analysis_report"]["available"]


def test_recovery_from_dynamic_report_without_static_or_state(sources, tmp_path):
    save_dynamic_analysis_report(tmp_path, report(sources, tmp_path.name))
    st = recover_scan_state(tmp_path)
    assert st["stages"]["dynamic_analysis"]["status"] == "completed"
    assert st["target"]["package_name"] == "com.example.app"
    assert not st["artifacts"]["static_analysis_report"]["available"]
    assert st["stages"]["report_generation"]["status"] == "partial"


def test_live_status_exposes_validated_stage_state(sources, tmp_path):
    from src.demo_web_server import DemoWebServer
    from src.demo_orchestrator import _wire_dynamic_analysis_report
    write_sources(tmp_path, sources); init_state(tmp_path); _wire_dynamic_analysis_report(tmp_path)
    server = DemoWebServer(runs_root=tmp_path.parent)
    run = {"run_id": tmp_path.name, "stages": {}, "overall_status": "completed"}
    status = server._build_status_response(run)
    assert status["scan_state"]["stages"]["dynamic_analysis"]["status"] == "completed"


@pytest.mark.parametrize("available,expected", [(True, "completed"), (False, "partial")])
def test_dashboard_dynamic_completion_requires_artifact(available, expected):
    import re
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        pytest.skip("Node unavailable for pure stage-adapter execution")
    html = Path("src/templates/dashboard.html").read_text()
    code = re.search(r"    function deriveProductStages\(.*?\n    function escapeHtml", html, re.S).group(0)
    code = code.rsplit("\n    function escapeHtml", 1)[0]
    status = {"scan_state": {"stages": {"dynamic_analysis": {"status": "completed"}},
                             "artifacts": {"dynamic_analysis_report": {"available": available, "relative_path": "dynamic_analysis_report.json"}}}}
    code += "\nconsole.log(JSON.stringify(deriveProductStages({}, " + json.dumps(status) + ")));"
    result = subprocess.run([node, "-e", code], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout)["dynamic_analysis"]["state"] == expected


def test_post_correlation_context_precedes_report(sources, tmp_path):
    from src.demo_orchestrator import _wire_api_correlation, _wire_dynamic_analysis_report
    write_sources(tmp_path, sources); init_state(tmp_path)
    (tmp_path / "dynamic/endpoint_contexts.json").unlink()
    with patch("src.demo_orchestrator._wire_endpoint_contexts") as context_builder:
        def saved_context(*args):
            assert (tmp_path / "dynamic/api_correlation.json").is_file()
            assert not (tmp_path / "dynamic_analysis_report.json").is_file()
            (tmp_path / "dynamic/endpoint_contexts.json").write_text(json.dumps(sources["endpoint_contexts"]))
        context_builder.side_effect = saved_context
        _wire_api_correlation(tmp_path, "session-test")
        assert _wire_dynamic_analysis_report(tmp_path)
        context_builder.assert_called_once()


def test_checkpointer_never_completes_when_registration_fails(sources, tmp_path):
    cp = ScanStateCheckpointer(tmp_path, tmp_path.name, "https://example.com/app.apk")
    cp.init_state()
    write_sources(tmp_path, sources); generate_dynamic_analysis_report(tmp_path)
    with patch("src.scan_state.save_scan_state", side_effect=OSError("checkpoint unavailable")):
        cp.on_dynamic_exploration_finished("completed")
    assert cp.get_state()["stages"]["dynamic_analysis"]["status"] == "partial"
    assert load_scan_state(tmp_path)["artifacts"]["dynamic_analysis_report"]["available"] is False
    assert load_scan_state(tmp_path)["stages"]["dynamic_analysis"]["status"] != "completed"


def test_corrupt_canonical_report_api_unavailable(sources, tmp_path):
    from src.demo_web_server import _DemoRequestHandler
    handler = MagicMock(); handler.path = "/reports/run_test/dynamic_analysis_report.json"
    handler._extract_status_run_id.return_value = None
    handler.web_server.get_run_dir.return_value = tmp_path
    (tmp_path / "dynamic_analysis_report.json").write_text("{corrupt")
    with patch("src.web.request_helpers.send_json") as response:
        _DemoRequestHandler.do_GET(handler)
    assert response.call_args.args[1] == 404


def test_live_status_handles_corrupt_registered_report(sources, tmp_path):
    from src.demo_web_server import DemoWebServer
    from src.demo_orchestrator import _wire_dynamic_analysis_report
    write_sources(tmp_path, sources); init_state(tmp_path); _wire_dynamic_analysis_report(tmp_path)
    (tmp_path / "dynamic_analysis_report.json").write_text("{corrupt")
    server = DemoWebServer(runs_root=tmp_path.parent)
    status = server._build_status_response({"run_id": tmp_path.name, "stages": {}, "overall_status": "completed"})
    assert "scan_state" not in status


def test_fully_available_coverage_is_distinct(sources):
    sources["exploration"]["status"] = "completed"
    sources["exploration"]["stop_reason"] = "no_actions"
    sources["exploration"]["metadata"] = {"frontier": {"observation_available": True,
        "safe_frontier_exhausted": True, "safe_actions_discovered": 8, "safe_actions_remaining": 0, "unsafe_skipped": 0}}
    sources["traffic"]["https_visibility"] = "available"
    sources["runtime"]["actions"] = sources["runtime"]["actions"][:1]
    result = report(sources)
    assert result["report_status"] == "completed"
    assert result["analysis_coverage"] == "complete"


def test_missing_preflight_does_not_fabricate_launch_failure(sources):
    del sources["preflight"]
    result = report(sources)
    assert result["preflight"]["status"] == "unavailable"
    assert result["preflight"]["launch_success"] is None
    assert result["preflight"]["process_running"] is None
