"""Synthetic evidence-only tests for Task 7.2."""
import copy
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.dynamic.context import build_endpoint_contexts, EndpointContextArtifact
from src.dynamic.context.endpoint_context_builder import body_shape
from src.dynamic.correlation.api_correlator import correlate_static_dynamic_apis
from src.dynamic.runtime.models import RuntimeActionEvidence, RuntimeEvidenceArtifact
from src.dynamic.traffic.models import (HttpRequestModel, HttpResponseModel, TrafficTransaction,
                                        ActionTrafficEvidence, TrafficEvidenceArtifact)
from src.dynamic.traffic.normalizer import normalize_http_transaction


@pytest.fixture
def evidence():
    candidate = {"id": "cand_login", "base_url": "https://api.example.com", "path": "/login", "method": "POST",
                 "source_file": "smali/Login.smali", "request_line": 42, "framework": "Fuel",
                 "evidence": {"base_url_value": "https://api.example.com", "password": "PROVENANCE_SECRET"}}
    tx = TrafficTransaction(transaction_id="tx_1", request=HttpRequestModel(
        method="POST", scheme="https", host="api.example.com", path="/login", timestamp="2026-10-01T12:00:00Z",
        headers={"Authorization": "Bearer TOKEN_SECRET", "Cookie": "session_id=COOKIE_SECRET", "X-API-Key": "API_SECRET",
                 "Content-Type": "application/json; charset=utf-8"},
        query={"q": "QUERY_SECRET", "page": "2"}, body={"username": "USER_SECRET", "password": "PASS_SECRET"},
        body_metadata={"size": 80}), response=HttpResponseModel(status_code=200,
        headers={"Content-Type": "application/json", "Set-Cookie": "session=RESP_COOKIE_SECRET"},
        body={"token": "RESPONSE_TOKEN_SECRET", "user_id": 123}, body_metadata={"size": 40}))
    traffic = TrafficEvidenceArtifact(session_id="session-123", actions=[ActionTrafficEvidence(
        action_id="act_login", source_node_id="screen_login", target_node_id="screen_home", transaction_ids=["tx_1"])])
    runtime = RuntimeEvidenceArtifact(session_id="session-123", actions=[RuntimeActionEvidence(
        action_id="act_login", source_node_id="screen_login", activity_changed=True, process_died=True,
        pid_changed=True, fatal_appeared=True, crash_appeared=True, compact_new_events=[{"message": "LOG_SECRET"}])])
    corr = correlate_static_dynamic_apis([candidate], [tx], session_id="session-123", traffic_evidence=traffic,
                                         https_visibility="partial", https_visibility_reason="pinning_suspected")
    return corr, [tx], traffic, runtime


def context(evidence):
    return build_endpoint_contexts(*evidence).endpoints[0]


def test_exact_context(evidence):
    e = context(evidence)
    assert (e.host, e.path, e.scheme, e.methods) == ("api.example.com", "/login", "https", ["POST"])
    assert e.static["match_type"] == "exact"
    assert e.static["confidence"] == "high"


def test_template_context_aggregation():
    txs = [TrafficTransaction(transaction_id=f"tx_{i}", request=HttpRequestModel(
        host="api.example.com", path=f"/users/{i}")) for i in (1, 2)]
    corr = correlate_static_dynamic_apis([{"host": "api.example.com", "path": "/users/{id}", "method": "GET"}], txs)
    artifact = build_endpoint_contexts(corr, txs)
    assert len(artifact.endpoints) == 1
    assert artifact.endpoints[0].path == "/users/{id}"
    assert artifact.endpoints[0].static["match_type"] == "template"
    assert artifact.endpoints[0].dynamic["observation_count"] == 2


def test_static_only_is_descriptive():
    corr = correlate_static_dynamic_apis([{"host": "api.example.com", "path": "/unused"}], [])
    e = build_endpoint_contexts(corr, []).endpoints[0]
    assert not e.dynamic["observed"]
    assert e.dynamic["note"] == "Not observed in available runtime traffic."
    assert e.scheme is None
    assert not e.request["body_present"]


def test_dynamic_only_no_fabricated_static(evidence):
    corr = correlate_static_dynamic_apis([], evidence[1])
    e = build_endpoint_contexts(corr, evidence[1]).endpoints[0]
    assert e.static == {}
    assert e.evidence_refs["static_candidate_ids"] == []
    assert e.dynamic["observed"]


def test_method_mismatch_preserves_methods(evidence):
    corr = correlate_static_dynamic_apis([{"host": "api.example.com", "path": "/login", "method": "GET"}], evidence[1])
    e = build_endpoint_contexts(corr, evidence[1]).endpoints[0]
    assert e.static["match_type"] == "method_mismatch"
    assert e.static["static_method"] == "GET"
    assert e.dynamic["observed_methods"] == ["POST"]
    assert e.methods == ["GET", "POST"]


@pytest.mark.parametrize("key,value", [("transaction_ids", ["tx_1"]), ("action_ids", ["act_login"]),
                                      ("runtime_action_ids", ["act_login"]), ("static_candidate_ids", ["cand_login"])])
def test_evidence_ids(evidence, key, value):
    assert context(evidence).evidence_refs[key] == value


def test_correlation_reference(evidence):
    assert context(evidence).evidence_refs["correlation_ids"] == [evidence[0].correlations[0].correlation_id]


def test_compact_action_and_route(evidence):
    e = context(evidence)
    expected = [{"action_id": "act_login", "source_node_id": "screen_login", "target_node_id": "screen_home"}]
    assert e.action_context == expected
    assert e.route_context == expected
    assert "screen_identity" not in json.dumps(e.to_dict())


@pytest.mark.parametrize("key", ["authorization_header_present", "bearer_token_present", "cookie_present",
                               "session_cookie_present", "api_key_header_present"])
def test_auth_presence_without_values(evidence, key):
    assert context(evidence).auth[key] is True
    assert "SECRET" not in json.dumps(context(evidence).to_dict())


def test_redacted_auth_has_unknown_subtype():
    tx = normalize_http_transaction({"url": "https://api.example.com/login", "headers": {
        "Authorization": "Bearer TOKEN_SECRET", "Cookie": "session=COOKIE_SECRET"}}, None, "capture")
    corr = correlate_static_dynamic_apis([], [tx])
    auth = build_endpoint_contexts(corr, [tx]).endpoints[0].auth
    assert auth["authorization_header_present"] and auth["cookie_present"]
    assert auth["bearer_token_present"] is None
    assert auth["session_cookie_present"] is None


def test_content_type_safe_metadata(evidence):
    e = context(evidence)
    assert e.request["content_types"] == ["application/json"]
    assert e.request["header_names"] == ["authorization", "content-type", "cookie", "x-api-key"]
    assert e.request["body_sizes"] == [80]


def test_request_body_keys_and_shape(evidence):
    e = context(evidence)
    assert e.request["body_keys"] == ["password", "username"]
    assert e.request["body_shapes"] == [{"password": "string", "username": "string"}]
    assert e.request["body_present"]


def test_nested_shape_bounded():
    assert body_shape({"user": {"id": 123, "profile": {"name": "SECRET"}}}) == {
        "user": {"id": "number", "profile": {"name": "string"}}}
    assert body_shape({"a": {"b": {"c": {"d": "SECRET"}}}}) == {"a": {"b": {"c": "object"}}}
    assert len(body_shape({str(i): i for i in range(100)})) == 32


def test_array_first_element_only():
    assert body_shape({"items": [{"id": 1}, {"SECRET": "SECRET"}]}) == {"items": [{"id": "number"}]}


@pytest.mark.parametrize("sensitive", ["password", "passwd", "token", "access_token", "refresh_token", "secret",
                                      "api_key", "authorization", "cookie", "session", "session_id"])
def test_sensitive_values_never_persist(evidence, sensitive):
    evidence[1][0].request.body = {sensitive: {"NESTED_SECRET": "SECRET"}}
    evidence[1][0].response.body = {sensitive: "RESPONSE_SECRET"}
    serialized = json.dumps(context(evidence).to_dict())
    assert "SECRET" not in serialized
    assert sensitive in context(evidence).request["body_keys"]


def test_form_keys_only(evidence):
    evidence[1][0].request.headers = {"Content-Type": "application/x-www-form-urlencoded"}
    evidence[1][0].request.body = "username=USER_SECRET&password=PASS_SECRET"
    request = context(evidence).request
    assert request["body_keys"] == ["password", "username"]
    assert request["body_types"] == ["form"]
    assert "SECRET" not in json.dumps(request)


def test_multipart_upload_not_parsed(evidence):
    evidence[1][0].request.headers = {"content-type": "multipart/form-data; boundary=SECRET"}
    evidence[1][0].request.body = "FILE_SECRET"
    request = context(evidence).request
    assert request["body_types"] == ["multipart"]
    assert request["body_shapes"] == []
    assert "SECRET" not in json.dumps(request)


def test_query_keys_values_omitted(evidence):
    assert context(evidence).request["query_keys"] == ["page", "q"]
    assert "QUERY_SECRET" not in json.dumps(context(evidence).to_dict())


def test_status_counts_and_content_types(evidence):
    corr, txs, traffic, runtime = evidence
    for index, status in enumerate([200, 401, 500], 2):
        tx = copy.deepcopy(txs[0]); tx.transaction_id = f"tx_{index}"
        tx.response.status_code = status
        tx.response.headers["Content-Type"] = "application/problem+json"
        txs.append(tx)
    entry = corr.correlations[0]
    entry.transaction_ids = [tx.transaction_id for tx in txs]
    entry.observation_count = 4
    e = context(evidence)
    assert e.response["observed_status_codes"] == [200, 401, 500]
    assert e.response["status_code_counts"] == {"200": 2, "401": 1, "500": 1}
    assert e.response["content_types"] == ["application/json", "application/problem+json"]
    assert e.response["body_shapes"] == [{"token": "string", "user_id": "number"}]


@pytest.mark.parametrize("key", ["process_death_observed", "activity_changes_observed", "crash_observed",
                                "pid_changed_observed", "fatal_observed"])
def test_runtime_flags_are_evidence(evidence, key):
    assert context(evidence).runtime_context[key] is True


def test_runtime_unrelated_and_unavailable_not_attributed(evidence):
    evidence[3].actions[0].action_id = "unrelated"
    assert not context(evidence).runtime_context["crash_observed"]
    evidence[3].actions[0].action_id = "act_login"
    evidence[3].actions[0].correlation_status = "unavailable"
    assert not context(evidence).runtime_context["evidence_available"]
    assert not context(evidence).runtime_context["crash_observed"]


def test_visibility_preserved(evidence):
    assert context(evidence).visibility == {"http_visibility": "available", "https_visibility": "partial",
                                          "https_visibility_reason": "pinning_suspected"}


def test_static_provenance_safe(evidence):
    e = context(evidence)
    assert (e.static["source_file"], e.static["request_line"], e.static["framework"]) == ("smali/Login.smali", 42, "Fuel")
    assert e.static["static_candidate_id_origin"] == "source_report"
    assert e.static["extraction_provenance_keys"] == ["base_url_value", "password"]


def test_host_paths_sanitized(evidence):
    evidence[0].correlations[0].provenance["source_file"] = "/Users/alice/project/Login.smali"
    assert context(evidence).static["source_file"] == "<host_path>"
    assert "/Users/alice" not in json.dumps(context(evidence).to_dict())


def test_no_raw_evidence_or_verdicts(evidence):
    data = context(evidence).to_dict()
    serialized = json.dumps(data)
    for forbidden in ("SECRET", "raw_payload", "compact_new_events", "snapshot", '"body":', '"diff":',
                      '"is_vulnerable"', '"vulnerability"', '"severity"', '"risk_score"', '"auth_broken"',
                      '"bola_detected"', '"idor_detected"'):
        assert forbidden not in serialized


def test_id_deterministic_under_ordering(evidence):
    a = context(evidence).endpoint_context_id
    evidence[0].correlations[0].transaction_ids.reverse()
    assert a == context(evidence).endpoint_context_id
    assert a.startswith("ctx_") and len(a) == 20


def test_id_distinguishes_methods(evidence):
    a = context(evidence).endpoint_context_id
    evidence[0].correlations[0].static_method = "GET"
    assert context(evidence).endpoint_context_id != a


def test_atomic_write_and_load(evidence, tmp_path):
    artifact = build_endpoint_contexts(*evidence)
    path = tmp_path / "endpoint_contexts.json"
    artifact.save_atomic(path)
    assert EndpointContextArtifact.load(path).to_dict() == artifact.to_dict()
    assert not list(tmp_path.glob("*.tmp.*"))


def test_atomic_failure_preserves_existing(evidence, tmp_path):
    path = tmp_path / "endpoint_contexts.json"; path.write_text("previous")
    with patch.object(Path, "replace", side_effect=OSError("failed")):
        with pytest.raises(OSError):
            build_endpoint_contexts(*evidence).save_atomic(path)
    assert path.read_text() == "previous"
    assert not list(tmp_path.glob("*.tmp.*"))


@pytest.mark.parametrize("raw", ["{", "[]", '{"schema_version":"2.0"}',
                                  '{"schema_version":"1.0","summary":{},"endpoints":[{}]}'])
def test_corrupt_artifact_explicit(tmp_path, raw):
    path = tmp_path / "endpoint_contexts.json"; path.write_text(raw)
    with pytest.raises(ValueError, match="Corrupt"):
        EndpointContextArtifact.load(path)


def test_inputs_not_mutated(evidence):
    before = copy.deepcopy([evidence[0].to_dict(), [t.to_dict() for t in evidence[1]],
                            evidence[2].to_dict(), evidence[3].to_dict()])
    build_endpoint_contexts(*evidence)
    assert before == [evidence[0].to_dict(), [t.to_dict() for t in evidence[1]], evidence[2].to_dict(), evidence[3].to_dict()]


def test_empty_correlation():
    artifact = build_endpoint_contexts(correlate_static_dynamic_apis([], []), [])
    assert artifact.endpoints == []
    assert artifact.summary == {"endpoint_context_count": 0, "runtime_observed_count": 0, "static_only_count": 0, "dynamic_only_count": 0}


def test_missing_runtime_and_traffic_evidence(evidence):
    e = build_endpoint_contexts(evidence[0], evidence[1]).endpoints[0]
    assert not e.runtime_context["evidence_available"]
    assert e.action_context == []
    assert e.evidence_refs["action_ids"] == ["act_login"]
    assert e.route_context


def test_missing_transaction_does_not_invent_body(evidence):
    e = build_endpoint_contexts(evidence[0], []).endpoints[0]
    assert e.dynamic["missing_transaction_ids"] == ["tx_1"]
    assert e.dynamic["available_transaction_count"] == 0
    assert not e.request["body_present"]


def test_dict_transactions_equal_models(evidence):
    a = build_endpoint_contexts(*evidence).to_dict()
    b = build_endpoint_contexts(evidence[0], [t.to_dict() for t in evidence[1]], evidence[2], evidence[3]).to_dict()
    assert a == b


def test_builder_has_no_execution_dependencies(evidence):
    with patch("urllib.request.urlopen") as network, patch("subprocess.run") as process:
        build_endpoint_contexts(*evidence)
        network.assert_not_called(); process.assert_not_called()
    for path in Path("src/dynamic/context").glob("*.py"):
        source = path.read_text()
        for dependency in ("import openai", "import anthropic", "import google", "import requests", "import subprocess"):
            assert dependency not in source


def write_sources(tmp_path, evidence):
    dyn = tmp_path / "dynamic"; dyn.mkdir()
    evidence[0].save_atomic(dyn / "api_correlation.json")
    (dyn / "traffic.json").write_text(json.dumps({"transactions": [t.to_dict() for t in evidence[1]]}))
    evidence[2].save_atomic(dyn / "traffic_evidence.json")
    evidence[3].save_atomic(dyn / "runtime_evidence.json")
    for name in ("route_graph.json", "timeline.json"):
        (dyn / name).write_text('{"preserved":true}')
    (tmp_path / "static_analysis_report.json").write_text('{"preserved":true}')
    return dyn


def test_production_wiring_and_compact_timeline(evidence, tmp_path):
    from src.demo_orchestrator import _wire_endpoint_contexts
    dyn = write_sources(tmp_path, evidence)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*.json")}
    timeline = MagicMock()
    result = _wire_endpoint_contexts(tmp_path, timeline_recorder=timeline)
    assert result and (dyn / "endpoint_contexts.json").is_file()
    timeline._record_system_event.assert_called_once_with("ENDPOINT_CONTEXTS_BUILT", result.summary)
    assert all(p.read_bytes() == content for p, content in before.items())
    assert not list(tmp_path.rglob("dynamic_analysis_report.json"))
    assert not list(tmp_path.rglob("agent_report.json"))


def test_wiring_requires_correlation(tmp_path):
    from src.demo_orchestrator import _wire_endpoint_contexts
    assert _wire_endpoint_contexts(tmp_path) is None
    assert not list(tmp_path.rglob("endpoint_contexts.json"))


def test_failure_isolation(evidence, tmp_path):
    from src.demo_orchestrator import _wire_endpoint_contexts
    write_sources(tmp_path, evidence)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*.json")}
    with patch("src.dynamic.context.build_endpoint_contexts", side_effect=RuntimeError("synthetic")):
        assert _wire_endpoint_contexts(tmp_path) is None
    assert all(p.read_bytes() == content for p, content in before.items())


def test_correlation_production_calls_context_after_save(tmp_path):
    from src.demo_orchestrator import _wire_api_correlation
    def check_saved(*args):
        assert (tmp_path / "dynamic/api_correlation.json").is_file()
    with patch("src.demo_orchestrator._wire_endpoint_contexts", side_effect=check_saved) as builder:
        assert _wire_api_correlation(tmp_path, "session") is not None
        builder.assert_called_once()


def test_wiring_preserves_stage_semantics(evidence, tmp_path):
    from src.demo_orchestrator import _wire_endpoint_contexts
    from src.scan_state import create_initial_scan_state, save_scan_state, load_scan_state
    write_sources(tmp_path, evidence)
    state = create_initial_scan_state(scan_id="test", target_url="http://example.com/app.apk")
    for name in ("dynamic_analysis", "report_generation"):
        state["stages"][name]["status"] = "partial"
    save_scan_state(tmp_path, state)
    before = copy.deepcopy(load_scan_state(tmp_path))
    _wire_endpoint_contexts(tmp_path)
    assert load_scan_state(tmp_path) == before
    assert load_scan_state(tmp_path)["stages"]["dynamic_analysis"]["status"] == "partial"
    assert not list(tmp_path.rglob("agent_report.json"))


def test_wide_form_bounded(evidence):
    evidence[1][0].request.headers = {"content-type": "application/x-www-form-urlencoded"}
    evidence[1][0].request.body = "&".join(f"field{i}=SECRET" for i in range(100))
    assert len(context(evidence).request["body_keys"]) == 32
    assert "SECRET" not in json.dumps(context(evidence).request)


def test_literal_numeric_contexts_remain_separate():
    txs = [TrafficTransaction(transaction_id=f"tx{i}", request=HttpRequestModel(
        host="api.example.com", path=f"/users/{i}")) for i in (1, 2)]
    corr = correlate_static_dynamic_apis([{"host": "api.example.com", "path": "/users/1", "method": "GET"}], txs)
    artifact = build_endpoint_contexts(corr, txs)
    assert {e.path for e in artifact.endpoints} == {"/users/1", "/users/2"}
    assert len({e.endpoint_context_id for e in artifact.endpoints}) == 2
    assert artifact.summary["dynamic_only_count"] == 1


def test_query_path_normalized_identity():
    tx = TrafficTransaction(request=HttpRequestModel(host="api.example.com", path="/search?q=SECRET&page=2"))
    corr = correlate_static_dynamic_apis([], [tx])
    e = build_endpoint_contexts(corr, [tx]).endpoints[0]
    assert e.path == "/search"
    assert e.request["query_keys"] == ["page", "q"]
    assert "SECRET" not in json.dumps(e.to_dict())


def test_mixed_schemes_are_not_fabricated(evidence):
    tx = copy.deepcopy(evidence[1][0]); tx.transaction_id = "tx2"; tx.request.scheme = "http"
    evidence[1].append(tx); evidence[0].correlations[0].transaction_ids.append("tx2")
    e = context(evidence)
    assert e.scheme is None
    assert e.dynamic["schemes"] == ["http", "https"]


def test_invalid_runtime_isolated(evidence, tmp_path):
    from src.demo_orchestrator import _wire_endpoint_contexts
    dyn = write_sources(tmp_path, evidence)
    (dyn / "runtime_evidence.json").write_text("{corrupt")
    result = _wire_endpoint_contexts(tmp_path)
    assert result and not result.endpoints[0].runtime_context["evidence_available"]
    assert (dyn / "runtime_evidence.json").read_text() == "{corrupt"


def test_timeline_failure_keeps_context(evidence, tmp_path):
    from src.demo_orchestrator import _wire_endpoint_contexts
    dyn = write_sources(tmp_path, evidence)
    timeline = MagicMock(); timeline._record_system_event.side_effect = RuntimeError("timeline")
    assert _wire_endpoint_contexts(tmp_path, timeline_recorder=timeline)
    assert (dyn / "endpoint_contexts.json").is_file()


def test_binary_metadata_does_not_imply_null_body(evidence):
    evidence[1][0].request.body = None
    evidence[1][0].request.headers = {"content-type": "application/octet-stream"}
    evidence[1][0].request.body_metadata = {"size": 500, "binary": True, "sha256": "SECRET_HASH"}
    request = context(evidence).request
    assert request["body_present"]
    assert request["body_types"] == ["binary"]
    assert request["body_shapes"] == []
    assert request["body_sizes"] == [500]
    assert "SECRET_HASH" not in json.dumps(request)
