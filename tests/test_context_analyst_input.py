"""Active input boundary tests against synthetic and actual canonical contexts."""
from copy import deepcopy
import json
from dataclasses import replace

import pytest

from src.agent.context_analyst.input_builder import InputInvalid, build_context_analyst_input, load_context_analyst_input
from src.dynamic.context.models import EndpointContext, EndpointContextArtifact


@pytest.fixture
def endpoint():
    return EndpointContext("ctx_1", "api.example.com", "/orders/{id}", methods=["GET"],
        static={"match_type": "template", "confidence": "medium", "static_method": "GET",
                "static_candidate_id": "cand_1", "static_candidate_id_origin": "source_report", "source_file": "smali/Api.smali"},
        dynamic={"observed": True, "observed_methods": ["GET"], "available_transaction_count": 1, "missing_transaction_ids": []},
        request={"header_names": ["Authorization", "Cookie"], "query_keys": ["page", "user_id"], "body_keys": ["order_id"],
                 "body_present": True, "body_shapes": [{"order_id": "number", "password": "string"}]},
        response={"observed_status_codes": [200], "content_types": ["application/json"], "body_shapes": [{"ok": "boolean"}]},
        auth={"authorization_header_present": True, "bearer_token_present": None, "cookie_present": True,
              "session_cookie_present": None, "api_key_header_present": False},
        runtime_context={"evidence_available": True, "activity_changes_observed": True},
        visibility={"http_visibility": "available", "https_visibility": "available"},
        evidence_refs={"transaction_ids": ["tx_1"], "correlation_ids": ["corr_1"], "static_candidate_ids": ["cand_1"],
                       "action_ids": ["act_1"], "runtime_action_ids": ["act_1"]},
        action_context=[{"action_id": "act_1", "source_node_id": "node_1", "target_node_id": "node_2"}])


def test_bounded_single_endpoint_input_and_read_only(endpoint):
    before = deepcopy(endpoint)
    result = build_context_analyst_input(endpoint)
    assert result.endpoint_context_id == "ctx_1"
    assert result.dynamic_context["runtime_confirmed"] is True
    assert result.endpoint["path"] == "/orders/{id}"
    assert endpoint == before
    detached = result.to_dict(); detached["endpoint"]["host"] = "changed"
    assert result.endpoint["host"] == "api.example.com"


@pytest.mark.parametrize("section,key,secret", [
    ("request", "headers", {"Authorization": "Bearer AUTH_SECRET", "Cookie": "SESSION_SECRET"}),
    ("request", "body", {"password": "PASSWORD_SECRET", "api_key": "KEY_SECRET"}),
    ("response", "body", {"token": "TOKEN_SECRET"}),
    ("auth", "authorization", "Bearer AUTH_SECRET"), ("auth", "cookie", "COOKIE_SECRET"),
    ("auth", "refresh_token", "REFRESH_SECRET"), ("runtime_context", "raw_logcat", "LOG_SECRET"),
    ("static", "jadx", "JADX_SECRET"), ("static", "source_file", "/Users/alice/FS_SECRET/Api.smali"),
    ("response", "headers", {"Set-Cookie": "COOKIE_SECRET"})])
def test_raw_values_and_filesystem_paths_excluded(endpoint, section, key, secret):
    getattr(endpoint, section)[key] = secret
    data = json.dumps(build_context_analyst_input(endpoint).to_dict())
    for marker in ("AUTH_SECRET", "SESSION_SECRET", "PASSWORD_SECRET", "KEY_SECRET", "TOKEN_SECRET",
                   "COOKIE_SECRET", "REFRESH_SECRET", "LOG_SECRET", "JADX_SECRET", "FS_SECRET", "/Users/alice"):
        assert marker not in data


def test_shapes_accept_only_type_tags_not_scalar_values(endpoint):
    endpoint.request["body_shapes"] = [{"password": "PASSWORD_SECRET", "token": 123, "api_key": True,
                                         "child": {"name": "string"}}]
    data = build_context_analyst_input(endpoint).request_context["body_shapes"]
    assert data == [{"api_key": "unknown", "child": {"name": "string"}, "password": "unknown", "token": "unknown"}]


def test_full_graph_and_unrelated_endpoint_excluded(endpoint):
    endpoint.route_context = [{"action_id": "act_1", "source_node_id": "node_1", "raw_graph": {"secret": "GRAPH_SECRET"},
                               "unrelated_endpoint": "https://unrelated.example.com"}]
    data = json.dumps(build_context_analyst_input(endpoint).to_dict())
    assert "GRAPH_SECRET" not in data and "unrelated.example.com" not in data


def test_valid_refs_preserved_and_source_surrogates_not_fabricated(endpoint):
    source = build_context_analyst_input(endpoint)
    assert "dynamic/traffic.json#transaction_id=tx_1" in source.evidence_universe
    assert "static_analysis_report.json#candidate_id=cand_1" in source.evidence_universe
    endpoint.static["static_candidate_id_origin"] = "correlation_reference"
    assert not build_context_analyst_input(endpoint).evidence_refs["static_candidates"]


def test_missing_refs_excluded_and_availability_can_only_narrow(endpoint):
    endpoint.dynamic["missing_transaction_ids"] = ["tx_1"]
    source = build_context_analyst_input(endpoint)
    assert not source.evidence_refs["transactions"]
    ctx_ref = source.evidence_refs["endpoint_context"][0]
    source = build_context_analyst_input(endpoint, available_evidence_refs={ctx_ref, "dynamic/traffic.json#transaction_id=tx_fake"})
    assert source.evidence_universe == (ctx_ref,)
    with pytest.raises(InputInvalid):
        build_context_analyst_input(endpoint, available_evidence_refs={"../bad.json"})


def test_input_ordering_is_deterministic(endpoint):
    endpoint.request["query_keys"] = ["z", "a", "z"]
    endpoint.response["observed_status_codes"] = [404, 200]
    endpoint.request["body_shapes"] = [{"z": "number"}, {"a": "string"}]
    first = build_context_analyst_input(endpoint).to_dict()
    endpoint.request["query_keys"].reverse(); endpoint.response["observed_status_codes"].reverse()
    endpoint.request["body_shapes"].reverse()
    assert build_context_analyst_input(endpoint).to_dict() == first


@pytest.mark.parametrize("match_type,observed,fragment", [
    ("static_only", False, "not observed in available runtime traffic"),
    ("dynamic_only", True, "no matching static candidate"),
    ("method_mismatch", True, "neither method is resolved as correct")])
def test_correlation_semantics_preserved(endpoint, match_type, observed, fragment):
    endpoint.static["match_type"] = match_type; endpoint.dynamic["observed"] = observed
    endpoint.dynamic["observed_methods"] = ["POST"]
    endpoint.methods = ["GET", "POST"]
    source = build_context_analyst_input(endpoint)
    assert any(fragment in f["statement"] for f in source.fact_catalog)
    assert source.static_context["static_method"] == "GET"
    assert source.dynamic_context["observed_methods"] == ["POST"]


def test_https_traffic_and_exploration_gaps(endpoint):
    endpoint.visibility["https_visibility"] = "unavailable"
    source = build_context_analyst_input(endpoint, coverage_metadata={"traffic_available": False, "stop_reason": "max_steps"})
    kinds = {g["kind"] for g in source.coverage["gaps"]}
    assert {"https_visibility_unavailable", "traffic_unavailable", "max_steps"} <= kinds


def test_unknown_not_false_and_static_auth_not_observable(endpoint):
    source = build_context_analyst_input(endpoint)
    assert source.auth_context["bearer_token_present"] is None
    assert source.auth_context["api_key_header_present"] is False
    endpoint.auth = {}; endpoint.runtime_context = {}
    source = build_context_analyst_input(endpoint)
    assert all(v is None for v in source.auth_context.values())
    assert source.runtime_context["crash_observed"] is None
    endpoint.static["match_type"] = "static_only"; endpoint.dynamic["observed"] = False
    endpoint.auth = {"cookie_present": False}
    assert build_context_analyst_input(endpoint).auth_context["cookie_present"] is None


def test_literal_numeric_does_not_manufacture_resource_template(endpoint):
    endpoint.path = "/orders/123"; endpoint.request = {}
    source = build_context_analyst_input(endpoint)
    assert not source.request_context["resource_identifier_keys"]
    assert "object_authorization_candidate" not in source.hypothesis_catalog


def test_static_only_admin_has_no_function_authorization_hypothesis(endpoint):
    endpoint.path = "/admin/action"; endpoint.static["match_type"] = "static_only"
    endpoint.dynamic["observed"] = False; endpoint.request = {}
    source = build_context_analyst_input(endpoint)
    assert "function_authorization_candidate" not in source.hypothesis_catalog
    assert "object_authorization_candidate" not in source.hypothesis_catalog


def test_bounds_are_explicit_and_preserve_gap(endpoint):
    endpoint.request["query_keys"] = [f"key_{i}" for i in range(40)]
    source = build_context_analyst_input(endpoint)
    assert len(source.request_context["query_keys"]) == 32
    assert source.coverage["input_truncated"] is True
    assert any("bounded" in g["description"] for g in source.coverage["gaps"])
    endpoint.request["query_keys"] = [f"key_{i}" for i in range(257)]
    with pytest.raises(InputInvalid):
        build_context_analyst_input(endpoint)


def test_load_one_endpoint_reuses_canonical_artifact(tmp_path, endpoint):
    other = replace(endpoint, endpoint_context_id="ctx_other", host="other.example.com")
    artifact = EndpointContextArtifact(endpoints=[other, endpoint])
    artifact.save_atomic(tmp_path / "dynamic" / "endpoint_contexts.json")
    source = load_context_analyst_input(tmp_path, "ctx_1")
    assert "other.example.com" not in json.dumps(source.to_dict())
    with pytest.raises(InputInvalid):
        load_context_analyst_input(tmp_path, "ctx_missing")


def test_actual_endpoint_builder_is_consumable():
    from tests.test_endpoint_context_builder import evidence, context
    endpoint = context(evidence.__wrapped__())
    source = build_context_analyst_input(endpoint)
    assert source.endpoint["path"] == "/login"
    assert source.auth_context["authorization_header_present"] is True
    assert "authentication_endpoint" in source.supported_roles
    assert "TOKEN_SECRET" not in json.dumps(source.to_dict())


@pytest.mark.parametrize("path", ["/users/123", "/orders/550e8400-e29b-41d4-a716-446655440000", "/users/literal{id}"])
def test_only_explicit_segments_produce_path_identifier_context(endpoint, path):
    endpoint.path = path; endpoint.request = {}
    assert not build_context_analyst_input(endpoint).request_context["resource_identifier_keys"]


@pytest.mark.parametrize("path", ["/orders/{id}", "/orders/:userId", "/orders/<order_id>"])
def test_existing_explicit_placeholder_syntax_preserved(endpoint, path):
    endpoint.path = path; endpoint.request = {}
    assert build_context_analyst_input(endpoint).request_context["resource_identifier_keys"]


def test_no_body_evidence_does_not_become_false_absence(endpoint):
    endpoint.static["match_type"] = "static_only"; endpoint.dynamic["observed"] = False
    endpoint.request = {"body_present": False}; endpoint.response = {"body_present": False}
    source = build_context_analyst_input(endpoint)
    assert source.request_context["body_present"] is None and source.response_context["body_present"] is None


def test_runtime_events_are_observations_not_causation(endpoint):
    endpoint.runtime_context["crash_observed"] = True
    source = build_context_analyst_input(endpoint)
    assert any("crash_observed: observed; causality is unknown" in f["statement"] for f in source.fact_catalog)
