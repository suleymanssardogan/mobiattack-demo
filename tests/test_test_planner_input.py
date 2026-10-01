"""Planner input relevance, privacy and current Analyst grounding."""
from copy import deepcopy
from dataclasses import replace
import json
import pytest

from src.agent.context_analyst import analyze_endpoint_context
from src.agent.models import ContractError
from src.agent.test_catalog import TEST_CATALOG
from src.agent.test_planner import build_test_planner_input
from tests.context_analyst_fakes import FakeModelClient, TIME
from tests.test_context_analyst_input import endpoint


@pytest.fixture
def analyst(endpoint):
    return analyze_endpoint_context(endpoint, FakeModelClient(), created_at=TIME)


def build(e, **kwargs):
    a = analyze_endpoint_context(e, FakeModelClient(), created_at=TIME)
    assert a.status == "completed"
    return build_test_planner_input(e, a, **kwargs)


def test_one_endpoint_hypotheses_refs_relevant_canonical_subset(endpoint, analyst):
    source = build_test_planner_input(endpoint, analyst)
    assert source.endpoint_context_id == endpoint.endpoint_context_id
    assert {h["hypothesis_id"] for h in source.analyst["hypotheses"]} == {h.hypothesis_id for h in analyst.hypotheses}
    assert set(source.evidence_refs).issubset(analyst.input_evidence_refs)
    assert source.available_tests
    assert "FUNCTION_AUTHORIZATION" not in {t["test_id"] for t in source.available_tests}
    for test in source.available_tests: assert test["risk_class"] == TEST_CATALOG[test["test_id"]].risk_class


def test_secret_raw_body_unrelated_data_and_paths_excluded(endpoint, analyst):
    endpoint.request["headers"] = {"Authorization": "Bearer SECRET_AUTH"}
    endpoint.request["body"] = {"password": "SECRET_PASSWORD"}
    endpoint.response["body"] = {"token": "SECRET_RESPONSE"}
    endpoint.static["source_file"] = "/Users/alice/PRIVATE_PATH.smali"
    endpoint.route_context = [{"raw": "UNRELATED_ENDPOINT"}]
    serialized = json.dumps(build_test_planner_input(endpoint, analyst).to_dict())
    for secret in ("SECRET_AUTH", "SECRET_PASSWORD", "SECRET_RESPONSE", "PRIVATE_PATH", "UNRELATED_ENDPOINT"):
        assert secret not in serialized


def test_mismatched_or_failed_analyst_rejected(endpoint, analyst):
    with pytest.raises(ContractError): build_test_planner_input(replace(endpoint, endpoint_context_id="ctx_other"), analyst)
    with pytest.raises(ContractError): build_test_planner_input(endpoint, replace(analyst, status="model_error", observation=None, hypotheses=(), coverage_gaps=(), endpoint_role="unknown"))


def test_stale_or_fabricated_analyst_rejected(endpoint, analyst):
    endpoint.path = "/different"
    with pytest.raises(ContractError): build_test_planner_input(endpoint, analyst)


def test_catalog_subset_narrows_never_invents_entries(endpoint, analyst):
    source = build_test_planner_input(endpoint, analyst, catalog_test_ids=["OBJECT_AUTHORIZATION"])
    assert [t["test_id"] for t in source.available_tests] == ["OBJECT_AUTHORIZATION"]
    with pytest.raises(ContractError): build_test_planner_input(endpoint, analyst, catalog_test_ids=["AI_SMART_HACK"])


def test_login_not_automatically_object_authorization(endpoint):
    endpoint.path = "/login"; endpoint.request = {"body_present": True, "body_keys": ["username", "password"]}
    ids = {t["test_id"] for t in build(endpoint).available_tests}
    assert "AUTHENTICATION_PRESENCE" in ids and "OBJECT_AUTHORIZATION" not in ids


def test_static_only_runtime_required_tests_not_emitted(endpoint):
    endpoint.static["match_type"] = "static_only"; endpoint.dynamic["observed"] = False
    source = build(endpoint)
    assert not source.proposal_candidates
    assert any("runtime transaction baseline" in n for n in source.planning_notes)
    assert any(g.kind == "static_not_observed" for g in source.coverage_gaps)


def test_unavailable_traffic_blocks_runtime_dependent_tests(endpoint, analyst):
    source = build_test_planner_input(endpoint, analyst, coverage_metadata={"traffic_available": False})
    assert {c["test_id"] for c in source.proposal_candidates} <= {"AUTHENTICATION_PRESENCE"}
    assert any(g.kind == "traffic_unavailable" for g in source.coverage_gaps)


def test_auth_unknown_stays_unknown_and_object_preconditions_remain_missing(endpoint):
    endpoint.auth = {}
    source = build(endpoint)
    assert all(v is None for v in source.context["auth_context"].values())
    candidate = next(c for c in source.proposal_candidates if c["test_id"] == "OBJECT_AUTHORIZATION")
    assert "Authenticated baseline evidence" in candidate["required_context"]
    assert "Resource ownership evidence" in candidate["required_context"]
    assert "AUTHENTICATION_PRESENCE" not in {t["test_id"] for t in source.available_tests}


def test_parameter_consistency_not_generic_fallback(endpoint):
    endpoint.path = "/search"; endpoint.request = {"query_keys": ["q"]}
    source = build(endpoint)
    assert "PARAMETER_CONSISTENCY" not in {t["test_id"] for t in source.available_tests}
    assert "INPUT_VALIDATION" not in {t["test_id"] for t in source.available_tests}  # catalog requires body
    endpoint.static["match_type"] = "method_mismatch"; endpoint.dynamic["observed_methods"] = ["POST"]
    endpoint.methods = ["GET", "POST"]
    assert "PARAMETER_CONSISTENCY" in {t["test_id"] for t in build(endpoint).available_tests}


def test_function_authorization_needs_independent_role_evidence(endpoint):
    endpoint.path = "/admin/action"
    source = build(endpoint)
    assert any(h["hypothesis_type"] == "function_authorization_candidate" for h in source.analyst["hypotheses"])
    assert "FUNCTION_AUTHORIZATION" not in {t["test_id"] for t in source.available_tests}
    assert any("role/permission evidence" in note for note in source.planning_notes)


def test_existing_coverage_preserved_and_input_order_detached(endpoint, analyst):
    before = deepcopy(endpoint)
    first = build_test_planner_input(endpoint, analyst)
    endpoint.request["query_keys"].reverse()
    assert build_test_planner_input(endpoint, analyst).to_dict() == first.to_dict()
    first.to_dict()["context"]["endpoint"]["host"] = "changed"
    assert first.context["endpoint"]["host"] == "api.example.com"
    endpoint.request["query_keys"].reverse(); assert endpoint == before
