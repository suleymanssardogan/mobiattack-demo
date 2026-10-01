"""Focused Task 9.4 policy integration; entirely synthetic, zero execution."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import ast

import pytest

from src.agent.context_analyst import analyze_endpoint_context
from src.agent.model_client import ModelMetadata
from src.agent.models import ContractError, POLICY_VERSION
from src.agent.policy import EvidenceRecord, PreconditionRecord, evaluate_proposal
from src.agent.policy_integration import (evaluate_planned_proposal, evaluate_test_plan,
    load_policy_decisions, save_policy_decisions, PolicyEvaluationResult)
from src.agent.test_planner import plan_endpoint_tests, TestPlannerResult
from tests.test_context_analyst_input import endpoint
from tests.context_analyst_fakes import FakeModelClient, TIME
from tests.test_planner_fakes import PlannerFake

CTX = "dynamic/endpoint_contexts.json#endpoint_context_id=ctx_1"
TX = "dynamic/traffic.json#transaction_id=tx_1"


@pytest.fixture
def pipeline(endpoint):
    analyst_client = FakeModelClient()
    analyst = analyze_endpoint_context(endpoint, analyst_client, created_at=TIME)
    planner_client = PlannerFake()
    plan = plan_endpoint_tests(endpoint, analyst, planner_client, created_at=TIME)
    assert analyst.status == plan.status == "completed"
    index = {CTX: EvidenceRecord(CTX, "ctx_1", "endpoint_context"),
             TX: EvidenceRecord(TX, "ctx_1", "traffic_transaction")}
    return endpoint, analyst, plan, index, analyst_client, planner_client


def get(pipeline, test="INPUT_VALIDATION"):
    return next(p for p in pipeline[2].proposals if p.test_id == test)


def prerequisites(pipeline, proposal):
    from src.agent.test_catalog import TEST_CATALOG
    # Synthetic resolver fixture explicitly vouches for expected-behavior evidence.
    # Credential/header presence alone is never used as proof of auth/ownership.
    return {key: PreconditionRecord(key, pipeline[0].endpoint_context_id, (CTX, TX))
            for key in proposal.required_context if key not in TEST_CATALOG[proposal.test_id].required_context}


def gate(pipeline, p=None, **kwargs):
    return evaluate_planned_proposal(p if p is not None else get(pipeline),
        pipeline[0], pipeline[1], pipeline[3], **kwargs)


@pytest.mark.parametrize("test", ["INPUT_VALIDATION", "AUTHENTICATION_PRESENCE", "SESSION_HANDLING", "PARAMETER_CONSISTENCY"])
def test_valid_low_passive_abstract_actions_allow_without_execution(pipeline, test):
    p = get(pipeline, test)
    before = deepcopy((pipeline[0], p))
    d = gate(pipeline, p, precondition_index=prerequisites(pipeline, p))
    assert (d.decision, d.reason_code) == ("allow", "ALLOWED")
    assert d.proposal_id == p.proposal_id
    assert (d.endpoint_context_id, d.hypothesis_id, d.test_id) == (p.endpoint_context_id, p.hypothesis_id, p.test_id)
    assert (pipeline[0], p) == before
    assert d.policy_version == POLICY_VERSION == "policy_v1"


def test_missing_known_evidence_is_needs_evidence(pipeline):
    p = get(pipeline)
    del pipeline[3][TX]
    d = gate(pipeline, precondition_index=prerequisites(pipeline, p))
    assert (d.decision, d.reason_code) == ("needs_evidence", "MISSING_EVIDENCE")


def test_missing_required_context_is_needs_evidence(pipeline):
    d = gate(pipeline)
    assert (d.decision, d.reason_code) == ("needs_evidence", "MISSING_REQUIRED_CONTEXT")
    assert "Expected input behavior" in d.reason or "Comparable input observations" in d.reason


@pytest.mark.parametrize("risk", ["medium", "high", "destructive"])
def test_blocked_risks_deny(pipeline, risk):
    p = get(pipeline, "OBJECT_AUTHORIZATION")
    if risk != "medium": p = replace(p, risk_class=risk)
    assert gate(pipeline, p).decision == "deny"


@pytest.mark.parametrize("change,code", [("test", "UNKNOWN_TEST"), ("endpoint", "UNKNOWN_ENDPOINT_CONTEXT"),
    ("hypothesis", "UNKNOWN_HYPOTHESIS"), ("missing_hypothesis", "SCHEMA_INVALID"),
    ("reference", "HALLUCINATED_EVIDENCE"), ("risk", "RISK_NOT_ALLOWED"),
    ("parameter", "PARAMETER_NOT_IN_EVIDENCE")])
def test_invalid_proposals_deny_with_stable_codes(pipeline, change, code):
    p = get(pipeline).to_dict()
    if change == "test": p["test_id"] = "AI_SMART_HACK"
    if change == "endpoint": p["endpoint_context_id"] = "ctx_other"
    if change == "hypothesis": p["hypothesis_id"] = "hyp_unknown"
    if change == "missing_hypothesis": p.pop("hypothesis_id")
    if change == "reference": p["evidence_refs"] += ("dynamic/traffic.json#transaction_id=tx_fake_999",)
    if change == "risk": p["risk_class"] = "passive"
    if change == "parameter": p["requested_action"]["parameters"] = [{"location": "body", "name": "unknown_user_id"}]
    d = gate(pipeline, p)
    assert (d.decision, d.reason_code) == ("deny", code)


@pytest.mark.parametrize("field,value", [("action", "GET /users/123"), ("action", "curl http://api.example.com"),
    ("action", "POST /admin/delete"), ("action", "purchase"), ("action", "transfer"),
    ("host", "api.example.com"), ("path", "/orders/123"), ("method", "POST"),
    ("raw_request", "Authorization: Bearer SECRET"), ("request_body", {"sql": "PAYLOAD"})])
def test_concrete_raw_destructive_network_instructions_deny(pipeline, field, value):
    p = get(pipeline).to_dict(); p["requested_action"][field] = value
    d = gate(pipeline, p)
    assert d.decision == "deny"
    assert "SECRET" not in json.dumps(d.to_dict()) and "PAYLOAD" not in json.dumps(d.to_dict())


def test_catalog_medium_cannot_be_downgraded(pipeline):
    p = replace(get(pipeline, "OBJECT_AUTHORIZATION"), risk_class="low")
    assert gate(pipeline, p).reason_code == "RISK_NOT_ALLOWED"


def test_orphan_and_scope_mismatched_precondition_evidence_deny(pipeline):
    p = get(pipeline); records = prerequisites(pipeline, p)
    key = sorted(records)[0]
    records[key] = PreconditionRecord(key, "ctx_other", (CTX,))
    assert gate(pipeline, precondition_index=records).decision == "deny"
    records[key] = PreconditionRecord(key, "ctx_1", ("dynamic/traffic.json#transaction_id=tx_fake_999",))
    assert gate(pipeline, precondition_index=records).decision == "deny"


def test_endpoint_evidence_spoof_deny_vs_known_missing_needs_evidence(pipeline):
    pipeline[3][TX] = EvidenceRecord(TX, "ctx_other", "traffic_transaction")
    assert gate(pipeline).decision == "deny"
    pipeline[3].pop(TX)
    assert gate(pipeline).decision == "needs_evidence"


def test_unknown_context_not_converted_to_absent_and_https_gap_not_global_deny(endpoint):
    endpoint.auth["authorization_header_present"] = None
    endpoint.visibility["https_visibility"] = "unavailable"
    a = analyze_endpoint_context(endpoint, FakeModelClient(), created_at=TIME)
    p = plan_endpoint_tests(endpoint, a, PlannerFake(), created_at=TIME)
    f = (endpoint, a, p, {CTX: EvidenceRecord(CTX, "ctx_1", "endpoint_context"),
                        TX: EvidenceRecord(TX, "ctx_1", "traffic_transaction")})
    d = gate(f)
    assert endpoint.auth["authorization_header_present"] is None
    assert d.decision == "needs_evidence"
    assert gate(f, precondition_index=prerequisites(f, get(f))).decision == "allow"


def test_deterministic_id_and_policy_version(pipeline):
    p = get(pipeline); records = prerequisites(pipeline, p)
    a = gate(pipeline, precondition_index=records)
    b = gate(pipeline, p.to_dict(), precondition_index=dict(reversed(list(records.items()))))
    assert a == b and a.decision_id.startswith("policy_")
    result = evaluate_test_plan(*pipeline[:4], precondition_index=records, created_at=TIME)
    assert result.policy_version == a.policy_version
    assert PolicyEvaluationResult.from_dict(result.to_dict()) == result
    tampered = result.to_dict(); tampered["allow_count"] += 1
    with pytest.raises(ContractError): PolicyEvaluationResult.from_dict(tampered)


@pytest.mark.parametrize("status", ["invalid_output", "model_error", "input_invalid"])
def test_failed_planner_has_zero_decisions_and_no_work(pipeline, status):
    failed = TestPlannerResult("planning_failed", "ctx_1", TIME, status)
    r = evaluate_test_plan(pipeline[0], pipeline[1], failed, pipeline[3], created_at=TIME)
    assert r.status == "not_processed" and r.decision_count == 0


def test_empty_planner_zero_decisions_and_proposal_array_supported(pipeline):
    e, a, _, index, _, client = pipeline
    empty = plan_endpoint_tests(e, a, client, catalog_test_ids=[], created_at=TIME)
    r = evaluate_test_plan(e, a, empty, index, created_at=TIME)
    assert r.status == "no_proposals" and r.decisions == ()
    p = get(pipeline)
    r = evaluate_test_plan(e, a, [p], index, precondition_index=prerequisites(pipeline, p), created_at=TIME)
    assert r.allow_count == r.decision_count == 1
    r = evaluate_test_plan(e, a, [replace(p, endpoint_context_id="ctx_other")], index, created_at=TIME)
    assert r.deny_count == 1


def test_one_synthetic_pipeline_all_decisions_zero_llm_network_execution(pipeline, tmp_path, monkeypatch):
    import socket, urllib.request, subprocess
    import src.agent.test_planner.service as planner_service
    import src.agent.context_analyst.service as analyst_service
    e, a, plan, index, ac, pc = pipeline
    before = deepcopy((e, a, plan))
    upstream_calls = (len(ac.requests), len(pc.requests))
    def forbidden(*args, **kwargs): raise AssertionError("No model/tools/execution allowed")
    monkeypatch.setattr(ac, "generate", forbidden); monkeypatch.setattr(pc, "generate", forbidden)
    monkeypatch.setattr(planner_service, "plan_endpoint_tests", forbidden)
    monkeypatch.setattr(analyst_service, "analyze_endpoint_context", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden); monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden); monkeypatch.setattr(subprocess, "Popen", forbidden)
    records = prerequisites(pipeline, get(pipeline))
    records.update(prerequisites(pipeline, get(pipeline, "AUTHENTICATION_PRESENCE")))
    result = evaluate_test_plan(e, a, plan, index, precondition_index=records, created_at=TIME)
    assert {d.decision for d in result.decisions} == {"allow", "needs_evidence", "deny"}
    assert result.allow_count and result.needs_evidence_count and result.deny_count
    assert upstream_calls == (len(ac.requests), len(pc.requests))
    assert (e, a, plan) == before and list(tmp_path.iterdir()) == []
    assert all(d.proposal_id in {p.proposal_id for p in plan.proposals} for d in result.decisions)
    assert all(d.hypothesis_id in {h.hypothesis_id for h in a.hypotheses} for d in result.decisions)
    assert "chain_of_thought" not in json.dumps(result.trace)


def test_atomic_persistence_failure_isolation_and_product_boundary(pipeline, tmp_path, monkeypatch):
    from src.scan_state import create_initial_scan_state, load_scan_state, save_scan_state
    import src.agent.policy_integration.persistence as persistence
    save_scan_state(tmp_path, create_initial_scan_state("synthetic", "https://example.com/app.apk"))
    (tmp_path / "agent").mkdir(exist_ok=True)
    names = ["scan_state.json", "agent/context_analysis.json", "agent/test_plans.json",
             "dynamic_analysis_report.json", "dynamic/endpoint_contexts.json", "dynamic/traffic.json"]
    for name in names[1:]:
        p = tmp_path / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(b"UPSTREAM")
    before = {name: (tmp_path/name).read_bytes() for name in names}
    result = evaluate_test_plan(*pipeline[:4], created_at=TIME)
    path = save_policy_decisions(tmp_path, [result])
    assert path == tmp_path / "agent/policy_decisions.json"
    assert load_policy_decisions(tmp_path) == (result,)
    snapshot = path.read_bytes()
    def fail(*args): raise OSError("synthetic atomic replace failure")
    monkeypatch.setattr(persistence.os, "replace", fail)
    with pytest.raises(OSError): save_policy_decisions(tmp_path, [result])
    assert path.read_bytes() == snapshot and not list(path.parent.glob(".tmp_*"))
    assert {name: (tmp_path/name).read_bytes() for name in names} == before
    assert not list(tmp_path.rglob("agent_report.json"))
    assert load_scan_state(tmp_path)["stages"]["agent_analysis"]["status"] == "not_available"
    skipped = PolicyEvaluationResult("evaluation_skip", "plan_skip", "ctx_1", TIME, "not_processed")
    assert save_policy_decisions(tmp_path, [skipped]) == path and path.read_bytes() == snapshot
    path.write_text("corrupt")
    with pytest.raises(ContractError): save_policy_decisions(tmp_path, [result])
    assert path.read_text() == "corrupt"


def test_policy_has_no_model_execution_or_tool_imports():
    paths = [Path("src/agent/policy.py"), *Path("src/agent/policy_integration").glob("*.py")]
    for path in paths:
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                assert not {n.name.split(".")[0] for n in node.names} & {"requests", "httpx", "socket", "subprocess", "openai", "urllib"}
            if isinstance(node, ast.ImportFrom):
                assert not any(n.name in {"AgentModelClient", "ModelRequest", "analyze_endpoint_context", "plan_endpoint_tests"} for n in node.names)


def test_pure_gate_evaluates_actual_missing_catalog_context_and_unknown_auth(pipeline):
    e, a, _, index, _, _ = pipeline
    p = get(pipeline)
    kwargs = {"proposal_only": True, "hypothesis_ids": tuple(h.hypothesis_id for h in a.hypotheses),
              "available_evidence_refs": a.input_evidence_refs, "precondition_index": prerequisites(pipeline, p)}
    e.request["body_present"] = None
    d = evaluate_proposal(p, {e.endpoint_context_id: e}, index, **kwargs)
    assert (d.decision, d.reason_code) == ("needs_evidence", "MISSING_REQUIRED_CONTEXT")
    p = get(pipeline, "AUTHENTICATION_PRESENCE")
    kwargs["precondition_index"] = prerequisites(pipeline, p)
    e.auth = {key: None for key in e.auth}
    assert evaluate_proposal(p, {e.endpoint_context_id: e}, index, **kwargs).decision == "needs_evidence"
    assert all(v is None for v in e.auth.values())


def test_declared_but_unavailable_transaction_is_missing_not_hallucinated(pipeline):
    e, a, _, index, _, _ = pipeline
    e.dynamic["missing_transaction_ids"] = ["tx_1"]
    p = get(pipeline)
    d = evaluate_proposal(p, {"ctx_1": e}, index, proposal_only=True,
                         hypothesis_ids=tuple(h.hypothesis_id for h in a.hypotheses),
                         available_evidence_refs=a.input_evidence_refs)
    assert (d.decision, d.reason_code) == ("needs_evidence", "MISSING_EVIDENCE")


@pytest.mark.parametrize("change", ["unknown_test", "risk", "concrete", "malformed_parameter"])
def test_completed_envelope_invalid_proposal_denies_instead_of_disappearing(pipeline, change):
    e, a, plan, index, _, _ = pipeline
    raw = plan.to_dict()
    p = next(p for p in raw["proposals"] if p["test_id"] == "INPUT_VALIDATION")
    pid = p["proposal_id"]
    if change == "unknown_test": p["test_id"] = "AI_SMART_HACK"
    if change == "risk": p["risk_class"] = "passive"
    if change == "concrete": p["requested_action"]["path"] = "/orders/123"
    if change == "malformed_parameter": p["requested_action"]["parameters"] = [{"location": [], "name": "invented"}]
    result = evaluate_test_plan(e, a, raw, index, created_at=TIME)
    assert result.status == "evaluated" and result.decision_count == len(plan.proposals)
    assert next(d for d in result.decisions if d.proposal_id == pid).decision == "deny"
