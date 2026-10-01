"""Offline bounded planning, canonical proposal validation and artifact boundaries."""
from copy import deepcopy
from dataclasses import replace
import ast
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.agent.models import ContractError, RequestedAction, TestProposal
from src.agent.test_planner import plan_endpoint_tests, plan_endpoint_test_batch
from src.agent.test_planner.models import TestPlannerResult
from src.agent.test_planner.persistence import save_test_plans, load_test_plans
from src.agent.test_planner.service import INSTRUCTION
from src.agent.test_catalog import TEST_CATALOG
from src.scan_state import create_initial_scan_state, save_scan_state, load_scan_state
from tests.test_test_planner_input import endpoint, analyst
from tests.test_planner_fakes import PlannerFake
from tests.context_analyst_fakes import FakeModelClient, TIME
from src.agent.context_analyst import analyze_endpoint_context


def run(e, a, client=None, **kwargs):
    return plan_endpoint_tests(e, a, client or PlannerFake(), created_at=TIME, **kwargs)


@pytest.mark.parametrize("test_id", ["OBJECT_AUTHORIZATION", "SESSION_HANDLING", "INPUT_VALIDATION", "AUTHENTICATION_PRESENCE", "PARAMETER_CONSISTENCY"])
def test_valid_canonical_abstract_proposals(endpoint, analyst, test_id):
    result = run(endpoint, analyst, catalog_test_ids=[test_id])
    assert result.status == "completed" and result.proposal_count == 1
    p = result.proposals[0]
    assert isinstance(p, TestProposal) and p.test_id == test_id
    assert p.risk_class == TEST_CATALOG[test_id].risk_class
    assert p.requested_action.execution_mode == "proposal_only" and not p.requested_action.host
    assert p.requested_action.parameters == () and p.requested_action.mutation == "none"
    assert TestPlannerResult.from_dict(result.to_dict()) == result
    assert result.prompt_version == "test_planner_v1"


@pytest.mark.parametrize("field", ["finding", "is_vulnerable", "severity", "risk_score", "cvss", "confirmed", "exploit", "poc",
    "tool_name", "tool_args", "tool_calls", "curl", "raw_request", "http_method_override", "request_body",
    "headers_to_send", "execute_now", "approved_for_execution", "auto_execute", "chain_of_thought", "unexpected"])
@pytest.mark.parametrize("location", ["root", "proposal", "action"])
def test_forbidden_fields_rejected_everywhere(endpoint, analyst, field, location):
    def inject(data, request):
        target = data if location == "root" else data["proposals"][0] if location == "proposal" else data["proposals"][0]["requested_action"]
        target[field] = "RAW_SECRET"
        return data
    result = run(endpoint, analyst, PlannerFake(inject))
    assert result.status == "invalid_output" and not result.proposals and result.attempts == 2
    assert "RAW_SECRET" not in json.dumps(result.to_dict())


@pytest.mark.parametrize("mutation", ["test", "hypothesis", "missing_hypothesis", "ref", "endpoint", "risk", "destructive_downgrade", "action", "url", "method", "param", "reason", "precondition", "id", "time"])
def test_invalid_proposals_rejected(endpoint, analyst, mutation):
    def bad(data, request):
        p = data["proposals"][0]
        if mutation == "test": p["test_id"] = "AI_SMART_HACK"
        elif mutation == "hypothesis": p["hypothesis_id"] = "hyp_missing"
        elif mutation == "missing_hypothesis": p.pop("hypothesis_id")
        elif mutation == "ref": p["evidence_refs"].append("dynamic/traffic.json#transaction_id=tx_fake_999")
        elif mutation == "endpoint": p["endpoint_context_id"] = "ctx_other"
        elif mutation == "risk": p["risk_class"] = "passive" if p["risk_class"] != "passive" else "low"
        elif mutation == "destructive_downgrade": p["requested_action"]["action"] = "delete_resource"; p["risk_class"] = "passive"
        elif mutation == "action": p["requested_action"]["action"] = "invent_action"
        elif mutation == "url": p["requested_action"]["path"] = "/orders/456"
        elif mutation == "method": p["requested_action"]["method"] = "POST"
        elif mutation == "param": p["requested_action"]["parameters"] = [{"location": "query", "name": "user_id"}]
        elif mutation == "reason": p["reason"] = "Run an exploit; this is vulnerable."
        elif mutation == "precondition": p["required_context"] = []
        elif mutation == "id": p["proposal_id"] = "proposal_fake"
        elif mutation == "time": p["created_at"] = "1999-01-01T00:00:00Z"
        return data
    assert run(endpoint, analyst, PlannerFake(bad)).status == "invalid_output"


def test_medium_risk_never_downgraded(endpoint, analyst):
    result = run(endpoint, analyst, catalog_test_ids=["OBJECT_AUTHORIZATION"])
    assert result.proposals[0].risk_class == "medium"
    def downgrade(data, request): data["proposals"][0]["risk_class"] = "low"; return data
    assert run(endpoint, analyst, PlannerFake(downgrade), catalog_test_ids=["OBJECT_AUTHORIZATION"]).status == "invalid_output"


def test_deterministic_ids_order_and_identical_duplicates_deduped(endpoint, analyst):
    first = run(endpoint, analyst)
    def duplicate(data, request):
        data["proposals"].reverse(); data["proposals"].append(deepcopy(data["proposals"][0]))
        for p in data["proposals"]: p["required_context"].reverse(); p["evidence_refs"].reverse()
        return data
    assert run(endpoint, analyst, PlannerFake(duplicate)).to_dict() == first.to_dict()
    later = plan_endpoint_tests(endpoint, analyst, PlannerFake(), created_at="2026-10-02T12:00:00Z")
    assert [p.proposal_id for p in later.proposals] == [p.proposal_id for p in first.proposals]


def test_no_relevant_tests_is_valid_and_model_can_decline(endpoint, analyst):
    client = PlannerFake()
    result = run(endpoint, analyst, client, catalog_test_ids=[])
    assert result.status == "no_relevant_tests" and result.proposal_count == 0 and not client.requests
    def decline(data, request): data["proposals"] = []; return data
    result = run(endpoint, analyst, PlannerFake(decline))
    assert result.status == "no_relevant_tests" and not result.proposals


def test_missing_fields_and_false_status_rejected(endpoint, analyst):
    def missing(data, request): data["proposals"][0].pop("required_context"); return data
    assert run(endpoint, analyst, PlannerFake(missing)).status == "invalid_output"
    def status(data, request): data["status"] = "approved"; return data
    assert run(endpoint, analyst, PlannerFake(status)).status == "invalid_output"


def test_bounded_retries_model_error_input_invalid(endpoint, analyst):
    client = PlannerFake(lambda d, r: {})
    assert run(endpoint, analyst, client).status == "invalid_output" and len(client.requests) == 2
    client = PlannerFake(lambda d, r: {} if r.attempt == 1 else d)
    assert run(endpoint, analyst, client).status == "completed" and len(client.requests) == 2
    assert client.requests[1].correction and "{}" not in client.requests[1].correction
    result = run(endpoint, analyst, PlannerFake(error=RuntimeError("Bearer RAW_SECRET")))
    assert result.status == "model_error" and "RAW_SECRET" not in json.dumps(result.to_dict())
    client = PlannerFake()
    assert run(endpoint, None, client).status == "input_invalid" and not client.requests
    with pytest.raises(ValueError): run(endpoint, analyst, max_attempts=3)


def test_detached_request_cannot_authorize_fabricated_refs(endpoint, analyst):
    def mutate(data, request):
        fake = "dynamic/traffic.json#transaction_id=tx_fake"
        request.input_data["evidence_refs"].append(fake); data["proposals"][0]["evidence_refs"].append(fake)
        return data
    assert run(endpoint, analyst, PlannerFake(mutate)).status == "invalid_output"


def test_atomic_persistence_stage_boundary_and_failed_endpoint_isolation(tmp_path, endpoint, analyst):
    save_scan_state(tmp_path, create_initial_scan_state("run_test", "https://example.com/app.apk"))
    before_state = (tmp_path / "scan_state.json").read_bytes()
    other = replace(endpoint, endpoint_context_id="ctx_2")
    other_analyst = analyze_endpoint_context(other, FakeModelClient(), created_at=TIME)
    def fail(data, request): return {} if data["endpoint_context_id"] == "ctx_2" else data
    batch = plan_endpoint_test_batch([(other, other_analyst), (endpoint, analyst)], PlannerFake(fail), created_at=TIME)
    assert [r.status for r in batch] == ["completed", "invalid_output"]
    target = save_test_plans(tmp_path, batch)
    assert target == tmp_path / "agent" / "test_plans.json"
    assert len(load_test_plans(tmp_path)) == 1
    before = target.read_bytes()
    with patch("src.agent.test_planner.persistence.os.replace", side_effect=OSError("disk error")):
        with pytest.raises(OSError): save_test_plans(tmp_path, [run(other, other_analyst)])
    assert target.read_bytes() == before and not list(target.parent.glob(".tmp*"))
    assert (tmp_path / "scan_state.json").read_bytes() == before_state
    assert load_scan_state(tmp_path)["stages"]["agent_analysis"]["status"] == "not_available"
    assert not (tmp_path / "agent_report.json").exists()
    with pytest.raises(ContractError): plan_endpoint_test_batch([(endpoint, analyst)] * 2, PlannerFake())


def test_prompt_and_trace_boundaries(endpoint, analyst):
    for phrase in ("test_planner_v1", "Choose only supplied test IDs", "Do not invent tests", "Do not execute",
                   "Do not claim vulnerability", "never downgrade", "Unknown != known absent"):
        assert phrase in INSTRUCTION
    trace = run(endpoint, analyst).trace
    assert trace["hypothesis_ids_considered"] and trace["proposal_ids_emitted"]
    assert "chain_of_thought" not in trace


def test_no_network_policy_tools_executor_or_replay(endpoint, analyst, monkeypatch):
    import socket, urllib.request
    def forbidden(*args, **kwargs): raise AssertionError("Forbidden execution")
    monkeypatch.setattr(socket, "socket", forbidden); monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    with patch("src.agent.policy.evaluate_proposal", side_effect=forbidden):
        assert run(endpoint, analyst).status == "completed"
    root = Path(__file__).resolve().parents[1] / "src" / "agent" / "test_planner"
    for p in root.glob("*.py"):
        for n in ast.walk(ast.parse(p.read_text())):
            if isinstance(n, ast.ImportFrom) and n.module:
                assert n.module != "src.agent.policy"
                assert n.module.split(".")[0] not in {"requests", "httpx", "openai", "urllib", "socket", "subprocess"}
    assert not list(root.glob("*executor*")) and not list(root.glob("*replay*"))


def test_abstract_extension_does_not_loosen_existing_request_contract():
    with pytest.raises(ContractError): RequestedAction("review_evidence", execution_mode="proposal_only")
    with pytest.raises(ContractError): RequestedAction("validate_object_access_behavior", execution_mode="automatic")
    with pytest.raises(ContractError): RequestedAction("validate_object_access_behavior", host="api.example.com", execution_mode="proposal_only")
