"""Synthetic contract tests; no agent, executor, credentials or live traffic."""
import ast
from dataclasses import fields, replace
from pathlib import Path

import pytest

from src.agent.models import (AgentHypothesis, AgentObservation, ContractError, CoverageGap,
    ParameterReference, PolicyDecision, RequestedAction, TestProposal, ToolExecutionResult,
    TransparentValidationTrace, ValidationResult, validate_trace_links, validate_transition)
from src.agent.test_catalog import TEST_CATALOG
from src.scan_state import create_initial_scan_state

CTX_REF = "dynamic/endpoint_contexts.json#endpoint_context_id=ctx_1"
TX_REF = "dynamic/traffic.json#transaction_id=tx_1"
TIME = "2026-10-01T12:00:00Z"


def proposal(test_id="AUTHENTICATION_PRESENCE", **changes):
    entry = TEST_CATALOG[test_id]
    parameters = (ParameterReference("query", "page"),) if test_id == "PARAMETER_CONSISTENCY" else ()
    action = RequestedAction(entry.allowed_actions[0], "api.example.com", "/users/1", "GET", parameters=parameters)
    if test_id == "INPUT_VALIDATION":
        action = replace(action, mutation="body_parameter", parameters=(ParameterReference("body", "name"),))
    p = TestProposal("prop_1", "hyp_1", "ctx_1", test_id, "Relevant to observed endpoint metadata",
        (CTX_REF, TX_REF), (), action, entry.risk_class, TIME)
    return replace(p, **changes)


def hypothesis():
    return AgentHypothesis("hyp_1", "ctx_1", "auth_presence", "Authentication presence requires review",
                           (CTX_REF,), ())


def validation(state="validated", **changes):
    return replace(ValidationResult("val_1", "prop_1", "exec_1", state, (TX_REF,),
        ("Compare expected access with observed behavior",), "Observed metadata", "Evidence reviewed", False), **changes)


def execution():
    return ToolExecutionResult("exec_1", "prop_1", "AUTHENTICATION_PRESENCE", TIME, TIME,
                               "completed", (TX_REF,), (TX_REF,), (), None)


def test_catalog_ids_and_immutable_entries():
    assert set(TEST_CATALOG) == {"AUTHENTICATION_PRESENCE", "OBJECT_AUTHORIZATION", "FUNCTION_AUTHORIZATION",
                                "SESSION_HANDLING", "INPUT_VALIDATION", "PARAMETER_CONSISTENCY"}
    required = {"test_id", "name", "category", "risk_class", "required_context", "required_evidence",
                "allowed_mutations", "validation_requirements", "stop_conditions", "auto_execution_allowed"}
    assert required <= {f.name for f in fields(next(iter(TEST_CATALOG.values())))}
    with pytest.raises(TypeError):
        TEST_CATALOG["FAKE"] = next(iter(TEST_CATALOG.values()))
    assert TEST_CATALOG["AUTHENTICATION_PRESENCE"].risk_class == "passive"
    assert TEST_CATALOG["PARAMETER_CONSISTENCY"].risk_class == "low"


@pytest.mark.parametrize("field,value", [("test_id", "FAKE"), ("endpoint_context_id", ""),
    ("risk_class", "critical"), ("evidence_refs", ()), ("created_at", "2026-10-01T12:00:00"),
    ("created_at", "yesterday"), ("reason", "Authorization: SECRET")])
def test_invalid_proposals_fail_schema(field, value):
    data = proposal().to_dict(); data[field] = value
    with pytest.raises(ContractError):
        TestProposal.from_dict(data)


@pytest.mark.parametrize("model", [proposal(), hypothesis(), validation(), execution(),
    AgentObservation("obs_1", "ctx_1", ("Auth metadata present",), (CTX_REF,), (), TIME),
    CoverageGap("gap_1", "ctx_1", "static_not_observed", "Not observed in this capture", (), ())])
def test_models_roundtrip_and_reject_extra_output(model):
    assert type(model).from_dict(model.to_dict()) == model
    data = model.to_dict(); data["vulnerability_verdict"] = "confirmed"
    with pytest.raises(ContractError):
        type(model).from_dict(data)


@pytest.mark.parametrize("state", ["invented", "observed", "validated", "confirmed"])
def test_hypothesis_cannot_self_promote(state):
    with pytest.raises(ContractError):
        replace(hypothesis(), status=state)


def test_hypothesis_requires_evidence():
    with pytest.raises(ContractError):
        replace(hypothesis(), evidence_refs=())


@pytest.mark.parametrize("ref", ["../traffic.json", "/tmp/report.json", "https://example.com/",
    "dynamic/traffic.json#transaction_id=tx_1?token=secret", "dynamic/traffic.json#unknown=tx_1"])
def test_noncanonical_or_value_bearing_evidence_rejected(ref):
    with pytest.raises(ContractError):
        replace(hypothesis(), evidence_refs=(ref,))


@pytest.mark.parametrize("state", ["validated", "rejected", "inconclusive", "blocked"])
def test_validation_states(state):
    assert validation(state).state == state


def test_validated_result_requires_refs_and_reproduction():
    with pytest.raises(ContractError):
        validation(evidence_refs=())
    with pytest.raises(ContractError):
        validation(reproducible=True)
    with pytest.raises(ContractError):
        validation("rejected", reproducible=True, reproduction_refs=(TX_REF,))
    with pytest.raises(ContractError):
        validation(state="confirmed")
    with pytest.raises(ContractError):
        validation(reproducible=True, reproduction_refs=(TX_REF,))
    assert validation("inconclusive", evidence_refs=()).state == "inconclusive"


@pytest.mark.parametrize("current,target", [("hypothesis", "confirmed"), ("planned", "validated"),
    ("observed", "confirmed"), ("confirmed", "planned"), ("invented", "planned"), ("blocked", "executed")])
def test_invalid_lifecycle_edges(current, target):
    with pytest.raises(ContractError):
        validate_transition(current, target)


def test_lifecycle_requires_validation_and_reproduction():
    for current, target in [("hypothesis", "planned"), ("planned", "executed"), ("executed", "observed"),
                            ("planned", "blocked"), ("executed", "inconclusive"), ("observed", "rejected"),
                            ("validated", "inconclusive")]:
        validate_transition(current, target)
    with pytest.raises(ContractError):
        validate_transition("observed", "validated", validation=execution())
    validate_transition("observed", "validated", validation=validation())
    with pytest.raises(ContractError):
        validate_transition("validated", "confirmed", validation=validation())
    validate_transition("validated", "confirmed", validation=validation(reproducible=True, reproduction_refs=("dynamic/traffic.json#transaction_id=tx_repeat",)))


def test_tool_success_is_not_a_finding():
    with pytest.raises(ContractError):
        replace(execution(), status="confirmed")
    with pytest.raises(ContractError):
        replace(execution(), request_refs=(), response_refs=())
    assert not {"finding", "severity", "validated", "vulnerability"} & {f.name for f in fields(ToolExecutionResult)}
    assert not {"finding", "verdict", "severity", "vulnerability"} & {f.name for f in fields(AgentObservation)}


def test_coverage_gap_is_independent_and_honest():
    gap = CoverageGap("gap_1", None, "traffic_unavailable", "Capture unavailable", (), ())
    assert gap.endpoint_context_id is None and gap.evidence_refs == ()
    assert "hypothesis_id" not in gap.to_dict()
    with pytest.raises(ContractError):
        replace(gap, kind="secure")


def test_structured_trace_links_no_hidden_reasoning():
    p, h, v, e = proposal(), hypothesis(), validation(), execution()
    policy = PolicyDecision("policy_1", p.proposal_id, "allow", "ALLOWED", "Contract eligible", p.evidence_refs)
    trace = TransparentValidationTrace("trace_1", h.hypothesis_id, p.proposal_id, policy.decision_id,
        ("Metadata observed",), (CTX_REF, TX_REF), v.validation_criteria, "stop", "Review complete", e.execution_id, v.validation_id)
    validate_trace_links(trace, h, p, policy, e, v)
    assert TransparentValidationTrace.from_dict(trace.to_dict()) == trace
    with pytest.raises(ContractError):
        validate_trace_links(replace(trace, proposal_id="prop_other"), h, p, policy, e, v)
    with pytest.raises(ContractError):
        validate_trace_links(trace, h, p, replace(policy, decision="deny"), e, v)
    with pytest.raises(ContractError):
        validate_trace_links(replace(trace, evidence_refs=("dynamic/traffic.json#transaction_id=tx_other",)), h, p, policy, e, v)
    with pytest.raises(ContractError):
        TransparentValidationTrace.from_dict({**trace.to_dict(), "chain_of_thought": "private"})


def test_schemas_need_no_secret_values():
    assert RequestedAction.from_dict(proposal().requested_action.to_dict()) == proposal().requested_action
    data = proposal().to_dict(); data["requested_action"]["authorization"] = "secret"
    with pytest.raises(ContractError):
        TestProposal.from_dict(data)


def test_foundation_has_no_runtime_or_external_dependencies(tmp_path):
    source_root = Path(__file__).resolve().parents[1] / "src" / "agent"
    files = {p.name for p in source_root.glob("*.py")}
    foundation = {"__init__.py", "models.py", "test_catalog.py", "policy.py", "model_client.py"}
    assert files == foundation | {"ollama_model_client.py"}
    forbidden = {"openai", "anthropic", "requests", "httpx", "urllib", "socket", "subprocess", "aiohttp", "langchain"}
    for path in (source_root / name for name in foundation):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {a.name.split(".")[0] for a in node.names} & forbidden
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in forbidden
                assert not node.module.endswith("ollama_model_client")
    state = create_initial_scan_state("scan_test", "https://example.com/app.apk")
    assert state["stages"]["agent_analysis"]["status"] == "not_available"
    assert state["artifacts"]["agent_report"]["available"] is False
    proposal(); hypothesis(); validation(); execution()
    assert list(tmp_path.iterdir()) == []
    assert not list(source_root.glob("*executor*"))


@pytest.mark.parametrize("required", [
    "NO EVIDENCE → NO FINDING", "NO REPRODUCTION → NO CONFIRMED FINDING", "AGENT OUTPUT ≠ EVIDENCE",
    "AGENT OUTPUT ≠ FINDING", "TOOL OUTPUT ≠ VALIDATED FINDING", "OBSERVED ≠ CAUSED", "NOT OBSERVED ≠ ABSENT",
    "INCOMPLETE COVERAGE ≠ SECURE", "EVERY FINDING MUST HAVE PROVENANCE", "EVERY ACTIVE ACTION MUST PASS POLICY",
    "→ Context Update", "trigger-based", "hypothesis → planned → executed → observed → validated → confirmed",
    "Future milestone: vulnerability chaining", "Future milestone: historical scan processing",
    "PoC requires deterministic execution", "Transparent attack validation", "CoverageGap semantics"])
def test_spec_contains_canonical_rules(required):
    spec = (Path(__file__).resolve().parents[1] / "SPEC.md").read_text()
    assert required in spec
