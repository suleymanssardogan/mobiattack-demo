"""Pure policy checks against synthetic scan-scoped EndpointContext evidence."""
from copy import deepcopy
from dataclasses import replace

import pytest

from src.agent.models import ParameterReference
from src.agent.policy import EvidenceRecord, evaluate_proposal
from src.dynamic.context.models import EndpointContext
from tests.test_agent_contracts import CTX_REF, TX_REF, proposal


@pytest.fixture
def inputs():
    ctx = EndpointContext("ctx_1", "api.example.com", "/users/1", methods=["GET"],
        auth={"authorization_present": True}, dynamic={"observed": True, "transaction_ids": ["tx_1"], "missing_transaction_ids": []},
        request={"query_keys": ["page"], "body_keys": ["name"], "body_present": True},
        evidence_refs={"transaction_ids": ["tx_1"]})
    return {"ctx_1": ctx}, {CTX_REF: EvidenceRecord(CTX_REF, "ctx_1", "endpoint_context"),
                           TX_REF: EvidenceRecord(TX_REF, "ctx_1", "traffic_transaction")}


def decision(p, inputs):
    return evaluate_proposal(p, *inputs)


@pytest.mark.parametrize("test_id", ["AUTHENTICATION_PRESENCE", "PARAMETER_CONSISTENCY", "INPUT_VALIDATION"])
def test_evidence_backed_passive_and_low_proposals_allowed(test_id, inputs):
    result = decision(proposal(test_id), inputs)
    assert (result.decision, result.reason_code) == ("allow", "ALLOWED")
    assert result.validated_evidence_refs == tuple(sorted((CTX_REF, TX_REF)))


def test_unknown_test_rejected(inputs):
    p = proposal().to_dict(); p["test_id"] = "HALLUCINATED_TEST"
    assert decision(p, inputs).reason_code == "UNKNOWN_TEST"


@pytest.mark.parametrize("test_id", ["OBJECT_AUTHORIZATION", "FUNCTION_AUTHORIZATION"])
@pytest.mark.parametrize("mode", ["automatic", "manual"])
def test_medium_and_high_blocked_without_manual_bypass(test_id, mode, inputs):
    p = proposal(test_id); p = replace(p, requested_action=replace(p.requested_action, execution_mode=mode))
    assert decision(p, inputs).reason_code == "RISK_NOT_ALLOWED"


@pytest.mark.parametrize("change", ["risk", "action", "mutation"])
def test_destructive_denied_even_mislabeled(change, inputs):
    p = proposal()
    if change == "risk":
        p = replace(p, risk_class="destructive")
    else:
        p = replace(p, requested_action=replace(p.requested_action, **{change: "delete_resource"}))
    assert decision(p, inputs).reason_code == "DESTRUCTIVE_ACTION"


def test_risk_must_match_catalog(inputs):
    assert decision(replace(proposal(), risk_class="low"), inputs).reason_code == "RISK_NOT_ALLOWED"


def test_unknown_endpoint_context(inputs):
    assert decision(replace(proposal(), endpoint_context_id="ctx_missing"), inputs).reason_code == "UNKNOWN_ENDPOINT_CONTEXT"


@pytest.mark.parametrize("field,value", [("host", "admin.example.com"), ("path", "/users/2"), ("method", "POST")])
def test_hallucinated_endpoint_identity_rejected(field, value, inputs):
    p = proposal(); p = replace(p, requested_action=replace(p.requested_action, **{field: value}))
    assert decision(p, inputs).reason_code == "ENDPOINT_NOT_IN_EVIDENCE"


def test_missing_evidence_not_allowed(inputs):
    contexts, refs = inputs
    refs.pop(TX_REF)
    result = decision(proposal(), inputs)
    assert (result.decision, result.reason_code) == ("needs_evidence", "MISSING_EVIDENCE")
    assert not result.validated_evidence_refs


def test_required_evidence_kind_cannot_be_omitted(inputs):
    p = replace(proposal("PARAMETER_CONSISTENCY"), evidence_refs=(CTX_REF,))
    assert decision(p, inputs).reason_code == "MISSING_EVIDENCE"


def test_evidence_cannot_cross_endpoint_or_claim_missing_transaction(inputs):
    contexts, index = inputs
    index[TX_REF] = EvidenceRecord(TX_REF, "ctx_other", "traffic_transaction")
    assert decision(proposal(), inputs).reason_code == "MISSING_EVIDENCE"
    index[TX_REF] = EvidenceRecord(TX_REF, "ctx_1", "traffic_transaction")
    contexts["ctx_1"].evidence_refs["transaction_ids"] = []
    assert decision(proposal(), inputs).reason_code == "MISSING_EVIDENCE"
    contexts["ctx_1"].evidence_refs["transaction_ids"] = ["tx_1"]
    contexts["ctx_1"].dynamic["missing_transaction_ids"] = ["tx_1"]
    assert decision(proposal(), inputs).reason_code == "MISSING_EVIDENCE"


def test_whole_artifact_not_endpoint_evidence(inputs):
    assert decision(replace(proposal(), evidence_refs=("dynamic/endpoint_contexts.json",)), inputs).reason_code == "MISSING_EVIDENCE"


@pytest.mark.parametrize("location,name,allowed", [("query", "page", True), ("body", "name", True),
    ("query", "invented", False), ("body", "page", False)])
def test_parameters_require_location_specific_evidence(location, name, allowed, inputs):
    p = proposal("PARAMETER_CONSISTENCY")
    p = replace(p, requested_action=replace(p.requested_action, parameters=(ParameterReference(location, name),)))
    result = decision(p, inputs)
    assert result.decision == ("allow" if allowed else "deny")
    if not allowed:
        assert result.reason_code == "PARAMETER_NOT_IN_EVIDENCE"


def test_catalog_auto_flag_enforced(inputs):
    p = proposal("SESSION_HANDLING")
    assert decision(p, inputs).reason_code == "AUTO_EXECUTION_NOT_ALLOWED"
    p = replace(p, requested_action=replace(p.requested_action, execution_mode="manual"))
    assert decision(p, inputs).decision == "allow"


def test_missing_required_context_and_cannot_remove_preconditions(inputs):
    contexts, refs = inputs
    contexts["ctx_1"].dynamic["observed"] = False
    assert decision(proposal("PARAMETER_CONSISTENCY"), inputs).reason_code == "MISSING_REQUIRED_CONTEXT"
    contexts["ctx_1"].dynamic["observed"] = True
    p = replace(proposal(), required_context=("request.unavailable_field",))
    assert decision(p, inputs).reason_code == "MISSING_REQUIRED_CONTEXT"


@pytest.mark.parametrize("field,value", [("risk_class", "unknown"), ("evidence_refs", []),
    ("endpoint_context_id", ""), ("required_context", "auth")])
def test_schema_invalid_outputs_denied(field, value, inputs):
    p = proposal().to_dict(); p[field] = value
    assert decision(p, inputs).reason_code == "SCHEMA_INVALID"


def test_unsupported_action_and_extra_payload_denied(inputs):
    p = proposal().to_dict(); p["requested_action"]["action"] = "arbitrary_command"
    assert decision(p, inputs).reason_code == "SCHEMA_INVALID"
    p = proposal(); p = replace(p, requested_action=replace(p.requested_action, action="input_check"))
    assert decision(p, inputs).reason_code == "UNSUPPORTED_ACTION"
    p = proposal().to_dict(); p["requested_action"]["body"] = {"password": "secret"}
    assert decision(p, inputs).reason_code == "SCHEMA_INVALID"


def test_policy_is_deterministic_and_does_not_mutate_inputs(inputs, tmp_path, monkeypatch):
    import socket
    import urllib.request
    def forbidden(*args, **kwargs):
        raise AssertionError("Network execution forbidden")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    before = deepcopy(inputs)
    p = proposal("PARAMETER_CONSISTENCY")
    result = decision(p, inputs)
    assert result == decision(p.to_dict(), inputs)
    assert inputs == before
    assert list(tmp_path.iterdir()) == []


def test_actual_endpoint_context_artifact_is_consumable():
    from tests.test_endpoint_context_builder import evidence, context
    ctx = context(evidence.__wrapped__())
    ref = f"dynamic/endpoint_contexts.json#endpoint_context_id={ctx.endpoint_context_id}"
    p = proposal(endpoint_context_id=ctx.endpoint_context_id, evidence_refs=(ref,))
    p = replace(p, requested_action=replace(p.requested_action, host=ctx.host, path=ctx.path, method="POST"))
    result = evaluate_proposal(p, {ctx.endpoint_context_id: ctx}, {ref: EvidenceRecord(ref, ctx.endpoint_context_id, "endpoint_context")})
    assert result.decision == "allow"


@pytest.mark.parametrize("payload", [None, [], "invented output", {"test_id": ["invalid"]}])
def test_malformed_agent_output_fails_closed(payload, inputs):
    assert decision(payload, inputs).reason_code == "SCHEMA_INVALID"


def test_malformed_context_link_cannot_crash_or_allow(inputs):
    contexts, _ = inputs
    contexts["ctx_1"].evidence_refs["transaction_ids"] = None
    result = decision(proposal(), inputs)
    assert (result.decision, result.reason_code) == ("needs_evidence", "MISSING_EVIDENCE")


def test_static_source_id_and_correlation_surrogate_are_not_interchangeable(inputs):
    contexts, refs = inputs
    ctx = contexts["ctx_1"]
    ref = "static_analysis_report.json#candidate_id=cand_1"
    ctx.evidence_refs["static_candidate_ids"] = ["cand_1"]
    ctx.static = {"static_candidate_id": "cand_1", "static_candidate_id_origin": "source_report"}
    refs[ref] = EvidenceRecord(ref, "ctx_1", "static_candidate")
    p = replace(proposal(), evidence_refs=(CTX_REF, TX_REF, ref))
    assert decision(p, inputs).decision == "allow"
    ctx.static["static_candidate_id_origin"] = "correlation_reference"
    assert decision(p, inputs).reason_code == "MISSING_EVIDENCE"
