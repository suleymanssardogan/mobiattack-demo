"""Deterministic integration. No model client, tools or execution callbacks."""
from datetime import datetime, timezone
from dataclasses import replace
import json
from collections.abc import Mapping

from src.agent.models import ContractError, TestProposal, identifier, POLICY_VERSION
from src.agent.model_client import ModelMetadata
from src.agent.policy import evaluate_proposal, _decision
from src.agent.test_catalog import TEST_CATALOG
from src.agent.test_planner import build_test_planner_input, TestPlannerResult
from src.agent.test_planner.validation import validate_model_output, PlannerOutputInvalid
from src.agent.context_analyst.validation import record_id
from .models import PolicyEvaluationResult


def _safe_id(value, fallback):
    try:
        identifier(value, "reference ID")
        return value
    except ContractError:
        return fallback


def _evaluate_raw(proposal, endpoint, source, evidence_index, precondition_index):
    raw = proposal.to_dict() if isinstance(proposal, TestProposal) else proposal
    pid = _safe_id(raw.get("proposal_id") if isinstance(raw, dict) else None, "invalid_proposal")
    try:
        if len(json.dumps(raw).encode()) > 32768:
            return _decision(pid, "deny", "SCHEMA_INVALID")
    except (TypeError, ValueError, RecursionError):
        return _decision(pid, "deny", "SCHEMA_INVALID")
    if isinstance(raw, dict) and isinstance(raw.get("test_id"), str) and raw["test_id"] not in TEST_CATALOG:
        return _decision(pid, "deny", "UNKNOWN_TEST")
    if isinstance(raw, dict) and isinstance(raw.get("requested_action"), dict):
        parameters = raw["requested_action"].get("parameters", [])
        if isinstance(parameters, (tuple, list)):
            for parameter in parameters:
                if isinstance(parameter, dict):
                    field = {"query": "query_keys", "body": "body_keys"}.get(parameter.get("location"))
                    if field is None or parameter.get("name") not in endpoint.request.get(field, []):
                        return _decision(pid, "deny", "PARAMETER_NOT_IN_EVIDENCE")
    try:
        p = TestProposal.from_dict(raw)
    except (ContractError, ValueError, TypeError, AttributeError):
        return _decision(pid, "deny", "SCHEMA_INVALID")
    if p.endpoint_context_id != endpoint.endpoint_context_id:
        return _decision(pid, "deny", "UNKNOWN_ENDPOINT_CONTEXT")
    hypotheses = tuple(h["hypothesis_id"] for h in source.analyst["hypotheses"])
    if p.hypothesis_id not in hypotheses:
        return _decision(pid, "deny", "UNKNOWN_HYPOTHESIS")
    entry = TEST_CATALOG[p.test_id]
    if p.risk_class == "destructive":
        return _decision(pid, "deny", "DESTRUCTIVE_ACTION")
    if p.risk_class != entry.risk_class or p.risk_class not in {"passive", "low"}:
        return _decision(pid, "deny", "RISK_NOT_ALLOWED")
    if not set(p.evidence_refs).issubset(source.evidence_refs):
        return _decision(pid, "deny", "HALLUCINATED_EVIDENCE")
    # Planner schema/grounding is rechecked at this second trust boundary.
    # The validator performs no model invocation.
    try:
        validate_model_output(json.loads(json.dumps({"schema_version": "1.0", "endpoint_context_id": endpoint.endpoint_context_id,
            "proposals": [p.to_dict()]})), source, created_at=p.created_at, metadata=ModelMetadata(), attempts=0)
    except (PlannerOutputInvalid, ContractError, ValueError, TypeError, AttributeError):
        return _decision(pid, "deny", "SCHEMA_INVALID")
    return evaluate_proposal(p, {endpoint.endpoint_context_id: endpoint}, evidence_index,
                            proposal_only=True, hypothesis_ids=hypotheses,
                            available_evidence_refs=source.evidence_refs, precondition_index=precondition_index)


def _evaluate(proposal, endpoint, source, evidence_index, precondition_index):
    try:
        decision = _evaluate_raw(proposal, endpoint, source, evidence_index, precondition_index)
    except (ContractError, TypeError, ValueError, KeyError, AttributeError, RecursionError):
        raw = proposal.to_dict() if isinstance(proposal, TestProposal) else proposal
        pid = _safe_id(raw.get("proposal_id") if isinstance(raw, dict) else None, "invalid_proposal")
        decision = _decision(pid, "deny", "SCHEMA_INVALID")
    raw = proposal.to_dict() if isinstance(proposal, TestProposal) else proposal
    # Preserve actual source lineage; untrusted IDs are sanitized, never copied as prose.
    if isinstance(raw, dict):
        decision = replace(decision,
            endpoint_context_id=_safe_id(raw.get("endpoint_context_id"), "unknown_endpoint"),
            hypothesis_id=_safe_id(raw.get("hypothesis_id"), "unknown_hypothesis"),
            test_id=_safe_id(raw.get("test_id"), "unknown_test"))
    return decision


def evaluate_planned_proposal(proposal, endpoint_context, analyst_result, evidence_index, *,
                              precondition_index=None, catalog_test_ids=None):
    """Resolve a proposed check against trusted endpoint evidence, never run it.

    evidence_index and precondition_index are caller-verified canonical artifact
    metadata, not Planner output. Omitted prerequisites remain needs_evidence.
    """
    try:
        source = build_test_planner_input(endpoint_context, analyst_result, catalog_test_ids=catalog_test_ids)
    except (ContractError, ValueError, TypeError, AttributeError, RecursionError):
        raw = proposal.to_dict() if isinstance(proposal, TestProposal) else proposal
        pid = _safe_id(raw.get("proposal_id") if isinstance(raw, dict) else None, "invalid_proposal")
        return _decision(pid, "deny", "SCHEMA_INVALID")
    return _evaluate(proposal, endpoint_context, source, evidence_index, precondition_index)


def evaluate_test_plan(endpoint_context, analyst_result, planner_result, evidence_index, *,
                       precondition_index=None, created_at=None):
    """Explicit integration entry point; Planner itself never invokes the Gate."""
    now = created_at or datetime.now(timezone.utc).isoformat()
    eid = _safe_id(getattr(endpoint_context, "endpoint_context_id", None), "unknown_endpoint")
    raw = planner_result.to_dict() if isinstance(planner_result, TestPlannerResult) else planner_result
    planning_id = _safe_id(raw.get("planning_id") if isinstance(raw, dict) else None, "unknown_plan")
    try:
        if isinstance(planner_result, (list, tuple)):
            if len(planner_result) > 16:
                raise ContractError("Proposal batch exceeds bound")
            proposals = planner_result
            ids = [p.proposal_id if isinstance(p, TestProposal) else p.get("proposal_id") for p in proposals]
            if any(not isinstance(pid, str) for pid in ids) or len(ids) != len(set(ids)):
                raise ContractError("Invalid/duplicate proposal IDs")
            planning_id = record_id("planning", repr(sorted(ids)))
            source = build_test_planner_input(endpoint_context, analyst_result)
        else:
            if not isinstance(raw, dict) or raw.get("status") not in {"completed", "no_relevant_tests"}:
                raise ContractError("Planner result unavailable")
            proposals = raw.get("proposals")
            if (not isinstance(proposals, (list, tuple)) or len(proposals) > 16
                    or type(raw.get("proposal_count")) is not int or raw["proposal_count"] != len(proposals)
                    or (raw["status"] == "completed") != bool(proposals)):
                raise ContractError("Invalid Planner envelope")
            # Validate the existing envelope contract independently of individual
            # untrusted proposals: malformed proposals must produce DENY, not vanish.
            envelope = {**raw, "proposals": [], "proposal_count": 0, "status": "no_relevant_tests"}
            result = TestPlannerResult.from_dict(envelope)
            if result.endpoint_context_id != eid:
                raise ContractError("Planner endpoint mismatch")
            source = build_test_planner_input(endpoint_context, analyst_result,
                                             catalog_test_ids=result.catalog_test_ids_available)
        if not isinstance(evidence_index, Mapping):
            raise ContractError("Invalid evidence index")
        decisions = tuple(sorted((_evaluate(p, endpoint_context, source, evidence_index, precondition_index)
                                  for p in proposals), key=lambda d: d.proposal_id))
        status = "evaluated" if decisions else "no_proposals"
    except (ContractError, ValueError, TypeError, AttributeError, RecursionError):
        status = "not_processed"
        decisions = ()
    identity = repr((POLICY_VERSION, planning_id, eid, [d.to_dict() for d in decisions]))
    return PolicyEvaluationResult(record_id("evaluation", identity), planning_id, eid, now, status, decisions)
