"""Planner output validation with canonical proposals, not policy execution."""
from dataclasses import fields, replace
import json

from src.agent.models import ContractError, TestProposal
from src.agent.context_analyst.validation import record_id, _unique_object
from .models import MAX_BYTES, MAX_PROPOSALS, TestPlannerResult

FORBIDDEN = frozenset({"finding", "is_vulnerable", "severity", "risk_score", "cvss", "confirmed", "exploit", "poc",
    "tool_name", "tool_args", "tool_calls", "curl", "raw_request", "http_method_override", "request_body",
    "headers_to_send", "execute_now", "approved_for_execution", "auto_execute", "chain_of_thought", "reasoning"})


class PlannerOutputInvalid(ContractError): pass


def proposal_id(endpoint_id, hypothesis_id, test_id):
    return record_id("proposal", json.dumps([endpoint_id, hypothesis_id, test_id], separators=(",", ":")))


def _scan(value, depth=0, budget=None):
    budget = [2048] if budget is None else budget
    budget[0] -= 1
    if depth > 8 or budget[0] < 0: raise PlannerOutputInvalid("OUTPUT_BOUND_EXCEEDED")
    if isinstance(value, dict):
        if len(value) > 32 or set(value) & FORBIDDEN: raise PlannerOutputInvalid("FORBIDDEN_OR_OVERSIZED_FIELD")
        for child in value.values(): _scan(child, depth + 1, budget)
    elif isinstance(value, list):
        if len(value) > 32: raise PlannerOutputInvalid("OUTPUT_BOUND_EXCEEDED")
        for child in value: _scan(child, depth + 1, budget)
    elif isinstance(value, str):
        if len(value) > 2048: raise PlannerOutputInvalid("OUTPUT_BOUND_EXCEEDED")
    elif value is not None and type(value) not in (bool, int, float): raise PlannerOutputInvalid("SCHEMA_INVALID")


def output_schema(source, created_at):
    variants = []
    for c in source.proposal_candidates:
        properties = {key: {"const": value} for key, value in c.items() if key not in {"evidence_refs", "required_context"}}
        properties.update({"proposal_id": {"const": proposal_id(source.endpoint_context_id, c["hypothesis_id"], c["test_id"])},
            "endpoint_context_id": {"const": source.endpoint_context_id}, "created_at": {"const": created_at},
            "evidence_refs": {"type": "array", "minItems": 1, "maxItems": 32, "uniqueItems": True,
                              "items": {"enum": list(source.evidence_refs)}},
            "required_context": {"type": "array", "minItems": len(c["required_context"]), "maxItems": len(c["required_context"]),
                                 "uniqueItems": True, "items": {"enum": c["required_context"]}}})
        variants.append({"type": "object", "additionalProperties": False,
                         "required": [f.name for f in fields(TestProposal)], "properties": properties})
    proposals = {"type": "array", "maxItems": MAX_PROPOSALS, "items": {"oneOf": variants}} if variants else {"type": "array", "maxItems": 0}
    return {"type": "object", "additionalProperties": False, "required": ["schema_version", "endpoint_context_id", "proposals"],
        "properties": {"schema_version": {"const": "1.0"}, "endpoint_context_id": {"const": source.endpoint_context_id},
                       "proposals": proposals, "status": {"enum": ["completed", "no_relevant_tests"]}}}


def result_from_proposals(source, proposals, *, created_at, metadata, attempts=0, errors=()):
    status = "completed" if proposals else "no_relevant_tests"
    identity = json.dumps([source.to_dict(), [p.to_dict() for p in proposals], created_at], sort_keys=True)
    return TestPlannerResult(record_id("planning", identity), source.endpoint_context_id, created_at, status,
        tuple(proposals), source.coverage_gaps, source.planning_notes, metadata, source.evidence_refs,
        tuple(h["hypothesis_id"] for h in source.analyst["hypotheses"]),
        tuple(t["test_id"] for t in source.available_tests), tuple(errors), attempts)


def validate_model_output(data, source, *, created_at, metadata, attempts, errors=()):
    try:
        if isinstance(data, str):
            if len(data.encode()) > MAX_BYTES: raise PlannerOutputInvalid("OUTPUT_BOUND_EXCEEDED")
            data = json.loads(data, object_pairs_hook=_unique_object)
        _scan(data)
        if len(json.dumps(data).encode()) > MAX_BYTES: raise PlannerOutputInvalid("OUTPUT_BOUND_EXCEEDED")
        allowed = {"schema_version", "endpoint_context_id", "proposals", "status"}
        if (not isinstance(data, dict) or set(data) - allowed or allowed - {"status"} - set(data)
                or data["schema_version"] != "1.0" or not isinstance(data["proposals"], list)
                or len(data["proposals"]) > MAX_PROPOSALS): raise PlannerOutputInvalid("SCHEMA_INVALID")
        if data["endpoint_context_id"] != source.endpoint_context_id: raise PlannerOutputInvalid("ENDPOINT_MISMATCH")
        lookup = {(c["hypothesis_id"], c["test_id"]): c for c in source.proposal_candidates}
        unique = {}
        for raw in data["proposals"]:
            if not isinstance(raw, dict) or set(raw) != {f.name for f in fields(TestProposal)}:
                raise PlannerOutputInvalid("PROPOSAL_FIELDS_INVALID")
            p = TestProposal.from_dict(raw)
            c = lookup.get((p.hypothesis_id, p.test_id))
            if c is None: raise PlannerOutputInvalid("UNSUPPORTED_TEST_OR_HYPOTHESIS")
            if p.endpoint_context_id != source.endpoint_context_id: raise PlannerOutputInvalid("ENDPOINT_MISMATCH")
            if p.risk_class != c["risk_class"]: raise PlannerOutputInvalid("RISK_MISMATCH")
            if p.requested_action.to_dict() != c["requested_action"]: raise PlannerOutputInvalid("ACTION_NOT_ABSTRACT")
            if not set(p.evidence_refs).issubset(source.evidence_refs): raise PlannerOutputInvalid("EVIDENCE_REF_NOT_SUPPLIED")
            if not set(c["evidence_refs"]).issubset(p.evidence_refs): raise PlannerOutputInvalid("SUPPORT_EVIDENCE_MISSING")
            if p.reason != c["reason"] or set(p.required_context) != set(c["required_context"]):
                raise PlannerOutputInvalid("PRECONDITIONS_OR_REASON_INVALID")
            if p.proposal_id != proposal_id(p.endpoint_context_id, p.hypothesis_id, p.test_id) or p.created_at != created_at:
                raise PlannerOutputInvalid("PROPOSAL_ID_OR_TIME_INVALID")
            p = replace(p, evidence_refs=tuple(sorted(set(p.evidence_refs))), required_context=tuple(sorted(set(p.required_context))))
            key = (p.endpoint_context_id, p.hypothesis_id, p.test_id)
            if key in unique and unique[key] != p: raise PlannerOutputInvalid("CONFLICTING_DUPLICATE_PROPOSAL")
            unique[key] = p
        proposals = tuple(sorted(unique.values(), key=lambda p: p.proposal_id))
        expected_status = "completed" if proposals else "no_relevant_tests"
        if data.get("status", expected_status) != expected_status: raise PlannerOutputInvalid("STATUS_COUNT_MISMATCH")
        return result_from_proposals(source, proposals, created_at=created_at, metadata=metadata, attempts=attempts, errors=errors)
    except PlannerOutputInvalid: raise
    except (ContractError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        raise PlannerOutputInvalid("SCHEMA_INVALID") from exc
