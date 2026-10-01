"""Strict output boundary; references and statements must be supplied, not invented."""
from __future__ import annotations

from dataclasses import MISSING, fields
import hashlib
import json

from src.agent.model_client import ModelMetadata
from src.agent.models import AgentHypothesis, AgentObservation, ContractError, CoverageGap
from .models import (ContextAnalystInput, ContextAnalystResult, MAX_OUTPUT_BYTES, MAX_OUTPUT_ITEMS, PROMPT_VERSION)

FORBIDDEN_FIELDS = frozenset({"test_id", "requested_action", "allowed_mutations", "auto_execute", "test_plan",
    "tool_name", "tool_args", "tool_calls", "finding", "is_vulnerable", "severity", "risk_score", "cvss",
    "confirmed_vulnerability", "exploit", "poc", "chain_of_thought", "reasoning", "authorization", "password"})


class OutputInvalid(ContractError):
    """Fixed diagnostic codes; never retain rejected model content."""


def record_id(namespace, value):
    return f"{namespace}_{hashlib.sha256(value.encode()).hexdigest()[:16]}"


def gap_id(endpoint_id, descriptor):
    return record_id("gap", endpoint_id + json.dumps(descriptor, sort_keys=True))


def _object_schema(model, properties):
    # Canonical field names/required fields come from the existing dataclasses.
    return {"type": "object", "additionalProperties": False, "properties": properties,
            "required": [f.name for f in fields(model) if f.default is MISSING and f.default_factory is MISSING]}


def _array(items, *, min_items=0):
    return {"type": "array", "items": items, "uniqueItems": True, "minItems": min_items, "maxItems": MAX_OUTPUT_ITEMS}


def output_schema(context: ContextAnalystInput, created_at: str):
    eid = context.endpoint_context_id
    ref_schema = {"type": "string", "enum": list(context.evidence_universe)}
    ids = [gap_id(eid, d) for d in context.coverage["gaps"]]
    string = {"type": "string", "minLength": 1, "maxLength": 2048}
    observation = _object_schema(AgentObservation, {
        "observation_id": {"const": record_id("obs", eid)}, "endpoint_context_id": {"const": eid},
        "facts": _array({"type": "string", "enum": [f["statement"] for f in context.fact_catalog]}, min_items=len(context.fact_catalog)),
        "evidence_refs": _array(ref_schema, min_items=1),
        "coverage_gaps": _array({"type": "string", "enum": ids}) if ids else {"type": "array", "maxItems": 0},
        "created_at": {"const": created_at}})
    hypotheses = _object_schema(AgentHypothesis, {
        "hypothesis_id": {"type": "string", "enum": [record_id("hyp", eid + kind) for kind in context.hypothesis_catalog]},
        "endpoint_context_id": {"const": eid}, "hypothesis_type": {"type": "string", "enum": sorted(context.hypothesis_catalog)},
        "statement": {"type": "string", "enum": [h["statement"] for h in context.hypothesis_catalog.values()]},
        "evidence_refs": _array(ref_schema, min_items=1), "required_evidence": _array(string), "status": {"const": "hypothesis"}})
    hypotheses["required"].append("status")
    coverage = _object_schema(CoverageGap, {
        "gap_id": {"type": "string", "enum": ids}, "endpoint_context_id": {"const": eid},
        "kind": {"type": "string", "enum": sorted({d["kind"] for d in context.coverage["gaps"]})},
        "description": {"type": "string", "enum": [d["description"] for d in context.coverage["gaps"]]},
        "evidence_refs": _array(ref_schema), "blocked_test_ids": {"type": "array", "maxItems": 0}})
    return {"type": "object", "additionalProperties": False,
        "required": ["schema_version", "endpoint_context_id", "observation", "hypotheses", "coverage_gaps"],
        "properties": {"schema_version": {"const": "1.0"}, "endpoint_context_id": {"const": eid},
            "endpoint_role": {"type": "string", "enum": list(context.supported_roles)}, "observation": observation,
            "hypotheses": _array(hypotheses) if context.hypothesis_catalog else {"type": "array", "maxItems": 0},
            "coverage_gaps": _array(coverage) if ids else {"type": "array", "maxItems": 0}}}


def _scan(value, depth=0, budget=None):
    budget = budget if budget is not None else [2048]
    budget[0] -= 1
    if budget[0] < 0:
        raise OutputInvalid("OUTPUT_NODES_EXCEEDED")
    if depth > 8:
        raise OutputInvalid("OUTPUT_DEPTH_EXCEEDED")
    if isinstance(value, dict):
        if len(value) > MAX_OUTPUT_ITEMS:
            raise OutputInvalid("OUTPUT_ITEMS_EXCEEDED")
        if set(value) & FORBIDDEN_FIELDS:
            raise OutputInvalid("FORBIDDEN_FIELD")
        for child in value.values():
            _scan(child, depth + 1, budget)
    elif isinstance(value, list):
        if len(value) > MAX_OUTPUT_ITEMS:
            raise OutputInvalid("OUTPUT_ITEMS_EXCEEDED")
        for child in value:
            _scan(child, depth + 1, budget)

    elif isinstance(value, str):
        if len(value) > 2048:
            raise OutputInvalid("OUTPUT_TEXT_EXCEEDED")
    elif value is not None and type(value) not in (int, float, bool):
        raise OutputInvalid("SCHEMA_INVALID")


def _unique_object(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise OutputInvalid("OUTPUT_DUPLICATE_KEY")
        output[key] = value
    return output


def validate_model_output(data, context: ContextAnalystInput, *, created_at: str,
                          metadata: ModelMetadata, attempts: int, errors=()) -> ContextAnalystResult:
    try:
        if isinstance(data, str):
            if len(data.encode()) > MAX_OUTPUT_BYTES:
                raise OutputInvalid("OUTPUT_SIZE_EXCEEDED")
            data = json.loads(data, object_pairs_hook=_unique_object)
        _scan(data)
        if len(json.dumps(data).encode()) > MAX_OUTPUT_BYTES:
            raise OutputInvalid("OUTPUT_SIZE_EXCEEDED")
        allowed = {"schema_version", "endpoint_context_id", "endpoint_role", "observation", "hypotheses", "coverage_gaps"}
        if (not isinstance(data, dict) or set(data) - allowed or allowed - {"endpoint_role"} - set(data)
                or data["schema_version"] != "1.0"):
            raise OutputInvalid("SCHEMA_INVALID")
        if data["endpoint_context_id"] != context.endpoint_context_id:
            raise OutputInvalid("ENDPOINT_MISMATCH")
        if not isinstance(data["hypotheses"], list) or not isinstance(data["coverage_gaps"], list):
            raise OutputInvalid("SCHEMA_INVALID")
        if any(not isinstance(h, dict) or h.get("status") != "hypothesis" for h in data["hypotheses"]):
            raise OutputInvalid("HYPOTHESIS_STATE_OR_ID_INVALID")
        observation = AgentObservation.from_dict(data["observation"])
        hypotheses = tuple(AgentHypothesis.from_dict(h) for h in data["hypotheses"])
        gaps = tuple(CoverageGap.from_dict(g) for g in data["coverage_gaps"])
        eid = context.endpoint_context_id
        if any(obj.endpoint_context_id != eid for obj in (observation, *hypotheses, *gaps)):
            raise OutputInvalid("ENDPOINT_MISMATCH")
        if observation.observation_id != record_id("obs", eid) or observation.created_at != created_at:
            raise OutputInvalid("OBSERVATION_ID_OR_TIME_MISMATCH")
        known_facts = {f["statement"]: f for f in context.fact_catalog}
        if len(observation.facts) != len(set(observation.facts)) or set(observation.facts) != set(known_facts):
            raise OutputInvalid("UNSUPPORTED_OR_MISSING_FACT")
        for fact in observation.facts:
            if not set(known_facts[fact]["evidence_refs"]).issubset(observation.evidence_refs):
                raise OutputInvalid("FACT_EVIDENCE_MISSING")
        seen_types = set()
        for h in hypotheses:
            support = context.hypothesis_catalog.get(h.hypothesis_type)
            if support is None:
                raise OutputInvalid("UNSUPPORTED_HYPOTHESIS")
            if (h.status != "hypothesis" or h.hypothesis_type in seen_types
                    or h.hypothesis_id != record_id("hyp", eid + h.hypothesis_type)):
                raise OutputInvalid("HYPOTHESIS_STATE_OR_ID_INVALID")
            seen_types.add(h.hypothesis_type)
            if (h.statement != support["statement"] or set(h.required_evidence) != set(support["required_evidence"])
                    or not set(support["evidence_refs"]).issubset(h.evidence_refs)):
                raise OutputInvalid("UNSUPPORTED_HYPOTHESIS_STATEMENT_OR_EVIDENCE")
        expected_gaps = {gap_id(eid, descriptor): descriptor for descriptor in context.coverage["gaps"]}
        if {g.gap_id for g in gaps} != set(expected_gaps):
            raise OutputInvalid("COVERAGE_GAP_MISSING_OR_INVENTED")
        for gap in gaps:
            descriptor = expected_gaps[gap.gap_id]
            if (gap.kind != descriptor["kind"] or gap.description != descriptor["description"]
                    or set(gap.evidence_refs) != set(descriptor["evidence_refs"]) or gap.blocked_test_ids):
                raise OutputInvalid("UNSUPPORTED_COVERAGE_GAP")
        role = data.get("endpoint_role", "unknown")
        if role not in context.supported_roles:
            raise OutputInvalid("UNSUPPORTED_ENDPOINT_ROLE")
        # Check every ref, including canonical-looking but invented fragments.
        refs = set(observation.evidence_refs)
        for item in (*hypotheses, *gaps):
            refs.update(item.evidence_refs)
        if not refs.issubset(context.evidence_universe):
            raise OutputInvalid("EVIDENCE_REF_NOT_SUPPLIED")
        from dataclasses import replace
        observation = replace(observation, facts=tuple(sorted(observation.facts)),
                              evidence_refs=tuple(sorted(set(observation.evidence_refs))), coverage_gaps=tuple(sorted(set(observation.coverage_gaps))))
        hypotheses = tuple(sorted((replace(h, evidence_refs=tuple(sorted(set(h.evidence_refs))),
                                          required_evidence=tuple(sorted(set(h.required_evidence)))) for h in hypotheses), key=lambda h: h.hypothesis_id))
        gaps = tuple(sorted((replace(g, evidence_refs=tuple(sorted(set(g.evidence_refs)))) for g in gaps), key=lambda g: g.gap_id))
        identity = json.dumps({"input": context.to_dict(), "observation": observation.to_dict(),
            "hypotheses": [h.to_dict() for h in hypotheses], "coverage_gaps": [g.to_dict() for g in gaps],
            "endpoint_role": role, "created_at": created_at}, sort_keys=True)
        return ContextAnalystResult(record_id("analysis", identity), eid, "completed", created_at,
            observation, hypotheses, gaps, role, metadata, context.evidence_universe, tuple(errors), attempts)
    except OutputInvalid:
        raise
    except (ContractError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        raise OutputInvalid("SCHEMA_INVALID") from exc
