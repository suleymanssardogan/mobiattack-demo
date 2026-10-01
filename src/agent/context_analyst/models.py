"""Bounded wrappers around the existing canonical observation/hypothesis/gap models."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json

from src.agent.model_client import ModelMetadata
from src.agent.models import (AgentHypothesis, AgentObservation, ContractError, CoverageGap,
                              identifier, references, timestamp)

PROMPT_VERSION = "context_analyst_v1"
HYPOTHESIS_TYPES = frozenset({"object_authorization_candidate", "function_authorization_candidate",
    "authentication_behavior_candidate", "session_behavior_candidate", "input_validation_candidate",
    "parameter_consistency_candidate", "coverage_limitation"})
ENDPOINT_ROLES = frozenset({"authentication_endpoint", "resource_endpoint", "collection_endpoint",
    "profile_endpoint", "transaction_endpoint", "upload_endpoint", "unknown"})
RESULT_STATES = frozenset({"completed", "invalid_output", "model_error", "input_invalid"})
MAX_INPUT_BYTES = 32768
MAX_OUTPUT_BYTES = 32768
MAX_OUTPUT_ITEMS = 32


@dataclass(frozen=True)
class ContextAnalystInput:
    endpoint_context_id: str
    endpoint: dict
    static_context: dict
    dynamic_context: dict
    request_context: dict
    response_context: dict
    auth_context: dict
    runtime_context: dict
    visibility: dict
    coverage: dict
    evidence_refs: dict
    fact_catalog: tuple[dict, ...]
    hypothesis_catalog: dict
    supported_roles: tuple[str, ...]
    schema_version: str = "1.0"

    def __post_init__(self):
        identifier(self.endpoint_context_id, "endpoint_context_id")
        if self.schema_version != "1.0":
            raise ContractError("Unsupported Context Analyst input schema")
        if len(json.dumps(self.to_dict(), sort_keys=True).encode()) > MAX_INPUT_BYTES:
            raise ContractError("Context Analyst input exceeds bound")
        references(self.evidence_universe)

    @property
    def evidence_universe(self):
        return tuple(sorted({ref for refs in self.evidence_refs.values() for ref in refs}))

    def to_dict(self):
        # Detached JSON values: model clients cannot mutate the evidence snapshot.
        return json.loads(json.dumps(asdict(self), sort_keys=True))


@dataclass(frozen=True)
class ContextAnalystResult:
    analysis_id: str
    endpoint_context_id: str
    status: str
    created_at: str
    observation: AgentObservation | None = None
    hypotheses: tuple[AgentHypothesis, ...] = ()
    coverage_gaps: tuple[CoverageGap, ...] = ()
    endpoint_role: str = "unknown"
    model_metadata: ModelMetadata = ModelMetadata()
    input_evidence_refs: tuple[str, ...] = ()
    validation_errors: tuple[str, ...] = ()
    attempts: int = 0
    prompt_version: str = PROMPT_VERSION
    schema_version: str = "1.0"

    def __post_init__(self):
        identifier(self.analysis_id, "analysis_id"); identifier(self.endpoint_context_id, "endpoint_context_id")
        timestamp(self.created_at)
        if (self.status not in RESULT_STATES or self.prompt_version != PROMPT_VERSION or self.schema_version != "1.0"
                or self.endpoint_role not in ENDPOINT_ROLES or type(self.attempts) is not int or not 0 <= self.attempts <= 2
                or not isinstance(self.model_metadata, ModelMetadata)):
            raise ContractError("Invalid Context Analyst result")
        references(self.input_evidence_refs, required=self.status == "completed")
        if not isinstance(self.validation_errors, tuple):
            raise ContractError("Invalid diagnostic codes")
        for code in self.validation_errors:
            identifier(code, "diagnostic code")
        if self.status != "completed":
            if self.observation is not None or self.hypotheses or self.coverage_gaps or self.endpoint_role != "unknown":
                raise ContractError("Failure cannot fabricate analysis")
            return
        if not isinstance(self.observation, AgentObservation) or self.observation.endpoint_context_id != self.endpoint_context_id:
            raise ContractError("Missing/mismatched observation")
        if not isinstance(self.hypotheses, tuple) or not isinstance(self.coverage_gaps, tuple):
            raise ContractError("Expected result tuples")
        universe = set(self.input_evidence_refs)
        refs = set(self.observation.evidence_refs)
        gap_ids = set()
        all_ids = [self.observation.observation_id]
        if len(self.hypotheses) > MAX_OUTPUT_ITEMS or len(self.coverage_gaps) > MAX_OUTPUT_ITEMS:
            raise ContractError("Result exceeds item bound")
        for h in self.hypotheses:
            if (not isinstance(h, AgentHypothesis) or h.endpoint_context_id != self.endpoint_context_id
                    or h.hypothesis_type not in HYPOTHESIS_TYPES or h.status != "hypothesis"):
                raise ContractError("Invalid Context Analyst hypothesis")
            refs.update(h.evidence_refs); all_ids.append(h.hypothesis_id)
        for gap in self.coverage_gaps:
            if not isinstance(gap, CoverageGap) or gap.endpoint_context_id != self.endpoint_context_id or gap.blocked_test_ids:
                raise ContractError("Invalid Context Analyst coverage gap")
            refs.update(gap.evidence_refs); gap_ids.add(gap.gap_id); all_ids.append(gap.gap_id)
        if (not refs.issubset(universe) or set(self.observation.coverage_gaps) != gap_ids
                or len(all_ids) != len(set(all_ids))):
            raise ContractError("Result evidence/ID links invalid")

    @property
    def trace(self):
        return {"prompt_version": self.prompt_version, "input_evidence_refs": list(self.input_evidence_refs),
                "observation_id": self.observation.observation_id if self.observation else None,
                "hypothesis_ids": [h.hypothesis_id for h in self.hypotheses],
                "coverage_gap_ids": [g.gap_id for g in self.coverage_gaps],
                "validation_errors": list(self.validation_errors), "model_metadata": asdict(self.model_metadata)}

    def to_dict(self):
        return json.loads(json.dumps(asdict(self), sort_keys=True))

    @classmethod
    def from_dict(cls, data):
        from dataclasses import fields
        if not isinstance(data, dict) or set(data) - {f.name for f in fields(cls)}:
            raise ContractError("Unknown result fields")
        parsed = dict(data)
        try:
            if parsed.get("observation") is not None:
                parsed["observation"] = AgentObservation.from_dict(parsed["observation"])
            parsed["hypotheses"] = tuple(AgentHypothesis.from_dict(h) for h in parsed.get("hypotheses", []))
            parsed["coverage_gaps"] = tuple(CoverageGap.from_dict(g) for g in parsed.get("coverage_gaps", []))
            parsed["model_metadata"] = ModelMetadata(**parsed.get("model_metadata", {}))
            for key in ("input_evidence_refs", "validation_errors"):
                if key in parsed:
                    if not isinstance(parsed[key], (list, tuple)):
                        raise ContractError("Expected result list")
                    parsed[key] = tuple(parsed[key])
            return cls(**parsed)
        except (TypeError, AttributeError) as exc:
            raise ContractError("Invalid persisted result") from exc
