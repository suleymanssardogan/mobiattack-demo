"""Planner wrappers; proposals use the existing canonical TestProposal model."""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json

from src.agent.model_client import ModelMetadata
from src.agent.models import ContractError, CoverageGap, TestProposal, identifier, references, timestamp
from src.agent.test_catalog import TEST_CATALOG

PROMPT_VERSION = "test_planner_v1"
MAX_BYTES = 32768
MAX_PROPOSALS = 16
SUCCESS_STATES = frozenset({"completed", "no_relevant_tests"})


@dataclass(frozen=True)
class TestPlannerInput:
    __test__ = False
    endpoint_context_id: str
    context: dict
    analyst: dict
    available_tests: tuple[dict, ...]
    proposal_candidates: tuple[dict, ...]
    coverage_gaps: tuple[CoverageGap, ...]
    planning_notes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    schema_version: str = "1.0"

    def __post_init__(self):
        identifier(self.endpoint_context_id, "endpoint_context_id"); references(self.evidence_refs)
        if self.schema_version != "1.0" or len(json.dumps(self.to_dict()).encode()) > MAX_BYTES:
            raise ContractError("Invalid or oversized planner input")

    def to_dict(self):
        return json.loads(json.dumps(asdict(self), sort_keys=True))


@dataclass(frozen=True)
class TestPlannerResult:
    __test__ = False
    planning_id: str
    endpoint_context_id: str
    created_at: str
    status: str
    proposals: tuple[TestProposal, ...] = ()
    coverage_gaps: tuple[CoverageGap, ...] = ()
    planning_notes: tuple[str, ...] = ()
    model_metadata: ModelMetadata = ModelMetadata()
    input_evidence_refs: tuple[str, ...] = ()
    hypothesis_ids_considered: tuple[str, ...] = ()
    catalog_test_ids_available: tuple[str, ...] = ()
    validation_errors: tuple[str, ...] = ()
    attempts: int = 0
    schema_version: str = "1.0"
    prompt_version: str = PROMPT_VERSION

    def __post_init__(self):
        identifier(self.planning_id, "planning_id"); identifier(self.endpoint_context_id, "endpoint_context_id")
        timestamp(self.created_at)
        if (self.schema_version != "1.0" or self.prompt_version != PROMPT_VERSION
                or self.status not in SUCCESS_STATES | {"input_invalid", "model_error", "invalid_output"}
                or type(self.attempts) is not int or not 0 <= self.attempts <= 2
                or not isinstance(self.model_metadata, ModelMetadata)):
            raise ContractError("Invalid planner result")
        for value in (self.proposals, self.coverage_gaps, self.planning_notes, self.input_evidence_refs,
                      self.hypothesis_ids_considered, self.catalog_test_ids_available, self.validation_errors):
            if not isinstance(value, tuple): raise ContractError("Expected result tuples")
        references(self.input_evidence_refs, required=self.status in SUCCESS_STATES)
        if len(self.proposals) > MAX_PROPOSALS:
            raise ContractError("Too many proposals")
        if self.status not in SUCCESS_STATES:
            if self.proposals: raise ContractError("Failure cannot fabricate proposals")
            return
        if bool(self.proposals) != (self.status == "completed"):
            raise ContractError("Planner status/count mismatch")
        identities = set()
        for p in self.proposals:
            if (not isinstance(p, TestProposal) or p.endpoint_context_id != self.endpoint_context_id
                    or p.hypothesis_id not in self.hypothesis_ids_considered
                    or p.test_id not in self.catalog_test_ids_available
                    or p.risk_class != TEST_CATALOG[p.test_id].risk_class
                    or p.requested_action.action != TEST_CATALOG[p.test_id].abstract_action
                    or p.requested_action.execution_mode != "proposal_only"
                    or not set(p.evidence_refs).issubset(self.input_evidence_refs)):
                raise ContractError("Invalid persisted proposal")
            identity = (p.endpoint_context_id, p.hypothesis_id, p.test_id)
            if identity in identities: raise ContractError("Duplicate persisted proposal")
            identities.add(identity)
        if any(g.endpoint_context_id != self.endpoint_context_id for g in self.coverage_gaps):
            raise ContractError("Coverage endpoint mismatch")

    @property
    def proposal_count(self): return len(self.proposals)

    @property
    def trace(self):
        return {"prompt_version": self.prompt_version, "hypothesis_ids_considered": list(self.hypothesis_ids_considered),
            "catalog_test_ids_available": list(self.catalog_test_ids_available),
            "proposal_ids_emitted": [p.proposal_id for p in self.proposals],
            "evidence_refs": list(self.input_evidence_refs), "validation_errors": list(self.validation_errors)}

    def to_dict(self):
        data = json.loads(json.dumps(asdict(self), sort_keys=True))
        data["proposal_count"] = self.proposal_count
        return data

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict) or set(data) - ({f.name for f in fields(cls)} | {"proposal_count"}):
            raise ContractError("Unknown planner result fields")
        parsed = dict(data); count = parsed.pop("proposal_count", None)
        try:
            parsed["proposals"] = tuple(TestProposal.from_dict(p) for p in parsed.get("proposals", []))
            parsed["coverage_gaps"] = tuple(CoverageGap.from_dict(g) for g in parsed.get("coverage_gaps", []))
            parsed["model_metadata"] = ModelMetadata(**parsed.get("model_metadata", {}))
            for key in ("planning_notes", "input_evidence_refs", "hypothesis_ids_considered", "catalog_test_ids_available", "validation_errors"):
                if key in parsed:
                    if not isinstance(parsed[key], (list, tuple)): raise ContractError("Invalid result collection")
                    parsed[key] = tuple(parsed[key])
            result = cls(**parsed)
            if type(count) is not int or count != result.proposal_count: raise ContractError("Invalid proposal_count")
            return result
        except (TypeError, KeyError, AttributeError) as exc:
            raise ContractError("Invalid planner result") from exc
