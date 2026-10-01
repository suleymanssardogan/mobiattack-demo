"""Strict, dependency-free Agent Analysis domain contracts.

These objects carry sanitized summaries and references, never request bodies,
credential values, hidden reasoning transcripts or finding verdicts.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import re
from typing import ClassVar


class ContractError(ValueError):
    """An untrusted output violates a canonical contract."""


RISK_CLASSES = frozenset({"passive", "low", "medium", "high", "destructive"})
LIFECYCLE_STATES = frozenset({"hypothesis", "planned", "executed", "observed", "validated", "confirmed",
                              "rejected", "inconclusive", "blocked"})
VALIDATION_STATES = frozenset({"validated", "rejected", "inconclusive", "blocked"})
ACTIONS = frozenset({"review_evidence", "check_parameter", "object_access", "function_access",
                     "session_check", "input_check", "delete_resource"})
ABSTRACT_ACTIONS = frozenset({"review_authentication_presence", "validate_object_access_behavior",
    "validate_function_access_behavior", "validate_session_dependency", "validate_input_handling",
    "validate_parameter_consistency"})
MUTATIONS = frozenset({"none", "query_parameter", "body_parameter", "delete_resource"})
ARTIFACTS = frozenset({"static_analysis_report.json", "dynamic_analysis_report.json",
    "dynamic/api_correlation.json", "dynamic/endpoint_contexts.json", "dynamic/runtime_evidence.json",
    "dynamic/traffic.json", "dynamic/traffic_evidence.json", "dynamic/route_graph.json", "dynamic/timeline.json"})
_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$")
# A guard against common accidental credential pastes, not a promise to detect every secret.
_SECRET = re.compile(r"(?i)\bbearer\s+\S+|(?:password|api[_-]?key|refresh[_-]?token|authorization|cookie)\s*[:=]\s*\S+")


def text(value, name):
    if not isinstance(value, str) or not value.strip() or len(value) > 2048 or _SECRET.search(value):
        raise ContractError(f"Invalid sanitized text: {name}")


def identifier(value, name):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ContractError(f"Invalid identifier: {name}")


def timestamp(value):
    text(value, "timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("Invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise ContractError("Timestamp requires timezone")


def strings(value, name, *, nonempty=False):
    if not isinstance(value, tuple) or (nonempty and not value):
        raise ContractError(f"Expected tuple: {name}")
    for item in value:
        text(item, name)


def reference(value):
    if not isinstance(value, str):
        raise ContractError("Invalid canonical evidence reference")
    path, sep, fragment = value.partition("#")
    if path not in ARTIFACTS:
        raise ContractError("Evidence must reference a canonical run-relative artifact")
    if sep:
        key, equal, identity = fragment.partition("=")
        if not equal or key not in {"endpoint_context_id", "correlation_id", "transaction_id", "candidate_id",
                                     "action_id", "node_id", "event_id"}:
            raise ContractError("Invalid evidence fragment")
        identifier(identity, "evidence identity")


def references(value, *, required=True):
    strings(value, "evidence_refs", nonempty=required)
    for ref in value:
        reference(ref)


class Contract:
    """Construct from dictionaries without silently accepting extra model output."""
    tuple_fields: ClassVar[frozenset[str]] = frozenset()

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict) or set(data) - {f.name for f in fields(cls)}:
            raise ContractError(f"Unknown fields in {cls.__name__}")
        parsed = dict(data)
        for key in cls.tuple_fields:
            if key in parsed:
                if not isinstance(parsed[key], (list, tuple)):
                    raise ContractError(f"Expected list: {key}")
                parsed[key] = tuple(parsed[key])
        if cls is TestProposal and isinstance(parsed.get("requested_action"), dict):
            parsed["requested_action"] = RequestedAction.from_dict(parsed["requested_action"])
        if cls is RequestedAction and "parameters" in parsed:
            parsed["parameters"] = tuple(ParameterReference.from_dict(p) if isinstance(p, dict) else p
                                          for p in parsed["parameters"])
        try:
            return cls(**parsed)
        except (TypeError, AttributeError) as exc:
            raise ContractError(f"Invalid {cls.__name__}") from exc

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class ParameterReference(Contract):
    location: str
    name: str

    def __post_init__(self):
        if self.location not in {"query", "body"}:
            raise ContractError("Unsupported parameter location")
        identifier(self.name, "parameter name")


@dataclass(frozen=True)
class RequestedAction(Contract):
    action: str
    host: str = ""
    path: str = ""
    method: str = ""
    execution_mode: str = "automatic"
    mutation: str = "none"
    parameters: tuple[ParameterReference, ...] = ()
    tuple_fields = frozenset({"parameters"})

    def __post_init__(self):
        if self.action in ABSTRACT_ACTIONS:
            if (self.execution_mode != "proposal_only" or self.host != "" or self.path != "" or self.method != ""
                    or self.mutation != "none" or self.parameters != ()):
                raise ContractError("Abstract proposal cannot carry execution fields")
            return
        if self.action not in ACTIONS or self.mutation not in MUTATIONS:
            raise ContractError("Unsupported action or mutation")
        if self.execution_mode not in {"automatic", "manual"}:
            raise ContractError("Unsupported execution mode")
        for name in ("host", "path", "method"):
            text(getattr(self, name), name)
        if not self.path.startswith("/") or "?" in self.path or "#" in self.path:
            raise ContractError("Expected canonical path identity")
        if not isinstance(self.parameters, tuple) or any(not isinstance(p, ParameterReference) for p in self.parameters):
            raise ContractError("Invalid parameter references")
        if self.action == "check_parameter" and not self.parameters:
            raise ContractError("Parameter check requires explicit parameter references")
        if self.mutation in {"query_parameter", "body_parameter"}:
            location = "query" if self.mutation == "query_parameter" else "body"
            if not self.parameters or any(p.location != location for p in self.parameters):
                raise ContractError("Mutation must name matching parameter references")


@dataclass(frozen=True)
class AgentObservation(Contract):
    observation_id: str
    endpoint_context_id: str
    facts: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    coverage_gaps: tuple[str, ...]
    created_at: str
    tuple_fields = frozenset({"facts", "evidence_refs", "coverage_gaps"})

    def __post_init__(self):
        identifier(self.observation_id, "observation_id"); identifier(self.endpoint_context_id, "endpoint_context_id")
        strings(self.facts, "facts", nonempty=True); references(self.evidence_refs)
        strings(self.coverage_gaps, "coverage_gaps"); timestamp(self.created_at)


@dataclass(frozen=True)
class AgentHypothesis(Contract):
    hypothesis_id: str
    endpoint_context_id: str
    hypothesis_type: str
    statement: str
    evidence_refs: tuple[str, ...]
    required_evidence: tuple[str, ...]
    status: str = "hypothesis"
    tuple_fields = frozenset({"evidence_refs", "required_evidence"})

    def __post_init__(self):
        identifier(self.hypothesis_id, "hypothesis_id"); identifier(self.endpoint_context_id, "endpoint_context_id")
        identifier(self.hypothesis_type, "hypothesis_type"); text(self.statement, "statement")
        references(self.evidence_refs); strings(self.required_evidence, "required_evidence")
        if self.status not in LIFECYCLE_STATES:
            raise ContractError("Invalid lifecycle state")
        # A reasoning hypothesis cannot self-promote to execution or a finding.
        if self.status not in {"hypothesis", "planned", "rejected", "inconclusive", "blocked"}:
            raise ContractError("Hypothesis cannot claim observed/validated/confirmed execution")


@dataclass(frozen=True)
class TestProposal(Contract):
    __test__ = False
    proposal_id: str
    hypothesis_id: str
    endpoint_context_id: str
    test_id: str
    reason: str
    evidence_refs: tuple[str, ...]
    required_context: tuple[str, ...]
    requested_action: RequestedAction
    risk_class: str
    created_at: str
    tuple_fields = frozenset({"evidence_refs", "required_context"})

    def __post_init__(self):
        from .test_catalog import TEST_CATALOG
        for name in ("proposal_id", "hypothesis_id", "endpoint_context_id"):
            identifier(getattr(self, name), name)
        if self.test_id not in TEST_CATALOG:
            raise ContractError("Unknown test")
        if self.risk_class not in RISK_CLASSES:
            raise ContractError("Invalid risk class")
        text(self.reason, "reason"); references(self.evidence_refs)
        strings(self.required_context, "required_context"); timestamp(self.created_at)
        if not isinstance(self.requested_action, RequestedAction):
            raise ContractError("Invalid requested_action")


POLICY_VERSION = "policy_v1"


@dataclass(frozen=True)
class PolicyDecision(Contract):
    decision_id: str
    proposal_id: str
    decision: str
    reason_code: str
    reason: str
    validated_evidence_refs: tuple[str, ...] = ()
    policy_version: str = POLICY_VERSION
    endpoint_context_id: str | None = None
    hypothesis_id: str | None = None
    test_id: str | None = None
    tuple_fields = frozenset({"validated_evidence_refs"})

    def __post_init__(self):
        identifier(self.decision_id, "decision_id"); identifier(self.proposal_id, "proposal_id")
        if self.decision not in {"allow", "deny", "needs_evidence"}:
            raise ContractError("Invalid policy decision")
        if self.reason_code not in {"ALLOWED", "UNKNOWN_TEST", "UNKNOWN_ENDPOINT_CONTEXT", "MISSING_EVIDENCE",
            "MISSING_REQUIRED_CONTEXT", "PARAMETER_NOT_IN_EVIDENCE", "RISK_NOT_ALLOWED", "DESTRUCTIVE_ACTION",
            "AUTO_EXECUTION_NOT_ALLOWED", "SCHEMA_INVALID", "ENDPOINT_NOT_IN_EVIDENCE", "UNSUPPORTED_ACTION",
            "UNKNOWN_HYPOTHESIS", "HALLUCINATED_EVIDENCE"}:
            raise ContractError("Unknown policy reason code")
        for name in ("endpoint_context_id", "hypothesis_id", "test_id"):
            if getattr(self, name) is not None:
                identifier(getattr(self, name), name)
        if self.policy_version != POLICY_VERSION:
            raise ContractError("Unsupported policy version")
        text(self.reason, "reason"); references(self.validated_evidence_refs, required=False)


@dataclass(frozen=True)
class ToolExecutionResult(Contract):
    execution_id: str
    proposal_id: str
    test_id: str
    started_at: str
    completed_at: str
    status: str
    request_refs: tuple[str, ...]
    response_refs: tuple[str, ...]
    output_refs: tuple[str, ...]
    error: str | None = None
    tuple_fields = frozenset({"request_refs", "response_refs", "output_refs"})

    def __post_init__(self):
        from .test_catalog import TEST_CATALOG
        identifier(self.execution_id, "execution_id"); identifier(self.proposal_id, "proposal_id")
        if self.test_id not in TEST_CATALOG or self.status not in {"completed", "failed", "blocked"}:
            raise ContractError("Invalid executor contract")
        timestamp(self.started_at); timestamp(self.completed_at)
        if datetime.fromisoformat(self.completed_at.replace("Z", "+00:00")) < datetime.fromisoformat(self.started_at.replace("Z", "+00:00")):
            raise ContractError("Execution timestamps out of order")
        for value in (self.request_refs, self.response_refs, self.output_refs):
            references(value, required=False)
        if self.status == "completed" and not (self.request_refs or self.response_refs or self.output_refs):
            raise ContractError("Completed tool output requires evidence references")
        if self.error is not None:
            text(self.error, "error")


@dataclass(frozen=True)
class ValidationResult(Contract):
    validation_id: str
    proposal_id: str
    execution_id: str
    state: str
    evidence_refs: tuple[str, ...]
    validation_criteria: tuple[str, ...]
    observed_behavior: str
    reason: str
    reproducible: bool
    reproduction_refs: tuple[str, ...] = ()
    tuple_fields = frozenset({"evidence_refs", "validation_criteria", "reproduction_refs"})

    def __post_init__(self):
        for name in ("validation_id", "proposal_id", "execution_id"):
            identifier(getattr(self, name), name)
        if self.state not in VALIDATION_STATES or type(self.reproducible) is not bool:
            raise ContractError("Invalid validation result")
        references(self.evidence_refs, required=self.state == "validated")
        strings(self.validation_criteria, "validation_criteria", nonempty=True)
        text(self.observed_behavior, "observed_behavior"); text(self.reason, "reason")
        references(self.reproduction_refs, required=self.reproducible)
        if self.reproducible and set(self.reproduction_refs).intersection(self.evidence_refs):
            raise ContractError("Reproduction requires distinct evidence references")
        if not self.reproducible and self.reproduction_refs:
            raise ContractError("Unverified reproduction cannot carry confirmation references")
        if self.reproducible and self.state != "validated":
            raise ContractError("Reproducibility cannot confirm nonvalidated behavior")


@dataclass(frozen=True)
class CoverageGap(Contract):
    gap_id: str
    endpoint_context_id: str | None
    kind: str
    description: str
    evidence_refs: tuple[str, ...]
    blocked_test_ids: tuple[str, ...] = ()
    tuple_fields = frozenset({"evidence_refs", "blocked_test_ids"})
    kinds: ClassVar[frozenset[str]] = frozenset({"static_not_observed", "https_visibility_unavailable", "max_steps",
        "max_depth", "input_skipped", "traffic_unavailable", "external_package", "system_ui", "policy_blocked",
        "required_evidence_unavailable"})

    def __post_init__(self):
        from .test_catalog import TEST_CATALOG
        identifier(self.gap_id, "gap_id")
        if self.endpoint_context_id is not None:
            identifier(self.endpoint_context_id, "endpoint_context_id")
        if self.kind not in self.kinds:
            raise ContractError("Unknown coverage gap")
        text(self.description, "description"); references(self.evidence_refs, required=False)
        strings(self.blocked_test_ids, "blocked_test_ids")
        if any(t not in TEST_CATALOG for t in self.blocked_test_ids):
            raise ContractError("Unknown blocked test")


@dataclass(frozen=True)
class TransparentValidationTrace(Contract):
    trace_id: str
    hypothesis_id: str
    proposal_id: str
    policy_decision_id: str
    observed_facts: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    validation_criteria: tuple[str, ...]
    next_action_decision: str
    stop_reason: str | None
    execution_id: str | None = None
    validation_id: str | None = None
    tuple_fields = frozenset({"observed_facts", "evidence_refs", "validation_criteria"})

    def __post_init__(self):
        for name in ("trace_id", "hypothesis_id", "proposal_id", "policy_decision_id"):
            identifier(getattr(self, name), name)
        for value in (self.execution_id, self.validation_id):
            if value is not None:
                identifier(value, "trace reference")
        if self.validation_id is not None and self.execution_id is None:
            raise ContractError("Validation trace requires execution reference")
        strings(self.observed_facts, "observed_facts"); references(self.evidence_refs)
        strings(self.validation_criteria, "validation_criteria")
        if self.next_action_decision not in {"stop", "request_evidence", "replan", "await_policy", "await_executor"}:
            raise ContractError("Invalid next action decision")
        if self.stop_reason is not None:
            text(self.stop_reason, "stop_reason")
        if self.next_action_decision == "stop" and self.stop_reason is None:
            raise ContractError("Stop requires reason")


LEGAL_TRANSITIONS = {
    "hypothesis": frozenset({"planned", "rejected", "inconclusive", "blocked"}),
    "planned": frozenset({"executed", "blocked", "rejected"}),
    "executed": frozenset({"observed", "inconclusive", "blocked"}),
    "observed": frozenset({"validated", "rejected", "inconclusive", "blocked"}),
    "validated": frozenset({"confirmed", "inconclusive", "rejected"}),
    "confirmed": frozenset(), "rejected": frozenset(), "inconclusive": frozenset(), "blocked": frozenset(),
}


def validate_transition(current: str, target: str, *, validation: ValidationResult | None = None):
    """Validate a lifecycle edge; this function does not create or persist findings."""
    if not isinstance(current, str) or not isinstance(target, str) or current not in LEGAL_TRANSITIONS or target not in LEGAL_TRANSITIONS[current]:
        raise ContractError("Illegal lifecycle transition")
    if target in {"validated", "confirmed"}:
        if not isinstance(validation, ValidationResult) or validation.state != "validated":
            raise ContractError("Validated transition requires validation evidence")
        if target == "confirmed" and not (validation.reproducible and validation.reproduction_refs):
            raise ContractError("Confirmation requires reproducible evidence")


def validate_trace_links(trace: TransparentValidationTrace, hypothesis: AgentHypothesis,
                         proposal: TestProposal, policy: PolicyDecision,
                         execution: ToolExecutionResult | None = None,
                         validation: ValidationResult | None = None):
    """Check foreign keys in a structured trace without interpreting reasoning."""
    if (trace.hypothesis_id != hypothesis.hypothesis_id or trace.proposal_id != proposal.proposal_id
            or proposal.hypothesis_id != hypothesis.hypothesis_id
            or proposal.endpoint_context_id != hypothesis.endpoint_context_id
            or trace.policy_decision_id != policy.decision_id or policy.proposal_id != proposal.proposal_id):
        raise ContractError("Trace lineage mismatch")
    if execution is None:
        if trace.execution_id is not None or validation is not None:
            raise ContractError("Missing trace execution")
    elif (trace.execution_id != execution.execution_id or execution.proposal_id != proposal.proposal_id
          or execution.test_id != proposal.test_id or policy.decision != "allow"):
        raise ContractError("Execution lineage or policy mismatch")
    if validation is None:
        if trace.validation_id is not None:
            raise ContractError("Missing trace validation")
    elif (trace.validation_id != validation.validation_id or validation.proposal_id != proposal.proposal_id
          or execution is None or validation.execution_id != execution.execution_id):
        raise ContractError("Validation lineage mismatch")
    known_refs = set(hypothesis.evidence_refs) | set(proposal.evidence_refs) | set(policy.validated_evidence_refs)
    if execution is not None:
        known_refs.update(execution.request_refs + execution.response_refs + execution.output_refs)
    if validation is not None:
        known_refs.update(validation.evidence_refs + validation.reproduction_refs)
    if not set(trace.evidence_refs).issubset(known_refs):
        raise ContractError("Unlinked trace evidence")
