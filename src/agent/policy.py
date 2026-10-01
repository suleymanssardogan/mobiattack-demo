"""Pure V1 proposal eligibility checks. ALLOW never executes an action.

The caller supplies a trusted, scan-scoped index of evidence already resolved
from canonical artifacts. This module performs no filesystem/network access.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from collections.abc import Mapping

from src.dynamic.context.models import EndpointContext
from .models import (ContractError, PolicyDecision, TestProposal, identifier, reference, references, text, POLICY_VERSION)
from .test_catalog import TEST_CATALOG


_REFERENCE_TYPES = {
    ("dynamic/endpoint_contexts.json", "endpoint_context_id"): ("endpoint_context", None),
    ("dynamic/traffic.json", "transaction_id"): ("traffic_transaction", "transaction_ids"),
    ("static_analysis_report.json", "candidate_id"): ("static_candidate", "static_candidate_ids"),
    ("dynamic/api_correlation.json", "correlation_id"): ("api_correlation", "correlation_ids"),
    ("dynamic/runtime_evidence.json", "action_id"): ("runtime_action", "runtime_action_ids"),
    ("dynamic/traffic_evidence.json", "action_id"): ("traffic_action", "action_ids"),
}


@dataclass(frozen=True)
class EvidenceRecord:
    """Index metadata only; availability must have been verified by the caller."""
    reference: str
    endpoint_context_id: str
    kind: str

    def __post_init__(self):
        reference(self.reference); identifier(self.endpoint_context_id, "endpoint_context_id")
        path, _, fragment = self.reference.partition("#")
        key = fragment.partition("=")[0]
        expected = _REFERENCE_TYPES.get((path, key))
        if expected is None or expected[0] != self.kind:
            raise ContractError("Unsupported or inconsistent indexed evidence kind")


@dataclass(frozen=True)
class PreconditionRecord:
    """Caller-verified evidence satisfying one prerequisite, never model output.

    Like EvidenceRecord, this is an explicit trusted resolver input. References
    alone do not establish semantics: callers must verify the named prerequisite.
    """
    name: str
    endpoint_context_id: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self):
        text(self.name, "precondition name")
        identifier(self.endpoint_context_id, "endpoint_context_id")
        references(self.evidence_refs)


def _decision(proposal_id, decision, code, refs=(), *, detail=None):
    refs = tuple(sorted(set(refs)))
    digest = hashlib.sha256(repr((POLICY_VERSION, proposal_id, decision, code, refs)).encode()).hexdigest()[:16]
    reasons = {
        "UNKNOWN_HYPOTHESIS": "Proposal does not reference a supplied validated hypothesis.",
        "HALLUCINATED_EVIDENCE": "Reference is outside the current endpoint evidence universe.",
        "ALLOWED": "Proposal satisfies V1 contract checks; no action was executed.",
        "UNKNOWN_TEST": "Test is not in the canonical catalog.",
        "UNKNOWN_ENDPOINT_CONTEXT": "Referenced EndpointContext is unavailable.",
        "MISSING_EVIDENCE": "Required scan-scoped endpoint evidence is unavailable.",
        "MISSING_REQUIRED_CONTEXT": "Required context is unavailable.",
        "PARAMETER_NOT_IN_EVIDENCE": "Requested parameter is absent from endpoint evidence.",
        "RISK_NOT_ALLOWED": "Risk is inconsistent with the catalog or blocked by V1 policy.",
        "DESTRUCTIVE_ACTION": "Destructive action is blocked.",
        "AUTO_EXECUTION_NOT_ALLOWED": "Catalog does not allow automatic execution eligibility.",
        "SCHEMA_INVALID": "Proposal or supplied context violates the contract.",
        "ENDPOINT_NOT_IN_EVIDENCE": "Requested host, path or method is not the referenced endpoint identity.",
        "UNSUPPORTED_ACTION": "Action or mutation is outside the selected catalog contract.",
    }
    reason = reasons[code] if detail is None else f"{reasons[code]} Missing: {detail}."
    return PolicyDecision(f"policy_{digest}", proposal_id, decision, code, reason, refs)


def _lookup(context, dotted):
    current = context.to_dict()
    for key in dotted.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _linked(record, context):
    if record.endpoint_context_id != context.endpoint_context_id:
        return False
    path, _, fragment = record.reference.partition("#")
    key, _, identity = fragment.partition("=")
    _, field = _REFERENCE_TYPES[(path, key)]
    if field is None:
        return identity == context.endpoint_context_id
    identities = context.evidence_refs.get(field, [])
    if not isinstance(identities, list) or identity not in identities:
        return False
    missing = context.dynamic.get("missing_transaction_ids", [])
    if not isinstance(missing, list):
        return False
    if field == "static_candidate_ids" and (
            context.static.get("static_candidate_id_origin") != "source_report"
            or context.static.get("static_candidate_id") != identity):
        return False
    if field == "transaction_ids" and identity in missing:
        return False
    return True


def evaluate_proposal(proposal, endpoint_contexts: Mapping[str, EndpointContext],
                      evidence_index: Mapping[str, EvidenceRecord], *, proposal_only=False,
                      hypothesis_ids=(), available_evidence_refs=(),
                      precondition_index=None) -> PolicyDecision:
    """Validate untrusted dict/model output against catalog and existing evidence.

    Missing prerequisites produce needs_evidence; unsafe/invalid inputs deny.
    Catalog/identity/parameter checks are never inferred from prose.
    """
    raw_id = proposal.get("proposal_id") if isinstance(proposal, dict) else getattr(proposal, "proposal_id", None)
    try:
        identifier(raw_id, "proposal_id")
    except ContractError:
        raw_id = "invalid_proposal"
    if isinstance(proposal, dict) and isinstance(proposal.get("test_id"), str) and proposal["test_id"] not in TEST_CATALOG:
        return _decision(raw_id, "deny", "UNKNOWN_TEST")
    try:
        # Revalidate even previously instantiated/frozen objects at this trust boundary.
        p = TestProposal.from_dict(proposal.to_dict() if isinstance(proposal, TestProposal) else proposal)
    except (ContractError, TypeError, ValueError):
        return _decision(raw_id, "deny", "SCHEMA_INVALID")
    entry = TEST_CATALOG[p.test_id]
    if not isinstance(endpoint_contexts, Mapping) or not isinstance(evidence_index, Mapping):
        return _decision(p.proposal_id, "deny", "SCHEMA_INVALID")
    context = endpoint_contexts.get(p.endpoint_context_id)
    if context is None:
        return _decision(p.proposal_id, "deny", "UNKNOWN_ENDPOINT_CONTEXT")
    if (not isinstance(context, EndpointContext) or context.endpoint_context_id != p.endpoint_context_id
            or not isinstance(context.evidence_refs, dict) or not isinstance(context.request, dict)
            or not isinstance(context.dynamic, dict) or not isinstance(context.static, dict)
            or not isinstance(context.methods, list)):
        return _decision(p.proposal_id, "deny", "SCHEMA_INVALID")
    action = p.requested_action
    if proposal_only:
        if p.hypothesis_id not in hypothesis_ids:
            return _decision(p.proposal_id, "deny", "UNKNOWN_HYPOTHESIS")
        if action.execution_mode != "proposal_only" or action.action != entry.abstract_action:
            return _decision(p.proposal_id, "deny", "UNSUPPORTED_ACTION")
    if p.risk_class == "destructive" or action.action == "delete_resource" or action.mutation == "delete_resource":
        return _decision(p.proposal_id, "deny", "DESTRUCTIVE_ACTION")
    if p.risk_class != entry.risk_class or p.risk_class not in {"passive", "low"}:
        return _decision(p.proposal_id, "deny", "RISK_NOT_ALLOWED")
    if not proposal_only and (action.host != context.host or action.path != context.path or action.method not in context.methods):
        return _decision(p.proposal_id, "deny", "ENDPOINT_NOT_IN_EVIDENCE")
    if not proposal_only and (action.action not in entry.allowed_actions or action.mutation not in entry.allowed_mutations):
        return _decision(p.proposal_id, "deny", "UNSUPPORTED_ACTION")
    if action.execution_mode == "automatic" and not entry.auto_execution_allowed:
        return _decision(p.proposal_id, "deny", "AUTO_EXECUTION_NOT_ALLOWED")
    refs = tuple(sorted(set(p.evidence_refs)))
    if proposal_only and not set(refs).issubset(available_evidence_refs):
        return _decision(p.proposal_id, "deny", "HALLUCINATED_EVIDENCE")
    kinds = set()
    for ref in refs:
        record = evidence_index.get(ref)
        if proposal_only and isinstance(record, EvidenceRecord) and (record.reference != ref or not _linked(record, context)):
            missing = context.dynamic.get("missing_transaction_ids", [])
            declared = context.evidence_refs.get("transaction_ids", [])
            known_missing = (record.reference == ref and record.endpoint_context_id == context.endpoint_context_id
                             and record.kind == "traffic_transaction" and isinstance(missing, list)
                             and ref.partition("#transaction_id=")[2] in missing
                             and isinstance(declared, list) and ref.partition("#transaction_id=")[2] in declared)
            if not known_missing:
                return _decision(p.proposal_id, "deny", "HALLUCINATED_EVIDENCE")
        if not isinstance(record, EvidenceRecord) or record.reference != ref or not _linked(record, context):
            return _decision(p.proposal_id, "needs_evidence", "MISSING_EVIDENCE")
        kinds.add(record.kind)
    if not set(entry.required_evidence).issubset(kinds):
        return _decision(p.proposal_id, "needs_evidence", "MISSING_EVIDENCE")
    for key in sorted(set(entry.required_context) | set(p.required_context)):
        if proposal_only and key not in entry.required_context:
            record = precondition_index.get(key) if isinstance(precondition_index, Mapping) else None
            if record is None:
                return _decision(p.proposal_id, "needs_evidence", "MISSING_REQUIRED_CONTEXT", refs, detail=key)
            if (not isinstance(record, PreconditionRecord) or record.name != key
                    or record.endpoint_context_id != context.endpoint_context_id
                    or not set(record.evidence_refs).issubset(available_evidence_refs)):
                return _decision(p.proposal_id, "deny", "HALLUCINATED_EVIDENCE")
            for ref in record.evidence_refs:
                evidence = evidence_index.get(ref)
                if evidence is None:
                    return _decision(p.proposal_id, "needs_evidence", "MISSING_EVIDENCE", refs)
                if not isinstance(evidence, EvidenceRecord) or evidence.reference != ref or not _linked(evidence, context):
                    return _decision(p.proposal_id, "deny", "HALLUCINATED_EVIDENCE")
            refs = tuple(sorted(set(refs) | set(record.evidence_refs)))
            continue
        value = _lookup(context, key)
        if proposal_only and key == "auth" and isinstance(value, dict) and not any(type(v) is bool for v in value.values()):
            return _decision(p.proposal_id, "needs_evidence", "MISSING_REQUIRED_CONTEXT", refs, detail=key)
        if value is None or value is False or value == "" or value == [] or value == {}:
            return _decision(p.proposal_id, "needs_evidence", "MISSING_REQUIRED_CONTEXT", refs, detail=key)
    for parameter in action.parameters:
        field = "query_keys" if parameter.location == "query" else "body_keys"
        names = context.request.get(field, [])
        if not isinstance(names, list) or parameter.name not in names:
            return _decision(p.proposal_id, "deny", "PARAMETER_NOT_IN_EVIDENCE", refs)
    return _decision(p.proposal_id, "allow", "ALLOWED", refs)
