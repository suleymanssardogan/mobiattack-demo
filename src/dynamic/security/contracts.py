"""Dynamic security contracts V1. Nothing here executes or approves execution.

Validation describes a controlled behavioral check, never a vulnerability.
Tool output/response differences alone are insufficient. Failed or incomplete
checks cannot assert security. Reproduction is required before any future
confirmed finding; this module creates no findings and has no executor.

Evidence registry entries must come from validated canonical artifacts, not
model output. This layer checks references and ownership, not raw payloads.
"""
from dataclasses import asdict, dataclass, fields
from datetime import datetime
import re
from typing import Mapping

from src.dynamic.context.models import EndpointContext

SCHEMA_VERSION = '1.0'
SAFETY_VERSION = 'dynamic_security_v1'
RISK_CLASSES = frozenset({'passive', 'low', 'medium', 'high', 'destructive'})
ACTIONS = {
    'authentication_presence': frozenset({'validate_authentication_presence', 'compare_authenticated_baseline_behavior'}),
    'object_authorization': frozenset({'validate_object_access_behavior'}),
    'function_authorization': frozenset({'validate_function_access_behavior'}),
    'session_handling': frozenset({'validate_session_dependency'}),
    'parameter_consistency': frozenset({'validate_parameter_consistency'}),
    'input_validation': frozenset({'validate_input_validation_behavior'}),
}
EXECUTION_STATUSES = frozenset({'completed', 'failed', 'blocked', 'unavailable', 'interrupted'})
OUTCOMES = frozenset({'validated', 'rejected', 'inconclusive', 'blocked'})
VALIDATION_REASON_CODES = frozenset({
    'AUTH_ENFORCEMENT_CONFIRMED', 'MISSING_BASELINE_EVIDENCE', 'MISSING_VARIANT_EVIDENCE',
    'MISSING_REQUIRED_EVIDENCE', 'MISSING_ENDPOINT_EVIDENCE', 'MISSING_SESSION_EVIDENCE',
    'MISSING_EXECUTION_EVIDENCE', 'MISSING_COMPARISON_EVIDENCE', 'CROSS_SESSION_EVIDENCE',
    'CROSS_ENDPOINT_EVIDENCE', 'UNEXPECTED_REQUEST_MUTATION', 'SYNTHETIC_RESPONSE',
    'INSUFFICIENT_RESPONSE_COMPARISON', 'EXECUTION_NOT_COMPLETED', 'INVALID_EVIDENCE',
    'ACTION_MISMATCH', 'REFERENCE_MISMATCH', 'UNREDACTED_EVIDENCE',
})
EVIDENCE_KINDS = frozenset({'context', 'request', 'response', 'tool', 'runtime', 'control', 'comparison', 'reproduction'})
_ID = re.compile(r'[A-Za-z0-9_.:-]{1,160}')
_UNSAFE_TEXT = re.compile(r'https?://|\bcurl\b|\b(?:GET|POST|PUT|PATCH|DELETE)\s+/|\b(?:password|token|cookie|secret|authorization)\s*[:=]', re.I)


def _id(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError('Invalid reference identifier')


def _endpoint(value):
    _id(value)
    if not value.startswith('ctx_') or len(value) <= 4:
        raise ValueError('Invalid endpoint context reference')


def _refs(value, required=False):
    if not isinstance(value, (tuple, list)) or len(value) > 128 or (required and not value):
        raise ValueError('Missing or unbounded evidence references')
    for ref in value:
        _id(ref)
    return tuple(sorted(set(value)))


def _time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('Invalid timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('Invalid timestamp') from None
    if parsed.tzinfo is None:
        raise ValueError('Timestamp timezone missing')
    return parsed


class UnsupportedRequestRouting(ValueError):
    """A valid identity/evidence envelope with routing that must never dispatch.

    Ordinary contract construction still fails. The executor may use this
    validated envelope solely to emit an explicit blocked result.
    """
    def __init__(self, request, reason):
        super().__init__(reason)
        self.request = request
        self.reason = reason


class StrictContract:
    schema_version = SCHEMA_VERSION

    def to_dict(self):
        return {'schema_version': self.schema_version, **asdict(self)}

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError('Expected contract object')
        value = dict(data)
        if value.pop('schema_version', SCHEMA_VERSION) != SCHEMA_VERSION:
            raise ValueError('Unsupported schema version')
        if set(value) - {f.name for f in fields(cls)}:
            raise ValueError('Unknown or forbidden contract fields')
        try:
            return cls(**value)
        except TypeError:
            raise ValueError('Missing or invalid contract fields') from None


@dataclass(frozen=True)
class DynamicTestRequest(StrictContract):
    test_id: str
    endpoint_context_id: str
    test_category: str
    purpose: str
    required_evidence_refs: tuple[str, ...]
    requested_action: str
    risk_class: str
    session_id: str | None = None

    def __post_init__(self):
        _id(self.test_id)
        _endpoint(self.endpoint_context_id)
        if not isinstance(self.risk_class, str) or self.risk_class not in RISK_CLASSES:
            raise ValueError('Invalid risk class')
        if not isinstance(self.purpose, str) or not 1 <= len(self.purpose.strip()) <= 500 or _UNSAFE_TEXT.search(self.purpose):
            raise ValueError('Purpose must be bounded and contain no raw request/payload')
        object.__setattr__(self, 'required_evidence_refs', _refs(self.required_evidence_refs, required=True))
        if self.session_id is not None:
            _id(self.session_id)
        if not isinstance(self.test_category, str) or not 1 <= len(self.test_category) <= 80:
            raise ValueError('Invalid category field')
        if not isinstance(self.requested_action, str) or not 1 <= len(self.requested_action) <= 160:
            raise ValueError('Invalid action field')
        if self.test_category not in ACTIONS:
            raise UnsupportedRequestRouting(self, 'unsupported_category')
        if self.requested_action not in ACTIONS[self.test_category]:
            raise UnsupportedRequestRouting(self, 'unsupported_action')


@dataclass(frozen=True)
class DynamicTestExecutionResult(StrictContract):
    test_id: str
    endpoint_context_id: str
    execution_status: str
    observed_request_ref: str | None
    observed_response_ref: str | None
    evidence_refs: tuple[str, ...]
    tool_refs: tuple[str, ...]
    started_at: str
    finished_at: str
    failure_reason: str | None = None
    session_id: str | None = None

    def __post_init__(self):
        _id(self.test_id)
        _endpoint(self.endpoint_context_id)
        if self.execution_status not in EXECUTION_STATUSES:
            raise ValueError('Invalid execution status')
        if _time(self.finished_at) < _time(self.started_at):
            raise ValueError('Invalid execution timestamp order')
        object.__setattr__(self, 'evidence_refs', _refs(self.evidence_refs))
        object.__setattr__(self, 'tool_refs', _refs(self.tool_refs))
        for ref in (self.observed_request_ref, self.observed_response_ref, self.session_id):
            if ref is not None:
                _id(ref)
        if self.execution_status == 'completed':
            if not self.observed_request_ref or not self.observed_response_ref or self.failure_reason is not None:
                raise ValueError('Completed execution needs observed request and response evidence')
            if not {self.observed_request_ref, self.observed_response_ref}.issubset(self.evidence_refs):
                raise ValueError('Observation references missing from execution evidence')
        elif not isinstance(self.failure_reason, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,79}', self.failure_reason):
            raise ValueError('Non-completed execution requires a safe failure reason code')


@dataclass(frozen=True)
class DynamicValidationResult(StrictContract):
    test_id: str
    endpoint_context_id: str
    outcome: str
    evidence_refs: tuple[str, ...]
    criterion: str
    coverage: str
    created_at: str
    session_id: str | None = None
    reason_codes: tuple[str, ...] = ()

    def __post_init__(self):
        if not isinstance(self.reason_codes, (tuple, list)) or len(self.reason_codes) > 16 or any(not isinstance(code, str) or code not in VALIDATION_REASON_CODES for code in self.reason_codes):
            raise ValueError('Invalid validation reason codes')
        object.__setattr__(self, 'reason_codes', tuple(sorted(set(self.reason_codes))))
        if 'AUTH_ENFORCEMENT_CONFIRMED' in self.reason_codes and self.outcome != 'validated':
            raise ValueError('Reason code and outcome mismatch')
        if self.outcome == 'validated' and set(self.reason_codes) - {'AUTH_ENFORCEMENT_CONFIRMED'}:
            raise ValueError('Incomplete or invalid evidence cannot be validated')
        _id(self.test_id)
        _endpoint(self.endpoint_context_id)
        _time(self.created_at)
        if self.outcome not in OUTCOMES or self.coverage not in {'available', 'partial', 'unavailable', 'unknown'}:
            raise ValueError('Invalid outcome or coverage')
        object.__setattr__(self, 'evidence_refs', _refs(self.evidence_refs, required=True))
        if self.session_id is not None:
            _id(self.session_id)
        criteria = {'controlled_behavior_check', 'criteria_not_met', 'insufficient_evidence', 'policy_or_execution_blocked'}
        if self.criterion not in criteria:
            raise ValueError('Unsupported criterion; observations alone are insufficient')
        expected = {'validated': 'controlled_behavior_check', 'rejected': 'criteria_not_met',
                    'inconclusive': 'insufficient_evidence', 'blocked': 'policy_or_execution_blocked'}
        if self.criterion != expected[self.outcome]:
            raise ValueError('Outcome and criterion mismatch')
        if self.outcome in {'validated', 'rejected'} and self.coverage != 'available':
            raise ValueError('Incomplete coverage cannot support a conclusive validation')


@dataclass(frozen=True)
class EvidenceReference:
    ref: str
    endpoint_context_id: str
    kind: str
    session_id: str | None = None

    def __post_init__(self):
        _id(self.ref)
        _endpoint(self.endpoint_context_id)
        if self.kind not in EVIDENCE_KINDS:
            raise ValueError('Unsupported evidence kind')
        if self.session_id is not None:
            _id(self.session_id)


def _verify_refs(refs, endpoint, session, registry: Mapping[str, EvidenceReference]):
    for ref in refs:
        record = registry.get(ref)
        if not isinstance(record, EvidenceReference) or record.ref != ref or record.endpoint_context_id != endpoint:
            raise ValueError('Missing, hallucinated or cross-endpoint evidence')
        if record.session_id != session:
            raise ValueError('Cross-session or unscoped evidence')


def check_request_safety(request, context: EndpointContext, registry):
    """Eligibility metadata only. No decision from this function executes anything."""
    if not isinstance(context, EndpointContext) or context.endpoint_context_id != request.endpoint_context_id:
        raise ValueError('Endpoint context mismatch')
    _verify_refs(request.required_evidence_refs, request.endpoint_context_id, request.session_id, registry)
    return {'policy_version': SAFETY_VERSION,
            'decision': 'eligible_for_future_policy_review' if request.risk_class in {'passive', 'low'} else 'blocked',
            'automatic_execution_allowed': False,
            'reason': 'executor_not_implemented' if request.risk_class in {'passive', 'low'} else 'risk_requires_explicit_policy_authorization'}


def validate_execution(request, execution, registry):
    if (execution.test_id, execution.endpoint_context_id, execution.session_id) != (
            request.test_id, request.endpoint_context_id, request.session_id):
        raise ValueError('Execution/request identity mismatch')
    refs = execution.evidence_refs + execution.tool_refs
    _verify_refs(refs, request.endpoint_context_id, request.session_id, registry)
    for ref, kind in ((execution.observed_request_ref, 'request'), (execution.observed_response_ref, 'response')):
        if ref is not None:
            _verify_refs((ref,), request.endpoint_context_id, request.session_id, registry)
            if registry[ref].kind != kind:
                raise ValueError('Invalid observed evidence kind')
    if any(registry[ref].kind != 'tool' for ref in execution.tool_refs):
        raise ValueError('Invalid tool reference kind')


def validate_result(request, execution, result, registry, *, auth_evidence=None):
    """No findings; only explicit controlled behavior evidence can be validated."""
    validate_execution(request, execution, registry)
    if (result.test_id, result.endpoint_context_id, result.session_id) != (
            request.test_id, request.endpoint_context_id, request.session_id):
        raise ValueError('Validation identity mismatch')
    _verify_refs(result.evidence_refs, request.endpoint_context_id, request.session_id, registry)
    if _time(result.created_at) < _time(execution.finished_at):
        raise ValueError('Validation predates execution')
    if result.outcome in {'validated', 'rejected'}:
        if execution.execution_status != 'completed':
            raise ValueError('Failed/incomplete test cannot support conclusive validation')
        kinds = {registry[ref].kind for ref in result.evidence_refs}
        if not {'request', 'response', 'control', 'comparison'}.issubset(kinds):
            raise ValueError('Tool output or changed response alone is insufficient')
        if not {execution.observed_request_ref, execution.observed_response_ref}.issubset(result.evidence_refs):
            raise ValueError('Validation must cite this execution observations')

    if request.test_category == 'authentication_presence' and result.outcome in {'validated', 'rejected'}:
        from src.dynamic.security.validation import inspect_auth_presence
        inspection = inspect_auth_presence(request, execution, registry, auth_evidence)
        if inspection.code != 'AUTH_ENFORCEMENT_CONFIRMED' or result.outcome != 'validated':
            raise ValueError(inspection.code)
        if result.reason_codes != ('AUTH_ENFORCEMENT_CONFIRMED',) or not inspection.refs.issubset(result.evidence_refs):
            raise ValueError('MISSING_REQUIRED_EVIDENCE')
