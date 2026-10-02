"""Offline auth-presence evidence validation. No transport, replay or findings.

Ref labels alone cannot establish response reality or mutation integrity. The
source bundle contains sanitized canonical payloads and actual lab receipts.
Legacy summaries/booleans are intentionally not inputs to the decision.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from src.dynamic.context.models import EndpointContext
from src.dynamic.runtime.models import utc_now_iso
from src.dynamic.security.contracts import (
    ACTIONS, DynamicTestRequest, DynamicTestExecutionResult, DynamicValidationResult,
    EvidenceReference, _time, validate_execution,
)
from src.dynamic.traffic.normalizer import sanitize_transaction_data


@dataclass(frozen=True)
class AuthPresenceEvidence:
    context: EndpointContext
    session: dict
    baseline: dict | None
    variant: dict | None
    baseline_receipts: list
    variant_receipts: list
    execution_ref: str
    control_ref: str
    comparison_ref: str


@dataclass(frozen=True)
class EvidenceInspection:
    code: str
    outcome: str
    refs: frozenset[str] = frozenset()


def inspect_auth_presence(request, execution, registry, evidence):
    """Return a stable reason, never promote incomplete or mismatched evidence."""
    def fail(code, blocked=False):
        return EvidenceInspection(code, 'blocked' if blocked else 'inconclusive')

    if not isinstance(evidence, AuthPresenceEvidence):
        return fail('MISSING_BASELINE_EVIDENCE')
    if not isinstance(evidence.context, EndpointContext) or not isinstance(evidence.session, dict) or not hasattr(registry, 'get'):
        return fail('INVALID_EVIDENCE', True)
    if request.test_category != 'authentication_presence' or request.requested_action not in ACTIONS['authentication_presence'] or request.risk_class != 'low':
        return fail('ACTION_MISMATCH', True)
    if execution.test_id != request.test_id or execution.endpoint_context_id != request.endpoint_context_id or evidence.context.endpoint_context_id != request.endpoint_context_id:
        return fail('CROSS_ENDPOINT_EVIDENCE', True)
    if not request.session_id or execution.session_id != request.session_id or evidence.session.get('session_id') != request.session_id:
        return fail('CROSS_SESSION_EVIDENCE', True)
    if execution.execution_status != 'completed':
        return fail('EXECUTION_NOT_COMPLETED')
    baseline, variant = evidence.baseline, evidence.variant
    for payload, code in [(baseline,'MISSING_BASELINE_EVIDENCE'), (variant,'MISSING_VARIANT_EVIDENCE')]:
        if not isinstance(payload, dict) or not isinstance(payload.get('request'), dict) or not isinstance(payload.get('response'), dict):
            return fail(code)
        if payload.get('session_id') != request.session_id:
            return fail('CROSS_SESSION_EVIDENCE', True)
        if any(part.get('synthetic') or part.get('internal') for part in (payload, payload['request'], payload['response'])):
            return fail('SYNTHETIC_RESPONSE', True)
        observation = payload.get('correlation', {}).get('response_observation', {})
        if observation and observation.get('state') != 'available':
            return fail('SYNTHETIC_RESPONSE', True)
    try:
        bq, br, vq, vr = baseline['request'], baseline['response'], variant['request'], variant['response']
        brr = br.get('headers', {}).get('x-lab-trace-id')
        vrr = vr.get('headers', {}).get('x-lab-trace-id')
        roles = [(bq.get('request_id'), 'request', 'MISSING_BASELINE_EVIDENCE'),
                 (brr, 'response', 'MISSING_BASELINE_EVIDENCE'),
                 (vq.get('request_id'), 'request', 'MISSING_VARIANT_EVIDENCE'),
                 (vrr, 'response', 'MISSING_VARIANT_EVIDENCE'),
                 (request.endpoint_context_id, 'context', 'MISSING_ENDPOINT_EVIDENCE'),
                 (request.session_id, 'runtime', 'MISSING_SESSION_EVIDENCE'),
                 (evidence.execution_ref, 'tool', 'MISSING_EXECUTION_EVIDENCE'),
                 (evidence.control_ref, 'control', 'MISSING_COMPARISON_EVIDENCE'),
                 (evidence.comparison_ref, 'comparison', 'MISSING_COMPARISON_EVIDENCE')]
        for ref, kind, missing in roles:
            record = registry.get(ref)
            if not isinstance(record, EvidenceReference) or record.ref != ref:
                return fail(missing)
            if record.session_id != request.session_id:
                return fail('CROSS_SESSION_EVIDENCE', True)
            if record.endpoint_context_id != request.endpoint_context_id:
                return fail('CROSS_ENDPOINT_EVIDENCE', True)
            if record.kind != kind:
                return fail('REFERENCE_MISMATCH', True)
            if ref not in execution.evidence_refs:
                return fail(missing)
        for ref in request.required_evidence_refs:
            record = registry.get(ref)
            if not isinstance(record, EvidenceReference) or record.ref != ref:
                return fail('MISSING_REQUIRED_EVIDENCE')
            if record.session_id != request.session_id:
                return fail('CROSS_SESSION_EVIDENCE', True)
            if record.endpoint_context_id != request.endpoint_context_id:
                return fail('CROSS_ENDPOINT_EVIDENCE', True)
        if not {bq['request_id'], brr, request.session_id, request.endpoint_context_id}.issubset(request.required_evidence_refs):
            return fail('MISSING_BASELINE_EVIDENCE')
        if (execution.observed_request_ref, execution.observed_response_ref) != (vq['request_id'], vrr) or evidence.execution_ref not in execution.tool_refs:
            return fail('REFERENCE_MISMATCH', True)
        digest = hashlib.sha256(json.dumps([request.test_id, request.endpoint_context_id, request.session_id, bq['request_id']]).encode()).hexdigest()[:20]
        if (evidence.execution_ref, evidence.control_ref, evidence.comparison_ref) != ('execution_'+digest, 'control_'+digest, 'comparison_'+digest):
            return fail('REFERENCE_MISMATCH', True)
        if bq['request_id'] == vq['request_id'] or brr == vrr:
            return fail('REFERENCE_MISMATCH', True)
        identity = (evidence.context.scheme, evidence.context.host, evidence.context.port, evidence.context.path)
        for q in (bq, vq):
            if (q.get('scheme'),q.get('host'),q.get('port'),q.get('path')) != identity or q.get('method') not in evidence.context.methods:
                return fail('CROSS_ENDPOINT_EVIDENCE', True)
            if q.get('headers', {}).get('x-lab-run-id') != request.session_id:
                return fail('CROSS_SESSION_EVIDENCE', True)
        if baseline.get('transaction_id') not in evidence.context.evidence_refs.get('transaction_ids', []) or not evidence.context.dynamic.get('observed') or not evidence.context.auth.get('authorization_header_present'):
            return fail('MISSING_BASELINE_EVIDENCE')
        if variant.get('attribution', {}).get('baseline_transaction_ref') != baseline.get('transaction_id'):
            return fail('REFERENCE_MISMATCH', True)
        # Do not silently normalize away synthetic markers or secret values.
        if sanitize_transaction_data(baseline) != baseline or sanitize_transaction_data(variant) != variant:
            return fail('UNREDACTED_EVIDENCE', True)
        from src.dynamic.security.authentication_presence import auth_removal_variant
        try:
            expected = auth_removal_variant(baseline)
        except ValueError:
            return fail('UNEXPECTED_REQUEST_MUTATION', True)
        # Only observation identity/time may differ. Unknown request fields fail.
        transient = {'request_id', 'timestamp'}
        if {k:v for k,v in expected.items() if k not in transient} != {k:v for k,v in vq.items() if k not in transient}:
            return fail('UNEXPECTED_REQUEST_MUTATION', True)
        if not (_time(execution.started_at) <= _time(vq['timestamp']) <= _time(vr['timestamp']) <= _time(execution.finished_at)) or _time(br['timestamp']) > _time(execution.started_at):
            return fail('REFERENCE_MISMATCH', True)
        for tx, receipts, authenticated, missing in [(baseline,evidence.baseline_receipts,True,'MISSING_BASELINE_EVIDENCE'), (variant,evidence.variant_receipts,False,'MISSING_VARIANT_EVIDENCE')]:
            q, r = tx['request'], tx['response']
            if not isinstance(r.get('status_code'), int) or isinstance(r['status_code'], bool) or not 100 <= r['status_code'] <= 599:
                return fail('INSUFFICIENT_RESPONSE_COMPARISON')
            meta = r.get('body_metadata')
            if not isinstance(meta, dict) or not isinstance(meta.get('size'), int) or meta['size'] <= 0 or meta.get('truncated') is not False or meta.get('binary') is not False or not isinstance(r.get('body'), dict) or r.get('headers', {}).get('content-type', '').split(';')[0] != 'application/json':
                return fail('INSUFFICIENT_RESPONSE_COMPARISON')
            if not isinstance(receipts, list):
                return fail(missing)
            records = [x for x in receipts if isinstance(x,dict) and x.get('trace_id') == r['headers'].get('x-lab-trace-id')]
            if len(records) != 1:
                return fail(missing)
            receipt = records[0]
            if receipt.get('synthetic') or receipt.get('internal'):
                return fail('SYNTHETIC_RESPONSE', True)
            if receipt.get('run_id') != request.session_id:
                return fail('CROSS_SESSION_EVIDENCE', True)
            if receipt.get('path') != q['path'] or receipt.get('method') != q['method'] or receipt.get('status') != r['status_code'] or receipt.get('auth_present') is not authenticated or receipt.get('auth_valid') is not authenticated:
                return fail('REFERENCE_MISMATCH', True)
            if receipt.get('source') != 'local_training_backend_actual_response':
                return fail(missing)
        validate_execution(request, execution, registry)
        if br['status_code'] != 200 or br['body'].get('authenticated') is not True or br['body'].get('purpose') != 'read_only_training_profile' or not isinstance(br['body'].get('profile'), dict):
            return fail('INSUFFICIENT_RESPONSE_COMPARISON')
        # Validate expected auth enforcement, never a vulnerability; 200 alone is inconclusive.
        if vr['status_code'] != 401 or vr['body'] != {'error':'authentication_required'}:
            return fail('INSUFFICIENT_RESPONSE_COMPARISON')
        return EvidenceInspection('AUTH_ENFORCEMENT_CONFIRMED', 'validated', frozenset(ref for ref,_,_ in roles))
    except (ValueError, TypeError, KeyError, AttributeError):
        return fail('INVALID_EVIDENCE', True)


def validate_authentication_presence(request, execution, registry, evidence, *, created_at=None):
    """Recompute the decision solely from payloads; never trust saved booleans."""
    inspection = inspect_auth_presence(request, execution, registry, evidence)
    # Only cite existing, owned records on a downgrade. Never invent replacement refs.
    refs = tuple(sorted(ref for ref in execution.evidence_refs + request.required_evidence_refs
                        if isinstance(registry.get(ref), EvidenceReference) and registry[ref].ref == ref
                        and registry[ref].endpoint_context_id == request.endpoint_context_id
                        and registry[ref].session_id == request.session_id))
    if not refs:
        raise ValueError(inspection.code)  # No evidence cannot satisfy the canonical result contract.
    timestamp = created_at or utc_now_iso()
    if _time(timestamp) < _time(execution.finished_at):
        if created_at is not None:
            raise ValueError('Validation predates execution')
        timestamp = execution.finished_at
    return DynamicValidationResult(
        test_id=request.test_id, endpoint_context_id=request.endpoint_context_id, session_id=request.session_id,
        outcome=inspection.outcome, evidence_refs=refs, reason_codes=(inspection.code,),
        criterion={'validated':'controlled_behavior_check','blocked':'policy_or_execution_blocked','inconclusive':'insufficient_evidence'}[inspection.outcome],
        coverage='available' if inspection.outcome == 'validated' else 'partial',
        created_at=timestamp)


def load_recorded_auth_presence_case(directory, baseline_directory):
    """Load canonical artifacts for offline revalidation, without modifying them."""
    directory, baseline_directory = Path(directory), Path(baseline_directory)
    read = lambda name: json.loads((directory/name).read_text())
    request = DynamicTestRequest.from_dict(read('test_request.json'))
    data = read('execution_result.json')
    execution_ref = data.pop('evidence_ref')
    execution = DynamicTestExecutionResult.from_dict(data)
    registry = {k:EvidenceReference(**v) for k,v in read('evidence_registry.json').items()}
    comparison = read('comparison.json')
    evidence = AuthPresenceEvidence(
        context=EndpointContext(**read('endpoint_context.json')), session=read('session_evidence.json'),
        baseline=read('baseline_transaction.json'), variant=read('variant_transaction.json'),
        baseline_receipts=json.loads((baseline_directory/'lab_receipts.json').read_text()),
        variant_receipts=read('lab_receipts.json'), execution_ref=execution_ref,
        control_ref=comparison.get('control_ref'), comparison_ref=comparison.get('comparison_ref'))
    source_traffic = json.loads((baseline_directory/'dynamic/traffic.json').read_text())
    source_contexts = json.loads((baseline_directory/'dynamic/endpoint_contexts.json').read_text())
    source_session = json.loads((baseline_directory/'dynamic/session.json').read_text())
    if (evidence.baseline not in source_traffic.get('transactions', [])
            or evidence.context.to_dict() not in source_contexts.get('endpoints', [])
            or evidence.session != source_session
            or source_traffic.get('session_id') != request.session_id
            or source_contexts.get('session_id') != request.session_id):
        raise ValueError('REFERENCE_MISMATCH')
    return request, execution, registry, evidence
