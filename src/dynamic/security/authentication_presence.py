"""One-shot auth removal for the explicitly bound local D10 lab only.

This is not a general replay transport. Stored redacted credentials are never
reconstructed. Historical baseline comparison is explicit; no finding is emitted.
"""
from copy import deepcopy
from http.client import HTTPConnection
from http.server import HTTPServer
import hashlib
import ipaddress
import json
import uuid

from src.dynamic.runtime.models import utc_now_iso
from src.dynamic.security.contracts import (
    DynamicTestExecutionResult, DynamicValidationResult, EvidenceReference,
    _verify_refs, validate_execution, validate_result,
)
from src.dynamic.traffic.normalizer import normalize_http_transaction, sanitize_transaction_data


def auth_removal_variant(baseline, *, evidence_only=False):
    """Only Authorization is supported in V1; ambiguous cookies fail closed."""
    request = deepcopy(baseline['request'])
    if request.get('method') != 'GET' or request.get('path') != '/profile' or request.get('scheme') != 'http' or request.get('port') != 18081:
        raise ValueError('Only the local read-only lab profile is supported')
    if request.get('query') or request.get('body') is not None:
        raise ValueError('No query/body reconstruction is supported')
    headers = request.get('headers', {})
    if len({k.lower() for k in headers}) != len(headers):
        raise ValueError('Ambiguous header names')
    auth = [k for k in headers if k.lower() == 'authorization']
    if len(auth) != 1 or not headers[auth[0]] or any(k.lower() in {'cookie', 'proxy-authorization', 'x-api-key', 'x-auth-token', 'x-access-token'} for k in headers):
        raise ValueError('Single observed Authorization baseline required')
    del headers[auth[0]]
    if any((not evidence_only and '[REDACTED]' in str(v)) or '\r' in str(v) or '\n' in str(v) for v in headers.values()):
        raise ValueError('Unreconstructable or invalid remaining headers')
    return request


class LocalLabAuthenticationPresence:
    """Opt-in backend scoped to an already bound local fixture, one send maximum.

    Receipts originate from the local HTTP handler, not model or tool text.
    The caller must validate canonical baseline artifacts before constructing it.
    """
    def __init__(self, *, server, receipts, baseline, context, session_id, baseline_receipts=None, session_evidence=None):
        if not isinstance(server, HTTPServer):
            raise ValueError('A bound local lab server is required')
        host, port = server.server_address[:2]
        address = ipaddress.ip_address(host)
        if not (address.is_private or address.is_loopback) or address.is_unspecified or port != 18081:
            raise ValueError('Local lab on port 18081 required')
        self.variant_request = auth_removal_variant(baseline)
        req, resp = baseline['request'], baseline.get('response')
        if any(item.get('synthetic') or item.get('internal') for item in (baseline, req, resp or {})):
            raise ValueError('Synthetic baseline excluded')
        if (context.host, context.port, context.scheme, context.path, context.methods) != (host, port, 'http', '/profile', ['GET']):
            raise ValueError('Local bound server/context mismatch')
        if req.get('host') != host or req['headers'].get('host') != f'{host}:{port}':
            raise ValueError('Baseline authority mismatch')
        if baseline.get('session_id') != session_id or req['headers'].get('x-lab-run-id') != session_id:
            raise ValueError('Baseline session ownership mismatch')
        if not context.dynamic.get('observed') or not context.auth.get('authorization_header_present') or baseline['transaction_id'] not in context.evidence_refs.get('transaction_ids', []):
            raise ValueError('Canonical authenticated evidence missing')
        if not resp or resp.get('status_code') != 200 or resp.get('body', {}).get('authenticated') is not True or resp.get('body', {}).get('purpose') != 'read_only_training_profile' or not resp.get('headers', {}).get('x-lab-trace-id'):
            raise ValueError('Authenticated lab baseline response missing')
        self._context = deepcopy(context)
        self._session = deepcopy(session_evidence or {'session_id': session_id})
        self._baseline_receipts = deepcopy(baseline_receipts or [])
        self.host, self.port = host, port
        self.context_id, self.session_id = context.endpoint_context_id, session_id
        self.baseline = deepcopy(baseline)
        self.receipts = receipts
        self.used = False
        self.transaction = None
        self.evidence = {}
        self.comparison = None
        self.execution_ref = None

    def run(self, request, context, evidence, started, clock=utc_now_iso):
        if self.used:
            raise ValueError('One controlled variant maximum')
        if request.risk_class != 'low' or request.test_category != 'authentication_presence' or request.requested_action not in {'validate_authentication_presence', 'compare_authenticated_baseline_behavior'}:
            raise ValueError('Only low-risk authentication presence is supported')
        if self.variant_request != auth_removal_variant(self.baseline):
            raise ValueError('Variant changed after deterministic auth removal')
        if (context.host, context.port, context.scheme, context.path, context.methods) != (self.host, self.port, 'http', '/profile', ['GET']):
            raise ValueError('Endpoint scope changed before dispatch')
        if request.endpoint_context_id != self.context_id or context.endpoint_context_id != self.context_id or request.session_id != self.session_id:
            raise ValueError('Backend scope mismatch')
        baseline_req = self.baseline['request']['request_id']
        baseline_resp = self.baseline['response']['headers']['x-lab-trace-id']
        required = {baseline_req: 'request', baseline_resp: 'response', self.context_id: 'context', self.session_id: 'runtime'}
        if not set(required).issubset(request.required_evidence_refs):
            raise ValueError('Required baseline references missing')
        _verify_refs(tuple(required), self.context_id, self.session_id, evidence)
        if any(evidence[ref].kind != kind for ref, kind in required.items()):
            raise ValueError('Baseline reference kind mismatch')
        self.used = True  # Consumed before transport; never retry failures.
        connection = HTTPConnection(self.host, self.port, timeout=3)
        try:
            # putrequest avoids automatically adding/changing baseline headers.
            connection.putrequest('GET', '/profile', skip_host=True, skip_accept_encoding=True)
            for name, value in self.variant_request['headers'].items():
                connection.putheader(name, value)
            connection.endheaders()
            response = connection.getresponse()  # No redirect following or retries.
            body = response.read(4097)
            if len(body) > 4096:
                raise ValueError('Response exceeds lab bound')
            raw_response = {'status_code': response.status, 'headers': dict(response.getheaders()), 'body': body, 'timestamp': clock()}
        finally:
            connection.close()
        raw_request = {**self.variant_request, 'timestamp': started}
        self.transaction = normalize_http_transaction(raw_request, raw_response, 'capture_'+uuid.uuid4().hex, self.session_id, scope='IN_SCOPE')
        self.transaction.attribution = {'method': 'deterministic_local_executor', 'baseline_transaction_ref': self.baseline['transaction_id'], 'historical_baseline': True}
        tx = sanitize_transaction_data(self.transaction.to_dict())
        trace = tx['response']['headers'].get('x-lab-trace-id')
        receipts = [r for r in self.receipts if r.get('trace_id') == trace and r.get('run_id') == self.session_id and r.get('method') == 'GET' and r.get('path') == '/profile' and r.get('status') == tx['response']['status_code'] and r.get('auth_present') is False and r.get('source') == 'local_training_backend_actual_response']
        if len(receipts) != 1:
            raise ValueError('Real local upstream receipt missing')
        digest = hashlib.sha256(json.dumps([request.test_id, self.context_id, self.session_id, baseline_req]).encode()).hexdigest()[:20]
        self.execution_ref = 'execution_'+digest
        control_ref, comparison_ref = 'control_'+digest, 'comparison_'+digest
        self.evidence = dict(evidence)
        for ref, kind in [(tx['request']['request_id'], 'request'), (trace, 'response'), (self.execution_ref, 'tool'), (control_ref, 'control'), (comparison_ref, 'comparison')]:
            if ref in self.evidence:
                raise ValueError('Evidence identity collision')
            self.evidence[ref] = EvidenceReference(ref, self.context_id, kind, self.session_id)
        denied = tx['response']['status_code'] == 401 and tx['response']['body'] == {'error': 'authentication_required'}
        self.comparison = {
            'control_ref': control_ref, 'comparison_ref': comparison_ref,
            'baseline_request_ref': baseline_req, 'baseline_response_ref': baseline_resp,
            'variant_request_ref': tx['request']['request_id'], 'variant_response_ref': trace,
            'baseline_status': 200, 'variant_status': tx['response']['status_code'],
            'baseline_response_keys': sorted(self.baseline['response']['body']),
            'variant_response_keys': sorted(tx['response']['body']) if isinstance(tx['response']['body'], dict) else [],
            'auth_removed': True, 'method_path_query_body_unchanged': True,
            'historical_baseline': True, 'fixture_restarted': True,
            'authenticated_session_currently_reverified': False,
            'expected_auth_enforcement_observed': denied,
            'finding_generated': False, 'status_200_alone_sufficient': False,
        }
        refs = tuple(required) + (tx['request']['request_id'], trace, self.execution_ref, control_ref, comparison_ref)
        execution = DynamicTestExecutionResult(
            test_id=request.test_id, endpoint_context_id=self.context_id, session_id=self.session_id,
            execution_status='completed', observed_request_ref=tx['request']['request_id'], observed_response_ref=trace,
            evidence_refs=refs, tool_refs=(self.execution_ref,), started_at=started, finished_at=clock())
        validate_execution(request, execution, self.evidence)
        return execution

    def validate(self, request, execution):
        if not self.comparison or execution.execution_status != 'completed' or self.execution_ref not in execution.tool_refs:
            raise ValueError('This execution has no verified comparison')
        from src.dynamic.security.validation import validate_authentication_presence
        evidence = self.validation_evidence()
        result = validate_authentication_presence(request, execution, self.evidence, evidence)
        if result.outcome == 'validated':
            validate_result(request, execution, result, self.evidence, auth_evidence=evidence)
        return result

    def validation_evidence(self):
        """Expose sanitized canonical proof for independent validator invocation."""
        from src.dynamic.security.validation import AuthPresenceEvidence
        evidence = AuthPresenceEvidence(
            context=self._context, session=self._session, baseline=self.baseline,
            variant=self.transaction.to_dict() if self.transaction else None,
            baseline_receipts=self._baseline_receipts, variant_receipts=self.receipts,
            execution_ref=self.execution_ref, control_ref=self.comparison.get('control_ref'),
            comparison_ref=self.comparison.get('comparison_ref'))
        from src.dynamic.security.auth_evidence_contract import adapt_auth_presence_evidence
        return adapt_auth_presence_evidence(evidence)
