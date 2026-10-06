"""Deterministic dispatch with opt-in, one-shot local training backends.

All other actions remain unavailable. No general replay or payload executor.
"""
from collections.abc import Mapping
from typing import Callable

from src.dynamic.context.models import EndpointContext
from src.dynamic.runtime.models import utc_now_iso
from src.dynamic.security.contracts import (
    ACTIONS, DynamicTestRequest, DynamicTestExecutionResult, EvidenceReference,
    UnsupportedRequestRouting, _time, check_request_safety, validate_execution,
)


class DeterministicSecurityExecutor:
    """Safety gate precedes every dispatch, including the local lab backend."""

    def __init__(self, *, clock: Callable[[], str] = utc_now_iso, auth_backend=None, object_backend=None, function_backend=None, session_backend=None):
        from src.dynamic.security.authentication_presence import LocalLabAuthenticationPresence
        if auth_backend is not None and type(auth_backend) is not LocalLabAuthenticationPresence:
            raise ValueError('Unsupported security backend')
        from src.dynamic.security.object_authorization import LocalLabObjectAuthorization
        if object_backend is not None and type(object_backend) is not LocalLabObjectAuthorization:
            raise ValueError('Unsupported security backend')
        from src.dynamic.security.function_authorization import LocalLabFunctionAuthorization
        if function_backend is not None and type(function_backend) is not LocalLabFunctionAuthorization:
            raise ValueError('Unsupported security backend')
        from src.dynamic.security.session_invalidation import LocalLabSessionInvalidation
        if session_backend is not None and type(session_backend) is not LocalLabSessionInvalidation:
            raise ValueError('Unsupported security backend')
        self._session_backend = session_backend
        self._function_backend = function_backend
        self._object_backend = object_backend
        self._auth_backend = auth_backend
        self._clock = clock
        self._handlers = {action: self._backend_unavailable
                          for actions in ACTIONS.values() for action in actions}

    def execute(self, request: DynamicTestRequest | Mapping, context: EndpointContext,
                evidence: Mapping[str, EvidenceReference], *, session_id: str | None = None
                ) -> DynamicTestExecutionResult:
        """Reject malformed/missing evidence; return explicit blocked routing/risk.

        session_id is the executing session, independently supplied by the
        caller. A session-scoped request requires an exact owner match.
        Neither the request nor the caller's registry is mutated.
        """
        if not isinstance(evidence, Mapping):
            raise ValueError('Evidence registry must be a mapping')
        routing_error = None
        try:
            if isinstance(request, DynamicTestRequest):
                # Revalidate typed objects at the boundary as well as serialized inputs.
                request = DynamicTestRequest.from_dict(request.to_dict())
            elif isinstance(request, Mapping):
                request = DynamicTestRequest.from_dict(dict(request))
            else:
                raise ValueError('Expected DynamicTestRequest or contract object')
        except UnsupportedRequestRouting as exc:
            request, routing_error = exc.request, exc.reason
            # This envelope may only be rejected, never forwarded to dispatch.

        if request.session_id is not None and request.session_id != session_id:
            raise ValueError('Executing session does not own this request')
        if request.session_id is None and session_id is not None:
            raise ValueError('Session-scoped execution requires a scoped request')
        decision = check_request_safety(request, context, evidence, controlled_object_lab=self._object_backend, controlled_function_lab=self._function_backend, controlled_session_lab=self._session_backend)
        started = self._clock()
        _time(started)
        if decision['decision'] == 'blocked':
            return self._result(request, evidence, started, 'blocked', decision['reason'] if decision['reason'] in {'controlled_object_lab_evidence_required','controlled_function_lab_evidence_required','controlled_session_lab_evidence_required'} else 'risk_not_automatically_executable')
        if routing_error:
            return self._result(request, evidence, started, 'blocked', routing_error)
        if request.test_category == 'object_authorization':
            if self._object_backend is None or not self._object_backend.eligible(request, context, evidence):
                return self._result(request, evidence, started, 'blocked', 'controlled_object_lab_evidence_required')
        try:
            if self._session_backend is not None and request.test_category=='session_handling':
                return self._session_backend.run(request,context,evidence,started,self._clock)
            if self._function_backend is not None and request.test_category == 'function_authorization':
                return self._function_backend.run(request,context,evidence,started,self._clock)
            if self._object_backend is not None and request.test_category == 'object_authorization':
                return self._object_backend.run(request, context, evidence, started, self._clock)
            if self._auth_backend is not None and request.test_category == 'authentication_presence':
                return self._auth_backend.run(request, context, evidence, started, self._clock)
            output = self._dispatch(request)
            # No D9 handler is capable of producing observation evidence. Even
            # a fabricated "completed" result cannot be accepted as success.
            if output is not None:
                return self._result(request, evidence, started, 'failed', 'unexpected_backend_output')
            return self._result(request, evidence, started, 'unavailable', 'security_backend_unavailable')
        except TimeoutError:
            return self._result(request, evidence, started, 'failed', 'execution_timeout')
        except (InterruptedError, KeyboardInterrupt):
            return self._result(request, evidence, started, 'interrupted', 'execution_interrupted')
        except Exception:
            # Never persist arbitrary provider exceptions or manufacture evidence.
            return self._result(request, evidence, started, 'failed', 'execution_failed')

    def validation_evidence(self, request, context, registry, execution):
        """Return proof, never a backend's validation claim or Agent evidence."""
        from src.dynamic.security.validation import AuthPresenceEvidence
        from src.dynamic.security.object_authorization import ObjectAuthorizationEvidence
        from src.dynamic.security.function_authorization import FunctionAuthorizationEvidence
        from src.dynamic.security.session_invalidation import SessionInvalidationEvidence
        backend = {'authentication_presence':self._auth_backend,
                   'object_authorization':self._object_backend,
                   'function_authorization':self._function_backend,
                   'session_handling':self._session_backend}.get(request.test_category)
        if execution.execution_status == 'completed' and backend is not None:
            proof = backend.validation_evidence() if request.test_category == 'authentication_presence' else backend.bundle
            if proof is None:
                raise ValueError('Execution evidence unavailable')
            return backend.evidence, proof
        # No replacement transaction is fabricated for blocked/failed execution.
        args = dict(context=context, session={'session_id':request.session_id}, baseline=None,
                    variant=None, baseline_receipts=[], variant_receipts=[], execution_ref='',
                    control_ref='', comparison_ref='')
        if request.test_category == 'session_handling':
            proof = SessionInvalidationEvidence(**args, lifecycle={}, logout=None, logout_receipts=[])
        elif request.test_category == 'object_authorization':
            proof = ObjectAuthorizationEvidence(**args, ownership={})
        elif request.test_category == 'function_authorization':
            proof = FunctionAuthorizationEvidence(**args, privileges={})
        else:
            proof = AuthPresenceEvidence(**args)
        return registry, proof

    def _dispatch(self, request):
        handler = self._handlers.get(request.requested_action)
        if handler is None:
            raise ValueError('No handler for abstract action')
        return handler(request)

    @staticmethod
    def _backend_unavailable(request):
        return None  # Deliberate absence of all live security-test implementations.

    def _result(self, request, evidence, started, status, reason):
        finished = self._clock()
        # Wall clock adjustment cannot invert the execution interval.
        if _time(finished) < _time(started):
            finished = started
        result = DynamicTestExecutionResult(
            test_id=request.test_id, endpoint_context_id=request.endpoint_context_id,
            session_id=request.session_id, execution_status=status,
            observed_request_ref=None, observed_response_ref=None,
            evidence_refs=(), tool_refs=(), started_at=started, finished_at=finished,
            failure_reason=reason,
        )
        validate_execution(request, result, evidence)
        return result
