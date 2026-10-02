"""Deterministic dispatch with an opt-in, one-shot local auth-presence backend.

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

    def __init__(self, *, clock: Callable[[], str] = utc_now_iso, auth_backend=None):
        from src.dynamic.security.authentication_presence import LocalLabAuthenticationPresence
        if auth_backend is not None and type(auth_backend) is not LocalLabAuthenticationPresence:
            raise ValueError('Unsupported security backend')
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
        decision = check_request_safety(request, context, evidence)
        started = self._clock()
        _time(started)
        if decision['decision'] == 'blocked':
            return self._result(request, evidence, started, 'blocked', 'risk_not_automatically_executable')
        if routing_error:
            return self._result(request, evidence, started, 'blocked', routing_error)
        try:
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
