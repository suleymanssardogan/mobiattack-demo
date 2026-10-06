"""Bounded in-process execution claims and safe provider failure classification."""
from threading import Lock
from weakref import WeakKeyDictionary


class ExecutionGuard:
    """Claim before dispatch; uncertainty never releases a claim for retry.

    This is process-local protection. Existing lab/backend guards still own their
    one-shot lifecycle checks; durable recovery needs a separate persisted ledger.
    """
    def __init__(self, max_claims=256):
        self._claims = set()
        self._lock = Lock()
        self._max_claims = max_claims

    def claim(self, request):
        key = (request.session_id, request.endpoint_context_id, request.test_category)
        with self._lock:
            if key in self._claims:
                return 'DUPLICATE_EXECUTION_BLOCKED'
            if len(self._claims) >= self._max_claims:
                return 'EXECUTION_GUARD_EXHAUSTED'
            self._claims.add(key)
        return None


_GUARDS = WeakKeyDictionary()
_GUARD_LOCK = Lock()


def guard_for(executor):
    with _GUARD_LOCK:
        if executor not in _GUARDS:
            _GUARDS[executor] = ExecutionGuard()
        return _GUARDS[executor]


class FailureAwareClient:
    """No retries/threads here: existing role runtimes own their bounded retry."""
    def __init__(self, client):
        self.client = client
        self.failure = None
        self._availability_checked = False

    @property
    def identity(self):
        from src.agent.model_client import model_identity
        return model_identity(self.client)

    def generate(self, request):
        if self.failure:
            raise RuntimeError('Agent provider stage already stopped')
        try:
            from src.agent.model_client import ProviderAvailability, ModelReply
            probe = getattr(self.client, 'check_availability', None)
            if not self._availability_checked and callable(probe):
                self._availability_checked = True
                availability = probe()
                if not isinstance(availability, ProviderAvailability):
                    self.failure = 'MALFORMED_RESPONSE'
                    raise RuntimeError('Provider availability invalid')
                if not availability.available:
                    self.failure = availability.reason_code if availability.reason_code in {
                        'TIMEOUT', 'MODEL_UNAVAILABLE', 'PROVIDER_UNAVAILABLE', 'MALFORMED_RESPONSE',
                        'EMPTY_RESPONSE', 'RESPONSE_TOO_LARGE'} else 'PROVIDER_UNAVAILABLE'
                    raise RuntimeError('Provider unavailable')
            reply = self.client.generate(request)
            if isinstance(reply, ModelReply) and (reply.data is None or isinstance(reply.data, str) and not reply.data.strip()):
                self.failure = 'EMPTY_RESPONSE'
                raise RuntimeError('Provider response empty')
            return reply
        except (KeyboardInterrupt, InterruptedError):
            self.failure = 'INTERRUPTED'
            raise RuntimeError('Agent stage interrupted') from None
        except TimeoutError:
            self.failure = 'TIMEOUT'
            raise RuntimeError('Agent model timeout') from None
        except Exception as exc:
            # Ollama uses a safe typed code. Never copy exception text into state.
            code = getattr(exc, 'code', None)
            self.failure = self.failure or (code if code in {'TIMEOUT', 'MODEL_UNAVAILABLE', 'MALFORMED_RESPONSE',
                'EMPTY_RESPONSE', 'OUTPUT_TRUNCATED', 'MODEL_MISMATCH', 'RESPONSE_TOO_LARGE', 'PROVIDER_ERROR'} else 'PROVIDER_UNAVAILABLE')
            raise RuntimeError('Agent provider unavailable') from None
