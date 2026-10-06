"""Local-only Ollama adapter for the existing AgentModelClient protocol.

No automatic model download, provider fallback, tool channel or response logging.
Runtime validators retain ownership of JSON/schema validation and bounded retries.
"""
from __future__ import annotations

import json
import math
import os
import re
import socket
from time import monotonic
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .model_client import ModelMetadata, ModelReply, ModelRequest, ProviderAvailability

MAX_RESPONSE_BYTES = 262_144
MAX_REQUEST_BYTES = 1_048_576


class OllamaClientError(RuntimeError):
    """Stable safe error codes; never echo server bodies, requests or credentials."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result


def _grammar_schema(value):
    """Ollama grammar cannot compile very large bounded string repetitions.

    Leave those length bounds to the unchanged runtime validator. The canonical
    schema remains unchanged on ModelRequest; do not mutate it.
    """
    if isinstance(value, dict):
        return {key: _grammar_schema(child) for key, child in value.items()
                if not (key == "maxLength" and type(child) is int and child > 256)}
    if isinstance(value, list):
        return [_grammar_schema(child) for child in value]
    return value


def _schema_structure(value):
    """Omit repeated enums from Analyst prose, not from enforced grammar.

    The sanitized fact/hypothesis/role/reference/gap catalogs already enumerate
    these values. Keep field structure, constants, bounds and required fields.
    """
    if isinstance(value, dict):
        return {key: _schema_structure(child) for key, child in value.items() if key != "enum"}
    if isinstance(value, list):
        return [_schema_structure(child) for child in value]
    return value


class OllamaModelClient:
    def __init__(self, *, base_url="http://127.0.0.1:11434", model="qwen2.5:7b", timeout=120):
        try:
            url = urlsplit(base_url)
            if (url.scheme not in {"http", "https"} or url.hostname not in {"localhost", "127.0.0.1", "::1"}
                    or url.username is not None or url.password is not None or url.query or url.fragment
                    or url.path not in {"", "/"} or url.port == 0):
                raise ValueError()
            if not isinstance(model, str) or not re.fullmatch(r"[a-z][a-z0-9_.:-]{0,63}", model):
                raise ValueError()
            if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 1 <= timeout <= 300:
                raise ValueError()
        except (TypeError, ValueError, AttributeError):
            raise OllamaClientError("CONFIG_INVALID") from None
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.last_generation_metrics = {}
        # Do not route local evidence through environment proxies or redirects.
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    @property
    def identity(self):
        return ModelMetadata(provider="local", model=self.model)

    def check_availability(self):
        """Inspect installed models only; never load/download/generate a model."""
        try:
            raw = self._request_bytes(Request(self.base_url + "/api/tags", method="GET"),
                                      min(3.0, self.timeout))
            body = json.loads(raw, object_pairs_hook=_unique_object)
            models = body.get('models') if isinstance(body, dict) else None
            if not isinstance(models, list) or any(not isinstance(m, dict) or
                    not isinstance(m.get('name'), str) for m in models):
                raise OllamaClientError('MALFORMED_RESPONSE')
            found = any(m['name'] == self.model for m in models)
            return ProviderAvailability(found, 'AVAILABLE' if found else 'MODEL_UNAVAILABLE', self.identity)
        except OllamaClientError as exc:
            reason = 'PROVIDER_UNAVAILABLE' if exc.code in {'CONNECTION_ERROR', 'HTTP_ERROR', 'MODEL_UNAVAILABLE'} else exc.code
            return ProviderAvailability(False, reason, self.identity)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return ProviderAvailability(False, 'MALFORMED_RESPONSE', self.identity)

    def _request_bytes(self, request, timeout):
        started = monotonic()
        try:
            with self._opener.open(request, timeout=timeout) as response:
                chunks = []
                size = 0
                while True:
                    remaining = timeout - (monotonic() - started)
                    if remaining <= 0:
                        raise OllamaClientError('TIMEOUT')
                    # HTTPResponse.read1 performs at most one underlying read.
                    # Keep each subsequent read inside the remaining budget.
                    sock = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
                    if isinstance(sock, socket.SocketType):
                        sock.settimeout(remaining)
                    chunk = response.read1(min(16384, MAX_RESPONSE_BYTES + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk); size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise OllamaClientError('RESPONSE_TOO_LARGE')
                raw = b''.join(chunks)
                if not raw.strip():
                    raise OllamaClientError('EMPTY_RESPONSE')
                return raw
        except HTTPError as exc:
            raise OllamaClientError('MODEL_UNAVAILABLE' if exc.code == 404 else 'HTTP_ERROR') from None
        except (TimeoutError, socket.timeout):
            raise OllamaClientError('TIMEOUT') from None
        except URLError as exc:
            raise OllamaClientError('TIMEOUT' if isinstance(exc.reason, (TimeoutError, socket.timeout)) else 'CONNECTION_ERROR') from None
        except OSError:
            raise OllamaClientError('CONNECTION_ERROR') from None

    @classmethod
    def from_env(cls):
        try:
            timeout = float(os.environ.get("MOBIATTACK_OLLAMA_TIMEOUT", "120"))
        except ValueError:
            raise OllamaClientError("CONFIG_INVALID") from None
        return cls(base_url=os.environ.get("MOBIATTACK_OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
                   model=os.environ.get("MOBIATTACK_OLLAMA_MODEL", "qwen2.5:7b"), timeout=timeout)

    def generate(self, request: ModelRequest) -> ModelReply:
        self.last_generation_metrics = {}
        if not isinstance(request, ModelRequest):
            raise OllamaClientError("REQUEST_INVALID")
        try:
            payload = self._payload(request)
        except (ValueError, TypeError, RecursionError):
            raise OllamaClientError("REQUEST_INVALID") from None
        if len(payload) > MAX_REQUEST_BYTES:
            raise OllamaClientError("REQUEST_TOO_LARGE")
        return self._generate(payload)

    def _payload(self, request):
        compact_analyst = (request.prompt_version == "context_analyst_v1"
                           and "fact_catalog" in request.input_data)
        schema = _schema_structure(request.output_schema) if compact_analyst else request.output_schema
        messages = [{"role": "system", "content": request.instruction},
                    {"role": "user", "content": json.dumps({"input": request.input_data, "output_schema": schema},
                                                            sort_keys=True, allow_nan=False,
                                                            **({"separators": (",", ":")} if compact_analyst else {}))}]
        if request.correction:
            messages.append({"role": "user", "content": request.correction})
        return json.dumps({"model": self.model, "messages": messages, "stream": False,
                              "think": False, "format": _grammar_schema(request.output_schema),
                              "options": {"temperature": 0, "seed": 0, "num_ctx": 16384, "num_predict": 4096}},
                             allow_nan=False).encode("utf-8")

    def _generate(self, payload):
        http_request = Request(self.base_url + "/api/chat", data=payload,
                               headers={"Content-Type": "application/json"}, method="POST")
        started = monotonic()
        raw = self._request_bytes(http_request, self.timeout)
        try:
            body = json.loads(raw, object_pairs_hook=_unique_object)
            if not isinstance(body, dict):
                raise ValueError()
            if "error" in body:
                raise OllamaClientError("PROVIDER_ERROR")
            message = body.get("message")
            if isinstance(message, dict) and isinstance(message.get('content'), str) and not message['content'].strip():
                raise OllamaClientError('EMPTY_RESPONSE')
            if (body.get("done") is not True or not isinstance(message, dict)
                    or message.get("role") != "assistant" or not isinstance(message.get("content"), str)
                    or not message["content"].strip() or message.get("tool_calls")):
                raise ValueError()
            if body.get("done_reason") == "length":
                raise OllamaClientError("OUTPUT_TRUNCATED")
            if body.get("model") != self.model:
                raise OllamaClientError("MODEL_MISMATCH")
            # Deliberately ignore message.thinking and all other server extras.
            duration = body.get("total_duration")
            if duration is not None and (type(duration) is not int or duration < 0):
                raise ValueError()
            metadata = ModelMetadata(provider="local", model=self.model,
                                     latency_ms=duration / 1_000_000 if duration is not None else (monotonic() - started) * 1000,
                                     input_tokens=body.get("prompt_eval_count"), output_tokens=body.get("eval_count"))
            # Numeric performance telemetry only; never response/thinking data.
            self.last_generation_metrics = {
                key: body[key] for key in ("load_duration", "prompt_eval_duration", "eval_duration",
                                          "total_duration", "prompt_eval_count", "eval_count")
                if type(body.get(key)) is int and body[key] >= 0
            }
            # Returning JSON text allows existing validators to classify invalid
            # output and retry; this adapter never repairs/fabricates a response.
            return ModelReply(data=message["content"], metadata=metadata)
        except OllamaClientError:
            raise
        except (TypeError, ValueError, KeyError, UnicodeError, RecursionError, OverflowError):
            raise OllamaClientError("MALFORMED_RESPONSE") from None
