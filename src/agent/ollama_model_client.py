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

from .model_client import ModelMetadata, ModelReply, ModelRequest

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
    schema is still supplied verbatim in the user message; do not mutate it.
    """
    if isinstance(value, dict):
        return {key: _grammar_schema(child) for key, child in value.items()
                if not (key == "maxLength" and type(child) is int and child > 256)}
    if isinstance(value, list):
        return [_grammar_schema(child) for child in value]
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
        # Do not route local evidence through environment proxies or redirects.
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    @classmethod
    def from_env(cls):
        try:
            timeout = float(os.environ.get("MOBIATTACK_OLLAMA_TIMEOUT", "120"))
        except ValueError:
            raise OllamaClientError("CONFIG_INVALID") from None
        return cls(base_url=os.environ.get("MOBIATTACK_OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
                   model=os.environ.get("MOBIATTACK_OLLAMA_MODEL", "qwen2.5:7b"), timeout=timeout)

    def generate(self, request: ModelRequest) -> ModelReply:
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
        messages = [{"role": "system", "content": request.instruction},
                    {"role": "user", "content": json.dumps({"input": request.input_data, "output_schema": request.output_schema},
                                                            sort_keys=True, allow_nan=False)}]
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
        try:
            with self._opener.open(http_request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as exc:
            code = "MODEL_UNAVAILABLE" if exc.code == 404 else "HTTP_ERROR"
            raise OllamaClientError(code) from None
        except (TimeoutError, socket.timeout):
            raise OllamaClientError("TIMEOUT") from None
        except URLError as exc:
            code = "TIMEOUT" if isinstance(exc.reason, (TimeoutError, socket.timeout)) else "CONNECTION_ERROR"
            raise OllamaClientError(code) from None
        except OSError:
            raise OllamaClientError("CONNECTION_ERROR") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise OllamaClientError("RESPONSE_TOO_LARGE")
        try:
            body = json.loads(raw, object_pairs_hook=_unique_object)
            if not isinstance(body, dict):
                raise ValueError()
            if "error" in body:
                raise OllamaClientError("PROVIDER_ERROR")
            message = body.get("message")
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
            # Returning JSON text allows existing validators to classify invalid
            # output and retry; this adapter never repairs/fabricates a response.
            return ModelReply(data=message["content"], metadata=metadata)
        except OllamaClientError:
            raise
        except (TypeError, ValueError, KeyError, UnicodeError, RecursionError, OverflowError):
            raise OllamaClientError("MALFORMED_RESPONSE") from None
