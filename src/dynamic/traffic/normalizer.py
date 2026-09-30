"""Traffic normalizer, sensitive data redaction, and body limit enforcement."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import parse_qs, urlparse

from src.dynamic.traffic.models import HttpRequestModel, HttpResponseModel, TrafficTransaction

MAX_CAPTURE_BODY_BYTES = 1_048_576  # 1 MB

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
}

SENSITIVE_PAYLOAD_KEYS = {
    "password",
    "passwd",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "authorization",
    "cookie",
    "credit_card",
    "cvv",
}


def sanitize_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Normalizes header keys to lowercase and redacts sensitive headers."""
    if not headers:
        return {}

    sanitized: dict[str, str] = {}
    for key, val in headers.items():
        lowered_key = str(key).strip().lower()
        if lowered_key in SENSITIVE_HEADERS:
            sanitized[lowered_key] = "[REDACTED]"
        else:
            sanitized[lowered_key] = str(val)
    return sanitized


def sanitize_body_payload(body: Any) -> Any:
    """Recursively redacts sensitive keys from JSON-parsed or dict body payload."""
    if isinstance(body, dict):
        sanitized_dict: dict[str, Any] = {}
        for key, val in body.items():
            lower_key = str(key).lower()
            # Do NOT redact if it is MobiAttack's internal correlation 'session_id' or 'transaction_id'
            if any(pat in lower_key for pat in SENSITIVE_PAYLOAD_KEYS):
                sanitized_dict[key] = "[REDACTED]"
            elif isinstance(val, (dict, list)):
                sanitized_dict[key] = sanitize_body_payload(val)
            else:
                sanitized_dict[key] = val
        return sanitized_dict
    elif isinstance(body, list):
        return [sanitize_body_payload(item) for item in body]
    return body


def process_body_content(
    raw_body: bytes | str | None,
    content_type: str | None,
) -> tuple[Any, dict[str, Any]]:
    """Enforces size limits, parses JSON or handles binary content safely."""
    if raw_body is None or raw_body == b"" or raw_body == "":
        return None, {"size": 0, "truncated": False, "binary": False}

    # Ensure bytes
    if isinstance(raw_body, str):
        body_bytes = raw_body.encode("utf-8", errors="replace")
    else:
        body_bytes = raw_body

    orig_size = len(body_bytes)
    body_meta: dict[str, Any] = {
        "size": orig_size,
        "truncated": False,
        "binary": False,
        "content_type": content_type or "application/octet-stream",
    }

    # Truncation check
    if orig_size > MAX_CAPTURE_BODY_BYTES:
        body_bytes = body_bytes[:MAX_CAPTURE_BODY_BYTES]
        body_meta["truncated"] = True
        body_meta["original_size"] = orig_size

    # Detect Binary vs Text / JSON
    ct = (content_type or "").lower()
    is_json = "json" in ct
    is_form = "x-www-form-urlencoded" in ct
    is_text = any(t in ct for t in ["text/", "xml", "html", "javascript"]) or is_json or is_form

    if not is_text and any(bin_type in ct for bin_type in ["image/", "audio/", "video/", "octet-stream", "zip", "pdf"]):
        body_meta["binary"] = True
        body_meta["sha256"] = hashlib.sha256(body_bytes).hexdigest()
        return None, body_meta

    # Try decode text
    try:
        decoded_text = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            decoded_text = body_bytes.decode("latin-1")
        except Exception:
            body_meta["binary"] = True
            body_meta["sha256"] = hashlib.sha256(body_bytes).hexdigest()
            return None, body_meta

    # Parse JSON if applicable
    if is_json or decoded_text.strip().startswith(("{", "[")):
        try:
            parsed = json.loads(decoded_text)
            sanitized = sanitize_body_payload(parsed)
            return sanitized, body_meta
        except Exception:
            pass

    # Parse urlencoded if applicable
    if is_form:
        try:
            parsed_qs = parse_qs(decoded_text, keep_blank_values=True)
            flat_qs = {k: v[0] if len(v) == 1 else v for k, v in parsed_qs.items()}
            return sanitize_body_payload(flat_qs), body_meta
        except Exception:
            pass

    return decoded_text, body_meta


def normalize_http_transaction(
    raw_req: dict[str, Any],
    raw_resp: dict[str, Any] | None,
    capture_id: str,
    session_id: str | None = None,
    duration_ms: float = 0.0,
    scope: str = "UNKNOWN",
) -> TrafficTransaction:
    """Creates a normalized TrafficTransaction with sanitized headers, parsed body, and query."""
    # Process Request
    req_headers = sanitize_headers(raw_req.get("headers"))
    req_ct = req_headers.get("content-type")
    req_body, req_body_meta = process_body_content(raw_req.get("body"), req_ct)

    url_str = raw_req.get("url", "")
    parsed_url = urlparse(url_str) if url_str else None

    scheme = raw_req.get("scheme") or (parsed_url.scheme if parsed_url else "http")
    host = raw_req.get("host") or (parsed_url.hostname if parsed_url else "")
    port = raw_req.get("port") or (parsed_url.port if parsed_url and parsed_url.port else (443 if scheme == "https" else 80))
    path = raw_req.get("path") or (parsed_url.path if parsed_url else "/")
    query = raw_req.get("query")
    if query is None and parsed_url and parsed_url.query:
        qs = parse_qs(parsed_url.query)
        query = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}

    request_model = HttpRequestModel(
        timestamp=raw_req.get("timestamp") or raw_req.get("time") or "",
        method=(raw_req.get("method") or "GET").upper(),
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=query or {},
        headers=req_headers,
        body=req_body,
        body_metadata=req_body_meta,
    )

    # Process Response
    response_model: HttpResponseModel | None = None
    if raw_resp:
        resp_headers = sanitize_headers(raw_resp.get("headers"))
        resp_ct = resp_headers.get("content-type")
        resp_body, resp_body_meta = process_body_content(raw_resp.get("body"), resp_ct)

        response_model = HttpResponseModel(
            status_code=int(raw_resp.get("status_code", 0)),
            headers=resp_headers,
            body=resp_body,
            timestamp=raw_resp.get("timestamp") or "",
            body_metadata=resp_body_meta,
        )

    return TrafficTransaction(
        capture_id=capture_id,
        session_id=session_id,
        request=request_model,
        response=response_model,
        duration_ms=round(duration_ms, 2),
        scope=scope,
    )
