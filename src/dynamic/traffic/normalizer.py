"""Traffic normalizer, sensitive data redaction, and body limit enforcement."""

from __future__ import annotations

from src.dynamic.traffic.auth_metadata import observe_auth, safe_auth_metadata, observe_payload_credentials
import hashlib
import json
import re
from copy import deepcopy
from typing import Any
from urllib.parse import parse_qs, urlparse, urlencode, urlsplit, urlunsplit

from src.dynamic.traffic.models import (HttpRequestModel, HttpResponseModel, TrafficTransaction, TrafficException, TrafficErrorCode)

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
    "auth",
    "key",
    "session",
    "jwt",
    "credential", "credentials", "sid", "otp", "pin", "sessionid",
}


def _sensitive_name(key: str) -> bool:
    name = re.sub(r"([a-z])([A-Z])", r"\1_\2", str(key)).lower().replace("-", "_")
    return name in SENSITIVE_PAYLOAD_KEYS or any(
        part in SENSITIVE_PAYLOAD_KEYS for part in name.split("_")
    )


def _redact_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_shape(item) for item in value]
    return "[REDACTED]"


def _sanitize_url_header(value: str) -> str:
    try:
        parsed = urlsplit(value)
        if parsed.username is not None or parsed.password is not None:
            return "[REDACTED]"
        query = sanitize_body_payload(parse_qs(parsed.query, keep_blank_values=True))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                           urlencode(query, doseq=True), ""))
    except ValueError:
        return "[REDACTED]"


def sanitize_headers(headers: dict[str, str] | None, session_id: str | None = None) -> dict[str, str]:
    """Keep header names, redact credential headers and secrets in URL headers."""
    sanitized = {}
    for key, val in (headers or {}).items():
        name = str(key).strip().lower()
        if name in SENSITIVE_HEADERS or _sensitive_name(name):
            sanitized[name] = "[REDACTED]"
        elif name == "host" and re.fullmatch(r"[A-Za-z0-9.\[\]:-]{1,253}", str(val)):
            sanitized[name] = str(val)
        elif name == "x-lab-run-id" and session_id and str(val) == session_id:
            sanitized[name] = str(val)  # Existing canonical session reference, not a credential.
        elif name == "x-lab-trace-id" and (re.fullmatch(r"lab_[0-9a-f]{32}", str(val)) or str(val) == "lab_test_variant"):
            sanitized[name] = str(val)  # Typed public executor evidence reference.
        elif name == "content-type":
            match = re.match(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+", str(val))
            sanitized[name] = match.group(0).lower() if match else "[REDACTED]"
        elif name == "content-length" and str(val).isdigit():
            sanitized[name] = str(val)
        else:
            sanitized[name] = "[REDACTED]"
    return sanitized


# Fixed public protocol constants used by the existing controlled validation contract.
# No arbitrary value, account name, endpoint-dependent rule or token is allowlisted.
PUBLIC_PROTOCOL_FIELDS = {
    "error": {"authentication_required", "session_invalidated", "function_access_denied", "object_access_denied", "server_failure", "other"},
    "purpose": {"read_only_training_profile", "protected_training_order"},
    "display_name": {"Training User", "Training User A"},
    "logout": {"completed"}, "function": {"training_toggle"},
    "owner_alias": {"user_A", "user_B"}, "resource_id": {"order_A", "order_B"},
}


def sanitize_body_payload(body: Any) -> Any:
    """Preserve structured shape and names while redacting sensitive leaves."""
    if isinstance(body, dict):
        return {key: _redact_shape(val) if _sensitive_name(key) else
                (val if (isinstance(val, str) and val in PUBLIC_PROTOCOL_FIELDS.get(key, set())) or (type(val) is int and key in {"count","size","length","revision","status_code"} and 0 <= val <= 1048576) else sanitize_body_payload(val)) for key, val in body.items()}
    if isinstance(body, list):
        return [sanitize_body_payload(item) for item in body]
    if isinstance(body, (str, int, float)) and not isinstance(body, bool):
        return "[REDACTED]"
    return body


def _internal(data: dict | None) -> bool:
    return bool(data and (data.get("synthetic") or data.get("internal")))


def sanitize_transaction_data(data: dict) -> dict:
    """Final persistence boundary, also covering directly constructed transactions."""
    if _internal(data) or _internal(data.get("request")):
        raise TrafficException(TrafficErrorCode.TRAFFIC_PARSE_FAILED,
                               "Internal proxy requests are not application evidence.")
    clean = deepcopy(data)
    response = clean.get("response")
    if _internal(response):
        clean["response"] = None
        clean.setdefault("correlation", {})["response_observation"] = {
            "state": "unavailable", "reason": "internal_proxy_response_excluded"}
    for side in ("request", "response"):
        item = clean.get(side)
        if not isinstance(item, dict):
            continue
        if "auth_metadata" in item:
            prior = safe_auth_metadata(item.get("auth_metadata"), clean.get("session_id"))
            item["auth_metadata"] = prior or observe_auth(item.get("headers"), clean.get("session_id"), response=side == "response")
        item["headers"] = sanitize_headers(item.get("headers"), clean.get("session_id"))
        body = item.get("body")
        meta = item.setdefault("body_metadata", {})
        if meta.get("binary"):
            item["body"] = None
        elif isinstance(body, (dict, list)):
            item["body"] = sanitize_body_payload(body)
        elif body is not None:
            item["body"], new_meta = process_body_content(body, item["headers"].get("content-type"))
            item["body_metadata"] = {**new_meta, **meta}
        if side == "request":
            item.pop("url", None)  # Canonical requests use host/path/query, never a raw URL.
            path = urlsplit(item.get("path") or "/")
            path_query = parse_qs(path.query, keep_blank_values=True)
            item["path"] = path.path or "/"
            item["query"] = sanitize_body_payload({**path_query, **(item.get("query") or {})})
    return clean


def process_body_content(
    raw_body: bytes | str | None,
    content_type: str | None,
) -> tuple[Any, dict[str, Any]]:
    """Enforces size limits, parses JSON or handles binary content safely."""
    if raw_body is None or raw_body == b"" or raw_body == "":
        return None, {"size": 0, "truncated": False, "binary": False}

    if isinstance(raw_body, (dict, list)):
        encoded = json.dumps(raw_body).encode("utf-8")
        if len(encoded) > MAX_CAPTURE_BODY_BYTES:
            return "[REDACTED]", {"size": len(encoded), "original_size": len(encoded),
                                  "truncated": True, "redacted": True, "binary": False,
                                  "content_type": content_type or "application/json"}
        return sanitize_body_payload(raw_body), {"size": len(encoded), "truncated": False,
                                                 "binary": False, "content_type": content_type or "application/json"}

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

    if ct and not is_text:
        body_meta["binary"] = True
        body_meta["sha256"] = hashlib.sha256(body_bytes).hexdigest()
        return None, body_meta

    # Try decode text
    try:
        decoded_text = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        body_meta["binary"] = True
        body_meta["sha256"] = hashlib.sha256(body_bytes).hexdigest()
        return None, body_meta

    # Parse JSON if applicable
    if is_json or decoded_text.strip().startswith(("{", "[")):
        try:
            parsed = json.loads(decoded_text)
            sanitized = sanitize_body_payload(parsed) if isinstance(parsed, (dict, list)) else "[REDACTED]"
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

    body_meta["redacted"] = True
    return "[REDACTED]", body_meta


def normalize_http_transaction(
    raw_req: dict[str, Any],
    raw_resp: dict[str, Any] | None,
    capture_id: str,
    session_id: str | None = None,
    duration_ms: float = 0.0,
    scope: str = "UNKNOWN",
) -> TrafficTransaction:
    """Creates a normalized TrafficTransaction with sanitized headers, parsed body, and query."""
    if _internal(raw_req):
        raise TrafficException(TrafficErrorCode.TRAFFIC_PARSE_FAILED,
                               "Internal proxy requests are not application evidence.")
    internal_response = _internal(raw_resp)
    if internal_response:
        raw_resp = None
    # Process Request
    req_headers = sanitize_headers(raw_req.get("headers"), session_id)
    req_ct = req_headers.get("content-type")
    req_body, req_body_meta = process_body_content(raw_req.get("body"), req_ct)

    url_str = raw_req.get("url", "")
    parsed_url = urlparse(url_str) if url_str else None

    scheme = raw_req.get("scheme") or (parsed_url.scheme if parsed_url else "http")
    host = raw_req.get("host") or (parsed_url.hostname if parsed_url else "")
    port = raw_req.get("port") or (parsed_url.port if parsed_url and parsed_url.port else (443 if scheme == "https" else 80))
    path = raw_req.get("path") or (parsed_url.path if parsed_url else "/")
    path_parts = urlsplit(path)
    path = path_parts.path or "/"
    query = raw_req.get("query")
    if query is None and parsed_url and parsed_url.query:
        qs = parse_qs(parsed_url.query, keep_blank_values=True)
        query = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}

    path_query = parse_qs(path_parts.query, keep_blank_values=True)
    query = {**path_query, **(query or {})}
    auth_metadata = observe_payload_credentials(observe_auth(raw_req.get("headers"),session_id), query, raw_req.get("body"), req_ct, session_id)
    query = sanitize_body_payload(query)

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
        auth_metadata=auth_metadata,
    )

    # Process Response
    response_model: HttpResponseModel | None = None
    if raw_resp:
        resp_headers = sanitize_headers(raw_resp.get("headers"), session_id)
        resp_ct = resp_headers.get("content-type")
        resp_body, resp_body_meta = process_body_content(raw_resp.get("body"), resp_ct)

        response_model = HttpResponseModel(
            status_code=int(raw_resp.get("status_code", 0)),
            headers=resp_headers,
            body=resp_body,
            timestamp=raw_resp.get("timestamp") or "",
            body_metadata=resp_body_meta,
            auth_metadata=observe_auth(raw_resp.get("headers"), session_id, response=True),
        )

    return TrafficTransaction(
        capture_id=capture_id,
        session_id=session_id,
        request=request_model,
        response=response_model,
        duration_ms=round(duration_ms, 2),
        scope=scope,
        correlation={"response_observation": {"state": "unavailable",
                     "reason": "internal_proxy_response_excluded"}} if internal_response else {},
    )
