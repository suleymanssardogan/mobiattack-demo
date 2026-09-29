"""Deterministic Normalization for Demo 3 Candidates.

Ensures canonical representations without altering case-sensitive path or query semantics.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, urlunparse

from src.demo3.candidate_model import RawCandidate

# Match trailing punctuation often captured from code or xml
TRAILING_PUNCT_RE = re.compile(r'["\'`,;:\)>\]}\s]+$')


def clean_extraction_artifacts(value: str) -> str:
    """Removes trailing and leading syntax artifacts while preserving content."""
    s = value.strip()
    s = re.sub(r'^["\'`\(<\[{]+', '', s)
    s = TRAILING_PUNCT_RE.sub('', s)
    return s.strip()


def normalize_url(raw_url: str) -> tuple[str, dict[str, Any]]:
    """Normalizes HTTP/HTTPS/WebSocket URLs preserving case-sensitive path/query.

    Returns:
        (canonical_url, components_dict)
    """
    cleaned = clean_extraction_artifacts(raw_url)
    try:
        parsed = urlparse(cleaned)
    except Exception:
        return cleaned, {"raw": cleaned}

    scheme = (parsed.scheme or "").lower()
    netloc = parsed.netloc

    # Split netloc into username, password, host, port
    # In standard urlparse, hostname is already lowercased, but port may be standard
    hostname = (parsed.hostname or "").lower()
    port = parsed.port

    # Strip default ports
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = hostname
    elif (scheme == "ws" and port == 80) or (scheme == "wss" and port == 443):
        netloc = hostname
    elif port:
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    # Handle userinfo if present
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo = f"{userinfo}:{parsed.password}"
        netloc = f"{userinfo}@{netloc}"

    path = parsed.path or ""
    # Normalize empty path to empty or single slash if host exists
    if not path and netloc:
        path = "/"

    # Reconstruct normalized URL
    reconstructed = urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        parsed.fragment,
    ))

    components: dict[str, Any] = {
        "scheme": scheme,
        "host": hostname,
        "port": port,
        "path": path,
    }
    if parsed.query:
        components["query"] = parsed.query
    if parsed.fragment:
        components["fragment"] = parsed.fragment

    return reconstructed, components


def normalize_domain(raw_domain: str) -> tuple[str, dict[str, Any]]:
    """Normalizes a hostname or domain name to lowercase without trailing dots."""
    cleaned = clean_extraction_artifacts(raw_domain)
    # Strip port if accidentally attached
    parts = cleaned.split(":")
    dom = parts[0].strip().lower().rstrip(".")
    port = None
    if len(parts) > 1 and parts[1].isdigit():
        port = int(parts[1])
    components: dict[str, Any] = {"host": dom}
    if port:
        components["port"] = port
        return f"{dom}:{port}", components
    return dom, components


def normalize_ip(raw_ip: str) -> tuple[str, dict[str, Any]]:
    """Normalizes IPv4 addresses."""
    cleaned = clean_extraction_artifacts(raw_ip)
    # Remove leading zeros from octets for canonical representation
    octets = cleaned.split(".")
    if len(octets) == 4 and all(o.isdigit() for o in octets):
        canon_ip = ".".join(str(int(o)) for o in octets)
        return canon_ip, {"ip": canon_ip, "version": 4}
    return cleaned, {"ip": cleaned}


def normalize_path(raw_path: str) -> tuple[str, dict[str, Any]]:
    """Normalizes an API path candidate while preserving case."""
    cleaned = clean_extraction_artifacts(raw_path)
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    # Collapse multiple consecutive slashes
    parts = [p for p in cleaned.split("/") if p]
    canon_path = "/" + "/".join(parts)
    return canon_path, {"path": canon_path}


def normalize_candidate(raw: RawCandidate) -> tuple[str, str, dict[str, Any]]:
    """Dispatches raw candidate to appropriate normalizer.

    Returns:
        (canonical_type, canonical_value, components)
    """
    ctype = raw.type.lower()
    raw_val = raw.raw_value

    if ctype in ("url", "network_url"):
        if raw_val.startswith("ws://") or raw_val.startswith("wss://"):
            val, comp = normalize_url(raw_val)
            return "websocket_url", val, comp
        val, comp = normalize_url(raw_val)
        return "url", val, comp

    if ctype in ("websocket", "websocket_url"):
        val, comp = normalize_url(raw_val)
        return "websocket_url", val, comp

    if ctype in ("domain", "domains", "host"):
        val, comp = normalize_domain(raw_val)
        return "domain", val, comp

    if ctype in ("ip", "ip_address", "ip_addresses"):
        val, comp = normalize_ip(raw_val)
        return "ip_address", val, comp

    if ctype in ("api_path", "path", "path_candidate", "path_candidates"):
        val, comp = normalize_path(raw_val)
        return "api_path", val, comp

    if ctype in ("base_url",):
        val, comp = normalize_url(raw_val)
        return "base_url", val, comp

    cleaned = clean_extraction_artifacts(raw_val)
    return ctype, cleaned, {"raw": cleaned}
