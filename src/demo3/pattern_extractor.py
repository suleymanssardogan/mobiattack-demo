"""Rule-based pattern extractor for Demo 3 candidates."""

from __future__ import annotations

import re
from typing import Generator

from src.demo3.candidate_model import RawCandidate
from src.ios.ios_network_indicator_extractor import is_valid_domain

# Regex patterns
NETWORK_URL_RE = re.compile(r'\bhttps?://[a-zA-Z0-9][-a-zA-Z0-9.]*(?::[0-9]+)?(?:/[^\s"\'<>]*)?')
WEBSOCKET_URL_RE = re.compile(r'\bwss?://[a-zA-Z0-9][-a-zA-Z0-9.]*(?::[0-9]+)?(?:/[^\s"\'<>]*)?')
IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b')
PATH_CANDIDATE_RE = re.compile(r'(?<![a-zA-Z0-9_<:/])/(?:[a-zA-Z0-9_.-]+/?)+')

SCHEMA_PREFIXES_TO_IGNORE = (
    "http://schemas.android.com/",
    "https://schemas.android.com/",
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://schemas.microsoft.com/",
    "http://www.apple.com/DTDs/",
    "https://www.apple.com/DTDs/",
)

COMMON_FILE_EXTENSIONS = {
    "xml", "png", "jpg", "jpeg", "gif", "webp", "smali", "json", "txt", "html",
    "js", "css", "so", "dex", "arsc", "java", "kt", "class", "mf", "sf", "rsa",
    "properties", "yml", "yaml", "ini", "conf", "svg", "ttf", "otf", "mp3", "wav",
    "apk", "bin", "aar",
}

PACKAGE_PREFIXES_TO_IGNORE = (
    "android.",
    "androidx.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "dalvik.",
    "com.android.",
    "org.xml.",
    "org.w3c.",
    "org.json.",
    "org.apache.",
)

CODE_PREFIXES_TO_IGNORE = (
    "this.",
    "super.",
    "window.",
    "self.",
    "root.",
    "owner.",
    "sb.",
    "options.",
    "option.",
    "regex.",
    "resources.",
    "document.",
    "view.",
    "vnd.",
    "r.string.",
)

CODE_SUFFIXES_TO_IGNORE = {
    "tostring", "toint", "tochar", "tolong", "tofloat", "todouble", "first", "second",
    "add", "subtract", "multiply", "divide", "negate", "and", "or", "not", "xor",
    "remainder", "matcher", "pattern", "split", "cancel", "getchildat", "value",
    "text", "context", "configuration", "displaymetrics", "oncreate", "onstart",
    "onresume", "onpause", "onstop", "ondestroy", "onattach", "ondetach",
}

LOCAL_PATH_PREFIXES_TO_IGNORE = (
    "/android_asset/",
    "/res/",
    "/drawable",
    "/layout",
    "/mipmap",
    "/assets/",
    "/data/",
    "/system/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/META-INF/",
    "/shared_prefs/",
    "/schemas.",
)


def _clean_trailing(val: str) -> str:
    return val.rstrip("\"'`,;:)>]} ")


def _create_evidence_snippet(line: str, match_str: str, max_len: int = 120) -> str:
    """Extracts a short, informative snippet of code/text containing the match."""
    stripped = line.strip()
    if len(stripped) <= max_len:
        return stripped
    idx = stripped.find(match_str)
    if idx == -1:
        return stripped[:max_len] + "..."
    start = max(0, idx - 30)
    end = min(len(stripped), idx + len(match_str) + 30)
    snippet = stripped[start:end]
    if start > 0:
        snippet = "..." + snippet
    if end < len(stripped):
        snippet = snippet + "..."
    return snippet


def extract_candidates_from_text(
    line: str,
    source_file: str,
    line_number: int,
) -> Generator[RawCandidate, None, None]:
    """Scans a single textual line for candidate endpoints and indicators."""
    all_urls_on_line: list[str] = []

    # 1. WebSockets
    for m in WEBSOCKET_URL_RE.finditer(line):
        val = _clean_trailing(m.group(0))
        if val:
            all_urls_on_line.append(val)
            evidence = _create_evidence_snippet(line, val)
            yield RawCandidate(
                type="websocket_url",
                raw_value=val,
                source_file=source_file,
                line_number=line_number,
                extraction_method="websocket_url_pattern",
                evidence=evidence,
            )

    # 2. HTTP/HTTPS URLs
    for m in NETWORK_URL_RE.finditer(line):
        val = _clean_trailing(m.group(0))
        if not val:
            continue
        all_urls_on_line.append(val)
        if any(val.startswith(p) for p in SCHEMA_PREFIXES_TO_IGNORE):
            continue
        evidence = _create_evidence_snippet(line, val)
        yield RawCandidate(
            type="url",
            raw_value=val,
            source_file=source_file,
            line_number=line_number,
            extraction_method="network_url_pattern",
            evidence=evidence,
        )

    # 3. IPv4 Addresses (ignoring those embedded inside URLs)
    for m in IPV4_RE.finditer(line):
        val = m.group(0)
        if any(val in u for u in all_urls_on_line):
            continue
        # Filter loopback/zero
        parts = [int(p) for p in val.split(".")]
        if parts[0] in (0, 127) or parts[-1] == 255:
            continue
        evidence = _create_evidence_snippet(line, val)
        yield RawCandidate(
            type="ip_address",
            raw_value=val,
            source_file=source_file,
            line_number=line_number,
            extraction_method="ipv4_pattern",
            evidence=evidence,
        )

    # 4. Bare Domains (ignoring hosts already represented inside URLs on this line)
    for m in DOMAIN_RE.finditer(line):
        val = _clean_trailing(m.group(0))
        if not is_valid_domain(val):
            continue
        if val.lower().startswith(("com.", "org.", "net.")):
            continue
        if any(ch.isupper() for label in val.split(".") for ch in label[1:]):
            continue
        # Do not report a partial package/class identifier as a host.
        if m.start() > 0 and (line[m.start() - 1].isalnum() or line[m.start() - 1] in "._"):
            continue
        if m.end() < len(line) and (line[m.end()].isalnum() or line[m.end()] in "._"):
            continue
        if any(val in u for u in all_urls_on_line):
            continue
        val_lower = val.lower()
        tld = val_lower.split(".")[-1]
        if tld in COMMON_FILE_EXTENSIONS:
            continue
        if any(val_lower.startswith(p) for p in CODE_PREFIXES_TO_IGNORE):
            continue
        if tld in CODE_SUFFIXES_TO_IGNORE:
            continue
        if any(val_lower.startswith(p) for p in PACKAGE_PREFIXES_TO_IGNORE):
            continue
        raw_tld = val.split(".")[-1]
        if raw_tld.istitle() or any(c.isupper() for c in raw_tld[1:]):
            continue

        evidence = _create_evidence_snippet(line, val)
        yield RawCandidate(
            type="domain",
            raw_value=val,
            source_file=source_file,
            line_number=line_number,
            extraction_method="domain_pattern",
            evidence=evidence,
        )

    # 5. API Path Candidates
    for m in PATH_CANDIDATE_RE.finditer(line):
        val = _clean_trailing(m.group(0))
        if any(val in u for u in all_urls_on_line):
            continue
        if any(val.startswith(p) for p in LOCAL_PATH_PREFIXES_TO_IGNORE):
            continue
        # Check API-like path prefixes
        val_lower = val.lower()
        if any(val_lower.startswith(p) for p in ("/api/", "/v1/", "/v2/", "/v3/", "/oauth/", "/auth/", "/rest/")):
            evidence = _create_evidence_snippet(line, val)
            yield RawCandidate(
                type="api_path",
                raw_value=val,
                source_file=source_file,
                line_number=line_number,
                extraction_method="api_path_pattern",
                evidence=evidence,
            )
