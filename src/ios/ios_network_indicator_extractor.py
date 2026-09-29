"""Deterministic iOS Network Indicator Extractor for MobiAttack V2.

Extracts static network indicators (URLs, domains, IP addresses, paths, local file URLs)
from iOS bundle property lists, JSON configurations, resource text, and Mach-O binary strings.

CRITICAL PRINCIPLE:
  STATIC NETWORK INDICATOR != API ENDPOINT
  Finding a URL or domain string proves only that the string constant exists in the package.
  It does not prove active runtime execution or confirm an API endpoint.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import plistlib
import re
from typing import Any

from src.ios.macho_analyzer import validate_macho_magic

# Regex definitions
LOCAL_FILE_URL_RE = re.compile(r'\bfile:///[^\s"\'<>]+')
NETWORK_URL_RE = re.compile(r'\bhttps?://[a-zA-Z0-9][-a-zA-Z0-9.]*(?::[0-9]+)?(?:/[^\s"\'<>]*)?')
IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b')
PATH_CANDIDATE_RE = re.compile(r'(?<![a-zA-Z0-9_<:/])/(?:[a-zA-Z0-9_.-]+/?)+')

# Standard XML schema / DTD namespaces to exclude
SCHEMA_PREFIXES_TO_IGNORE = (
    "http://www.apple.com/DTDs/",
    "https://www.apple.com/DTDs/",
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://schemas.xmlsoap.org/",
    "http://schemas.microsoft.com/",
    "http://schemas.android.com/",
)

COMMON_FILE_EXTENSIONS = {
    # Text / markup / code
    "xml", "json", "txt", "html", "htm", "js", "css", "h", "m", "c", "cpp",
    "swift", "swiftinterface", "swiftmodule", "swiftdoc", "modulemap",
    "storyboard", "storyboardc", "nib", "strings", "stringsdict", "plist",
    "pch", "sh", "py", "rb", "lock", "tmp", "bak",
    # Images / media / fonts
    "png", "jpg", "jpeg", "gif", "webp", "svg", "pdf", "ico", "icns", "car",
    "ttf", "otf", "woff", "woff2", "mp3", "wav", "mp4", "mov", "m4a", "caf",
    # Binaries / bundles / data
    "app", "bundle", "dylib", "framework", "appex", "zip", "ipa", "tar", "gz", "7z", "bin",
    "dat", "data", "db", "sqlite", "sqlite3", "cer", "der", "p12", "p7b",
    "mobileprovision", "momd", "omo", "xcassets", "xcprivacy",
}

# Recognized standard internet TLDs (generic and ccTLDs)
VALID_TLDS = {
    # Generic & popular TLDs
    "com", "org", "net", "edu", "gov", "mil", "int", "io", "ai", "co",
    "app", "dev", "me", "info", "biz", "tv", "cc", "cloud", "tech", "online",
    "site", "store", "live", "link", "global", "digital", "network", "systems",
    "security", "solutions", "services", "pro", "xyz", "mobi", "asia", "club",
    "space", "vip", "top", "shop", "news", "media", "one", "page", "group",
    "agency", "center", "expert", "direct", "zone", "rocks", "world", "today",
    "life", "guide", "tools", "capital", "fund", "finance", "design", "art",
    # Major country-code TLDs (ccTLDs)
    "uk", "us", "ca", "de", "fr", "jp", "cn", "au", "eu", "nl", "se", "no",
    "ch", "at", "ru", "br", "za", "tr", "mx", "es", "it", "kr", "sg", "nz",
    "in", "ie", "be", "dk", "fi", "pl", "cz", "gr", "pt", "hu", "ro", "bg",
    "hr", "sk", "si", "lt", "lv", "ee", "is", "lu", "mt", "cy", "hk", "tw",
    "my", "th", "vn", "id", "ph", "ae", "sa", "il", "eg", "ng", "ke", "ar",
    "cl", "pe", "ve", "pk", "bd", "lk", "np", "ua", "by", "kz", "uz",
}

# Substring labels typical of Apple SF Symbols, UI assets, or code components
DISALLOWED_DOMAIN_LABELS = {
    "fill", "circle", "slash", "square", "badge", "rectangle", "capsule",
    "triangle", "bubble", "shield", "portrait", "landscape", "glyph",
    "storyboard", "swiftinterface", "swiftmodule", "swiftdoc",
    "write", "location", "open", "log", "error",
}

# JavaScript, DOM, or Objective-C symbol-like prefixes
DISALLOWED_DOMAIN_PREFIXES = (
    "document.", "window.", "console.", "navigator.", "location.",
    "screen.", "history.", "storage.", "sessionStorage.", "localStorage.",
    "self.", "this.", "super.", "parent.", "top.",
)

PACKAGE_PREFIXES_TO_IGNORE = (
    "com.apple.",
    "apple.",
    "org.xml.",
    "org.w3c.",
    "NS",
    "UI",
    "CF",
)


def is_valid_domain(candidate: str) -> bool:
    """Conservatively validates whether a string represents a real network domain.

    Rejects filenames, SF Symbol names, Swift interface artifacts, JavaScript/DOM
    identifiers, and non-existent TLDs.
    """
    if not candidate or len(candidate) > 253:
        return False

    candidate_lower = candidate.lower()

    # Reject obvious JS/DOM or code symbol prefixes
    if any(candidate_lower.startswith(p) for p in DISALLOWED_DOMAIN_PREFIXES):
        return False

    # Must contain at least one dot
    if "." not in candidate:
        return False

    labels = candidate_lower.split(".")
    if len(labels) < 2:
        return False

    tld = labels[-1]

    # Reject known file extensions
    if tld in COMMON_FILE_EXTENSIONS:
        return False

    # Reject if TLD is not in valid internet TLD whitelist
    if tld not in VALID_TLDS:
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        # Valid hostname label syntax (RFC 1035): letters, digits, hyphens (not leading/trailing)
        if not re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", label):
            return False
        # Disallow SF Symbol and UI symbol tokens
        if label in DISALLOWED_DOMAIN_LABELS:
            return False

    # Reject two-part strings whose first part is a known generic code/asset keyword
    if len(labels) == 2 and labels[0] in {"document", "window", "screen", "location", "view", "controller"}:
        return False

    return True


def _clean_trailing(val: str) -> str:
    """Trim trailing quotes, semicolons, commas, or parentheses."""
    return val.rstrip("\"'`,;:)>]} ")


def _extract_strings_from_plist_data(obj: Any) -> list[str]:
    """Recursively extracts string values from a deserialized plist object."""
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                strings.append(k)
            strings.extend(_extract_strings_from_plist_data(v))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            strings.extend(_extract_strings_from_plist_data(item))
    return strings


def _extract_binary_strings(
    file_path: Path,
    max_bytes: int = 50 * 1024 * 1024,
    max_results: int = 10_000,
) -> list[tuple[str, int]]:
    """Extract printable ASCII runs while retaining byte-offset provenance.

    External ``strings`` output is intentionally not used: it does not reliably
    provide offsets, which made a reported binary indicator impossible to locate.
    The streaming implementation also avoids loading an entire Mach-O into memory.
    """
    results: list[tuple[str, int]] = []
    try:
        with open(file_path, "rb") as f:
            current_run = bytearray()
            start_offset = 0
            offset = 0
            remaining = max_bytes
            while remaining > 0 and len(results) < max_results:
                chunk = f.read(min(64 * 1024, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                for b in chunk:
                    if 0x20 <= b <= 0x7E:
                        if not current_run:
                            start_offset = offset
                        current_run.append(b)
                    else:
                        if len(current_run) >= 6:
                            results.append((current_run.decode("ascii", errors="replace"), start_offset))
                            if len(results) >= max_results:
                                break
                        current_run.clear()
                    offset += 1
            if len(current_run) >= 6 and len(results) < max_results:
                results.append((current_run.decode("ascii", errors="replace"), start_offset))
    except Exception:
        pass
    return results


def extract_ios_network_indicators(
    app_bundle_dir: str | Path,
    relative_bundle_path: str = "Payload/App.app",
    main_executable_name: str | None = None,
    scan_embedded_binaries: bool = True,
) -> dict[str, list[dict[str, Any]]]:
    """Scans an extracted iOS app bundle for static network indicators.

    Args:
        app_bundle_dir: Path to the extracted .app directory.
        relative_bundle_path: Relative path for evidence provenance.
        main_executable_name: Optional name of the main executable to inspect.
        scan_embedded_binaries: Scan embedded Mach-O frameworks and extensions too.

    Returns:
        Dictionary containing categorized indicator lists:
            - network_urls
            - domains
            - ip_addresses
            - path_candidates
            - local_file_urls
    """
    bundle_path = Path(app_bundle_dir).resolve()
    rel_root = relative_bundle_path.rstrip("/\\")

    network_urls: list[dict[str, Any]] = []
    domains: list[dict[str, Any]] = []
    ip_addresses: list[dict[str, Any]] = []
    path_candidates: list[dict[str, Any]] = []
    local_file_urls: list[dict[str, Any]] = []

    seen: set[tuple[str, str, str, int | None, int | None]] = set()

    def record(bucket: list[dict[str, Any]], item_type: str, value: str, **provenance: Any) -> None:
        key = (
            item_type,
            value,
            provenance["source_file"],
            provenance.get("line_number"),
            provenance.get("offset"),
        )
        if key not in seen:
            seen.add(key)
            bucket.append({"value": value, "type": item_type, **provenance})

    def process_text_line(line: str, source_file: str, source_type: str, method: str, line_no: int | None = None, offset: int | None = None) -> None:
        url_values = [_clean_trailing(match.group(0)) for match in NETWORK_URL_RE.finditer(line)]
        # 1. Local file URLs
        for m in LOCAL_FILE_URL_RE.finditer(line):
            val = _clean_trailing(m.group(0))
            record(local_file_urls, "local_file_url", val, source_file=source_file,
                   source_type=source_type, line_number=line_no, offset=offset,
                   extraction_method=method)

        # 2. Network URLs
        for m in NETWORK_URL_RE.finditer(line):
            val = _clean_trailing(m.group(0))
            if any(val.startswith(p) for p in SCHEMA_PREFIXES_TO_IGNORE):
                continue
            record(network_urls, "network_url", val, source_file=source_file,
                   source_type=source_type, line_number=line_no, offset=offset,
                   extraction_method=method)

        # 3. Standalone IPv4 addresses
        for m in IPV4_RE.finditer(line):
            val = _clean_trailing(m.group(0))
            if any(val in url for url in url_values):
                continue
            parts = [int(p) for p in val.split(".")]
            # Filter non-routable / loopback noise if desired, or accept standard IPv4
            if parts[0] in (0, 127) or parts[-1] == 255:
                continue
            record(ip_addresses, "ip_address", val, source_file=source_file,
                   source_type=source_type, line_number=line_no, offset=offset,
                   extraction_method=method)

        # 4. Bare domain candidates
        for m in DOMAIN_RE.finditer(line):
            val = _clean_trailing(m.group(0))
            if not is_valid_domain(val):
                continue
            if any(val.startswith(p) for p in PACKAGE_PREFIXES_TO_IGNORE):
                continue
            # A host inside a URL is already represented by the stronger URL fact.
            if any(val in url for url in url_values):
                continue
            record(domains, "domain", val, source_file=source_file,
                   source_type=source_type, line_number=line_no, offset=offset,
                   extraction_method=method)

        # 5. Path candidates (API-like paths)
        for m in PATH_CANDIDATE_RE.finditer(line):
            val = _clean_trailing(m.group(0))
            if any(val in url for url in url_values):
                continue
            if len(val) >= 4 and any(val.startswith(prefix) for prefix in ("/api/", "/v1/", "/v2/", "/v3/", "/oauth/", "/auth/")):
                record(path_candidates, "path_candidate", val, source_file=source_file,
                       source_type=source_type, line_number=line_no, offset=offset,
                       extraction_method=method)

    # 1. Scan Plist files
    for root, dirs, files in os.walk(bundle_path):
        dirs.sort()
        files.sort()
        rel_root_dir = Path(root).relative_to(bundle_path)
        for f in files:
            file_path = Path(root) / f
            source_file_rel = f"{rel_root}/{rel_root_dir / f}" if str(rel_root_dir) != "." else f"{rel_root}/{f}"

            if f.endswith(".plist"):
                try:
                    with open(file_path, "rb") as fp:
                        plist_obj = plistlib.load(fp)
                    strings = _extract_strings_from_plist_data(plist_obj)
                    for s in strings:
                        process_text_line(s, source_file=source_file_rel, source_type="plist", method="plistlib")
                except Exception:
                    pass

            elif f.endswith(".json"):
                try:
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                    try:
                        json_obj = json.loads(text)
                        strings = _extract_strings_from_plist_data(json_obj)
                        for s in strings:
                            process_text_line(s, source_file=source_file_rel, source_type="json", method="json_traversal")
                    except Exception:
                        for line_no, line in enumerate(text.splitlines(), start=1):
                            process_text_line(line, source_file=source_file_rel, source_type="json", method="text_scan", line_no=line_no)
                except Exception:
                    pass

            elif f.endswith((".txt", ".conf", ".ini", ".yaml", ".yml", ".strings")):
                try:
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                    for line_no, line in enumerate(text.splitlines(), start=1):
                        process_text_line(line, source_file=source_file_rel, source_type="config", method="text_scan", line_no=line_no)
                except Exception:
                    pass

    # 2. Scan Main Executable Strings (if present)
    if main_executable_name:
        exe_path = bundle_path / main_executable_name
        if exe_path.is_file():
            source_file_rel = f"{rel_root}/{main_executable_name}"
            extracted_strings = _extract_binary_strings(exe_path)
            for s, offset in extracted_strings:
                process_text_line(s, source_file=source_file_rel, source_type="binary_strings", method="binary_strings_scan", offset=offset)

    # Framework and extension binaries carry first-party and third-party endpoint
    # configuration as often as the main binary. Restrict the scan to files with a
    # verified Mach-O header so resources are never treated as binary text.
    if scan_embedded_binaries:
        main_path = (bundle_path / main_executable_name).resolve() if main_executable_name else None
        for candidate in sorted((p for p in bundle_path.rglob("*") if p.is_file()), key=lambda p: p.as_posix()):
            if main_path and candidate.resolve() == main_path:
                continue
            if not validate_macho_magic(candidate).get("is_macho"):
                continue
            rel = candidate.relative_to(bundle_path).as_posix()
            for s, offset in _extract_binary_strings(candidate):
                process_text_line(s, source_file=f"{rel_root}/{rel}", source_type="binary_strings",
                                  method="binary_strings_scan", offset=offset)

    def sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        return (item["value"], item["source_file"], item.get("line_number") or -1, item.get("offset") or -1)

    return {
        "network_urls": sorted(network_urls, key=sort_key),
        "domains": sorted(domains, key=sort_key),
        "ip_addresses": sorted(ip_addresses, key=sort_key),
        "path_candidates": sorted(path_candidates, key=sort_key),
        "local_file_urls": sorted(local_file_urls, key=sort_key),
    }
