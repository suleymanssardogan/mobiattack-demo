"""Deterministic Info.plist Parser for MobiAttack V2.

Extracts factual application metadata, declared usage descriptions, and ATS
configuration from XML and binary property lists using Python's standard plistlib.
Never uses regex to parse plist data.
"""

from __future__ import annotations

from pathlib import Path
import plistlib
from typing import Any

# Known Apple usage description keys
USAGE_DESCRIPTION_SUFFIX = "UsageDescription"

# Core application identification keys
CORE_METADATA_KEYS = (
    "CFBundleIdentifier",
    "CFBundleName",
    "CFBundleDisplayName",
    "CFBundleExecutable",
    "CFBundleShortVersionString",
    "CFBundleVersion",
    "MinimumOSVersion",
    "CFBundleSupportedPlatforms",
    "UIDeviceFamily",
)


class PlistParseError(ValueError):
    """Raised when parsing a plist file fails due to corruption or invalid syntax."""
    pass


def parse_plist_file(plist_path: str | Path, source_file_label: str | None = None) -> dict[str, Any]:
    """Reads and parses an XML or binary property list file safely using plistlib.

    Args:
        plist_path: Absolute or relative path to the .plist file.
        source_file_label: Optional label preserved as evidence source_file.

    Returns:
        Dictionary representation of the plist contents.

    Raises:
        FileNotFoundError: If the file does not exist.
        PlistParseError: If plistlib fails to deserialize the content.
    """
    path = Path(plist_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Plist file not found: '{plist_path}'")

    try:
        with open(path, "rb") as fp:
            data = plistlib.load(fp)
    except Exception as exc:
        raise PlistParseError(f"Failed to parse plist '{path.name}': {exc}") from exc

    if not isinstance(data, dict):
        raise PlistParseError(f"Root object in plist '{path.name}' is not a dictionary (type: {type(data).__name__})")

    return data


def parse_info_plist(
    plist_path: str | Path,
    relative_source_path: str | None = None,
) -> dict[str, Any]:
    """Extracts factual application configuration and declared metadata from Info.plist.

    Strict rules:
      - Never infers permissions used at runtime; usage descriptions are labeled
        strictly as 'declared_usage_description'.
      - App Transport Security keys are extracted as factual 'configuration_fact',
        without vulnerability grading or verdicts.
      - Preserves exact evidence provenance for all extracted facts.

    Args:
        plist_path: Path to Info.plist.
        relative_source_path: Canonical relative path (e.g. 'Payload/App.app/Info.plist')
                              for evidence attribution.

    Returns:
        Structured dictionary matching normalized iOS schema.
    """
    path = Path(plist_path)
    source_label = relative_source_path or str(path)

    raw_plist = parse_plist_file(path, source_file_label=source_label)

    # 1. Core Application Metadata Facts
    bundle_id = raw_plist.get("CFBundleIdentifier")
    bundle_name = raw_plist.get("CFBundleName")
    display_name = raw_plist.get("CFBundleDisplayName") or bundle_name
    executable = raw_plist.get("CFBundleExecutable")
    version = raw_plist.get("CFBundleShortVersionString")
    build = raw_plist.get("CFBundleVersion")
    min_os = raw_plist.get("MinimumOSVersion")
    supported_platforms = raw_plist.get("CFBundleSupportedPlatforms")
    device_family_raw = raw_plist.get("UIDeviceFamily")

    # Normalize device family numbers (1: iPhone/iPod, 2: iPad, 3: Apple TV, 4: Apple Watch, 6: Mac)
    device_family: list[str] = []
    if isinstance(device_family_raw, list):
        family_map = {1: "iPhone", 2: "iPad", 3: "AppleTV", 4: "AppleWatch", 6: "Mac"}
        for f in device_family_raw:
            if isinstance(f, int) and f in family_map:
                device_family.append(family_map[f])
            elif f is not None:
                device_family.append(str(f))
    elif isinstance(device_family_raw, int):
        family_map = {1: "iPhone", 2: "iPad", 3: "AppleTV", 4: "AppleWatch", 6: "Mac"}
        device_family.append(family_map.get(device_family_raw, str(device_family_raw)))

    # 2. Declared Usage Descriptions
    usage_descriptions: list[dict[str, Any]] = []
    for key, value in raw_plist.items():
        if isinstance(key, str) and key.endswith(USAGE_DESCRIPTION_SUFFIX):
            usage_descriptions.append({
                "key": key,
                "value": str(value) if value is not None else "",
                "classification": "declared_usage_description",
                "evidence": {
                    "source_file": source_label,
                    "plist_key": key,
                    "extraction_method": "plistlib",
                },
            })
    usage_descriptions.sort(key=lambda x: x["key"])

    # 3. URL Schemes & Application Query Schemes
    url_schemes: list[dict[str, Any]] = []
    url_types = raw_plist.get("CFBundleURLTypes")
    if isinstance(url_types, list):
        for ut in url_types:
            if isinstance(ut, dict):
                name = ut.get("CFBundleURLName")
                schemes = ut.get("CFBundleURLSchemes")
                if isinstance(schemes, list):
                    for s in schemes:
                        if s and isinstance(s, str):
                            url_schemes.append({
                                "scheme": s,
                                "name": name,
                                "classification": "declared_url_scheme",
                                "evidence": {
                                    "source_file": source_label,
                                    "plist_key": "CFBundleURLTypes",
                                    "extraction_method": "plistlib",
                                },
                            })

    queries_schemes_raw = raw_plist.get("LSApplicationQueriesSchemes")
    queries_schemes: list[str] = []
    if isinstance(queries_schemes_raw, list):
        for qs in queries_schemes_raw:
            if isinstance(qs, str) and qs.strip():
                queries_schemes.append(qs.strip())

    # 4. App Transport Security (ATS) Configuration
    ats_raw = raw_plist.get("NSAppTransportSecurity")
    ats_facts: dict[str, Any] = {
        "status": "extracted" if ats_raw is not None else "not_found",
        "allows_arbitrary_loads": False,
        "allows_local_networking": False,
        "allows_arbitrary_loads_in_web_content": False,
        "allows_arbitrary_loads_for_media": False,
        "exception_domains": [],
        "configuration_facts": [],
    }

    if isinstance(ats_raw, dict):
        allows_arb = ats_raw.get("NSAllowsArbitraryLoads")
        if isinstance(allows_arb, bool):
            ats_facts["allows_arbitrary_loads"] = allows_arb
            ats_facts["configuration_facts"].append({
                "key": "NSAllowsArbitraryLoads",
                "value": allows_arb,
                "classification": "configuration_fact",
                "source": source_label,
            })

        allows_local = ats_raw.get("NSAllowsLocalNetworking")
        if isinstance(allows_local, bool):
            ats_facts["allows_local_networking"] = allows_local
            ats_facts["configuration_facts"].append({
                "key": "NSAllowsLocalNetworking",
                "value": allows_local,
                "classification": "configuration_fact",
                "source": source_label,
            })

        allows_web = ats_raw.get("NSAllowsArbitraryLoadsInWebContent")
        if isinstance(allows_web, bool):
            ats_facts["allows_arbitrary_loads_in_web_content"] = allows_web
            ats_facts["configuration_facts"].append({
                "key": "NSAllowsArbitraryLoadsInWebContent",
                "value": allows_web,
                "classification": "configuration_fact",
                "source": source_label,
            })

        allows_media = ats_raw.get("NSAllowsArbitraryLoadsForMedia")
        if isinstance(allows_media, bool):
            ats_facts["allows_arbitrary_loads_for_media"] = allows_media
            ats_facts["configuration_facts"].append({
                "key": "NSAllowsArbitraryLoadsForMedia",
                "value": allows_media,
                "classification": "configuration_fact",
                "source": source_label,
            })

        exc_domains_raw = ats_raw.get("NSExceptionDomains")
        if isinstance(exc_domains_raw, dict):
            for dom_name, dom_cfg in exc_domains_raw.items():
                if isinstance(dom_cfg, dict):
                    exc_entry = {
                        "domain": dom_name,
                        "includes_subdomains": bool(dom_cfg.get("NSIncludesSubdomains", False)),
                        "allows_insecure_http_loads": bool(dom_cfg.get("NSExceptionAllowsInsecureHTTPLoads", False)),
                        "minimum_tls_version": dom_cfg.get("NSExceptionMinimumTLSVersion"),
                        "requires_forward_secrecy": dom_cfg.get("NSExceptionRequiresForwardSecrecy"),
                    }
                    ats_facts["exception_domains"].append(exc_entry)
                    ats_facts["configuration_facts"].append({
                        "key": f"NSExceptionDomains.{dom_name}",
                        "value": exc_entry,
                        "classification": "configuration_fact",
                        "source": source_label,
                    })

    return {
        "bundle_identifier": str(bundle_id) if bundle_id is not None else None,
        "bundle_name": str(bundle_name) if bundle_name is not None else None,
        "display_name": str(display_name) if display_name is not None else None,
        "executable": str(executable) if executable is not None else None,
        "version": str(version) if version is not None else None,
        "build": str(build) if build is not None else None,
        "minimum_os_version": str(min_os) if min_os is not None else None,
        "supported_platforms": supported_platforms if isinstance(supported_platforms, list) else ([supported_platforms] if supported_platforms else []),
        "device_family": device_family,
        "usage_descriptions": usage_descriptions,
        "url_schemes": url_schemes,
        "queries_schemes": queries_schemes,
        "ats": ats_facts,
        "raw_keys_count": len(raw_plist),
    }
