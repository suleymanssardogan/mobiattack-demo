"""Normalized iOS Static Context Builder for MobiAttack V2.

Aggregates deterministic facts from plist_parser, ios_structure_extractor,
macho_analyzer, entitlements_parser, and ios_network_indicator_extractor
into a normalized platform-independent schema.

Strict Invariants:
  - api_candidates is strictly [] for Phase 1 iOS analysis.
  - Absence of evidence is not evidence of absence.
  - Preserves complete provenance evidence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.ios.plist_parser import parse_info_plist
from src.ios.ios_structure_extractor import extract_ios_structure
from src.ios.macho_analyzer import analyze_macho_executable
from src.ios.entitlements_parser import extract_entitlements
from src.ios.ios_network_indicator_extractor import extract_ios_network_indicators


def build_ios_static_context(
    app_bundle_dir: str | Path,
    relative_bundle_path: str = "Payload/App.app",
    ipa_metadata: dict[str, Any] | None = None,
    use_system_tools: bool = True,
) -> dict[str, Any]:
    """Builds a unified, normalized static security context from an extracted iOS app bundle.

    Args:
        app_bundle_dir: Path to the extracted .app directory.
        relative_bundle_path: Relative path for evidence provenance (e.g. 'Payload/Test.app').
        ipa_metadata: Optional acquisition metadata (filename, sha256, size_bytes).
        use_system_tools: Whether to allow system tools like otool/codesign.

    Returns:
        Structured dictionary matching the normalized MobiAttack schema.
    """
    bundle_path = Path(app_bundle_dir).resolve()
    if not bundle_path.is_dir():
        raise NotADirectoryError(f"Application bundle directory not found: '{app_bundle_dir}'")

    meta = ipa_metadata or {}
    rel_root = relative_bundle_path.rstrip("/\\")
    info_plist_path = bundle_path / "Info.plist"
    info_plist_rel = f"{rel_root}/Info.plist"

    evidence: list[dict[str, Any]] = []

    # 1. Parse Info.plist
    if info_plist_path.is_file():
        plist_facts = parse_info_plist(info_plist_path, relative_source_path=info_plist_rel)
        executable_name = plist_facts.get("executable")
        evidence.append({
            "fact": "CFBundleIdentifier",
            "value": plist_facts.get("bundle_identifier"),
            "evidence": {"source_file": info_plist_rel, "extraction_method": "plistlib"},
        })
    else:
        plist_facts = {
            "bundle_identifier": None,
            "bundle_name": None,
            "display_name": None,
            "executable": None,
            "version": None,
            "build": None,
            "minimum_os_version": None,
            "supported_platforms": [],
            "device_family": [],
            "usage_descriptions": [],
            "url_schemes": [],
            "queries_schemes": [],
            "ats": {"status": "not_found", "allows_arbitrary_loads": False, "exception_domains": []},
        }
        executable_name = None

    # 2. Extract Structure & Inventory
    structure = extract_ios_structure(
        app_bundle_dir=bundle_path,
        executable_name=executable_name,
        relative_bundle_path=rel_root,
    )

    # 3. Analyze Main Mach-O Executable
    if executable_name and (bundle_path / executable_name).is_file():
        macho_info = analyze_macho_executable(
            executable_path=bundle_path / executable_name,
            use_system_tools=use_system_tools,
        )
        evidence.append({
            "fact": "Mach-O Architectures",
            "value": macho_info.get("architectures"),
            "evidence": {"source_file": f"{rel_root}/{executable_name}", "extraction_method": "macho_parser"},
        })
    else:
        macho_info = {
            "status": "not_found",
            "is_macho": False,
            "architectures": [],
            "bitness": None,
            "file_type": None,
            "linked_libraries": [],
            "uuid": None,
            "encryption_info": None,
        }

    structure["executable"] = macho_info

    # 4. Extract Entitlements
    entitlements_info = extract_entitlements(
        app_bundle_dir=bundle_path,
        relative_bundle_path=rel_root,
        use_system_tools=use_system_tools,
    )
    if entitlements_info.get("status") == "extracted":
        evidence.append({
            "fact": "Entitlements",
            "value": f"{entitlements_info.get('item_count')} items",
            "evidence": {
                "source_file": entitlements_info.get("source"),
                "extraction_method": entitlements_info.get("extraction_method"),
            },
        })

    # 5. Extract Static Network Indicators
    network_indicators = extract_ios_network_indicators(
        app_bundle_dir=bundle_path,
        relative_bundle_path=rel_root,
        main_executable_name=executable_name,
    )

    # Compile Application block
    application = {
        "platform": "ios",
        "bundle_identifier": plist_facts.get("bundle_identifier"),
        "bundle_name": plist_facts.get("bundle_name"),
        "display_name": plist_facts.get("display_name"),
        "executable": executable_name,
        "version": plist_facts.get("version"),
        "build": plist_facts.get("build"),
        "minimum_os_version": plist_facts.get("minimum_os_version"),
        "supported_platforms": plist_facts.get("supported_platforms", []),
        "device_family": plist_facts.get("device_family", []),
        "filename": meta.get("filename") or (Path(meta.get("ipa_path", "")).name if meta.get("ipa_path") else "app.ipa"),
        "sha256": meta.get("sha256", "unknown"),
        "size_bytes": meta.get("size_bytes"),
    }

    configuration = {
        "usage_descriptions": plist_facts.get("usage_descriptions", []),
        "url_schemes": plist_facts.get("url_schemes", []),
        "queries_schemes": plist_facts.get("queries_schemes", []),
        "ats": plist_facts.get("ats", {}),
        "entitlements": entitlements_info,
    }

    limitations = [
        "API candidate call-context extraction is not implemented for iOS Phase 1 (zero candidates reported).",
        "Dynamic instrumentation, traffic interception (MITM/Burp), and deep UI exploration were not performed.",
        "Static network indicators prove only that the string constant exists in the package; they do not prove runtime use.",
        "Presence of a usage description does not prove runtime permission access.",
        "Only selected ATS and signed debug entitlement checks are scored later; no overall security verdict is provided.",
    ]

    return {
        "platform": "ios",
        "application": application,
        "configuration": configuration,
        "structure": structure,
        "network_indicators": network_indicators,
        "api_candidates": [],  # Strictly empty in Phase 1
        "limitations": limitations,
        "evidence": evidence,
    }
