"""Unified Split Static Context Builder for MobiAttack V2 (Task 14 Phase C).

Runs existing static analyzers across all applicable preprocessed split components
and aggregates their facts into a single unified static context, preserving explicit
provenance (source_apk, source_file, line_number) across all evidence.

Rules:
- No new security analyzer or heuristic logic.
- Analyzers run independently per-split (no cross-split dataflow inference).
- DEX-less splits skip API candidate extraction cleanly.
- Failed splits are recorded as warnings without crashing the pipeline.
- Base APK is the authoritative application context (package name, launcher activity).
- Produces deterministic workspace/unified_analysis/static_context.json.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.manifest_parser import parse_manifest
from src.apk_structure_extractor import extract_apk_structure
from src.network_indicator_extractor import extract_network_indicators
from src.api_candidate_extractor import extract_api_candidates


def build_split_static_context(
    package_set_input: str | Path | dict,
    unified_analysis_root: str | Path | None = None,
) -> dict:
    """Builds unified static analysis context from preprocessed package-set components.

    Args:
        package_set_input: Package-set dictionary, or path to package_set.json, or workspace dir.
        unified_analysis_root: Optional directory to store static_context.json (defaults to workspace/unified_analysis).

    Returns:
        Structured unified static context dictionary matching MobiAttack schema with provenance.

    Raises:
        FileNotFoundError: If package_set.json cannot be found.
        ValueError: If package set has no components.
    """
    # 1. Resolve package_set data and filesystem paths
    pkg_set_file: Path | None = None
    if isinstance(package_set_input, dict):
        package_set = package_set_input
    else:
        p = Path(package_set_input).resolve()
        if p.is_file() and p.name == "package_set.json":
            pkg_set_file = p
            with open(p, "r", encoding="utf-8") as f:
                package_set = json.load(f)
        elif (p / "package_set" / "package_set.json").is_file():
            pkg_set_file = p / "package_set" / "package_set.json"
            with open(pkg_set_file, "r", encoding="utf-8") as f:
                package_set = json.load(f)
        elif (p / "package_set.json").is_file():
            pkg_set_file = p / "package_set.json"
            with open(pkg_set_file, "r", encoding="utf-8") as f:
                package_set = json.load(f)
        else:
            raise FileNotFoundError(f"Cannot resolve package_set.json from input: '{package_set_input}'")

    from src.android_identity import canonical_components, canonical_candidates, AndroidIdentityError
    components = canonical_components(package_set.get("components", []))
    if not components:
        raise ValueError("Package set does not contain any components to analyze.")

    # 2. Resolve unified_analysis destination
    if unified_analysis_root is not None:
        unified_dir = Path(unified_analysis_root).resolve()
    elif pkg_set_file is not None:
        workspace_base = pkg_set_file.parent.parent
        unified_dir = workspace_base / "unified_analysis"
    else:
        unified_dir = Path.cwd() / "unified_analysis"

    unified_dir.mkdir(parents=True, exist_ok=True)

    package_name = package_set.get("package_name")
    if not package_name:
        raise AndroidIdentityError('PACKAGE_MISMATCH', 'Package identity is missing.')
    # Verify every decoded manifest before merging any facts.
    versions = set()
    split_ids = set()
    import xml.etree.ElementTree as ET
    from src.manifest_parser import ANDROID_NS
    for component in components:
        decoded = component.get('preprocessing', {}).get('apktool_dir')
        manifest = Path(decoded)/'AndroidManifest.xml' if decoded else None
        if manifest is None or not manifest.is_file():
            if component['role'] == 'base':
                raise AndroidIdentityError('SPLIT_SET_INCOMPLETE', 'Base manifest evidence unavailable.')
            continue
        root = ET.parse(manifest).getroot()
        if root.attrib.get('package') != package_name:
            raise AndroidIdentityError('PACKAGE_MISMATCH', 'Split package identity differs from requested package.')
        version = root.attrib.get(f'{{{ANDROID_NS}}}versionCode')
        if version is not None:versions.add(version)
        split_id = root.attrib.get('split')
        if split_id and component['role'] == 'base':
            raise AndroidIdentityError('BASE_APK_NOT_FOUND', 'Base manifest identifies a split, not the application base.')
        if split_id:
            if split_id in split_ids:raise AndroidIdentityError('SPLIT_SET_INCOMPLETE', 'Duplicate manifest split identity.')
            split_ids.add(split_id)
        elif component['role'] != 'base':
            # Older fixtures may omit split metadata; retain explicit source APK provenance.
            pass
    if len(versions) > 1:
        raise AndroidIdentityError('PACKAGE_MISMATCH', 'Split version codes differ.')
    package_layout = package_set.get("package_layout", "split")
    all_warnings: list[str] = list(package_set.get("warnings", []))

    # Containers for aggregated evidence
    app_info: dict = {"package_name": package_name, "launcher_activity": None}
    base_permissions: list[str] = []
    base_activities: list[str] = []
    manifest_evidence: list[dict] = []
    base_manifest = {}
    structure_components: list[dict] = []

    aggregated_network_urls: list[dict] = []
    aggregated_domains: list[dict] = []
    aggregated_ip_addresses: list[dict] = []
    aggregated_path_candidates: list[dict] = []
    aggregated_local_file_urls: list[dict] = []

    aggregated_api_candidates: list[dict] = []
    from src.api_candidate_canonicalizer import canonicalize_api_candidates, bind_source_apk
    api_discovery_components: list[dict] = []

    # 3. Analyze each component independently
    for comp in components:
        fname = comp.get("filename", "unknown.apk")
        role = comp.get("role", "unknown")
        has_dex = comp.get("has_dex", False)
        prep = comp.get("preprocessing", {})

        apktool_status = prep.get("apktool_status", "not_run")
        raw_status = prep.get("raw_extract_status", "not_run")
        raw_apk_dir = Path(prep["raw_apk_dir"]) if prep.get("raw_apk_dir") else None
        apktool_dir = Path(prep["apktool_dir"]) if prep.get("apktool_dir") else None

        # Check if preprocessing produced artifacts
        if apktool_status == "failed" or not apktool_dir or not apktool_dir.is_dir():
            w_msg = f"Component '{fname}' skipped from static analysis: apktool output unavailable (status: {apktool_status})"
            all_warnings.append(w_msg)
            structure_components.append({
                "source_apk": fname,
                "role": role,
                "status": "unavailable",
                "dex_files": [],
                "dex_count": 0,
                "is_multidex": False,
                "native_libraries": [],
                "has_native_code": False,
                "assets": [],
                "smali_roots": [],
                "has_kotlin_metadata": False,
            })
            continue

        # --- A. Manifest Evidence ---
        manifest_file = apktool_dir / "AndroidManifest.xml"
        if manifest_file.is_file():
            try:
                manifest_data = parse_manifest(manifest_file)
                evidence_entry = {
                    "manifest": manifest_data,
                    "source_apk": fname,
                    "role": role,
                    "package_name": manifest_data.get("package_name"),
                    "launcher_activity": manifest_data.get("launcher_activity"),
                    "permissions": manifest_data.get("permissions", []),
                    "activities": manifest_data.get("activities", []),
                }
                manifest_evidence.append(evidence_entry)

                # Primary application facts derived from base APK
                if role == "base":
                    base_manifest = manifest_data
                    app_info = {
                        "package_name": manifest_data.get("package_name") or package_name,
                        "launcher_activity": manifest_data.get("launcher_activity"),
                        "launcher_target_activity": manifest_data.get("launcher_target_activity"),
                        "launcher_status": manifest_data.get("launcher_status"),
                    }
                    base_permissions = manifest_data.get("permissions", [])
                    base_activities = manifest_data.get("activities", [])
            except Exception as exc:
                w_msg = f"Failed parsing manifest for '{fname}': {exc}"
                all_warnings.append(w_msg)

        # --- B. Structure Inventory ---
        if raw_apk_dir and raw_apk_dir.is_dir():
            try:
                struct = extract_apk_structure(raw_apk_dir, apktool_dir)
                structure_components.append({
                    "source_apk": fname,
                    "role": role,
                    "status": "success",
                    "dex_files": struct["dex_files"],
                    "dex_count": struct["dex_count"],
                    "is_multidex": struct["is_multidex"],
                    "native_libraries": struct["native_libraries"],
                    "has_native_code": struct["has_native_code"],
                    "assets": struct["assets"],
                    "smali_roots": struct["smali_roots"],
                    "has_kotlin_metadata": struct["has_kotlin_metadata"],
                })
            except Exception as exc:
                w_msg = f"Failed extracting structure for '{fname}': {exc}"
                all_warnings.append(w_msg)
                structure_components.append({
                    "source_apk": fname,
                    "role": role,
                    "status": "failed",
                    "dex_files": [],
                    "dex_count": 0,
                    "is_multidex": False,
                    "native_libraries": [],
                    "has_native_code": False,
                    "assets": [],
                    "smali_roots": [],
                    "has_kotlin_metadata": False,
                })

        # --- C. Network Indicators (with Provenance) ---
        try:
            net_indicators = extract_network_indicators(apktool_dir)
            for item in net_indicators.get("network_urls", []):
                record = dict(item)
                record["source_apk"] = fname
                aggregated_network_urls.append(record)

            for item in net_indicators.get("domains", []):
                record = dict(item)
                record["source_apk"] = fname
                aggregated_domains.append(record)

            for item in net_indicators.get("ip_addresses", []):
                record = dict(item)
                record["source_apk"] = fname
                aggregated_ip_addresses.append(record)

            for item in net_indicators.get("path_candidates", []):
                record = dict(item)
                record["source_apk"] = fname
                aggregated_path_candidates.append(record)

            for item in net_indicators.get("local_file_urls", []):
                record = dict(item)
                record["source_apk"] = fname
                aggregated_local_file_urls.append(record)
        except Exception as exc:
            w_msg = f"Failed extracting network indicators for '{fname}': {exc}"
            all_warnings.append(w_msg)

        # --- D. Static API Candidates (Only when DEX bytecode exists) ---
        if has_dex:
            try:
                api_res = extract_api_candidates(apktool_dir)
                api_discovery_components.append({"source_apk": fname, **api_res.get("discovery_diagnostics", {})})
                for cand in api_res.get("api_candidates", []):
                    cand_record = bind_source_apk(cand, fname)
                    aggregated_api_candidates.append(cand_record)
            except Exception as exc:
                w_msg = f"Failed extracting API candidates for '{fname}': {exc}"
                all_warnings.append(w_msg)

    aggregated_api_candidates = canonicalize_api_candidates(aggregated_api_candidates)
    all_warnings = sorted(set(all_warnings))

    # 4. Compute package-level aggregation totals
    total_dex_count = sum(s.get("dex_count", 0) for s in structure_components)
    all_dex_files = [f"{s['source_apk']}:{d}" for s in structure_components for d in s.get("dex_files", [])]
    total_indicators_count = (
        len(aggregated_network_urls)
        + len(aggregated_domains)
        + len(aggregated_ip_addresses)
        + len(aggregated_path_candidates)
        + len(aggregated_local_file_urls)
    )

    # Build canonical unified context model
    unified_context = {
        "package_name": package_name,
        "package_layout": package_layout,
        "split_count": len(components),
        "app": app_info,
        "permissions": base_permissions,
        "activities": base_activities,
        "manifest": base_manifest,
        "manifest_evidence": manifest_evidence,
        "components": [
            {
                "filename": c.get("filename"),
                "role": c.get("role", "unknown"),
                "size_bytes": c.get("size_bytes"),
                "sha256": c.get("sha256"),
                "has_dex": c.get("has_dex", False),
                "dex_count": c.get("dex_count", 0),
                "preprocessing_status": c.get("preprocessing", {}).get("apktool_status"),
            }
            for c in components
        ],
        "structure": {
            "components": structure_components,
            "total_dex_count": total_dex_count,
            "dex_files": all_dex_files,
            "is_multidex": total_dex_count > 1,
            "has_native_code": any(s.get("has_native_code", False) for s in structure_components),
            "has_kotlin_metadata": any(s.get("has_kotlin_metadata", False) for s in structure_components),
        },
        "network_indicators": {
            "network_urls": aggregated_network_urls,
            "domains": aggregated_domains,
            "ip_addresses": aggregated_ip_addresses,
            "path_candidates": aggregated_path_candidates,
            "local_file_urls": aggregated_local_file_urls,
            "total_count": total_indicators_count,
        },
        "api_candidates": aggregated_api_candidates,
        "api_discovery": {"components": api_discovery_components},
        "aggregation_counts": {
            "total_dex_count": total_dex_count,
            "network_indicator_count": total_indicators_count,
            "api_candidate_count": len(aggregated_api_candidates),
        },
        "analysis_warnings": all_warnings,
    }

    # 5. Write deterministic static_context.json
    output_json_path = unified_dir / "static_context.json"
    with open(output_json_path, "w", encoding="utf-8") as f:
        json.dump(unified_context, f, indent=2)

    return unified_context
