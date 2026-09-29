"""Builds, validates, and serializes the baseline_report.json artifact for Demo 3."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from src.demo3.schema_validator import SchemaValidationError, validate_baseline_report


def build_baseline_report(
    run_id: str,
    pipeline_result: dict[str, Any] | None,
    demo3_scan_data: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Assembles the canonical Demo 3 baseline report data structure.

    Args:
        run_id: Unique identifier for the demo run.
        pipeline_result: Pipeline results dictionary from run_demo.
        demo3_scan_data: Output of Demo 3 deterministic static scanner.
        error: Failure message if pipeline or scan aborted.

    Returns:
        Structured baseline report dictionary adhering to baseline_report.schema.json.
    """
    res = pipeline_result or {}
    acq = res.get("acquisition") or {}
    static = res.get("static_analysis") or {}
    app = static.get("application") or static.get("app") or res.get("application") or {}
    scan_meta = demo3_scan_data or static.get("demo3_scan") or {}

    stats = scan_meta.get("statistics") or {
        "files_discovered": 0,
        "files_analyzed": 0,
        "files_skipped": 0,
        "files_failed": 0,
        "failed_files": [],
    }

    # Derive scan status
    raw_status = scan_meta.get("status")
    if error or res.get("demo_status") == "failed":
        status = "failed"
    elif raw_status in ("completed", "partial", "failed"):
        status = raw_status
    elif stats.get("files_failed", 0) > 0 and stats.get("files_analyzed", 0) > 0:
        status = "partial"
    elif stats.get("files_analyzed", 0) == 0 and stats.get("files_failed", 0) > 0:
        status = "failed"
    else:
        status = "completed"

    errors: list[str] = []
    if error:
        errors.append(error)
    if res.get("failure_reason"):
        errors.append(str(res["failure_reason"]))

    warnings: list[str] = []
    for ff in stats.get("failed_files", []):
        warnings.append(f"Failed file {ff.get('file')}: {ff.get('reason')}")

    # Build artifact metadata
    pkg_name = (
        app.get("package_name")
        or app.get("bundle_identifier")
        or acq.get("package_name")
        or "unknown"
    )
    filename = (
        acq.get("filename")
        or app.get("filename")
        or "unknown"
    )
    sha256 = (
        acq.get("sha256")
        or app.get("sha256")
        or "0" * 64
    )
    source = (
        acq.get("source_type")
        or res.get("input", {}).get("source_type")
        or "direct_apk"
    )
    platform = (
        res.get("platform")
        or acq.get("platform")
        or res.get("input", {}).get("platform")
        or "android"
    )

    candidates = scan_meta.get("candidates") or []
    if not candidates and (static.get("network_indicators") or static.get("api_candidates")):
        from src.demo3.deduplicator import CandidateDeduplicator
        from src.demo3.candidate_model import RawCandidate
        fallback_dedup = CandidateDeduplicator()
        net = static.get("network_indicators") or {}
        for item in net.get("network_urls", []):
            val = item.get("value", "") if isinstance(item, dict) else str(item)
            if val:
                fallback_dedup.add_raw(RawCandidate(
                    type="url",
                    raw_value=val,
                    source_file=item.get("source_file", "unknown") if isinstance(item, dict) else "static_analysis",
                    line_number=item.get("line_number") if isinstance(item, dict) else None,
                    extraction_method=item.get("extraction_method", "network_url_pattern") if isinstance(item, dict) else "network_url_pattern",
                    evidence=val,
                ))
        for item in net.get("domains", []):
            val = item.get("value", "") if isinstance(item, dict) else str(item)
            if val:
                fallback_dedup.add_raw(RawCandidate(
                    type="domain",
                    raw_value=val,
                    source_file=item.get("source_file", "unknown") if isinstance(item, dict) else "static_analysis",
                    line_number=item.get("line_number") if isinstance(item, dict) else None,
                    extraction_method=item.get("extraction_method", "domain_pattern") if isinstance(item, dict) else "domain_pattern",
                    evidence=val,
                ))
        for item in net.get("ip_addresses", []):
            val = item.get("value", "") if isinstance(item, dict) else str(item)
            if val:
                fallback_dedup.add_raw(RawCandidate(
                    type="ip_address",
                    raw_value=val,
                    source_file=item.get("source_file", "unknown") if isinstance(item, dict) else "static_analysis",
                    line_number=item.get("line_number") if isinstance(item, dict) else None,
                    extraction_method=item.get("extraction_method", "ipv4_pattern") if isinstance(item, dict) else "ipv4_pattern",
                    evidence=val,
                ))
        for item in net.get("path_candidates", []):
            val = item.get("value", "") if isinstance(item, dict) else str(item)
            if val:
                fallback_dedup.add_raw(RawCandidate(
                    type="api_path",
                    raw_value=val,
                    source_file=item.get("source_file", "unknown") if isinstance(item, dict) else "static_analysis",
                    line_number=item.get("line_number") if isinstance(item, dict) else None,
                    extraction_method=item.get("extraction_method", "api_path_pattern") if isinstance(item, dict) else "api_path_pattern",
                    evidence=val,
                ))
        for item in static.get("api_candidates", []):
            val = item.get("full_url") or item.get("path") or ""
            if val:
                ctype = "url" if val.startswith("http") else "api_path"
                fallback_dedup.add_raw(RawCandidate(
                    type=ctype,
                    raw_value=val,
                    source_file=item.get("source_file", "unknown.smali"),
                    line_number=item.get("request_line"),
                    extraction_method="fuel_smali_call_context",
                    evidence=f"Fuel.{item.get('method', 'request')}({val})",
                ))
        candidates = [c.to_dict() for c in fallback_dedup.get_canonical_candidates()]

    # Map static findings from vulnerabilities if available
    findings_list: list[dict[str, Any]] = []
    raw_vulns = res.get("vulnerabilities", {}).get("findings", [])
    for v in raw_vulns:
        ev = v.get("evidence")
        src_file = v.get("source_file") or (ev.get("file") if isinstance(ev, dict) else None) or "AndroidManifest.xml"
        findings_list.append({
            "id": v.get("id") or f"finding-{len(findings_list)+1:03d}",
            "rule_id": v.get("rule_id") or v.get("id") or "static_rule",
            "title": v.get("title") or "Static finding",
            "severity": (v.get("severity") or "INFO").upper(),
            "category": v.get("category") or "general",
            "source_file": src_file,
            "evidence": ev or v.get("description") or "",
            "description": v.get("description") or "",
            "recommendation": v.get("recommendation") or "",
        })

    report: dict[str, Any] = {
        "schema_version": "1.0.0",
        "scan": {
            "run_id": run_id,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "errors": errors,
            "warnings": warnings,
        },
        "artifact": {
            "source": source,
            "filename": filename,
            "sha256": sha256,
            "package_name": pkg_name,
            "size_bytes": acq.get("size_bytes"),
            "platform": platform,
        },
        "analysis": {
            "files_discovered": stats.get("files_discovered", 0),
            "files_analyzed": stats.get("files_analyzed", 0),
            "files_skipped": stats.get("files_skipped", 0),
            "files_failed": stats.get("files_failed", 0),
            "failed_files": stats.get("failed_files", []),
        },
        "inventory": {
            "candidate_count": len(candidates),
            "candidates": candidates,
        },
        "static_findings": findings_list,
    }

    return report


def save_baseline_report(
    target_dir: str | Path,
    baseline_dict: dict[str, Any],
) -> Path:
    """Validates baseline report against schema and writes baseline_report.json to target_dir.

    Raises:
        SchemaValidationError: If validation against JSON Schema fails.
    """
    dest_dir = Path(target_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # 1. Strict schema validation
    validate_baseline_report(baseline_dict)

    # 2. Write baseline_report.json
    out_file = dest_dir / "baseline_report.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(baseline_dict, f, indent=2)

    return out_file
