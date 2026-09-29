"""Deterministic Static Scanner for Demo 3.

Orchestrates deterministic walking, candidate extraction, normalization, and deduplication.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.demo3.candidate_model import (
    CanonicalCandidate,
    RawCandidate,
    ScanStatistics,
)
from src.demo3.deduplicator import CandidateDeduplicator
from src.demo3.file_walker import deterministic_walk
from src.demo3.pattern_extractor import extract_candidates_from_text
from src.api_candidate_extractor import extract_api_candidates


def scan_artifacts_deterministically(
    analysis_root: str | Path,
    include_fuel_smali: bool = True,
) -> dict[str, Any]:
    """Deterministically extracts, normalizes, and deduplicates candidates from analysis_root.

    Args:
        analysis_root: Path to the decoded APK / artifact root (e.g. apktool_out).
        include_fuel_smali: Whether to also run Smali Fuel call-context analysis.

    Returns:
        Dictionary with:
            - status: "completed" | "partial" | "failed"
            - statistics: ScanStatistics dict
            - candidate_count: int
            - candidates: list[dict]
            - failed_files: list[dict]
    """
    root_path = Path(analysis_root).resolve()
    stats = ScanStatistics()
    deduplicator = CandidateDeduplicator()

    raw_candidates_count = 0

    try:
        for fpath, rel_path in deterministic_walk(root_path, stats):
            try:
                with fpath.open("r", encoding="utf-8", errors="replace") as f:
                    for line_num, line in enumerate(f, start=1):
                        line_str = line.strip()
                        if not line_str:
                            continue
                        for raw_cand in extract_candidates_from_text(line, rel_path, line_num):
                            deduplicator.add_raw(raw_cand)
                            raw_candidates_count += 1
            except Exception as exc:
                stats.files_failed += 1
                stats.failed_files.append({
                    "file": rel_path,
                    "reason": f"Scan read error: {type(exc).__name__}: {exc}",
                })
    except Exception as exc:
        stats.files_failed += 1
        stats.failed_files.append({
            "file": str(analysis_root),
            "reason": f"Traversal fatal error: {type(exc).__name__}: {exc}",
        })

    # Integrate Smali Fuel call-context API candidates if enabled and root exists
    if include_fuel_smali and root_path.is_dir():
        try:
            fuel_res = extract_api_candidates(root_path)
            for item in fuel_res.get("api_candidates", []):
                val = item.get("full_url") or item.get("path") or ""
                if not val:
                    continue
                ctype = "url" if (val.startswith("http://") or val.startswith("https://")) else "api_path"
                ev_data = item.get("evidence", {})
                ev_str = f"Fuel.{item.get('method', 'request')}({val}) [req_line={item.get('request_line')}]"
                raw_cand = RawCandidate(
                    type=ctype,
                    raw_value=val,
                    source_file=item.get("source_file", "unknown.smali"),
                    line_number=item.get("request_line"),
                    extraction_method="fuel_smali_call_context",
                    evidence=ev_str,
                    metadata=item,
                )
                deduplicator.add_raw(raw_cand)
                raw_candidates_count += 1
        except Exception:
            pass

    canonical_candidates = deduplicator.get_canonical_candidates()
    stats.raw_candidate_count = raw_candidates_count
    stats.canonical_candidate_count = len(canonical_candidates)

    # Determine status: completed vs partial vs failed
    if stats.files_analyzed == 0 and stats.files_failed > 0:
        status = "failed"
    elif stats.files_failed > 0:
        status = "partial"
    else:
        status = "completed"

    return {
        "status": status,
        "statistics": stats.to_dict(),
        "candidate_count": len(canonical_candidates),
        "candidates": [c.to_dict() for c in canonical_candidates],
        "failed_files": stats.failed_files,
    }
