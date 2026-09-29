"""Demo 3: Deterministic Static Extraction, Normalization, Deduplication and Baseline Reporting."""

from src.demo3.candidate_model import (
    CandidateOccurrence,
    CanonicalCandidate,
    RawCandidate,
    ScanStatistics,
)
from src.demo3.deduplicator import CandidateDeduplicator
from src.demo3.file_walker import deterministic_walk
from src.demo3.normalizer import (
    clean_extraction_artifacts,
    normalize_candidate,
    normalize_domain,
    normalize_ip,
    normalize_path,
    normalize_url,
)
from src.demo3.pattern_extractor import extract_candidates_from_text
from src.demo3.scanner import scan_artifacts_deterministically
from src.demo3.schema_validator import SchemaValidationError, validate_baseline_report
from src.demo3.baseline_reporter import build_baseline_report, save_baseline_report

__all__ = [
    "CandidateOccurrence",
    "CanonicalCandidate",
    "RawCandidate",
    "ScanStatistics",
    "CandidateDeduplicator",
    "deterministic_walk",
    "clean_extraction_artifacts",
    "normalize_candidate",
    "normalize_domain",
    "normalize_ip",
    "normalize_path",
    "normalize_url",
    "extract_candidates_from_text",
    "scan_artifacts_deterministically",
    "SchemaValidationError",
    "validate_baseline_report",
    "build_baseline_report",
    "save_baseline_report",
]
