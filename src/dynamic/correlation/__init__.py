"""Static <-> Dynamic API Correlation module (Week 2 — Day 7 Task 7.1)."""

from src.dynamic.correlation.api_correlator import (
    correlate_static_dynamic_apis,
    match_paths,
    normalize_host,
    normalize_method,
    normalize_path,
)
from src.dynamic.correlation.models import (
    ApiCorrelationEntry,
    ApiCorrelationResult,
    ApiCorrelationSummary,
    MatchConfidence,
    MatchType,
    generate_deterministic_correlation_id,
)

__all__ = [
    "correlate_static_dynamic_apis",
    "match_paths",
    "normalize_host",
    "normalize_method",
    "normalize_path",
    "ApiCorrelationEntry",
    "ApiCorrelationResult",
    "ApiCorrelationSummary",
    "MatchConfidence",
    "MatchType",
    "generate_deterministic_correlation_id",
]
