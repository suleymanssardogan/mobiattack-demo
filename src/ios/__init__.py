"""iOS Static Analysis Pipeline for MobiAttack V2.

Provides deterministic, evidence-based static package analysis for iOS IPA archives.
"""

from __future__ import annotations

__all__ = [
    "IpaExtractionError",
    "extract_ipa",
]

from src.ios.ipa_extractor import IpaExtractionError, extract_ipa
