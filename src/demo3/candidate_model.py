"""Structured Data Models for Demo 3 Deterministic Static Analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from typing import Any


@dataclass
class CandidateOccurrence:
    """Represents a single physical observation of a candidate in an artifact."""

    source_file: str
    line_number: int | None
    extraction_method: str
    raw_value: str
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "source_file": self.source_file,
            "extraction_method": self.extraction_method,
            "raw_value": self.raw_value,
            "evidence": self.evidence,
        }
        if self.line_number is not None:
            d["line_number"] = self.line_number
        return d


@dataclass
class RawCandidate:
    """Represents a raw candidate extracted directly by a rule before normalization."""

    type: str
    raw_value: str
    source_file: str
    line_number: int | None = None
    extraction_method: str = "pattern_match"
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CanonicalCandidate:
    """Represents a normalized, deduplicated candidate preserving all occurrences."""

    id: str
    type: str
    value: str
    components: dict[str, Any] = field(default_factory=dict)
    occurrence_count: int = 0
    occurrences: list[CandidateOccurrence] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        candidate_type: str,
        normalized_value: str,
        components: dict[str, Any] | None = None,
    ) -> CanonicalCandidate:
        seed = f"{candidate_type}:{normalized_value}".encode("utf-8")
        cid = f"cand-{hashlib.sha256(seed).hexdigest()[:12]}"
        return cls(
            id=cid,
            type=candidate_type,
            value=normalized_value,
            components=components or {},
            occurrence_count=0,
            occurrences=[],
        )

    def add_occurrence(self, occurrence: CandidateOccurrence) -> None:
        # Check duplicate occurrence in identical file and line
        for existing in self.occurrences:
            if (
                existing.source_file == occurrence.source_file
                and existing.line_number == occurrence.line_number
                and existing.raw_value == occurrence.raw_value
            ):
                return
        self.occurrences.append(occurrence)
        self.occurrence_count = len(self.occurrences)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "components": self.components,
            "occurrence_count": self.occurrence_count,
            "occurrences": [occ.to_dict() for occ in self.occurrences],
        }


@dataclass
class ScanStatistics:
    """Accounting for deterministic file traversal and candidate extraction."""

    files_discovered: int = 0
    files_analyzed: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    failed_files: list[dict[str, str]] = field(default_factory=list)
    raw_candidate_count: int = 0
    canonical_candidate_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_discovered": self.files_discovered,
            "files_analyzed": self.files_analyzed,
            "files_skipped": self.files_skipped,
            "files_failed": self.files_failed,
            "failed_files": self.failed_files,
            "raw_candidate_count": self.raw_candidate_count,
            "canonical_candidate_count": self.canonical_candidate_count,
        }
