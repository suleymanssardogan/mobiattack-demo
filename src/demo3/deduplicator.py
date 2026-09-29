"""Deterministic Deduplication preserving complete provenance and evidence."""

from __future__ import annotations

from typing import Iterable

from src.demo3.candidate_model import (
    CandidateOccurrence,
    CanonicalCandidate,
    RawCandidate,
)
from src.demo3.normalizer import normalize_candidate


class CandidateDeduplicator:
    """Aggregates raw candidate occurrences into deduplicated canonical candidates."""

    def __init__(self) -> None:
        self._canonical_map: dict[tuple[str, str], CanonicalCandidate] = {}

    def add_raw(self, raw: RawCandidate) -> None:
        canon_type, canon_value, components = normalize_candidate(raw)
        key = (canon_type, canon_value)

        if key not in self._canonical_map:
            self._canonical_map[key] = CanonicalCandidate.create(
                candidate_type=canon_type,
                normalized_value=canon_value,
                components=components,
            )

        candidate = self._canonical_map[key]
        occurrence = CandidateOccurrence(
            source_file=raw.source_file,
            line_number=raw.line_number,
            extraction_method=raw.extraction_method,
            raw_value=raw.raw_value,
            evidence=raw.evidence or raw.raw_value,
        )
        candidate.add_occurrence(occurrence)

    def add_many(self, raws: Iterable[RawCandidate]) -> None:
        for r in raws:
            self.add_raw(r)

    def get_canonical_candidates(self) -> list[CanonicalCandidate]:
        """Returns sorted, deterministic list of canonical candidates with sorted occurrences."""
        candidates = list(self._canonical_map.values())
        # Sort candidates deterministically by type, then canonical value
        candidates.sort(key=lambda c: (c.type, c.value))

        for cand in candidates:
            # Sort occurrences deterministically by source_file, then line_number
            cand.occurrences.sort(
                key=lambda occ: (occ.source_file, occ.line_number if occ.line_number is not None else -1, occ.raw_value)
            )
            cand.occurrence_count = len(cand.occurrences)

        return candidates
