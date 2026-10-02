"""Data models and enums for Static <-> Dynamic API Correlation (Week 2 — Day 7 Task 7.1)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any
import uuid


def utc_now_iso() -> str:
    """Returns current timestamp in strict ISO-8601 UTC format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class MatchType(str, Enum):
    """Deterministic match classification vocabulary."""
    EXACT = "exact"
    TEMPLATE = "template"
    HOST_PATH = "host_path"
    METHOD_MISMATCH = "method_mismatch"
    STATIC_ONLY = "static_only"
    DYNAMIC_ONLY = "dynamic_only"


class MatchConfidence(str, Enum):
    """Categorical evidence strength."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


_HOST_PATH_RE = re.compile(r"/(?:Users|home)/[^/\s]+/[^\s'\"]*")
_OPT_PATH_RE = re.compile(r"/opt/homebrew/[^\s'\"]*")
_TMP_PATH_RE = re.compile(r"/(?:tmp|private/tmp|var/folders)/[^\s'\"]*")


def sanitize_provenance_paths(val: Any) -> Any:
    """Recursively sanitizes scanner host filesystem paths."""
    if isinstance(val, dict):
        return {k: sanitize_provenance_paths(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize_provenance_paths(item) for item in val]
    elif isinstance(val, str):
        cleaned = _HOST_PATH_RE.sub("<host_path>", val)
        cleaned = _OPT_PATH_RE.sub("<host_path>", cleaned)
        cleaned = _TMP_PATH_RE.sub("<host_path>", cleaned)
        return cleaned
    return val


def generate_deterministic_correlation_id(
    static_candidate_id: str | None,
    host: str,
    path: str,
    match_type: str,
    method: str | None = None,
    scheme: str | None = None,
    port: int | None = None,
) -> str:
    """Computes a stable, deterministic correlation ID from key matching dimensions."""
    key = f"{static_candidate_id or ''}|{host.strip().lower()}|{path.strip()}|{match_type}|{method or ''}"
    key += f"|{scheme or ''}|{port or ''}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"corr_{digest}"


@dataclass
class ApiCorrelationEntry:
    """Evidence-backed correlation entry between static API candidates and dynamic traffic."""

    correlation_id: str
    match_type: str
    confidence: str
    host: str
    path: str
    static_candidate_id: str | None = None
    transaction_ids: list[str] = field(default_factory=list)
    static_method: str | None = None
    observed_methods: list[str] = field(default_factory=list)
    observed_status_codes: list[int] = field(default_factory=list)
    first_observed_at: str | None = None
    last_observed_at: str | None = None
    observation_count: int = 0
    observed_action_ids: list[str] = field(default_factory=list)
    observed_query_keys: list[str] = field(default_factory=list)
    route_context: list[dict[str, Any]] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    notes: str | None = None
    scheme: str | None = None
    port: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Returns JSON-serializable dictionary without request/response bodies or sensitive data."""
        data: dict[str, Any] = {
            "correlation_id": self.correlation_id,
            "match_type": self.match_type,
            "confidence": self.confidence,
            "host": self.host,
            "scheme": self.scheme,
            "port": self.port,
            "path": self.path,
            "static_candidate_id": self.static_candidate_id,
            "transaction_ids": list(self.transaction_ids),
            "static_method": self.static_method,
            "observed_methods": list(self.observed_methods),
            "observed_status_codes": list(self.observed_status_codes),
            "first_observed_at": self.first_observed_at,
            "last_observed_at": self.last_observed_at,
            "observation_count": self.observation_count,
            "observed_action_ids": list(self.observed_action_ids),
            "observed_query_keys": list(self.observed_query_keys),
            "route_context": sanitize_provenance_paths(self.route_context),
            "provenance": sanitize_provenance_paths(self.provenance),
        }
        if self.notes:
            data["notes"] = sanitize_provenance_paths(self.notes)
        return data


@dataclass
class ApiCorrelationSummary:
    """Summary statistics and traffic visibility context for API correlation."""

    static_candidate_count: int = 0
    dynamic_endpoint_count: int = 0
    correlated_count: int = 0
    static_only_count: int = 0
    dynamic_only_count: int = 0
    http_visibility: str = "available"
    https_visibility: str = "unavailable"
    https_visibility_reason: str = "certificate_trust_unknown"
    visibility_note: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "static_candidate_count": self.static_candidate_count,
            "dynamic_endpoint_count": self.dynamic_endpoint_count,
            "correlated_count": self.correlated_count,
            "static_only_count": self.static_only_count,
            "dynamic_only_count": self.dynamic_only_count,
            "http_visibility": self.http_visibility,
            "https_visibility": self.https_visibility,
            "https_visibility_reason": self.https_visibility_reason,
        }
        if self.visibility_note:
            data["visibility_note"] = self.visibility_note
        if self.notes:
            data["notes"] = list(self.notes)
        return data


@dataclass
class ApiCorrelationResult:
    """Artifact schema for dynamic/api_correlation.json."""

    schema_version: str = "1.0"
    session_id: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    summary: ApiCorrelationSummary = field(default_factory=ApiCorrelationSummary)
    correlations: list[ApiCorrelationEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "summary": self.summary.to_dict(),
            "correlations": [c.to_dict() for c in self.correlations],
        }

    def save_atomic(self, file_path: Path | str) -> str:
        """Atomically saves api_correlation.json via temporary file replace."""
        target_path = Path(file_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target_path.with_suffix(f".tmp.{uuid.uuid4().hex[:8]}")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, target_path)
        return str(target_path)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ApiCorrelationResult:
        """Parses dictionary into ApiCorrelationResult."""
        if not isinstance(data, dict):
            raise ValueError("Corrupt API correlation data: expected dict")

        schema_ver = data.get("schema_version", "1.0")
        session_id = data.get("session_id", "")
        created_at = data.get("created_at", utc_now_iso())

        sum_dict = data.get("summary", {})
        if not isinstance(sum_dict, dict):
            raise ValueError("Corrupt API correlation data: summary must be a dict")

        summary = ApiCorrelationSummary(
            static_candidate_count=sum_dict.get("static_candidate_count", 0),
            dynamic_endpoint_count=sum_dict.get("dynamic_endpoint_count", 0),
            correlated_count=sum_dict.get("correlated_count", 0),
            static_only_count=sum_dict.get("static_only_count", 0),
            dynamic_only_count=sum_dict.get("dynamic_only_count", 0),
            http_visibility=sum_dict.get("http_visibility", "available"),
            https_visibility=sum_dict.get("https_visibility", "unavailable"),
            https_visibility_reason=sum_dict.get("https_visibility_reason", "certificate_trust_unknown"),
            visibility_note=sum_dict.get("visibility_note"),
            notes=sum_dict.get("notes", []),
        )

        correlations: list[ApiCorrelationEntry] = []
        for c in data.get("correlations", []):
            if not isinstance(c, dict):
                raise ValueError("Corrupt API correlation data: correlation entry must be a dict")
            correlations.append(
                ApiCorrelationEntry(
                    correlation_id=c.get("correlation_id", ""),
                    match_type=c.get("match_type", MatchType.EXACT.value),
                    confidence=c.get("confidence", MatchConfidence.HIGH.value),
                    host=c.get("host", ""),
                    path=c.get("path", ""),
                    scheme=c.get("scheme"),
                    port=c.get("port"),
                    static_candidate_id=c.get("static_candidate_id"),
                    transaction_ids=c.get("transaction_ids", []),
                    static_method=c.get("static_method"),
                    observed_methods=c.get("observed_methods", []),
                    observed_status_codes=c.get("observed_status_codes", []),
                    first_observed_at=c.get("first_observed_at"),
                    last_observed_at=c.get("last_observed_at"),
                    observation_count=c.get("observation_count", 0),
                    observed_action_ids=c.get("observed_action_ids", []),
                    observed_query_keys=c.get("observed_query_keys", []),
                    route_context=c.get("route_context", []),
                    provenance=c.get("provenance", {}),
                    notes=c.get("notes"),
                )
            )

        return cls(
            schema_version=schema_ver,
            session_id=session_id,
            created_at=created_at,
            summary=summary,
            correlations=correlations,
        )

    @classmethod
    def load(cls, file_path: Path | str) -> ApiCorrelationResult:
        """Loads and parses api_correlation.json from disk."""
        target_path = Path(file_path)
        if not target_path.is_file():
            raise FileNotFoundError(f"API correlation file not found at {file_path}")

        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Corrupt JSON in API correlation artifact {file_path}: {exc}") from exc

        return cls.from_dict(data)
