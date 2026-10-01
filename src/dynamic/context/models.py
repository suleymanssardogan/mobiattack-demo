"""Evidence-only endpoint context artifact models."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import uuid
from typing import Any


def generate_endpoint_context_id(host: str, path: str, method: str | None,
                                 observed_methods: list[str], correlation_id: str) -> str:
    """Preserve correlation identity; observations never regroup endpoints."""
    identity = [host, path, method or sorted(set(observed_methods)), correlation_id]
    digest = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()[:16]
    return f"ctx_{digest}"


@dataclass
class EndpointContext:
    endpoint_context_id: str
    host: str
    path: str
    scheme: str | None = None
    methods: list[str] = field(default_factory=list)
    static: dict[str, Any] = field(default_factory=dict)
    dynamic: dict[str, Any] = field(default_factory=dict)
    request: dict[str, Any] = field(default_factory=dict)
    response: dict[str, Any] = field(default_factory=dict)
    auth: dict[str, Any] = field(default_factory=dict)
    action_context: list[dict[str, Any]] = field(default_factory=list)
    route_context: list[dict[str, Any]] = field(default_factory=list)
    runtime_context: dict[str, Any] = field(default_factory=dict)
    visibility: dict[str, Any] = field(default_factory=dict)
    evidence_refs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EndpointContextArtifact:
    session_id: str = ""
    schema_version: str = "1.0"
    summary: dict[str, int] = field(default_factory=dict)
    endpoints: list[EndpointContext] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save_atomic(self, file_path: str | Path) -> str:
        target = Path(file_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(f".tmp.{uuid.uuid4().hex}")
        try:
            temporary.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        return str(target)

    @classmethod
    def load(cls, file_path: str | Path) -> EndpointContextArtifact:
        try:
            data = json.loads(Path(file_path).read_text(encoding="utf-8"))
            if (not isinstance(data, dict) or data.get("schema_version") != "1.0"
                    or not isinstance(data.get("summary"), dict)
                    or not isinstance(data.get("endpoints"), list)):
                raise ValueError("Invalid endpoint context schema")
            return cls(session_id=data.get("session_id", ""), summary=data["summary"],
                       endpoints=[EndpointContext(**entry) for entry in data["endpoints"]])
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"Corrupt endpoint context artifact: {exc}") from exc
