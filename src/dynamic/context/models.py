"""Evidence-only endpoint context artifact models."""
from __future__ import annotations

from src.persistence import write_json_atomic

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any


def generate_endpoint_context_id(host: str, path: str, method: str | None,
                                 observed_methods: list[str] | None = None,
                                 correlation_id: str = "", *, scheme: str | None = None,
                                 port: int | None = None) -> str:
    """Identity only: protocol, authority, method and literal/template path."""
    from src.dynamic.correlation.api_correlator import normalize_transport, normalize_path, normalize_method
    host, scheme, port = normalize_transport(host, scheme, port)
    identity = [scheme, host, port, normalize_method(method), normalize_path(path)]
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
    port: int | None = None

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
        target = write_json_atomic(file_path, self.to_dict())
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
