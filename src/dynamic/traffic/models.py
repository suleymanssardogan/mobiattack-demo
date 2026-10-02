"""Data models and enums for Dynamic Traffic Capture and Proxy Readiness."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
from typing import Any
import uuid


def utc_now_iso() -> str:
    """Returns current timestamp in strict ISO-8601 UTC format."""
    return datetime.now(timezone.utc).isoformat()


class TrafficReadinessStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class CaptureStatus(str, Enum):
    CREATED = "CREATED"
    STARTING = "STARTING"
    ACTIVE = "ACTIVE"
    STOPPING = "STOPPING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class TrafficErrorCode(str, Enum):
    ADB_NOT_FOUND = "ADB_NOT_FOUND"
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    MITMPROXY_NOT_FOUND = "MITMPROXY_NOT_FOUND"
    PROXY_PORT_IN_USE = "PROXY_PORT_IN_USE"
    PROXY_CONFIGURATION_FAILED = "PROXY_CONFIGURATION_FAILED"
    PROXY_RESTORE_FAILED = "PROXY_RESTORE_FAILED"
    CAPTURE_START_FAILED = "CAPTURE_START_FAILED"
    CAPTURE_STOP_FAILED = "CAPTURE_STOP_FAILED"
    CAPTURE_PROCESS_DIED = "CAPTURE_PROCESS_DIED"
    CAPTURE_TIMEOUT = "CAPTURE_TIMEOUT"
    TRAFFIC_PARSE_FAILED = "TRAFFIC_PARSE_FAILED"
    TRAFFIC_STORAGE_FAILED = "TRAFFIC_STORAGE_FAILED"
    INVALID_CAPTURE_STATE = "INVALID_CAPTURE_STATE"


class TrafficException(Exception):
    """Structured exception for traffic capture and proxy management errors."""

    def __init__(self, error_code: TrafficErrorCode, message: str) -> None:
        super().__init__(f"[{error_code.value}] {message}")
        self.error_code = error_code
        self.message = message


@dataclass
class HttpsInterceptionReadiness:
    ca_certificate_installed: bool = False
    certificate_trust_unknown: bool = True
    pinning_suspected: bool = False
    ca_trust_state: str = "unknown"
    ca_trust_reason: str = "certificate_trust_unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ca_certificate_installed": self.ca_certificate_installed,
            "certificate_trust_unknown": self.certificate_trust_unknown,
            "pinning_suspected": self.pinning_suspected,
            "ca_trust_state": self.ca_trust_state,
            "ca_trust_reason": self.ca_trust_reason,
        }


@dataclass
class ProxyReadinessResult:
    stage: str = "proxy_readiness"
    device_serial: str = ""
    adb_available: bool = False
    capture_backend: str = "mitmproxy"
    backend_available: bool = False
    proxy_host: str = "10.0.2.2"
    proxy_port: int = 8080
    port_available: bool = False
    device_reachable_proxy: bool = False
    https_interception: HttpsInterceptionReadiness = field(default_factory=HttpsInterceptionReadiness)
    status: TrafficReadinessStatus = TrafficReadinessStatus.FAIL
    warnings: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "device_serial": self.device_serial,
            "adb_available": self.adb_available,
            "capture_backend": self.capture_backend,
            "backend_available": self.backend_available,
            "proxy_host": self.proxy_host,
            "proxy_port": self.proxy_port,
            "port_available": self.port_available,
            "device_reachable_proxy": self.device_reachable_proxy,
            "https_interception": self.https_interception.to_dict(),
            "status": self.status.value if isinstance(self.status, TrafficReadinessStatus) else str(self.status),
            "warnings": self.warnings,
            "errors": self.errors,
        }


@dataclass
class HttpRequestModel:
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=utc_now_iso)
    method: str = "GET"
    scheme: str = "http"
    host: str = ""
    port: int = 80
    path: str = "/"
    query: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    body_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "method": self.method,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "headers": self.headers,
            "body": self.body,
            "body_metadata": self.body_metadata,
        }


@dataclass
class HttpResponseModel:
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    timestamp: str = field(default_factory=utc_now_iso)
    body_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "timestamp": self.timestamp,
            "body_metadata": self.body_metadata,
        }


@dataclass
class TrafficTransaction:
    transaction_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    capture_id: str = ""
    session_id: str | None = None
    flow_id: str | None = None
    request: HttpRequestModel = field(default_factory=HttpRequestModel)
    response: HttpResponseModel | None = None
    duration_ms: float = 0.0
    correlation: dict[str, Any] = field(default_factory=dict)
    attribution: dict[str, Any] = field(default_factory=dict)
    scope: str = "UNKNOWN"  # IN_SCOPE, OUT_OF_SCOPE, UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "capture_id": self.capture_id,
            "session_id": self.session_id,
            "flow_id": self.flow_id,
            "request": self.request.to_dict() if self.request else {},
            "response": self.response.to_dict() if self.response else None,
            "duration_ms": self.duration_ms,
            "correlation": self.correlation,
            "attribution": self.attribution,
            "scope": self.scope,
        }


@dataclass
class CaptureSession:
    capture_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    device_serial: str = ""
    backend: str = "mitmproxy"
    proxy_host: str = "10.0.2.2"
    proxy_port: int = 8080
    started_at: str = field(default_factory=utc_now_iso)
    ended_at: str | None = None
    status: CaptureStatus = CaptureStatus.CREATED
    warnings: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture_id": self.capture_id,
            "session_id": self.session_id,
            "device_serial": self.device_serial,
            "backend": self.backend,
            "proxy_host": self.proxy_host,
            "proxy_port": self.proxy_port,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "status": self.status.value if isinstance(self.status, CaptureStatus) else str(self.status),
            "warnings": self.warnings,
            "errors": self.errors,
            "metadata": self.metadata,
        }


@dataclass
class CaptureSummary:
    capture_id: str = ""
    session_id: str = ""
    total_transactions: int = 0
    http_count: int = 0
    https_count: int = 0
    domains: list[str] = field(default_factory=list)
    correlated_flow_count: int = 0
    in_scope_count: int = 0
    proxy_restored: bool = False
    http_visibility: str = "available"
    https_visibility: str = "unavailable"
    https_visibility_reason: str = "certificate_trust_unknown"
    ca_trust_state: str = "unknown"
    ca_trust_reason: str = "certificate_trust_unknown"
    verified_https_transactions: int = 0
    tls_failure_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture_id": self.capture_id,
            "session_id": self.session_id,
            "total_transactions": self.total_transactions,
            "http_count": self.http_count,
            "https_count": self.https_count,
            "domains": self.domains,
            "correlated_flow_count": self.correlated_flow_count,
            "in_scope_count": self.in_scope_count,
            "proxy_restored": self.proxy_restored,
            "http_visibility": self.http_visibility,
            "https_visibility": self.https_visibility,
            "https_visibility_reason": self.https_visibility_reason,
            "ca_trust_state": self.ca_trust_state,
            "ca_trust_reason": self.ca_trust_reason,
            "verified_https_transactions": self.verified_https_transactions,
            "tls_failure_count": self.tls_failure_count,
        }


class CorrelationStatus(str, Enum):
    AVAILABLE = "available"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


@dataclass
class ActionTrafficEvidence:
    """Compact correlation evidence between a UI action and HTTP transactions observed during its window."""

    action_id: str = ""
    occurrence: int = 1
    source_node_id: str = ""
    target_node_id: str | None = None
    correlation_status: str = CorrelationStatus.AVAILABLE.value
    transaction_count: int = 0
    transaction_ids: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    status_codes: list[int] = field(default_factory=list)
    http_visibility: str = "available"
    https_visibility: str = "unavailable"
    https_visibility_reason: str = ""
    correlation_note: str = "traffic observed during action window"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "occurrence": self.occurrence,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "correlation_status": self.correlation_status,
            "transaction_count": self.transaction_count,
            "transaction_ids": self.transaction_ids,
            "methods": self.methods,
            "hosts": self.hosts,
            "status_codes": self.status_codes,
            "http_visibility": self.http_visibility,
            "https_visibility": self.https_visibility,
            "https_visibility_reason": self.https_visibility_reason,
            "correlation_note": self.correlation_note,
            "error": self.error,
        }


@dataclass
class TrafficEvidenceArtifact:
    """Internal correlation artifact schema for dynamic/traffic_evidence.json."""

    schema_version: str = "1.0"
    session_id: str = ""
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)
    actions: list[ActionTrafficEvidence] = field(default_factory=list)

    def record_action_evidence(self, evidence: ActionTrafficEvidence, file_path: Path | str) -> None:
        """Appends or updates action traffic correlation record in-place and saves atomically."""
        self.updated_at = utc_now_iso()
        for idx, existing in enumerate(self.actions):
            if existing.action_id == evidence.action_id and existing.occurrence == evidence.occurrence:
                self.actions[idx] = evidence
                self.save_atomic(file_path)
                return

        self.actions.append(evidence)
        self.save_atomic(file_path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "actions": [a.to_dict() for a in self.actions],
        }

    def save_atomic(self, file_path: Path | str) -> None:
        """Atomically persists the artifact to disk via a temporary file."""
        target_path = Path(file_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = target_path.with_suffix(f".tmp.{uuid.uuid4().hex[:8]}")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, target_path)

    @classmethod
    def load_or_create(cls, file_path: Path | str, session_id: str = "") -> TrafficEvidenceArtifact:
        """Loads an existing traffic evidence file or creates a new empty artifact."""
        target_path = Path(file_path)
        if not target_path.is_file():
            return cls(session_id=session_id)

        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            actions = []
            for a in data.get("actions", []):
                actions.append(
                    ActionTrafficEvidence(
                        action_id=a.get("action_id", ""),
                        occurrence=a.get("occurrence", 1),
                        source_node_id=a.get("source_node_id", ""),
                        target_node_id=a.get("target_node_id"),
                        correlation_status=a.get("correlation_status", CorrelationStatus.AVAILABLE.value),
                        transaction_count=a.get("transaction_count", 0),
                        transaction_ids=a.get("transaction_ids", []),
                        methods=a.get("methods", []),
                        hosts=a.get("hosts", []),
                        status_codes=a.get("status_codes", []),
                        http_visibility=a.get("http_visibility", "available"),
                        https_visibility=a.get("https_visibility", "unavailable"),
                        https_visibility_reason=a.get("https_visibility_reason", ""),
                        correlation_note=a.get("correlation_note", "traffic observed during action window"),
                        error=a.get("error"),
                    )
                )
            return cls(
                schema_version=data.get("schema_version", "1.0"),
                session_id=data.get("session_id", session_id),
                created_at=data.get("created_at", utc_now_iso()),
                updated_at=data.get("updated_at", utc_now_iso()),
                actions=actions,
            )
        except Exception:
            return cls(session_id=session_id)


def create_action_traffic_evidence(
    action_id: str,
    source_node_id: str,
    target_node_id: str | None = None,
    occurrence: int = 1,
    transactions: list[TrafficTransaction] | None = None,
    correlation_status: str | None = None,
    http_visibility: str = "available",
    https_visibility: str = "unavailable",
    https_visibility_reason: str = "",
    error: str | None = None,
) -> ActionTrafficEvidence:
    """Builds a compact ActionTrafficEvidence record from a list of transactions taking visibility into account."""
    tx_list = transactions or []
    tx_ids: list[str] = []
    methods: set[str] = set()
    hosts: set[str] = set()
    status_codes: list[int] = []

    for tx in tx_list:
        if tx.transaction_id:
            tx_ids.append(tx.transaction_id)
        if tx.request and tx.request.method:
            methods.add(tx.request.method.upper())
        if tx.request and tx.request.host:
            hosts.add(tx.request.host)
        if tx.response and tx.response.status_code:
            status_codes.append(tx.response.status_code)

    # Determine correlation status and honest visibility-aware correlation note
    if error or correlation_status == CorrelationStatus.UNAVAILABLE.value:
        status = CorrelationStatus.UNAVAILABLE.value if correlation_status is None else correlation_status
        note = error or "Traffic capture unavailable"
    elif tx_list:
        # Transactions observed during window
        status = correlation_status or (
            CorrelationStatus.AVAILABLE.value if https_visibility == "available" else CorrelationStatus.PARTIAL.value
        )
        note = "traffic observed during action window"
    else:
        # Zero transactions observed
        if https_visibility == "available":
            status = correlation_status or CorrelationStatus.AVAILABLE.value
            note = "No traffic was observed during the action window."
        else:
            status = correlation_status or CorrelationStatus.PARTIAL.value
            note = f"No visible HTTP transactions were captured during the action window; HTTPS visibility was {https_visibility}."
            if https_visibility_reason:
                note += f" ({https_visibility_reason})"

    return ActionTrafficEvidence(
        action_id=action_id,
        occurrence=occurrence,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        correlation_status=status,
        transaction_count=len(tx_list),
        transaction_ids=tx_ids,
        methods=sorted(list(methods)),
        hosts=sorted(list(hosts)),
        status_codes=status_codes,
        http_visibility=http_visibility,
        https_visibility=https_visibility,
        https_visibility_reason=https_visibility_reason,
        correlation_note=note,
        error=error,
    )

