"""Data models and enums for Dynamic Traffic Capture and Proxy Readiness."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "ca_certificate_installed": self.ca_certificate_installed,
            "certificate_trust_unknown": self.certificate_trust_unknown,
            "pinning_suspected": self.pinning_suspected,
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
        }
