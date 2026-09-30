"""Data models, enums, and schemas for Dynamic Session & Flow Recording."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid


def utc_now_iso() -> str:
    """Returns current timestamp in strict ISO-8601 UTC format."""
    return datetime.now(timezone.utc).isoformat()


class SessionStatus(str, Enum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"
    FAILED = "FAILED"


class FlowStatus(str, Enum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"
    FAILED = "FAILED"


class EventType(str, Enum):
    USER_ACTION = "USER_ACTION"
    SYSTEM_EVENT = "SYSTEM_EVENT"
    MARKER = "MARKER"
    NOTE = "NOTE"


class SessionErrorCode(str, Enum):
    SESSION_NOT_ACTIVE = "SESSION_NOT_ACTIVE"
    SESSION_ALREADY_COMPLETED = "SESSION_ALREADY_COMPLETED"
    FLOW_NOT_ACTIVE = "FLOW_NOT_ACTIVE"
    FLOW_ALREADY_COMPLETED = "FLOW_ALREADY_COMPLETED"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    PREFLIGHT_FAILED = "PREFLIGHT_FAILED"
    STORAGE_WRITE_FAILED = "STORAGE_WRITE_FAILED"
    INVALID_EVENT = "INVALID_EVENT"


class SessionException(Exception):
    """Structured exception for dynamic session and flow recording errors."""

    def __init__(self, error_code: SessionErrorCode, message: str) -> None:
        super().__init__(f"[{error_code.value}] {message}")
        self.error_code = error_code
        self.message = message


@dataclass
class TimelineEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: EventType = EventType.USER_ACTION
    name: str = ""
    timestamp: str = field(default_factory=utc_now_iso)
    metadata: dict[str, Any] = field(default_factory=dict)
    flow_id: str | None = None
    session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "type": self.type.value if isinstance(self.type, EventType) else str(self.type),
            "name": self.name,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "flow_id": self.flow_id,
            "session_id": self.session_id,
        }


@dataclass
class TargetFlow:
    flow_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    status: FlowStatus = FlowStatus.CREATED
    started_at: str = field(default_factory=utc_now_iso)
    ended_at: str | None = None
    events: list[TimelineEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value if isinstance(self.status, FlowStatus) else str(self.status),
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "events": [e.to_dict() for e in self.events],
        }


@dataclass
class DynamicSession:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    stage: str = "dynamic_session"
    package_name: str = ""
    device_serial: str = ""
    preflight_status: str = "UNKNOWN"
    started_at: str = field(default_factory=utc_now_iso)
    ended_at: str | None = None
    status: SessionStatus = SessionStatus.CREATED
    flows: list[TargetFlow] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Returns normalized session dictionary matching project standard."""
        return {
            "session_id": self.session_id,
            "stage": self.stage,
            "package_name": self.package_name,
            "device_serial": self.device_serial,
            "preflight_status": self.preflight_status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "status": self.status.value if isinstance(self.status, SessionStatus) else str(self.status),
            "flows": [f.to_dict() for f in self.flows],
            "warnings": self.warnings,
            "errors": self.errors,
            "metadata": self.metadata,
        }
