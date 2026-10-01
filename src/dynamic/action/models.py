"""Data models and schemas for Android Action Execution (Week 1 — Day 5 Task 5.2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any

_HOST_PATH_RE = re.compile(r"/(?:Users|home)/[^/\s]+/[^\s'\"]*")
_OPT_PATH_RE = re.compile(r"/opt/homebrew/[^\s'\"]*")
_TMP_PATH_RE = re.compile(r"/(?:tmp|private/tmp|var/folders)/[^\s'\"]*")


def utc_now_iso() -> str:
    """Returns current UTC timestamp in strict ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def sanitize_str(val: str | None) -> str | None:
    """Sanitizes host filesystem paths from a string."""
    if val is None:
        return None
    cleaned = _HOST_PATH_RE.sub("<host_path>", val)
    cleaned = _OPT_PATH_RE.sub("<host_path>", cleaned)
    cleaned = _TMP_PATH_RE.sub("<host_path>", cleaned)
    return cleaned


def sanitize_value(val: Any) -> Any:
    """Recursively sanitizes values for metadata output."""
    if isinstance(val, dict):
        return {k: sanitize_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize_value(item) for item in val]
    elif isinstance(val, str):
        return sanitize_str(val)
    return val


class ActionType(str, Enum):
    """Supported interactive action types in V1."""
    CLICK = "click"
    INPUT = "input"
    BACK = "back"


class ActionExecutionStatus(str, Enum):
    """Execution status for an action attempt."""
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


class ActionErrorCode(str, Enum):
    """Structured error codes for action execution failures."""
    INVALID_ACTION = "INVALID_ACTION"
    INVALID_BOUNDS = "INVALID_BOUNDS"
    ADB_COMMAND_FAILED = "ADB_COMMAND_FAILED"
    ACTION_TIMEOUT = "ACTION_TIMEOUT"
    UNSUPPORTED_ACTION_TYPE = "UNSUPPORTED_ACTION_TYPE"
    DEVICE_UNAVAILABLE = "DEVICE_UNAVAILABLE"


@dataclass
class ActionExecutionResult:
    """Structured result of executing a single UI action on a device."""

    action_id: str
    action_type: str
    status: str
    started_at: str
    completed_at: str
    attempts: int = 1
    error_code: str | None = None
    message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        """Convenience property for checking execution success."""
        return self.status == ActionExecutionStatus.SUCCEEDED.value

    def to_dict(self) -> dict[str, Any]:
        """Serializes result to dictionary, strictly enforcing secret and path sanitization."""
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "attempts": self.attempts,
            "error_code": self.error_code,
            "message": sanitize_str(self.message),
            "metadata": sanitize_value(self.metadata),
        }

    def to_timeline_metadata(self) -> dict[str, Any]:
        """Produces compact, privacy-safe metadata for ACTION_EXECUTED timeline events."""
        meta: dict[str, Any] = {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "status": self.status,
            "attempts": self.attempts,
        }
        if self.error_code:
            meta["error_code"] = self.error_code
        if self.message:
            meta["message"] = sanitize_str(self.message)

        # Include safe metadata (e.g. coordinates, resource_id, input_length)
        for k, v in self.metadata.items():
            if k in ("input_text", "password", "secret", "raw_text", "text"):
                continue
            meta[k] = sanitize_value(v)

        return meta

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActionExecutionResult:
        """Deserializes ActionExecutionResult from dictionary."""
        return cls(
            action_id=data["action_id"],
            action_type=data.get("action_type", "click"),
            status=data.get("status", ActionExecutionStatus.FAILED.value),
            started_at=data.get("started_at", utc_now_iso()),
            completed_at=data.get("completed_at", utc_now_iso()),
            attempts=data.get("attempts", 1),
            error_code=data.get("error_code"),
            message=data.get("message"),
            metadata=data.get("metadata", {}),
        )
