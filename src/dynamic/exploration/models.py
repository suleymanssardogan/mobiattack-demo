"""Data models and configurations for Bounded Dynamic Exploration (Week 1 — Day 5 Task 5.3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any

from src.dynamic.route.models import ActionStatus, DiscoveredAction

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


DESTRUCTIVE_KEYWORDS: set[str] = {
    "delete",
    "remove account",
    "uninstall",
    "purchase",
    "buy",
    "pay",
    "confirm payment",
    "sil",
    "hesabı sil",
    "kaldır",
    "satın al",
    "öde",
}


def is_destructive_action(action: DiscoveredAction) -> bool:
    """Detects potentially destructive actions based on a conservative label denylist."""
    text = (action.text or "").lower()
    desc = (action.content_desc or "").lower()
    res_id = (action.resource_id or "").lower()
    combined = f"{text} {desc} {res_id}"
    return any(kw in combined for kw in DESTRUCTIVE_KEYWORDS)


def is_safe_clickable_action(action: DiscoveredAction) -> bool:
    """Verifies that an action candidate is a safe, unattempted click interaction."""
    if action.action_type != "click":
        return False
    if action.status != ActionStatus.DISCOVERED.value:
        return False
    if is_destructive_action(action):
        return False
    return True


ALLOWED_PERMISSION_PACKAGES: frozenset[str] = frozenset({
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
})


def is_allowed_system_dialog(target: Any) -> bool:
    """Checks whether an observation, route node, or package name represents an explicitly allowed system dialog.

    Allowed dialogs currently include standard Android runtime permission controllers.
    """
    if isinstance(target, str):
        pkg = target.strip().lower()
        return pkg in ALLOWED_PERMISSION_PACKAGES

    if not getattr(target, "is_dialog_or_system", False):
        return False

    pkg = (
        getattr(target, "foreground_package", None)
        or getattr(target, "package_name", None)
        or ""
    ).strip().lower()
    return pkg in ALLOWED_PERMISSION_PACKAGES


def is_allowed_exploration_surface(target: Any) -> bool:
    """Checks whether autonomous safe click exploration is allowed on the observed screen.

    Returns True for:
    - Target application (is_target_package == True)
    - Explicitly allowed system dialogs (e.g. runtime permission controllers)

    Returns False for:
    - Generic SystemUI, Android Settings, Package Installer
    - External/unrelated third-party applications
    """
    if getattr(target, "is_target_package", False):
        return True
    return is_allowed_system_dialog(target)


class ExplorationStatus(str, Enum):
    """Overall outcome of the exploration loop run."""
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class StopReason(str, Enum):
    """Specific condition that terminated the exploration loop."""
    COMPLETED = "completed"
    NO_ACTIONS = "no_actions"
    MAX_STEPS = "max_steps"
    MAX_DEPTH = "max_depth"
    DEADLINE = "deadline"
    EXTERNAL_PACKAGE = "external_package"
    SYSTEM_UI_BOUNDARY = "system_ui_boundary"
    OBSERVATION_FAILED = "observation_failed"
    EXECUTOR_FAILED = "executor_failed"


@dataclass
class ExplorationLimits:
    """Configurable boundaries for autonomous exploration."""

    max_steps: int = 10
    max_depth: int = 3
    deadline_seconds: float = 60.0
    action_settle_delay: float = 0.2
    allow_system_dialogs: bool = True
    stop_on_external_package: bool = True


@dataclass
class ExplorationResult:
    """Comprehensive summary of a bounded exploration run."""

    status: str
    stop_reason: str
    steps_attempted: int = 0
    actions_succeeded: int = 0
    actions_failed: int = 0
    screens_observed: int = 0
    transitions_recorded: int = 0
    started_at: str = field(default_factory=utc_now_iso)
    completed_at: str = field(default_factory=utc_now_iso)
    duration_seconds: float = 0.0
    root_node_id: str | None = None
    current_node_id: str | None = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serializes exploration result to user-safe dictionary."""
        return {
            "schema_version": "1.0",
            "status": self.status,
            "stop_reason": self.stop_reason,
            "steps_attempted": self.steps_attempted,
            "actions_succeeded": self.actions_succeeded,
            "actions_failed": self.actions_failed,
            "screens_observed": self.screens_observed,
            "transitions_recorded": self.transitions_recorded,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "root_node_id": self.root_node_id,
            "current_node_id": self.current_node_id,
            "error": sanitize_str(self.error),
            "metadata": sanitize_value(self.metadata),
        }
