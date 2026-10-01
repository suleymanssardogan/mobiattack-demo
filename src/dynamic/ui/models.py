"""Data models and schemas for Generic UI Observation (Week 1 — Day 4 Task 4.2)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
from typing import Any


def utc_now_iso() -> str:
    """Returns current UTC timestamp in strict ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class UiNode:
    """Represents a normalized Android UI element from hierarchy dump."""

    node_id: str = ""
    class_name: str = ""
    package: str = ""
    resource_id: str = ""
    text: str = ""
    content_desc: str = ""
    clickable: bool = False
    enabled: bool = True
    focusable: bool = False
    focused: bool = False
    editable: bool = False
    password: bool = False
    scrollable: bool = False
    checkable: bool = False
    checked: bool = False
    bounds: tuple[int, int, int, int] = (0, 0, 0, 0)
    center_x: int = 0
    center_y: int = 0
    width: int = 0
    height: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "class_name": self.class_name,
            "package": self.package,
            "resource_id": self.resource_id,
            "text": self.text,
            "content_desc": self.content_desc,
            "clickable": self.clickable,
            "enabled": self.enabled,
            "focusable": self.focusable,
            "focused": self.focused,
            "editable": self.editable,
            "password": self.password,
            "scrollable": self.scrollable,
            "checkable": self.checkable,
            "checked": self.checked,
            "bounds": list(self.bounds),
            "center": [self.center_x, self.center_y],
            "dimensions": [self.width, self.height],
        }


@dataclass
class ActionCandidate:
    """Actionable interactive control identified on the current screen."""

    node_id: str = ""
    resource_id: str = ""
    class_name: str = ""
    text: str = ""
    content_desc: str = ""
    bounds: tuple[int, int, int, int] = (0, 0, 0, 0)
    center_x: int = 0
    center_y: int = 0
    action_type: str = "click"  # "click", "input"

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "resource_id": self.resource_id,
            "class_name": self.class_name,
            "text": self.text,
            "content_desc": self.content_desc,
            "bounds": list(self.bounds),
            "center": [self.center_x, self.center_y],
            "action_type": self.action_type,
        }


@dataclass
class ScreenObservation:
    """Snapshot observation of a mobile screen state."""

    screen_identity: str = ""
    foreground_package: str = ""
    foreground_activity: str = ""
    target_package: str = ""
    is_target_package: bool = False
    is_dialog_or_system: bool = False
    timestamp: str = field(default_factory=utc_now_iso)
    nodes: list[UiNode] = field(default_factory=list)
    clickable_count: int = 0
    input_count: int = 0
    action_candidates: list[ActionCandidate] = field(default_factory=list)
    observation_attempts: int = 1
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "screen_identity": self.screen_identity,
            "foreground_package": self.foreground_package,
            "foreground_activity": self.foreground_activity,
            "target_package": self.target_package,
            "is_target_package": self.is_target_package,
            "is_dialog_or_system": self.is_dialog_or_system,
            "timestamp": self.timestamp,
            "node_count": len(self.nodes),
            "clickable_count": self.clickable_count,
            "input_count": self.input_count,
            "action_candidates": [c.to_dict() for c in self.action_candidates],
            "observation_attempts": self.observation_attempts,
            "diagnostics": self.diagnostics,
        }
