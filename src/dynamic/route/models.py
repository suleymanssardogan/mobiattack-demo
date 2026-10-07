"""Data models for Route Graph and Screen State navigation (Week 1 — Day 5 Task 5.1).

Defines deterministic models:
- DiscoveredAction: actionable UI element descriptor on a screen node
- RouteNode: observed screen state identified deterministically by screen_identity
- RouteEdge: state transition connecting source, action, and target
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import re
from typing import Any

from src.dynamic.ui.models import ActionCandidate, ScreenObservation

# Path sanitization patterns
_HOST_PATH_RE = re.compile(r"/(?:Users|home)/[^/\s]+/[^\s'\"]*")
_OPT_PATH_RE = re.compile(r"/opt/homebrew/[^\s'\"]*")
_TMP_PATH_RE = re.compile(r"/(?:tmp|private/tmp|var/folders)/[^\s'\"]*")


def utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def sanitize_str(val: str | None) -> str | None:
    """Sanitizes host paths from string values."""
    if val is None:
        return None
    cleaned = _HOST_PATH_RE.sub("<host_path>", val)
    cleaned = _OPT_PATH_RE.sub("<host_path>", cleaned)
    cleaned = _TMP_PATH_RE.sub("<host_path>", cleaned)
    return cleaned


def compute_node_id(screen_identity: str) -> str:
    """Computes a deterministic node identifier from screen_identity."""
    digest = hashlib.sha256(screen_identity.encode("utf-8")).hexdigest()[:16]
    return f"node_{digest}"


def compute_action_id(source_screen_identity: str, ui_node_id: str, action_type: str) -> str:
    """Computes a deterministic action identifier from source screen, node id, and action type."""
    raw = f"{source_screen_identity}:{ui_node_id}:{action_type}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"act_{digest}"


def compute_edge_id(source_node_id: str, action_id: str, target_node_id: str) -> str:
    """Computes a deterministic edge identifier from source, action, and target."""
    raw = f"{source_node_id}->{action_id}->{target_node_id}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"edge_{digest}"


class ActionStatus(str, Enum):
    """Lifecycle status of a discovered action."""
    DISCOVERED = "discovered"
    ATTEMPTED = "attempted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass
class DiscoveredAction:
    """Action descriptor representing a potential interactive element on a screen node."""

    action_id: str
    source_node_id: str
    source_screen_identity: str
    ui_node_id: str
    action_type: str  # "click", "input"
    resource_id: str | None = None
    class_name: str = ""
    bounds: tuple[int, int, int, int] = (0, 0, 0, 0)
    center: tuple[int, int] = (0, 0)
    content_desc: str | None = None
    text: str | None = None
    status: str = ActionStatus.DISCOVERED.value
    first_seen_at: str = field(default_factory=utc_now_iso)
    last_seen_at: str = field(default_factory=utc_now_iso)
    navigation_evidence: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_action_candidate(
        cls,
        candidate: ActionCandidate,
        source_node_id: str,
        source_screen_identity: str,
        timestamp: str | None = None,
    ) -> DiscoveredAction:
        """Constructs a DiscoveredAction from a UI ActionCandidate."""
        ts = timestamp or utc_now_iso()
        act_id = compute_action_id(
            source_screen_identity=source_screen_identity,
            ui_node_id=candidate.node_id,
            action_type=candidate.action_type,
        )

        # Sanitize password fields and sensitive texts
        text_val = candidate.text
        class_lower = (candidate.class_name or "").lower()
        res_lower = (candidate.resource_id or "").lower()
        if any(term in class_lower or term in res_lower for term in ("password", "passwd", "pin", "secret")):
            text_val = None

        return cls(
            action_id=act_id,
            source_node_id=source_node_id,
            source_screen_identity=source_screen_identity,
            ui_node_id=candidate.node_id,
            action_type=candidate.action_type,
            resource_id=sanitize_str(candidate.resource_id) if candidate.resource_id else None,
            class_name=candidate.class_name,
            bounds=tuple(candidate.bounds) if candidate.bounds else (0, 0, 0, 0),
            center=(candidate.center_x, candidate.center_y),
            content_desc=sanitize_str(candidate.content_desc) if candidate.content_desc else None,
            text=sanitize_str(text_val) if text_val else None,
            status=ActionStatus.DISCOVERED.value,
            navigation_evidence=dict(candidate.navigation_evidence),
            first_seen_at=ts,
            last_seen_at=ts,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes action to a user-safe JSON dictionary."""
        return {
            "action_id": self.action_id,
            "source_node_id": self.source_node_id,
            "source_screen_identity": self.source_screen_identity,
            "ui_node_id": self.ui_node_id,
            "action_type": self.action_type,
            "resource_id": self.resource_id,
            "class_name": self.class_name,
            "bounds": list(self.bounds),
            "center": list(self.center),
            "content_desc": self.content_desc,
            "text": self.text,
            "status": self.status,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            **({"navigation_evidence": dict(self.navigation_evidence)} if self.navigation_evidence else {}),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveredAction:
        """Deserializes action from a dictionary."""
        bounds_raw = data.get("bounds", [0, 0, 0, 0])
        bounds = tuple(bounds_raw) if isinstance(bounds_raw, list) else (0, 0, 0, 0)
        center_raw = data.get("center", [0, 0])
        center = tuple(center_raw) if isinstance(center_raw, list) else (0, 0)

        return cls(
            navigation_evidence=dict(data.get("navigation_evidence", {})),
            action_id=data["action_id"],
            source_node_id=data["source_node_id"],
            source_screen_identity=data["source_screen_identity"],
            ui_node_id=data["ui_node_id"],
            action_type=data.get("action_type", "click"),
            resource_id=data.get("resource_id"),
            class_name=data.get("class_name", ""),
            bounds=bounds,
            center=center,
            content_desc=data.get("content_desc"),
            text=data.get("text"),
            status=data.get("status", ActionStatus.DISCOVERED.value),
            first_seen_at=data.get("first_seen_at", utc_now_iso()),
            last_seen_at=data.get("last_seen_at", utc_now_iso()),
        )


@dataclass
class RouteNode:
    """Represents a unique observed screen state in the route graph."""

    route_node_id: str
    screen_identity: str
    package_name: str
    activity: str
    is_target_package: bool
    is_dialog_or_system: bool
    first_seen_at: str
    last_seen_at: str
    visit_count: int = 1
    clickable_count: int = 0
    input_count: int = 0
    actions: dict[str, DiscoveredAction] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_observation(
        cls,
        obs: ScreenObservation,
        timestamp: str | None = None,
    ) -> RouteNode:
        """Creates a RouteNode from a ScreenObservation."""
        ts = timestamp or obs.timestamp or utc_now_iso()
        node_id = compute_node_id(obs.screen_identity)

        node = cls(
            route_node_id=node_id,
            screen_identity=obs.screen_identity,
            package_name=sanitize_str(obs.foreground_package) or "",
            activity=sanitize_str(obs.foreground_activity) or "",
            is_target_package=obs.is_target_package,
            is_dialog_or_system=obs.is_dialog_or_system,
            first_seen_at=ts,
            last_seen_at=ts,
            visit_count=1,
            clickable_count=obs.clickable_count,
            input_count=obs.input_count,
        )

        from src.dynamic.exploration.models import classify_screen_context
        ctx = classify_screen_context(obs)
        node.metadata["screen_context"] = ctx

        for candidate in obs.action_candidates:
            action = DiscoveredAction.from_action_candidate(
                candidate=candidate,
                source_node_id=node_id,
                source_screen_identity=obs.screen_identity,
                timestamp=ts,
            )
            setattr(action, "_screen_context", ctx)
            node.actions[action.action_id] = action

        return node

    def merge_observation(
        self,
        obs: ScreenObservation,
        timestamp: str | None = None,
    ) -> None:
        """Merges a re-observation into this existing node (incrementing visit count and merging actions)."""
        ts = timestamp or obs.timestamp or utc_now_iso()
        self.visit_count += 1
        self.last_seen_at = ts
        self.clickable_count = obs.clickable_count
        self.input_count = obs.input_count

        from src.dynamic.exploration.models import classify_screen_context
        ctx = classify_screen_context(obs)
        self.metadata["screen_context"] = ctx
        for action in self.actions.values():
            setattr(action, "_screen_context", ctx)

        # Merge action candidates: update existing timestamp, add newly discovered, keep historical
        for candidate in obs.action_candidates:
            act_id = compute_action_id(
                source_screen_identity=self.screen_identity,
                ui_node_id=candidate.node_id,
                action_type=candidate.action_type,
            )
            if act_id in self.actions:
                self.actions[act_id].last_seen_at = ts
            else:
                new_act = DiscoveredAction.from_action_candidate(
                    candidate=candidate,
                    source_node_id=self.route_node_id,
                    source_screen_identity=self.screen_identity,
                    timestamp=ts,
                )
                self.actions[new_act.action_id] = new_act

    def to_dict(self) -> dict[str, Any]:
        """Serializes node to user-safe dictionary without raw XML or full element tree."""
        return {
            "route_node_id": self.route_node_id,
            "screen_identity": self.screen_identity,
            "package_name": self.package_name,
            "activity": self.activity,
            "is_target_package": self.is_target_package,
            "is_dialog_or_system": self.is_dialog_or_system,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "visit_count": self.visit_count,
            "clickable_count": self.clickable_count,
            "input_count": self.input_count,
            "actions": [act.to_dict() for act in sorted(self.actions.values(), key=lambda a: a.action_id)],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RouteNode:
        """Deserializes node from a dictionary."""
        actions_list = data.get("actions", [])
        actions_dict = {
            a["action_id"]: DiscoveredAction.from_dict(a)
            for a in actions_list
        }

        return cls(
            route_node_id=data["route_node_id"],
            screen_identity=data["screen_identity"],
            package_name=data.get("package_name", ""),
            activity=data.get("activity", ""),
            is_target_package=data.get("is_target_package", False),
            is_dialog_or_system=data.get("is_dialog_or_system", False),
            first_seen_at=data.get("first_seen_at", utc_now_iso()),
            last_seen_at=data.get("last_seen_at", utc_now_iso()),
            visit_count=data.get("visit_count", 1),
            clickable_count=data.get("clickable_count", 0),
            input_count=data.get("input_count", 0),
            actions=actions_dict,
            metadata=data.get("metadata", {}),
        )


@dataclass
class RouteEdge:
    """Represents a state transition edge in the route graph."""

    edge_id: str
    source_node_id: str
    target_node_id: str
    action_id: str
    action_type: str = "click"
    created_at: str = field(default_factory=utc_now_iso)
    observation_count: int = 1
    success: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serializes edge to dictionary."""
        return {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "action_id": self.action_id,
            "action_type": self.action_type,
            "created_at": self.created_at,
            "observation_count": self.observation_count,
            "success": self.success,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RouteEdge:
        """Deserializes edge from dictionary."""
        return cls(
            edge_id=data["edge_id"],
            source_node_id=data["source_node_id"],
            target_node_id=data["target_node_id"],
            action_id=data["action_id"],
            action_type=data.get("action_type", "click"),
            created_at=data.get("created_at", utc_now_iso()),
            observation_count=data.get("observation_count", 1),
            success=data.get("success", True),
            metadata=data.get("metadata", {}),
        )
