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


def navigation_skip_reason(action: DiscoveredAction) -> str | None:
    """Conservative navigation-only policy; unknown side effects never auto-dispatch."""
    if action.action_type != "click":
        return "NON_NAVIGATION_INPUT"
    label = " ".join((action.text or "", action.content_desc or "", action.resource_id or "")).lower()
    if is_destructive_action(action) or re.search(
        r"submit|sign.?in|sign.?up|login|register|logout|send|message|save|update|confirm|"
        r"\bsubscribe\b|credential|password|permission_allow|while using|allow access|enable|disable", label
    ):
        return "SIDE_EFFECT_BOUNDARY"
    # Checkable controls may modify persistent state even when their caption looks informational.
    if any(term in action.class_name.lower() for term in ("switch", "checkbox", "toggle")):
        return "SIDE_EFFECT_BOUNDARY"
    if structural_navigation(action):
        return None
    if re.search(r"\b(menu|navigation|drawer|tab|back|cancel|close|dismiss|help|about|instructions|information|details)\b", label):
        return None
    if re.search(r"\b(open|show|view)\s+(an?\s+)?(informational|screen|dialog|list|settings)\b", label):
        return None
    if re.search(r"\bimplementation\b", label):
        return None  # informational implementation sections, not test/submit buttons
    return "UNCERTAIN_SIDE_EFFECTS"


def structural_navigation(action):
    evidence = getattr(action, 'navigation_evidence', {})
    return (isinstance(evidence, dict) and evidence.get('role') == 'navigation_item'
            and evidence.get('source') in {'material_navigation_hierarchy', 'android_tab_widget'}
            and evidence.get('control_path', '').startswith(evidence.get('container_path', '') + '/')
            and bool(evidence.get('container_path')))


def navigation_classification(action):
    """Classification for evidence-based roles; existing informational policy is unchanged."""
    label = ' '.join((action.text or '', action.content_desc or '', action.resource_id or '')).lower()
    if is_destructive_action(action):
        return 'DESTRUCTIVE'
    if re.search(r'login|register|sign.?in|sign.?up|credential|password', label):
        return 'CREDENTIAL/AUTH'
    reason = navigation_skip_reason(action)
    if reason in {'SIDE_EFFECT_BOUNDARY', 'NON_NAVIGATION_INPUT'}:
        return 'SIDE_EFFECTING'
    if structural_navigation(action) and reason is None:
        return 'SAFE_NAVIGATION'
    return 'AMBIGUOUS'


def is_safe_clickable_action(action: DiscoveredAction) -> bool:
    return action.status == ActionStatus.DISCOVERED.value and navigation_skip_reason(action) is None


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
    UNSAFE_ACTION_BOUNDARY = "unsafe_action_boundary"
    REPEATED_STATE = "repeated_state"
    MAX_STEPS = "max_steps"
    AUTH_NOT_COMPLETED = "auth_intervention_not_completed"
    HARD_STEP_CEILING = "hard_step_ceiling"
    FRONTIER_STAGNATED = "frontier_stagnated"
    RUNTIME_UNAVAILABLE = "runtime_unavailable"
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
    base_step_budget: int | None = None
    hard_step_ceiling: int | None = None
    stagnation_actions: int = 3
    minimum_extension_seconds: float = 1.0

    def __post_init__(self):
        base = self.max_steps if self.base_step_budget is None else self.base_step_budget
        ceiling = base if self.hard_step_ceiling is None else self.hard_step_ceiling
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 1
               for v in (base, ceiling, self.stagnation_actions)) or ceiling < base:
            raise ValueError("Budgets must be positive integers with hard ceiling >= base")
        import math
        if not math.isfinite(self.minimum_extension_seconds) or self.minimum_extension_seconds <= 0:
            raise ValueError("Extension requires a finite positive remaining deadline")

    @property
    def base_budget(self):
        return self.max_steps if self.base_step_budget is None else self.base_step_budget

    @property
    def hard_ceiling(self):
        return self.base_budget if self.hard_step_ceiling is None else self.hard_step_ceiling



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
