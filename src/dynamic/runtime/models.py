"""Data models for Android Runtime Observation Primitive (Week 2 — Day 6 Task 6.1).

Defines structured, sanitized dataclasses for:
- RuntimeLogEvent: Individual parsed, categorized, and redacted logcat events.
- RuntimeSnapshot: Point-in-time Android process, foreground, and health state.
- RuntimeDiff: Comparative delta between pre-action and post-action runtime snapshots.
"""

from __future__ import annotations

from src.persistence import write_json_atomic

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
import re
from typing import Any


def utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


# Sensitive data redaction patterns
BEARER_AUTH_RE = re.compile(r"(?i)\bAuthorization:\s*Bearer\s+[^\s,;'\"]+", re.IGNORECASE)
BEARER_TOKEN_RE = re.compile(r"(?i)\bBearer\s+[a-zA-Z0-9_\-\.]{8,}", re.IGNORECASE)
KEY_VALUE_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api_key|apikey|private_key|token|access_token|cookie)\s*[:=]\s*['\"]?([^\s'\",;&]+)['\"]?",
    re.IGNORECASE,
)
HOST_PATH_RE = re.compile(
    r"/(?:Users|home|opt/homebrew|private/tmp|tmp|var/folders)/[^\s'\",;]+",
    re.IGNORECASE,
)


def sanitize_log_message(msg: str) -> str:
    """Sanitizes sensitive bearer tokens, passwords, cookies, and local filesystem paths."""
    if not msg:
        return ""
    text = msg
    # 1. Bearer authorization header
    text = BEARER_AUTH_RE.sub("Authorization: Bearer [REDACTED]", text)
    # 2. Bearer token standalone
    text = BEARER_TOKEN_RE.sub("Bearer [REDACTED]", text)
    # 3. Key-value secrets (password, token, cookie, etc.)
    text = KEY_VALUE_SECRET_RE.sub(r"\1=[REDACTED]", text)
    # 4. Host absolute paths
    text = HOST_PATH_RE.sub("[host_path]", text)
    return text


class LogEventKind(str, Enum):
    """Categorical classification of runtime log entries."""
    FATAL = "fatal"
    CRASH = "crash"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class RuntimeLogEvent:
    """Structured, sanitized logcat event."""

    timestamp: str | None = None
    level: str = "I"
    tag: str = "unknown"
    message: str = ""
    kind: str = LogEventKind.INFO.value
    target_attributed: bool = False
    attribution: str = "unknown"  # "target" | "unknown"
    attribution_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serializes log event to dictionary."""
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "tag": self.tag,
            "message": sanitize_log_message(self.message),
            "kind": self.kind,
            "target_attributed": self.target_attributed,
            "attribution": self.attribution,
            "attribution_reason": sanitize_log_message(self.attribution_reason) if self.attribution_reason else None,
        }


@dataclass
class RuntimeSnapshot:
    """Point-in-time observation of target process, foreground state, and log events."""

    package_name: str
    timestamp: str = field(default_factory=utc_now_iso)
    pid: int | None = None
    process_running: bool = False
    foreground_package: str | None = None
    foreground_activity: str | None = None
    is_foreground: bool = False
    fatal_detected: bool = False
    crash_detected: bool = False
    log_events: list[RuntimeLogEvent] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serializes runtime snapshot to compact, user-safe dictionary."""
        return {
            "timestamp": self.timestamp,
            "package_name": self.package_name,
            "pid": self.pid,
            "process_running": self.process_running,
            "foreground_package": self.foreground_package,
            "foreground_activity": self.foreground_activity,
            "is_foreground": self.is_foreground,
            "fatal_detected": self.fatal_detected,
            "crash_detected": self.crash_detected,
            "log_events": [evt.to_dict() for evt in self.log_events],
            "diagnostics": list(self.diagnostics),
        }


@dataclass
class RuntimeDiff:
    """Comparative diff between two sequential RuntimeSnapshots."""

    package_name: str
    pid_changed: bool = False
    before_pid: int | None = None
    after_pid: int | None = None
    process_died: bool = False
    process_spawned: bool = False
    foreground_changed: bool = False
    before_foreground_package: str | None = None
    after_foreground_package: str | None = None
    activity_changed: bool = False
    before_activity: str | None = None
    after_activity: str | None = None
    fatal_appeared: bool = False
    crash_appeared: bool = False
    new_log_events: list[RuntimeLogEvent] = field(default_factory=list)
    new_log_event_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serializes runtime diff to dictionary."""
        return {
            "package_name": self.package_name,
            "pid_changed": self.pid_changed,
            "before_pid": self.before_pid,
            "after_pid": self.after_pid,
            "process_died": self.process_died,
            "process_spawned": self.process_spawned,
            "foreground_changed": self.foreground_changed,
            "before_foreground_package": self.before_foreground_package,
            "after_foreground_package": self.after_foreground_package,
            "activity_changed": self.activity_changed,
            "before_activity": self.before_activity,
            "after_activity": self.after_activity,
            "fatal_appeared": self.fatal_appeared,
            "crash_appeared": self.crash_appeared,
            "new_log_events": [evt.to_dict() for evt in self.new_log_events],
            "new_log_event_count": self.new_log_event_count,
        }


def compare_runtime_snapshots(before: RuntimeSnapshot, after: RuntimeSnapshot) -> RuntimeDiff:
    """Computes deterministic delta between two snapshots (e.g. before/after an action)."""
    pid_changed = (before.pid != after.pid)
    process_died = (before.process_running and not after.process_running)
    process_spawned = (not before.process_running and after.process_running)

    fg_changed = (before.foreground_package != after.foreground_package)
    act_changed = (before.foreground_activity != after.foreground_activity)

    fatal_appeared = (not before.fatal_detected and after.fatal_detected)
    crash_appeared = (not before.crash_detected and after.crash_detected)

    # Correlate new log events appearing in after that were not present in before
    before_keys = {
        (e.timestamp, e.level, e.tag, e.message)
        for e in before.log_events
    }
    new_events: list[RuntimeLogEvent] = []
    for e in after.log_events:
        key = (e.timestamp, e.level, e.tag, e.message)
        if key not in before_keys:
            new_events.append(e)

    return RuntimeDiff(
        package_name=after.package_name,
        pid_changed=pid_changed,
        before_pid=before.pid,
        after_pid=after.pid,
        process_died=process_died,
        process_spawned=process_spawned,
        foreground_changed=fg_changed,
        before_foreground_package=before.foreground_package,
        after_foreground_package=after.foreground_package,
        activity_changed=act_changed,
        before_activity=before.foreground_activity,
        after_activity=after.foreground_activity,
        fatal_appeared=fatal_appeared,
        crash_appeared=crash_appeared,
        new_log_events=new_events,
        new_log_event_count=len(new_events),
    )


class CorrelationStatus(str, Enum):
    """Quality and availability state of runtime action correlation."""
    AVAILABLE = "available"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"


@dataclass
class RuntimeActionEvidence:
    """Compact correlated runtime evidence for a single action execution."""

    action_id: str
    source_node_id: str
    target_node_id: str | None = None
    source_screen_identity: str | None = None
    target_screen_identity: str | None = None
    before_timestamp: str | None = None
    after_timestamp: str | None = None
    before_pid: int | None = None
    after_pid: int | None = None
    pid_changed: bool = False
    process_died: bool = False
    foreground_changed: bool = False
    activity_changed: bool = False
    fatal_appeared: bool = False
    crash_appeared: bool = False
    new_log_event_count: int = 0
    correlation_status: str = CorrelationStatus.AVAILABLE.value
    diff: dict[str, Any] = field(default_factory=dict)
    compact_new_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serializes action runtime evidence to a compact dictionary."""
        return {
            "action_id": self.action_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "source_screen_identity": self.source_screen_identity,
            "target_screen_identity": self.target_screen_identity,
            "before_timestamp": self.before_timestamp,
            "after_timestamp": self.after_timestamp,
            "before_pid": self.before_pid,
            "after_pid": self.after_pid,
            "pid_changed": self.pid_changed,
            "process_died": self.process_died,
            "foreground_changed": self.foreground_changed,
            "activity_changed": self.activity_changed,
            "fatal_appeared": self.fatal_appeared,
            "crash_appeared": self.crash_appeared,
            "new_log_event_count": self.new_log_event_count,
            "correlation_status": self.correlation_status,
            "diff": self.diff,
            "compact_new_events": self.compact_new_events,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuntimeActionEvidence:
        """Deserializes action runtime evidence from dictionary."""
        return cls(
            action_id=data["action_id"],
            source_node_id=data["source_node_id"],
            target_node_id=data.get("target_node_id"),
            source_screen_identity=data.get("source_screen_identity"),
            target_screen_identity=data.get("target_screen_identity"),
            before_timestamp=data.get("before_timestamp"),
            after_timestamp=data.get("after_timestamp"),
            before_pid=data.get("before_pid"),
            after_pid=data.get("after_pid"),
            pid_changed=data.get("pid_changed", False),
            process_died=data.get("process_died", False),
            foreground_changed=data.get("foreground_changed", False),
            activity_changed=data.get("activity_changed", False),
            fatal_appeared=data.get("fatal_appeared", False),
            crash_appeared=data.get("crash_appeared", False),
            new_log_event_count=data.get("new_log_event_count", 0),
            correlation_status=data.get("correlation_status", CorrelationStatus.AVAILABLE.value),
            diff=data.get("diff", {}),
            compact_new_events=data.get("compact_new_events", []),
        )


def create_action_runtime_evidence(
    action_id: str,
    source_node_id: str,
    target_node_id: str | None = None,
    source_screen_identity: str | None = None,
    target_screen_identity: str | None = None,
    before: RuntimeSnapshot | None = None,
    after: RuntimeSnapshot | None = None,
) -> RuntimeActionEvidence:
    """Builds a compact RuntimeActionEvidence from before and after snapshots."""
    if before and after:
        diff = compare_runtime_snapshots(before, after)
        status = CorrelationStatus.AVAILABLE.value
        compact_events = [
            {
                "timestamp": e.timestamp,
                "level": e.level,
                "tag": e.tag,
                "message": sanitize_log_message(e.message)[:200],
                "kind": e.kind,
                "target_attributed": e.target_attributed,
            }
            for e in diff.new_log_events[:10]
        ]
        diff_dict = {
            "pid_changed": diff.pid_changed,
            "before_pid": diff.before_pid,
            "after_pid": diff.after_pid,
            "process_died": diff.process_died,
            "process_spawned": diff.process_spawned,
            "foreground_changed": diff.foreground_changed,
            "before_foreground_package": diff.before_foreground_package,
            "after_foreground_package": diff.after_foreground_package,
            "activity_changed": diff.activity_changed,
            "before_activity": diff.before_activity,
            "after_activity": diff.after_activity,
            "fatal_appeared": diff.fatal_appeared,
            "crash_appeared": diff.crash_appeared,
            "new_log_event_count": diff.new_log_event_count,
        }
        return RuntimeActionEvidence(
            action_id=action_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            source_screen_identity=source_screen_identity,
            target_screen_identity=target_screen_identity,
            before_timestamp=before.timestamp,
            after_timestamp=after.timestamp,
            before_pid=before.pid,
            after_pid=after.pid,
            pid_changed=diff.pid_changed,
            process_died=diff.process_died,
            foreground_changed=diff.foreground_changed,
            activity_changed=diff.activity_changed,
            fatal_appeared=diff.fatal_appeared,
            crash_appeared=diff.crash_appeared,
            new_log_event_count=diff.new_log_event_count,
            correlation_status=status,
            diff=diff_dict,
            compact_new_events=compact_events,
        )
    elif before or after:
        return RuntimeActionEvidence(
            action_id=action_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            source_screen_identity=source_screen_identity,
            target_screen_identity=target_screen_identity,
            before_timestamp=before.timestamp if before else None,
            after_timestamp=after.timestamp if after else None,
            before_pid=before.pid if before else None,
            after_pid=after.pid if after else None,
            correlation_status=CorrelationStatus.PARTIAL.value,
        )
    else:
        return RuntimeActionEvidence(
            action_id=action_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            source_screen_identity=source_screen_identity,
            target_screen_identity=target_screen_identity,
            correlation_status=CorrelationStatus.UNAVAILABLE.value,
        )


@dataclass
class RuntimeEvidenceArtifact:
    """Internal evidence artifact dynamic/runtime_evidence.json."""

    session_id: str
    schema_version: str = "1.0"
    actions: list[RuntimeActionEvidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serializes runtime evidence artifact to dictionary."""
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "actions": [a.to_dict() for a in self.actions],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuntimeEvidenceArtifact:
        """Deserializes runtime evidence artifact from dictionary."""
        actions = [
            RuntimeActionEvidence.from_dict(a)
            for a in data.get("actions", [])
        ]
        return cls(
            session_id=data.get("session_id", ""),
            schema_version=data.get("schema_version", "1.0"),
            actions=actions,
        )

    def save_atomic(self, file_path: str | Path) -> None:
        """Persists runtime evidence artifact atomically to disk."""
        write_json_atomic(file_path, self.to_dict())

    @classmethod
    def load_or_create(cls, file_path: str | Path, session_id: str) -> RuntimeEvidenceArtifact:
        """Loads existing runtime_evidence.json or creates a new empty one."""
        target = Path(file_path)
        if target.is_file():
            try:
                with open(target, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return cls.from_dict(data)
            except Exception:
                pass
        return cls(session_id=session_id)

    def record_action_evidence(self, evidence: RuntimeActionEvidence, file_path: str | Path | None = None) -> None:
        """Appends one action correlation record and atomically writes if file_path given."""
        self.actions.append(evidence)
        if file_path:
            self.save_atomic(file_path)

