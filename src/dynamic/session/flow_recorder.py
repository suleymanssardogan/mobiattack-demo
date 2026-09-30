"""Target Flow recorder and event sanitization module."""

from __future__ import annotations

from typing import Any, Callable

from src.dynamic.session.models import (
    EventType,
    FlowStatus,
    SessionErrorCode,
    SessionException,
    TargetFlow,
    TimelineEvent,
    utc_now_iso,
)

SENSITIVE_KEY_PATTERNS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "auth",
    "authorization",
    "cookie",
    "set-cookie",
    "api_key",
    "apikey",
    "private_key",
}


def sanitize_metadata(meta: dict[str, Any] | None) -> dict[str, Any]:
    """Recursively redacts sensitive keys from event metadata dictionaries."""
    if not meta:
        return {}

    sanitized: dict[str, Any] = {}
    for key, val in meta.items():
        lower_key = str(key).lower()
        if any(pat in lower_key for pat in SENSITIVE_KEY_PATTERNS):
            sanitized[key] = "[REDACTED]"
        elif isinstance(val, dict):
            sanitized[key] = sanitize_metadata(val)
        elif isinstance(val, list):
            sanitized[key] = [
                sanitize_metadata(item) if isinstance(item, dict) else item for item in val
            ]
        else:
            sanitized[key] = val
    return sanitized


class FlowRecorder:
    """Controls lifecycle and event emission for a single TargetFlow."""

    def __init__(
        self,
        flow: TargetFlow,
        session_id: str,
        on_event_recorded: Callable[[TimelineEvent], None] | None = None,
        on_flow_updated: Callable[[], None] | None = None,
    ) -> None:
        self.flow = flow
        self.session_id = session_id
        self._on_event_recorded = on_event_recorded
        self._on_flow_updated = on_flow_updated

    @property
    def flow_id(self) -> str:
        return self.flow.flow_id

    @property
    def name(self) -> str:
        return self.flow.name

    @property
    def status(self) -> FlowStatus:
        return self.flow.status

    def record_action(self, name: str, metadata: dict[str, Any] | None = None) -> TimelineEvent:
        """Records a user action event inside this flow."""
        return self._add_event(EventType.USER_ACTION, name, metadata)

    def add_marker(self, name: str, metadata: dict[str, Any] | None = None) -> TimelineEvent:
        """Adds a correlation marker event inside this flow."""
        return self._add_event(EventType.MARKER, name, metadata)

    def record_note(self, text: str, metadata: dict[str, Any] | None = None) -> TimelineEvent:
        """Records an analyst note inside this flow."""
        meta = metadata.copy() if metadata else {}
        meta["note"] = text
        return self._add_event(EventType.NOTE, "NOTE", meta)

    def record_system_event(self, name: str, metadata: dict[str, Any] | None = None) -> TimelineEvent:
        """Records a system lifecycle event inside this flow."""
        return self._add_event(EventType.SYSTEM_EVENT, name, metadata)

    def complete(self) -> TargetFlow:
        """Marks this flow as successfully COMPLETED."""
        if self.flow.status == FlowStatus.COMPLETED:
            raise SessionException(
                SessionErrorCode.FLOW_ALREADY_COMPLETED,
                f"Flow '{self.flow.name}' is already completed.",
            )
        if self.flow.status not in (FlowStatus.CREATED, FlowStatus.ACTIVE):
            raise SessionException(
                SessionErrorCode.FLOW_NOT_ACTIVE,
                f"Cannot complete flow in status '{self.flow.status.value}'.",
            )

        self.flow.status = FlowStatus.COMPLETED
        self.flow.ended_at = utc_now_iso()
        if self._on_flow_updated:
            self._on_flow_updated()
        return self.flow

    def abort(self, reason: str = "") -> TargetFlow:
        """Marks this flow as ABORTED."""
        if self.flow.status in (FlowStatus.COMPLETED, FlowStatus.ABORTED):
            raise SessionException(
                SessionErrorCode.INVALID_STATE_TRANSITION,
                f"Cannot abort flow already in status '{self.flow.status.value}'.",
            )

        if reason:
            self.record_system_event("FLOW_ABORTED", {"reason": reason})
        self.flow.status = FlowStatus.ABORTED
        self.flow.ended_at = utc_now_iso()
        if self._on_flow_updated:
            self._on_flow_updated()
        return self.flow

    def _add_event(
        self,
        event_type: EventType,
        name: str,
        metadata: dict[str, Any] | None,
    ) -> TimelineEvent:
        """Validates state, sanitizes metadata, and appends event."""
        if self.flow.status == FlowStatus.COMPLETED:
            raise SessionException(
                SessionErrorCode.FLOW_ALREADY_COMPLETED,
                f"Cannot record events in completed flow '{self.flow.name}'.",
            )
        if self.flow.status != FlowStatus.ACTIVE:
            # If CREATED, move to ACTIVE on first event
            if self.flow.status == FlowStatus.CREATED:
                self.flow.status = FlowStatus.ACTIVE
            else:
                raise SessionException(
                    SessionErrorCode.FLOW_NOT_ACTIVE,
                    f"Flow '{self.flow.name}' is not active (status: {self.flow.status.value}).",
                )

        if not name or not name.strip():
            raise SessionException(
                SessionErrorCode.INVALID_EVENT,
                "Event name cannot be empty.",
            )

        sanitized_meta = sanitize_metadata(metadata)
        event = TimelineEvent(
            type=event_type,
            name=name.strip(),
            timestamp=utc_now_iso(),
            metadata=sanitized_meta,
            flow_id=self.flow.flow_id,
            session_id=self.session_id,
        )
        self.flow.events.append(event)

        if self._on_event_recorded:
            self._on_event_recorded(event)
        if self._on_flow_updated:
            self._on_flow_updated()

        return event
