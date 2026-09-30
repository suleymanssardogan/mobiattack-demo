"""Dynamic Session Manager orchestrating session lifecycle, flows, and timeline."""

from __future__ import annotations

import logging
from typing import Any

from src.dynamic.preflight.models import PreflightResult, PreflightStatus
from src.dynamic.session.flow_recorder import FlowRecorder
from src.dynamic.session.models import (
    DynamicSession,
    EventType,
    FlowStatus,
    SessionErrorCode,
    SessionException,
    SessionStatus,
    TargetFlow,
    TimelineEvent,
    utc_now_iso,
)
from src.dynamic.session.storage import SessionStorage

logger = logging.getLogger(__name__)


class DynamicSessionManager:
    """Manages active dynamic analysis session, flows, timeline, and persistence."""

    def __init__(self, storage: SessionStorage | None = None) -> None:
        self.storage = storage or SessionStorage()
        self.session: DynamicSession | None = None

    def start_session(
        self,
        package_name: str,
        device_serial: str,
        preflight_result: PreflightResult | dict[str, Any] | None = None,
        session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> DynamicSession:
        """Validates preflight status, initializes session, and sets state to ACTIVE."""
        preflight_status_str = "NOT_EVALUATED"
        preflight_warnings: list[str] = []
        preflight_errors: list[dict[str, str]] = []

        if preflight_result is not None:
            if isinstance(preflight_result, PreflightResult):
                preflight_status_str = preflight_result.status.value
                preflight_warnings = list(preflight_result.warnings)
                preflight_errors = list(preflight_result.errors)
            elif isinstance(preflight_result, dict):
                preflight_status_str = str(preflight_result.get("status", "UNKNOWN")).upper()
                preflight_warnings = list(preflight_result.get("warnings", []))
                preflight_errors = list(preflight_result.get("errors", []))

            # Validate preflight gate
            if preflight_status_str == PreflightStatus.FAIL.value:
                err_msg = "; ".join(e.get("message", "") for e in preflight_errors) or "Preflight checks failed"
                raise SessionException(
                    SessionErrorCode.PREFLIGHT_FAILED,
                    f"Cannot start session because preflight check failed: {err_msg}",
                )

        # Initialize session
        self.session = DynamicSession(
            package_name=package_name,
            device_serial=device_serial,
            preflight_status=preflight_status_str,
            status=SessionStatus.ACTIVE,
            warnings=preflight_warnings,
            metadata=metadata or {},
        )
        if session_id:
            self.session.session_id = session_id

        # Record initial SYSTEM_EVENT in timeline
        self._record_system_event(
            name="SESSION_STARTED",
            metadata={
                "package_name": package_name,
                "device_serial": device_serial,
                "preflight_status": preflight_status_str,
            },
        )

        # Persist initial session
        self.storage.save_session(self.session)
        logger.info(f"Dynamic session {self.session.session_id} started for {package_name} on {device_serial}")
        return self.session

    def start_flow(self, name: str, description: str = "") -> FlowRecorder:
        """Starts a new TargetFlow inside the current active session."""
        if not self.session or self.session.status != SessionStatus.ACTIVE:
            raise SessionException(
                SessionErrorCode.SESSION_NOT_ACTIVE,
                "Cannot start flow: No active session running.",
            )

        if not name or not name.strip():
            raise SessionException(
                SessionErrorCode.INVALID_EVENT,
                "Flow name cannot be empty.",
            )

        clean_name = name.strip()
        flow = TargetFlow(
            name=clean_name,
            description=description,
            status=FlowStatus.ACTIVE,
            started_at=utc_now_iso(),
        )
        self.session.flows.append(flow)

        # Record SYSTEM_EVENT for flow start
        self._record_system_event(
            name="FLOW_STARTED",
            metadata={"flow_name": clean_name, "description": description},
            flow_id=flow.flow_id,
        )

        recorder = FlowRecorder(
            flow=flow,
            session_id=self.session.session_id,
            on_event_recorded=self._on_flow_event_recorded,
            on_flow_updated=self._persist_current_session,
        )
        self._persist_current_session()
        return recorder

    def complete_session(self) -> DynamicSession:
        """Completes active flows and marks the entire dynamic session as COMPLETED."""
        if not self.session:
            raise SessionException(
                SessionErrorCode.SESSION_NOT_ACTIVE,
                "Cannot complete session: No session exists.",
            )

        if self.session.status == SessionStatus.COMPLETED:
            raise SessionException(
                SessionErrorCode.SESSION_ALREADY_COMPLETED,
                f"Session {self.session.session_id} is already completed.",
            )

        if self.session.status not in (SessionStatus.CREATED, SessionStatus.ACTIVE):
            raise SessionException(
                SessionErrorCode.INVALID_STATE_TRANSITION,
                f"Cannot complete session in status '{self.session.status.value}'.",
            )

        # Auto-complete any still active flows
        for flow in self.session.flows:
            if flow.status == FlowStatus.ACTIVE:
                flow.status = FlowStatus.COMPLETED
                flow.ended_at = utc_now_iso()

        self._record_system_event("SESSION_COMPLETED")
        self.session.status = SessionStatus.COMPLETED
        self.session.ended_at = utc_now_iso()
        self._persist_current_session()
        logger.info(f"Dynamic session {self.session.session_id} completed.")
        return self.session

    def abort_session(self, reason: str = "") -> DynamicSession:
        """Aborts active flows and marks session as ABORTED."""
        if not self.session or self.session.status in (SessionStatus.COMPLETED, SessionStatus.ABORTED):
            raise SessionException(
                SessionErrorCode.INVALID_STATE_TRANSITION,
                "Cannot abort session that is already completed or aborted.",
            )

        for flow in self.session.flows:
            if flow.status == FlowStatus.ACTIVE:
                flow.status = FlowStatus.ABORTED
                flow.ended_at = utc_now_iso()

        self._record_system_event("SESSION_ABORTED", metadata={"reason": reason})
        self.session.status = SessionStatus.ABORTED
        self.session.ended_at = utc_now_iso()
        self._persist_current_session()
        logger.info(f"Dynamic session {self.session.session_id} aborted: {reason}")
        return self.session

    def get_timeline(self) -> list[dict[str, Any]]:
        """Returns chronological, deterministically sorted list of timeline events."""
        if not self.session:
            return []

        # Deterministic sort by ISO timestamp
        sorted_events = sorted(self.session.timeline, key=lambda e: e.timestamp)
        return [
            {
                "timestamp": e.timestamp,
                "type": e.type.value if isinstance(e.type, EventType) else str(e.type),
                "name": e.name,
                "metadata": e.metadata,
                "flow_id": e.flow_id,
                "session_id": e.session_id,
            }
            for e in sorted_events
        ]

    def _on_flow_event_recorded(self, event: TimelineEvent) -> None:
        """Appends flow event to global session timeline."""
        if self.session:
            self.session.timeline.append(event)

    def _record_system_event(
        self,
        name: str,
        metadata: dict[str, Any] | None = None,
        flow_id: str | None = None,
    ) -> TimelineEvent:
        """Appends a SYSTEM_EVENT directly to session timeline."""
        event = TimelineEvent(
            type=EventType.SYSTEM_EVENT,
            name=name,
            timestamp=utc_now_iso(),
            metadata=metadata or {},
            flow_id=flow_id,
            session_id=self.session.session_id if self.session else None,
        )
        if self.session:
            self.session.timeline.append(event)
        return event

    def _persist_current_session(self) -> None:
        """Saves current state atomically."""
        if self.session:
            self.storage.save_session(self.session)
