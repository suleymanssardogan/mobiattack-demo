"""Timeline responsibilities for the demo pipeline."""
from __future__ import annotations

from pathlib import Path
from typing import Any
import logging


from src.persistence import write_json_atomic

logger = logging.getLogger(__name__)


class ExplorationTimelineRecorder:
    """Appends compact exploration events to the existing dynamic session timeline."""

    def __init__(self, timeline_path: Path, session_id: str | None = None) -> None:
        self.timeline_path = timeline_path
        self.session_id = session_id

    def _record_system_event(self, name: str, metadata: dict[str, Any] | None = None) -> None:
        self._append_event("system_event", name, metadata)

    def _record_user_action(self, name: str, metadata: dict[str, Any] | None = None) -> None:
        self._append_event("user_action", name, metadata)

    def append(self, event: Any) -> None:
        if hasattr(event, "to_dict"):
            d = event.to_dict()
        elif isinstance(event, dict):
            d = event
        else:
            return
        self._write_event_dict(d)

    def _append_event(self, ev_type: str, name: str, metadata: dict[str, Any] | None) -> None:
        from src.dynamic.exploration.models import utc_now_iso
        event_dict = {
            "type": ev_type,
            "name": name,
            "timestamp": utc_now_iso(),
            "metadata": metadata or {},
            "session_id": self.session_id,
        }
        self._write_event_dict(event_dict)

    def _write_event_dict(self, event_dict: dict[str, Any]) -> None:
        try:
            import json as _json
            events: list[dict[str, Any]] = []
            if self.timeline_path.is_file():
                with open(self.timeline_path, "r", encoding="utf-8") as f:
                    events = _json.load(f)
            events.append(event_dict)
            write_json_atomic(str(self.timeline_path), events)
        except Exception as err:
            logger.warning("Failed to append event '%s' to timeline: %s", event_dict.get("name"), err)
