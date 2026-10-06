"""Atomic disk persistence for Dynamic Sessions and Timelines."""

from __future__ import annotations

from src.persistence import write_json_atomic

import json
import logging
import os
from typing import Any

from src.dynamic.session.models import DynamicSession, SessionErrorCode, SessionException, TimelineEvent

logger = logging.getLogger(__name__)

DEFAULT_SESSIONS_DIR = "artifacts/dynamic/sessions"


class SessionStorage:
    """Handles thread-safe and atomic JSON storage for dynamic sessions.

    Args:
        base_dir: Root directory for session storage.
        run_scoped: When True, session.json and timeline.json are written
            directly to base_dir (e.g. demo_runs/<run_id>/dynamic/) instead
            of creating a per-session-id subdirectory. Default False preserves
            backward compatibility with existing tests and isolated module use.
    """

    def __init__(self, base_dir: str = DEFAULT_SESSIONS_DIR, run_scoped: bool = False) -> None:
        self.base_dir = base_dir
        self.run_scoped = run_scoped

    def get_session_dir(self, session_id: str) -> str:
        """Returns the storage directory for the given session.

        In run_scoped mode, returns base_dir directly (flat layout).
        In default mode, returns base_dir/<session_id>/ (legacy layout).
        """
        if self.run_scoped:
            return self.base_dir
        return os.path.join(self.base_dir, session_id)

    def save_session(self, session: DynamicSession) -> str:
        """Atomically saves session.json and timeline.json to disk."""
        target_dir = self.get_session_dir(session.session_id)
        try:
            os.makedirs(target_dir, exist_ok=True)

            session_file = os.path.join(target_dir, "session.json")
            self._atomic_write_json(session_file, session.to_dict())

            timeline_file = os.path.join(target_dir, "timeline.json")
            timeline_list = [e.to_dict() for e in session.timeline]
            self._atomic_write_json(timeline_file, timeline_list)

            return target_dir
        except Exception as exc:
            logger.error(f"Failed to persist session {session.session_id} to {target_dir}: {exc}")
            raise SessionException(
                SessionErrorCode.STORAGE_WRITE_FAILED,
                f"Could not save session data to disk: {exc}",
            ) from exc

    def load_session(self, session_id: str) -> dict[str, Any]:
        """Loads the raw session.json dictionary from disk."""
        target_file = os.path.join(self.get_session_dir(session_id), "session.json")
        if not os.path.isfile(target_file):
            raise FileNotFoundError(f"Session file not found: {target_file}")

        with open(target_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_timeline(self, session_id: str) -> list[dict[str, Any]]:
        """Loads the raw timeline.json list from disk."""
        target_file = os.path.join(self.get_session_dir(session_id), "timeline.json")
        if not os.path.isfile(target_file):
            raise FileNotFoundError(f"Timeline file not found: {target_file}")

        with open(target_file, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _atomic_write_json(filepath: str, data: Any) -> None:
        """Writes JSON to a temporary file in the same directory and replaces atomically."""
        write_json_atomic(filepath, data)
