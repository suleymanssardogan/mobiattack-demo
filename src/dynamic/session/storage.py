"""Atomic disk persistence for Dynamic Sessions and Timelines."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import Any

from src.dynamic.session.models import DynamicSession, SessionErrorCode, SessionException, TimelineEvent

logger = logging.getLogger(__name__)

DEFAULT_SESSIONS_DIR = "artifacts/dynamic/sessions"


class SessionStorage:
    """Handles thread-safe and atomic JSON storage for dynamic sessions."""

    def __init__(self, base_dir: str = DEFAULT_SESSIONS_DIR) -> None:
        self.base_dir = base_dir

    def get_session_dir(self, session_id: str) -> str:
        """Returns the dedicated directory for the given session ID."""
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
        dir_name = os.path.dirname(filepath)
        os.makedirs(dir_name, exist_ok=True)

        fd, temp_path = tempfile.mkstemp(dir=dir_name, prefix=".tmp_session_", suffix=".json")
        try:
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            os.replace(temp_path, filepath)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
