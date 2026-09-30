"""Append-safe storage for traffic transactions and summary JSON artifacts."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import Any

from src.dynamic.traffic.models import (
    CaptureSession,
    CaptureSummary,
    TrafficErrorCode,
    TrafficException,
    TrafficTransaction,
)

logger = logging.getLogger(__name__)

DEFAULT_SESSIONS_DIR = "artifacts/dynamic/sessions"


class TrafficStorage:
    """Manages appending transactions to transactions.jsonl and saving capture.json."""

    def __init__(self, base_dir: str = DEFAULT_SESSIONS_DIR) -> None:
        self.base_dir = base_dir

    def get_traffic_dir(self, session_id: str) -> str:
        """Returns artifacts/dynamic/sessions/<session_id>/traffic/ directory."""
        return os.path.join(self.base_dir, session_id, "traffic")

    def append_transaction(self, session_id: str, transaction: TrafficTransaction) -> None:
        """Appends a single normalized transaction line to transactions.jsonl."""
        traffic_dir = self.get_traffic_dir(session_id)
        os.makedirs(traffic_dir, exist_ok=True)
        jsonl_path = os.path.join(traffic_dir, "transactions.jsonl")

        try:
            line = json.dumps(transaction.to_dict(), ensure_ascii=False) + "\n"
            with open(jsonl_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as exc:
            logger.error(f"Failed to append transaction to {jsonl_path}: {exc}")
            raise TrafficException(
                TrafficErrorCode.TRAFFIC_STORAGE_FAILED,
                f"Could not persist transaction line: {exc}",
            ) from exc

    def save_capture_session(
        self,
        session_id: str,
        capture: CaptureSession,
        summary: CaptureSummary | None = None,
    ) -> str:
        """Atomically saves capture.json with session status and summary statistics."""
        traffic_dir = self.get_traffic_dir(session_id)
        os.makedirs(traffic_dir, exist_ok=True)
        capture_path = os.path.join(traffic_dir, "capture.json")

        payload: dict[str, Any] = {
            "capture": capture.to_dict(),
            "summary": summary.to_dict() if summary else None,
        }

        try:
            fd, tmp_path = tempfile.mkstemp(dir=traffic_dir, prefix=".tmp_capture_", suffix=".json")
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, capture_path)
            return capture_path
        except Exception as exc:
            logger.error(f"Failed to save capture metadata to {capture_path}: {exc}")
            raise TrafficException(
                TrafficErrorCode.TRAFFIC_STORAGE_FAILED,
                f"Could not save capture metadata: {exc}",
            ) from exc

    def load_transactions(self, session_id: str) -> list[dict[str, Any]]:
        """Reads all transactions from transactions.jsonl."""
        jsonl_path = os.path.join(self.get_traffic_dir(session_id), "transactions.jsonl")
        if not os.path.isfile(jsonl_path):
            return []

        results: list[dict[str, Any]] = []
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    try:
                        results.append(json.loads(line_str))
                    except Exception:
                        pass
        return results

    def load_capture_metadata(self, session_id: str) -> dict[str, Any]:
        """Loads capture.json dictionary."""
        capture_path = os.path.join(self.get_traffic_dir(session_id), "capture.json")
        if not os.path.isfile(capture_path):
            raise FileNotFoundError(f"Capture metadata file not found at {capture_path}")

        with open(capture_path, "r", encoding="utf-8") as f:
            return json.load(f)
