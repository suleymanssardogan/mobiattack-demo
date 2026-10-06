"""Common responsibilities for the demo pipeline."""
from __future__ import annotations

from typing import Callable
import logging

logger = logging.getLogger(__name__)


class DemoOrchestrationError(ValueError):
    """Raised when any stage of the demo orchestration fails."""

    def __init__(self, message: str, stage: str, cause: Exception | None = None, reason_code: str | None = None):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage
        self.cause = cause
        self.reason_code = reason_code or getattr(cause, "reason_code", None)


def _emit_progress(
    callback: Callable[[str, str, str, dict | None], None] | None,
    stage: str,
    state: str,
    message: str,
    data: dict | None = None,
) -> None:
    if callback is not None:
        try:
            callback(stage, state, message, data)
        except Exception:
            pass
