"""Android Action Executor implementation (Week 1 — Day 5 Task 5.2).

Provides safe, deterministic, and bounded action execution over ADB:
- Click/Tap via validated coordinates (center_x, center_y)
- Input text with secure shell escaping and payload redaction
- Back navigation via KEYCODE_BACK (4)
- Bounded retries for transient ADB failures without infinite hangs
- Deterministic error classification and privacy-safe result reporting
"""

from __future__ import annotations
from src.dynamic.deadline import bounded_operation, current_deadline
from src.dynamic.deadline import bounded_timeout

import logging
import subprocess
import time
from typing import Any

from src.android_runtime_launcher import resolve_adb_executable
from src.dynamic.action.models import (
    ActionErrorCode,
    ActionExecutionResult,
    ActionExecutionStatus,
    ActionType,
    sanitize_str,
    utc_now_iso,
)

logger = logging.getLogger(__name__)

DEFAULT_ACTION_TIMEOUT_SECONDS: float = 5.0
DEFAULT_ACTION_MAX_ATTEMPTS: int = 2
KEYCODE_BACK: str = "4"


SHELL_SPECIAL_CHARS = set(r"""\'"$`&;|<>()~*?[]{}!""")


def escape_adb_input_text(text: str) -> str:
    """Escapes text string for safe delivery via 'adb shell input text'.

    Android's input binary converts '%s' into a space character.
    Shell meta-characters are backslash-escaped to prevent command injection.
    """
    escaped: list[str] = []
    for ch in text:
        if ch == " ":
            escaped.append("%s")
        elif ch in SHELL_SPECIAL_CHARS:
            escaped.append(f"\\{ch}")
        else:
            escaped.append(ch)
    return "".join(escaped)


def validate_click_target(
    bounds: tuple[int, int, int, int] | list[int] | None,
    center: tuple[int, int] | list[int] | None,
) -> tuple[bool, str | None]:
    """Validates that click bounds and center coordinates are valid on screen."""
    if not bounds or len(bounds) != 4:
        return False, f"Invalid bounds descriptor: {bounds}"
    if not center or len(center) != 2:
        return False, f"Invalid center coordinate descriptor: {center}"

    left, top, right, bottom = bounds[0], bounds[1], bounds[2], bounds[3]
    cx, cy = center[0], center[1]

    width = right - left
    height = bottom - top

    if cx < 0 or cy < 0:
        return False, f"Negative center coordinates: ({cx}, {cy})"
    if width <= 0 or height <= 0:
        return False, f"Non-positive element dimensions: width={width}, height={height}"

    # Also verify center falls within bounds
    if not (left <= cx <= right and top <= cy <= bottom):
        return False, f"Center ({cx}, {cy}) lies outside bounding box [{left}, {top}, {right}, {bottom}]"

    return True, None


class ActionExecutor:
    """Executes single UI actions (click, input, back) on target Android devices via ADB."""

    def __init__(
        self,
        serial: str,
        adb_bin: str | None = None,
        default_timeout_seconds: float = DEFAULT_ACTION_TIMEOUT_SECONDS,
        max_attempts: int = DEFAULT_ACTION_MAX_ATTEMPTS,
        timeline_recorder: Any | None = None,
    ) -> None:
        self.serial = str(serial).strip()
        if adb_bin:
            try:
                self.adb_bin = resolve_adb_executable(adb_bin)
            except Exception:
                self.adb_bin = adb_bin
        else:
            try:
                self.adb_bin = resolve_adb_executable(None)
            except Exception:
                self.adb_bin = "adb"
        self.default_timeout_seconds = default_timeout_seconds
        self.max_attempts = max(1, max_attempts)
        self.timeline_recorder = timeline_recorder

    def execute(
        self,
        action: Any,
        input_text: str | None = None,
        timeout_seconds: float | None = None,
        timeline_recorder: Any | None = None,
    ) -> ActionExecutionResult:
        """Dispatches an action descriptor (click, input, back) to its specific handler."""
        act_type = getattr(action, "action_type", None)
        if act_type is None and isinstance(action, dict):
            act_type = action.get("action_type")
        elif act_type is None and isinstance(action, str):
            act_type = action.lower()

        if not act_type:
            started = utc_now_iso()
            res = ActionExecutionResult(
                action_id=str(getattr(action, "action_id", "unknown")),
                action_type="unknown",
                status=ActionExecutionStatus.FAILED.value,
                started_at=started,
                completed_at=utc_now_iso(),
                attempts=1,
                error_code=ActionErrorCode.INVALID_ACTION.value,
                message="Cannot determine action_type from action descriptor.",
            )
            self._record_timeline(res, timeline_recorder)
            return res

        act_type_lower = act_type.lower()
        if act_type_lower == ActionType.CLICK.value:
            return self.click(action, timeout_seconds=timeout_seconds, timeline_recorder=timeline_recorder)
        elif act_type_lower == ActionType.INPUT.value:
            # Caller-provided payload or fallback to action text
            payload = input_text if input_text is not None else getattr(action, "text", None)
            if payload is None and isinstance(action, dict):
                payload = action.get("text")
            return self.input(action, input_text=payload, timeout_seconds=timeout_seconds, timeline_recorder=timeline_recorder)
        elif act_type_lower == ActionType.BACK.value:
            act_id = getattr(action, "action_id", "back") if not isinstance(action, str) else action
            return self.back(action_id=act_id, timeout_seconds=timeout_seconds, timeline_recorder=timeline_recorder)
        else:
            started = utc_now_iso()
            act_id = str(getattr(action, "action_id", "unknown")) if not isinstance(action, str) else action
            res = ActionExecutionResult(
                action_id=act_id,
                action_type=act_type,
                status=ActionExecutionStatus.FAILED.value,
                started_at=started,
                completed_at=utc_now_iso(),
                attempts=1,
                error_code=ActionErrorCode.UNSUPPORTED_ACTION_TYPE.value,
                message=f"Unsupported action type '{act_type}'. V1 supports 'click', 'input', 'back'.",
            )
            self._record_timeline(res, timeline_recorder)
            return res

    def click(
        self,
        action: Any,
        timeout_seconds: float | None = None,
        timeline_recorder: Any | None = None,
    ) -> ActionExecutionResult:
        """Executes a click action at target center coordinates."""
        started_at = utc_now_iso()
        timeout = timeout_seconds or self.default_timeout_seconds

        # Extract bounds and center coordinates
        bounds = getattr(action, "bounds", None)
        center = getattr(action, "center", None)
        act_id = getattr(action, "action_id", getattr(action, "node_id", "click_action"))
        res_id = getattr(action, "resource_id", None)

        if isinstance(action, dict):
            bounds = action.get("bounds", bounds)
            center = action.get("center", center)
            act_id = action.get("action_id", action.get("node_id", act_id))
            res_id = action.get("resource_id", res_id)

        # In ActionCandidate, center may be center_x and center_y
        if center is None and hasattr(action, "center_x") and hasattr(action, "center_y"):
            center = (action.center_x, action.center_y)

        is_valid, reason = validate_click_target(bounds, center)
        if not is_valid:
            res = ActionExecutionResult(
                action_id=str(act_id),
                action_type=ActionType.CLICK.value,
                status=ActionExecutionStatus.FAILED.value,
                started_at=started_at,
                completed_at=utc_now_iso(),
                attempts=1,
                error_code=ActionErrorCode.INVALID_BOUNDS.value,
                message=reason,
                metadata={"bounds": bounds, "center": center, "resource_id": sanitize_str(res_id)},
            )
            self._record_timeline(res, timeline_recorder)
            return res

        cx, cy = center[0], center[1]
        cmd = [self.adb_bin, "-s", self.serial, "shell", "input", "tap", str(cx), str(cy)]
        metadata = {
            "center": [cx, cy],
            "bounds": list(bounds) if isinstance(bounds, (list, tuple)) else bounds,
            "resource_id": sanitize_str(res_id),
        }

        res = self._run_bounded_adb_action(
            action_id=str(act_id),
            action_type=ActionType.CLICK.value,
            cmd=cmd,
            timeout=timeout,
            started_at=started_at,
            metadata=metadata,
        )
        self._record_timeline(res, timeline_recorder)
        return res

    def input(
        self,
        action: Any,
        input_text: str | None,
        timeout_seconds: float | None = None,
        timeline_recorder: Any | None = None,
    ) -> ActionExecutionResult:
        """Executes text input via ADB with secure shell escaping and payload redaction."""
        started_at = utc_now_iso()
        timeout = timeout_seconds or self.default_timeout_seconds

        act_id = getattr(action, "action_id", getattr(action, "node_id", "input_action"))
        res_id = getattr(action, "resource_id", None)
        if isinstance(action, dict):
            act_id = action.get("action_id", action.get("node_id", act_id))
            res_id = action.get("resource_id", res_id)

        if input_text is None:
            res = ActionExecutionResult(
                action_id=str(act_id),
                action_type=ActionType.INPUT.value,
                status=ActionExecutionStatus.FAILED.value,
                started_at=started_at,
                completed_at=utc_now_iso(),
                attempts=1,
                error_code=ActionErrorCode.INVALID_ACTION.value,
                message="Input action requires explicit input_text payload from caller.",
                metadata={"resource_id": sanitize_str(res_id)},
            )
            self._record_timeline(res, timeline_recorder)
            return res

        escaped = escape_adb_input_text(input_text)
        cmd = [self.adb_bin, "-s", self.serial, "shell", "input", "text", escaped]

        # Enforce strict secret redaction in metadata
        metadata = {
            "resource_id": sanitize_str(res_id),
            "input_length": len(input_text),
            "input_redacted": True,
        }

        res = self._run_bounded_adb_action(
            action_id=str(act_id),
            action_type=ActionType.INPUT.value,
            cmd=cmd,
            timeout=timeout,
            started_at=started_at,
            metadata=metadata,
        )
        self._record_timeline(res, timeline_recorder)
        return res

    def back(
        self,
        action_id: str = "back",
        timeout_seconds: float | None = None,
        timeline_recorder: Any | None = None,
    ) -> ActionExecutionResult:
        """Executes back navigation key event (KEYCODE_BACK / 4)."""
        started_at = utc_now_iso()
        timeout = timeout_seconds or self.default_timeout_seconds

        cmd = [self.adb_bin, "-s", self.serial, "shell", "input", "keyevent", KEYCODE_BACK]
        metadata = {"keyevent": "KEYCODE_BACK", "keycode": KEYCODE_BACK}

        res = self._run_bounded_adb_action(
            action_id=str(action_id),
            action_type=ActionType.BACK.value,
            cmd=cmd,
            timeout=timeout,
            started_at=started_at,
            metadata=metadata,
        )
        self._record_timeline(res, timeline_recorder)
        return res

    @bounded_operation(8.0, field="timeout")
    def _run_bounded_adb_action(
        self,
        action_id: str,
        action_type: str,
        cmd: list[str],
        timeout: float,
        started_at: str,
        metadata: dict[str, Any],
    ) -> ActionExecutionResult:
        """Executes an ADB command with bounded retries for transient errors and safety timeout."""
        attempts = 0
        last_error_code = None
        last_error_msg = None

        while attempts < self.max_attempts:
            attempts += 1
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=bounded_timeout(timeout),
                )
                if proc.returncode == 0:
                    return ActionExecutionResult(
                        action_id=action_id,
                        action_type=action_type,
                        status=ActionExecutionStatus.SUCCEEDED.value,
                        started_at=started_at,
                        completed_at=utc_now_iso(),
                        attempts=attempts,
                        error_code=None,
                        message=None,
                        metadata=metadata,
                    )
                else:
                    err_out = (proc.stderr or proc.stdout or "").strip()
                    last_error_code = ActionErrorCode.ADB_COMMAND_FAILED.value
                    last_error_msg = f"ADB command returned non-zero ({proc.returncode}): {err_out}"
                    logger.warning(
                        "Action '%s' failed attempt %d/%d: %s",
                        action_id,
                        attempts,
                        self.max_attempts,
                        last_error_msg,
                    )
            except subprocess.TimeoutExpired as exc:
                last_error_code = ActionErrorCode.ACTION_TIMEOUT.value
                last_error_msg = f"Action execution timed out after {timeout}s"
                logger.warning(
                    "Action '%s' timed out on attempt %d/%d after %ss",
                    action_id,
                    attempts,
                    self.max_attempts,
                    timeout,
                )
                break  # Dispatch may have happened; observe postcondition instead of resending.
            except (OSError, Exception) as exc:
                last_error_code = ActionErrorCode.ADB_COMMAND_FAILED.value
                last_error_msg = f"ADB execution exception: {exc}"
                logger.warning(
                    "Action '%s' error on attempt %d/%d: %s",
                    action_id,
                    attempts,
                    self.max_attempts,
                    exc,
                )

            if not (metadata.get('idempotent') and metadata.get('dispatch_rejected')):
                break

        status = (
            ActionExecutionStatus.TIMED_OUT.value
            if last_error_code == ActionErrorCode.ACTION_TIMEOUT.value
            else ActionExecutionStatus.FAILED.value
        )
        return ActionExecutionResult(
            action_id=action_id,
            action_type=action_type,
            status=status,
            started_at=started_at,
            completed_at=utc_now_iso(),
            attempts=attempts,
            error_code=last_error_code,
            message=last_error_msg,
            metadata=metadata,
        )

    def _record_timeline(
        self,
        result: ActionExecutionResult,
        timeline_recorder: Any | None = None,
    ) -> None:
        """Optionally records a compact ACTION_EXECUTED timeline event if a recorder is provided."""
        recorder = self.timeline_recorder if timeline_recorder is None else timeline_recorder
        if recorder is None:
            return

        try:
            meta = result.to_timeline_metadata()
            if hasattr(recorder, "_record_user_action"):
                recorder._record_user_action("ACTION_EXECUTED", metadata=meta)
            elif hasattr(recorder, "append"):
                from src.dynamic.session.models import EventType, TimelineEvent
                recorder.append(
                    TimelineEvent(
                        type=EventType.USER_ACTION,
                        name="ACTION_EXECUTED",
                        timestamp=result.completed_at,
                        metadata=meta,
                    )
                )
            elif callable(recorder):
                recorder(result)
        except Exception as exc:
            logger.warning("Failed to record action execution event to timeline: %s", exc)
