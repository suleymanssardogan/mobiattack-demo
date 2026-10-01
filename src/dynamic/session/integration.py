"""Dynamic Session & Evidence Persistence Integration (Week 1 — Day 4 Task 4.3).

Thin integration layer connecting:
- Preflight result (src/dynamic/preflight/)
- UI observation (src/dynamic/ui/)
- Session lifecycle (src/dynamic/session/)

Produces run-scoped artifacts:
    demo_runs/<run_id>/dynamic/session.json
    demo_runs/<run_id>/dynamic/timeline.json

Does NOT execute actions, build route graphs, or generate dynamic reports.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Callable

from src.dynamic.preflight.models import PreflightResult, PreflightStatus
from src.dynamic.session.manager import DynamicSessionManager
from src.dynamic.session.models import (
    DynamicSession,
    EventType,
    SessionErrorCode,
    SessionException,
    SessionStatus,
    TimelineEvent,
    utc_now_iso,
)
from src.dynamic.session.storage import SessionStorage

logger = logging.getLogger(__name__)


# --- Path sanitization for session/timeline output ---

_HOST_PATH_RE = re.compile(r"/(?:Users|home)/[^/\s]+/[^\s'\"]*")
_OPT_PATH_RE = re.compile(r"/opt/homebrew/[^\s'\"]*")
_TMP_PATH_RE = re.compile(r"/(?:tmp|private/tmp|var/folders)/[^\s'\"]*")


def _sanitize_value(val: Any) -> Any:
    """Recursively sanitizes host-specific paths from session/timeline data."""
    if isinstance(val, dict):
        return {k: _sanitize_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [_sanitize_value(item) for item in val]
    elif isinstance(val, str):
        cleaned = _HOST_PATH_RE.sub("<host_path>", val)
        cleaned = _OPT_PATH_RE.sub("<host_path>", cleaned)
        cleaned = _TMP_PATH_RE.sub("<host_path>", cleaned)
        return cleaned
    return val


def _build_preflight_event_metadata(
    preflight_result: PreflightResult,
) -> dict[str, Any]:
    """Extracts compact, user-safe preflight evidence for timeline metadata."""
    meta: dict[str, Any] = {
        "status": preflight_result.status.value,
        "device_connected": preflight_result.device.connected,
        "device_is_emulator": preflight_result.device.is_emulator,
        "package_installed": preflight_result.application.installed,
        "process_running": preflight_result.application.process_running,
        "foreground": preflight_result.application.foreground,
        "launch_success": preflight_result.runtime.launch_success,
        "launch_attempts": preflight_result.runtime.launch_attempts,
        "network_reachable": preflight_result.network.internet_reachable,
    }
    if preflight_result.runtime.pid is not None:
        meta["pid"] = preflight_result.runtime.pid
    if preflight_result.runtime.ready_after_attempt is not None:
        meta["ready_after_attempt"] = preflight_result.runtime.ready_after_attempt
    if preflight_result.warnings:
        meta["warnings"] = list(preflight_result.warnings)
    if preflight_result.errors:
        # Sanitize error messages to remove host paths
        meta["errors"] = [
            {"code": e.get("code", "UNKNOWN"), "message": _sanitize_value(e.get("message", ""))}
            for e in preflight_result.errors
        ]
    return _sanitize_value(meta)


def _build_observation_event_metadata(
    observation: dict[str, Any] | None,
) -> dict[str, Any]:
    """Extracts compact observation evidence for timeline metadata.

    Uses only summary fields, never the full node tree.
    """
    if not observation:
        return {}

    return {
        "screen_identity": observation.get("screen_identity", ""),
        "foreground_package": observation.get("foreground_package", ""),
        "foreground_activity": observation.get("foreground_activity", ""),
        "is_target_package": observation.get("is_target_package", False),
        "is_dialog_or_system": observation.get("is_dialog_or_system", False),
        "node_count": observation.get("node_count", 0),
        "clickable_count": observation.get("clickable_count", 0),
        "input_count": observation.get("input_count", 0),
        "observation_attempts": observation.get("observation_attempts", 1),
    }


def initialize_dynamic_session(
    run_id: str,
    run_dir: str,
    package_name: str,
    device_serial: str,
    preflight_result: PreflightResult,
    observe_screen_fn: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Initializes a dynamic session with preflight evidence and optional initial observation.

    This is the integration entry point connecting preflight → session → observation.

    Design decisions:
    - PASS / WARN preflight: session starts as ACTIVE, preflight event recorded,
      initial UI observation attempted.
    - FAIL preflight: session is created directly as ABORTED for evidence preservation.
      No UI observation is attempted.
    - Session remains ACTIVE after initialization (not COMPLETED). Real dynamic
      analysis has not happened yet.
    - session_id is a distinct UUID from run_id; run_id is stored in metadata.

    Args:
        run_id: The MobiAttack scan run identifier.
        run_dir: Absolute path to demo_runs/<run_id>/.
        package_name: Target Android application package name.
        device_serial: ADB device serial.
        preflight_result: Completed PreflightResult from preflight service.
        observe_screen_fn: Optional callable(serial, target_package=...) -> ScreenObservation.
            When provided and preflight allows, performs one side-effect-free observation.

    Returns:
        dict with keys: session_id, status, session_dir, observation (if performed).
    """
    dynamic_dir = os.path.join(run_dir, "dynamic")
    os.makedirs(dynamic_dir, exist_ok=True)

    storage = SessionStorage(base_dir=dynamic_dir, run_scoped=True)

    result: dict[str, Any] = {
        "run_id": run_id,
        "session_id": None,
        "status": None,
        "session_dir": dynamic_dir,
        "observation": None,
        "observation_error": None,
    }

    # Sanitize warnings/errors from preflight before they reach session persistence
    sanitized_warnings = [_sanitize_value(w) for w in preflight_result.warnings]
    sanitized_errors = [_sanitize_value(e) for e in preflight_result.errors]

    # --- FAIL preflight: create ABORTED session for evidence ---
    if preflight_result.status == PreflightStatus.FAIL:
        session = DynamicSession(
            package_name=package_name,
            device_serial=device_serial,
            preflight_status=preflight_result.status.value,
            status=SessionStatus.CREATED,
            warnings=sanitized_warnings,
            errors=sanitized_errors,
            metadata={"run_id": run_id},
        )

        # Record SESSION_STARTED
        session.timeline.append(TimelineEvent(
            type=EventType.SYSTEM_EVENT,
            name="SESSION_STARTED",
            timestamp=utc_now_iso(),
            metadata=_sanitize_value({
                "package_name": package_name,
                "device_serial": device_serial,
                "preflight_status": preflight_result.status.value,
            }),
            session_id=session.session_id,
        ))

        # Record DYNAMIC_PREFLIGHT_COMPLETED
        session.timeline.append(TimelineEvent(
            type=EventType.SYSTEM_EVENT,
            name="DYNAMIC_PREFLIGHT_COMPLETED",
            timestamp=utc_now_iso(),
            metadata=_build_preflight_event_metadata(preflight_result),
            session_id=session.session_id,
        ))

        # Abort session
        session.timeline.append(TimelineEvent(
            type=EventType.SYSTEM_EVENT,
            name="SESSION_ABORTED",
            timestamp=utc_now_iso(),
            metadata={"reason": "Preflight checks failed; dynamic execution blocked."},
            session_id=session.session_id,
        ))
        session.status = SessionStatus.ABORTED
        session.ended_at = utc_now_iso()

        storage.save_session(session)

        result["session_id"] = session.session_id
        result["status"] = SessionStatus.ABORTED.value
        logger.info(
            f"Dynamic session {session.session_id} created as ABORTED "
            f"for run {run_id} (preflight FAIL)"
        )
        return result

    # --- PASS / WARN preflight: start ACTIVE session via manager ---
    # Create a sanitized copy of preflight_result so the manager stores
    # clean warnings/errors without host paths.
    sanitized_preflight = PreflightResult(
        stage=preflight_result.stage,
        device=preflight_result.device,
        application=preflight_result.application,
        runtime=preflight_result.runtime,
        network=preflight_result.network,
        status=preflight_result.status,
        warnings=sanitized_warnings,
        errors=sanitized_errors,
    )

    manager = DynamicSessionManager(storage=storage)
    session = manager.start_session(
        package_name=package_name,
        device_serial=device_serial,
        preflight_result=sanitized_preflight,
        metadata={"run_id": run_id},
    )

    # Record DYNAMIC_PREFLIGHT_COMPLETED event
    manager._record_system_event(
        name="DYNAMIC_PREFLIGHT_COMPLETED",
        metadata=_build_preflight_event_metadata(preflight_result),
    )
    manager._persist_current_session()

    result["session_id"] = session.session_id
    result["status"] = SessionStatus.ACTIVE.value

    # --- Initial screen observation (only if callable provided) ---
    if observe_screen_fn is not None:
        try:
            observation = observe_screen_fn(
                serial=device_serial,
                target_package=package_name,
            )
            # Normalize to dict
            obs_dict = observation.to_dict() if hasattr(observation, "to_dict") else dict(observation)

            manager._record_system_event(
                name="SCREEN_OBSERVED",
                metadata=_build_observation_event_metadata(obs_dict),
            )
            manager._persist_current_session()

            result["observation"] = _build_observation_event_metadata(obs_dict)
            result["raw_observation"] = observation

        except Exception as exc:
            error_msg = _sanitize_value(str(exc))
            manager._record_system_event(
                name="UI_OBSERVATION_FAILED",
                metadata={"reason": error_msg},
            )
            manager._persist_current_session()

            result["observation_error"] = error_msg
            logger.warning(
                f"Initial UI observation failed for session {session.session_id}: {error_msg}"
            )

    logger.info(
        f"Dynamic session {session.session_id} initialized (ACTIVE) "
        f"for run {run_id} (preflight {preflight_result.status.value})"
    )
    return result
