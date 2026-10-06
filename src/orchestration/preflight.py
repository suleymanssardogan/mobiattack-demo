"""Preflight responsibilities for the demo pipeline."""
from __future__ import annotations

from pathlib import Path
import logging


from src.dynamic.preflight.models import (ApplicationInfo, DeviceInfo, ErrorCode, NetworkInfo, PreflightResult, PreflightStatus, RuntimeBaseline)
from src.dynamic.preflight.service import save_preflight_result

logger = logging.getLogger(__name__)


def _persist_preflight_fallback(
    root_path: Path,
    package_name: str,
    launcher_activity: str | None,
    status: PreflightStatus,
    error_msg: str | None = None,
    error_code: ErrorCode | str | None = None,
    adb_serial: str | None = None,
    device_state: str = "not_found",
) -> None:
    """Ensures dynamic/preflight_result.json is persisted even on skip or failure."""
    try:
        errors = []
        if error_msg:
            code_val = error_code.value if isinstance(error_code, ErrorCode) else (str(error_code) if error_code else "PREFLIGHT_FAILED")
            errors.append({"code": code_val, "message": error_msg})
        pref = PreflightResult(
            stage="dynamic_preflight",
            device=DeviceInfo(
                connected=(status == PreflightStatus.PASS),
                serial=adb_serial,
                state=device_state if status != PreflightStatus.PASS else "device",
            ),
            application=ApplicationInfo(
                package_name=package_name,
                installed=False,
                launchable=False,
                main_activity=launcher_activity,
            ),
            runtime=RuntimeBaseline(
                launch_success=(status == PreflightStatus.PASS),
                immediate_crash=(error_code == ErrorCode.APP_CRASHED),
                fatal_log_detected=(error_code == ErrorCode.APP_CRASHED),
            ),
            network=NetworkInfo(),
            status=status,
            errors=errors,
        )
        save_preflight_result(pref, root_path)
    except Exception:
        pass


def _ensure_preflight_persisted_from_meta(
    root_path: Path,
    package_name: str,
    launcher_activity: str | None,
    runtime_meta: dict,
    adb_serial: str | None = None,
) -> None:
    """Persists preflight artifact from runtime_meta with hardened blocker/warning semantics."""
    if runtime_meta.get('runtime_permissions') is not None:
        from src.runtime_permissions import save_permission_observation
        save_permission_observation(root_path, runtime_meta['runtime_permissions'])
    preflight_file = root_path / "dynamic" / "preflight_result.json"
    if preflight_file.is_file():
        return
    try:
        rt = runtime_meta.get("runtime", {})
        pid = rt.get("pid")
        fg = bool(rt.get("foreground_verified"))
        status_str = str(runtime_meta.get("status", "")).lower()

        if pid is None or "failed" in status_str:
            preflight_status = PreflightStatus.FAIL
            errors = [{"code": ErrorCode.APP_LAUNCH_FAILED.value, "message": "Process failed to start or launch was not verified"}]
            warnings = []
        elif not fg:
            preflight_status = PreflightStatus.WARN
            errors = []
            warnings = [f"Application process is running (PID {pid}), but foreground window could not be verified."]
        else:
            preflight_status = PreflightStatus.PASS
            errors = []
            warnings = []

        pref = PreflightResult(
            stage="dynamic_preflight",
            device=DeviceInfo(
                connected=True,
                serial=runtime_meta.get("adb", {}).get("serial") or adb_serial,
                state="device",
            ),
            application=ApplicationInfo(
                package_name=package_name,
                installed=True,
                launchable=(pid is not None),
                main_activity=launcher_activity,
                process_running=(pid is not None),
                foreground=fg,
            ),
            runtime=RuntimeBaseline(
                launch_success=(pid is not None),
                immediate_crash=False,
                fatal_log_detected=False,
                pid=pid,
                launch_attempts=rt.get("launch_attempts", 1),
                ready_after_attempt=rt.get("ready_after_attempt", 1 if fg else None),
            ),
            network=NetworkInfo(internet_reachable=True, dns_configured=True),
            status=preflight_status,
            warnings=warnings,
            errors=errors,
        )
        save_preflight_result(pref, root_path)
    except Exception:
        pass
