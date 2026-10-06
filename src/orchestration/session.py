"""Session responsibilities for the demo pipeline."""
from __future__ import annotations

from pathlib import Path
from typing import Callable
import logging


from src.dynamic.preflight.models import (ApplicationInfo, DeviceInfo, NetworkInfo, PreflightResult, PreflightStatus, RuntimeBaseline)

logger = logging.getLogger(__name__)


def _wire_dynamic_session(
    root_path: Path,
    package_name: str,
    adb_serial: str | None,
    *,
    _wire_dynamic_analysis_report: Callable,
) -> None:
    """Initializes run-scoped dynamic session from persisted preflight evidence.

    Reads preflight_result.json, reconstructs PreflightResult, and invokes
    initialize_dynamic_session() with the UI observer wired for PASS/WARN paths.

    Failure is isolated — session initialization errors are silently absorbed
    and never break the pipeline or erase existing artifacts (static report,
    preflight_result.json).
    """
    try:
        preflight_file = root_path / "dynamic" / "preflight_result.json"
        if not preflight_file.is_file():
            return

        # Guard against duplicate initialization
        session_file = root_path / "dynamic" / "session.json"
        if session_file.is_file():
            return

        import json as _json
        with open(preflight_file, "r", encoding="utf-8") as f:
            pf_data = _json.load(f)

        status_str = pf_data.get("status", "FAIL")
        try:
            pf_status = PreflightStatus(status_str)
        except ValueError:
            pf_status = PreflightStatus.FAIL

        dev = pf_data.get("device", {})
        app = pf_data.get("application", {})
        rt = pf_data.get("runtime", {})
        net = pf_data.get("network", {})

        preflight = PreflightResult(
            device=DeviceInfo(
                connected=dev.get("connected", False),
                serial=dev.get("serial"),
                state=dev.get("state", "not_found"),
                is_emulator=dev.get("is_emulator", False),
            ),
            application=ApplicationInfo(
                package_name=app.get("package_name", package_name),
                installed=app.get("installed", False),
                launchable=app.get("launchable", False),
                main_activity=app.get("main_activity"),
                process_running=app.get("process_running", False),
                foreground=app.get("foreground", False),
            ),
            runtime=RuntimeBaseline(
                launch_success=rt.get("launch_success", False),
                immediate_crash=rt.get("immediate_crash", False),
                fatal_log_detected=rt.get("fatal_log_detected", False),
                pid=rt.get("pid"),
                launch_attempts=rt.get("launch_attempts", 1),
                ready_after_attempt=rt.get("ready_after_attempt"),
            ),
            network=NetworkInfo(
                internet_reachable=net.get("internet_reachable", False),
                dns_configured=net.get("dns_configured", False),
            ),
            status=pf_status,
            warnings=pf_data.get("warnings", []),
            errors=pf_data.get("errors", []),
        )

        pkg = app.get("package_name") or package_name
        from src.dynamic.runtime.execution_target import resolve_run_transport, verify_run_target
        from src.dynamic.preflight.device_check import run_adb_cmd, find_adb_binary
        verify_run_target(root_path, lambda args: run_adb_cmd(find_adb_binary() or 'adb', args))
        serial = resolve_run_transport(root_path, dev.get("serial"), adb_serial)

        # Only provide observation function when device is usable
        observe_fn = None
        if pf_status in (PreflightStatus.PASS, PreflightStatus.WARN):
            if dev.get("connected", True):
                try:
                    from src.dynamic.ui.observer import observe_screen
                    observe_fn = observe_screen
                except ImportError:
                    pass

        from src.dynamic.session.integration import initialize_dynamic_session
        return initialize_dynamic_session(
            run_id=root_path.name,
            run_dir=str(root_path),
            package_name=pkg,
            device_serial=serial,
            preflight_result=preflight,
            observe_screen_fn=observe_fn,
        )
    except Exception as exc:
        logger.warning("Dynamic session initialization unavailable.")
        _wire_dynamic_analysis_report(root_path)
        return None
