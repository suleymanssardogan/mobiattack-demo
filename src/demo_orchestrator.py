"""Final End-to-End Demo Orchestrator for MobiAttack-v1.

Chains the complete deterministic analysis pipeline across:
- Task 06: URL to APK Acquisition (src/apk_acquirer.py)
- Task 07: APKtool / JADX Preprocessing Automation (src/apk_preprocessor.py)
- Task 05: Deterministic Static Context Builder (src/static_context_builder.py,
           reusing Tasks 01–04)
- Task 08: ADB / MuMu Basic Install & Launch Automation (src/android_runtime_launcher.py)

Provides a unified public run_demo entry point, human-readable summary formatting,
and fail-fast stage tracking without duplicating analysis logic or making security verdicts.
"""

from __future__ import annotations

from pathlib import Path

from src.apk_acquirer import ApkAcquisitionError, acquire_apk
from src.apk_preprocessor import ApkPreprocessingError, preprocess_apk
from src.static_context_builder import build_static_context
from src.url_classifier import classify_input_url
from src.android_runtime_launcher import (
    AndroidDeviceUnavailableError,
    AndroidRuntimeError,
    check_device_availability,
    get_connected_devices,
    launch_android_app,
)
from src.dynamic.preflight.models import (
    ApplicationInfo,
    DeviceInfo,
    ErrorCode,
    NetworkInfo,
    PreflightResult,
    PreflightStatus,
    RuntimeBaseline,
)
from src.dynamic.preflight.service import save_preflight_result
from src.play_store_acquirer import PlayStoreAcquisitionError, acquire_play_store_app, acquire_play_store_package
from src.split_preprocessor import preprocess_package_set
from src.split_static_context_builder import build_split_static_context
import hashlib
import ssl
import urllib.parse
import urllib.request
from src.platform_detector import detect_platform
from src.ios.ipa_extractor import IpaExtractionError, extract_ipa
from src.constants import IOS_RUNTIME_NOT_IMPLEMENTED
from src.ios.ios_static_context_builder import build_ios_static_context
from src.dynamic.exploration.loop import run_exploration
from src.dynamic.exploration.models import ExplorationLimits
import logging

logger = logging.getLogger(__name__)


class DemoOrchestrationError(ValueError):
    """Raised when any stage of the demo orchestration fails."""

    def __init__(self, message: str, stage: str, cause: Exception | None = None, reason_code: str | None = None):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage
        self.cause = cause
        self.reason_code = reason_code or getattr(cause, "reason_code", None)

from typing import Callable


def _runtime_with_availability(root_path, package_name, launcher_activity, *, progress_callback=None, **kwargs):
    """Runtime limitations are isolated; Static and result assembly always continue."""
    from src.dynamic.runtime.availability import availability, save_availability, RuntimeReason
    from src.android_runtime_launcher import AndroidRuntimeError
    try:
        if not isinstance(launcher_activity, str) or not launcher_activity.strip() or launcher_activity.endswith('.unknown'):
            raise AndroidRuntimeError('No declared enabled launcher.', 'LAUNCHER_UNRESOLVED',
                                      evidence={'source': 'launcher_resolution'})
        metadata = launch_android_app(package_name=package_name.strip(), launcher_activity=launcher_activity.strip(), **kwargs)
        runtime = metadata.get('runtime', {})
        pid = runtime.get('pid')
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 or runtime.get('process_survived') is False:
            raise AndroidRuntimeError('Runtime process could not be verified.', 'RUNTIME_OBSERVATION_UNAVAILABLE',
                                      evidence={'source': 'runtime_observation', 'process_survived': False})
        foreground = bool(runtime.get('foreground_verified'))
        record = availability('SUPPORTED', package_name=package_name, target_serial=metadata.get('adb', {}).get('serial') or kwargs.get('adb_serial'), status='available' if foreground else 'partial', evidence={
            'source': 'runtime_launcher', 'pid': pid, 'process_appeared': True, 'process_survived': True,
            'foreground_verified': foreground})
        from src.dynamic.runtime.execution_target import ExecutionTarget, save_target
        if metadata.get('execution_target'):
            selected = ExecutionTarget.from_dict(metadata['execution_target'])
            if selected.adb_serial != record['target_serial']:
                raise ValueError('TARGET_IDENTITY_MISMATCH')
            save_target(root_path, selected)
            record['execution_target_id'] = selected.target_id
        save_availability(root_path, record)
        metadata['runtime_availability'] = record
        _ensure_preflight_persisted_from_meta(root_path, package_name, launcher_activity, metadata, kwargs.get('adb_serial'))
        _emit_progress(progress_callback, 'runtime', 'success', record['message'], metadata)
        return metadata
    except Exception as exc:
        reason = getattr(exc, 'reason_code', 'UNKNOWN')
        if isinstance(exc, AndroidDeviceUnavailableError):
            reason = 'RUNTIME_OBSERVATION_UNAVAILABLE'
        if reason not in {item.value for item in RuntimeReason}:
            reason = 'UNKNOWN'
        backend_reason = getattr(exc, 'backend_reason_code', reason)
        if isinstance(exc, AndroidDeviceUnavailableError):
            backend_reason = {'adb_not_found': 'ADB_NOT_FOUND', 'unauthorized': 'DEVICE_UNAUTHORIZED',
                'offline': 'DEVICE_OFFLINE', 'multiple_devices': 'MULTIPLE_DEVICES'}.get(getattr(exc, 'reason', ''), 'DEVICE_NOT_FOUND')
        record = availability(reason, package_name=package_name, target_serial=kwargs.get('adb_serial'), backend_reason=backend_reason,
            evidence=getattr(exc, 'evidence', None) or {'source': 'runtime_boundary', 'exception_type': type(exc).__name__})
        from src.dynamic.runtime.execution_target import load_target
        selected = load_target(root_path)
        if selected:
            record['target_serial'] = selected.adb_serial
            record['execution_target_id'] = selected.target_id
        save_availability(root_path, record)
        _persist_preflight_fallback(root_path, package_name, launcher_activity, PreflightStatus.FAIL,
            record['message'], record['reason_code'], adb_serial=kwargs.get('adb_serial'))
        _emit_progress(progress_callback, 'runtime', 'skipped', record['message'], {'runtime_availability': record})
        _wire_dynamic_analysis_report(root_path)
        _update_scan_state_dynamic_stage(root_path, 'not_available', record['message'])
        return {'status': 'unavailable', 'runtime_availability': record, 'runtime': {'pid': None, 'process_running': False}}


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

def _wire_dynamic_session(
    root_path: Path,
    package_name: str,
    adb_serial: str | None,
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
            from src.dynamic.session.storage import SessionStorage
            events: list[dict[str, Any]] = []
            if self.timeline_path.is_file():
                with open(self.timeline_path, "r", encoding="utf-8") as f:
                    events = _json.load(f)
            events.append(event_dict)
            SessionStorage._atomic_write_json(str(self.timeline_path), events)
        except Exception as err:
            logger.warning("Failed to append event '%s' to timeline: %s", event_dict.get("name"), err)


def _update_scan_state_dynamic_stage(
    root_path: Path,
    status: str,
    message: str,
    current_stage: str | None = None,
) -> None:
    """Updates scan_state.json dynamically using atomic scan_state helpers."""
    try:
        from src.scan_state import (
            load_scan_state,
            mark_artifact_available,
            save_scan_state,
            update_stage_status,
            sync_dynamic_report_artifact,
        )
        st = load_scan_state(root_path, validate_artifacts=False)
        if not st:
            return

        # Product integrity: dynamic_analysis cannot be completed without canonical dynamic_analysis_report
        was_registered = st["artifacts"]["dynamic_analysis_report"].get("available", False)
        available = sync_dynamic_report_artifact(st, root_path, complete_stage=False)
        if available and not was_registered:
            save_scan_state(root_path, st)
        sync_dynamic_report_artifact(st, root_path)
        actual_stat = ("completed" if available else "partial") if status in ("partial", "completed") else status
        update_stage_status(st, "dynamic_analysis", actual_stat, message)
        if current_stage:
            st["current_stage"] = current_stage
        elif status == "running":
            st["current_stage"] = "dynamic_analysis"
        elif st.get("current_stage") == "dynamic_analysis":
            st["current_stage"] = "report_generation"

        # Maintain report_generation partial state if static_analysis_report is available
        static_report = root_path / "static_analysis_report.json"
        if static_report.is_file():
            mark_artifact_available(st, "static_analysis_report", "static_analysis_report.json")
            update_stage_status(
                st,
                "report_generation",
                "partial",
                "Static analysis report available; additional analysis reports pending.",
            )

        save_scan_state(root_path, st)
    except Exception as exc:
        logger.warning("Failed to update scan_state for dynamic_analysis: %s", exc)


def _finalize_scan_state_post_run(root_path: Path) -> None:
    """Updates scan_state.json after report generation to ensure current_stage and artifacts are consistent."""
    try:
        from src.scan_state import (
            load_scan_state,
            save_scan_state,
            mark_artifact_available,
            update_stage_status,
        )
        st = load_scan_state(root_path)
        if not st:
            return
        static_report = root_path / "static_analysis_report.json"
        if static_report.is_file():
            mark_artifact_available(st, "static_analysis_report", "static_analysis_report.json")
            update_stage_status(
                st,
                "report_generation",
                "partial",
                "Static analysis report available; additional analysis reports pending.",
            )
        # Avoid stale current_stage: truthful representation of latest reached stage
        if st.get("overall_status") == "completed":
            st["current_stage"] = "completed"
        elif st.get("current_stage") == "dynamic_analysis":
            st["current_stage"] = "report_generation"
        save_scan_state(root_path, st)
    except Exception as exc:
        logger.debug("Failed to finalize scan_state post-run: %s", exc)


def _wire_dynamic_exploration(
    root_path: Path,
    package_name: str,
    adb_serial: str | None = None,
    progress_callback: Callable[[str, str, str, dict | None], None] | None = None,
    limits: Any | None = None,
    initial_observation: Any | None = None,
    traffic_proxy_port: int = 8080,
) -> Any | None:
    """Wires and executes the bounded dynamic exploration loop in the real scan pipeline.

    Convergence Flow:
    1. Checks preflight usability (PASS or usable WARN).
    2. Verifies existing dynamic session (reusing session_id).
    3. Guards against duplicate exploration.
    4. Updates scan_state: dynamic_analysis -> 'running', current_stage -> 'dynamic_analysis'.
    5. Instantiates RouteGraph, RouteGraphStorage, ActionExecutor, and UI observer.
    6. Appends exploration events to the existing dynamic/timeline.json.
    7. Runs bounded exploration.
    8. Persists dynamic/exploration_result.json atomically.
    9. Generates canonical dynamic report; completes only after validated artifact registration.
    10. Failure isolation: never raises or corrupts static report, preflight, or session artifacts.
    """
    try:
        import json as _json
        from src.android_runtime_launcher import resolve_adb_executable
        from src.dynamic.action.executor import ActionExecutor
        from src.dynamic.route.graph import RouteGraph
        from src.dynamic.route.storage import RouteGraphStorage
        from src.dynamic.session.storage import SessionStorage

        preflight_file = root_path / "dynamic" / "preflight_result.json"
        if not preflight_file.is_file():
            return None

        # Guard against duplicate exploration
        result_file = root_path / "dynamic" / "exploration_result.json"
        if result_file.is_file():
            return None

        with open(preflight_file, "r", encoding="utf-8") as f:
            pf_data = _json.load(f)

        status_str = pf_data.get("status", "FAIL")
        if status_str not in ("PASS", "WARN"):
            return None

        dev = pf_data.get("device", {})
        app = pf_data.get("application", {})
        rt = pf_data.get("runtime", {})

        # If WARN, check if device and application are usable
        if status_str == "WARN":
            connected = dev.get("connected", False)
            launch_ok = rt.get("launch_success", False) or app.get("process_running", False)
            crashed = rt.get("immediate_crash", False)
            if not connected or not launch_ok or crashed:
                logger.info("Dynamic exploration skipped: preflight WARN indicates app/device not usable.")
                return None

        # Check session existence and active status
        session_file = root_path / "dynamic" / "session.json"
        if not session_file.is_file():
            logger.info("Dynamic exploration skipped: dynamic/session.json not found.")
            return None

        with open(session_file, "r", encoding="utf-8") as f:
            session_data = _json.load(f)

        if session_data.get("status") == "ABORTED":
            return None

        session_id = session_data.get("session_id")
        target_pkg = app.get("package_name") or package_name
        from src.dynamic.runtime.execution_target import resolve_run_transport, verify_run_target
        from src.dynamic.preflight.device_check import run_adb_cmd, find_adb_binary
        verify_run_target(root_path, lambda args: run_adb_cmd(find_adb_binary() or 'adb', args))
        target_serial = resolve_run_transport(root_path, dev.get("serial"), adb_serial, session_data.get("device_serial"))

        # Update product state: dynamic_analysis becomes running
        _update_scan_state_dynamic_stage(
            root_path,
            status="running",
            message="Dynamic UI exploration in progress...",
            current_stage="dynamic_analysis",
        )
        _emit_progress(
            progress_callback,
            "dynamic_analysis",
            "running",
            "Dynamic UI exploration in progress...",
        )

        # Prepare components
        try:
            adb_bin = resolve_adb_executable()
        except Exception:
            adb_bin = "adb"
        route_graph = RouteGraph(run_id=root_path.name, session_id=session_id)
        graph_storage = RouteGraphStorage(base_dir=root_path / "dynamic")
        executor = ActionExecutor(serial=target_serial, adb_bin=adb_bin)
        cfg = limits or ExplorationLimits(max_steps=10, max_depth=3, deadline_seconds=60.0)

        # Observer callback
        from src.dynamic.ui.observer import observe_screen
        def _observer_callback():
            return observe_screen(serial=target_serial, adb_bin=adb_bin, target_package=target_pkg)

        # Runtime observer wiring (Task 6.2)
        from src.dynamic.runtime.observer import AndroidRuntimeObserver
        runtime_observer = AndroidRuntimeObserver(serial=target_serial, adb_bin=adb_bin)
        runtime_evidence_file = root_path / "dynamic" / "runtime_evidence.json"

        # Timeline recorder wiring to existing timeline.json
        timeline_path = root_path / "dynamic" / "timeline.json"
        timeline_recorder = ExplorationTimelineRecorder(timeline_path, session_id=session_id)

        # Traffic capture wiring (Task 6.3)
        from src.dynamic.traffic.service import DynamicTrafficService
        from src.dynamic.traffic.storage import TrafficStorage
        from src.dynamic.traffic.mitmproxy_backend import MitmproxyCaptureBackend
        from src.dynamic.traffic.native_backend import NativeProxyCaptureBackend

        traffic_evidence_file = root_path / "dynamic" / "traffic_evidence.json"
        traffic_file = root_path / "dynamic" / "traffic.json"
        traffic_storage = TrafficStorage(base_dir=str(root_path / "dynamic"))

        mitm_backend = MitmproxyCaptureBackend()
        traffic_backend = mitm_backend if mitm_backend.check_available() else NativeProxyCaptureBackend()
        traffic_service = DynamicTrafficService(
            backend=traffic_backend,
            storage=traffic_storage,
            adb_bin=adb_bin,
        )

        traffic_started = False
        try:
            from src.dynamic.runtime.execution_target import load_target, record_capabilities
            current_target = load_target(root_path)
            proxy_options = {'proxy_host': current_target.proxy_context['host']} if current_target and current_target.proxy_context else {}
            readiness = traffic_service.check_readiness(device_serial=target_serial, proxy_port=traffic_proxy_port, **proxy_options)
            record_capabilities(root_path, {'host_reachability': 'available' if readiness.device_reachable_proxy is True else 'unknown'}, 'proxy_readiness')
            if readiness.backend_available and readiness.adb_available and readiness.port_available:
                traffic_service.start_capture(
                    session=session_id,
                    device_serial=target_serial,
                    proxy_port=traffic_proxy_port,
                    **proxy_options,
                )
                traffic_started = True
                timeline_recorder._record_system_event(
                    "TRAFFIC_CAPTURE_STARTED",
                    {"backend": traffic_backend.__class__.__name__, "proxy_port": traffic_proxy_port},
                )
            else:
                traffic_service.http_visibility = "unavailable"
                traffic_service.http_reason = readiness.errors[0]["code"] if readiness.errors else "proxy_readiness_failed"
                timeline_recorder._record_system_event(
                    "TRAFFIC_CAPTURE_UNAVAILABLE",
                    {"warnings": readiness.warnings},
                )
        except Exception as exc:
            traffic_service.http_visibility = "unavailable"
            traffic_service.http_reason = getattr(getattr(exc, "error_code", None), "value", "capture_start_failed")
            logger.warning("Traffic capture start skipped/failed: %s", exc)
            timeline_recorder._record_system_event(
                "TRAFFIC_CAPTURE_UNAVAILABLE",
                {"error": str(exc)},
            )

        from src.dynamic.runtime.execution_target import record_capabilities
        visibility = traffic_service.get_visibility_metadata()
        if not traffic_started:
            from src.dynamic.traffic.models import CaptureSummary
            traffic_service.storage.save_traffic_json(
                target_path=traffic_file, session_id=session_id, transactions=[],
                capture=traffic_service.active_capture,
                summary=CaptureSummary(session_id=session_id, http_visibility='unavailable',
                    http_visibility_reason=visibility.get('http_reason', 'capture_start_failed'),
                    https_visibility=visibility.get('https_visibility', 'unavailable'),
                    https_visibility_reason=visibility.get('https_reason', 'capture_backend_unavailable')))
        record_capabilities(root_path, {
            'traffic_capture': 'available' if traffic_started else 'unavailable',
            'proxy_configuration': 'available' if traffic_started else 'unknown',
            'http_capture': visibility.get('http_visibility', 'unknown') if traffic_started else 'unknown',
            'https_capture': visibility.get('https_visibility', 'unknown') if visibility.get('https_visibility') in {'available', 'unavailable', 'unknown'} else 'unknown',
        }, 'traffic_backend')

        try:
            # Run bounded exploration loop
            res = run_exploration(
                observer=_observer_callback,
                executor=executor,
                route_graph=route_graph,
                graph_storage=graph_storage,
                timeline_recorder=timeline_recorder,
                limits=cfg,
                initial_observation=initial_observation,
                runtime_observer=runtime_observer,
                target_package=target_pkg,
                runtime_evidence_file=runtime_evidence_file,
                traffic_service=traffic_service if traffic_started else None,
                traffic_evidence_file=traffic_evidence_file if traffic_started else None,
            )
        finally:
            if traffic_started:
                try:
                    summary = traffic_service.stop_capture()
                    if traffic_service.active_capture:
                        traffic_service.storage.save_traffic_json(
                            target_path=traffic_file,
                            session_id=session_id,
                            transactions=traffic_service.captured_transactions,
                            capture=traffic_service.active_capture,
                            summary=summary,
                        )
                    tx_cnt = getattr(summary, "total_transactions", 0) if summary else 0
                    p_rest = getattr(summary, "proxy_restored", True) if summary else True
                    timeline_recorder._record_system_event(
                        "TRAFFIC_CAPTURE_STOPPED",
                        {"total_transactions": tx_cnt, "proxy_restored": p_rest},
                    )
                except Exception as exc:
                    logger.error("Failed to stop traffic capture or restore proxy: %s", exc)

        # Persist compact exploration_result.json atomically
        result_dict = res.to_dict()
        SessionStorage._atomic_write_json(str(result_file), result_dict)

        # Determine dynamic_analysis final status based on evidence
        has_evidence = (
            res.screens_observed > 0
            or res.actions_succeeded > 0
            or (root_path / "dynamic" / "route_graph.json").is_file()
            or (root_path / "dynamic" / "runtime_evidence.json").is_file()
            or (root_path / "dynamic" / "traffic.json").is_file()
            or (root_path / "dynamic" / "traffic_evidence.json").is_file()
        )
        if has_evidence:
            final_status = "partial"
            final_msg = "Dynamic exploration produced partial runtime evidence."

            # Static <-> Dynamic API Correlation (Task 7.1)
            try:
                _wire_api_correlation(
                    root_path=root_path,
                    session_id=session_id,
                    timeline_recorder=timeline_recorder,
                    traffic_service=traffic_service if traffic_started else None,
                )
            except Exception as corr_exc:
                logger.error("Static <-> Dynamic API correlation failed (isolated): %s", corr_exc)

            # Task 8.1: project finalized evidence into the root canonical product report.
            report = _wire_dynamic_analysis_report(root_path)
            if report is not None:
                final_status = "completed"
                final_msg = "Canonical dynamic report generated and validated; runtime coverage may be partial."
        else:
            final_status = "failed"
            final_msg = f"Dynamic exploration failed: {res.error or 'No UI evidence observed.'}"

        _update_scan_state_dynamic_stage(
            root_path,
            status=final_status,
            message=final_msg,
            current_stage="report_generation",
        )
        _emit_progress(
            progress_callback,
            "dynamic_analysis",
            final_status,
            final_msg,
            result_dict,
        )
        return res

    except Exception as exc:
        from src.dynamic.runtime.execution_target import load_target
        selected = load_target(root_path)
        if selected and selected.availability == 'unavailable':
            _wire_dynamic_analysis_report(root_path)
            _update_scan_state_dynamic_stage(root_path, 'not_available', 'Current execution environment unavailable.')
            return None
        logger.error("Dynamic exploration wiring encountered an error: %s", exc, exc_info=True)
        try:
            _update_scan_state_dynamic_stage(
                root_path,
                status="failed",
                message=f"Dynamic exploration error: {str(exc)}",
                current_stage="report_generation",
            )
            _emit_progress(
                progress_callback,
                "dynamic_analysis",
                "failed",
                f"Dynamic exploration error: {str(exc)}",
            )
        except Exception:
            pass
        return None


def _wire_api_correlation(
    root_path: Path,
    session_id: str,
    timeline_recorder: Any | None = None,
    traffic_service: Any | None = None,
) -> Any:
    """Task 7.1: Correlates static API candidates with captured dynamic traffic transactions.

    Persists dynamic/api_correlation.json atomically.
    Failure-isolated: prior evidence is never modified or erased.
    """
    try:
        import json
        from src.dynamic.correlation import correlate_static_dynamic_apis
        from src.dynamic.traffic.models import TrafficEvidenceArtifact

        dynamic_dir = root_path / "dynamic"
        corr_file = dynamic_dir / "api_correlation.json"

        # 1. Load static candidates from static_analysis_report.json if available
        static_report_path = root_path / "static_analysis_report.json"
        static_candidates: list[Any] = []
        if static_report_path.is_file():
            try:
                with open(static_report_path, "r", encoding="utf-8") as f:
                    static_data = json.load(f)
                static_candidates = static_data.get("api_candidates", [])
            except Exception as exc:
                logger.warning("Could not read static candidates for correlation: %s", exc)

        # 2. Collect dynamic transactions and visibility context
        transactions: list[Any] = []
        http_vis = "available"
        https_vis = "unavailable"
        https_reason = "certificate_trust_unknown"

        traffic_file = dynamic_dir / "traffic.json"
        if traffic_service and getattr(traffic_service, "captured_transactions", None):
            transactions = list(traffic_service.captured_transactions)
            visibility = traffic_service.get_visibility_metadata()
            http_vis = visibility.get('http_visibility', 'unknown')
            https_vis = visibility.get('https_visibility', 'unknown')
            https_reason = visibility.get('https_reason', 'no_https_transaction_available_to_verify')
        elif traffic_file.is_file():
            try:
                with open(traffic_file, "r", encoding="utf-8") as f:
                    traffic_data = json.load(f)
                transactions = traffic_data.get("transactions", [])
                http_vis = traffic_data.get("http_visibility", "available")
                https_vis = traffic_data.get("https_visibility", "unavailable")
                https_reason = traffic_data.get("https_visibility_reason", "certificate_trust_unknown")
            except Exception as exc:
                logger.warning("Could not read traffic.json for correlation: %s", exc)

        # 3. Load traffic_evidence.json if available
        traffic_evidence_file = dynamic_dir / "traffic_evidence.json"
        traffic_evidence = None
        if traffic_evidence_file.is_file():
            try:
                traffic_evidence = TrafficEvidenceArtifact.load_or_create(traffic_evidence_file, session_id=session_id)
            except Exception as exc:
                logger.warning("Could not read traffic_evidence.json for correlation: %s", exc)

        # 4. Perform correlation
        corr_result = correlate_static_dynamic_apis(
            static_candidates=static_candidates,
            traffic_transactions=transactions,
            session_id=session_id,
            traffic_evidence=traffic_evidence,
            http_visibility=http_vis,
            https_visibility=https_vis,
            https_visibility_reason=https_reason,
        )

        # 5. Atomically persist api_correlation.json
        corr_result.save_atomic(corr_file)

        # 6. Record compact timeline event if timeline_recorder available
        if timeline_recorder and hasattr(timeline_recorder, "_record_system_event"):
            try:
                timeline_recorder._record_system_event(
                    "API_CORRELATION_COMPLETED",
                    {
                        "static_candidates": corr_result.summary.static_candidate_count,
                        "dynamic_endpoints": corr_result.summary.dynamic_endpoint_count,
                        "correlated_count": corr_result.summary.correlated_count,
                        "static_only": corr_result.summary.static_only_count,
                        "dynamic_only": corr_result.summary.dynamic_only_count,
                    },
                )
            except Exception as exc:
                logger.warning("Could not record API_CORRELATION_COMPLETED event: %s", exc)

        _wire_endpoint_contexts(root_path, transactions, traffic_evidence, timeline_recorder)

        return corr_result
    except Exception as exc:
        logger.error("Static <-> Dynamic API correlation failed (isolated): %s", exc, exc_info=True)
        return None



def _wire_endpoint_contexts(
    root_path: Path,
    transactions: list[Any] | None = None,
    traffic_evidence: Any | None = None,
    timeline_recorder: Any | None = None,
) -> Any:
    """Task 7.2: build passive context only after canonical correlation exists."""
    try:
        import json
        from src.dynamic.context import build_endpoint_contexts
        from src.dynamic.correlation.models import ApiCorrelationResult
        from src.dynamic.runtime.models import RuntimeEvidenceArtifact
        from src.dynamic.traffic.models import TrafficEvidenceArtifact

        dynamic_dir = root_path / "dynamic"
        corr_file = dynamic_dir / "api_correlation.json"
        if not corr_file.is_file():
            return None
        correlation = ApiCorrelationResult.load(corr_file)
        if transactions is None:
            traffic_file = dynamic_dir / "traffic.json"
            transactions = json.loads(traffic_file.read_text()).get("transactions", []) if traffic_file.is_file() else []
        if traffic_evidence is None and (dynamic_dir / "traffic_evidence.json").is_file():
            traffic_evidence = TrafficEvidenceArtifact.load_or_create(dynamic_dir / "traffic_evidence.json", correlation.session_id)
        runtime_file = dynamic_dir / "runtime_evidence.json"
        runtime_evidence = None
        if runtime_file.is_file():
            try:
                runtime_evidence = RuntimeEvidenceArtifact.from_dict(json.loads(runtime_file.read_text()))
            except Exception as exc:
                logger.warning("Could not read runtime evidence for endpoint contexts: %s", exc)
        result = build_endpoint_contexts(correlation, transactions, traffic_evidence, runtime_evidence)
        result.save_atomic(dynamic_dir / "endpoint_contexts.json")
        if timeline_recorder and hasattr(timeline_recorder, "_record_system_event"):
            try:
                timeline_recorder._record_system_event("ENDPOINT_CONTEXTS_BUILT", dict(result.summary))
            except Exception as exc:
                logger.warning("Could not record ENDPOINT_CONTEXTS_BUILT: %s", exc)
        return result
    except Exception as exc:
        logger.error("Endpoint context builder failed (isolated): %s", exc, exc_info=True)
        return None



def _wire_dynamic_analysis_report(root_path: Path) -> Any | None:
    """Report-only generation; persistence and validation precede state registration."""
    try:
        from src.report_generator import generate_dynamic_analysis_report
        from src.scan_state import load_scan_state, save_scan_state, sync_dynamic_report_artifact
        state = load_scan_state(root_path, validate_artifacts=False)
        report = generate_dynamic_analysis_report(root_path, state.get("target", {}) if state else {})
        if state:
            # Checkpoint availability first. Completion is a subsequent persisted transition.
            state["artifacts"]["dynamic_analysis_report"] = {"available": True, "relative_path": "dynamic_analysis_report.json"}
            save_scan_state(root_path, state)
            sync_dynamic_report_artifact(state, root_path)
            save_scan_state(root_path, state)
        return report
    except Exception as exc:
        logger.warning("Canonical dynamic report generation failed (isolated): %s", exc)
        return None



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


def _run_ios_pipeline(
    url: str,
    output_root: Path,
    timeout_seconds: float = 300.0,
    progress_callback: Callable[[str, str, str, dict | None], None] | None = None,
) -> dict:
    downloads_dir = output_root / "downloads"
    workspaces_dir = output_root / "workspaces"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    workspaces_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------
    # STAGE 1: ACQUISITION (iOS)
    # -------------------------------------------------------------
    _emit_progress(progress_callback, "acquisition", "running", "Acquiring and validating iOS IPA package...")
    clean_url = url.strip()
    target_file: Path | None = None

    if clean_url.startswith(("http://", "https://")):
        try:
            parsed = urllib.parse.urlparse(clean_url)
            filename = Path(parsed.path).name or "app.ipa"
            if not filename.lower().endswith(".ipa"):
                filename = f"{filename}.ipa"
            dest_file = downloads_dir / filename
            req = urllib.request.Request(clean_url, headers={"User-Agent": "MobiAttack/2.0"})
            # Framework Python on macOS may lack a bundled CA file; use the system
            # trust bundle when present, while retaining normal TLS verification.
            default_ca = ssl.get_default_verify_paths().openssl_cafile
            mac_ca = Path("/etc/ssl/cert.pem")
            tls_context = (
                ssl.create_default_context(cafile=str(mac_ca))
                if default_ca and not Path(default_ca).is_file() and mac_ca.is_file()
                else ssl.create_default_context()
            )
            with urllib.request.urlopen(req, timeout=min(timeout_seconds, 60.0), context=tls_context) as resp, open(dest_file, "wb") as out_fp:
                while chunk := resp.read(65536):
                    out_fp.write(chunk)
            target_file = dest_file
        except Exception as exc:
            _emit_progress(progress_callback, "acquisition", "failed", f"Failed to acquire IPA: {exc}")
            raise DemoOrchestrationError(message=f"Failed to acquire IPA: {exc}", stage="acquisition", cause=exc) from exc
    elif clean_url.startswith("file://"):
        target_file = Path(urllib.parse.unquote(clean_url[7:])).resolve()
    else:
        target_file = Path(clean_url).resolve()

    if not target_file or not target_file.is_file():
        err_msg = f"Target IPA file does not exist: '{target_file}'"
        _emit_progress(progress_callback, "acquisition", "failed", err_msg)
        raise DemoOrchestrationError(message=err_msg, stage="acquisition")

    detection = detect_platform(target_file)
    if detection.get("platform") != "ios" or not detection.get("valid"):
        err_msg = f"Invalid iOS IPA package: {detection.get('reason', 'structural validation failed')}"
        _emit_progress(progress_callback, "acquisition", "failed", err_msg)
        raise DemoOrchestrationError(message=err_msg, stage="acquisition")

    hasher = hashlib.sha256()
    with open(target_file, "rb") as fp:
        while chunk := fp.read(65536):
            hasher.update(chunk)
    sha256 = hasher.hexdigest()
    size_bytes = target_file.stat().st_size

    acq_meta = {
        "platform": "ios",
        "source_type": "direct_ipa",
        "filename": target_file.name,
        "ipa_path": str(target_file),
        "sha256": sha256,
        "size_bytes": size_bytes,
        "validation": {
            "is_valid_ipa": True,
            "app_bundle": detection.get("app_bundle"),
            "has_info_plist": detection.get("has_info_plist", True),
        },
    }
    _emit_progress(progress_callback, "acquisition", "success", f"iOS IPA validated ({acq_meta['filename']}).", acq_meta)

    # -------------------------------------------------------------
    # STAGE 2: PREPROCESSING (iOS Safe Extraction)
    # -------------------------------------------------------------
    _emit_progress(progress_callback, "preprocessing", "running", "Safely extracting iOS IPA into workspace...")
    extract_out = workspaces_dir / "ios_extracted"
    try:
        extract_res = extract_ipa(ipa_path=target_file, output_dir=extract_out)
    except Exception as exc:
        _emit_progress(progress_callback, "preprocessing", "failed", str(exc))
        raise DemoOrchestrationError(message=str(exc), stage="preprocessing", cause=exc) from exc

    prep_meta = {
        "status": "success",
        "platform": "ios",
        "app_bundle": extract_res["app_bundle"],
        "app_bundle_dir": extract_res["app_bundle_dir"],
        "extracted_files": extract_res["extracted_files"],
        "total_files": extract_res["extracted_files"],
        "total_extracted_bytes": extract_res["total_extracted_bytes"],
    }
    _emit_progress(progress_callback, "preprocessing", "success", f"Extracted {extract_res['extracted_files']} files cleanly.", prep_meta)

    # -------------------------------------------------------------
    # STAGE 3: STATIC ANALYSIS (iOS Normalized Context)
    # -------------------------------------------------------------
    _emit_progress(progress_callback, "static_analysis", "running", "Building normalized iOS static security context...")
    try:
        static_context = build_ios_static_context(
            app_bundle_dir=extract_res["app_bundle_dir"],
            relative_bundle_path=extract_res["app_bundle"],
            ipa_metadata=acq_meta,
        )
    except Exception as exc:
        _emit_progress(progress_callback, "static_analysis", "failed", str(exc))
        raise DemoOrchestrationError(message=str(exc), stage="static_analysis", cause=exc) from exc

    bundle_id = static_context.get("application", {}).get("bundle_identifier") or "unknown"
    _emit_progress(progress_callback, "static_analysis", "success", f"iOS static context generated for '{bundle_id}'.", static_context)

    # -------------------------------------------------------------
    # STAGE 4: RUNTIME VERIFICATION (Explicit factual state)
    # -------------------------------------------------------------
    _emit_progress(progress_callback, "runtime", "skipped", "iOS runtime launch verification is not implemented in Phase 1.")
    import copy
    runtime_meta = copy.deepcopy(IOS_RUNTIME_NOT_IMPLEMENTED)

    # -------------------------------------------------------------
    # STAGE 5: RESULT ASSEMBLY
    # -------------------------------------------------------------
    demo3_scan = None
    try:
        from src.demo3.scanner import scan_artifacts_deterministically
        demo3_scan = scan_artifacts_deterministically(extract_res["app_bundle_dir"])
    except Exception:
        pass

    final_result = {
        "platform": "ios",
        "input": {
            "url": url,
            "platform": "ios",
            "source_type": "direct_ipa",
            "package_name": bundle_id,
            "adb_serial": None,
            "reinstall": False,
            "grant_permissions": False,
        },
        "application": static_context.get("application", {}),
        "configuration": static_context.get("configuration", {}),
        "structure": static_context.get("structure", {}),
        "network_indicators": static_context.get("network_indicators", []),
        "api_candidates": static_context.get("api_candidates", []),
        "acquisition": acq_meta,
        "preprocessing": prep_meta,
        "static_analysis": static_context,
        "runtime": runtime_meta,
        "vulnerabilities": None,
        "demo3_scan": demo3_scan,
        "demo_status": "completed",
    }
    from src.vulnerability_evaluator import evaluate_vulnerabilities
    final_result["vulnerabilities"] = evaluate_vulnerabilities(final_result)
    from src.report_generator import generate_reports
    generate_reports(run_dir=output_root, run_id=output_root.name, pipeline_result=final_result)

    _emit_progress(progress_callback, "demo", "completed", "iOS demo pipeline execution completed.", final_result)
    return final_result


def run_demo(
    url: str,
    output_root: str | Path,
    platform: str = "android",
    adb_serial: str | None = None,
    reinstall: bool = False,
    grant_permissions: bool = False,
    timeout_seconds: float = 300.0,
    progress_callback: Callable[[str, str, str, dict | None], None] | None = None,
    install_mode: str = "manual",
    install_wait_timeout_seconds: float = 180.0,
    traffic_proxy_port: int = 8080,
) -> dict:
    """Executes the full deterministic MobiAttack-v1 demo pipeline.

    Args:
        url: Direct or redirected HTTP/HTTPS URL for the target APK, or Google Play Store URL.
        output_root: Root directory where demo downloads and workspaces will reside.
        platform: Target mobile OS platform ('android' or 'ios'). Defaults to 'android'.
        adb_serial: Optional target device/emulator serial for runtime installation.
        reinstall: If True, instructs ADB to allow reinstalling existing packages.
        grant_permissions: If True, passes '-g' to ADB to pre-grant runtime permissions.
        timeout_seconds: Subprocess timeout ceiling for preprocessing and ADB commands.
        traffic_proxy_port: Existing capture service port; defaults to 8080.
        progress_callback: Optional callable(stage, state, message, data=None) for live tracking.

    Returns:
        Structured demo result dictionary containing all stage outputs.

    Raises:
        DemoOrchestrationError: On failure at any pipeline stage, preserving stage tag
                                and original exception cause.
    """
    if type(traffic_proxy_port) is not int or not 1 <= traffic_proxy_port <= 65535:
        raise ValueError("traffic_proxy_port must be an integer from 1 to 65535")
    root_path = Path(output_root).resolve()
    downloads_dir = root_path / "downloads"
    workspaces_dir = root_path / "workspaces"

    downloads_dir.mkdir(parents=True, exist_ok=True)
    workspaces_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------
    # STAGE 1: ACQUISITION (Task 06 / Task 13)
    # -------------------------------------------------------------
    classification = classify_input_url(url=url, platform=platform)
    if classification.get("platform") == "ios":
        if classification.get("type") == "direct_ipa":
            return _run_ios_pipeline(
                url=url,
                output_root=root_path,
                timeout_seconds=timeout_seconds,
                progress_callback=progress_callback,
            )
        err_msg = classification.get("message") or "iOS analysis is not implemented in V1."
        _emit_progress(progress_callback, "acquisition", "failed", err_msg)
        raise DemoOrchestrationError(message=err_msg, stage="acquisition")

    if classification.get("type") == "unsupported":
        err_msg = classification.get("reason") or "Unsupported Android URL. Provide a direct APK URL or a Google Play Store application URL."
        _emit_progress(progress_callback, "acquisition", "failed", err_msg)
        raise DemoOrchestrationError(message=err_msg, stage="acquisition", reason_code="INVALID_ANDROID_URL")

    url = classification.get("normalized_url", url)
    if classification.get("type") == "play_store":
        pkg = classification.get("package_name") or "unknown"
        _emit_progress(
            progress_callback,
            "acquisition",
            "running",
            f"Querying connected Android device for installed package '{pkg}'...",
        )
        target_serial = adb_serial
        if not target_serial:
            try:
                connected = get_connected_devices(with_states=True)
                if not connected:
                    err_msg = "No connected Android devices found via ADB for Play Store acquisition."
                    _emit_progress(progress_callback, "acquisition", "failed", err_msg)
                    raise DemoOrchestrationError(message=err_msg, stage="acquisition")
                from src.dynamic.runtime.execution_target import select_transport
                target_serial = select_transport([s if isinstance(s, tuple) else (s, 'device') for s in connected])
            except Exception as exc:
                _emit_progress(progress_callback, "acquisition", "failed", str(exc))
                raise DemoOrchestrationError(message=str(exc), stage="acquisition", cause=exc) from exc

        adb_serial = target_serial  # pin acquisition and runtime to the same selected transport
        try:
            acq_meta = acquire_play_store_app(
                package_name=pkg,
                output_dir=downloads_dir,
                serial=target_serial,
                timeout_seconds=min(timeout_seconds, 60.0),
                allow_splits=True,
                allow_store_install=True,
                install_mode=install_mode,
                install_wait_timeout_seconds=install_wait_timeout_seconds,
                progress_callback=progress_callback,
            )
        except Exception as exc:
            reason = getattr(exc, "reason_code", None)
            _emit_progress(
                progress_callback,
                "acquisition",
                "failed",
                str(exc),
                {"package_name": pkg, "reason_code": reason},
            )
            raise DemoOrchestrationError(
                message=str(exc),
                stage="acquisition",
                cause=exc,
                reason_code=reason,
            ) from exc

    else:
        _emit_progress(
            progress_callback,
            "acquisition",
            "running",
            "Downloading APK from target URL and validating package structure...",
        )
        try:
            acq_meta = acquire_apk(
                url=url,
                output_dir=downloads_dir,
                timeout=min(timeout_seconds, 60.0),
            )
            acq_meta["platform"] = "android"
            acq_meta["source_type"] = "direct_apk"
        except Exception as exc:
            _emit_progress(progress_callback, "acquisition", "failed", str(exc))
            raise DemoOrchestrationError(
                message=str(exc),
                stage="acquisition",
                cause=exc,
            ) from exc


    # -------------------------------------------------------------
    # SPLIT APK PIPELINE BRANCH (Task 14 V2)
    # -------------------------------------------------------------
    if acq_meta.get("package_layout") == "split":
        split_count = acq_meta.get("split_count", len(acq_meta.get("components", [])))
        _emit_progress(
            progress_callback,
            "acquisition",
            "success",
            f"Split APK package detected: {split_count} components.",
            acq_meta,
        )

        # STAGE 2: Split Preprocessing
        _emit_progress(
            progress_callback,
            "preprocessing",
            "running",
            "Extracting and preprocessing all split APK components independently...",
        )
        try:
            prep_meta = preprocess_package_set(
                package_set_input=acq_meta.get("package_set_path") or acq_meta,
                processed_root=workspaces_dir / "processed",
                timeout_seconds=timeout_seconds,
            )
        except Exception as exc:
            _emit_progress(progress_callback, "preprocessing", "failed", str(exc))
            raise DemoOrchestrationError(message=str(exc), stage="preprocessing", cause=exc) from exc

        prep_state = "warning" if prep_meta.get("status") == "success_with_warnings" else "success"
        prep_msg = (
            f"{prep_meta.get('component_count')} components processed with warnings."
            if prep_state == "warning"
            else f"{prep_meta.get('component_count')} components processed cleanly."
        )
        _emit_progress(progress_callback, "preprocessing", prep_state, prep_msg, prep_meta)

        # STAGE 3: Split Static Context
        _emit_progress(
            progress_callback,
            "static_analysis",
            "running",
            "Building split-aware static security context across all components...",
        )
        try:
            static_context = build_split_static_context(
                package_set_input=acq_meta.get("package_set_path") or prep_meta.get("package_set_path") or acq_meta,
                unified_analysis_root=workspaces_dir / "unified_analysis",
            )
        except Exception as exc:
            _emit_progress(progress_callback, "static_analysis", "failed", str(exc))
            raise DemoOrchestrationError(message=str(exc), stage="static_analysis", cause=exc) from exc

        app_info = static_context.get("app", {})
        package_name = app_info.get("package_name")
        launcher_activity = app_info.get("launcher_activity")

        _emit_progress(
            progress_callback,
            "static_analysis",
            "success",
            f"Split-aware static context generated for '{package_name}' ({len(static_context.get('api_candidates', []))} API candidates).",
            static_context,
        )

        # STAGE 4: Runtime Observation & Foreground Launch
        _emit_progress(
            progress_callback,
            "runtime",
            "running",
            f"Checking ADB connection to verify foreground launch of installed package '{package_name}'...",
        )
        runtime_meta = _runtime_with_availability(root_path, package_name, launcher_activity,
            apk_path=None, adb_serial=adb_serial, reinstall=reinstall, grant_permissions=grant_permissions,
            timeout_seconds=min(timeout_seconds, 60.0), skip_install=True, progress_callback=progress_callback)

        if runtime_meta.get('status') != 'unavailable':
            session_info = _wire_dynamic_session(root_path, package_name.strip(), adb_serial)
            init_obs = session_info.get("raw_observation") if isinstance(session_info, dict) else None
            _wire_dynamic_exploration(
                root_path,
                package_name.strip(),
                adb_serial,
                progress_callback=progress_callback,
                initial_observation=init_obs,
                **({"traffic_proxy_port": traffic_proxy_port} if traffic_proxy_port != 8080 else {}),
            )

        # STAGE 5: Result Assembly for Split Package
        demo3_scan = None
        try:
            from src.demo3.scanner import scan_artifacts_deterministically
            component_roots = sorted((workspaces_dir / "processed").glob("*/apktool_out"))
            if component_roots:
                scans = [scan_artifacts_deterministically(root) for root in component_roots]
                numeric_keys = ("files_discovered", "files_analyzed", "files_skipped", "files_failed")
                statistics = {key: sum(scan["statistics"].get(key, 0) for scan in scans) for key in numeric_keys}
                statistics["failed_files"] = [
                    {**item, "component": root.parent.name}
                    for root, scan in zip(component_roots, scans)
                    for item in scan["statistics"].get("failed_files", [])
                ]
                demo3_scan = {
                    "status": "partial" if statistics["files_failed"] else "completed",
                    "statistics": statistics,
                    # The split static context already combines component
                    # indicators with source APK provenance for the inventory.
                    "candidates": [],
                }
        except Exception:
            pass

        final_result = {
            "input": {
                "url": url,
                "platform": platform,
                "source_type": acq_meta.get("source_type", "play_store"),
                "package_name": acq_meta.get("package_name"),
                "adb_serial": adb_serial,
                "reinstall": reinstall,
                "grant_permissions": grant_permissions,
            },
            "acquisition": acq_meta,
            "preprocessing": prep_meta,
            "static_analysis": static_context,
            "runtime": runtime_meta,
            "demo3_scan": demo3_scan,
            "demo_status": "completed",
        }
        try:
            from src.report_generator import generate_reports
            generate_reports(run_dir=root_path, run_id=root_path.name, pipeline_result=final_result)
        except Exception:
            pass
        _finalize_scan_state_post_run(root_path)
        _emit_progress(
            progress_callback,
            "demo",
            "completed",
            "Demo pipeline execution completed.",
            final_result,
        )
        return final_result

    # Invariant: Determine exact concrete APK file path created by Task 06
    filename = acq_meta.get("filename")
    saved_path_str = acq_meta.get("saved_path")
    if saved_path_str and Path(saved_path_str).resolve().is_file():
        concrete_apk_path = Path(saved_path_str).resolve()
    elif filename and (downloads_dir / filename).is_file():
        concrete_apk_path = (downloads_dir / filename).resolve()
    else:
        err_msg = f"Acquisition succeeded but acquired APK file could not be located at '{saved_path_str}'."
        _emit_progress(progress_callback, "acquisition", "failed", err_msg)
        raise DemoOrchestrationError(
            message=err_msg,
            stage="acquisition",
        )

    _emit_progress(
        progress_callback,
        "acquisition",
        "success",
        f"Acquired '{filename}' ({acq_meta.get('size_bytes')} bytes) with verified ZIP & DEX structure.",
        acq_meta,
    )

    # -------------------------------------------------------------
    # STAGE 2: PREPROCESSING (Task 07)
    # -------------------------------------------------------------
    _emit_progress(
        progress_callback,
        "preprocessing",
        "running",
        "Extracting raw APK archive, decoding with Apktool, and decompiling with JADX...",
    )
    try:
        prep_meta = preprocess_apk(
            apk_path=concrete_apk_path,
            output_root=workspaces_dir,
            timeout_seconds=timeout_seconds,
        )
    except Exception as exc:
        _emit_progress(progress_callback, "preprocessing", "failed", str(exc))
        raise DemoOrchestrationError(
            message=str(exc),
            stage="preprocessing",
            cause=exc,
        ) from exc

    # Validate required directory paths produced by Task 07
    raw_apk_out = prep_meta.get("raw_apk", {}).get("output_dir")
    apktool_out = prep_meta.get("apktool", {}).get("output_dir")

    if not raw_apk_out or not Path(raw_apk_out).resolve().is_dir():
        err_msg = f"Preprocessing metadata missing valid raw_apk directory: '{raw_apk_out}'."
        _emit_progress(progress_callback, "preprocessing", "failed", err_msg)
        raise DemoOrchestrationError(
            message=err_msg,
            stage="preprocessing",
        )
    if not apktool_out or not Path(apktool_out).resolve().is_dir():
        err_msg = f"Preprocessing metadata missing valid apktool directory: '{apktool_out}'."
        _emit_progress(progress_callback, "preprocessing", "failed", err_msg)
        raise DemoOrchestrationError(
            message=err_msg,
            stage="preprocessing",
        )

    raw_apk_root = Path(raw_apk_out).resolve()
    apktool_root = Path(apktool_out).resolve()
    manifest_path = apktool_root / "AndroidManifest.xml"

    if not manifest_path.is_file():
        err_msg = f"Required AndroidManifest.xml missing in apktool output: '{manifest_path}'."
        _emit_progress(progress_callback, "preprocessing", "failed", err_msg)
        raise DemoOrchestrationError(
            message=err_msg,
            stage="preprocessing",
        )

    jadx_status = prep_meta.get("jadx", {}).get("status")
    prep_state = "warning" if jadx_status == "success_with_warnings" else "success"
    prep_msg = (
        f"Preprocessing completed with JADX warnings (returncode {prep_meta.get('jadx', {}).get('returncode')})."
        if prep_state == "warning"
        else "Preprocessing completed cleanly."
    )
    _emit_progress(progress_callback, "preprocessing", prep_state, prep_msg, prep_meta)

    # -------------------------------------------------------------
    # STAGE 3: STATIC CONTEXT (Task 05, reusing Tasks 01–04)
    # -------------------------------------------------------------
    _emit_progress(
        progress_callback,
        "static_analysis",
        "running",
        "Building static security context: manifest, file inventory, network indicators, and API candidates...",
    )
    try:
        static_context = build_static_context(
            manifest_path=manifest_path,
            raw_apk_root=raw_apk_root,
            apktool_root=apktool_root,
        )
    except Exception as exc:
        _emit_progress(progress_callback, "static_analysis", "failed", str(exc))
        raise DemoOrchestrationError(
            message=str(exc),
            stage="static_analysis",
            cause=exc,
        ) from exc

    # Extract and validate runtime identifiers
    app_info = static_context.get("app", {})
    package_name = app_info.get("package_name")
    launcher_activity = app_info.get("launcher_activity")

    if not isinstance(package_name, str) or not package_name.strip():
        err_msg = "Static analysis did not discover a valid non-empty package_name in AndroidManifest.xml."
        _emit_progress(progress_callback, "static_analysis", "failed", err_msg)
        raise DemoOrchestrationError(
            message=err_msg,
            stage="static_analysis",
        )

    _emit_progress(
        progress_callback,
        "static_analysis",
        "success",
        f"Static context generated for '{package_name}' ({len(static_context.get('api_candidates', []))} API candidates).",
        static_context,
    )

    # -------------------------------------------------------------
    # STAGE 4: RUNTIME INSTALL & LAUNCH (Task 08)
    # -------------------------------------------------------------
    _emit_progress(
        progress_callback,
        "runtime",
        "running",
        f"Checking ADB connection to verify foreground launch of '{package_name}'...",
    )
    is_play_store = acq_meta.get("source_type") == "play_store"
    runtime_meta = _runtime_with_availability(root_path, package_name, launcher_activity,
        apk_path=None if is_play_store else concrete_apk_path, adb_serial=adb_serial,
        reinstall=reinstall, grant_permissions=grant_permissions, timeout_seconds=min(timeout_seconds, 60.0),
        **({'skip_install': True} if is_play_store else {}), progress_callback=progress_callback)

    if runtime_meta.get('status') != 'unavailable':
        session_info = _wire_dynamic_session(root_path, package_name.strip(), adb_serial)
        init_obs = session_info.get("raw_observation") if isinstance(session_info, dict) else None
        _wire_dynamic_exploration(
            root_path,
            package_name.strip(),
            adb_serial,
            progress_callback=progress_callback,
            initial_observation=init_obs,
            **({"traffic_proxy_port": traffic_proxy_port} if traffic_proxy_port != 8080 else {}),
        )

    # -------------------------------------------------------------
    # STAGE 5: RESULT ASSEMBLY
    # -------------------------------------------------------------
    demo3_scan = None
    try:
        from src.demo3.scanner import scan_artifacts_deterministically
        demo3_scan = scan_artifacts_deterministically(apktool_root)
    except Exception:
        pass

    final_result = {
        "input": {
            "url": url,
            "platform": platform,
            "source_type": acq_meta.get("source_type", "direct_apk"),
            "package_name": acq_meta.get("package_name"),
            "adb_serial": adb_serial,
            "reinstall": reinstall,
            "grant_permissions": grant_permissions,
        },
        "acquisition": acq_meta,
        "preprocessing": prep_meta,
        "static_analysis": static_context,
        "runtime": runtime_meta,
        "demo3_scan": demo3_scan,
        "demo_status": "completed",
    }
    try:
        from src.report_generator import generate_reports
        generate_reports(run_dir=root_path, run_id=root_path.name, pipeline_result=final_result)
    except Exception:
        pass
    _finalize_scan_state_post_run(root_path)
    _emit_progress(
        progress_callback,
        "demo",
        "completed",
        "Demo pipeline execution completed.",
        final_result,
    )
    return final_result


def format_demo_summary(result: dict) -> str:
    """Produces a clean, human-readable summary of the demo execution."""
    inp = result.get("input", {})
    if inp.get("platform") == "ios" or result.get("acquisition", {}).get("platform") == "ios":
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("MOBIATTACK V2 IOS DEMO EXECUTION SUMMARY")
        lines.append("=" * 60)
        lines.append(f"Input URL / Path: {inp.get('url')}")
        lines.append(f"Platform:         iOS")
        lines.append("-" * 60)
        acq = result.get("acquisition", {})
        lines.append("Stage 1 — Acquisition:")
        lines.append(f"  Filename:       {acq.get('filename')}")
        lines.append(f"  Size:           {acq.get('size_bytes')} bytes")
        lines.append(f"  SHA-256:        {acq.get('sha256')}")
        lines.append(f"  Valid IPA:      {acq.get('validation', {}).get('is_valid_ipa')}")
        lines.append("-" * 60)
        prep = result.get("preprocessing", {})
        lines.append("Stage 2 — Preprocessing:")
        lines.append(f"  App Bundle:     {prep.get('app_bundle')}")
        lines.append(f"  Extracted Files:{prep.get('extracted_files')}")
        lines.append(f"  Status:         {prep.get('status')}")
        lines.append("-" * 60)
        static = result.get("static_analysis", {})
        app = static.get("application", {})
        cfg = static.get("configuration", {})
        struct = static.get("structure", {})
        net = static.get("network_indicators", {})
        lines.append("Stage 3 — Static Analysis:")
        lines.append(f"  Bundle ID:      {app.get('bundle_identifier')}")
        lines.append(f"  Display Name:   {app.get('display_name')}")
        lines.append(f"  Version:        {app.get('version')} (build {app.get('build')})")
        lines.append(f"  Min OS Version: {app.get('minimum_os_version')}")
        lines.append(f"  Executable:     {app.get('executable')}")
        lines.append(f"  Architectures:  {struct.get('executable', {}).get('architectures')}")
        lines.append(f"  Frameworks:     {struct.get('framework_count', len(struct.get('frameworks', [])))} embedded")
        lines.append(f"  Usage Descr:    {len(cfg.get('usage_descriptions', []))} declared")
        lines.append(f"  ATS Status:     {cfg.get('ats', {}).get('status')}")
        lines.append(f"  Entitlements:   {cfg.get('entitlements', {}).get('status')}")
        lines.append(f"  Network URLs:   {len(net.get('network_urls', []))}")
        lines.append(f"  API Candidates: 0 (not implemented in Phase 1)")
        lines.append("-" * 60)
        lines.append("Stage 4 — Runtime Verification:")
        lines.append(f"  Status:         Not implemented for iOS in Phase 1")
        lines.append("=" * 60)
        lines.append(f"DEMO STATUS:      {result.get('demo_status')}")
        lines.append("=" * 60)
        return "\n".join(lines)

    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("MOBYATTACK-V1 DEMO EXECUTION SUMMARY")
    lines.append("=" * 60)

    # Input
    lines.append(f"Input URL:        {inp.get('url')}")
    lines.append("Target:           Current execution environment")
    lines.append(f"Reinstall Mode:   {inp.get('reinstall')}")
    lines.append(f"Grant Perms:      {inp.get('grant_permissions')}")
    lines.append("-" * 60)

    # Acquisition
    acq = result.get("acquisition", {})
    val = acq.get("validation", {})
    lines.append("Stage 1 — Acquisition:")
    lines.append(f"  Filename:       {acq.get('filename')}")
    lines.append(f"  Size:           {acq.get('size_bytes')} bytes")
    lines.append(f"  SHA-256:        {acq.get('sha256')}")
    lines.append(f"  Valid APK:      {val.get('is_valid_apk')}")
    lines.append("-" * 60)

    # Preprocessing
    prep = result.get("preprocessing", {})
    apktool = prep.get("apktool", {})
    jadx = prep.get("jadx", {})
    lines.append("Stage 2 — Preprocessing:")
    lines.append(f"  Raw Files:      {prep.get('raw_apk', {}).get('file_count')} files extracted")
    lines.append(f"  Apktool:        {apktool.get('status')} (exit code {apktool.get('returncode')})")
    lines.append(f"  JADX:           {jadx.get('status')} (exit code {jadx.get('returncode')})")
    lines.append("-" * 60)

    # Static Analysis
    static = result.get("static_analysis", {})
    app = static.get("app", {})
    struct = static.get("structure", {})
    net = static.get("network_indicators", {})
    candidates = static.get("api_candidates", [])
    lines.append("Stage 3 — Static Analysis:")
    lines.append(f"  Package:        {app.get('package_name')}")
    lines.append(f"  Launcher:       {app.get('launcher_activity')}")
    lines.append(f"  DEX Count:      {struct.get('dex_count')} (multidex={struct.get('is_multidex')})")
    lines.append(f"  Permissions:    {len(static.get('permissions', []))} declared")
    lines.append(f"  Activities:     {len(static.get('activities', []))} declared")
    lines.append(f"  Network URLs:   {len(net.get('network_urls', []))}")
    lines.append(f"  API Candidates: {len(candidates)}")
    for i, cand in enumerate(candidates, 1):
        lines.append(f"    [{i}] {cand.get('method')} {cand.get('full_url')} ({cand.get('status')})")

    demo3 = result.get("demo3_scan") or {}
    if demo3 and demo3.get("candidates") is not None:
        lines.append("-" * 60)
        lines.append("Stage 3b — Demo 3 Deterministic Static Inventory:")
        lines.append(f"  Canonical Candidates: {demo3.get('candidate_count', len(demo3.get('candidates', [])))}")
        stats = demo3.get("statistics", {})
        lines.append(f"  Files Analyzed:       {stats.get('files_analyzed', 0)}")
        lines.append(f"  Scan Status:          {demo3.get('status', 'completed')}")
    lines.append("-" * 60)

    # Runtime Execution
    rt = result.get("runtime", {})
    rt_inner = rt.get("runtime", {})
    lines.append("Stage 4 — Runtime Launch:")
    if rt.get("status") == "skipped":
        lines.append("  Status:         SKIPPED (no connected Android device or emulator detected)")
        lines.append(f"  Reason:         {rt.get('reason', 'no_adb_device')}")
    else:
        lines.append(f"  Device Serial:  {rt.get('adb', {}).get('serial')}")
        lines.append(f"  Installed:      {rt.get('install', {}).get('success')}")
        lines.append(f"  Reinstall:      {rt.get('install', {}).get('reinstall')}")
        lines.append(f"  Grant Perms:    {rt.get('install', {}).get('grant_permissions')}")
        lines.append(f"  Component:      {rt.get('launch', {}).get('component')}")
        lines.append(f"  Process PID:    {rt_inner.get('pid')}")
        lines.append(f"  Observed Pkg:   {rt_inner.get('observed_package')}")
        lines.append(f"  Observed Act:   {rt_inner.get('observed_activity')}")
        lines.append(f"  Foreground:     {rt_inner.get('foreground_verified')}")
        lines.append(f"  Runtime Status: {rt.get('status')}")
    lines.append("=" * 60)
    lines.append(f"DEMO STATUS:      {result.get('demo_status')}")
    lines.append("=" * 60)

    return "\n".join(lines)
