"""Exploration responsibilities for the demo pipeline."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable
import logging


from src.persistence import write_json_atomic
from src.dynamic.exploration.models import ExplorationLimits
from src.orchestration.timeline import ExplorationTimelineRecorder

logger = logging.getLogger(__name__)


def _wire_dynamic_exploration(
    root_path: Path,
    package_name: str,
    adb_serial: str | None = None,
    progress_callback: Callable[[str, str, str, dict | None], None] | None = None,
    limits: Any | None = None,
    initial_observation: Any | None = None,
    traffic_proxy_port: int = 8080,
    traffic_mode: str = "https",
    *,
    run_exploration: Callable,
    _update_scan_state_dynamic_stage: Callable,
    _emit_progress: Callable,
    _wire_api_correlation: Callable,
    _wire_dynamic_analysis_report: Callable,
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
    from src.dynamic.traffic.backend_selection import select_capture_backend, validate_traffic_mode
    validate_traffic_mode(traffic_mode)
    try:
        import json as _json
        from src.android_runtime_launcher import resolve_adb_executable
        from src.dynamic.action.executor import ActionExecutor
        from src.dynamic.route.graph import RouteGraph
        from src.dynamic.route.storage import RouteGraphStorage

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

        traffic_evidence_file = root_path / "dynamic" / "traffic_evidence.json"
        traffic_file = root_path / "dynamic" / "traffic.json"
        traffic_storage = TrafficStorage(base_dir=str(root_path / "dynamic"))

        traffic_backend = select_capture_backend(traffic_mode)
        write_json_atomic(root_path / "dynamic" / "traffic_backend.json", {
            "schema_version": "1.0", "session_id": session_id,
            "mode": traffic_mode, "backend": type(traffic_backend).__name__,
            "fallback_allowed": False,
        })
        traffic_service = DynamicTrafficService(
            backend=traffic_backend,
            storage=traffic_storage,
            adb_bin=adb_bin,
        )

        traffic_started = False
        current_target = None
        try:
            from src.dynamic.runtime.execution_target import load_target, record_capabilities, TargetType
            current_target = load_target(root_path)
            if current_target and current_target.target_type == TargetType.PHYSICAL_DEVICE:
                raise RuntimeError('PHYSICAL_DEVICE_TRAFFIC_UNAVAILABLE')
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
            traffic_service.http_reason = ("physical_device_traffic_not_supported" if str(exc) == "PHYSICAL_DEVICE_TRAFFIC_UNAVAILABLE"
                                          else getattr(getattr(exc, "error_code", None), "value", "capture_start_failed"))
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
                backend_name=type(traffic_backend).__name__,
                summary=CaptureSummary(session_id=session_id, http_visibility='unavailable',
                    http_visibility_reason=visibility.get('http_reason', 'capture_start_failed'),
                    https_visibility=visibility.get('https_visibility', 'unavailable'),
                    https_visibility_reason=visibility.get('https_reason', 'capture_backend_unavailable')))
        if not (current_target and current_target.target_type == TargetType.PHYSICAL_DEVICE):
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
                auth_wait_seconds=5.0,
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
        write_json_atomic(str(result_file), result_dict)

        # Determine dynamic_analysis final status based on evidence
        has_evidence = (
            res.screens_observed > 0
            or res.actions_succeeded > 0
            or (root_path / "dynamic" / "route_graph.json").is_file()
            or (root_path / "dynamic" / "runtime_evidence.json").is_file()
            # Report validator checks process/foreground proof; UI/traffic
            # failure must not prevent attempting this evidence projection.
            or (root_path / "dynamic" / "runtime_availability.json").is_file()
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
