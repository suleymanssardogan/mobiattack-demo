"""Public demo composition root.

Selects the platform and composes acquisition, preparation, runtime and reporting
adapters. Legacy helper imports remain available for existing callers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from src.android_runtime_launcher import get_connected_devices, launch_android_app
from src.apk_acquirer import acquire_apk
from src.apk_preprocessor import preprocess_apk
from src.dynamic.exploration.loop import run_exploration
from src.ios.ios_static_context_builder import build_ios_static_context
from src.ios.ipa_extractor import extract_ipa
from src.orchestration import (
    acquisition as _acquisition_wiring,
    artifacts as _artifacts_wiring,
    exploration as _exploration_wiring,
    ios as _ios_wiring,
    preparation as _preparation_wiring,
    results as _results_wiring,
    runtime as _runtime_wiring,
    session as _session_wiring,
)
from src.orchestration.artifacts import _wire_endpoint_contexts
from src.orchestration.common import DemoOrchestrationError, _emit_progress
from src.orchestration.lifecycle import (
    _finalize_scan_state_post_run,
    _update_scan_state_dynamic_stage,
    _wire_dynamic_analysis_report,
)
from src.orchestration.preflight import (
    _ensure_preflight_persisted_from_meta,
    _persist_preflight_fallback,
)
from src.orchestration.timeline import ExplorationTimelineRecorder
from src.platform_detector import detect_platform
from src.play_store_acquirer import acquire_play_store_app
from src.split_preprocessor import preprocess_package_set
from src.split_static_context_builder import build_split_static_context
from src.static_context_builder import build_static_context
from src.url_classifier import classify_input_url
from src.web.demo_summary import format_demo_summary


def _runtime_with_availability(
    root_path,
    package_name,
    launcher_activity,
    *,
    progress_callback=None,
    **kwargs,
):
    """Compatibility facade; collaborators are composed at the public entry point."""
    return _runtime_wiring._runtime_with_availability(
        root_path=root_path,
        package_name=package_name,
        launcher_activity=launcher_activity,
        progress_callback=progress_callback,
        launch_android_app=launch_android_app,
        _ensure_preflight_persisted_from_meta=_ensure_preflight_persisted_from_meta,
        _persist_preflight_fallback=_persist_preflight_fallback,
        _emit_progress=_emit_progress,
        _wire_dynamic_analysis_report=_wire_dynamic_analysis_report,
        _update_scan_state_dynamic_stage=_update_scan_state_dynamic_stage,
        **kwargs,
    )


def _wire_dynamic_session(root_path: Path, package_name: str, adb_serial: str | None) -> None:
    """Compatibility facade; collaborators are composed at the public entry point."""
    return _session_wiring._wire_dynamic_session(
        root_path=root_path,
        package_name=package_name,
        adb_serial=adb_serial,
        _wire_dynamic_analysis_report=_wire_dynamic_analysis_report,
    )


def _wire_dynamic_exploration(
    root_path: Path,
    package_name: str,
    adb_serial: str | None = None,
    progress_callback: Callable[[str, str, str, dict | None], None] | None = None,
    limits: Any | None = None,
    initial_observation: Any | None = None,
    traffic_proxy_port: int = 8080,
    traffic_mode: str = "https",
) -> Any | None:
    """Compatibility facade; collaborators are composed at the public entry point."""
    return _exploration_wiring._wire_dynamic_exploration(
        root_path=root_path,
        package_name=package_name,
        adb_serial=adb_serial,
        progress_callback=progress_callback,
        limits=limits,
        initial_observation=initial_observation,
        traffic_proxy_port=traffic_proxy_port,
        traffic_mode=traffic_mode,
        run_exploration=run_exploration,
        _update_scan_state_dynamic_stage=_update_scan_state_dynamic_stage,
        _emit_progress=_emit_progress,
        _wire_api_correlation=_wire_api_correlation,
        _wire_dynamic_analysis_report=_wire_dynamic_analysis_report,
    )


def _wire_api_correlation(
    root_path: Path,
    session_id: str,
    timeline_recorder: Any | None = None,
    traffic_service: Any | None = None,
) -> Any:
    """Compatibility facade; collaborators are composed at the public entry point."""
    return _artifacts_wiring._wire_api_correlation(
        root_path=root_path,
        session_id=session_id,
        timeline_recorder=timeline_recorder,
        traffic_service=traffic_service,
        _wire_endpoint_contexts=_wire_endpoint_contexts,
    )


def _run_ios_pipeline(
    url: str,
    output_root: Path,
    timeout_seconds: float = 300.0,
    progress_callback: Callable[[str, str, str, dict | None], None] | None = None,
) -> dict:
    """Compatibility facade; collaborators are composed at the public entry point."""
    return _ios_wiring._run_ios_pipeline(
        url=url,
        output_root=output_root,
        timeout_seconds=timeout_seconds,
        progress_callback=progress_callback,
        detect_platform=detect_platform,
        extract_ipa=extract_ipa,
        build_ios_static_context=build_ios_static_context,
    )


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
    traffic_mode: str = "https",
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
        traffic_mode: https (mitmproxy) or explicit native_http; never auto-fallback.
        progress_callback: Optional callable(stage, state, message, data=None) for live tracking.

    Returns:
        Structured demo result dictionary containing all stage outputs.

    Raises:
        DemoOrchestrationError: On failure at any pipeline stage, preserving stage tag
                                and original exception cause.
    """
    from src.dynamic.traffic.backend_selection import validate_traffic_mode
    validate_traffic_mode(traffic_mode)
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

    url, acq_meta, adb_serial = _acquisition_wiring.acquire_android_target(
        url, classification, downloads_dir, adb_serial, timeout_seconds,
        install_mode, install_wait_timeout_seconds, progress_callback,
        acquire_apk=acquire_apk, acquire_play_store_app=acquire_play_store_app,
        get_connected_devices=get_connected_devices,
    )
    is_split = acq_meta.get("package_layout") == "split"
    if is_split:
        prep_meta, static_context = _preparation_wiring.prepare_split_target(
            acq_meta, workspaces_dir, timeout_seconds, progress_callback,
            preprocess_package_set=preprocess_package_set,
            build_split_static_context=build_split_static_context,
        )
        concrete_apk_path = None
        apktool_root = None
    else:
        prep_meta, static_context, concrete_apk_path, apktool_root = _preparation_wiring.prepare_single_target(
            acq_meta, downloads_dir, workspaces_dir, timeout_seconds, progress_callback,
            preprocess_apk=preprocess_apk, build_static_context=build_static_context,
        )

    app_info = static_context.get("app", {})
    package_name = app_info.get("package_name")
    launcher_activity = app_info.get("launcher_activity")
    runtime_message = (
        f"Checking ADB connection to verify foreground launch of installed package '{package_name}'..."
        if is_split else
        f"Checking ADB connection to verify foreground launch of '{package_name}'..."
    )
    _emit_progress(progress_callback, "runtime", "running", runtime_message)
    skip_install = is_split or acq_meta.get("source_type") == "play_store"
    runtime_meta = _runtime_with_availability(
        root_path, package_name, launcher_activity,
        apk_path=None if skip_install else concrete_apk_path, adb_serial=adb_serial,
        reinstall=reinstall, grant_permissions=grant_permissions,
        timeout_seconds=min(timeout_seconds, 60.0),
        **({'skip_install': True} if skip_install else {}), progress_callback=progress_callback,
    )
    if runtime_meta.get('status') != 'unavailable':
        session_info = _wire_dynamic_session(root_path, package_name.strip(), adb_serial)
        init_obs = session_info.get("raw_observation") if isinstance(session_info, dict) else None
        _wire_dynamic_exploration(
            root_path, package_name.strip(), adb_serial,
            progress_callback=progress_callback, initial_observation=init_obs,
            **({"traffic_proxy_port": traffic_proxy_port} if traffic_proxy_port != 8080 else {}),
            **({"traffic_mode": traffic_mode} if traffic_mode != "https" else {}),
        )

    demo3_scan = (
        _results_wiring.scan_split_inventory(workspaces_dir) if is_split
        else _results_wiring.scan_single_inventory(apktool_root)
    )
    return _results_wiring.finish_android_run(
        url=url,
        platform=platform,
        adb_serial=adb_serial,
        reinstall=reinstall,
        grant_permissions=grant_permissions,
        acq_meta=acq_meta,
        prep_meta=prep_meta,
        static_context=static_context,
        runtime_meta=runtime_meta,
        demo3_scan=demo3_scan,
        root_path=root_path,
        progress_callback=progress_callback,
        default_source_type='play_store' if is_split else 'direct_apk',
        _finalize_scan_state_post_run=_finalize_scan_state_post_run,
    )
