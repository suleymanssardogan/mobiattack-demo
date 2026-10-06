"""APK preprocessing and Static context preparation for single/split packages."""
from __future__ import annotations

from pathlib import Path
from typing import Callable
from src.orchestration.common import DemoOrchestrationError, _emit_progress


def prepare_split_target(acq_meta, workspaces_dir, timeout_seconds, progress_callback, *,
                         preprocess_package_set: Callable, build_split_static_context: Callable):
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
    return prep_meta, static_context


def prepare_single_target(
    acq_meta,
    downloads_dir,
    workspaces_dir,
    timeout_seconds,
    progress_callback,
    *,
    preprocess_apk: Callable,
    build_static_context: Callable,
):
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
    return prep_meta, static_context, concrete_apk_path, apktool_root
