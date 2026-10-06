"""Android acquisition and transport selection, independent of analysis stages."""
from __future__ import annotations

from typing import Callable
from src.orchestration.common import DemoOrchestrationError, _emit_progress


def acquire_android_target(
    url, classification, downloads_dir, adb_serial, timeout_seconds,
    install_mode, install_wait_timeout_seconds, progress_callback, *,
    acquire_apk: Callable, acquire_play_store_app: Callable, get_connected_devices: Callable,
):
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
    return url, acq_meta, adb_serial
