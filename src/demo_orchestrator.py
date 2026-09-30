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
from src.play_store_acquirer import PlayStoreAcquisitionError, acquire_play_store_app, acquire_play_store_package
from src.split_preprocessor import preprocess_package_set
from src.split_static_context_builder import build_split_static_context
import hashlib
import ssl
import urllib.parse
import urllib.request
from src.platform_detector import detect_platform
from src.ios.ipa_extractor import IpaExtractionError, extract_ipa
from src.ios.ios_static_context_builder import build_ios_static_context


class DemoOrchestrationError(ValueError):
    """Raised when any stage of the demo orchestration fails."""

    def __init__(self, message: str, stage: str, cause: Exception | None = None, reason_code: str | None = None):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage
        self.cause = cause
        self.reason_code = reason_code or getattr(cause, "reason_code", None)

from typing import Callable


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
    runtime_meta = {
        "status": "not_implemented",
        "platform": "ios",
        "message": "Runtime launch verification is not implemented for iOS in Phase 1.",
    }

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
        "vulnerabilities": {
            "status": "not_evaluated",
            "reason": "not_implemented",
            "risk_score": "NOT_EVALUATED",
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "findings": [],
            "message": "iOS vulnerability evaluation is not implemented in Phase 1.",
        },
        "demo3_scan": demo3_scan,
        "demo_status": "completed",
    }
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
        progress_callback: Optional callable(stage, state, message, data=None) for live tracking.

    Returns:
        Structured demo result dictionary containing all stage outputs.

    Raises:
        DemoOrchestrationError: On failure at any pipeline stage, preserving stage tag
                                and original exception cause.
    """
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
        raise DemoOrchestrationError(message=err_msg, stage="acquisition")

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
                connected = get_connected_devices()
                if not connected:
                    err_msg = "No connected Android devices found via ADB for Play Store acquisition."
                    _emit_progress(progress_callback, "acquisition", "failed", err_msg)
                    raise DemoOrchestrationError(message=err_msg, stage="acquisition")
                target_serial = connected[0]
            except Exception as exc:
                _emit_progress(progress_callback, "acquisition", "failed", str(exc))
                raise DemoOrchestrationError(message=str(exc), stage="acquisition", cause=exc) from exc

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
        package_name = app_info.get("package_name") or acq_meta.get("package_name") or "unknown"
        launcher_activity = app_info.get("launcher_activity") or "unknown"

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
        try:
            runtime_meta = launch_android_app(
                apk_path=None,
                package_name=package_name.strip(),
                launcher_activity=launcher_activity.strip(),
                adb_serial=adb_serial,
                reinstall=reinstall,
                grant_permissions=grant_permissions,
                timeout_seconds=min(timeout_seconds, 60.0),
                skip_install=True,
            )
            _emit_progress(
                progress_callback,
                "runtime",
                "success",
                f"App successfully launched (PID {runtime_meta.get('runtime', {}).get('pid')}, status: {runtime_meta.get('status')}).",
                runtime_meta,
            )
        except AndroidDeviceUnavailableError as exc:
            skip_msg = "No connected Android device or emulator was detected. Runtime launch verification skipped; static analysis completed normally."
            runtime_meta = {
                "status": "skipped",
                "reason": getattr(exc, "reason", "no_adb_device"),
                "message": skip_msg,
                "platform": "android",
                "runtime": {
                    "pid": None,
                    "observed_package": None,
                    "observed_activity": None,
                },
            }
            _emit_progress(
                progress_callback,
                "runtime",
                "skipped",
                skip_msg,
                runtime_meta,
            )
        except Exception as exc:
            _emit_progress(progress_callback, "runtime", "failed", str(exc))
            raise DemoOrchestrationError(message=str(exc), stage="runtime", cause=exc) from exc

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
        _emit_progress(
            progress_callback,
            "demo",
            "completed",
            "Demo pipeline execution completed.",
            final_result,
        )
        try:
            from src.report_generator import generate_reports
            generate_reports(run_dir=root_path, run_id=root_path.name, pipeline_result=final_result)
        except Exception:
            pass
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
    if not isinstance(launcher_activity, str) or not launcher_activity.strip():
        err_msg = "Static analysis did not discover a valid non-empty launcher_activity in AndroidManifest.xml."
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
    try:
        if is_play_store:
            runtime_meta = launch_android_app(
                apk_path=None,
                package_name=package_name.strip(),
                launcher_activity=launcher_activity.strip(),
                adb_serial=adb_serial,
                reinstall=reinstall,
                grant_permissions=grant_permissions,
                timeout_seconds=min(timeout_seconds, 60.0),
                skip_install=True,
            )
        else:
            runtime_meta = launch_android_app(
                apk_path=concrete_apk_path,
                package_name=package_name.strip(),
                launcher_activity=launcher_activity.strip(),
                adb_serial=adb_serial,
                reinstall=reinstall,
                grant_permissions=grant_permissions,
                timeout_seconds=min(timeout_seconds, 60.0),
            )
        _emit_progress(
            progress_callback,
            "runtime",
            "success",
            f"App successfully launched (PID {runtime_meta.get('runtime', {}).get('pid')}, status: {runtime_meta.get('status')}).",
            runtime_meta,
        )
    except AndroidDeviceUnavailableError as exc:
        skip_msg = "No connected Android device or emulator was detected. Runtime launch verification skipped; static analysis completed normally."
        runtime_meta = {
            "status": "skipped",
            "reason": getattr(exc, "reason", "no_adb_device"),
            "message": skip_msg,
            "platform": "android",
            "runtime": {
                "pid": None,
                "observed_package": None,
                "observed_activity": None,
            },
        }
        _emit_progress(
            progress_callback,
            "runtime",
            "skipped",
            skip_msg,
            runtime_meta,
        )
    except Exception as exc:
        _emit_progress(progress_callback, "runtime", "failed", str(exc))
        raise DemoOrchestrationError(
            message=str(exc),
            stage="runtime",
            cause=exc,
        ) from exc

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
    _emit_progress(
        progress_callback,
        "demo",
        "completed",
        "Demo pipeline execution completed.",
        final_result,
    )
    try:
        from src.report_generator import generate_reports
        generate_reports(run_dir=root_path, run_id=root_path.name, pipeline_result=final_result)
    except Exception:
        pass
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
    lines.append(f"Target Serial:    {inp.get('adb_serial') or 'Auto-selected'}")
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
