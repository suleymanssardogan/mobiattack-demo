"""Ios responsibilities for the demo pipeline."""
from __future__ import annotations

from pathlib import Path
from typing import Callable
import logging


import hashlib
import ssl
import urllib.parse
import urllib.request
from src.constants import IOS_RUNTIME_NOT_IMPLEMENTED
from src.orchestration.common import DemoOrchestrationError, _emit_progress

logger = logging.getLogger(__name__)


def _run_ios_pipeline(
    url: str,
    output_root: Path,
    timeout_seconds: float = 300.0,
    progress_callback: Callable[[str, str, str, dict | None], None] | None = None,
    *,
    detect_platform: Callable,
    extract_ipa: Callable,
    build_ios_static_context: Callable,
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
