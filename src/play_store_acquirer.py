"""Google Play Store Device Acquisition Module for MobiAttack-v2.

Handles Play Store workflows by inspecting and pulling application packages from
connected Android test devices via ADB, supporting both monolithic and split APK
packages, with robust market URI opening, HTTPS fallback, and automated UI / manual
installation flows.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Callable

from src.android_runtime_launcher import (
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    AndroidRuntimeError,
    resolve_adb_executable,
)
from src.apk_acquirer import validate_apk_structure


class PlayStoreAcquisitionError(ValueError):
    """Raised when device inspection, package resolution, or APK pulling fails."""

    def __init__(
        self,
        message: str,
        package_name: str | None = None,
        installed_on_device: bool = False,
        package_layout: str | None = None,
        reason_code: str | None = None,
        diagnostics: list[str] | None = None,
    ):
        super().__init__(message)
        self.package_name = package_name
        self.installed_on_device = installed_on_device
        self.package_layout = package_layout
        self.reason_code = reason_code
        self.diagnostics = diagnostics or []


def parse_pm_path_output(output: str) -> list[str]:
    """Parses output of 'adb shell pm path <package>' into a clean list of APK paths.

    Lines typically look like:
        package:/data/app/~~XYZ/com.example.app-ABC/base.apk
        package:/data/app/~~XYZ/com.example.app-ABC/split_config.arm64_v8a.apk
    """
    paths: list[str] = []
    for line in output.splitlines():
        cleaned = line.strip()
        if cleaned.startswith("package:"):
            apk_path = cleaned[len("package:"):].strip()
            if apk_path:
                paths.append(apk_path)
    return paths


def detect_package_layout(apk_paths: list[str]) -> str:
    """Classifies device installation as monolithic or split.

    Returns:
        'monolithic' if exactly one APK is present (typically base.apk),
        'split' if multiple APK files are installed,
        'none' if no APK paths were found.
    """
    if not apk_paths:
        return "none"
    if len(apk_paths) == 1:
        return "monolithic"
    return "split"


def query_package_paths(
    adb_bin: str,
    serial: str,
    package_name: str,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> list[str]:
    """Queries device PackageManager for installed APK filesystem paths."""
    cmd = [adb_bin, "-s", serial, "shell", "pm", "path", package_name]
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, OSError) as err:
        raise PlayStoreAcquisitionError(
            f"Failed to query package path via adb: {err}",
            package_name=package_name,
        ) from err

    stdout = res.stdout or ""
    return parse_pm_path_output(stdout)


def pull_device_apk(
    adb_bin: str,
    serial: str,
    remote_path: str,
    local_path: Path,
    timeout_seconds: float = 60.0,
) -> None:
    """Pulls an APK file from the device to local filesystem."""
    cmd = [adb_bin, "-s", serial, "pull", remote_path, str(local_path)]
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, OSError) as err:
        raise PlayStoreAcquisitionError(
            f"Timed out or failed pulling APK from device: {err}",
        ) from err

    if res.returncode != 0 or not local_path.is_file():
        err_msg = res.stderr.strip() if res.stderr else f"Exit code {res.returncode}"
        raise PlayStoreAcquisitionError(f"Failed to pull APK from device '{serial}': {err_msg}")


def verify_play_store_foreground(
    serial: str,
    adb_bin: str | None = None,
    timeout_seconds: float = 5.0,
) -> bool:
    """Verifies that Google Play Store (com.android.vending) is the active foreground application."""
    resolved_adb = resolve_adb_executable(adb_bin)

    # Check 1: dumpsys window (mCurrentFocus / mResumedActivity)
    cmd = [resolved_adb, "-s", serial, "shell", "dumpsys", "window"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        output = res.stdout or ""
        for line in output.splitlines():
            if ("mCurrentFocus" in line or "mResumedActivity" in line) and "com.android.vending" in line:
                return True
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Check 2: dumpsys activity activities (topResumedActivity)
    cmd2 = [resolved_adb, "-s", serial, "shell", "dumpsys", "activity", "activities"]
    try:
        res2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=timeout_seconds)
        output2 = res2.stdout or ""
        for line in output2.splitlines():
            if ("topResumedActivity" in line or "mResumedActivity" in line) and "com.android.vending" in line:
                return True
    except (subprocess.TimeoutExpired, OSError):
        pass

    return False


def open_play_store_on_device(
    serial: str,
    package_name: str | None = None,
    play_store_url: str | None = None,
    adb_bin: str | None = None,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    verify_foreground: bool = False,
    prefer_market_uri: bool = False,
) -> dict:
    """Launches Google Play Store page on the connected device via VIEW Intent.

    If prefer_market_uri or verify_foreground is True:
      - Attempts 'market://details?id=<package>' first.
      - Verifies that com.android.vending is present in the foreground.
      - If unverified, attempts fallback to 'https://play.google.com/store/apps/details?id=<package>'.
      - Returns factual verification metadata.
    """
    resolved_adb = resolve_adb_executable(adb_bin)

    # Resolve package id
    pkg = package_name
    if not pkg and play_store_url:
        match = re.search(r"[?&]id=([a-zA-Z0-9._]+)", play_store_url)
        if match:
            pkg = match.group(1)

    # Legacy simple launch (when neither market URI nor verification is requested)
    if not prefer_market_uri and not verify_foreground:
        target_url = play_store_url or f"https://play.google.com/store/apps/details?id={pkg or ''}"
        cmd = [
            resolved_adb,
            "-s",
            serial,
            "shell",
            "am",
            "start",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            target_url,
        ]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except (subprocess.TimeoutExpired, OSError) as err:
            raise PlayStoreAcquisitionError(f"Failed to launch Play Store intent on device: {err}") from err

        stdout = res.stdout or ""
        stderr = res.stderr or ""
        if res.returncode != 0 or "Error:" in f"{stdout}\n{stderr}":
            raise PlayStoreAcquisitionError(f"Failed to launch Play Store intent: {stdout} {stderr}")

        return {
            "success": True,
            "serial": serial,
            "url": target_url,
        }

    # Verified dual-mode launch (market URI primary + HTTPS fallback)
    target_pkg = pkg or "unknown"
    market_url = f"market://details?id={target_pkg}"
    https_url = play_store_url or f"https://play.google.com/store/apps/details?id={target_pkg}"

    # Attempt 1: market://
    cmd_market = [
        resolved_adb,
        "-s",
        serial,
        "shell",
        "am",
        "start",
        "-a",
        "android.intent.action.VIEW",
        "-d",
        market_url,
    ]
    market_started = False
    try:
        res_m = subprocess.run(cmd_market, capture_output=True, text=True, timeout=timeout_seconds)
        if res_m.returncode == 0 and "Error:" not in (res_m.stdout or ""):
            market_started = True
    except (subprocess.TimeoutExpired, OSError):
        pass

    if market_started:
        time.sleep(1.0)
        if verify_play_store_foreground(serial, adb_bin=resolved_adb):
            return {
                "success": True,
                "open_status": "success",
                "open_method": "market_uri",
                "play_store_foreground_verified": True,
                "target_url": market_url,
                "url": market_url,
                "serial": serial,
            }

    # Attempt 2: HTTPS Fallback
    cmd_https = [
        resolved_adb,
        "-s",
        serial,
        "shell",
        "am",
        "start",
        "-a",
        "android.intent.action.VIEW",
        "-d",
        https_url,
    ]
    https_started = False
    try:
        res_h = subprocess.run(cmd_https, capture_output=True, text=True, timeout=timeout_seconds)
        if res_h.returncode == 0 and "Error:" not in (res_h.stdout or ""):
            https_started = True
    except (subprocess.TimeoutExpired, OSError):
        pass

    if https_started:
        time.sleep(1.0)
        if verify_play_store_foreground(serial, adb_bin=resolved_adb):
            return {
                "success": True,
                "open_status": "success",
                "open_method": "https_fallback",
                "play_store_foreground_verified": True,
                "target_url": https_url,
                "url": https_url,
                "serial": serial,
            }

    # Neither market nor https succeeded in bringing Play Store into foreground
    return {
        "success": False,
        "open_status": "failed",
        "open_method": "failed",
        "play_store_foreground_verified": False,
        "target_url": market_url,
        "url": market_url,
        "serial": serial,
        "error": "Google Play Store was not detected in foreground after market URI and HTTPS fallback",
    }


def wait_for_device_installation(
    serial: str,
    package_name: str,
    timeout_seconds: float = 180.0,
    poll_interval: float = 2.0,
    adb_bin: str | None = None,
    progress_callback: Callable[[str, str, str, dict | None], None] | None = None,
) -> list[str]:
    """Polls ADB package manager until package is detected or timeout occurs."""
    resolved_adb = resolve_adb_executable(adb_bin)
    start_time = time.monotonic()

    while (time.monotonic() - start_time) < timeout_seconds:
        paths = query_package_paths(
            adb_bin=resolved_adb,
            serial=serial,
            package_name=package_name,
            timeout_seconds=min(10.0, timeout_seconds),
        )
        if paths:
            return paths

        elapsed = time.monotonic() - start_time
        remaining = max(0, int(timeout_seconds - elapsed))
        if progress_callback:
            try:
                progress_callback(
                    "acquisition",
                    "waiting_for_installation",
                    f"Waiting for installation of '{package_name}' in emulator Play Store... ({remaining}s remaining)",
                    {"package_name": package_name, "remaining_seconds": remaining},
                )
            except Exception:
                pass

        time.sleep(poll_interval)

    # Final check
    paths = query_package_paths(
        adb_bin=resolved_adb,
        serial=serial,
        package_name=package_name,
        timeout_seconds=min(10.0, timeout_seconds),
    )
    if paths:
        return paths

    raise PlayStoreAcquisitionError(
        f"Package '{package_name}' was not installed on device within {timeout_seconds:.0f}s timeout.",
        package_name=package_name,
        reason_code="installation_timeout",
        installed_on_device=False,
    )


def acquire_play_store_app(
    package_name: str,
    output_dir: Path | str,
    serial: str,
    adb_bin: str | None = None,
    timeout_seconds: float = 60.0,
    allow_splits: bool = False,
    allow_store_install: bool = False,
    install_mode: str = "manual",
    install_wait_timeout_seconds: float = 180.0,
    progress_callback: Callable[[str, str, str, dict | None], None] | None = None,
) -> dict:
    """Acquires a Play Store app from the connected Android test device.

    Workflow:
      1. Verifies ADB connection and queries 'pm path <package>'.
      2. If package is already installed, proceeds immediately with acquisition.
      3. If package is NOT installed:
         - If allow_store_install is False, raises PlayStoreAcquisitionError immediately.
         - If allow_store_install is True:
           - Opens Play Store via verified market URI + HTTPS fallback.
           - If install_mode == 'ui_automation': inspects screen, detects blockers, taps Install if safe.
           - Polls 'pm path' until package is installed or timeout expires.
      4. Inspects package layout (monolithic vs split) and pulls APK files.
      5. Validates structural integrity and computes SHA-256 digests.
    """
    resolved_adb = resolve_adb_executable(adb_bin)
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    apk_paths = query_package_paths(
        adb_bin=resolved_adb,
        serial=serial,
        package_name=package_name,
        timeout_seconds=min(timeout_seconds, 30.0),
    )

    initially_installed = bool(apk_paths)
    install_status = "already_installed" if initially_installed else "none"
    play_store_open_status = "skipped" if initially_installed else "not_started"
    play_store_open_method = "none"
    play_store_foreground_verified = False

    # 1. Package not installed
    if not apk_paths:
        if not allow_store_install:
            raise PlayStoreAcquisitionError(
                "Package is not installed on the connected Android device.",
                package_name=package_name,
                installed_on_device=False,
                package_layout="none",
                reason_code="package_not_installed",
            )

        # Open Google Play Store on device
        if progress_callback:
            progress_callback(
                "acquisition",
                "running",
                f"Package '{package_name}' not installed. Opening Google Play Store on device...",
                {"package_name": package_name},
            )

        open_res = open_play_store_on_device(
            serial=serial,
            package_name=package_name,
            adb_bin=resolved_adb,
            verify_foreground=True,
            prefer_market_uri=True,
        )
        play_store_open_status = open_res.get("open_status", "failed")
        play_store_open_method = open_res.get("open_method", "failed")
        play_store_foreground_verified = open_res.get("play_store_foreground_verified", False)

        if not open_res.get("success"):
            err_msg = open_res.get("error", "Google Play Store is not available or failed to open.")
            raise PlayStoreAcquisitionError(
                f"Failed to open Google Play Store for '{package_name}': {err_msg}",
                package_name=package_name,
                reason_code="play_store_not_available",
                diagnostics=[err_msg],
            )

        # Installation Phase
        if install_mode == "ui_automation":
            if progress_callback:
                progress_callback(
                    "acquisition",
                    "running",
                    f"Inspecting Play Store screen for automated installation of '{package_name}'...",
                    {"package_name": package_name},
                )
            time.sleep(2.0)
            from src.play_store_ui_automator import attempt_play_store_ui_install
            ui_res = attempt_play_store_ui_install(
                serial=serial,
                package_name=package_name,
                adb_bin=resolved_adb,
            )

            if ui_res.get("status") == "blocked":
                block_reason = ui_res.get("reason") or "device_not_compatible"
                raise PlayStoreAcquisitionError(
                    f"Play Store installation blocked: {block_reason}",
                    package_name=package_name,
                    reason_code=block_reason,
                    diagnostics=ui_res.get("diagnostics", []),
                )
            if ui_res.get("status") == "failed":
                fail_reason = ui_res.get("reason") or "ui_automation_failed"
                raise PlayStoreAcquisitionError(
                    f"Play Store UI automation failed: {fail_reason}",
                    package_name=package_name,
                    reason_code=fail_reason,
                    diagnostics=ui_res.get("diagnostics", []),
                )

            # ui_res["status"] is 'install_triggered' or 'already_installed'
            if progress_callback:
                progress_callback(
                    "acquisition",
                    "waiting_for_installation",
                    f"Install triggered. Waiting for '{package_name}' to appear on device...",
                    {"package_name": package_name},
                )

            apk_paths = wait_for_device_installation(
                serial=serial,
                package_name=package_name,
                timeout_seconds=install_wait_timeout_seconds,
                poll_interval=2.0,
                adb_bin=resolved_adb,
                progress_callback=progress_callback,
            )
            install_status = "installed_via_ui_automation"

        else:  # manual mode (default)
            if progress_callback:
                progress_callback(
                    "acquisition",
                    "waiting_for_installation",
                    f"Waiting for installation of '{package_name}' in emulator Play Store (timeout: {int(install_wait_timeout_seconds)}s)...",
                    {"package_name": package_name, "remaining_seconds": int(install_wait_timeout_seconds)},
                )

            apk_paths = wait_for_device_installation(
                serial=serial,
                package_name=package_name,
                timeout_seconds=install_wait_timeout_seconds,
                poll_interval=2.0,
                adb_bin=resolved_adb,
                progress_callback=progress_callback,
            )
            install_status = "installed_via_manual"

    # 2. Split APK Detection
    layout = detect_package_layout(apk_paths)
    if layout == "split":
        if not allow_splits:
            raise PlayStoreAcquisitionError(
                "Split APK package detected. Split APK analysis is not supported in V1.",
                package_name=package_name,
                installed_on_device=True,
                package_layout="split",
            )
        from src.split_acquirer import acquire_split_package_set
        split_meta = acquire_split_package_set(
            package_name=package_name,
            output_dir=out_dir,
            serial=serial,
            adb_bin=resolved_adb,
            timeout_seconds=timeout_seconds,
            remote_paths=apk_paths,
        )
        split_meta["initially_installed"] = initially_installed
        split_meta["install_mode"] = install_mode
        split_meta["install_status"] = install_status
        split_meta["play_store_open_status"] = play_store_open_status
        split_meta["play_store_open_method"] = play_store_open_method
        split_meta["play_store_foreground_verified"] = play_store_foreground_verified
        return split_meta

    # 3. Monolithic Package Acquisition
    remote_base = apk_paths[0]
    local_filename = f"{package_name}.apk"
    local_apk_path = out_dir / local_filename

    # If file exists, remove or overwrite cleanly in isolated run workspace
    if local_apk_path.exists():
        try:
            local_apk_path.unlink()
        except OSError:
            pass

    pull_device_apk(
        adb_bin=resolved_adb,
        serial=serial,
        remote_path=remote_base,
        local_path=local_apk_path,
        timeout_seconds=timeout_seconds,
    )

    # Structural APK validation on pulled package
    validation = validate_apk_structure(local_apk_path)
    if not validation["is_valid_apk"]:
        raise PlayStoreAcquisitionError(
            "Pulled device package failed structural APK validation.",
            package_name=package_name,
            installed_on_device=True,
            package_layout="monolithic",
        )

    # Compute SHA-256 and size
    hasher = hashlib.sha256()
    size_bytes = local_apk_path.stat().st_size
    with open(local_apk_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)

    try:
        saved_path = local_apk_path.relative_to(Path.cwd()).as_posix()
    except ValueError:
        saved_path = local_apk_path.as_posix()

    return {
        "input_url": f"https://play.google.com/store/apps/details?id={package_name}",
        "platform": "android",
        "source_type": "play_store",
        "package_name": package_name,
        "installed_on_device": True,
        "package_layout": "monolithic",
        "remote_paths": apk_paths,
        "filename": local_filename,
        "saved_path": saved_path,
        "size_bytes": size_bytes,
        "sha256": hasher.hexdigest(),
        "package_type": "apk",
        "validation": validation,
        "initially_installed": initially_installed,
        "install_mode": install_mode,
        "install_status": install_status,
        "play_store_open_status": play_store_open_status,
        "play_store_open_method": play_store_open_method,
        "play_store_foreground_verified": play_store_foreground_verified,
    }


def acquire_play_store_package(
    package_name: str,
    output_dir: Path | str,
    serial: str,
    adb_bin: str | None = None,
    timeout_seconds: float = 60.0,
    install_mode: str = "manual",
    install_wait_timeout_seconds: float = 180.0,
    progress_callback: Callable[[str, str, str, dict | None], None] | None = None,
) -> dict:
    """V2 Split-aware and install-aware Play Store package acquisition."""
    return acquire_play_store_app(
        package_name=package_name,
        output_dir=output_dir,
        serial=serial,
        adb_bin=adb_bin,
        timeout_seconds=timeout_seconds,
        allow_splits=True,
        allow_store_install=True,
        install_mode=install_mode,
        install_wait_timeout_seconds=install_wait_timeout_seconds,
        progress_callback=progress_callback,
    )
