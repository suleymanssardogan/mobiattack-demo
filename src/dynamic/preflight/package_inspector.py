"""Package inspection, installation check, and runtime metadata extractor."""

from __future__ import annotations

import os
import re
from typing import Tuple

from src.dynamic.preflight.device_check import run_adb_cmd
from src.dynamic.preflight.models import ApplicationInfo, ErrorCode


def inspect_package(
    adb_bin: str,
    serial: str,
    package_name: str,
) -> Tuple[ApplicationInfo, ErrorCode | None, str | None]:
    """Inspects package status on target device via ADB."""
    if not package_name or not package_name.strip():
        return (
            ApplicationInfo(package_name=""),
            ErrorCode.PACKAGE_NOT_FOUND,
            "Package name must not be empty",
        )

    clean_pkg = package_name.strip()
    app_info = ApplicationInfo(package_name=clean_pkg)

    # 1. Check if installed via 'pm path <pkg>'
    code, stdout, _ = run_adb_cmd(adb_bin, ["shell", "pm", "path", clean_pkg], serial=serial)
    if code != 0 or not stdout or "package:" not in stdout:
        app_info.installed = False
        return (
            app_info,
            ErrorCode.APP_NOT_INSTALLED,
            f"Package '{clean_pkg}' is not installed on device '{serial}'",
        )

    app_info.installed = True
    # Extract install path from first 'package:/path/to/base.apk'
    for line in stdout.splitlines():
        if line.startswith("package:"):
            app_info.install_path = line.replace("package:", "").strip()
            break

    # 2. Extract detailed metadata via 'dumpsys package <pkg>'
    code, dumpsys_out, _ = run_adb_cmd(
        adb_bin, ["shell", "dumpsys", "package", clean_pkg], serial=serial, timeout_seconds=10.0
    )
    if code == 0 and dumpsys_out:
        _parse_dumpsys_package(dumpsys_out, app_info)

    return app_info, None, None


def _parse_dumpsys_package(raw_output: str, app_info: ApplicationInfo) -> None:
    """Parses versionCode, versionName, targetSdk, and permissions from dumpsys package."""
    # Version name
    vname_match = re.search(r"versionName=([^\s]+)", raw_output)
    if vname_match:
        app_info.version_name = vname_match.group(1).strip()

    # Version code and targetSdk
    vcode_match = re.search(r"versionCode=(\d+)", raw_output)
    if vcode_match:
        try:
            app_info.version_code = int(vcode_match.group(1))
        except ValueError:
            pass

    target_match = re.search(r"targetSdk=(\d+)", raw_output)
    if target_match:
        try:
            app_info.target_sdk = int(target_match.group(1))
        except ValueError:
            pass

    # Permissions
    in_requested_section = False
    in_granted_section = False
    requested: list[str] = []
    granted: list[str] = []

    for line in raw_output.splitlines():
        stripped = line.strip()
        if "requested permissions:" in line.lower():
            in_requested_section = True
            in_granted_section = False
            continue
        elif "install permissions:" in line.lower() or "runtime permissions:" in line.lower():
            in_requested_section = False
            in_granted_section = True
            continue
        elif line.startswith("    ") and not line.startswith("      ") and stripped.endswith(":"):
            # New section started
            in_requested_section = False
            in_granted_section = False

        if in_requested_section and stripped:
            perm = stripped.split(":")[0].strip()
            if perm.startswith("android.permission.") or "." in perm:
                requested.append(perm)
        elif in_granted_section and stripped:
            if "granted=true" in stripped:
                perm = stripped.split(":")[0].strip()
                granted.append(perm)

    app_info.requested_permissions = sorted(list(set(requested)))
    app_info.granted_permissions = sorted(list(set(granted)))


def install_apk_on_device(
    adb_bin: str,
    serial: str,
    apk_path: str,
    reinstall: bool = True,
    grant_permissions: bool = True,
    timeout_seconds: float = 60.0,
) -> Tuple[bool, ErrorCode | None, str | None]:
    """Installs an APK file onto the target device via ADB."""
    if not os.path.isfile(apk_path):
        return False, ErrorCode.PACKAGE_NOT_FOUND, f"APK file not found at '{apk_path}'"

    args = ["install"]
    if reinstall:
        args.append("-r")
    if grant_permissions:
        args.append("-g")
    args.append(apk_path)

    code, stdout, stderr = run_adb_cmd(
        adb_bin, args, serial=serial, timeout_seconds=timeout_seconds
    )
    combined = (stdout + "\n" + stderr).strip()

    if code == 0 and "Success" in combined:
        return True, None, None

    if "INSTALL_FAILED_ALREADY_EXISTS" in combined:
        return True, None, "Already installed"

    return (
        False,
        ErrorCode.APP_LAUNCH_FAILED,
        f"APK installation failed: {combined}",
    )
