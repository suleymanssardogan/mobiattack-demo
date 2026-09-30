"""App launchability check and activity invocation module."""

from __future__ import annotations

import re
from typing import Tuple

from src.dynamic.preflight.device_check import run_adb_cmd
from src.dynamic.preflight.models import ErrorCode


def resolve_launchable_activity(
    adb_bin: str,
    serial: str,
    package_name: str,
) -> str | None:
    """Discovers the main/launchable activity for a package on the device."""
    # Method 1: 'cmd package resolve-activity --brief <pkg>'
    code, stdout, _ = run_adb_cmd(
        adb_bin,
        ["shell", "cmd", "package", "resolve-activity", "--brief", package_name],
        serial=serial,
    )
    if code == 0 and stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if "/" in line and not line.startswith("priority="):
                # Returns formatted like 'com.example.app/.MainActivity'
                parts = line.split("/")
                if len(parts) == 2 and package_name in parts[0]:
                    act = parts[1]
                    if act.startswith("."):
                        return parts[0] + act
                    return act

    # Method 2: Fallback query via dumpsys package intent-filters
    code, dumpsys_out, _ = run_adb_cmd(
        adb_bin,
        ["shell", "dumpsys", "package", package_name],
        serial=serial,
    )
    if code == 0 and dumpsys_out:
        # Search for android.intent.action.MAIN filter
        pattern = re.compile(
            r"Activity\s+([a-zA-Z0-9_\.]+\/[a-zA-Z0-9_\.]+).*?android\.intent\.action\.MAIN",
            re.DOTALL,
        )
        match = pattern.search(dumpsys_out)
        if match:
            raw_comp = match.group(1).strip()
            if "/" in raw_comp:
                parts = raw_comp.split("/")
                act = parts[1]
                if act.startswith("."):
                    return parts[0] + act
                return act

    return None


def launch_application(
    adb_bin: str,
    serial: str,
    package_name: str,
    activity_name: str | None = None,
    timeout_seconds: float = 15.0,
) -> Tuple[bool, str | None, ErrorCode | None, str | None]:
    """Attempts to launch application activity on device and classifies failures."""
    target_activity = activity_name
    if not target_activity:
        target_activity = resolve_launchable_activity(adb_bin, serial, package_name)

    if not target_activity:
        return (
            False,
            None,
            ErrorCode.APP_LAUNCH_FAILED,
            f"No launchable activity found for package '{package_name}'",
        )

    # Normalize component: com.example.app/.MainActivity -> com.example.app/com.example.app.MainActivity
    if target_activity.startswith("."):
        component = f"{package_name}/{package_name}{target_activity}"
    elif "/" in target_activity:
        component = target_activity
    else:
        component = f"{package_name}/{target_activity}"

    # Execute am start -W
    code, stdout, stderr = run_adb_cmd(
        adb_bin,
        ["shell", "am", "start", "-W", "-n", component],
        serial=serial,
        timeout_seconds=timeout_seconds,
    )
    output = (stdout + "\n" + stderr).strip()

    if code == -1:
        return False, target_activity, ErrorCode.COMMAND_TIMEOUT, f"am start timed out after {timeout_seconds}s"

    # Analyze am start output
    if "Status: ok" in output:
        return True, target_activity, None, None

    if "SecurityException" in output or "Permission Denial" in output:
        return (
            False,
            target_activity,
            ErrorCode.APP_LAUNCH_FAILED,
            f"Permission denied launching {component}: {output}",
        )

    if "Activity class" in output and "does not exist" in output:
        return (
            False,
            target_activity,
            ErrorCode.APP_LAUNCH_FAILED,
            f"Activity does not exist on device: {component}",
        )

    if "Error: Activity not started" in output or "crash" in output.lower():
        return (
            False,
            target_activity,
            ErrorCode.APP_CRASHED,
            f"App crashed or failed to start: {output}",
        )

    # Some versions return code 0 but with Error string
    if "Error:" in output:
        return (
            False,
            target_activity,
            ErrorCode.APP_LAUNCH_FAILED,
            f"Launch failed with error: {output}",
        )

    # If return code is 0 and no explicit error, accept as success
    if code == 0:
        return True, target_activity, None, None

    return (
        False,
        target_activity,
        ErrorCode.APP_LAUNCH_FAILED,
        f"am start exited with code {code}: {output}",
    )
