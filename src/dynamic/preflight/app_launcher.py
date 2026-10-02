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
    from src.android_identity import launch_component, AndroidIdentityError
    code, stdout, _ = run_adb_cmd(adb_bin,
        ['shell', 'cmd', 'package', 'resolve-activity', '--brief', '-a',
         'android.intent.action.MAIN', '-c', 'android.intent.category.LAUNCHER', package_name], serial=serial)
    if code == 0:
        components = []
        for line in stdout.splitlines():
            if '/' not in line or line.startswith('priority='):continue
            try:components.append(launch_component(package_name, line.strip()))
            except AndroidIdentityError:continue
        if len(set(components)) == 1:return components[0].split('/', 1)[1]
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

    from src.android_identity import launch_component, AndroidIdentityError
    try:
        component = launch_component(package_name, target_activity)
    except AndroidIdentityError as error:
        return False, None, ErrorCode.LAUNCHER_UNRESOLVED, error.reason_code

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
