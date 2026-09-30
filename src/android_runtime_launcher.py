"""ADB / MuMu Basic Install & Launch Automation Module for MobiAttack-v1.

Automates device discovery, APK installation, launcher activity start, process
verification, and foreground activity observation over ADB. Provides deterministic
runtime execution evidence without dynamic vulnerability assessment or UI interaction.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import time

from src.system_env import resolve_executable

DEFAULT_COMMAND_TIMEOUT_SECONDS: float = 30.0
DEFAULT_MAX_WAIT_SECONDS: float = 8.0
DEFAULT_POLL_INTERVAL: float = 0.5


class AndroidRuntimeError(ValueError):
    """Raised when ADB executable resolution, device selection, installation, or launch fails."""
    pass


class AndroidDeviceUnavailableError(AndroidRuntimeError):
    """Raised when ADB executable or a usable Android device/emulator is unavailable."""

    def __init__(self, message: str, reason: str = "device_unavailable"):
        super().__init__(message)
        self.reason = reason


def resolve_adb_executable(adb_executable: str | None = None) -> str:
    """Resolves adb binary from system PATH or explicit path.

    Raises:
        AndroidDeviceUnavailableError: If adb executable cannot be found.
    """
    resolved = resolve_executable("adb", adb_executable)
    if not resolved:
        raise AndroidDeviceUnavailableError(
            f"Required executable 'adb' not found on system PATH. "
            f"(Specified: '{adb_executable or 'adb'}')",
            reason="adb_not_found",
        )
    return resolved


def get_connected_devices(
    adb_executable: str | None = None,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> list[str]:
    """Queries adb devices and returns serial numbers of devices in 'device' state.

    Ignores entries with status offline, unauthorized, unknown, etc.
    """
    adb_bin = resolve_adb_executable(adb_executable)
    cmd = [adb_bin, "devices"]
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, OSError) as err:
        raise AndroidDeviceUnavailableError(
            f"Failed to query connected devices via adb: {err}",
            reason="adb_server_error",
        ) from err

    if res.returncode != 0:
        err_msg = (res.stderr or res.stdout or "").strip()
        raise AndroidDeviceUnavailableError(
            f"adb devices command failed ({res.returncode}): {err_msg}",
            reason="adb_server_error",
        )

    devices: list[str] = []
    lines = res.stdout.strip().splitlines()
    # Skip header line 'List of devices attached'
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])

    return devices


def select_target_device(
    adb_serial: str | None = None,
    adb_executable: str | None = None,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> str:
    """Selects and validates a target device serial.

    Rules:
    - If adb_serial is provided: verifies that device is connected in 'device' state.
    - If adb_serial is None:
        - 0 devices -> raises AndroidDeviceUnavailableError
        - 1 device -> auto-selects it
        - >1 devices -> raises AndroidDeviceUnavailableError (explicit serial required)
    """
    usable_devices = get_connected_devices(adb_executable, timeout_seconds=timeout_seconds)

    if adb_serial is not None:
        clean_serial = str(adb_serial).strip()
        if clean_serial not in usable_devices:
            raise AndroidDeviceUnavailableError(
                f"Specified device serial '{clean_serial}' is not connected or not in 'device' state. "
                f"Available devices: {usable_devices}",
                reason="device_not_ready",
            )
        return clean_serial

    if len(usable_devices) == 0:
        raise AndroidDeviceUnavailableError(
            "No Android device/emulator found in 'device' state. "
            "Please start MuMu emulator or connect an Android device via ADB.",
            reason="no_devices",
        )
    elif len(usable_devices) == 1:
        return usable_devices[0]
    else:
        raise AndroidDeviceUnavailableError(
            f"Multiple devices/emulators connected ({usable_devices}). "
            f"Explicit adb_serial is required to avoid ambiguous execution.",
            reason="multiple_devices",
        )


def check_device_availability(
    adb_serial: str | None = None,
    adb_executable: str | None = None,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> tuple[bool, str, str | None]:
    """Non-throwing preflight check for whether ADB and a usable target device are available.

    Returns:
        tuple (is_available: bool, reason: str, serial: str | None)
    """
    try:
        adb_bin = resolve_adb_executable(adb_executable)
        serial = select_target_device(
            adb_serial=adb_serial,
            adb_executable=adb_bin,
            timeout_seconds=timeout_seconds,
        )
        return True, "ready", serial
    except AndroidDeviceUnavailableError as exc:
        return False, getattr(exc, "reason", "device_unavailable"), None
    except Exception as exc:
        return False, f"adb_error: {exc}", None


def normalize_component_name(package_name: str, activity_name: str) -> str:
    """Normalizes package name and activity name into standard 'package/component' syntax."""
    pkg = package_name.strip()
    act = activity_name.strip()
    if not pkg:
        raise AndroidRuntimeError("Package name must be a non-empty string.")
    if not act:
        raise AndroidRuntimeError("Launcher activity must be a non-empty string.")

    # Ensure fully-qualified activity representation
    if act.startswith("."):
        full_act = f"{pkg}{act}"
    elif "." not in act:
        full_act = f"{pkg}.{act}"
    else:
        full_act = act

    return f"{pkg}/{full_act}"


def install_apk(
    adb_bin: str,
    serial: str,
    apk_path: str | Path,
    reinstall: bool = False,
    grant_permissions: bool = False,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> dict:
    """Installs an APK onto the target device.

    Args:
        adb_bin: Path to adb executable.
        serial: Verified device serial.
        apk_path: Path to APK file on host.
        reinstall: If True, uses 'install -r'; if False, standard 'install'.
        grant_permissions: If True, uses 'install -g' to grant runtime permissions.
        timeout_seconds: Subprocess command timeout.

    Returns:
        dict: {"success": True, "reinstall": bool, "grant_permissions": bool}

    Raises:
        AndroidRuntimeError: If installation fails or APK does not exist.
    """
    apk_file = Path(apk_path)
    if not apk_file.is_file():
        raise AndroidRuntimeError(f"APK file not found: '{apk_path}'")

    cmd = [adb_bin, "-s", serial, "install"]
    if grant_permissions:
        cmd.append("-g")
    if reinstall:
        cmd.append("-r")
    cmd.append(str(apk_file))

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, OSError) as err:
        raise AndroidRuntimeError(f"adb install command timed out or failed: {err}") from err

    stdout = res.stdout or ""
    stderr = res.stderr or ""
    combined = f"{stdout}\n{stderr}".strip()

    # Android adb install output typically prints "Success" on completion
    has_success_text = "Success" in stdout or "Success" in stderr
    if res.returncode != 0 or ("Failure" in combined and not has_success_text):
        err_msg = combined[:300] if combined else f"returncode {res.returncode}"
        raise AndroidRuntimeError(f"APK installation failed on device '{serial}': {err_msg}")

    return {
        "success": True,
        "reinstall": reinstall,
        "grant_permissions": grant_permissions,
    }


def launch_activity(
    adb_bin: str,
    serial: str,
    component: str,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> dict:
    """Starts the launcher activity using 'am start -n <component>'."""
    cmd = [adb_bin, "-s", serial, "shell", "am", "start", "-n", component]
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, OSError) as err:
        raise AndroidRuntimeError(f"adb am start command timed out or failed: {err}") from err

    stdout = res.stdout or ""
    stderr = res.stderr or ""
    combined = f"{stdout}\n{stderr}".strip()

    # Detect explicit am start errors (e.g. Error: Activity class ... does not exist)
    if res.returncode != 0 or "Error:" in combined:
        err_msg = combined[:300] if combined else f"returncode {res.returncode}"
        raise AndroidRuntimeError(f"Failed to start activity '{component}': {err_msg}")

    return {"success": True, "component": component}


def query_process_pid(
    adb_bin: str,
    serial: str,
    package_name: str,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> int | None:
    """Queries device for running process PID of package_name.

    Primary: 'pidof <package_name>'
    Fallback: 'ps -A' with exact package name matching.
    """
    # 1. Try pidof
    cmd_pidof = [adb_bin, "-s", serial, "shell", "pidof", package_name]
    try:
        res = subprocess.run(
            cmd_pidof,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        if res.returncode == 0 and res.stdout:
            parts = res.stdout.strip().split()
            if parts and parts[0].isdigit():
                return int(parts[0])
    except (subprocess.TimeoutExpired, OSError):
        pass

    # 2. Fallback to ps -A
    cmd_ps = [adb_bin, "-s", serial, "shell", "ps", "-A"]
    try:
        res = subprocess.run(
            cmd_ps,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        if res.returncode == 0 and res.stdout:
            for line in res.stdout.strip().splitlines():
                fields = line.split()
                # ps -A format typically: USER PID PPID VSZ RSS WCHAN ADDR S NAME
                # We strictly check if the last field matches package_name exactly
                if len(fields) >= 9 and fields[-1] == package_name:
                    if fields[1].isdigit():
                        return int(fields[1])
                elif len(fields) >= 2 and fields[-1] == package_name:
                    if fields[1].isdigit():
                        return int(fields[1])
    except (subprocess.TimeoutExpired, OSError):
        pass

    return None


def parse_dumpsys_foreground_activity(dumpsys_text: str) -> tuple[str | None, str | None]:
    """Parses dumpsys output to extract observed foreground package and activity.

    Looks for recognized foreground patterns:
    - ResumedActivity: ActivityRecord{... u0 pkg/act ...}
    - mResumedActivity: ActivityRecord{... u0 pkg/act ...}
    - topResumedActivity=ActivityRecord{... pkg/act}
    - mCurrentFocus=Window{... pkg/act}

    Returns:
        (observed_package, observed_activity) or (None, None)
    """
    if not dumpsys_text:
        return None, None

    patterns = [
        # ResumedActivity: ActivityRecord{... u0 <pkg>/<act> ...}
        r"(?:ResumedActivity|mResumedActivity|topResumedActivity)[^:\n]*:\s*(?:ActivityRecord\{[^}]*?\s+)?([a-zA-Z0-9_.]+)/([a-zA-Z0-9_.]+)",
        # mCurrentFocus=Window{... <pkg>/<act>}
        r"mCurrentFocus=Window\{[^}]*?\s+([a-zA-Z0-9_.]+)/([a-zA-Z0-9_.]+)",
    ]

    for pat in patterns:
        m = re.search(pat, dumpsys_text)
        if m:
            pkg = m.group(1)
            raw_act = m.group(2)
            # Normalize .MainActivity -> pkg.MainActivity
            if raw_act.startswith("."):
                normalized_act = f"{pkg}{raw_act}"
            elif "." not in raw_act:
                normalized_act = f"{pkg}.{raw_act}"
            else:
                normalized_act = raw_act
            return pkg, normalized_act

    return None, None


def get_current_activity(
    adb_serial: str,
    adb_executable: str | None = None,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> dict:
    """Observation helper extracting current foreground package and activity from dumpsys.

    Non-intrusive observation only; performs no taps, input, or interactions.
    """
    adb_bin = resolve_adb_executable(adb_executable)
    # Primary: dumpsys activity activities
    cmd = [adb_bin, "-s", adb_serial, "shell", "dumpsys", "activity", "activities"]
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        if res.returncode == 0 and res.stdout:
            pkg, act = parse_dumpsys_foreground_activity(res.stdout)
            if pkg and act:
                return {
                    "observed_package": pkg,
                    "observed_activity": act,
                }
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Fallback: dumpsys window
    cmd_win = [adb_bin, "-s", adb_serial, "shell", "dumpsys", "window"]
    try:
        res = subprocess.run(
            cmd_win,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        if res.returncode == 0 and res.stdout:
            pkg, act = parse_dumpsys_foreground_activity(res.stdout)
            if pkg and act:
                return {
                    "observed_package": pkg,
                    "observed_activity": act,
                }
    except (subprocess.TimeoutExpired, OSError):
        pass

    return {
        "observed_package": None,
        "observed_activity": None,
    }


def launch_android_app(
    apk_path: str | Path | None,
    package_name: str,
    launcher_activity: str,
    adb_serial: str | None = None,
    adb_executable: str | None = None,
    reinstall: bool = False,
    grant_permissions: bool = False,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    max_wait_seconds: float = DEFAULT_MAX_WAIT_SECONDS,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    skip_install: bool = False,
) -> dict:
    """Installs APK, starts launcher activity, and verifies runtime execution presence.

    Args:
        apk_path: Path to target APK file.
        package_name: Trusted upstream package name (from Task 01).
        launcher_activity: Trusted upstream launcher activity (from Task 01).
        adb_serial: Optional target device serial.
        adb_executable: Optional path to adb binary.
        reinstall: If True, passes '-r' to adb install.
        grant_permissions: If True, passes '-g' to adb install to grant runtime permissions.
        timeout_seconds: Timeout per individual adb command.
        max_wait_seconds: Total time window to poll for process/foreground presence.
        poll_interval: Delay between poll attempts.

    Returns:
        Deterministic runtime metadata dictionary.

    Raises:
        AndroidRuntimeError: On missing tools, no devices, install failure, am start failure,
                             or if the process cannot be detected within max_wait_seconds.
    """
    adb_bin = resolve_adb_executable(adb_executable)
    serial = select_target_device(
        adb_serial=adb_serial,
        adb_executable=adb_bin,
        timeout_seconds=timeout_seconds,
    )

    # 1. Normalize component
    component = normalize_component_name(package_name, launcher_activity)

    # 2. Install APK (or skip if already installed on device, e.g. Play Store packages)
    if skip_install:
        install_meta = {
            "success": True,
            "skipped_already_installed": True,
            "apk_path": str(apk_path) if apk_path else None,
            "reinstall": reinstall,
            "grant_permissions": grant_permissions,
            "returncode": 0,
            "stdout": "Skipped install: package already installed on device",
            "stderr": "",
        }
    else:
        if not apk_path:
            raise AndroidRuntimeError("apk_path must be provided when skip_install is False")
        install_meta = install_apk(
            adb_bin=adb_bin,
            serial=serial,
            apk_path=apk_path,
            reinstall=reinstall,
            grant_permissions=grant_permissions,
            timeout_seconds=timeout_seconds,
        )

    # 3. Start launcher activity
    launch_meta = launch_activity(
        adb_bin=adb_bin,
        serial=serial,
        component=component,
        timeout_seconds=timeout_seconds,
    )

    # 4. Bounded retry polling for process and foreground activity
    start_time = time.monotonic()
    pid: int | None = None
    observed_pkg: str | None = None
    observed_act: str | None = None

    while (time.monotonic() - start_time) < max_wait_seconds:
        if pid is None:
            pid = query_process_pid(
                adb_bin=adb_bin,
                serial=serial,
                package_name=package_name,
                timeout_seconds=timeout_seconds,
            )

        activity_info = get_current_activity(
            adb_serial=serial,
            adb_executable=adb_bin,
            timeout_seconds=timeout_seconds,
        )
        observed_pkg = activity_info.get("observed_package")
        observed_act = activity_info.get("observed_activity")

        # Stop early if process is detected and foreground activity is verified
        if pid is not None and observed_pkg == package_name:
            break

        time.sleep(poll_interval)

    # If after max_wait_seconds, PID is still not detected, fail clearly
    if pid is None:
        raise AndroidRuntimeError(
            f"Package process '{package_name}' did not start on device '{serial}' "
            f"within {max_wait_seconds} seconds after launch."
        )

    # Explicit status semantics:
    # PID exists + observed foreground package == requested package -> "runtime_launch_verified"
    # PID exists + foreground activity cannot be verified or another package foreground -> "runtime_presence_verified"
    foreground_verified = bool(observed_pkg == package_name)
    status = "runtime_launch_verified" if foreground_verified else "runtime_presence_verified"

    # 5. Live Process Memory & Logcat Leak Inspection (CWE-532 / OWASP M2)
    inspection_meta = None
    try:
        from src.android_runtime_inspector import inspect_runtime_process
        inspection_meta = inspect_runtime_process(
            adb_bin=adb_bin,
            serial=serial,
            package_name=package_name,
            pid=pid,
            timeout_seconds=min(timeout_seconds, 6.0),
        )
    except Exception as exc:
        inspection_meta = {"status": "unavailable", "error": str(exc)}

    return {
        "adb": {
            "executable": adb_bin,
            "serial": serial,
        },
        "install": install_meta,
        "launch": launch_meta,
        "runtime": {
            "process_running": True,
            "pid": pid,
            "observed_package": observed_pkg,
            "observed_activity": observed_act,
            "foreground_verified": foreground_verified,
            "inspection": inspection_meta,
        },
        "status": status,
    }
