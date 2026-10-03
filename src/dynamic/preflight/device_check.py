"""Device and emulator readiness check module."""

from __future__ import annotations
from src.dynamic.deadline import bounded_timeout

import os
import shutil
import subprocess
from typing import Tuple

from src.dynamic.preflight.models import DeviceInfo, ErrorCode


def find_adb_binary(custom_path: str | None = None) -> str | None:
    """Locates the ADB executable from custom path, PATH, or common Android SDK locations."""
    if custom_path and os.path.isfile(custom_path) and os.access(custom_path, os.X_OK):
        return custom_path

    env_adb = os.getenv("ADB_PATH")
    if env_adb and os.path.isfile(env_adb) and os.access(env_adb, os.X_OK):
        return env_adb

    which_adb = shutil.which("adb")
    if which_adb:
        return which_adb

    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Library/Android/sdk/platform-tools/adb"),
        os.path.join(home, "Android/Sdk/platform-tools/adb"),
        "/opt/homebrew/bin/adb",
        "/usr/local/bin/adb",
        "/usr/bin/adb",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


def run_adb_cmd(
    adb_bin: str,
    args: list[str],
    serial: str | None = None,
    timeout_seconds: float = 8.0,
) -> Tuple[int, str, str]:
    """Runs an ADB command with timeout and bounded output."""
    cmd = [adb_bin]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(args)

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=bounded_timeout(timeout_seconds),
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout_seconds}s"
    except Exception as exc:
        return -2, "", str(exc)


def check_connected_device(
    adb_bin: str,
    target_serial: str | None = None,
) -> Tuple[DeviceInfo, ErrorCode | None, str | None]:
    """Lists connected devices and validates the target device status."""
    code, stdout, stderr = run_adb_cmd(adb_bin, ["devices"])
    if code != 0:
        return (
            DeviceInfo(connected=False, state="not_found"),
            ErrorCode.DEVICE_NOT_FOUND,
            f"Failed to query adb devices: {stderr}",
        )

    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    device_entries: list[tuple[str, str]] = []
    for line in lines[1:]:  # skip 'List of devices attached'
        parts = line.split()
        if len(parts) >= 2:
            device_entries.append((parts[0], parts[1]))

    if not device_entries:
        return (
            DeviceInfo(connected=False, state="not_found"),
            ErrorCode.DEVICE_NOT_FOUND,
            "No devices or emulators attached via ADB",
        )

    from src.dynamic.runtime.execution_target import select_transport
    try:
        serial = select_transport(device_entries, target_serial)
    except ValueError as exc:
        reason = str(exc)
        error = ErrorCode.MULTIPLE_DEVICES if reason == 'MULTIPLE_DEVICES' else ErrorCode(reason)
        state = {'DEVICE_OFFLINE': 'offline', 'DEVICE_UNAUTHORIZED': 'unauthorized'}.get(reason, 'not_found')
        return DeviceInfo(connected=False, serial=target_serial, state=state), error, (
            'Multiple execution targets attached; explicit selection required.' if reason == 'MULTIPLE_DEVICES'
            else 'Selected execution target is unavailable.')
    state = 'device'

    if state == "unauthorized":
        return (
            DeviceInfo(connected=False, serial=serial, state="unauthorized"),
            ErrorCode.DEVICE_UNAUTHORIZED,
            f"Device '{serial}' is unauthorized. Please accept the USB debugging prompt on the screen.",
        )
    if state == "offline":
        return (
            DeviceInfo(connected=False, serial=serial, state="offline"),
            ErrorCode.DEVICE_OFFLINE,
            f"Device '{serial}' is offline. Please reconnect or restart the emulator.",
        )
    if state != "device":
        return (
            DeviceInfo(connected=False, serial=serial, state=state),
            ErrorCode.DEVICE_NOT_FOUND,
            f"Device '{serial}' is in unrecognized state '{state}'",
        )

    # Device is ready in 'device' state
    dev_info = DeviceInfo(connected=True, serial=serial, state="device")

    # Detect emulator signals
    dev_info.is_emulator = _detect_is_emulator(adb_bin, serial)

    # Detect root signals
    dev_info.root_detected, dev_info.root_signals = _detect_root_signals(adb_bin, serial)

    return dev_info, None, None


def _detect_is_emulator(adb_bin: str, serial: str) -> bool:
    """Detects if connected target is an Android emulator."""
    if serial.startswith("emulator-") or "127.0.0.1:" in serial or "localhost:" in serial:
        return True

    # Check system properties
    _, qemu, _ = run_adb_cmd(adb_bin, ["shell", "getprop", "ro.kernel.qemu"], serial=serial)
    if qemu == "1":
        return True

    _, chars, _ = run_adb_cmd(adb_bin, ["shell", "getprop", "ro.build.characteristics"], serial=serial)
    if "emulator" in chars.lower():
        return True

    _, model, _ = run_adb_cmd(adb_bin, ["shell", "getprop", "ro.product.model"], serial=serial)
    if any(k in model.lower() for k in ["sdk", "emulator", "goldfish", "ranchu"]):
        return True

    return False


def _detect_root_signals(adb_bin: str, serial: str) -> tuple[bool, list[str]]:
    """Inspects target environment for root / superuser presence without modifying anything."""
    signals: list[str] = []

    # 1. which su
    code, stdout, _ = run_adb_cmd(adb_bin, ["shell", "which", "su"], serial=serial)
    if code == 0 and stdout and "/su" in stdout:
        signals.append(f"su binary in PATH: {stdout}")

    # 2. Standard su file locations
    su_paths = [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
    ]
    for p in su_paths:
        c, out, _ = run_adb_cmd(adb_bin, ["shell", "ls", p], serial=serial)
        if c == 0 and "No such file" not in out and p in out:
            signals.append(f"su binary at: {p}")

    # 3. Magisk / Superuser indicators
    c, out, _ = run_adb_cmd(adb_bin, ["shell", "ls", "/data/adb/magisk"], serial=serial)
    if c == 0 and "No such file" not in out:
        signals.append("Magisk directory found (/data/adb/magisk)")

    return len(signals) > 0, signals
