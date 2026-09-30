"""Runtime baseline health check module."""

from __future__ import annotations

import re
import time
from typing import Tuple

from src.dynamic.preflight.device_check import run_adb_cmd
from src.dynamic.preflight.models import ErrorCode, RuntimeBaseline


def check_runtime_health(
    adb_bin: str,
    serial: str,
    package_name: str,
    post_launch_wait_seconds: float = 1.5,
) -> Tuple[RuntimeBaseline, bool, ErrorCode | None, str | None]:
    """Evaluates process baseline health, foreground state, and fatal logcat entries.

    Returns:
        (RuntimeBaseline, is_foreground, ErrorCode | None, error_msg | None)
    """
    time.sleep(post_launch_wait_seconds)
    baseline = RuntimeBaseline(launch_success=True)

    # 1. Process ID detection
    pid = _find_process_pid(adb_bin, serial, package_name)
    baseline.pid = pid

    if pid is None:
        baseline.immediate_crash = True
        baseline.launch_success = False
        return (
            baseline,
            False,
            ErrorCode.APP_CRASHED,
            f"Process for package '{package_name}' is not running (immediate exit or crash).",
        )

    # 2. Foreground verification
    is_foreground = _check_foreground_status(adb_bin, serial, package_name)

    # 3. Fatal Logcat inspection
    has_fatal, snippets = _scan_recent_fatal_logs(adb_bin, serial, pid, package_name)
    baseline.fatal_log_detected = has_fatal
    baseline.fatal_log_snippets = snippets

    if has_fatal:
        baseline.immediate_crash = True
        return (
            baseline,
            is_foreground,
            ErrorCode.APP_CRASHED,
            f"Fatal exception or crash detected in logcat: {snippets[:1]}",
        )

    return baseline, is_foreground, None, None


def _find_process_pid(adb_bin: str, serial: str, package_name: str) -> int | None:
    """Queries device for process PID via pidof with ps fallback."""
    code, stdout, _ = run_adb_cmd(adb_bin, ["shell", "pidof", package_name], serial=serial)
    if code == 0 and stdout:
        tokens = stdout.split()
        for tok in tokens:
            if tok.isdigit():
                return int(tok)

    # Fallback to 'ps -A'
    code, ps_out, _ = run_adb_cmd(adb_bin, ["shell", "ps", "-A"], serial=serial)
    if code == 0 and ps_out:
        for line in ps_out.splitlines():
            if package_name in line:
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1])

    return None


def _check_foreground_status(adb_bin: str, serial: str, package_name: str) -> bool:
    """Verifies if package is currently focused or resumed in foreground."""
    # Method 1: dumpsys window displays
    code, win_out, _ = run_adb_cmd(
        adb_bin, ["shell", "dumpsys", "window", "displays"], serial=serial
    )
    if code == 0 and win_out:
        for line in win_out.splitlines():
            if ("mCurrentFocus" in line or "mFocusedApp" in line) and package_name in line:
                return True

    # Method 2: dumpsys activity activities (mResumedActivity)
    code, act_out, _ = run_adb_cmd(
        adb_bin, ["shell", "dumpsys", "activity", "activities"], serial=serial
    )
    if code == 0 and act_out:
        for line in act_out.splitlines():
            if ("mResumedActivity" in line or "topResumedActivity" in line) and package_name in line:
                return True

    return False


def _scan_recent_fatal_logs(
    adb_bin: str,
    serial: str,
    pid: int,
    package_name: str,
) -> tuple[bool, list[str]]:
    """Inspects recent logcat lines for fatal exceptions or crash signatures."""
    fatal_patterns = [
        re.compile(r"FATAL EXCEPTION", re.IGNORECASE),
        re.compile(r"AndroidRuntime:\s+Shutting down VM", re.IGNORECASE),
        re.compile(r"NullPointerException", re.IGNORECASE),
        re.compile(r"Fatal signal\s+\d+", re.IGNORECASE),
        re.compile(rf"ANR in\s+{re.escape(package_name)}", re.IGNORECASE),
    ]

    # Query logcat for this PID with bounded lines
    code, stdout, _ = run_adb_cmd(
        adb_bin,
        ["shell", "logcat", "-d", f"--pid={pid}", "-t", "300"],
        serial=serial,
    )
    if code != 0 or not stdout:
        return False, []

    snippets: list[str] = []
    for line in stdout.splitlines():
        for pat in fatal_patterns:
            if pat.search(line):
                snippets.append(line.strip())
                break
        if len(snippets) >= 5:
            break

    return len(snippets) > 0, snippets
