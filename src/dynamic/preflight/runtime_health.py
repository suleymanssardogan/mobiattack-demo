"""Runtime baseline health check module."""

from __future__ import annotations
from src.dynamic.deadline import bounded_operation, current_deadline

import re
import time
from typing import Callable, Tuple

from src.dynamic.preflight.device_check import run_adb_cmd
from src.dynamic.preflight.models import ErrorCode, RuntimeBaseline


DEFAULT_LAUNCH_MAX_ATTEMPTS: int = 5
DEFAULT_LAUNCH_POLL_INTERVAL: float = 0.5
DEFAULT_LAUNCH_DEADLINE_SECONDS: float = 8.0


@bounded_operation(8.0, field="deadline_seconds")
def check_runtime_health(
    adb_bin: str,
    serial: str,
    package_name: str,
    post_launch_wait_seconds: float | None = None,
    max_attempts: int = DEFAULT_LAUNCH_MAX_ATTEMPTS,
    poll_interval: float = DEFAULT_LAUNCH_POLL_INTERVAL,
    deadline_seconds: float = DEFAULT_LAUNCH_DEADLINE_SECONDS,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    relaunch_fn: Callable[[], Tuple[bool, str | None]] | None = None,
) -> Tuple[RuntimeBaseline, bool, ErrorCode | None, str | None]:
    """Evaluates process baseline health, foreground state, and fatal logcat entries via a bounded stabilization loop.

    Replaces fragile fixed sleeps with condition-based polling:
    - Bounded by max_attempts and deadline_seconds
    - Immediate early termination on fatal logcat crash or process death
    - Adaptive acceptance of delayed PID or delayed foreground state
    - Optional single controlled relaunch if app fails to reach foreground

    Returns:
        (RuntimeBaseline, is_foreground, ErrorCode | None, error_msg | None)
    """
    if post_launch_wait_seconds is not None and post_launch_wait_seconds > 0:
        deadline_seconds = max(deadline_seconds, post_launch_wait_seconds)

    start_time = clock()
    attempt = 0
    pid: int | None = None
    is_foreground: bool = False
    relaunched: bool = False
    observed_pid_previously: bool = False

    baseline = RuntimeBaseline(launch_success=False)

    while attempt < max_attempts and (clock() - start_time) < deadline_seconds:
        attempt += 1

        # 1. Query PID
        try:
            current_pid = _find_process_pid(adb_bin, serial, package_name)
        except OSError:
            baseline.pid = None
            baseline.launch_attempts = attempt
            return baseline, False, ErrorCode.RUNTIME_OBSERVATION_UNAVAILABLE, 'Process observation backend unavailable.'

        pid = current_pid
        if current_pid is not None:
            observed_pid_previously = True

        if current_deadline().remaining() <= 0:
            baseline.pid = None
            baseline.launch_attempts = attempt
            return baseline, False, ErrorCode.COMMAND_TIMEOUT, 'Runtime observation deadline exhausted; state unavailable.'

        # 2. Check for fatal crash signatures in logcat
        has_fatal, snippets = _scan_recent_fatal_logs(
            adb_bin, serial, current_pid, package_name
        )
        if current_deadline().remaining() <= 0:
            baseline.pid = None
            return baseline, False, ErrorCode.COMMAND_TIMEOUT, 'Runtime observation deadline exhausted; state unavailable.'
        if has_fatal:
            baseline.pid = current_pid
            baseline.immediate_crash = True
            baseline.fatal_log_detected = True
            baseline.fatal_log_snippets = snippets
            baseline.launch_attempts = attempt
            return (
                baseline,
                False,
                ErrorCode.APP_CRASHED,
                f"Fatal exception or crash detected in logcat: {snippets[:1]}",
            )

        # 3. Detect sudden process death (was running, now gone)
        if observed_pid_previously and current_pid is None:
            baseline.pid = None
            baseline.immediate_crash = False
            baseline.launch_success = False
            baseline.launch_attempts = attempt
            return (
                baseline,
                False,
                ErrorCode.PROCESS_EXITED,
                f"Process for package '{package_name}' died immediately after launch.",
            )

        # 4. Check foreground state
        if pid is not None:
            is_foreground = _check_foreground_status(adb_bin, serial, package_name)
            if is_foreground and current_deadline().remaining() > 0:
                # Fully stabilized in foreground
                baseline.launch_success = True
                baseline.pid = pid
                baseline.immediate_crash = False
                baseline.fatal_log_detected = False
                baseline.launch_attempts = attempt
                baseline.ready_after_attempt = attempt
                return baseline, True, None, None

        # 5. Controlled single relaunch if app has not reached foreground by attempt 2
        if attempt >= 2 and not is_foreground and relaunch_fn is not None and not relaunched:
            relaunched = True
            try:
                relaunch_fn()
            except Exception:
                pass

        # 6. Sleep for poll interval if within bounds
        elapsed = clock() - start_time
        remaining_time = deadline_seconds - elapsed
        if attempt < max_attempts and remaining_time > 0:
            wait_time = min(poll_interval, remaining_time, current_deadline().remaining())
            if wait_time > 0:
                sleeper(wait_time)

    baseline.launch_attempts = attempt

    # If PID is running but not foreground within deadline, accept presence verified
    if pid is not None and current_deadline().remaining() > 0:
        baseline.launch_success = True
        baseline.pid = pid
        baseline.immediate_crash = False
        baseline.fatal_log_detected = False
        baseline.ready_after_attempt = attempt
        return baseline, False, None, None

    # Never opened (PID never detected)
    baseline.launch_success = False
    baseline.immediate_crash = False
    return (
        baseline,
        False,
        ErrorCode.APP_LAUNCH_FAILED,
        f"Process for package '{package_name}' did not start within {deadline_seconds:.1f}s ({attempt} attempts).",
    )


def _find_process_pid(adb_bin: str, serial: str, package_name: str) -> int | None:
    """Queries device for process PID via pidof with ps fallback."""
    code, stdout, _ = run_adb_cmd(adb_bin, ["shell", "pidof", package_name], serial=serial)
    if code == 0 and stdout:
        tokens = stdout.split()
        for tok in tokens:
            if tok.isdigit():
                return int(tok)

    # Fallback to 'ps -A'
    pid_code = code
    code, ps_out, _ = run_adb_cmd(adb_bin, ["shell", "ps", "-A"], serial=serial)
    if code == 0 and ps_out:
        for line in ps_out.splitlines():
            if package_name in line:
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    return int(parts[1])

    if code != 0 and pid_code != 0:
        raise OSError('Process observation backend unavailable')
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
    pid: int | None,
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

    # Query logcat for this PID with bounded lines, or recent lines if pid is None
    logcat_args = ["shell", "logcat", "-d"]
    if pid is not None:
        logcat_args.append(f"--pid={pid}")
    logcat_args.extend(["-t", "300"])

    code, stdout, _ = run_adb_cmd(
        adb_bin,
        logcat_args,
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
