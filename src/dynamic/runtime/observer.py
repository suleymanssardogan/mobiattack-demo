"""Android Runtime Observation Primitive V1 (Week 2 — Day 6 Task 6.1).

Non-intrusive, side-effect-free observation of Android process health,
foreground activity, and bounded logcat crash/fatal signatures.
"""

from __future__ import annotations

import logging
from pathlib import Path
import re
import subprocess
import time
from typing import Any, Callable

from src.android_runtime_launcher import (
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    get_current_activity,
    resolve_adb_executable,
)
from src.dynamic.preflight.runtime_health import _find_process_pid
from src.dynamic.runtime.models import (
    LogEventKind,
    RuntimeLogEvent,
    RuntimeSnapshot,
    sanitize_log_message,
    utc_now_iso,
)

logger = logging.getLogger(__name__)

DEFAULT_OBSERVE_TIMEOUT_SECONDS: float = 5.0
DEFAULT_MAX_LOG_LINES: int = 250
DEFAULT_MAX_LOG_EVENTS: int = 100

# High-confidence fatal exception signatures
FATAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"FATAL EXCEPTION", re.IGNORECASE),
    re.compile(r"AndroidRuntime:\s+Shutting down VM", re.IGNORECASE),
    re.compile(r"Fatal signal\s+\d+", re.IGNORECASE),
    re.compile(r"\bSIGSEGV\b|\bSIGABRT\b|\bSIGBUS\b|\bSIGFPE\b", re.IGNORECASE),
    re.compile(r"Force finishing activity", re.IGNORECASE),
]

# Crash and process death signatures
CRASH_PATTERNS: list[re.Pattern] = [
    re.compile(r"Process\s+.*has died", re.IGNORECASE),
    re.compile(r"\bANR in\s+", re.IGNORECASE),
    re.compile(r"\bcrash\b|\btombstone\b", re.IGNORECASE),
]

# Standard logcat -v time and -v threadtime patterns
LOGCAT_TIME_RE = re.compile(
    r"^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+([VDIWEF])/([^\(:]+)(?:\(\s*(\d+)\))?:\s*(.*)$"
)
LOGCAT_THREADTIME_RE = re.compile(
    r"^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+([^:]+):\s*(.*)$"
)


_LOGCAT_DATE_TIME_RE = re.compile(
    r"^(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$"
)


def _parse_timestamp_parts(ts: str | None) -> tuple[int, int, int, int, int, int] | None:
    """Extracts (month, day, hour, minute, second, millisecond) from ISO or logcat timestamps.

    Returns None if unparseable or invalid.
    """
    if not ts:
        return None
    clean = str(ts).strip()
    if not clean:
        return None

    # Case A: ISO timestamp (YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD HH:MM:SS)
    if "T" in clean or ("-" in clean and len(clean.split("-")[0]) == 4):
        try:
            iso_str = clean.replace(" ", "T", 1) if "T" not in clean else clean
            date_part, time_part = iso_str.split("T", 1)
            d_tokens = date_part.split("-")
            if len(d_tokens) >= 3:
                month = int(d_tokens[1])
                day = int(d_tokens[2])
            else:
                return None
            # Clean timezone suffix
            clean_time = time_part.split("+")[0].split("-")[0].rstrip("Z")
            if "." in clean_time:
                t_base, t_ms = clean_time.split(".", 1)
                ms = int((t_ms + "000")[:3])
            else:
                t_base = clean_time
                ms = 0
            t_tokens = t_base.split(":")
            hour = int(t_tokens[0])
            minute = int(t_tokens[1])
            second = int(t_tokens[2])
            return (month, day, hour, minute, second, ms)
        except Exception:
            return None

    # Case B: Logcat timestamp 'MM-DD HH:MM:SS[.mmm]'
    m = _LOGCAT_DATE_TIME_RE.match(clean)
    if m:
        try:
            ms = int((m.group(6) + "000")[:3]) if m.group(6) else 0
            return (
                int(m.group(1)),
                int(m.group(2)),
                int(m.group(3)),
                int(m.group(4)),
                int(m.group(5)),
                ms,
            )
        except Exception:
            return None

    return None


def is_timestamp_at_or_after(log_ts: str | None, since_ts: str | None) -> bool:
    """Checks if logcat timestamp is >= since_timestamp.

    Fails conservatively (returns True) if either timestamp is None or unparseable.
    Handles year boundary rollover (Dec -> Jan).
    """
    if not since_ts or not log_ts:
        return True
    since_parts = _parse_timestamp_parts(since_ts)
    log_parts = _parse_timestamp_parts(log_ts)
    if since_parts is None or log_parts is None:
        # Conservative fallback: keep log line
        return True

    # Year boundary rollover handling (Dec -> Jan)
    # If since is Jan (month 1) and log is Dec (month 12), the log is from the previous year
    if since_parts[0] == 1 and log_parts[0] == 12:
        return False
    # If since is Dec (month 12) and log is Jan (month 1), the log is from the next year
    if since_parts[0] == 12 and log_parts[0] == 1:
        return True

    return log_parts >= since_parts


def determine_log_attribution(
    raw_line: str,
    raw_message: str,
    is_pid_scoped: bool,
    target_package: str,
    target_pid: int | None = None,
    context_package: str | None = None,
) -> tuple[bool, str, str]:
    """Determines attribution for a log event.

    Returns:
        (target_attributed, attribution, attribution_reason)
    """
    if is_pid_scoped:
        return True, "target", "pid_scoped"

    clean_pkg = str(target_package).strip()

    # 1. Context package from multi-line lookahead (e.g. AndroidRuntime Process header)
    if context_package:
        if clean_pkg and context_package == clean_pkg:
            return True, "target", "context_package_marker"
        else:
            return False, "unknown", "foreign_package"

    # 2. Check for explicit foreign package markers
    # E.g. "Process com.other.app ... has died" or "ANR in com.other.app"
    m_proc = re.search(r"Process\s+([a-zA-Z0-9_\.]+)", raw_line)
    if m_proc and clean_pkg and m_proc.group(1) != clean_pkg:
        return False, "unknown", "foreign_package"
    m_anr = re.search(r"ANR in\s+([a-zA-Z0-9_\.]+)", raw_line)
    if m_anr and clean_pkg and m_anr.group(1) != clean_pkg:
        return False, "unknown", "foreign_package"
    m_force = re.search(r"Force finishing activity\s+([a-zA-Z0-9_\.]+)", raw_line)
    if m_force and clean_pkg and not m_force.group(1).startswith(clean_pkg):
        return False, "unknown", "foreign_package"

    # 3. Explicit target package in line or message
    if clean_pkg and (clean_pkg in raw_line or clean_pkg in raw_message):
        return True, "target", "explicit_package_marker"

    # 4. Target PID marker
    if target_pid is not None:
        pid_pats = [
            f"pid {target_pid}",
            f"pid={target_pid}",
            f"PID: {target_pid}",
            f"(pid {target_pid})",
            f"({target_pid})",
            f"( {target_pid})",
        ]
        if any(pat in raw_line for pat in pid_pats):
            return True, "target", "target_pid_marker"

    return False, "unknown", "unscoped_fallback"


def parse_logcat_line(
    line: str,
    is_pid_scoped: bool = False,
    target_package: str = "",
    target_pid: int | None = None,
    context_package: str | None = None,
) -> RuntimeLogEvent | None:
    """Parses a single logcat output line into a structured, sanitized, attributed RuntimeLogEvent."""
    clean = line.strip()
    if not clean or clean.startswith("--------- beginning of"):
        return None

    timestamp: str | None = None
    level = "I"
    tag = "unknown"
    raw_message = clean

    m_time = LOGCAT_TIME_RE.match(clean)
    if m_time:
        timestamp = m_time.group(1)
        level = m_time.group(2).upper()
        tag = m_time.group(3).strip()
        raw_message = m_time.group(5).strip()
    else:
        m_thread = LOGCAT_THREADTIME_RE.match(clean)
        if m_thread:
            timestamp = m_thread.group(1)
            level = m_thread.group(4).upper()
            tag = m_thread.group(5).strip()
            raw_message = m_thread.group(6).strip()

    # Determine kind
    is_fatal = any(pat.search(raw_message) for pat in FATAL_PATTERNS)
    is_crash = any(pat.search(raw_message) for pat in CRASH_PATTERNS)

    if is_fatal:
        kind = LogEventKind.FATAL.value
    elif is_crash:
        kind = LogEventKind.CRASH.value
    elif level in ("E", "F"):
        kind = LogEventKind.ERROR.value
    elif level == "W":
        kind = LogEventKind.WARNING.value
    else:
        kind = LogEventKind.INFO.value

    sanitized_msg = sanitize_log_message(raw_message)

    target_attributed, attribution, attribution_reason = determine_log_attribution(
        raw_line=clean,
        raw_message=raw_message,
        is_pid_scoped=is_pid_scoped,
        target_package=target_package,
        target_pid=target_pid,
        context_package=context_package,
    )

    return RuntimeLogEvent(
        timestamp=timestamp,
        level=level,
        tag=tag,
        message=sanitized_msg,
        kind=kind,
        target_attributed=target_attributed,
        attribution=attribution,
        attribution_reason=attribution_reason,
    )


class AndroidRuntimeObserver:
    """Deterministic, side-effect-free Android runtime state observer."""

    def __init__(
        self,
        serial: str = "",
        adb_bin: str | None = None,
        timeout_seconds: float = DEFAULT_OBSERVE_TIMEOUT_SECONDS,
        max_log_lines: int = DEFAULT_MAX_LOG_LINES,
        max_log_events: int = DEFAULT_MAX_LOG_EVENTS,
        subprocess_runner: Callable[..., subprocess.CompletedProcess] | None = None,
    ) -> None:
        self.serial = str(serial).strip()
        self.adb_bin = adb_bin
        self.timeout_seconds = max(0.5, float(timeout_seconds))
        self.max_log_lines = max_log_lines
        self.max_log_events = max_log_events
        self._runner = subprocess_runner or subprocess.run

    def _resolve_adb(self) -> str:
        """Resolves the ADB binary or falls back to 'adb'."""
        try:
            return resolve_adb_executable(self.adb_bin)
        except Exception:
            return self.adb_bin or "adb"

    def _query_pid(self, package_name: str, adb_bin: str, diagnostics: list[str]) -> int | None:
        """Queries process PID using existing _find_process_pid helper."""
        try:
            return _find_process_pid(adb_bin, self.serial, package_name)
        except (subprocess.TimeoutExpired, OSError) as exc:
            diagnostics.append(f"PID query failed: {exc}")
            return None
        except Exception as exc:
            diagnostics.append(f"PID query error: {exc}")
            return None

    def _query_foreground(
        self,
        package_name: str,
        adb_bin: str,
        diagnostics: list[str],
    ) -> tuple[str | None, str | None, bool]:
        """Queries foreground package and activity via existing get_current_activity helper."""
        try:
            act_info = get_current_activity(
                adb_serial=self.serial,
                adb_executable=adb_bin,
                timeout_seconds=self.timeout_seconds,
            )
            fg_pkg = act_info.get("observed_package")
            fg_act = act_info.get("observed_activity")
            is_fg = bool(fg_pkg and fg_pkg == package_name)
            return fg_pkg, fg_act, is_fg
        except (subprocess.TimeoutExpired, OSError) as exc:
            diagnostics.append(f"Foreground query failed: {exc}")
            return None, None, False
        except Exception as exc:
            diagnostics.append(f"Foreground query error: {exc}")
            return None, None, False

    def _collect_bounded_logs(
        self,
        adb_bin: str,
        pid: int | None,
        package_name: str,
        since_timestamp: str | None,
        diagnostics: list[str],
    ) -> tuple[list[RuntimeLogEvent], bool, bool]:
        """Captures bounded logcat window with PID filtering preference, attribution hardening, and fallback."""
        raw_output = ""
        is_pid_scoped = False

        # Step 1: Attempt PID-filtered logcat if PID is available
        if pid is not None:
            cmd = [adb_bin]
            if self.serial:
                cmd.extend(["-s", self.serial])
            cmd.extend(["logcat", "-d", f"--pid={pid}", "-v", "time", "-t", str(self.max_log_lines)])
            try:
                proc = self._runner(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout:
                    raw_output = proc.stdout
                    is_pid_scoped = True
                else:
                    diagnostics.append(
                        "Target PID logcat filtering returned non-zero; falling back to unfiltered window. "
                        "PID-scoped logcat unavailable; using attribution-filtered fallback."
                    )
            except subprocess.TimeoutExpired:
                diagnostics.append(f"PID-filtered logcat command timed out after {self.timeout_seconds}s")
                diagnostics.append("PID-scoped logcat unavailable; using attribution-filtered fallback.")
            except Exception as exc:
                diagnostics.append(f"PID-filtered logcat error: {exc}")
                diagnostics.append("PID-scoped logcat unavailable; using attribution-filtered fallback.")
        else:
            diagnostics.append("PID-scoped logcat unavailable; using attribution-filtered fallback.")

        # Step 2: Fallback to general windowed logcat if PID filtering was not attempted or returned empty
        if not raw_output:
            cmd_fallback = [adb_bin]
            if self.serial:
                cmd_fallback.extend(["-s", self.serial])
            cmd_fallback.extend(["logcat", "-d", "-v", "time", "-t", str(self.max_log_lines)])
            try:
                proc_fb = self._runner(
                    cmd_fallback,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                if proc_fb.returncode == 0 and proc_fb.stdout:
                    raw_output = proc_fb.stdout
            except subprocess.TimeoutExpired:
                diagnostics.append(f"Fallback logcat command timed out after {self.timeout_seconds}s")
            except Exception as exc:
                diagnostics.append(f"Fallback logcat query error: {exc}")

        if not raw_output:
            return [], False, False

        # Validate since_timestamp determinism
        if since_timestamp and _parse_timestamp_parts(since_timestamp) is None:
            diagnostics.append("Invalid or unparseable since_timestamp; retained bounded recent log window.")

        raw_lines = raw_output.splitlines()

        # Multi-line context lookahead for AndroidRuntime exception headers in global fallback
        context_packages: dict[int, str] = {}
        if not is_pid_scoped:
            for idx, line in enumerate(raw_lines):
                if "FATAL EXCEPTION" in line or "AndroidRuntime:" in line:
                    for offset in range(1, min(6, len(raw_lines) - idx)):
                        nxt = raw_lines[idx + offset]
                        m_proc = re.search(r"Process:\s*([a-zA-Z0-9_\.]+)", nxt)
                        if m_proc:
                            pkg_found = m_proc.group(1).strip()
                            for k in range(idx, idx + offset + 1):
                                context_packages[k] = pkg_found
                            break

        # Parse lines
        events: list[RuntimeLogEvent] = []

        for idx, line in enumerate(raw_lines):
            ctx_pkg = context_packages.get(idx)
            evt = parse_logcat_line(
                line,
                is_pid_scoped=is_pid_scoped,
                target_package=package_name,
                target_pid=pid,
                context_package=ctx_pkg,
            )
            if not evt:
                continue

            # Apply deterministic since_timestamp comparison
            if since_timestamp and evt.timestamp:
                if not is_timestamp_at_or_after(evt.timestamp, since_timestamp):
                    continue

            events.append(evt)

        # Cap retained events to preserve bounded memory/artifact footprint
        bounded_events = events[-self.max_log_events:]

        # Derive target-level flags ONLY from target-attributed events
        fatal_detected = any(e.kind == LogEventKind.FATAL.value and e.target_attributed for e in bounded_events)
        crash_detected = any(e.kind in (LogEventKind.FATAL.value, LogEventKind.CRASH.value) and e.target_attributed for e in bounded_events)

        return bounded_events, fatal_detected, crash_detected

    def observe(
        self,
        package_name: str,
        since_timestamp: str | None = None,
    ) -> RuntimeSnapshot:
        """Collects point-in-time runtime observation for the target application package.

        Pure observation: executes no UI actions, does not mutate RouteGraph or scan_state.
        """
        clean_pkg = str(package_name).strip()
        snapshot_time = utc_now_iso()
        diagnostics: list[str] = []
        adb_bin = self._resolve_adb()

        # 1. Query PID
        pid = self._query_pid(clean_pkg, adb_bin, diagnostics)
        process_running = (pid is not None)

        # 2. Query Foreground Activity
        fg_pkg, fg_act, is_fg = self._query_foreground(clean_pkg, adb_bin, diagnostics)

        # 3. Query Bounded Logcat Window
        log_events, fatal_detected, crash_detected = self._collect_bounded_logs(
            adb_bin=adb_bin,
            pid=pid,
            package_name=clean_pkg,
            since_timestamp=since_timestamp,
            diagnostics=diagnostics,
        )

        return RuntimeSnapshot(
            package_name=clean_pkg,
            timestamp=snapshot_time,
            pid=pid,
            process_running=process_running,
            foreground_package=fg_pkg,
            foreground_activity=fg_act,
            is_foreground=is_fg,
            fatal_detected=fatal_detected,
            crash_detected=crash_detected,
            log_events=log_events,
            diagnostics=diagnostics,
        )


def observe_runtime(
    package_name: str,
    adb_serial: str = "",
    adb_bin: str | None = None,
    since_timestamp: str | None = None,
    timeout_seconds: float = DEFAULT_OBSERVE_TIMEOUT_SECONDS,
    max_log_lines: int = DEFAULT_MAX_LOG_LINES,
) -> RuntimeSnapshot:
    """Convenience functional interface for AndroidRuntimeObserver."""
    observer = AndroidRuntimeObserver(
        serial=adb_serial,
        adb_bin=adb_bin,
        timeout_seconds=timeout_seconds,
        max_log_lines=max_log_lines,
    )
    return observer.observe(package_name=package_name, since_timestamp=since_timestamp)
