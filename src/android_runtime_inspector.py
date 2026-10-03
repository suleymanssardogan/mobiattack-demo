"""Live Android Runtime Inspection Module for MobiAttack-v2.

Performs deterministic runtime security audits on connected Android devices/emulators:
1. Live Process Memory Footprint (via 'dumpsys meminfo <pkg>')
2. Live Logcat Sensitive Data Leakage Audit (via 'logcat -d --pid=<pid>')
   mapped to OWASP M2 (Insecure Data Storage) and CWE-532 (Information Exposure Through Log Files).
"""

from __future__ import annotations
from src.dynamic.deadline import bounded_timeout

import re
import subprocess
from typing import Any


# Regex patterns to detect sensitive leaks in logcat
LEAK_PATTERNS = [
    (
        "auth_token",
        re.compile(r"Bearer\s+([a-zA-Z0-9_\-\.]{15,})", re.IGNORECASE),
        "high",
        "Bearer token / authorization header logged in plaintext",
    ),
    (
        "credential",
        re.compile(
            r"(?i)\b(password|passwd|secret|api_key|apikey|private_key)\s*[:=]\s*['\"]?([^\s'\"]{4,})",
            re.IGNORECASE,
        ),
        "high",
        "Credential or secret variable logged in plaintext",
    ),
    (
        "auth_url",
        re.compile(
            r"https?://[^\s]*[?&](token|secret|password|api_key)=([^\s&]+)",
            re.IGNORECASE,
        ),
        "high",
        "Sensitive query parameter in URL logged in plaintext",
    ),
    (
        "unhandled_exception",
        re.compile(
            r"(?i)\b(FATAL EXCEPTION|NullPointerException|ArrayIndexOutOfBoundsException|ANR in)\b"
        ),
        "medium",
        "Unhandled application exception or ANR recorded in logcat",
    ),
]


def _mask_secret(val: str) -> str:
    """Masks secret values for safe evidence display."""
    if len(val) <= 4:
        return "****"
    return val[:2] + "****" + val[-2:]


def parse_meminfo_output(raw_output: str) -> dict[str, Any]:
    """Parses 'dumpsys meminfo' output for key process memory indicators."""
    total_pss_kb = 0
    native_heap_kb = 0
    dalvik_heap_kb = 0

    for line in raw_output.splitlines():
        # Match TOTAL line
        m_tot = re.match(r"^\s*TOTAL\s+(\d+)", line)
        if m_tot:
            try:
                total_pss_kb = int(m_tot.group(1))
            except ValueError:
                pass
            continue

        # Match Native Heap
        m_nat = re.match(r"^\s*Native Heap\s+(\d+)", line)
        if m_nat:
            try:
                native_heap_kb = int(m_nat.group(1))
            except ValueError:
                pass
            continue

        # Match Dalvik Heap
        m_dal = re.match(r"^\s*Dalvik Heap\s+(\d+)", line)
        if m_dal:
            try:
                dalvik_heap_kb = int(m_dal.group(1))
            except ValueError:
                pass
            continue

    total_pss_mb = round(total_pss_kb / 1024.0, 2)
    return {
        "total_pss_kb": total_pss_kb,
        "total_pss_mb": total_pss_mb,
        "native_heap_kb": native_heap_kb,
        "dalvik_heap_kb": dalvik_heap_kb,
        "status": "measured" if total_pss_kb > 0 else "unavailable",
    }


def parse_logcat_lines(lines: list[str]) -> dict[str, Any]:
    """Audits logcat lines for sensitive data exposure (CWE-532)."""
    leak_findings: list[dict[str, Any]] = []

    for idx, line in enumerate(lines, 1):
        clean_line = line.strip()
        if not clean_line or clean_line.startswith("--------- beginning of"):
            continue

        for p_type, pattern, severity, desc in LEAK_PATTERNS:
            match = pattern.search(clean_line)
            if match:
                # Mask matched secret groups if present
                safe_evidence = clean_line
                if match.groups():
                    for g in match.groups():
                        if g and len(g) > 2:
                            safe_evidence = safe_evidence.replace(g, _mask_secret(g))

                leak_findings.append({
                    "pattern_type": p_type,
                    "line_number": idx,
                    "severity": severity,
                    "evidence": safe_evidence[:160],
                    "message": desc,
                })
                break  # match once per line

    return {
        "lines_captured": len(lines),
        "has_leak_warnings": len(leak_findings) > 0,
        "leak_count": len(leak_findings),
        "leak_findings": leak_findings,
        "sample_lines": [l.strip() for l in lines[-10:] if l.strip()],
    }


def inspect_runtime_process(
    adb_bin: str,
    serial: str,
    package_name: str,
    pid: int,
    timeout_seconds: float = 8.0,
) -> dict[str, Any]:
    """Inspects live process memory and logcat for a verified running Android package.

    Args:
        adb_bin: Path to adb executable.
        serial: Target device serial.
        package_name: Target application package name.
        pid: Active Process ID.
        timeout_seconds: Timeout ceiling for ADB inspection queries.

    Returns:
        Structured runtime inspection dictionary with memory and logcat audits.
    """
    # 1. Process Memory Footprint
    mem_result: dict[str, Any] = {
        "total_pss_kb": 0,
        "total_pss_mb": 0.0,
        "native_heap_kb": 0,
        "dalvik_heap_kb": 0,
        "status": "unavailable",
    }
    try:
        mem_cmd = [adb_bin, "-s", serial, "shell", f"dumpsys meminfo {package_name}"]
        proc = subprocess.run(
            mem_cmd,
            capture_output=True,
            text=True,
            timeout=bounded_timeout(timeout_seconds),
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            mem_result = parse_meminfo_output(proc.stdout)
    except Exception as exc:
        mem_result["error"] = str(exc)

    # 2. Live Logcat Leak Audit
    logcat_result: dict[str, Any] = {
        "lines_captured": 0,
        "has_leak_warnings": False,
        "leak_count": 0,
        "leak_findings": [],
        "sample_lines": [],
    }
    try:
        # Bounded logcat capture filtered by PID
        log_cmd = [adb_bin, "-s", serial, "logcat", "-d", f"--pid={pid}", "-v", "time"]
        proc_log = subprocess.run(
            log_cmd,
            capture_output=True,
            text=True,
            timeout=bounded_timeout(timeout_seconds),
            check=False,
        )
        if proc_log.returncode == 0 and proc_log.stdout:
            raw_lines = proc_log.stdout.splitlines()[-250:]  # keep latest 250 lines
            logcat_result = parse_logcat_lines(raw_lines)
    except Exception as exc:
        logcat_result["error"] = str(exc)

    return {
        "memory_footprint": mem_result,
        "logcat_audit": logcat_result,
    }
