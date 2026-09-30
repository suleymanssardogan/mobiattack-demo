"""Baseline network connectivity and readiness check module."""

from __future__ import annotations

from typing import Tuple

from src.dynamic.preflight.device_check import run_adb_cmd
from src.dynamic.preflight.models import ErrorCode, NetworkInfo


def check_network_readiness(
    adb_bin: str,
    serial: str,
    timeout_seconds: float = 4.0,
) -> Tuple[NetworkInfo, ErrorCode | None, str | None]:
    """Checks baseline network and DNS availability on target device."""
    net_info = NetworkInfo()

    # 1. Check IP connectivity (ICMP ping to 8.8.8.8 or 1.1.1.1)
    code_ip, stdout_ip, _ = run_adb_cmd(
        adb_bin,
        ["shell", "ping", "-c", "1", "-W", "2", "8.8.8.8"],
        serial=serial,
        timeout_seconds=timeout_seconds,
    )
    ip_reachable = (code_ip == 0 and ("1 packets transmitted, 1 received" in stdout_ip or "1 packets received" in stdout_ip or "bytes from" in stdout_ip))

    # 2. Check DNS connectivity (ping domain)
    code_dns, stdout_dns, _ = run_adb_cmd(
        adb_bin,
        ["shell", "ping", "-c", "1", "-W", "2", "google.com"],
        serial=serial,
        timeout_seconds=timeout_seconds,
    )
    dns_reachable = (code_dns == 0 and ("1 packets transmitted, 1 received" in stdout_dns or "1 packets received" in stdout_dns or "bytes from" in stdout_dns))

    # 3. Fallback: query 'dumpsys connectivity' or system DNS properties if ping is blocked by SElinux
    if not ip_reachable and not dns_reachable:
        code_dns_prop, dns_prop, _ = run_adb_cmd(
            adb_bin, ["shell", "getprop", "net.dns1"], serial=serial
        )
        has_dns_prop = (code_dns_prop == 0 and bool(dns_prop.strip()))

        code_conn, conn_out, _ = run_adb_cmd(
            adb_bin, ["shell", "dumpsys", "connectivity"], serial=serial
        )
        has_active_network = (code_conn == 0 and "state: CONNECTED/CONNECTED" in conn_out)

        if has_active_network or has_dns_prop:
            net_info.internet_reachable = True
            net_info.dns_configured = has_dns_prop
            net_info.details = "Active connection detected via dumpsys connectivity."
            return net_info, None, None

    net_info.internet_reachable = (ip_reachable or dns_reachable)
    net_info.dns_configured = dns_reachable

    if not net_info.internet_reachable:
        net_info.details = "No route to internet (ICMP and DNS probes failed)."
        return (
            net_info,
            ErrorCode.NETWORK_UNAVAILABLE,
            "Target device has no verified internet connectivity.",
        )

    net_info.details = "Internet and DNS probes verified reachable."
    return net_info, None, None
