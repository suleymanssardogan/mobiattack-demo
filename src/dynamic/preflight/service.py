"""Dynamic Preflight and Runtime Readiness orchestrator service."""

from __future__ import annotations

import logging
from typing import Any

from src.dynamic.preflight.app_launcher import launch_application
from src.dynamic.preflight.device_check import check_connected_device, find_adb_binary
from src.dynamic.preflight.models import (
    ApplicationInfo,
    DeviceInfo,
    ErrorCode,
    NetworkInfo,
    PreflightResult,
    PreflightStatus,
    RuntimeBaseline,
)
from src.dynamic.preflight.network_check import check_network_readiness
from src.dynamic.preflight.package_inspector import inspect_package, install_apk_on_device
from src.dynamic.preflight.runtime_health import check_runtime_health

logger = logging.getLogger(__name__)


class DynamicPreflightService:
    """Service to coordinate preflight checks before and immediately after app execution."""

    def __init__(self, adb_bin: str | None = None) -> None:
        self.adb_bin = find_adb_binary(adb_bin)

    def run_preflight(
        self,
        package_name: str,
        apk_path: str | None = None,
        target_serial: str | None = None,
        activity_name: str | None = None,
        auto_install: bool = True,
        is_split_apk: bool = False,
    ) -> PreflightResult:
        """Executes the full dynamic preflight suite and produces normalized results."""
        result = PreflightResult()
        warnings: list[str] = []
        errors: list[dict[str, str]] = []

        # 1. ADB Binary check
        if not self.adb_bin:
            errors.append({
                "code": ErrorCode.ADB_NOT_FOUND.value,
                "message": "ADB executable not found in PATH or standard Android SDK directories.",
            })
            result.status = PreflightStatus.FAIL
            result.errors = errors
            return result

        # 2. Device Connectivity Check
        dev_info, dev_err_code, dev_err_msg = check_connected_device(
            self.adb_bin, target_serial=target_serial
        )
        result.device = dev_info

        if dev_err_code is not None:
            errors.append({
                "code": dev_err_code.value,
                "message": dev_err_msg or "Device connectivity check failed",
            })
            result.status = PreflightStatus.FAIL
            result.errors = errors
            return result

        serial = dev_info.serial or ""

        # Flag environment characteristics
        if dev_info.is_emulator:
            warnings.append("Android Emulator environment detected.")
        if dev_info.root_detected:
            signals_desc = "; ".join(dev_info.root_signals)
            warnings.append(f"Root / Superuser environment detected ({signals_desc}).")

        # 3. Split APK check
        if is_split_apk:
            warnings.append(
                "Split APK detected: Dynamic preflight validates the base APK package; dynamic multi-split delivery is not fully supported."
            )

        # 4. Package Inspection & Installation Check
        app_info, pkg_err_code, pkg_err_msg = inspect_package(
            self.adb_bin, serial, package_name
        )
        result.application = app_info

        if pkg_err_code == ErrorCode.APP_NOT_INSTALLED:
            if auto_install and apk_path:
                logger.info(f"Package '{package_name}' not installed. Attempting installation from {apk_path}...")
                installed, inst_err, inst_msg = install_apk_on_device(
                    self.adb_bin, serial, apk_path
                )
                if not installed:
                    errors.append({
                        "code": (inst_err or ErrorCode.APP_LAUNCH_FAILED).value,
                        "message": inst_msg or "Failed to auto-install APK on target device",
                    })
                    result.status = PreflightStatus.FAIL
                    result.warnings = warnings
                    result.errors = errors
                    return result

                # Re-inspect metadata post-install
                app_info, _, _ = inspect_package(self.adb_bin, serial, package_name)
                result.application = app_info
            else:
                errors.append({
                    "code": ErrorCode.APP_NOT_INSTALLED.value,
                    "message": pkg_err_msg or f"Package '{package_name}' is not installed",
                })
                result.status = PreflightStatus.FAIL
                result.warnings = warnings
                result.errors = errors
                return result
        elif pkg_err_code is not None:
            errors.append({
                "code": pkg_err_code.value,
                "message": pkg_err_msg or "Package inspection error",
            })
            result.status = PreflightStatus.FAIL
            result.warnings = warnings
            result.errors = errors
            return result

        # 5. Baseline Network Readiness Check
        net_info, net_err_code, net_err_msg = check_network_readiness(self.adb_bin, serial)
        result.network = net_info
        if net_err_code is not None:
            warnings.append(f"Network unavailable: {net_err_msg}")

        # 6. App Launchability Check
        launched, launched_activity, launch_err_code, launch_err_msg = launch_application(
            self.adb_bin,
            serial,
            package_name,
            activity_name=activity_name or app_info.main_activity,
        )
        app_info.launchable = launched
        app_info.main_activity = launched_activity

        if launch_err_code is not None or not launched:
            errors.append({
                "code": (launch_err_code or ErrorCode.APP_LAUNCH_FAILED).value,
                "message": launch_err_msg or f"Failed to launch application '{package_name}'",
            })
            result.status = PreflightStatus.FAIL
            result.warnings = warnings
            result.errors = errors
            return result

        # 7. Runtime Baseline Health Check
        baseline, is_foreground, health_err_code, health_err_msg = check_runtime_health(
            self.adb_bin, serial, package_name
        )
        result.runtime = baseline
        app_info.process_running = (baseline.pid is not None)
        app_info.foreground = is_foreground

        if health_err_code is not None or baseline.immediate_crash:
            errors.append({
                "code": (health_err_code or ErrorCode.APP_CRASHED).value,
                "message": health_err_msg or f"Application '{package_name}' crashed immediately after launch.",
            })
            result.status = PreflightStatus.FAIL
            result.warnings = warnings
            result.errors = errors
            return result

        # 8. Compute Final Preflight Status
        if errors:
            result.status = PreflightStatus.FAIL
        elif warnings:
            result.status = PreflightStatus.WARN
        else:
            result.status = PreflightStatus.PASS

        result.warnings = warnings
        result.errors = errors
        return result


def run_dynamic_preflight(
    package_name: str,
    apk_path: str | None = None,
    target_serial: str | None = None,
    activity_name: str | None = None,
    auto_install: bool = True,
    is_split_apk: bool = False,
    adb_bin: str | None = None,
) -> dict[str, Any]:
    """Convenience functional wrapper returning the standardized dictionary."""
    service = DynamicPreflightService(adb_bin=adb_bin)
    result = service.run_preflight(
        package_name=package_name,
        apk_path=apk_path,
        target_serial=target_serial,
        activity_name=activity_name,
        auto_install=auto_install,
        is_split_apk=is_split_apk,
    )
    return result.to_dict()
