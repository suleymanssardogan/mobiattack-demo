"""Data models and standardized schema for Dynamic Preflight / Runtime Readiness."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class PreflightStatus(str, Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class ErrorCode(str, Enum):
    MULTIPLE_DEVICES = "MULTIPLE_DEVICES"
    PROCESS_EXITED = 'PROCESS_EXITED'
    RUNTIME_OBSERVATION_UNAVAILABLE = 'RUNTIME_OBSERVATION_UNAVAILABLE'
    INSTALL_FAILED = 'INSTALL_FAILED'
    INSTALL_INCOMPATIBLE = 'INSTALL_INCOMPATIBLE'
    ABI_UNSUPPORTED = 'ABI_UNSUPPORTED'
    DEVICE_FEATURE_UNAVAILABLE = 'DEVICE_FEATURE_UNAVAILABLE'
    INTEGRITY_ENVIRONMENT_REJECTED = 'INTEGRITY_ENVIRONMENT_REJECTED'
    ADB_NOT_FOUND = "ADB_NOT_FOUND"
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    DEVICE_UNAUTHORIZED = "DEVICE_UNAUTHORIZED"
    DEVICE_OFFLINE = "DEVICE_OFFLINE"
    PACKAGE_NOT_FOUND = "PACKAGE_NOT_FOUND"
    APP_NOT_INSTALLED = "APP_NOT_INSTALLED"
    APP_LAUNCH_FAILED = "APP_LAUNCH_FAILED"
    LAUNCHER_UNRESOLVED = "LAUNCHER_UNRESOLVED"
    APP_CRASHED = "APP_CRASHED"
    NETWORK_UNAVAILABLE = "NETWORK_UNAVAILABLE"
    COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
    SPLIT_APK_DETECTED = "SPLIT_APK_DETECTED"
    INTENT_FILTER_MISMATCH = "INTENT_FILTER_MISMATCH"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


@dataclass
class DeviceInfo:
    connected: bool = False
    serial: str | None = None
    state: str = "not_found"  # "device", "unauthorized", "offline", "not_found"
    is_emulator: bool = False
    root_detected: bool = False
    root_signals: list[str] = field(default_factory=list)


@dataclass
class ApplicationInfo:
    package_name: str = ""
    installed: bool = False
    launchable: bool = False
    main_activity: str | None = None
    process_running: bool = False
    foreground: bool = False
    version_name: str | None = None
    version_code: int | None = None
    target_sdk: int | None = None
    install_path: str | None = None
    granted_permissions: list[str] = field(default_factory=list)
    requested_permissions: list[str] = field(default_factory=list)


@dataclass
class RuntimeBaseline:
    launch_success: bool = False
    immediate_crash: bool = False
    fatal_log_detected: bool = False
    pid: int | None = None
    fatal_log_snippets: list[str] = field(default_factory=list)
    launch_attempts: int = 1
    ready_after_attempt: int | None = None


@dataclass
class NetworkInfo:
    internet_reachable: bool = False
    dns_configured: bool = False
    details: str | None = None


@dataclass
class PreflightResult:
    stage: str = "dynamic_preflight"
    device: DeviceInfo = field(default_factory=DeviceInfo)
    application: ApplicationInfo = field(default_factory=ApplicationInfo)
    runtime: RuntimeBaseline = field(default_factory=RuntimeBaseline)
    network: NetworkInfo = field(default_factory=NetworkInfo)
    status: PreflightStatus = PreflightStatus.FAIL
    execution_target: dict | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Converts result into normalized JSON-serializable dictionary."""
        return {
            **({"execution_target": self.execution_target} if self.execution_target is not None else {}),
            "stage": self.stage,
            "device": {
                "connected": self.device.connected,
                "serial": self.device.serial,
                "state": self.device.state,
                "is_emulator": self.device.is_emulator,
                "root_detected": self.device.root_detected,
                "root_signals": self.device.root_signals,
            },
            "application": {
                "package_name": self.application.package_name,
                "installed": self.application.installed,
                "launchable": self.application.launchable,
                "main_activity": self.application.main_activity,
                "process_running": self.application.process_running,
                "foreground": self.application.foreground,
                "version_name": self.application.version_name,
                "version_code": self.application.version_code,
                "target_sdk": self.application.target_sdk,
                "install_path": self.application.install_path,
                "granted_permissions_count": len(self.application.granted_permissions),
                "requested_permissions_count": len(self.application.requested_permissions),
            },
            "runtime": {
                "launch_success": self.runtime.launch_success,
                "immediate_crash": self.runtime.immediate_crash,
                "fatal_log_detected": self.runtime.fatal_log_detected,
                "pid": self.runtime.pid,
                "launch_attempts": self.runtime.launch_attempts,
                "ready_after_attempt": self.runtime.ready_after_attempt,
            },
            "network": {
                "internet_reachable": self.network.internet_reachable,
                "dns_configured": self.network.dns_configured,
            },
            "status": self.status.value,
            "warnings": self.warnings,
            "errors": self.errors,
        }
