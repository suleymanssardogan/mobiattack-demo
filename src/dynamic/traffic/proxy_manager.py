"""Device global proxy lifecycle manager with guaranteed restore on stop/failure."""

from __future__ import annotations

import logging
from typing import Any

from src.dynamic.preflight.device_check import run_adb_cmd
from src.dynamic.traffic.models import TrafficErrorCode, TrafficException

logger = logging.getLogger(__name__)


class DeviceProxyManager:
    """Manages Android system-wide HTTP proxy configuration with guaranteed rollback.

    Usage:
        proxy_mgr = DeviceProxyManager(adb_bin, serial, proxy_host="10.0.2.2", proxy_port=8080)
        with proxy_mgr:
            # Proxy is set on device
            ...
        # Previous proxy is guaranteed restored here, even if an exception occurred.
    """

    def __init__(
        self,
        adb_bin: str,
        serial: str,
        proxy_host: str = "10.0.2.2",
        proxy_port: int = 8080,
    ) -> None:
        self.adb_bin = adb_bin
        self.serial = serial
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.previous_proxy: str | None = None
        self.configured: bool = False

    def get_current_proxy(self) -> str | None:
        """Reads current global HTTP proxy from Android device settings."""
        code, stdout, stderr = run_adb_cmd(
            self.adb_bin,
            ["shell", "settings", "get", "global", "http_proxy"],
            serial=self.serial,
        )
        if code != 0:
            logger.warning(f"Could not read current http_proxy on {self.serial}: {stderr}")
            return None

        val = stdout.strip()
        # Android returns ':0' or 'null' when no proxy is configured
        if not val or val in ("null", ":0"):
            return None
        return val

    def apply_proxy(self) -> None:
        """Backs up existing proxy and applies target host:port."""
        self.previous_proxy = self.get_current_proxy()
        target_value = f"{self.proxy_host}:{self.proxy_port}"

        logger.info(
            f"Configuring proxy on {self.serial} -> {target_value} (backup: {self.previous_proxy or 'none'})"
        )
        code, _, stderr = run_adb_cmd(
            self.adb_bin,
            ["shell", "settings", "put", "global", "http_proxy", target_value],
            serial=self.serial,
        )
        if code != 0:
            raise TrafficException(
                TrafficErrorCode.PROXY_CONFIGURATION_FAILED,
                f"Failed to set global http_proxy to {target_value}: {stderr}",
            )

        self.configured = True

    def restore_proxy(self) -> bool:
        """Restores previous proxy setting (or removes proxy if previously none)."""
        logger.info(f"Restoring proxy on {self.serial} -> {self.previous_proxy or 'cleared'}")
        if self.previous_proxy:
            code, _, stderr = run_adb_cmd(
                self.adb_bin,
                ["shell", "settings", "put", "global", "http_proxy", self.previous_proxy],
                serial=self.serial,
            )
        else:
            # Clear proxy
            code, _, stderr = run_adb_cmd(
                self.adb_bin,
                ["shell", "settings", "put", "global", "http_proxy", ":0"],
                serial=self.serial,
            )

        self.configured = False
        if code != 0:
            logger.error(f"Failed to restore http_proxy on {self.serial}: {stderr}")
            return False
        return True

    def __enter__(self) -> DeviceProxyManager:
        self.apply_proxy()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            self.restore_proxy()
        except Exception as e:
            logger.error(f"Exception during proxy restore on {self.serial}: {e}")
