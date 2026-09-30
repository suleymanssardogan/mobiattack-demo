"""Mitmproxy capture backend managing child process lifecycle and flow stream."""

from __future__ import annotations

import logging
import os
import shutil
import signal
import socket
import subprocess
import time
from typing import Any, Callable

from src.dynamic.traffic.models import (
    TrafficErrorCode,
    TrafficException,
    TrafficTransaction,
)
from src.dynamic.traffic.normalizer import normalize_http_transaction

logger = logging.getLogger(__name__)


def find_mitmproxy_binary(custom_path: str | None = None) -> str | None:
    """Finds mitmdump or mitmproxy executable from custom path or PATH."""
    if custom_path and os.path.isfile(custom_path) and os.access(custom_path, os.X_OK):
        return custom_path

    env_bin = os.getenv("MITMPROXY_PATH") or os.getenv("MITMDUMP_PATH")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin

    which_dump = shutil.which("mitmdump")
    if which_dump:
        return which_dump

    which_proxy = shutil.which("mitmproxy")
    if which_proxy:
        return which_proxy

    # Common macOS Homebrew and Linux paths
    candidates = [
        "/opt/homebrew/bin/mitmdump",
        "/usr/local/bin/mitmdump",
        "/usr/bin/mitmdump",
        "/opt/homebrew/bin/mitmproxy",
        "/usr/local/bin/mitmproxy",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c

    return None


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Checks whether the specified port is already bound on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


class MitmproxyCaptureBackend:
    """Controls mitmdump process lifecycle, addon script, and stream ingestion."""

    def __init__(self, executable_path: str | None = None) -> None:
        self.executable_path = find_mitmproxy_binary(executable_path)
        self.process: subprocess.Popen[str] | None = None
        self.captured_transactions: list[TrafficTransaction] = []
        self._on_transaction: Callable[[TrafficTransaction], None] | None = None
        self.listen_host: str = "127.0.0.1"
        self.listen_port: int = 8080

    def check_available(self) -> bool:
        """Returns True if mitmdump/mitmproxy executable is detected on system."""
        return self.executable_path is not None

    def start(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8080,
        on_transaction_captured: Callable[[TrafficTransaction], None] | None = None,
        script_path: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        """Starts mitmdump as a background child process with graceful failure checks."""
        if not self.check_available():
            raise TrafficException(
                TrafficErrorCode.MITMPROXY_NOT_FOUND,
                "mitmdump/mitmproxy executable not found in PATH or standard installation paths.",
            )

        if is_port_in_use(listen_port):
            raise TrafficException(
                TrafficErrorCode.PROXY_PORT_IN_USE,
                f"Proxy port {listen_port} is already in use by another process.",
            )

        self.listen_host = listen_host
        self.listen_port = listen_port
        self._on_transaction = on_transaction_captured
        self.captured_transactions = []

        cmd = [
            self.executable_path,  # type: ignore[list-item]
            "--listen-host",
            listen_host,
            "-p",
            str(listen_port),
            "--set",
            "flow_detail=1",
            "--set",
            "ssl_insecure=true",
        ]
        if script_path and os.path.isfile(script_path):
            cmd.extend(["-s", script_path])

        logger.info(f"Starting mitmproxy: {' '.join(cmd)}")
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )
        except Exception as exc:
            raise TrafficException(
                TrafficErrorCode.CAPTURE_START_FAILED,
                f"Failed to launch mitmproxy process: {exc}",
            ) from exc

        # Wait shortly to verify process did not crash immediately
        time.sleep(0.6)
        if self.process.poll() is not None:
            _, stderr = self.process.communicate()
            raise TrafficException(
                TrafficErrorCode.CAPTURE_PROCESS_DIED,
                f"mitmproxy exited immediately with code {self.process.returncode}: {stderr.strip()}",
            )

    def stop(self, timeout_seconds: float = 4.0) -> None:
        """Terminates mitmproxy process gracefully with SIGTERM, then SIGKILL fallback."""
        if not self.process:
            return

        logger.info(f"Stopping mitmproxy process (PID: {self.process.pid})")
        try:
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                except Exception:
                    self.process.terminate()
            else:
                self.process.terminate()

            self.process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            logger.warning("mitmproxy did not exit within timeout, killing forcibly...")
            if hasattr(os, "killpg") and hasattr(os, "getpgid"):
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except Exception:
                    self.process.kill()
            else:
                self.process.kill()
            self.process.wait()
        except Exception as exc:
            logger.error(f"Error terminating mitmproxy process: {exc}")
        finally:
            self.process = None

    def is_alive(self) -> bool:
        """Returns True if the child process is alive and running."""
        if not self.process:
            return False
        return self.process.poll() is None

    def ingest_raw_flow(
        self,
        raw_req: dict[str, Any],
        raw_resp: dict[str, Any] | None,
        capture_id: str,
        duration_ms: float = 0.0,
    ) -> TrafficTransaction:
        """Ingests a raw request/response pair into normalized transaction."""
        transaction = normalize_http_transaction(
            raw_req=raw_req,
            raw_resp=raw_resp,
            capture_id=capture_id,
            duration_ms=duration_ms,
        )
        self.captured_transactions.append(transaction)
        if self._on_transaction:
            self._on_transaction(transaction)
        return transaction

    def get_captured_transactions(self) -> list[TrafficTransaction]:
        return list(self.captured_transactions)
