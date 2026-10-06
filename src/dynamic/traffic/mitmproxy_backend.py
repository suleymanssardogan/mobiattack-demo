"""Mitmproxy capture backend managing child process lifecycle and flow stream."""

from __future__ import annotations

import logging
import json
import threading
from pathlib import Path
import os
import shutil
import signal
import socket
import subprocess
import time
from src.dynamic.deadline import bounded_operation, current_deadline, bounded_timeout
from typing import Any, Callable

from src.dynamic.traffic.models import (
    HttpRequestModel, HttpResponseModel,
    TrafficErrorCode,
    TrafficException,
    TrafficTransaction,
)
from src.dynamic.traffic.normalizer import normalize_http_transaction

from src.dynamic.traffic.https_visibility import HttpsVisibility

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
        s.settimeout(bounded_timeout(0.5))
        return s.connect_ex((host, port)) == 0


class MitmproxyCaptureBackend:
    """Controls mitmdump process lifecycle, addon script, and stream ingestion."""

    def __init__(self, executable_path: str | None = None, ca_directory: str | Path | None = None) -> None:
        self.executable_path = find_mitmproxy_binary(executable_path)
        self.process: subprocess.Popen[str] | None = None
        self.captured_transactions: list[TrafficTransaction] = []
        self._on_transaction: Callable[[TrafficTransaction], None] | None = None
        self.listen_host: str = "127.0.0.1"
        self.listen_port: int = 8080
        self.ca_directory = Path(ca_directory) if ca_directory else Path.home() / '.mitmproxy'
        self.https = HttpsVisibility()
        self._bridge_ready = threading.Event()
        self._startup_ready = False
        self.cleanup_state = 'not_started'
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None

    def check_available(self) -> bool:
        """Returns True if mitmdump/mitmproxy executable is detected on system."""
        return self.executable_path is not None

    @bounded_operation(5.0, field="timeout_seconds")
    def start(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8080,
        on_transaction_captured: Callable[[TrafficTransaction], None] | None = None,
        script_path: str | None = None,
        session_id: str | None = None,
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
        self._bridge_ready.clear()
        self._startup_ready = False
        self.https = HttpsVisibility(ca_trust=self.https.ca_trust, ca_reason=self.https.ca_reason)

        cmd = [
            self.executable_path,  # type: ignore[list-item]
            "--listen-host",
            listen_host,
            "-p",
            str(listen_port),
            "--set",
            "flow_detail=0",
            "--set",
            "ssl_insecure=false",
            "--set", "confdir=" + str(self.ca_directory),
            "-s", str(Path(__file__).with_name('mitmproxy_addon.py')),
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
                env={**os.environ, 'MOBIATTACK_CAPTURE_SESSION': session_id or '', 'PYTHONPATH': str(Path(__file__).resolve().parents[3]) + os.pathsep + os.environ.get('PYTHONPATH', '')},
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )
        except Exception as exc:
            self.https.backend_failed = True
            raise TrafficException(
                TrafficErrorCode.CAPTURE_START_FAILED,
                f"Failed to launch mitmproxy process: {exc}",
            ) from exc

        # Process exit is an explicit startup failure.
        if self.process.poll() is not None:
            self.https.backend_failed = True
            _, stderr = self.process.communicate(timeout=bounded_timeout(timeout_seconds))
            raise TrafficException(
                TrafficErrorCode.CAPTURE_PROCESS_DIED,
                f"mitmproxy exited immediately with code {self.process.returncode}: {stderr.strip()}",
            )

        self._reader = threading.Thread(target=self._read_events, daemon=True)
        self._reader.start()
        self._stderr_reader = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_reader.start()
        try:
            ready = self._bridge_ready.wait(timeout=bounded_timeout(timeout_seconds))
            ready = ready and self._startup_ready and self.is_alive() and not self.https.backend_failed
        except subprocess.TimeoutExpired:
            ready = False
        if not ready:
            self.https.backend_failed = True
            self.stop()
            raise TrafficException(TrafficErrorCode.CAPTURE_START_FAILED, 'Sanitized capture bridge did not become ready.')

    def _drain_stderr(self) -> None:
        if self.process and self.process.stderr:
            for _ in self.process.stderr:
                pass  # Drain without retaining raw provider logs.

    def _read_events(self) -> None:
        if self.process and self.process.stdout:
            for line in self.process.stdout:
                self.process_event_line(line)
        self._bridge_ready.set()  # EOF wakes startup; startup_ready still distinguishes error/ready.

    def process_event_line(self, line: str) -> None:
        if not line.startswith('MOBIATTACK_EVIDENCE '):
            return
        try:
            record = json.loads(line[len('MOBIATTACK_EVIDENCE '):])
            if record.get('event') == 'ready':
                self._startup_ready = True
                self._bridge_ready.set()
            elif record.get('event') == 'tls_failure':
                self.https.tls_failures += 1
            elif record.get('event') == 'transaction':
                from src.dynamic.traffic.normalizer import sanitize_transaction_data
                data = sanitize_transaction_data(record['transaction'])
                req = HttpRequestModel(**data.pop('request'))
                resp = HttpResponseModel(**data.pop('response')) if data.get('response') else None
                data.pop('response', None)
                transaction = TrafficTransaction(request=req, response=resp, **data)
                self._record_transaction(transaction, verified=True)
        except (ValueError, TypeError, KeyError, AttributeError, TrafficException):
            self.https.backend_failed = True

    def _record_transaction(self, transaction: TrafficTransaction, *, verified: bool = False) -> None:
        if verified and transaction.request.scheme == 'https' and transaction.response is not None:
            self.https.verified_transactions += 1
        self.captured_transactions.append(transaction)
        if self._on_transaction:
            self._on_transaction(transaction)

    @bounded_operation(4.0, field="timeout_seconds")
    def stop(self, timeout_seconds: float = 4.0) -> None:
        deadline = current_deadline()
        self.cleanup_state = 'completed'
        process = self.process
        if not process:
            for reader in (self._reader, self._stderr_reader):
                if reader:
                    reader.join(timeout=deadline.remaining())
                    if reader.is_alive():
                        self.cleanup_state = 'partial'
            return
        try:
            if os.name == "posix" and isinstance(process.pid, int):
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except OSError:
                    process.terminate()
            else:
                process.terminate()
            # Reserve part of the shared budget for kill and stream drain.
            process.wait(timeout=deadline.timeout(min(timeout_seconds * 0.5, deadline.remaining())))
        except subprocess.TimeoutExpired:
            try:
                if os.name == "posix" and isinstance(process.pid, int):
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except OSError:
                        process.kill()
                else:
                    process.kill()
                process.wait(timeout=deadline.timeout(timeout_seconds))
            except Exception:
                self.cleanup_state = 'partial'
        except Exception:
            self.cleanup_state = 'partial'
        for reader in (self._reader, self._stderr_reader):
            if reader:
                reader.join(timeout=deadline.remaining())
                if reader.is_alive():
                    self.cleanup_state = 'partial'
        if process.poll() is None:
            self.cleanup_state = 'partial'
        else:
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
        self._record_transaction(transaction)
        return transaction

    def get_captured_transactions(self) -> list[TrafficTransaction]:
        return list(self.captured_transactions)
