"""HTML Probe Server & ADB Reverse Connectivity Helper for MobiAttack-v1.

Provides a minimal local HTTP server to verify emulator-to-host connectivity
during mentor demonstrations, recording probe hits deterministically:
- Serves minimal HTML on /probe/<run_id>
- Thread-safely records hit counts and metadata
- Exposes /status/<run_id> and server.get_status(run_id)
- Manages ADB reverse port forwarding (adb reverse tcp:X tcp:Y)
- Provides an emulator browser intent trigger for connectivity verification only.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import shutil
import subprocess
import threading
import urllib.parse

from src.system_env import resolve_executable

PROBE_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>MobiAttack Demo Probe</title>
</head>
<body>
  <h1>MobiAttack Demo Probe</h1>
  <p>Page successfully loaded.</p>
</body>
</html>
"""


class AdbReverseError(ValueError):
    """Raised when ADB reverse configuration or removal fails."""
    pass


class _ProbeRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Probe Server."""

    def log_message(self, format: str, *args) -> None:
        # Suppress standard HTTP server console noise
        pass

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.strip()

        # Handle GET /probe/<run_id>
        probe_match = re.match(r"^/probe/([a-zA-Z0-9_\-]+)$", path)
        if probe_match:
            run_id = probe_match.group(1)
            user_agent = self.headers.get("User-Agent")
            client_ip = self.client_address[0] if self.client_address else None

            # Thread-safe hit registration
            self.server.probe_server._record_hit(
                run_id=run_id,
                request_path=path,
                user_agent=user_agent,
                client_ip=client_ip,
            )

            html_bytes = PROBE_HTML_TEMPLATE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_bytes)))
            self.end_headers()
            self.wfile.write(html_bytes)
            return

        # Handle GET /status/<run_id>
        status_match = re.match(r"^/status/([a-zA-Z0-9_\-]+)$", path)
        if status_match:
            run_id = status_match.group(1)
            status_data = self.server.probe_server.get_status(run_id)
            body = json.dumps(status_data, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Default 404
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 Not Found")


class ProbeServer:
    """Thread-safe HTTP probe server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self._requested_port = port
        self.port: int = port
        self.base_url: str = ""
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._hits: dict[str, dict] = {}
        self._running = False

    def _record_hit(
        self,
        run_id: str,
        request_path: str,
        user_agent: str | None,
        client_ip: str | None,
    ) -> None:
        with self._lock:
            if run_id not in self._hits:
                self._hits[run_id] = {
                    "run_id": run_id,
                    "hit": True,
                    "hit_count": 1,
                    "request_path": request_path,
                    "last_user_agent": user_agent,
                    "last_client_ip": client_ip,
                }
            else:
                entry = self._hits[run_id]
                entry["hit_count"] += 1
                entry["request_path"] = request_path
                entry["last_user_agent"] = user_agent
                entry["last_client_ip"] = client_ip

    def start(self) -> None:
        """Starts the probe server in a background daemon thread."""
        if self._running:
            return

        self._server = HTTPServer((self.host, self._requested_port), _ProbeRequestHandler)
        # Attach reference back to self for request handler access
        self._server.probe_server = self  # type: ignore
        self.port = self._server.server_port
        self.base_url = f"http://{self.host}:{self.port}"

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._running = True

    def stop(self) -> None:
        """Stops the probe server, joins thread, and releases socket."""
        if not self._running or self._server is None:
            return

        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

        self._server = None
        self._running = False

    def get_status(self, run_id: str) -> dict:
        """Returns deterministic status for the specified run_id."""
        with self._lock:
            if run_id in self._hits:
                entry = self._hits[run_id]
                return {
                    "run_id": run_id,
                    "hit": True,
                    "hit_count": entry["hit_count"],
                    "request_path": entry.get("request_path"),
                    "last_user_agent": entry.get("last_user_agent"),
                    "last_client_ip": entry.get("last_client_ip"),
                }
            else:
                return {
                    "run_id": run_id,
                    "hit": False,
                    "hit_count": 0,
                    "request_path": None,
                    "last_user_agent": None,
                    "last_client_ip": None,
                }

    def get_probe_url(self, run_id: str) -> str:
        """Returns full probe URL for run_id."""
        return f"{self.base_url}/probe/{run_id}"


def start_probe_server(host: str = "127.0.0.1", port: int = 0) -> ProbeServer:
    """Helper function to instantiate and start a ProbeServer."""
    server = ProbeServer(host=host, port=port)
    server.start()
    return server


def stop_probe_server(server: ProbeServer) -> None:
    """Helper function to cleanly stop a ProbeServer."""
    if server is not None:
        server.stop()


# ---------------------------------------------------------------------------
# ADB Reverse & Emulator Connectivity Helpers
# ---------------------------------------------------------------------------

def configure_adb_reverse(
    adb_serial: str,
    device_port: int = 8080,
    host_port: int = 8080,
    adb_executable: str | None = None,
    timeout_seconds: float = 30.0,
) -> dict:
    """Configures ADB reverse port forwarding (device -> host).

    Command equivalent:
        adb -s <serial> reverse tcp:<device_port> tcp:<host_port>

    Returns:
        dict: {"serial": str, "device_port": int, "host_port": int, "success": True}
    """
    adb_bin = resolve_executable("adb", adb_executable)
    if not adb_bin:
        raise AdbReverseError(
            f"Required executable 'adb' not found on system PATH. (Specified: '{adb_executable or 'adb'}')"
        )

    if not adb_serial or not str(adb_serial).strip():
        raise AdbReverseError("Explicit adb_serial is required for adb reverse configuration.")

    cmd = [
        adb_bin,
        "-s",
        str(adb_serial).strip(),
        "reverse",
        f"tcp:{device_port}",
        f"tcp:{host_port}",
    ]

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, OSError) as err:
        raise AdbReverseError(f"adb reverse command timed out or failed: {err}") from err

    if res.returncode != 0:
        err_msg = (res.stderr or res.stdout or "").strip()
        raise AdbReverseError(
            f"adb reverse failed ({res.returncode}) for {adb_serial} (tcp:{device_port} -> tcp:{host_port}): {err_msg}"
        )

    return {
        "serial": str(adb_serial).strip(),
        "device_port": device_port,
        "host_port": host_port,
        "success": True,
    }


def remove_adb_reverse(
    adb_serial: str,
    device_port: int = 8080,
    adb_executable: str | None = None,
    timeout_seconds: float = 30.0,
) -> bool:
    """Removes ADB reverse port forwarding for the specified device port.

    Command equivalent:
        adb -s <serial> reverse --remove tcp:<device_port>
    """
    adb_bin = resolve_executable("adb", adb_executable)
    if not adb_bin:
        return False

    cmd = [
        adb_bin,
        "-s",
        str(adb_serial).strip(),
        "reverse",
        "--remove",
        f"tcp:{device_port}",
    ]

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return res.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def trigger_device_browser(
    adb_serial: str,
    url: str,
    adb_executable: str | None = None,
    timeout_seconds: float = 30.0,
) -> dict:
    """Issues an Android VIEW intent to open the specified URL in the device browser.

    CRITICAL SEMANTIC NOTICE:
    This helper proves ONLY emulator-to-host network connectivity.
    It does NOT represent, prove, or imply target-application navigation.
    """
    adb_bin = resolve_executable("adb", adb_executable)
    if not adb_bin:
        raise AdbReverseError(f"Required executable 'adb' not found on system PATH.")

    cmd = [
        adb_bin,
        "-s",
        str(adb_serial).strip(),
        "shell",
        "am",
        "start",
        "-a",
        "android.intent.action.VIEW",
        "-d",
        url,
    ]

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, OSError) as err:
        raise AdbReverseError(f"adb browser intent trigger timed out or failed: {err}") from err

    if res.returncode != 0:
        err_msg = (res.stderr or res.stdout or "").strip()
        raise AdbReverseError(f"Failed to launch browser intent: {err_msg}")

    return {
        "serial": str(adb_serial).strip(),
        "url": url,
        "action": "android.intent.action.VIEW",
        "connectivity_intent_dispatched": True,
    }
