"""Python-native HTTP Proxy Capture Backend with zero external dependencies.

Acts as an HTTP proxy (supporting GET/POST/etc with full path or proxy request URI),
captures request and response, streams directly to MobiAttack's TrafficTransaction model,
and for transparent/local test server forwarders.
"""

from __future__ import annotations

import subprocess
import http.client
import http.server
import json
import logging
import os
import socket
from socketserver import ThreadingMixIn
import threading
import time
from typing import Any, Callable
from urllib.parse import urlparse
from src.dynamic.deadline import bounded_operation, current_deadline, Deadline

from src.dynamic.traffic.capture_backend import TrafficCaptureBackend
from src.dynamic.traffic.mitmproxy_backend import is_port_in_use
from src.dynamic.traffic.models import (
    TrafficErrorCode,
    TrafficException,
    TrafficTransaction,
    utc_now_iso,
)
from src.dynamic.traffic.normalizer import normalize_http_transaction

logger = logging.getLogger(__name__)


class _ThreadingHTTPServer(ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        self.ready = threading.Event()
        self.clients = set()
        self.clients_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def get_request(self):
        client, address = super().get_request()
        client.settimeout(3.0)
        return client, address

    def service_actions(self):
        self.ready.set()

    def process_request(self, request, address):
        with self.clients_lock:
            self.clients.add(request)
        super().process_request(request, address)

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            with self.clients_lock:
                self.clients.discard(request)



class NativeProxyCaptureBackend:
    """Zero-dependency HTTP proxy capture backend powered by Python standard library."""

    def __init__(self) -> None:
        self.server: _ThreadingHTTPServer | None = None
        self.server_thread: threading.Thread | None = None
        self.cleanup_state = "not_started"
        self._upstreams = set()
        self._upstreams_lock = threading.Lock()
        self.running: bool = False
        self.captured_transactions: list[TrafficTransaction] = []
        self._on_transaction: Callable[[TrafficTransaction], None] | None = None
        self.listen_host: str = "0.0.0.0"
        self.listen_port: int = 8080
        self.capture_id: str = "native-capture"

    def check_available(self) -> bool:
        """Always available as it uses Python standard library without external binaries."""
        return True

    @bounded_operation(5.0, field="timeout_seconds")
    def start(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8080,
        on_transaction_captured: Callable[[TrafficTransaction], None] | None = None,
        capture_id: str | None = None,
        session_id: str | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        """Binds and starts the HTTP proxy server on a background thread."""
        if self.running:
            return

        if is_port_in_use(listen_port, host="127.0.0.1"):
            raise TrafficException(
                TrafficErrorCode.PROXY_PORT_IN_USE,
                f"Proxy port {listen_port} is already in use by another process.",
            )

        self.listen_host = listen_host
        self.listen_port = listen_port
        self._on_transaction = on_transaction_captured
        self.session_id = session_id
        self.captured_transactions = []
        if capture_id:
            self.capture_id = capture_id

        backend_self = self

        import http.server

        class ProxyRequestHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                # Suppress noisy default stderr logging
                pass

            def do_GET(self) -> None:
                self._handle_proxy_request("GET")

            def do_POST(self) -> None:
                self._handle_proxy_request("POST")

            def do_PUT(self) -> None:
                self._handle_proxy_request("PUT")

            def do_DELETE(self) -> None:
                self._handle_proxy_request("DELETE")

            def do_HEAD(self) -> None:
                self._handle_proxy_request("HEAD")

            def do_OPTIONS(self) -> None:
                self._handle_proxy_request("OPTIONS")

            def _handle_proxy_request(self, method: str) -> None:
                request_deadline = Deadline(3.0)
                self.connection.settimeout(request_deadline.timeout(3.0))
                start_time = time.time()
                req_ts = utc_now_iso()

                # Read body if present
                content_len = int(self.headers.get("Content-Length", 0))
                body_chunks = []
                remaining_body = content_len
                try:
                    while remaining_body > 0:
                        self.connection.settimeout(request_deadline.timeout(3.0))
                        chunk = self.rfile.read1(min(65536, remaining_body))
                        if not chunk:
                            return  # incomplete request is not a completed transaction
                        body_chunks.append(chunk)
                        remaining_body -= len(chunk)
                except (OSError, subprocess.TimeoutExpired):
                    return
                req_body = b"".join(body_chunks)

                # Parse target URL / Host
                url_path = self.path
                parsed = urlparse(url_path)
                authority = parsed if parsed.hostname else urlparse("//" + self.headers.get("Host", "unknown-host"))
                host = authority.hostname or "unknown-host"
                port = authority.port or (443 if parsed.scheme == "https" else 80)
                path = parsed.path or "/"
                if parsed.query:
                    path += f"?{parsed.query}"

                headers_dict = dict(self.headers.items())

                # Only a received upstream response is canonical application evidence.
                # Localhost is forwarded normally; errors produce an internal 502 only.
                upstream_observed = False
                failure_reason = "upstream_unavailable"
                resp_status = 502
                resp_headers = {"Content-Type": "application/json", "Server": "MobiAttack-Proxy/Internal"}
                resp_body = b'{"error":"upstream_unavailable","internal":true}'
                conn = None
                try:
                    if parsed.scheme not in ("", "http"):
                        failure_reason = "unsupported_scheme"
                    else:
                        conn = http.client.HTTPConnection(host, port, timeout=request_deadline.timeout(3.0))
                        fwd_headers = {k: v for k, v in headers_dict.items() if k.lower() != "proxy-connection"}
                        with backend_self._upstreams_lock:
                            backend_self._upstreams.add(conn)
                        conn.request(method, path, body=req_body, headers=fwd_headers)
                        if conn.sock:
                            conn.sock.settimeout(request_deadline.timeout(3.0))
                        upstream_resp = conn.getresponse()
                        chunks = []
                        response_socket = conn.sock or getattr(getattr(upstream_resp.fp, 'raw', None), '_sock', None)
                        while True:
                            remaining = request_deadline.timeout(3.0)
                            if response_socket:
                                response_socket.settimeout(remaining)
                            chunk = upstream_resp.read1(65536)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        upstream_body = b''.join(chunks)
                        resp_status = upstream_resp.status
                        upstream_headers = upstream_resp.getheaders()
                        resp_headers = dict(upstream_headers)
                        cookie_values = [v for k,v in upstream_headers if k.lower() == 'set-cookie']
                        if cookie_values: resp_headers['Set-Cookie'] = cookie_values
                        resp_body = upstream_body
                        upstream_observed = True
                except Exception:
                    # No mock success, no raw exception/credentials in persisted errors.
                    failure_reason = "upstream_failure"
                finally:
                    if conn:
                        with backend_self._upstreams_lock:
                            backend_self._upstreams.discard(conn)
                        try:
                            conn.close()
                        except Exception:
                            pass

                # Send response back to emulator / client
                try:
                    self.connection.settimeout(request_deadline.timeout(3.0))
                    self.send_response(resp_status)
                    for h_k, h_v in resp_headers.items():
                        if isinstance(h_v,list):
                            for value in h_v: self.send_header(h_k,value)
                        else: self.send_header(h_k, h_v)
                    self.end_headers()
                    self.wfile.write(resp_body)
                except Exception as send_err:
                    logger.debug(f"Error responding to proxy client: {send_err}")

                duration_ms = (time.time() - start_time) * 1000.0

                # Form raw dicts for normalizer
                raw_req = {
                    "timestamp": req_ts,
                    "method": method,
                    "url": url_path if url_path.startswith("http") else f"http://{host}:{port}{url_path}",
                    "host": host,
                    "port": port,
                    "path": path,
                    "headers": headers_dict,
                    "body": req_body,
                }
                raw_resp = {
                    "timestamp": utc_now_iso(),
                    "status_code": resp_status,
                    "headers": resp_headers,
                    "body": resp_body,
                }

                # Normalize and dispatch
                tx = normalize_http_transaction(
                    raw_req=raw_req,
                    session_id=backend_self.session_id,
                    raw_resp=raw_resp if upstream_observed else None,
                    capture_id=backend_self.capture_id,
                    duration_ms=duration_ms,
                )
                if not upstream_observed:
                    tx.correlation["response_observation"] = {
                        "state": "unavailable", "reason": failure_reason,
                        "internal_proxy_response_excluded": True,
                    }
                backend_self.captured_transactions.append(tx)
                if backend_self._on_transaction:
                    backend_self._on_transaction(tx)

        try:
            self.server = _ThreadingHTTPServer((listen_host, listen_port), ProxyRequestHandler)
            self.server_thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.05), daemon=True)
            self.server_thread.start()
            if not self.server.ready.wait(timeout=current_deadline().timeout(timeout_seconds)) or not self.server_thread.is_alive():
                raise RuntimeError('Native proxy readiness unavailable')
            self.running = True
            logger.info(f"NativeProxyCaptureBackend listening on {listen_host}:{listen_port}")
        except Exception as exc:
            self.stop()
            raise TrafficException(
                TrafficErrorCode.CAPTURE_START_FAILED,
                f"Failed to start native proxy server: {exc}",
            ) from exc

    @property
    def pending_count(self):
        if not self.server:
            return 0
        with self.server.clients_lock:
            return len(self.server.clients)

    @bounded_operation(4.0, field="timeout_seconds")
    def stop(self, timeout_seconds: float = 4.0) -> None:
        deadline = current_deadline()
        self.cleanup_state = 'completed'
        self.running = False
        server = self.server
        if server:
            with server.clients_lock:
                clients = list(server.clients)
            with self._upstreams_lock:
                upstreams = list(self._upstreams)
            for client in clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                except OSError:
                    pass
            for connection in upstreams:
                try:
                    if connection.sock:
                        connection.sock.shutdown(socket.SHUT_RDWR)
                    connection.close()
                except OSError:
                    pass
            done = threading.Event()
            def shutdown():
                try:
                    server.shutdown()
                    server.server_close()
                finally:
                    done.set()
            thread = threading.Thread(target=shutdown, daemon=True)
            thread.start()
            if not done.wait(timeout=deadline.remaining()):
                self.cleanup_state = 'partial'
        if self.server_thread and self.server_thread.ident is not None:
            self.server_thread.join(timeout=deadline.remaining())
            if self.server_thread.is_alive():
                self.cleanup_state = 'partial'
        if server:
            with server.clients_lock:
                if server.clients:
                    self.cleanup_state = 'partial'
        if self.cleanup_state == 'completed':
            self.server = None
            self.server_thread = None

    def is_alive(self) -> bool:
        return bool(self.running and self.server is not None and self.server_thread and self.server_thread.is_alive())

    def get_captured_transactions(self) -> list[TrafficTransaction]:
        return list(self.captured_transactions)
