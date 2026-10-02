"""Python-native HTTP Proxy Capture Backend with zero external dependencies.

Acts as an HTTP proxy (supporting GET/POST/etc with full path or proxy request URI),
captures request and response, streams directly to MobiAttack's TrafficTransaction model,
and for transparent/local test server forwarders.
"""

from __future__ import annotations

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


class NativeProxyCaptureBackend:
    """Zero-dependency HTTP proxy capture backend powered by Python standard library."""

    def __init__(self) -> None:
        self.server: _ThreadingHTTPServer | None = None
        self.server_thread: threading.Thread | None = None
        self.running: bool = False
        self.captured_transactions: list[TrafficTransaction] = []
        self._on_transaction: Callable[[TrafficTransaction], None] | None = None
        self.listen_host: str = "0.0.0.0"
        self.listen_port: int = 8080
        self.capture_id: str = "native-capture"

    def check_available(self) -> bool:
        """Always available as it uses Python standard library without external binaries."""
        return True

    def start(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8080,
        on_transaction_captured: Callable[[TrafficTransaction], None] | None = None,
        capture_id: str | None = None,
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
                start_time = time.time()
                req_ts = utc_now_iso()

                # Read body if present
                content_len = int(self.headers.get("Content-Length", 0))
                req_body = self.rfile.read(content_len) if content_len > 0 else b""

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
                        conn = http.client.HTTPConnection(host, port, timeout=3.0)
                        fwd_headers = {k: v for k, v in headers_dict.items() if k.lower() != "proxy-connection"}
                        conn.request(method, path, body=req_body, headers=fwd_headers)
                        upstream_resp = conn.getresponse()
                        upstream_body = upstream_resp.read()
                        resp_status = upstream_resp.status
                        resp_headers = dict(upstream_resp.getheaders())
                        resp_body = upstream_body
                        upstream_observed = True
                except Exception:
                    # No mock success, no raw exception/credentials in persisted errors.
                    failure_reason = "upstream_failure"
                finally:
                    if conn:
                        try:
                            conn.close()
                        except Exception:
                            pass

                # Send response back to emulator / client
                try:
                    self.send_response(resp_status)
                    for h_k, h_v in resp_headers.items():
                        self.send_header(h_k, h_v)
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
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            self.running = True
            logger.info(f"NativeProxyCaptureBackend listening on {listen_host}:{listen_port}")
        except Exception as exc:
            raise TrafficException(
                TrafficErrorCode.CAPTURE_START_FAILED,
                f"Failed to start native proxy server: {exc}",
            ) from exc

    def stop(self, timeout_seconds: float = 4.0) -> None:
        """Shuts down the server and waits for thread termination."""
        if not self.running:
            return

        self.running = False
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception as e:
                logger.debug(f"Error shutting down native proxy: {e}")
            finally:
                self.server = None

        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=timeout_seconds)
            self.server_thread = None

    def is_alive(self) -> bool:
        return self.running and self.server is not None

    def get_captured_transactions(self) -> list[TrafficTransaction]:
        return list(self.captured_transactions)
