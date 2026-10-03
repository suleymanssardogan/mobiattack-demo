"""Orchestrator service for Proxy Readiness, Traffic Capture, and Session Correlation."""

from __future__ import annotations

import logging
import threading
import time
from src.dynamic.deadline import bounded_operation, current_deadline
from typing import Any

from src.dynamic.preflight.device_check import check_connected_device, find_adb_binary, run_adb_cmd
from src.dynamic.session.manager import DynamicSessionManager
from src.dynamic.session.models import DynamicSession, utc_now_iso
from src.dynamic.traffic.capture_backend import TrafficCaptureBackend
from src.dynamic.traffic.correlator import TrafficCorrelator
from src.dynamic.traffic.mitmproxy_backend import MitmproxyCaptureBackend, is_port_in_use
from src.dynamic.traffic.models import (
    CaptureSession,
    CaptureStatus,
    CaptureSummary,
    HttpsInterceptionReadiness,
    ProxyReadinessResult,
    TrafficErrorCode,
    TrafficException,
    TrafficReadinessStatus,
    TrafficTransaction,
)
from src.dynamic.traffic.normalizer import normalize_http_transaction
from src.dynamic.traffic.proxy_manager import DeviceProxyManager
from src.dynamic.traffic.storage import TrafficStorage
from src.dynamic.traffic.https_visibility import check_ca_trust

logger = logging.getLogger(__name__)


class DynamicTrafficService:
    """Coordinates proxy readiness checks, device proxy configuration, and capture lifecycle."""

    def __init__(
        self,
        backend: TrafficCaptureBackend | None = None,
        storage: TrafficStorage | None = None,
        adb_bin: str | None = None,
    ) -> None:
        self.adb_bin = find_adb_binary(adb_bin)
        self.backend: TrafficCaptureBackend = backend or MitmproxyCaptureBackend()
        self.storage: TrafficStorage = storage or TrafficStorage()
        self.active_capture: CaptureSession | None = None
        self.proxy_mgr: DeviceProxyManager | None = None
        self.correlator: TrafficCorrelator | None = None
        self.captured_transactions: list[TrafficTransaction] = []
        self._transactions_changed = threading.Condition()
        self.last_traffic_wait = {}
        self.auth_privacy = False
        self.cleanup_state = 'not_started'
        self.last_readiness: ProxyReadinessResult | None = None
        self.http_visibility = "unknown"
        self.http_reason = "capture_not_started"

    @bounded_operation(15.0)
    def check_readiness(
        self,
        device_serial: str | None = None,
        proxy_host: str = "10.0.2.2",
        proxy_port: int = 8080,
    ) -> ProxyReadinessResult:
        """Executes full proxy readiness check and returns normalized result."""
        result = ProxyReadinessResult(
            device_serial=device_serial or "",
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            capture_backend=type(self.backend).__name__,
        )
        self.last_readiness = result
        warnings: list[str] = []
        errors: list[dict[str, str]] = []

        # 1. ADB Check
        if not self.adb_bin:
            result.adb_available = False
            errors.append({
                "code": TrafficErrorCode.ADB_NOT_FOUND.value,
                "message": "ADB binary not found on system.",
            })
            result.status = TrafficReadinessStatus.FAIL
            result.errors = errors
            return result

        result.adb_available = True

        # 2. Target Device Check
        dev_info, dev_err_code, dev_err_msg = check_connected_device(
            self.adb_bin, target_serial=device_serial
        )
        if dev_err_code is not None or not dev_info.connected:
            errors.append({
                "code": (dev_err_code or TrafficErrorCode.DEVICE_NOT_FOUND).value,
                "message": dev_err_msg or "Target device is not connected or accessible.",
            })
            result.status = TrafficReadinessStatus.FAIL
            result.errors = errors
            return result

        result.device_serial = dev_info.serial or ""

        # 3. Capture Backend (mitmproxy) Binary Check
        backend_ready = self.backend.check_available()
        result.backend_available = backend_ready
        if not backend_ready:
            errors.append({
                "code": TrafficErrorCode.MITMPROXY_NOT_FOUND.value,
                "message": "Capture backend (mitmproxy/mitmdump) is not installed or available in PATH.",
            })
            result.status = TrafficReadinessStatus.FAIL
            result.errors = errors
            return result

        # 4. Port Availability Check
        port_free = not is_port_in_use(proxy_port)
        result.port_available = port_free
        if not port_free:
            errors.append({
                "code": TrafficErrorCode.PROXY_PORT_IN_USE.value,
                "message": f"Proxy port {proxy_port} is already occupied on host.",
            })
            result.status = TrafficReadinessStatus.FAIL
            result.errors = errors
            return result

        # Reachability is observed, never inferred from device type or a host alias.
        code, _, _ = run_adb_cmd(self.adb_bin,
            ['shell', 'ping', '-c', '1', '-W', '1', proxy_host], serial=dev_info.serial)
        result.device_reachable_proxy = code == 0
        if not result.device_reachable_proxy:
            warnings.append('Proxy host reachability from the current execution environment could not be verified.')

        # Store inspection is read-only and does not prove that a target app trusts user CAs.
        if isinstance(self.backend, MitmproxyCaptureBackend):
            self.refresh_ca_trust(result.device_serial)
            state = self.backend.https.ca_trust
            result.https_interception = HttpsInterceptionReadiness(
                ca_certificate_installed=state == 'trusted', certificate_trust_unknown=state != 'trusted',
                ca_trust_state=state, ca_trust_reason=self.backend.https.ca_reason)
        warnings.append("HTTPS visibility requires a verified intercepted transaction; proxy startup is not proof.")

        if errors:
            result.status = TrafficReadinessStatus.FAIL
        elif warnings:
            result.status = TrafficReadinessStatus.WARN
        else:
            result.status = TrafficReadinessStatus.PASS

        result.warnings = warnings
        result.errors = errors
        self.last_readiness = result
        return result

    def get_visibility_metadata(self) -> dict[str, str]:
        """Returns protocol visibility metadata based on active backend and readiness."""
        backend_cls_name = self.backend.__class__.__name__
        capture_available = self.active_capture is not None and self.active_capture.status == CaptureStatus.ACTIVE
        is_backend_available = self.backend.check_available()
        if capture_available:
            alive = self.backend.is_alive()
            self.http_visibility = "available" if alive and self.proxy_mgr and self.proxy_mgr.configured else "unavailable"
            self.http_reason = "capture_ready" if self.http_visibility == "available" else "capture_backend_or_proxy_unavailable"
        elif not is_backend_available:
            self.http_visibility, self.http_reason = "unavailable", "capture_backend_unavailable"

        if "Native" in backend_cls_name:
            return {
                "capture_available": str(capture_available).lower(),
                "http_visibility": self.http_visibility,
                "http_reason": self.http_reason,
                "https_visibility": "unavailable",
                "https_reason": "cleartext_http_only_backend",
            }

        if isinstance(self.backend, MitmproxyCaptureBackend):
            if self.active_capture and self.active_capture.status == CaptureStatus.ACTIVE and not self.backend.is_alive():
                self.backend.https.backend_failed = True
            https_vis, reason = self.backend.https.metadata()
            if not is_backend_available:
                https_vis, reason = 'unavailable', 'capture_backend_unavailable'
            ca_trust = self.backend.https.ca_trust
        else:
            https_vis, reason, ca_trust = 'unknown', 'no_https_transaction_available_to_verify', 'unknown'
        return {
            'capture_available': str(capture_available).lower(),
            'http_visibility': self.http_visibility, 'http_reason': self.http_reason,
            'https_visibility': https_vis, 'https_reason': reason, 'ca_trust': ca_trust,
            'ca_trust_reason': self.backend.https.ca_reason if isinstance(self.backend, MitmproxyCaptureBackend) else 'not_applicable',
        }

    def refresh_ca_trust(self, device_serial: str) -> None:
        if isinstance(self.backend, MitmproxyCaptureBackend) and self.adb_bin:
            state, reason = check_ca_trust(self.adb_bin, device_serial,
                                          self.backend.ca_directory / 'mitmproxy-ca-cert.pem')
            self.backend.https.ca_trust, self.backend.https.ca_reason = state, reason


    @bounded_operation(15.0)
    def start_capture(
        self,
        session: DynamicSession | str,
        device_serial: str,
        proxy_host: str = "10.0.2.2",
        proxy_port: int = 8080,
        in_scope_domains: list[str] | None = None,
    ) -> CaptureSession:
        """Configures device proxy, starts capture backend, and transitions state to ACTIVE."""
        if self.active_capture and self.active_capture.status == CaptureStatus.ACTIVE:
            raise TrafficException(
                TrafficErrorCode.INVALID_CAPTURE_STATE,
                "A capture session is already active.",
            )

        session_obj: DynamicSession | None = session if isinstance(session, DynamicSession) else None
        session_id_str: str = session.session_id if isinstance(session, DynamicSession) else str(session)

        if not self.adb_bin:
            raise TrafficException(TrafficErrorCode.ADB_NOT_FOUND, "ADB binary not found.")

        capture = CaptureSession(
            session_id=session_id_str,
            device_serial=device_serial,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            status=CaptureStatus.STARTING,
            backend=type(self.backend).__name__,
        )
        self.active_capture = capture
        self.captured_transactions = []
        self.auth_privacy = False
        self.correlator = TrafficCorrelator(session=session_obj, in_scope_domains=in_scope_domains)

        try:
            # 1. Configure Android device global proxy
            self.proxy_mgr = DeviceProxyManager(
                adb_bin=self.adb_bin,
                serial=device_serial,
                proxy_host=proxy_host,
                proxy_port=proxy_port,
            )
            self.proxy_mgr.apply_proxy()

            # 2. Start capture backend (mitmproxy or adapter)
            self.backend.start(
                listen_host="0.0.0.0",
                listen_port=proxy_port,
                on_transaction_captured=self._on_transaction_captured,
            )

            self.refresh_ca_trust(device_serial)
            capture.metadata["proxy_readback_verified"] = self.proxy_mgr.readback_verified
            self.http_visibility, self.http_reason = "available", "capture_ready"
            capture.status = CaptureStatus.ACTIVE
            capture.started_at = utc_now_iso()
            self.storage.save_capture_session(session_id_str, capture)
            logger.info(f"Traffic capture {capture.capture_id} started on port {proxy_port}")
            return capture

        except Exception as exc:
            logger.error(f"Failed to start capture: {exc}. Rolling back proxy configuration...")
            self.http_visibility = "unavailable"
            self.http_reason = exc.error_code.value if isinstance(exc, TrafficException) else "capture_start_failed"
            self._emergency_cleanup()
            capture.status = CaptureStatus.FAILED
            capture.ended_at = utc_now_iso()
            capture.errors.append({"code": TrafficErrorCode.CAPTURE_START_FAILED.value, "message": str(exc)})
            self.storage.save_capture_session(session_id_str, capture)
            if isinstance(exc, TrafficException):
                raise
            raise TrafficException(
                TrafficErrorCode.CAPTURE_START_FAILED,
                f"Failed to start traffic capture: {exc}",
            ) from exc

    def record_raw_transaction(
        self,
        raw_req: dict[str, Any],
        raw_resp: dict[str, Any] | None,
        duration_ms: float = 0.0,
    ) -> TrafficTransaction:
        """Normalizes, correlates, persists, and tracks an HTTP transaction."""
        if not self.active_capture or self.active_capture.status != CaptureStatus.ACTIVE:
            raise TrafficException(
                TrafficErrorCode.INVALID_CAPTURE_STATE,
                "Cannot record transaction: No active capture session.",
            )

        norm_tx = normalize_http_transaction(
            raw_req=raw_req,
            raw_resp=raw_resp,
            capture_id=self.active_capture.capture_id,
            session_id=self.active_capture.session_id,
            duration_ms=duration_ms,
        )

        if self.correlator:
            norm_tx = self.correlator.correlate(norm_tx)

        self._on_transaction_captured(norm_tx)
        return norm_tx

    def get_current_marker(self) -> int:
        """Returns current transaction count as an action correlation marker."""
        return len(self.captured_transactions)

    def get_transactions_since(self, marker: int) -> list[TrafficTransaction]:
        """Returns incremental transactions captured since the marker."""
        if marker < 0 or marker > len(self.captured_transactions):
            return []
        return self.captured_transactions[marker:]

    @bounded_operation(1.0, field="timeout_seconds")
    def wait_transactions_since(self, marker, timeout_seconds=1.0, quiet_seconds=0.1):
        deadline = current_deadline()
        with self._transactions_changed:
            last_count = len(self.captured_transactions)
            last_arrival = deadline.clock()
            while deadline.remaining() > 0:
                count = len(self.captured_transactions)
                if count != last_count:
                    last_count, last_arrival = count, deadline.clock()
                has_observed = count > marker
                quiet_remaining = max(0.0, quiet_seconds - (deadline.clock() - last_arrival))
                pending = getattr(self.backend, 'pending_count', None)
                if has_observed and quiet_remaining == 0 and pending == 0:
                    break
                wait_time = deadline.remaining()
                if has_observed and quiet_remaining > 0:
                    wait_time = min(wait_time, quiet_remaining)
                self._transactions_changed.wait(timeout=wait_time)
            txs = list(self.get_transactions_since(marker))
            pending = getattr(self.backend, 'pending_count', None)
            self.last_traffic_wait = {'observation': 'observed' if txs else 'not_observed',
                'pending_count': pending, 'in_flight_state': 'unknown' if pending is None else ('pending' if pending else 'drained'),
                'late_arrivals_possible': True, 'deadline_exhausted': deadline.remaining() <= 0,
                'correlation_semantics': 'observed_not_caused'}
            return txs

    @bounded_operation(5.0, field="timeout_seconds")
    def stop_capture(self, timeout_seconds=5.0) -> CaptureSummary:
        """Stops backend, restores device proxy, generates capture summary, and persists artifacts."""
        if not self.active_capture:
            raise TrafficException(
                TrafficErrorCode.INVALID_CAPTURE_STATE,
                "Cannot stop capture: No capture session exists.",
            )

        if self.active_capture.status not in (CaptureStatus.ACTIVE, CaptureStatus.STARTING):
            raise TrafficException(
                TrafficErrorCode.INVALID_CAPTURE_STATE,
                f"Capture is in '{self.active_capture.status.value}' state, cannot stop.",
            )

        vis = self.get_visibility_metadata()
        self.active_capture.status = CaptureStatus.STOPPING
        logger.info(f"Stopping capture {self.active_capture.capture_id}...")

        # 1. Stop backend engine
        try:
            self.backend.stop()
        except Exception as e:
            logger.warning(f"Error stopping backend: {e}")

        self.cleanup_state = getattr(self.backend, 'cleanup_state', 'unknown')
        if self.cleanup_state != 'completed':
            self.active_capture.warnings.append('Capture cleanup partial; retained collected evidence.')

        # 2. Guaranteed device proxy rollback
        proxy_restored = False
        if self.proxy_mgr:
            try:
                res = self.proxy_mgr.restore_proxy()
                proxy_restored = bool(res)
            except Exception as e:
                logger.error(f"Error restoring proxy on device: {e}")

        if self.proxy_mgr and not proxy_restored:
            self.cleanup_state = 'partial'
            self.active_capture.warnings.append('Device proxy restore unavailable within cleanup budget.')
        self.active_capture.status = CaptureStatus.COMPLETED
        self.active_capture.ended_at = utc_now_iso()

        self.refresh_ca_trust(self.active_capture.device_serial)

        # 3. Compile Summary
        http_count = 0
        https_count = 0
        domains: set[str] = set()
        correlated_count = 0
        in_scope_count = 0

        for tx in self.captured_transactions:
            if tx.request.scheme.lower() == "https":
                https_count += 1
            else:
                http_count += 1

            if tx.request.host:
                domains.add(tx.request.host)

            if tx.flow_id:
                correlated_count += 1

            if tx.scope == "IN_SCOPE":
                in_scope_count += 1

        summary = CaptureSummary(
            capture_id=self.active_capture.capture_id,
            session_id=self.active_capture.session_id,
            total_transactions=len(self.captured_transactions),
            http_count=http_count,
            https_count=https_count,
            domains=sorted(list(domains)),
            correlated_flow_count=correlated_count,
            in_scope_count=in_scope_count,
            proxy_restored=proxy_restored,
            http_visibility=vis.get("http_visibility", "unknown"),
            http_visibility_reason=vis.get("http_reason", "unknown"),
            https_visibility=vis.get("https_visibility", "unavailable"),
            https_visibility_reason=vis.get("https_reason", "certificate_trust_unknown"),
            ca_trust_state=vis.get('ca_trust', 'unknown'),
            ca_trust_reason=vis.get('ca_trust_reason', 'certificate_trust_unknown'),
            verified_https_transactions=self.backend.https.verified_transactions if isinstance(self.backend, MitmproxyCaptureBackend) else 0,
            tls_failure_count=self.backend.https.tls_failures if isinstance(self.backend, MitmproxyCaptureBackend) else 0,
        )

        self.storage.save_capture_session(
            session_id=self.active_capture.session_id,
            capture=self.active_capture,
            summary=summary,
        )
        logger.info(
            f"Capture completed: {summary.total_transactions} txs across {len(summary.domains)} domains. Proxy restored: {proxy_restored}."
        )
        return summary

    @bounded_operation(5.0)
    def abort_capture(self, reason: str = "") -> None:
        """Forces immediate cleanup and sets capture status to ABORTED."""
        if not self.active_capture:
            return

        self._emergency_cleanup()
        self.active_capture.status = CaptureStatus.ABORTED
        self.active_capture.ended_at = utc_now_iso()
        if reason:
            self.active_capture.warnings.append(f"Capture aborted: {reason}")
        self.storage.save_capture_session(self.active_capture.session_id, self.active_capture)

    def enable_auth_privacy(self, session_id):
        if self.active_capture is None or self.active_capture.session_id != session_id:
            raise ValueError('AUTH_TRAFFIC_SESSION_MISMATCH')
        self.auth_privacy = True  # retained through capture end for late/in-flight login traffic
        self.active_capture.metadata['auth_intervention_values_withheld'] = True

    def _on_transaction_captured(self, transaction: TrafficTransaction) -> None:
        """Persists transaction to transactions.jsonl and keeps memory reference."""
        if self.auth_privacy:
            transaction.request.query = {k: '[REDACTED]' for k in transaction.request.query}
            for message in (transaction.request, transaction.response):
                if message is not None:
                    message.headers = {k: '[REDACTED]' for k in message.headers}
                    message.body = None
                    message.body_metadata = {'auth_intervention_values_withheld': True}
        if self.correlator and not transaction.correlation:
            transaction = self.correlator.correlate(transaction)

        if self.active_capture:
            transaction.capture_id = self.active_capture.capture_id
            transaction.session_id = self.active_capture.session_id
            self.storage.append_transaction(self.active_capture.session_id, transaction)
        with self._transactions_changed:
            self.captured_transactions.append(transaction)
            self._transactions_changed.notify_all()

    @bounded_operation(5.0)
    def _emergency_cleanup(self) -> None:
        """Failsafe method ensuring backend is stopped and proxy is restored."""
        try:
            self.backend.stop()
        except Exception:
            pass

        if self.proxy_mgr:
            try:
                self.proxy_mgr.restore_proxy()
            except Exception:
                pass
