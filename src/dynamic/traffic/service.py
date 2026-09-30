"""Orchestrator service for Proxy Readiness, Traffic Capture, and Session Correlation."""

from __future__ import annotations

import logging
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
        )
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

        # 5. Device proxy reachability check (for emulators, host is reachable at 10.0.2.2)
        # Check if device can ping/resolve or query network
        if dev_info.is_emulator and proxy_host == "10.0.2.2":
            result.device_reachable_proxy = True
        else:
            code, _, _ = run_adb_cmd(
                self.adb_bin,
                ["shell", "ping", "-c", "1", "-W", "1", proxy_host],
                serial=dev_info.serial,
            )
            result.device_reachable_proxy = (code == 0)
            if not result.device_reachable_proxy:
                warnings.append(
                    f"Direct ICMP reachability to proxy host '{proxy_host}' from device could not be verified."
                )

        # 6. HTTPS Interception visibility (Notice: CA cert installation not performed yet)
        https_info = HttpsInterceptionReadiness(
            ca_certificate_installed=False,
            certificate_trust_unknown=True,
            pinning_suspected=False,
        )
        result.https_interception = https_info
        warnings.append("HTTPS interception certificate trust is not confirmed; plain HTTP will be captured.")

        if errors:
            result.status = TrafficReadinessStatus.FAIL
        elif warnings:
            result.status = TrafficReadinessStatus.WARN
        else:
            result.status = TrafficReadinessStatus.PASS

        result.warnings = warnings
        result.errors = errors
        return result

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
        )
        self.active_capture = capture
        self.captured_transactions = []
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

            capture.status = CaptureStatus.ACTIVE
            capture.started_at = utc_now_iso()
            self.storage.save_capture_session(session_id_str, capture)
            logger.info(f"Traffic capture {capture.capture_id} started on port {proxy_port}")
            return capture

        except Exception as exc:
            logger.error(f"Failed to start capture: {exc}. Rolling back proxy configuration...")
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

    def stop_capture(self) -> CaptureSummary:
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

        self.active_capture.status = CaptureStatus.STOPPING
        logger.info(f"Stopping capture {self.active_capture.capture_id}...")

        # 1. Stop backend engine
        try:
            self.backend.stop()
        except Exception as e:
            logger.warning(f"Error stopping backend: {e}")

        # 2. Guaranteed device proxy rollback
        proxy_restored = False
        if self.proxy_mgr:
            try:
                res = self.proxy_mgr.restore_proxy()
                proxy_restored = bool(res)
            except Exception as e:
                logger.error(f"Error restoring proxy on device: {e}")

        self.active_capture.status = CaptureStatus.COMPLETED
        self.active_capture.ended_at = utc_now_iso()

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

    def _on_transaction_captured(self, transaction: TrafficTransaction) -> None:
        """Persists transaction to transactions.jsonl and keeps memory reference."""
        self.captured_transactions.append(transaction)
        if self.active_capture:
            self.storage.append_transaction(self.active_capture.session_id, transaction)

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
