"""Unit tests for Dynamic Traffic Capture and Proxy Readiness."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.dynamic.session.models import DynamicSession, EventType, TargetFlow, TimelineEvent
from src.dynamic.traffic.correlator import TrafficCorrelator
from src.dynamic.traffic.models import (
    CaptureSession,
    CaptureStatus,
    HttpRequestModel,
    HttpResponseModel,
    TrafficErrorCode,
    TrafficException,
    TrafficReadinessStatus,
    TrafficTransaction,
)
from src.dynamic.traffic.normalizer import (
    MAX_CAPTURE_BODY_BYTES,
    normalize_http_transaction,
    process_body_content,
    sanitize_body_payload,
    sanitize_headers,
)
from src.dynamic.traffic.proxy_manager import DeviceProxyManager
from src.dynamic.traffic.service import DynamicTrafficService
from src.dynamic.traffic.storage import TrafficStorage


class TestDynamicTraffic(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_traffic_")
        self.storage = TrafficStorage(base_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. mitmproxy yoksa readiness FAIL
    @patch("src.dynamic.traffic.service.check_connected_device")
    def test_01_mitmproxy_missing_readiness_fail(self, mock_device):
        mock_device.return_value = (MagicMock(connected=True, serial="dev-1"), None, None)
        mock_backend = MagicMock()
        mock_backend.check_available.return_value = False

        service = DynamicTrafficService(backend=mock_backend, storage=self.storage, adb_bin="/mock/adb")
        res = service.check_readiness(device_serial="dev-1")
        self.assertEqual(res.status, TrafficReadinessStatus.FAIL)
        self.assertFalse(res.backend_available)
        self.assertTrue(any(e["code"] == TrafficErrorCode.MITMPROXY_NOT_FOUND.value for e in res.errors))

    # 2. device yoksa FAIL
    @patch("src.dynamic.traffic.service.check_connected_device")
    def test_02_device_missing_readiness_fail(self, mock_device):
        mock_device.return_value = (MagicMock(connected=False), TrafficErrorCode.DEVICE_NOT_FOUND, "No devices")
        mock_backend = MagicMock()
        mock_backend.check_available.return_value = True

        service = DynamicTrafficService(backend=mock_backend, storage=self.storage, adb_bin="/mock/adb")
        res = service.check_readiness(device_serial="dev-1")
        self.assertEqual(res.status, TrafficReadinessStatus.FAIL)
        self.assertTrue(any(e["code"] == TrafficErrorCode.DEVICE_NOT_FOUND.value for e in res.errors))

    # 3. proxy state backup alınır
    @patch("src.dynamic.traffic.proxy_manager.run_adb_cmd")
    def test_03_proxy_state_backup_taken(self, mock_adb):
        # 1st call: settings get -> returns previous proxy
        mock_adb.side_effect = [
            (0, "192.168.1.50:8888", ""),
            (0, "", ""),  # settings put
        ]
        mgr = DeviceProxyManager("/mock/adb", "emulator-5554", "10.0.2.2", 8080)
        mgr.apply_proxy()
        self.assertEqual(mgr.previous_proxy, "192.168.1.50:8888")
        self.assertTrue(mgr.configured)

    # 4. proxy configure edilir
    @patch("src.dynamic.traffic.proxy_manager.run_adb_cmd")
    def test_04_proxy_configured(self, mock_adb):
        mock_adb.side_effect = [
            (0, ":0", ""),  # no proxy
            (0, "", ""),  # settings put 10.0.2.2:8080
        ]
        mgr = DeviceProxyManager("/mock/adb", "emulator-5554", "10.0.2.2", 8080)
        mgr.apply_proxy()
        put_call = mock_adb.call_args_list[1]
        self.assertIn("10.0.2.2:8080", put_call[0][1])

    # 5. normal stop sonrası proxy restore edilir
    @patch("src.dynamic.traffic.proxy_manager.run_adb_cmd")
    def test_05_normal_stop_restores_proxy(self, mock_adb):
        mock_adb.side_effect = [
            (0, "old_proxy:8080", ""),
            (0, "", ""),  # put new
            (0, "", ""),  # restore old
        ]
        with DeviceProxyManager("/mock/adb", "emulator-5554", "10.0.2.2", 8080) as mgr:
            self.assertEqual(mgr.previous_proxy, "old_proxy:8080")
        restore_call = mock_adb.call_args_list[2]
        self.assertIn("old_proxy:8080", restore_call[0][1])

    # 6. exception sonrası proxy restore edilir
    @patch("src.dynamic.traffic.proxy_manager.run_adb_cmd")
    def test_06_exception_restores_proxy(self, mock_adb):
        mock_adb.side_effect = [
            (0, ":0", ""),  # get
            (0, "", ""),  # put
            (0, "", ""),  # restore :0
        ]
        with self.assertRaises(ValueError):
            with DeviceProxyManager("/mock/adb", "emulator-5554", "10.0.2.2", 8080):
                raise ValueError("Crash during capture!")

        restore_call = mock_adb.call_args_list[2]
        self.assertIn(":0", restore_call[0][1])

    # 7. capture state transition doğru çalışır
    def test_07_capture_state_transitions(self):
        mock_backend = MagicMock()
        mock_backend.check_available.return_value = True

        service = DynamicTrafficService(backend=mock_backend, storage=self.storage, adb_bin="/mock/adb")
        with patch.object(DeviceProxyManager, "apply_proxy"), patch.object(DeviceProxyManager, "restore_proxy"):
            capture = service.start_capture("sess-1", "emulator-5554")
            self.assertEqual(capture.status, CaptureStatus.ACTIVE)
            summary = service.stop_capture()
            self.assertEqual(capture.status, CaptureStatus.COMPLETED)
            self.assertEqual(summary.total_transactions, 0)

    # 8. invalid capture transition hata verir
    def test_08_invalid_capture_transition_raises_error(self):
        service = DynamicTrafficService(backend=MagicMock(), storage=self.storage, adb_bin="/mock/adb")
        with self.assertRaises(TrafficException) as ctx:
            service.stop_capture()
        self.assertEqual(ctx.exception.error_code, TrafficErrorCode.INVALID_CAPTURE_STATE)

    # 9. sensitive headers redact edilir
    def test_09_sensitive_headers_redacted(self):
        raw_headers = {
            "Host": "api.example.com",
            "Authorization": "Bearer super_secret_token",
            "Cookie": "session_id=secret123",
            "X-Api-Key": "key999",
            "Content-Type": "application/json",
        }
        sanitized = sanitize_headers(raw_headers)
        self.assertEqual(sanitized["authorization"], "[REDACTED]")
        self.assertEqual(sanitized["cookie"], "[REDACTED]")
        self.assertEqual(sanitized["x-api-key"], "[REDACTED]")
        self.assertEqual(sanitized["content-type"], "application/json")
        self.assertEqual(sanitized["host"], "api.example.com")

    # 10. JSON body sensitive field redact edilir
    def test_10_json_body_sensitive_fields_redacted(self):
        body = {
            "email": "user@example.com",
            "password": "Password123!",
            "auth": {"refresh_token": "token_xyz"},
            "session_id": "app_internal_session_id",  # sensitive pattern
        }
        sanitized = sanitize_body_payload(body)
        self.assertEqual(sanitized["email"], "user@example.com")
        self.assertEqual(sanitized["password"], "[REDACTED]")
        self.assertEqual(sanitized["auth"]["refresh_token"], "[REDACTED]")

    # 11. oversized body truncate edilir
    def test_11_oversized_body_truncated(self):
        big_body = b"A" * (MAX_CAPTURE_BODY_BYTES + 500)
        content, meta = process_body_content(big_body, "text/plain")
        self.assertTrue(meta["truncated"])
        self.assertEqual(meta["original_size"], MAX_CAPTURE_BODY_BYTES + 500)
        self.assertEqual(content, "[REDACTED]")

    # 12. binary body metadata olarak tutulur
    def test_12_binary_body_stored_as_metadata(self):
        png_header = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        content, meta = process_body_content(png_header, "image/png")
        self.assertIsNone(content)
        self.assertTrue(meta["binary"])
        self.assertIn("sha256", meta)

    # 13. flow timestamp correlation doğru çalışır
    def test_13_flow_timestamp_correlation(self):
        session = DynamicSession(
            session_id="sess-1",
            flows=[
                TargetFlow(
                    flow_id="flow-login",
                    name="login",
                    started_at="2026-09-30T10:00:00Z",
                    ended_at="2026-09-30T10:00:10Z",
                )
            ],
        )
        correlator = TrafficCorrelator(session=session)

        # Transaction inside window
        tx = TrafficTransaction(
            capture_id="c1",
            request=HttpRequestModel(timestamp="2026-09-30T10:00:05Z", host="api.com"),
        )
        correlated = correlator.correlate(tx)
        self.assertEqual(correlated.flow_id, "flow-login")

        # Transaction outside window
        tx2 = TrafficTransaction(
            capture_id="c1",
            request=HttpRequestModel(timestamp="2026-09-30T10:00:15Z", host="api.com"),
        )
        correlated2 = correlator.correlate(tx2)
        self.assertIsNone(correlated2.flow_id)

    # 14. nearest marker correlation doğru çalışır
    def test_14_nearest_marker_correlation(self):
        session = DynamicSession(
            session_id="sess-1",
            timeline=[
                TimelineEvent(
                    type=EventType.MARKER,
                    name="LOGIN_SUBMIT",
                    timestamp="2026-09-30T10:00:05.000Z",
                ),
                TimelineEvent(
                    type=EventType.MARKER,
                    name="LOGIN_SUCCESS",
                    timestamp="2026-09-30T10:00:05.200Z",
                ),
            ],
        )
        correlator = TrafficCorrelator(session=session, marker_window_ms=1000.0)

        tx = TrafficTransaction(
            capture_id="c1",
            request=HttpRequestModel(timestamp="2026-09-30T10:00:05.100Z", host="api.com"),
        )
        correlated = correlator.correlate(tx)
        self.assertEqual(correlated.correlation["nearest_marker_before"]["name"], "LOGIN_SUBMIT")
        self.assertEqual(correlated.correlation["nearest_marker_after"]["name"], "LOGIN_SUCCESS")

    # 15. correlation window dışındaki marker bağlanmaz
    def test_15_marker_outside_window_not_correlated(self):
        session = DynamicSession(
            session_id="sess-1",
            timeline=[
                TimelineEvent(
                    type=EventType.MARKER,
                    name="DISTANT_MARKER",
                    timestamp="2026-09-30T10:00:00.000Z",
                )
            ],
        )
        # Request is 10 seconds later, window is 2 seconds
        correlator = TrafficCorrelator(session=session, marker_window_ms=2000.0)
        tx = TrafficTransaction(
            capture_id="c1",
            request=HttpRequestModel(timestamp="2026-09-30T10:00:10.000Z", host="api.com"),
        )
        correlated = correlator.correlate(tx)
        self.assertNotIn("nearest_marker_before", correlated.correlation)

    # 16. traffic persistence JSONL doğru çalışır
    def test_16_traffic_persistence_jsonl(self):
        tx1 = TrafficTransaction(
            capture_id="c1",
            session_id="s1",
            request=HttpRequestModel(host="api1.com", path="/test1"),
        )
        tx2 = TrafficTransaction(
            capture_id="c1",
            session_id="s1",
            request=HttpRequestModel(host="api2.com", path="/test2"),
        )
        self.storage.append_transaction("s1", tx1)
        self.storage.append_transaction("s1", tx2)

        lines = self.storage.load_transactions("s1")
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["request"]["host"], "api1.com")
        self.assertEqual(lines[1]["request"]["host"], "api2.com")

    # 17. backend crash FAILED state üretir
    @patch.object(DeviceProxyManager, "apply_proxy")
    @patch.object(DeviceProxyManager, "restore_proxy")
    def test_17_backend_crash_leads_to_failed_state(self, mock_res, mock_app):
        mock_backend = MagicMock()
        mock_backend.start.side_effect = TrafficException(
            TrafficErrorCode.CAPTURE_PROCESS_DIED, "mitmproxy crashed"
        )
        service = DynamicTrafficService(backend=mock_backend, storage=self.storage, adb_bin="/mock/adb")

        with self.assertRaises(TrafficException):
            service.start_capture("sess-1", "dev-1")

        self.assertEqual(service.active_capture.status, CaptureStatus.FAILED)
        mock_res.assert_called()  # Proxy was rolled back

    # 18. overlapping flow correlation deterministic çalışır
    def test_18_overlapping_flows_deterministic_selection(self):
        session = DynamicSession(
            session_id="sess-1",
            flows=[
                TargetFlow(
                    flow_id="flow-outer",
                    name="outer",
                    started_at="2026-09-30T10:00:00Z",
                    ended_at="2026-09-30T10:00:30Z",
                ),
                TargetFlow(
                    flow_id="flow-inner",
                    name="inner",
                    started_at="2026-09-30T10:00:10Z",
                    ended_at="2026-09-30T10:00:20Z",
                ),
            ],
        )
        correlator = TrafficCorrelator(session=session)
        # Request at 10:00:15 falls in both outer and inner
        tx = TrafficTransaction(
            capture_id="c1",
            request=HttpRequestModel(timestamp="2026-09-30T10:00:15Z", host="api.com"),
        )
        correlated = correlator.correlate(tx)
        # Most recently started flow (inner) is deterministically selected
        self.assertEqual(correlated.flow_id, "flow-inner")
        self.assertIn("overlap_warning", correlated.correlation)


if __name__ == "__main__":
    unittest.main()
