"""Unit tests for Dynamic Session Manager & Target Flow Recording."""

import json
import os
import shutil
import tempfile
import unittest

from src.dynamic.preflight.models import (
    ApplicationInfo,
    DeviceInfo,
    PreflightResult,
    PreflightStatus,
)
from src.dynamic.session.flow_recorder import sanitize_metadata
from src.dynamic.session.manager import DynamicSessionManager
from src.dynamic.session.models import (
    EventType,
    FlowStatus,
    SessionErrorCode,
    SessionException,
    SessionStatus,
)
from src.dynamic.session.storage import SessionStorage


class TestDynamicSession(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_dynamic_sessions_")
        self.storage = SessionStorage(base_dir=self.test_dir)
        self.manager = DynamicSessionManager(storage=self.storage)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_pass_preflight_starts_session(self):
        preflight = PreflightResult(
            device=DeviceInfo(connected=True, serial="dev-1"),
            application=ApplicationInfo(package_name="com.test.app"),
            status=PreflightStatus.PASS,
        )
        session = self.manager.start_session("com.test.app", "dev-1", preflight_result=preflight)
        self.assertEqual(session.status, SessionStatus.ACTIVE)
        self.assertEqual(session.preflight_status, "PASS")
        self.assertEqual(session.warnings, [])

    def test_02_warn_preflight_starts_session_and_preserves_warnings(self):
        preflight = PreflightResult(
            device=DeviceInfo(connected=True, serial="emulator-5554", is_emulator=True),
            application=ApplicationInfo(package_name="com.test.app"),
            status=PreflightStatus.WARN,
            warnings=["Emulator detected", "Root signal detected"],
        )
        session = self.manager.start_session("com.test.app", "emulator-5554", preflight_result=preflight)
        self.assertEqual(session.status, SessionStatus.ACTIVE)
        self.assertEqual(session.preflight_status, "WARN")
        self.assertIn("Emulator detected", session.warnings)
        self.assertIn("Root signal detected", session.warnings)

    def test_03_fail_preflight_blocks_session_start(self):
        preflight = PreflightResult(
            status=PreflightStatus.FAIL,
            errors=[{"code": "APP_CRASHED", "message": "Immediate crash"}],
        )
        with self.assertRaises(SessionException) as ctx:
            self.manager.start_session("com.test.app", "dev-1", preflight_result=preflight)
        self.assertEqual(ctx.exception.error_code, SessionErrorCode.PREFLIGHT_FAILED)

    def test_04_flow_creation_success(self):
        self.manager.start_session("com.test.app", "dev-1")
        flow_rec = self.manager.start_flow("login", "User login")
        self.assertEqual(flow_rec.name, "login")
        self.assertEqual(flow_rec.status, FlowStatus.ACTIVE)
        self.assertEqual(len(self.manager.session.flows), 1)

    def test_05_events_added_to_timeline(self):
        self.manager.start_session("com.test.app", "dev-1")
        flow = self.manager.start_flow("checkout")
        action = flow.record_action("tap_button", {"btn_id": "pay"})
        self.assertEqual(action.type, EventType.USER_ACTION)
        self.assertEqual(action.name, "tap_button")

        timeline = self.manager.get_timeline()
        action_events = [e for e in timeline if e["name"] == "tap_button"]
        self.assertEqual(len(action_events), 1)
        self.assertEqual(action_events[0]["metadata"]["btn_id"], "pay")

    def test_06_markers_recorded_accurately(self):
        self.manager.start_session("com.test.app", "dev-1")
        flow = self.manager.start_flow("onboarding")
        marker = flow.add_marker("WELCOME_SCREEN_DISPLAYED")
        self.assertEqual(marker.type, EventType.MARKER)
        self.assertEqual(marker.name, "WELCOME_SCREEN_DISPLAYED")

        timeline = self.manager.get_timeline()
        marker_events = [e for e in timeline if e["type"] == "MARKER"]
        self.assertEqual(len(marker_events), 1)
        self.assertEqual(marker_events[0]["name"], "WELCOME_SCREEN_DISPLAYED")

    def test_07_completed_flow_rejects_new_events(self):
        self.manager.start_session("com.test.app", "dev-1")
        flow = self.manager.start_flow("profile")
        flow.record_action("view_profile")
        flow.complete()

        with self.assertRaises(SessionException) as ctx:
            flow.record_action("edit_avatar")
        self.assertEqual(ctx.exception.error_code, SessionErrorCode.FLOW_ALREADY_COMPLETED)

    def test_08_completed_session_cannot_be_recompleted(self):
        self.manager.start_session("com.test.app", "dev-1")
        self.manager.complete_session()

        with self.assertRaises(SessionException) as ctx:
            self.manager.complete_session()
        self.assertEqual(ctx.exception.error_code, SessionErrorCode.SESSION_ALREADY_COMPLETED)

    def test_09_json_persistence_atomic_and_readable(self):
        session = self.manager.start_session("com.test.app", "dev-1")
        flow = self.manager.start_flow("search")
        flow.record_action("type_query", {"query": "security"})
        flow.complete()
        self.manager.complete_session()

        saved_session = self.storage.load_session(session.session_id)
        saved_timeline = self.storage.load_timeline(session.session_id)

        self.assertEqual(saved_session["session_id"], session.session_id)
        self.assertEqual(saved_session["status"], "COMPLETED")
        self.assertEqual(len(saved_session["flows"]), 1)
        self.assertEqual(saved_session["flows"][0]["name"], "search")
        self.assertTrue(len(saved_timeline) >= 3)  # SESSION_STARTED, FLOW_STARTED, type_query, SESSION_COMPLETED

    def test_10_sensitive_metadata_redacted(self):
        raw_meta = {
            "user": "alice",
            "password": "ClearTextPassword123!",
            "auth_token": "Bearer secret_jwt_value",
            "api_key": "xyz987",
            "cookie": "session_id=123",
            "nested": {
                "secret_key": "super_secret",
                "normal_field": "ok",
            },
        }
        sanitized = sanitize_metadata(raw_meta)
        self.assertEqual(sanitized["user"], "alice")
        self.assertEqual(sanitized["password"], "[REDACTED]")
        self.assertEqual(sanitized["auth_token"], "[REDACTED]")
        self.assertEqual(sanitized["api_key"], "[REDACTED]")
        self.assertEqual(sanitized["cookie"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["secret_key"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["normal_field"], "ok")

    def test_11_invalid_state_transition_raises_error(self):
        session = self.manager.start_session("com.test.app", "dev-1")
        flow = self.manager.start_flow("cart")
        flow.abort(reason="User cancelled")

        # Aborting again
        with self.assertRaises(SessionException) as ctx:
            flow.abort()
        self.assertEqual(ctx.exception.error_code, SessionErrorCode.INVALID_STATE_TRANSITION)

    def test_12_multiple_flows_maintain_chronological_timeline(self):
        self.manager.start_session("com.test.app", "dev-1")

        f1 = self.manager.start_flow("flow_1")
        f1.add_marker("F1_MARK")
        f1.complete()

        f2 = self.manager.start_flow("flow_2")
        f2.add_marker("F2_MARK")
        f2.complete()

        timeline = self.manager.get_timeline()
        timestamps = [e["timestamp"] for e in timeline]
        # Verify strictly chronological
        self.assertEqual(timestamps, sorted(timestamps))
        names = [e["name"] for e in timeline]
        self.assertIn("SESSION_STARTED", names)
        self.assertIn("F1_MARK", names)
        self.assertIn("F2_MARK", names)


if __name__ == "__main__":
    unittest.main()
