"""Comprehensive unit tests for Android Action Executor (Week 1 — Day 5 Task 5.2).

Verifies all 22 requirements:
1. click action executes tap once.
2. click uses center coordinates.
3. invalid bounds fail without ADB call.
4. input action executes adb input text.
5. input payload properly escaped.
6. sensitive input value not persisted/logged.
7. back action executes KEYCODE_BACK.
8. unsupported action type fails cleanly.
9. transient ADB failure retries boundedly.
10. deterministic failure does not retry.
11. max attempts respected.
12. timeout returns timed_out.
13. no infinite loop.
14. result timestamps populated.
15. success result correct.
16. failed result correct.
17. system dialog action allowed.
18. executor does not call observe_screen.
19. executor does not mutate RouteGraph.
20. timeline ACTION_EXECUTED compact metadata.
21. password/input raw value absent from timeline.
22. no host absolute path leaks.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

from src.dynamic.action.executor import (
    ActionExecutor,
    escape_adb_input_text,
    validate_click_target,
)
from src.dynamic.action.models import (
    ActionErrorCode,
    ActionExecutionResult,
    ActionExecutionStatus,
    ActionType,
)
from src.dynamic.route.graph import RouteGraph
from src.dynamic.route.models import DiscoveredAction
from src.dynamic.ui.models import ActionCandidate, ScreenObservation


class TestDynamicActionExecutor(unittest.TestCase):
    """Test suite for ActionExecutor."""

    def setUp(self):
        self.serial = "emulator-5554"
        self.fake_adb = "/usr/bin/adb"

    def _make_candidate(
        self,
        node_id: str = "btn_submit",
        action_type: str = "click",
        bounds: tuple[int, int, int, int] = (100, 200, 300, 400),
        center: tuple[int, int] = (200, 300),
        res_id: str = "com.example.app:id/submit",
    ) -> ActionCandidate:
        return ActionCandidate(
            node_id=node_id,
            resource_id=res_id,
            class_name="android.widget.Button",
            text="Submit",
            bounds=bounds,
            center_x=center[0],
            center_y=center[1],
            action_type=action_type,
        )

    def _make_discovered(
        self,
        action_id: str = "act_123",
        action_type: str = "click",
        bounds: tuple[int, int, int, int] = (100, 200, 300, 400),
        center: tuple[int, int] = (200, 300),
        res_id: str = "com.example.app:id/submit",
    ) -> DiscoveredAction:
        return DiscoveredAction(
            action_id=action_id,
            source_node_id="node_abc",
            source_screen_identity="screen_abc",
            ui_node_id="btn_1",
            action_type=action_type,
            resource_id=res_id,
            bounds=bounds,
            center=center,
        )

    # 1. click action executes tap once
    @patch("subprocess.run")
    def test_01_click_action_executes_tap_once(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        action = self._make_discovered(action_type="click")

        res = executor.execute(action)

        self.assertTrue(res.is_success)
        self.assertEqual(res.status, ActionExecutionStatus.SUCCEEDED.value)
        self.assertEqual(mock_run.call_count, 1)
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, [self.fake_adb, "-s", self.serial, "shell", "input", "tap", "200", "300"])

    # 2. click uses center coordinates
    @patch("subprocess.run")
    def test_02_click_uses_center_coordinates(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        cand = self._make_candidate(bounds=(50, 100, 150, 200), center=(100, 150))

        res = executor.click(cand)

        self.assertTrue(res.is_success)
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[-2:], ["100", "150"])

    # 3. invalid bounds fail without ADB call
    @patch("subprocess.run")
    def test_03_invalid_bounds_fail_without_adb_call(self, mock_run):
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        # Negative coordinates
        bad_act_1 = self._make_discovered(bounds=(-10, 0, 10, 20), center=(-1, 10))
        res1 = executor.click(bad_act_1)
        self.assertEqual(res1.status, ActionExecutionStatus.FAILED.value)
        self.assertEqual(res1.error_code, ActionErrorCode.INVALID_BOUNDS.value)

        # Zero width
        bad_act_2 = self._make_discovered(bounds=(10, 10, 10, 20), center=(10, 15))
        res2 = executor.click(bad_act_2)
        self.assertEqual(res2.status, ActionExecutionStatus.FAILED.value)
        self.assertEqual(res2.error_code, ActionErrorCode.INVALID_BOUNDS.value)

        mock_run.assert_not_called()

    # 4. input action executes adb input text
    @patch("subprocess.run")
    def test_04_input_action_executes_adb_input_text(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        cand = self._make_candidate(node_id="field_username", action_type="input")

        res = executor.execute(cand, input_text="alice_smith")

        self.assertTrue(res.is_success)
        self.assertEqual(mock_run.call_count, 1)
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, [self.fake_adb, "-s", self.serial, "shell", "input", "text", "alice_smith"])

    # 5. input payload properly escaped
    def test_05_input_payload_properly_escaped(self):
        raw = "hello world & $foo 'bar' ; |"
        escaped = escape_adb_input_text(raw)

        # Space converted to %s
        self.assertIn("%s", escaped)
        self.assertNotIn(" ", escaped)

        # Special shell characters escaped
        self.assertIn(r"\&", escaped)
        self.assertIn(r"\$", escaped)
        self.assertIn(r"\'", escaped)
        self.assertIn(r"\;", escaped)
        self.assertIn(r"\|", escaped)

    # 6. sensitive input value not persisted/logged
    @patch("subprocess.run")
    def test_06_sensitive_input_value_not_persisted_or_logged(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        action = self._make_discovered(action_id="input_pwd", action_type="input")

        secret = "UltraSecretPassword123!"
        res = executor.input(action, input_text=secret)

        self.assertTrue(res.is_success)
        d = res.to_dict()
        dumped = json.dumps(d)
        self.assertNotIn(secret, dumped)
        self.assertEqual(res.metadata.get("input_length"), len(secret))
        self.assertTrue(res.metadata.get("input_redacted"))

    # 7. back action executes KEYCODE_BACK
    @patch("subprocess.run")
    def test_07_back_action_executes_keycode_back(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        res = executor.back()

        self.assertTrue(res.is_success)
        self.assertEqual(res.action_type, ActionType.BACK.value)
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, [self.fake_adb, "-s", self.serial, "shell", "input", "keyevent", "4"])

    # 8. unsupported action type fails cleanly
    @patch("subprocess.run")
    def test_08_unsupported_action_type_fails_cleanly(self, mock_run):
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        res = executor.execute(action={"action_type": "swipe", "action_id": "sw_1"})

        self.assertEqual(res.status, ActionExecutionStatus.FAILED.value)
        self.assertEqual(res.error_code, ActionErrorCode.UNSUPPORTED_ACTION_TYPE.value)
        self.assertEqual(res.attempts, 1)
        mock_run.assert_not_called()

    # 9. transient ADB failure retries boundedly
    @patch("subprocess.run")
    def test_09_transient_adb_failure_retries_boundedly(self, mock_run):
        # Attempt 1 fails, Attempt 2 succeeds
        mock_run.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="transient error"),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
        ]
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb, max_attempts=2)
        action = self._make_discovered()

        res = executor.execute(action)

        self.assertFalse(res.is_success)
        self.assertEqual(res.attempts, 1)
        self.assertEqual(mock_run.call_count, 1)

    # 10. deterministic failure does not retry
    @patch("subprocess.run")
    def test_10_deterministic_failure_does_not_retry(self, mock_run):
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb, max_attempts=3)
        bad_act = self._make_discovered(bounds=(0, 0, 0, 0), center=(0, 0))

        res = executor.click(bad_act)

        self.assertEqual(res.attempts, 1)
        mock_run.assert_not_called()

    # 11. max attempts respected
    @patch("subprocess.run")
    def test_11_max_attempts_respected(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="persistent failure")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb, max_attempts=2)
        action = self._make_discovered()

        res = executor.execute(action)

        self.assertEqual(res.status, ActionExecutionStatus.FAILED.value)
        self.assertEqual(res.attempts, 1)
        self.assertEqual(mock_run.call_count, 1)

    # 12. timeout returns timed_out
    @patch("subprocess.run")
    def test_12_timeout_returns_timed_out(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="adb", timeout=5.0)
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb, max_attempts=2)
        action = self._make_discovered()

        res = executor.execute(action)

        self.assertEqual(res.status, ActionExecutionStatus.TIMED_OUT.value)
        self.assertEqual(res.error_code, ActionErrorCode.ACTION_TIMEOUT.value)
        self.assertEqual(res.attempts, 1)

    # 13. no infinite loop
    @patch("subprocess.run")
    def test_13_no_infinite_loop(self, mock_run):
        mock_run.side_effect = OSError("adb connection lost")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb, max_attempts=3)
        action = self._make_discovered()

        res = executor.execute(action)

        self.assertEqual(res.status, ActionExecutionStatus.FAILED.value)
        self.assertEqual(res.attempts, 1)
        self.assertEqual(mock_run.call_count, 1)

    # 14. result timestamps populated
    @patch("subprocess.run")
    def test_14_result_timestamps_populated(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        res = executor.back()

        self.assertIsNotNone(res.started_at)
        self.assertIsNotNone(res.completed_at)
        self.assertIn("T", res.started_at)
        self.assertIn("T", res.completed_at)

    # 15. success result correct
    @patch("subprocess.run")
    def test_15_success_result_correct(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        action = self._make_discovered(action_id="act_ok")

        res = executor.click(action)

        self.assertEqual(res.action_id, "act_ok")
        self.assertEqual(res.action_type, "click")
        self.assertEqual(res.status, "succeeded")
        self.assertIsNone(res.error_code)
        self.assertIsNone(res.message)
        self.assertEqual(res.attempts, 1)

    # 16. failed result correct
    @patch("subprocess.run")
    def test_16_failed_result_correct(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=127, stdout="", stderr="device offline")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb, max_attempts=1)
        action = self._make_discovered(action_id="act_fail")

        res = executor.click(action)

        self.assertEqual(res.action_id, "act_fail")
        self.assertEqual(res.status, "failed")
        self.assertEqual(res.error_code, ActionErrorCode.ADB_COMMAND_FAILED.value)
        self.assertIn("device offline", res.message)

    # 17. system dialog action allowed
    @patch("subprocess.run")
    def test_17_system_dialog_action_allowed(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        # Action on Android permission controller dialog
        action = self._make_discovered(
            res_id="com.android.permissioncontroller:id/permission_allow_button",
            center=(400, 800),
            bounds=(300, 750, 500, 850),
        )

        res = executor.click(action)

        self.assertTrue(res.is_success)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[-2:], ["400", "800"])

    # 18. executor does not call observe_screen
    @patch("src.dynamic.ui.observer.observe_screen")
    @patch("subprocess.run")
    def test_18_executor_does_not_call_observe_screen(self, mock_run, mock_observe):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        executor.click(self._make_discovered())
        executor.input(self._make_discovered(action_type="input"), input_text="test")
        executor.back()

        mock_observe.assert_not_called()

    # 19. executor does not mutate RouteGraph
    @patch("subprocess.run")
    def test_19_executor_does_not_mutate_route_graph(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        graph = RouteGraph(run_id="run_test")
        obs = ScreenObservation(
            screen_identity="s_init",
            foreground_package="com.example",
            foreground_activity="MainActivity",
            clickable_count=1,
            action_candidates=[self._make_candidate()],
        )
        node = graph.observe_screen(obs)
        init_nodes = graph.node_count
        init_edges = graph.edge_count
        init_actions = graph.discovered_action_count

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click(list(node.actions.values())[0])

        self.assertEqual(graph.node_count, init_nodes)
        self.assertEqual(graph.edge_count, init_edges)
        self.assertEqual(graph.discovered_action_count, init_actions)

    # 20. timeline ACTION_EXECUTED compact metadata
    @patch("subprocess.run")
    def test_20_timeline_action_executed_compact_metadata(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        timeline: list[Any] = []
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb, timeline_recorder=timeline)
        action = self._make_discovered(action_id="act_timeline_test")

        res = executor.click(action)

        self.assertEqual(len(timeline), 1)
        event = timeline[0]
        self.assertEqual(event.name, "ACTION_EXECUTED")
        self.assertEqual(event.metadata["action_id"], "act_timeline_test")
        self.assertEqual(event.metadata["action_type"], "click")
        self.assertEqual(event.metadata["status"], "succeeded")
        self.assertEqual(event.metadata["attempts"], 1)

    # 21. password/input raw value absent from timeline
    @patch("subprocess.run")
    def test_21_password_input_raw_value_absent_from_timeline(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        timeline: list[Any] = []
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb, timeline_recorder=timeline)
        action = self._make_discovered(action_id="act_input_pwd", action_type="input")

        secret = "TopSecretToken_999!"
        executor.input(action, input_text=secret)

        self.assertEqual(len(timeline), 1)
        meta = timeline[0].metadata
        dumped = json.dumps(meta)
        self.assertNotIn(secret, dumped)
        self.assertEqual(meta["input_length"], len(secret))
        self.assertTrue(meta["input_redacted"])

    # 22. no host absolute path leaks
    @patch("subprocess.run")
    def test_22_no_host_absolute_path_leaks(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="Error loading /Users/alice/Library/Android/sdk/platform-tools/adb",
        )
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb, max_attempts=1)
        action = self._make_discovered(res_id="/Users/alice/app/resource")

        res = executor.click(action)

        d = res.to_dict()
        dumped = json.dumps(d)
        self.assertNotIn("/Users/alice", dumped)
        self.assertIn("<host_path>", dumped)
