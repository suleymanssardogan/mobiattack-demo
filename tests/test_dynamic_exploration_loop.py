"""Comprehensive unit tests for Bounded Dynamic Exploration Loop V1 (Week 1 — Day 5 Task 5.3).

Verifies all 32 requirements:
1. initial screen observed and root created.
2. deterministic first unattempted click selected.
3. action marked attempted before execution.
4. successful click marked succeeded.
5. failed action marked failed.
6. post-action screen observation occurs after success.
7. changed screen creates transition edge.
8. same screen creates self-loop.
9. duplicate screen does not create duplicate node.
10. same attempted action not executed twice.
11. newly discovered action on revisited screen can be executed.
12. input actions not auto-executed.
13. destructive labeled action skipped.
14. external unrelated package stops branch/exploration safely.
15. system dialog observation accepted.
16. max_steps stops loop.
17. max_depth respected.
18. deadline respected.
19. no_actions stops cleanly.
20. action timeout does not infinite loop.
21. observation failure after successful action produces no fake edge.
22. route_graph persisted after initial observation.
23. graph persisted after action status mutation.
24. graph persisted after transition.
25. timeline exploration events compact.
26. raw XML not persisted.
27. passwords/raw input not persisted.
28. partial graph survives raised exception.
29. executor called only for selected click actions.
30. no ADB real device required.
31. loop does not create dynamic_analysis_report.json.
32. loop does not mark dynamic stage completed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

from src.dynamic.action.executor import ActionExecutor
from src.dynamic.action.models import (
    ActionErrorCode,
    ActionExecutionResult,
    ActionExecutionStatus,
)
from src.dynamic.exploration.loop import run_exploration, select_next_action
from src.dynamic.exploration.models import (
    ALLOWED_PERMISSION_PACKAGES,
    ExplorationLimits,
    ExplorationResult,
    ExplorationStatus,
    StopReason,
    is_allowed_exploration_surface,
    is_allowed_system_dialog,
    is_destructive_action,
    is_safe_clickable_action,
)
from src.dynamic.route.graph import RouteGraph
from src.dynamic.route.models import ActionStatus, DiscoveredAction, RouteNode
from src.dynamic.route.storage import RouteGraphStorage
from src.dynamic.ui.models import ActionCandidate, ScreenObservation
from src.scan_state import create_initial_scan_state, load_scan_state, save_scan_state


def _make_candidate(
    node_id: str = "btn_1",
    action_type: str = "click",
    text: str = "Click Me",
    bounds: tuple[int, int, int, int] = (10, 20, 100, 60),
    res_id: str = "com.example.app:id/btn",
) -> ActionCandidate:
    cx = (bounds[0] + bounds[2]) // 2
    cy = (bounds[1] + bounds[3]) // 2
    return ActionCandidate(
        node_id=node_id,
        resource_id=res_id,
        class_name="android.widget.Button",
        text=text,
        content_desc="Open informational screen",
        bounds=bounds,
        center_x=cx,
        center_y=cy,
        action_type=action_type,
    )


def _make_obs(
    screen_identity: str = "s_root",
    pkg: str = "com.example.app",
    activity: str = "com.example.app.MainActivity",
    is_target_pkg: bool = True,
    is_dialog: bool = False,
    actions: list[ActionCandidate] | None = None,
) -> ScreenObservation:
    cands = actions or []
    return ScreenObservation(
        screen_identity=screen_identity,
        foreground_package=pkg,
        foreground_activity=activity,
        target_package="com.example.app",
        is_target_package=is_target_pkg,
        is_dialog_or_system=is_dialog,
        clickable_count=sum(1 for a in cands if a.action_type == "click"),
        input_count=sum(1 for a in cands if a.action_type == "input"),
        action_candidates=cands,
    )


class TestDynamicExplorationLoop(unittest.TestCase):
    """Test suite for Bounded Dynamic Exploration Loop V1."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)
        self.serial = "emulator-5554"
        self.fake_adb = "/usr/bin/adb"

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. initial screen observed and root created
    def test_01_initial_screen_observed_and_root_created(self):
        graph = RouteGraph(run_id="run_1")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        obs = _make_obs(screen_identity="s_init")

        res = run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            sleeper=lambda s: None,
        )

        self.assertEqual(graph.node_count, 1)
        self.assertEqual(graph.root_node_id, graph.current_node_id)
        self.assertEqual(res.screens_observed, 1)

    # 2. deterministic first unattempted click selected
    def test_02_deterministic_first_unattempted_click_selected(self):
        btn_z = _make_candidate(node_id="btn_z")
        btn_a = _make_candidate(node_id="btn_a")
        obs = _make_obs(actions=[btn_z, btn_a])
        node = RouteNode.from_observation(obs)

        # select_next_action should sort by action_id ascending
        selected = select_next_action(node)
        self.assertIsNotNone(selected)
        expected_first = sorted(node.actions.values(), key=lambda a: a.action_id)[0]
        self.assertEqual(selected.action_id, expected_first.action_id)

    # 3. action marked attempted before execution
    def test_03_action_marked_attempted_before_execution(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_1")
        obs1 = _make_obs(screen_identity="s1", actions=[btn])
        obs2 = _make_obs(screen_identity="s2")

        observations = [obs1, obs2]
        action_statuses_during_exec = []

        def fake_click(action, **kwargs):
            action_statuses_during_exec.append(action.status)
            return ActionExecutionResult(
                action_id=action.action_id,
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(side_effect=fake_click)

        run_exploration(
            observer=lambda: observations.pop(0) if observations else obs2,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
        )

        self.assertEqual(action_statuses_during_exec, [ActionStatus.ATTEMPTED.value])

    # 4. successful click marked succeeded
    def test_04_successful_click_marked_succeeded(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_ok")
        obs1 = _make_obs(screen_identity="s1", actions=[btn])
        obs2 = _make_obs(screen_identity="s2")

        observations = [obs1, obs2]
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_ok",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        res = run_exploration(
            observer=lambda: observations.pop(0) if observations else obs2,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
        )

        node = graph.get_node_by_identity("s1")
        action = list(node.actions.values())[0]
        self.assertEqual(action.status, ActionStatus.SUCCEEDED.value)
        self.assertEqual(res.actions_succeeded, 1)

    # 5. failed action marked failed
    def test_05_failed_action_marked_failed(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_fail")
        obs = _make_obs(screen_identity="s1", actions=[btn])

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_fail",
                action_type="click",
                status=ActionExecutionStatus.FAILED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
                error_code="ADB_COMMAND_FAILED",
                message="device offline",
            )
        )

        res = run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
        )

        node = graph.get_node_by_identity("s1")
        action = list(node.actions.values())[0]
        self.assertEqual(action.status, ActionStatus.FAILED.value)
        self.assertEqual(res.actions_failed, 1)

    # 6. post-action screen observation occurs after success
    def test_06_post_action_screen_observation_occurs_after_success(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_1")
        obs1 = _make_obs(screen_identity="s1", actions=[btn])
        obs2 = _make_obs(screen_identity="s2")

        obs_calls = []

        def fake_observe():
            if not obs_calls:
                obs_calls.append("initial")
                return obs1
            obs_calls.append("post_action")
            return obs2

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_1",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        run_exploration(
            observer=fake_observe,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
        )

        self.assertEqual(obs_calls, ["initial", "post_action"])

    # 7. changed screen creates transition edge
    def test_07_changed_screen_creates_transition_edge(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_next")
        obs1 = _make_obs(screen_identity="screen_A", actions=[btn])
        obs2 = _make_obs(screen_identity="screen_B")
        seq = [obs1, obs2]

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_next",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        res = run_exploration(
            observer=lambda: seq.pop(0) if seq else obs2,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
        )

        self.assertEqual(graph.node_count, 2)
        self.assertEqual(graph.edge_count, 1)
        self.assertEqual(res.transitions_recorded, 1)
        edge = list(graph.edges.values())[0]
        self.assertNotEqual(edge.source_node_id, edge.target_node_id)

    # 8. same screen creates self-loop
    def test_08_same_screen_creates_self_loop(self):
        graph = RouteGraph()
        toggle = _make_candidate(node_id="switch_1")
        obs_a = _make_obs(screen_identity="screen_settings", actions=[toggle])

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_toggle",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        res = run_exploration(
            observer=lambda: obs_a,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
            no_navigation_postcondition=lambda obs: obs.screen_identity == "screen_settings",
        )

        self.assertEqual(graph.node_count, 1)
        self.assertEqual(graph.edge_count, 1)
        edge = list(graph.edges.values())[0]
        self.assertEqual(edge.source_node_id, edge.target_node_id)

    # 9. duplicate screen does not create duplicate node
    def test_09_duplicate_screen_does_not_create_duplicate_node(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_loop")
        obs = _make_obs(screen_identity="screen_revisited", actions=[btn])

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_1",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=2),
            sleeper=lambda s: None,
        )

        self.assertEqual(graph.node_count, 1)

    # 10. same attempted action not executed twice
    def test_10_same_attempted_action_not_executed_twice(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_once")
        obs = _make_obs(screen_identity="screen_a", actions=[btn])

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_once",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        res = run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=5),
            sleeper=lambda s: None,
            no_navigation_postcondition=lambda obs: True,
        )

        # Should execute btn_once once, then halt because no more unattempted actions
        self.assertEqual(executor.click.call_count, 1)
        self.assertEqual(res.stop_reason, StopReason.NO_ACTIONS.value)

    # 11. newly discovered action on revisited screen can be executed
    def test_11_newly_discovered_action_on_revisited_screen_can_be_executed(self):
        graph = RouteGraph()
        btn1 = _make_candidate(node_id="btn_step1")
        btn2 = _make_candidate(node_id="btn_step2")
        obs_initial = _make_obs(screen_identity="screen_dyn", actions=[btn1])
        obs_revisited = _make_obs(screen_identity="screen_dyn", actions=[btn1, btn2])

        seq = [obs_initial, obs_revisited, obs_revisited]

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_ok",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        res = run_exploration(
            observer=lambda: seq.pop(0) if seq else obs_revisited,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=5),
            sleeper=lambda s: None,
            no_navigation_postcondition=lambda obs: True,
        )

        self.assertEqual(executor.click.call_count, 2)
        self.assertEqual(res.actions_succeeded, 2)

    # 12. input actions not auto-executed
    def test_12_input_actions_not_auto_executed(self):
        graph = RouteGraph()
        inp = _make_candidate(node_id="edit_text", action_type="input")
        obs = _make_obs(screen_identity="screen_login", actions=[inp])

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock()

        res = run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            sleeper=lambda s: None,
        )

        # Input action must NOT be executed in V1
        executor.click.assert_not_called()
        self.assertEqual(res.steps_attempted, 0)
        self.assertEqual(res.stop_reason, StopReason.UNSAFE_ACTION_BOUNDARY.value)

    # 13. destructive labeled action skipped
    def test_13_destructive_labeled_action_skipped(self):
        graph = RouteGraph()
        btn_del = _make_candidate(node_id="btn_del", text="Delete Account")
        obs = _make_obs(screen_identity="screen_danger", actions=[btn_del])

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock()

        res = run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            sleeper=lambda s: None,
        )

        executor.click.assert_not_called()
        self.assertEqual(res.stop_reason, StopReason.UNSAFE_ACTION_BOUNDARY.value)
        # Action remains discovered in graph
        node = graph.get_node_by_identity("screen_danger")
        act = list(node.actions.values())[0]
        self.assertEqual(act.status, ActionStatus.DISCOVERED.value)

    # 14. external unrelated package stops branch/exploration safely
    def test_14_external_unrelated_package_stops_branch_safely(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_browser")
        obs_internal = _make_obs(screen_identity="s_app", is_target_pkg=True, actions=[btn])
        obs_external = _make_obs(
            screen_identity="s_chrome",
            pkg="com.android.chrome",
            is_target_pkg=False,
            is_dialog=False,
        )
        seq = [obs_internal, obs_external]

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_browser",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        res = run_exploration(
            observer=lambda: seq.pop(0) if seq else obs_external,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=5, stop_on_external_package=True),
            sleeper=lambda s: None,
        )

        self.assertEqual(res.stop_reason, StopReason.EXTERNAL_PACKAGE.value)
        self.assertEqual(graph.node_count, 2)

    # 15. system dialog observation accepted
    def test_15_system_dialog_observation_accepted(self):
        graph = RouteGraph()
        btn_perm = _make_candidate(node_id="btn_allow", text="Cancel")
        obs_dialog = _make_obs(
            screen_identity="s_perm_dialog",
            pkg="com.google.android.permissioncontroller",
            is_target_pkg=False,
            is_dialog=True,
            actions=[btn_perm],
        )

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_allow",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        res = run_exploration(
            observer=lambda: obs_dialog,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
        )

        # Dialog should be accepted and click allowed
        self.assertEqual(executor.click.call_count, 1)
        self.assertTrue(graph.get_node_by_identity("s_perm_dialog").is_dialog_or_system)

    # 16. max_steps stops loop
    def test_16_max_steps_stops_loop(self):
        graph = RouteGraph()
        obs = _make_obs(
            screen_identity="s_many",
            actions=[_make_candidate(node_id=f"btn_{i}") for i in range(10)],
        )

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_ok",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        res = run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=3),
            sleeper=lambda s: None,
            no_navigation_postcondition=lambda obs: True,
        )

        self.assertEqual(res.steps_attempted, 3)
        self.assertEqual(res.stop_reason, StopReason.MAX_STEPS.value)

    # 17. max_depth respected
    def test_17_max_depth_respected(self):
        graph = RouteGraph()
        # Screens A -> B -> C -> D
        obs_a = _make_obs(screen_identity="s_A", actions=[_make_candidate(node_id="btn_a")])
        obs_b = _make_obs(screen_identity="s_B", actions=[_make_candidate(node_id="btn_b")])
        obs_c = _make_obs(screen_identity="s_C", actions=[_make_candidate(node_id="btn_c")])
        obs_d = _make_obs(screen_identity="s_D", actions=[_make_candidate(node_id="btn_d")])
        seq = [obs_a, obs_b, obs_c, obs_d]

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_ok",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        # Depth: Root=0 (s_A), s_B=1, s_C=2. When max_depth=2, s_C depth=2 reached -> stop
        res = run_exploration(
            observer=lambda: seq.pop(0) if seq else obs_d,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_depth=2, max_steps=10),
            sleeper=lambda s: None,
        )

        self.assertEqual(res.stop_reason, StopReason.MAX_DEPTH.value)

    # 18. deadline respected
    def test_18_deadline_respected(self):
        graph = RouteGraph()
        obs = _make_obs(screen_identity="s_loop", actions=[_make_candidate(node_id=f"btn_{i}") for i in range(5)])

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_ok",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        # Mock clock advancing past deadline
        time_values = [0.0, 1.0, 15.0]  # First check, second step, deadline exceeded

        def mock_clock():
            return time_values.pop(0) if time_values else 20.0

        res = run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(deadline_seconds=10.0, max_steps=10),
            clock=mock_clock,
            sleeper=lambda s: None,
        )

        self.assertEqual(res.stop_reason, StopReason.DEADLINE.value)

    # 19. no_actions stops cleanly
    def test_19_no_actions_stops_cleanly(self):
        graph = RouteGraph()
        obs = _make_obs(screen_identity="s_empty", actions=[])
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        res = run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            sleeper=lambda s: None,
        )

        self.assertEqual(res.stop_reason, StopReason.NO_ACTIONS.value)
        self.assertEqual(res.steps_attempted, 0)

    # 20. action timeout does not infinite loop
    def test_20_action_timeout_does_not_infinite_loop(self):
        graph = RouteGraph()
        obs = _make_obs(screen_identity="s_timeout", actions=[_make_candidate(node_id="btn_slow")])

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_slow",
                action_type="click",
                status=ActionExecutionStatus.TIMED_OUT.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:05+00:00",
                error_code=ActionErrorCode.ACTION_TIMEOUT.value,
                message="Timed out",
            )
        )

        res = run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=5),
            sleeper=lambda s: None,
        )

        self.assertEqual(res.actions_failed, 1)
        self.assertEqual(executor.click.call_count, 1)
        self.assertEqual(res.stop_reason, StopReason.OBSERVATION_FAILED.value)

    # 21. observation failure after successful action produces no fake edge
    def test_21_observation_failure_after_successful_action_produces_no_fake_edge(self):
        graph = RouteGraph()
        obs1 = _make_obs(screen_identity="s_init", actions=[_make_candidate(node_id="btn_crash")])

        obs_count = 0

        def observe_then_fail():
            nonlocal obs_count
            obs_count += 1
            if obs_count == 1:
                return obs1
            raise RuntimeError("UI dump crashed")

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_crash",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        res = run_exploration(
            observer=observe_then_fail,
            executor=executor,
            route_graph=graph,
            sleeper=lambda s: None,
        )

        self.assertEqual(graph.edge_count, 0)
        self.assertEqual(res.stop_reason, StopReason.OBSERVATION_FAILED.value)

    # 22. route_graph persisted after initial observation
    def test_22_route_graph_persisted_after_initial_observation(self):
        storage = RouteGraphStorage(base_dir=self.output_dir)
        graph = RouteGraph(run_id="persist_init")
        obs = _make_obs(screen_identity="s_persist")

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            graph_storage=storage,
            sleeper=lambda s: None,
        )

        graph_file = self.output_dir / "dynamic" / "route_graph.json"
        self.assertTrue(graph_file.is_file())

    # 23. graph persisted after action status mutation
    def test_23_graph_persisted_after_action_status_mutation(self):
        storage = RouteGraphStorage(base_dir=self.output_dir)
        graph = RouteGraph(run_id="persist_mut")
        btn = _make_candidate(node_id="btn_1")
        obs = _make_obs(screen_identity="s1", actions=[btn])

        save_calls = []
        original_save = storage.save_graph

        def spy_save(g, **kwargs):
            save_calls.append(len(save_calls) + 1)
            return original_save(g, **kwargs)

        storage.save_graph = MagicMock(side_effect=spy_save)

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_1",
                action_type="click",
                status=ActionExecutionStatus.FAILED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            graph_storage=storage,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
        )

        # Expected saves: initial obs, marked attempted, marked failed, completion
        self.assertGreaterEqual(len(save_calls), 3)

    # 24. graph persisted after transition
    def test_24_graph_persisted_after_transition(self):
        storage = RouteGraphStorage(base_dir=self.output_dir)
        graph = RouteGraph(run_id="persist_trans")
        btn = _make_candidate(node_id="btn_1")
        obs1 = _make_obs(screen_identity="s1", actions=[btn])
        obs2 = _make_obs(screen_identity="s2")
        seq = [obs1, obs2]

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_1",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        run_exploration(
            observer=lambda: seq.pop(0) if seq else obs2,
            executor=executor,
            route_graph=graph,
            graph_storage=storage,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
        )

        loaded = storage.load_graph(self.output_dir / "dynamic" / "route_graph.json")
        self.assertEqual(loaded.edge_count, 1)

    # 25. timeline exploration events compact
    def test_25_timeline_exploration_events_compact(self):
        timeline: list[Any] = []
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_compact")
        obs1 = _make_obs(screen_identity="s_init", actions=[btn])
        obs2 = _make_obs(screen_identity="s_next")
        seq = [obs1, obs2]

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_c",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )

        run_exploration(
            observer=lambda: seq.pop(0) if seq else obs2,
            executor=executor,
            route_graph=graph,
            timeline_recorder=timeline,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
        )

        event_names = [e.name for e in timeline]
        self.assertIn("EXPLORATION_STARTED", event_names)
        self.assertIn("ACTION_SELECTED", event_names)
        self.assertIn("SCREEN_OBSERVED", event_names)
        self.assertIn("ROUTE_TRANSITION_RECORDED", event_names)
        self.assertIn("EXPLORATION_COMPLETED", event_names)

        # Compactness: no full element trees or dumps
        for e in timeline:
            self.assertNotIn("nodes", e.metadata)
            self.assertNotIn("raw_xml", e.metadata)

    # 26. raw XML not persisted
    def test_26_raw_xml_not_persisted(self):
        storage = RouteGraphStorage(base_dir=self.output_dir)
        graph = RouteGraph(run_id="xml_check")
        obs = _make_obs(screen_identity="s_xml")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            graph_storage=storage,
            sleeper=lambda s: None,
        )

        graph_file = self.output_dir / "dynamic" / "route_graph.json"
        content = graph_file.read_text(encoding="utf-8")
        self.assertNotIn("<hierarchy", content)
        self.assertNotIn("<?xml", content)

    # 27. passwords/raw input not persisted
    def test_27_passwords_raw_input_not_persisted(self):
        storage = RouteGraphStorage(base_dir=self.output_dir)
        graph = RouteGraph(run_id="pwd_check")
        pwd_candidate = _make_candidate(
            node_id="edit_password",
            action_type="input",
            text="VerySecretPassword123!",
            res_id="com.example:id/password",
        )
        obs = _make_obs(screen_identity="s_pwd", actions=[pwd_candidate])
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            graph_storage=storage,
            sleeper=lambda s: None,
        )

        graph_file = self.output_dir / "dynamic" / "route_graph.json"
        content = graph_file.read_text(encoding="utf-8")
        self.assertNotIn("VerySecretPassword123!", content)

    # 28. partial graph survives raised exception
    def test_28_partial_graph_survives_raised_exception(self):
        storage = RouteGraphStorage(base_dir=self.output_dir)
        graph = RouteGraph(run_id="crash_test")
        btn = _make_candidate(node_id="btn_boom")
        obs = _make_obs(screen_identity="s_crash", actions=[btn])

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(side_effect=RuntimeError("Unrecoverable device glitch"))

        res = run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            graph_storage=storage,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
        )

        self.assertEqual(res.status, ExplorationStatus.FAILED.value)
        # Graph file must exist on disk with root node preserved
        graph_file = self.output_dir / "dynamic" / "route_graph.json"
        self.assertTrue(graph_file.is_file())
        loaded = storage.load_graph(graph_file)
        self.assertEqual(loaded.node_count, 1)

    # 29. executor called only for selected click actions
    def test_29_executor_called_only_for_selected_click_actions(self):
        graph = RouteGraph()
        btn1 = _make_candidate(node_id="btn_click", action_type="click")
        inp = _make_candidate(node_id="field_inp", action_type="input")
        obs = _make_obs(screen_identity="s_mixed", actions=[btn1, inp])

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(
            return_value=ActionExecutionResult(
                action_id="act_1",
                action_type="click",
                status=ActionExecutionStatus.SUCCEEDED.value,
                started_at="2026-10-01T10:00:00+00:00",
                completed_at="2026-10-01T10:00:01+00:00",
            )
        )
        executor.input = MagicMock()

        run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=5),
            sleeper=lambda s: None,
        )

        # Only click executed once, input never called
        self.assertEqual(executor.click.call_count, 1)
        executor.input.assert_not_called()

    # 30. no ADB real device required
    @patch("subprocess.run")
    def test_30_no_adb_real_device_required(self, mock_subproc):
        mock_subproc.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        graph = RouteGraph()
        obs = _make_obs(screen_identity="s_pure_mock", actions=[_make_candidate()])
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        res = run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
            no_navigation_postcondition=lambda obs: True,
        )
        self.assertIn(res.status, (ExplorationStatus.COMPLETED.value, ExplorationStatus.PARTIAL.value))
        self.assertEqual(res.actions_succeeded, 1)
        self.assertTrue(mock_subproc.called)

    # 31. loop does not create dynamic_analysis_report.json
    def test_31_loop_does_not_create_dynamic_analysis_report_json(self):
        storage = RouteGraphStorage(base_dir=self.output_dir)
        graph = RouteGraph(run_id="no_report_check")
        obs = _make_obs(screen_identity="s_report_test")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            graph_storage=storage,
            sleeper=lambda s: None,
        )

        self.assertFalse((self.output_dir / "dynamic_analysis_report.json").exists())
        self.assertFalse((self.output_dir / "dynamic" / "dynamic_analysis_report.json").exists())

    # 32. loop does not mark dynamic stage completed
    def test_32_loop_does_not_mark_dynamic_stage_completed(self):
        # Set up a canonical scan_state.json
        state_dir = self.output_dir / "scan_run_dir"
        state_dir.mkdir(parents=True, exist_ok=True)
        init_state = create_initial_scan_state(
            scan_id="scan_p_53",
            target_url="http://example.com/app.apk",
            platform="android",
        )
        save_scan_state(state_dir, init_state)

        # Run exploration
        storage = RouteGraphStorage(base_dir=state_dir)
        graph = RouteGraph(run_id="scan_p_53")
        obs = _make_obs(screen_identity="s_state_test")
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)

        run_exploration(
            observer=lambda: obs,
            executor=executor,
            route_graph=graph,
            graph_storage=storage,
            sleeper=lambda s: None,
        )

        # Check scan_state.json
        loaded_state = load_scan_state(state_dir)
        self.assertEqual(
            loaded_state["stages"]["dynamic_analysis"]["status"],
            "not_available",
            "dynamic_analysis stage must remain 'not_available'",
        )
        self.assertFalse(loaded_state["artifacts"]["dynamic_analysis_report"]["available"])

    # --- Task 5.3.1 System UI Policy Hardening & Schema Tests ---

    # 33. target package screen continues exploration
    def test_33_target_package_screen_continues_exploration(self):
        obs = _make_obs(screen_identity="s_target", pkg="com.example.app", is_target_pkg=True)
        self.assertTrue(is_allowed_exploration_surface(obs))

        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_app", text="Next")
        obs_with_btn = _make_obs(screen_identity="s_target", pkg="com.example.app", is_target_pkg=True, actions=[btn])
        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(return_value=ActionExecutionResult(
            action_id="act_next", action_type="click", status=ActionExecutionStatus.SUCCEEDED.value,
            started_at="2026-10-01T10:00:00+00:00", completed_at="2026-10-01T10:00:01+00:00",
        ))

        res = run_exploration(
            observer=lambda: obs_with_btn,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
            no_navigation_postcondition=lambda obs: True,
        )
        self.assertEqual(executor.click.call_count, 1)
        self.assertEqual(res.actions_succeeded, 1)

    # 34. Android permission controller is accepted
    def test_34_android_permission_controller_is_accepted(self):
        obs_aosp = _make_obs(
            screen_identity="s_perm1",
            pkg="com.android.permissioncontroller",
            is_target_pkg=False,
            is_dialog=True,
        )
        obs_google = _make_obs(
            screen_identity="s_perm2",
            pkg="com.google.android.permissioncontroller",
            is_target_pkg=False,
            is_dialog=True,
        )
        obs_settings = _make_obs(
            screen_identity="s_settings",
            pkg="com.android.settings",
            is_target_pkg=False,
            is_dialog=True,
        )

        self.assertTrue(is_allowed_system_dialog(obs_aosp))
        self.assertTrue(is_allowed_system_dialog(obs_google))
        self.assertFalse(is_allowed_system_dialog(obs_settings))
        self.assertTrue(is_allowed_exploration_surface(obs_aosp))
        self.assertTrue(is_allowed_exploration_surface(obs_google))
        self.assertFalse(is_allowed_exploration_surface(obs_settings))

    # 35. permission dialog can expose safe click actions
    def test_35_permission_dialog_can_expose_safe_click_actions(self):
        graph = RouteGraph()
        btn_req = _make_candidate(node_id="btn_request_perm", text="Allow Camera")
        obs_app = _make_obs(screen_identity="s_app_home", pkg="com.example.app", is_target_pkg=True, actions=[btn_req])

        btn_allow = _make_candidate(node_id="btn_while_using", text="Cancel")
        obs_dialog = _make_obs(
            screen_identity="s_perm_dialog",
            pkg="com.google.android.permissioncontroller",
            is_target_pkg=False,
            is_dialog=True,
            actions=[btn_allow],
        )

        obs_app_after = _make_obs(screen_identity="s_app_camera", pkg="com.example.app", is_target_pkg=True)

        seq = [obs_app, obs_dialog, obs_app_after]

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(return_value=ActionExecutionResult(
            action_id="act_ok", action_type="click", status=ActionExecutionStatus.SUCCEEDED.value,
            started_at="2026-10-01T10:00:00+00:00", completed_at="2026-10-01T10:00:01+00:00",
        ))

        res = run_exploration(
            observer=lambda: seq.pop(0) if seq else obs_app_after,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=2),
            sleeper=lambda s: None,
        )

        # Both the app button and the permission dialog button were clicked
        self.assertEqual(executor.click.call_count, 2)
        self.assertEqual(res.actions_succeeded, 2)
        self.assertEqual(graph.node_count, 3)
        self.assertEqual(graph.edge_count, 2)

    # 36. generic Android Settings screen stops autonomous exploration
    def test_36_generic_android_settings_screen_stops_autonomous_exploration(self):
        graph = RouteGraph()
        btn_open = _make_candidate(node_id="btn_open_settings", text="Go to Settings")
        obs_app = _make_obs(screen_identity="s_app_main", pkg="com.example.app", is_target_pkg=True, actions=[btn_open])

        btn_settings_click = _make_candidate(node_id="btn_toggle", text="Wi-Fi")
        obs_settings = _make_obs(
            screen_identity="s_settings",
            pkg="com.android.settings",
            is_target_pkg=False,
            is_dialog=True,
            actions=[btn_settings_click],
        )

        seq = [obs_app, obs_settings]

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(return_value=ActionExecutionResult(
            action_id="act_settings", action_type="click", status=ActionExecutionStatus.SUCCEEDED.value,
            started_at="2026-10-01T10:00:00+00:00", completed_at="2026-10-01T10:00:01+00:00",
        ))

        res = run_exploration(
            observer=lambda: seq.pop(0) if seq else obs_settings,
            executor=executor,
            route_graph=graph,
            limits=ExplorationLimits(max_steps=5),
            sleeper=lambda s: None,
        )

        # Clicked to open settings, but did NOT click on Settings screen
        self.assertEqual(executor.click.call_count, 1)
        self.assertEqual(res.stop_reason, StopReason.SYSTEM_UI_BOUNDARY.value)
        self.assertEqual(res.status, ExplorationStatus.PARTIAL.value)

    # 37. SystemUI screen stops autonomous exploration
    def test_37_systemui_screen_stops_autonomous_exploration(self):
        graph = RouteGraph()
        obs_sysui = _make_obs(
            screen_identity="s_sysui",
            pkg="com.android.systemui",
            is_target_pkg=False,
            is_dialog=True,
            actions=[_make_candidate(node_id="btn_qs", text="Quick Settings")],
        )

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock()

        res = run_exploration(
            observer=lambda: obs_sysui,
            executor=executor,
            route_graph=graph,
            sleeper=lambda s: None,
        )

        executor.click.assert_not_called()
        self.assertEqual(res.stop_reason, StopReason.SYSTEM_UI_BOUNDARY.value)
        self.assertEqual(res.status, ExplorationStatus.PARTIAL.value)

    # 38. browser/external app still stops exploration
    def test_38_browser_external_app_still_stops_exploration(self):
        graph = RouteGraph()
        obs_browser = _make_obs(
            screen_identity="s_browser",
            pkg="com.android.chrome",
            is_target_pkg=False,
            is_dialog=False,
            actions=[_make_candidate(node_id="btn_search", text="Search")],
        )

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock()

        res = run_exploration(
            observer=lambda: obs_browser,
            executor=executor,
            route_graph=graph,
            sleeper=lambda s: None,
        )

        executor.click.assert_not_called()
        self.assertEqual(res.stop_reason, StopReason.EXTERNAL_PACKAGE.value)

    # 39. unsupported system node remains in route graph as evidence
    def test_39_unsupported_system_node_remains_in_route_graph_as_evidence(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_to_settings", text="Settings")
        obs_app = _make_obs(screen_identity="s_app_v1", pkg="com.example.app", is_target_pkg=True, actions=[btn])
        obs_settings = _make_obs(screen_identity="s_settings_evidence", pkg="com.android.settings", is_target_pkg=False, is_dialog=True)
        seq = [obs_app, obs_settings]

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(return_value=ActionExecutionResult(
            action_id="act_set", action_type="click", status=ActionExecutionStatus.SUCCEEDED.value,
            started_at="2026-10-01T10:00:00+00:00", completed_at="2026-10-01T10:00:01+00:00",
        ))

        run_exploration(
            observer=lambda: seq.pop(0) if seq else obs_settings,
            executor=executor,
            route_graph=graph,
            sleeper=lambda s: None,
        )

        self.assertEqual(graph.node_count, 2)
        settings_node = graph.get_node_by_identity("s_settings_evidence")
        self.assertIsNotNone(settings_node)
        self.assertEqual(settings_node.package_name, "com.android.settings")

    # 40. transition into unsupported system UI is preserved before stopping
    def test_40_transition_into_unsupported_system_ui_is_preserved_before_stopping(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_installer", text="Install APK")
        obs_app = _make_obs(screen_identity="s_installer_source", pkg="com.example.app", is_target_pkg=True, actions=[btn])
        obs_installer = _make_obs(screen_identity="s_installer_target", pkg="com.android.packageinstaller", is_target_pkg=False, is_dialog=True)
        seq = [obs_app, obs_installer]

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(return_value=ActionExecutionResult(
            action_id="act_inst", action_type="click", status=ActionExecutionStatus.SUCCEEDED.value,
            started_at="2026-10-01T10:00:00+00:00", completed_at="2026-10-01T10:00:01+00:00",
        ))

        res = run_exploration(
            observer=lambda: seq.pop(0) if seq else obs_installer,
            executor=executor,
            route_graph=graph,
            sleeper=lambda s: None,
        )

        self.assertEqual(res.stop_reason, StopReason.SYSTEM_UI_BOUNDARY.value)
        self.assertEqual(graph.edge_count, 1)
        edge = list(graph.edges.values())[0]
        self.assertEqual(edge.source_node_id, graph.get_node_by_identity("s_installer_source").route_node_id)
        self.assertEqual(edge.target_node_id, graph.get_node_by_identity("s_installer_target").route_node_id)

    # 41. destructive action filtering still applies on permission dialogs
    def test_41_destructive_action_filtering_still_applies_on_permission_dialogs(self):
        graph = RouteGraph()
        btn_destructive = _make_candidate(node_id="btn_delete_all", text="Delete all permissions and data")
        obs_dialog = _make_obs(
            screen_identity="s_perm_destructive",
            pkg="com.google.android.permissioncontroller",
            is_target_pkg=False,
            is_dialog=True,
            actions=[btn_destructive],
        )

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock()

        res = run_exploration(
            observer=lambda: obs_dialog,
            executor=executor,
            route_graph=graph,
            sleeper=lambda s: None,
        )

        executor.click.assert_not_called()
        self.assertEqual(res.stop_reason, StopReason.UNSAFE_ACTION_BOUNDARY.value)
        node = graph.get_node_by_identity("s_perm_destructive")
        act = list(node.actions.values())[0]
        self.assertEqual(act.status, ActionStatus.DISCOVERED.value)

    # 42. post-action observation failure still creates no fake edge
    def test_42_post_action_observation_failure_still_creates_no_fake_edge(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_crash_obs", text="Click and Vanish")
        obs_init = _make_obs(screen_identity="s_init_crash", pkg="com.example.app", is_target_pkg=True, actions=[btn])

        call_count = 0
        def failing_observer():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return obs_init
            raise RuntimeError("UI dump lost connection")

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(return_value=ActionExecutionResult(
            action_id="act_crash", action_type="click", status=ActionExecutionStatus.SUCCEEDED.value,
            started_at="2026-10-01T10:00:00+00:00", completed_at="2026-10-01T10:00:01+00:00",
        ))

        res = run_exploration(
            observer=failing_observer,
            executor=executor,
            route_graph=graph,
            sleeper=lambda s: None,
        )

        # Dispatch succeeded, but semantic completion is unconfirmed
        self.assertEqual(res.actions_succeeded, 0)
        # But observation failed, creating NO transition edge
        self.assertEqual(graph.edge_count, 0)
        self.assertEqual(res.stop_reason, StopReason.OBSERVATION_FAILED.value)
        node = graph.get_node_by_identity("s_init_crash")
        act = list(node.actions.values())[0]
        self.assertEqual(act.status, ActionStatus.FAILED.value)

    # 43. canonical route graph serialization schema remains unchanged
    def test_43_canonical_route_graph_serialization_schema_remains_unchanged(self):
        storage = RouteGraphStorage(base_dir=self.output_dir)
        graph = RouteGraph(run_id="schema_canonical_check")

        btn = _make_candidate(node_id="btn_schema", text="Step 1")
        obs1 = _make_obs(screen_identity="s_schema_1", pkg="com.example.app", is_target_pkg=True, actions=[btn])
        obs2 = _make_obs(screen_identity="s_schema_2", pkg="com.example.app", is_target_pkg=True)
        seq = [obs1, obs2]

        executor = ActionExecutor(serial=self.serial, adb_bin=self.fake_adb)
        executor.click = MagicMock(return_value=ActionExecutionResult(
            action_id="act_s", action_type="click", status=ActionExecutionStatus.SUCCEEDED.value,
            started_at="2026-10-01T10:00:00+00:00", completed_at="2026-10-01T10:00:01+00:00",
        ))

        run_exploration(
            observer=lambda: seq.pop(0) if seq else obs2,
            executor=executor,
            route_graph=graph,
            graph_storage=storage,
            limits=ExplorationLimits(max_steps=1),
            sleeper=lambda s: None,
        )

        # Verify in-memory graph dict schema
        graph_dict = graph.to_dict()
        expected_graph_keys = {
            "schema_version", "graph_id", "run_id", "session_id", "created_at",
            "updated_at", "root_node_id", "current_node_id", "node_count",
            "edge_count", "discovered_action_count", "nodes", "edges",
        }
        self.assertEqual(set(graph_dict.keys()), expected_graph_keys)

        # Verify node schema
        node_dict = graph_dict["nodes"][0]
        expected_node_keys = {
            "route_node_id", "screen_identity", "package_name", "activity",
            "is_target_package", "is_dialog_or_system", "first_seen_at", "last_seen_at",
            "visit_count", "clickable_count", "input_count", "actions", "metadata",
        }
        self.assertEqual(set(node_dict.keys()), expected_node_keys)

        # Verify action schema
        node_with_actions = next(n for n in graph_dict["nodes"] if n["actions"])
        act_dict = node_with_actions["actions"][0]
        expected_action_keys = {
            "action_id", "source_node_id", "source_screen_identity", "ui_node_id",
            "action_type", "resource_id", "class_name", "bounds", "center",
            "content_desc", "text", "status", "first_seen_at", "last_seen_at",
        }
        self.assertEqual(set(act_dict.keys()), expected_action_keys)

        # Verify edge schema
        edge_dict = graph_dict["edges"][0]
        expected_edge_keys = {
            "edge_id", "source_node_id", "target_node_id", "action_id",
            "action_type", "created_at", "observation_count", "success", "metadata",
        }
        self.assertEqual(set(edge_dict.keys()), expected_edge_keys)

        # Verify persisted JSON matches exact schema
        persisted = storage.load_graph()
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted.node_count, 2)
        self.assertEqual(persisted.edge_count, 1)
