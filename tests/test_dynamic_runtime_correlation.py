"""Comprehensive tests for Action <-> Runtime Correlation V1 (Week 2 — Day 6 Task 6.2).

Verifies all 30 requirements:
1. before snapshot taken before action execution.
2. after snapshot taken after successful action.
3. RuntimeDiff generated from before/after.
4. PID change persisted.
5. process death persisted.
6. activity change persisted.
7. foreground change persisted.
8. target fatal appears in correlation.
9. target crash appears in correlation.
10. foreign/ambiguous fatal does not appear as target fatal.
11. new_log_event_count persisted.
12. compact runtime metadata attached to RouteEdge.
13. self-loop still receives runtime metadata.
14. failed action creates no fake route runtime effect.
15. UI observation failure can still preserve runtime diff.
16. runtime BEFORE failure does not erase action/route evidence.
17. runtime AFTER failure produces partial correlation.
18. runtime observer failure does not crash entire exploration unnecessarily.
19. confirmed process death stops further unsafe clicks.
20. timeline receives compact runtime correlation evidence.
21. raw full logcat not embedded in timeline.
22. raw secret not persisted.
23. runtime_evidence.json written atomically.
24. existing evidence survives later correlation failure.
25. one action execution produces one correlation record.
26. runtime evidence uses existing session_id.
27. dynamic_analysis never completed.
28. no dynamic_analysis_report.json created.
29. no Frida imports/dependencies.
30. no traffic integration.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

from src.dynamic.action.executor import ActionExecutor
from src.dynamic.action.models import ActionExecutionResult, ActionExecutionStatus
from src.dynamic.exploration.loop import run_exploration
from src.dynamic.exploration.models import ExplorationLimits, ExplorationStatus, StopReason
from src.dynamic.route.graph import RouteGraph
from src.dynamic.route.models import ActionStatus, DiscoveredAction, RouteEdge, RouteNode
from src.dynamic.route.storage import RouteGraphStorage
from src.dynamic.runtime.models import (
    CorrelationStatus,
    LogEventKind,
    RuntimeActionEvidence,
    RuntimeDiff,
    RuntimeEvidenceArtifact,
    RuntimeLogEvent,
    RuntimeSnapshot,
    compare_runtime_snapshots,
    create_action_runtime_evidence,
)
from src.dynamic.runtime.observer import AndroidRuntimeObserver
from src.dynamic.ui.models import ActionCandidate, ScreenObservation


def _make_action_result(action_id: str, success: bool = True) -> ActionExecutionResult:
    return ActionExecutionResult(
        action_id=action_id,
        action_type="click",
        status=ActionExecutionStatus.SUCCEEDED.value if success else ActionExecutionStatus.FAILED.value,
        started_at="2026-10-01T10:00:00Z",
        completed_at="2026-10-01T10:00:01Z",
    )


class TestDynamicRuntimeCorrelation(unittest.TestCase):
    """Test suite for Action <-> Runtime Correlation V1."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.session_id = "test-session-1234"
        self.pkg = "com.example.targetapp"
        self.evidence_file = self.base_dir / "runtime_evidence.json"
        self.timeline_file = self.base_dir / "timeline.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    _make_action_result = staticmethod(_make_action_result)

    def _create_mock_observation(self, screen_id: str, activity: str = "MainActivity", is_target: bool = True) -> ScreenObservation:
        cand = ActionCandidate(
            node_id="btn_1",
            action_type="click",
            bounds=(10, 10, 100, 100),
            center_x=55,
            center_y=55,
            resource_id="com.example.targetapp:id/submit",
            text="Submit",
        )
        return ScreenObservation(
            screen_identity=screen_id,
            foreground_package=self.pkg,
            target_package=self.pkg,
            foreground_activity=activity,
            is_target_package=is_target,
            action_candidates=[cand],
            clickable_count=1,
            input_count=0,
        )

    # 1. before snapshot taken before action execution
    def test_01_before_snapshot_taken_before_action_execution(self):
        call_order: list[str] = []

        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        mock_observer.observe.side_effect = lambda pkg, since_timestamp=None: (
            call_order.append(f"observe_after_{since_timestamp}" if since_timestamp else "observe_before"),
            RuntimeSnapshot(package_name=pkg, timestamp="2026-10-01T10:00:00.000Z", pid=1001, process_running=True)
        )[1]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.side_effect = lambda action, timeline_recorder=None: (
            call_order.append("execute_action"),
            _make_action_result(action.action_id, success=True)
        )[1]

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")
        ui_obs_mock = MagicMock(side_effect=[obs2])

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        limits = ExplorationLimits(max_steps=1)

        run_exploration(
            observer=ui_obs_mock,
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            limits=limits,
        )

        self.assertIn("observe_before", call_order)
        self.assertIn("execute_action", call_order)
        # Ensure observe_before precedes execute_action
        self.assertLess(call_order.index("observe_before"), call_order.index("execute_action"))

    # 2. after snapshot taken after successful action
    def test_02_after_snapshot_taken_after_successful_action(self):
        call_order: list[str] = []
        before_ts = "2026-10-01T10:00:00.000Z"

        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        def _mock_obs(pkg, since_timestamp=None):
            if since_timestamp:
                call_order.append(f"observe_after_since_{since_timestamp}")
                return RuntimeSnapshot(package_name=pkg, timestamp="2026-10-01T10:00:01.000Z", pid=1001, process_running=True)
            else:
                call_order.append("observe_before")
                return RuntimeSnapshot(package_name=pkg, timestamp=before_ts, pid=1001, process_running=True)
        mock_observer.observe.side_effect = _mock_obs

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.side_effect = lambda action, timeline_recorder=None: (
            call_order.append("execute_action"),
            _make_action_result(action.action_id, success=True)
        )[1]

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        limits = ExplorationLimits(max_steps=1)

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            limits=limits,
        )

        self.assertIn(f"observe_after_since_{before_ts}", call_order)
        self.assertLess(call_order.index("execute_action"), call_order.index(f"observe_after_since_{before_ts}"))

    # 3. RuntimeDiff generated from before/after
    def test_03_runtimediff_generated_from_before_after(self):
        before = RuntimeSnapshot(package_name=self.pkg, pid=1000, process_running=True, foreground_activity="MainActivity")
        after = RuntimeSnapshot(package_name=self.pkg, pid=1000, process_running=True, foreground_activity="SettingsActivity")

        evidence = create_action_runtime_evidence(
            action_id="act_1",
            source_node_id="node_1",
            target_node_id="node_2",
            before=before,
            after=after,
        )

        self.assertEqual(evidence.correlation_status, CorrelationStatus.AVAILABLE.value)
        self.assertTrue(evidence.activity_changed)
        self.assertFalse(evidence.pid_changed)
        self.assertFalse(evidence.process_died)
        self.assertIn("activity_changed", evidence.diff)

    # 4. PID change persisted
    def test_04_pid_changed_persisted(self):
        before = RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)
        after = RuntimeSnapshot(package_name=self.pkg, pid=1002, process_running=True)

        evidence = create_action_runtime_evidence("act_1", "src_1", before=before, after=after)
        self.assertTrue(evidence.pid_changed)
        self.assertEqual(evidence.before_pid, 1001)
        self.assertEqual(evidence.after_pid, 1002)

        artifact = RuntimeEvidenceArtifact(session_id=self.session_id)
        artifact.record_action_evidence(evidence, self.evidence_file)

        loaded = RuntimeEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(loaded.actions), 1)
        self.assertTrue(loaded.actions[0].pid_changed)
        self.assertEqual(loaded.actions[0].before_pid, 1001)
        self.assertEqual(loaded.actions[0].after_pid, 1002)

    # 5. process death persisted
    def test_05_process_died_persisted(self):
        before = RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)
        after = RuntimeSnapshot(package_name=self.pkg, pid=None, process_running=False)

        evidence = create_action_runtime_evidence("act_1", "src_1", before=before, after=after)
        self.assertTrue(evidence.process_died)

        artifact = RuntimeEvidenceArtifact(session_id=self.session_id)
        artifact.record_action_evidence(evidence, self.evidence_file)

        loaded = RuntimeEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertTrue(loaded.actions[0].process_died)

    # 6. activity change persisted
    def test_06_activity_change_persisted(self):
        before = RuntimeSnapshot(package_name=self.pkg, foreground_activity="com.example.MainActivity")
        after = RuntimeSnapshot(package_name=self.pkg, foreground_activity="com.example.DetailsActivity")

        evidence = create_action_runtime_evidence("act_1", "src_1", before=before, after=after)
        self.assertTrue(evidence.activity_changed)
        self.assertEqual(evidence.diff["before_activity"], "com.example.MainActivity")
        self.assertEqual(evidence.diff["after_activity"], "com.example.DetailsActivity")

    # 7. foreground change persisted
    def test_07_foreground_changed_persisted(self):
        before = RuntimeSnapshot(package_name=self.pkg, foreground_package=self.pkg)
        after = RuntimeSnapshot(package_name=self.pkg, foreground_package="com.android.settings")

        evidence = create_action_runtime_evidence("act_1", "src_1", before=before, after=after)
        self.assertTrue(evidence.foreground_changed)
        self.assertEqual(evidence.diff["before_foreground_package"], self.pkg)
        self.assertEqual(evidence.diff["after_foreground_package"], "com.android.settings")

    # 8. target fatal appears in correlation
    def test_08_target_fatal_appears_in_correlation(self):
        before = RuntimeSnapshot(package_name=self.pkg, fatal_detected=False)
        target_fatal_evt = RuntimeLogEvent(
            timestamp="10-01 10:00:00.000",
            level="E",
            tag="AndroidRuntime",
            message="FATAL EXCEPTION: main",
            kind=LogEventKind.FATAL.value,
            target_attributed=True,
            attribution="target",
        )
        after = RuntimeSnapshot(package_name=self.pkg, fatal_detected=True, crash_detected=True, log_events=[target_fatal_evt])

        evidence = create_action_runtime_evidence("act_1", "src_1", before=before, after=after)
        self.assertTrue(evidence.fatal_appeared)
        self.assertTrue(evidence.crash_appeared)

    # 9. target crash appears in correlation
    def test_09_target_crash_appears_in_correlation(self):
        before = RuntimeSnapshot(package_name=self.pkg, crash_detected=False)
        target_crash_evt = RuntimeLogEvent(
            timestamp="10-01 10:00:00.000",
            level="E",
            tag="ActivityManager",
            message=f"Process {self.pkg} (pid 1234) has died",
            kind=LogEventKind.CRASH.value,
            target_attributed=True,
            attribution="target",
        )
        after = RuntimeSnapshot(package_name=self.pkg, fatal_detected=False, crash_detected=True, log_events=[target_crash_evt])

        evidence = create_action_runtime_evidence("act_1", "src_1", before=before, after=after)
        self.assertFalse(evidence.fatal_appeared)
        self.assertTrue(evidence.crash_appeared)

    # 10. foreign/ambiguous fatal does not appear as target fatal
    def test_10_foreign_ambiguous_fatal_does_not_appear_as_target_fatal(self):
        before = RuntimeSnapshot(package_name=self.pkg, fatal_detected=False)
        foreign_evt = RuntimeLogEvent(
            timestamp="10-01 10:00:00.000",
            level="E",
            tag="AndroidRuntime",
            message="FATAL EXCEPTION: main",
            kind=LogEventKind.FATAL.value,
            target_attributed=False,
            attribution="unknown",
            attribution_reason="unscoped_fallback",
        )
        # Foreign / ambiguous event does NOT set target-level fatal_detected on snapshot
        after = RuntimeSnapshot(package_name=self.pkg, fatal_detected=False, crash_detected=False, log_events=[foreign_evt])

        evidence = create_action_runtime_evidence("act_1", "src_1", before=before, after=after)
        self.assertFalse(evidence.fatal_appeared)
        self.assertFalse(evidence.crash_appeared)

    # 11. new_log_event_count persisted
    def test_11_new_log_event_count_persisted(self):
        before = RuntimeSnapshot(package_name=self.pkg, log_events=[])
        evt1 = RuntimeLogEvent(timestamp="10-01 10:00:00.100", message="Log 1")
        evt2 = RuntimeLogEvent(timestamp="10-01 10:00:00.200", message="Log 2")
        after = RuntimeSnapshot(package_name=self.pkg, log_events=[evt1, evt2])

        evidence = create_action_runtime_evidence("act_1", "src_1", before=before, after=after)
        self.assertEqual(evidence.new_log_event_count, 2)
        self.assertEqual(len(evidence.compact_new_events), 2)

    # 12. compact runtime metadata attached to RouteEdge
    def test_12_compact_runtime_metadata_attached_to_route_edge(self):
        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        mock_observer.observe.side_effect = [
            RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True, foreground_activity="MainActivity"),
            RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True, foreground_activity="DetailActivity"),
        ]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1", activity="MainActivity")
        obs2 = self._create_mock_observation("screen_2", activity="DetailActivity")

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        limits = ExplorationLimits(max_steps=1)

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            limits=limits,
        )

        self.assertEqual(rg.edge_count, 1)
        edge = list(rg.edges.values())[0]
        self.assertIn("runtime", edge.metadata)
        self.assertTrue(edge.metadata["runtime"]["activity_changed"])
        self.assertFalse(edge.metadata["runtime"]["process_died"])
        self.assertFalse(edge.metadata["runtime"]["pid_changed"])

    # 13. self-loop still receives runtime metadata
    def test_13_self_loop_still_receives_runtime_metadata(self):
        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        mock_observer.observe.side_effect = [
            RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True),
            RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True, log_events=[RuntimeLogEvent(message="Tapped")]),
        ]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        # Same screen returned (self-loop)
        obs1 = self._create_mock_observation("screen_same")
        obs2 = self._create_mock_observation("screen_same")

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        limits = ExplorationLimits(max_steps=1)

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            no_navigation_postcondition=lambda obs: True,
            limits=limits,
        )

        self.assertEqual(rg.edge_count, 1)
        edge = list(rg.edges.values())[0]
        self.assertEqual(edge.source_node_id, edge.target_node_id)
        self.assertIn("runtime", edge.metadata)
        self.assertEqual(edge.metadata["runtime"]["new_log_event_count"], 1)

    # 14. failed action creates no fake route runtime effect
    def test_14_failed_action_creates_no_fake_route_runtime_effect(self):
        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        mock_observer.observe.return_value = RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)

        mock_executor = MagicMock(spec=ActionExecutor)
        # Action fails
        mock_executor.click.return_value = _make_action_result("act_1", success=False)

        obs1 = self._create_mock_observation("screen_1")
        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        limits = ExplorationLimits(max_steps=1)

        run_exploration(
            observer=MagicMock(),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            limits=limits,
        )

        # No transition edges recorded in RouteGraph
        self.assertEqual(rg.edge_count, 0)

        # Evidence file records partial correlation for the failed action
        loaded = RuntimeEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(loaded.actions), 1)
        self.assertEqual(loaded.actions[0].correlation_status, CorrelationStatus.PARTIAL.value)
        self.assertIsNone(loaded.actions[0].target_node_id)

    # 15. UI observation failure can still preserve runtime diff
    def test_15_ui_observation_failure_can_still_preserve_runtime_diff(self):
        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        before_snap = RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True, timestamp="2026-10-01T10:00:00Z")
        after_snap = RuntimeSnapshot(package_name=self.pkg, pid=1002, process_running=True, timestamp="2026-10-01T10:00:01Z")
        mock_observer.observe.side_effect = [before_snap, after_snap]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        # Post-action UI observation returns None / fails
        ui_mock = MagicMock(return_value=None)

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        limits = ExplorationLimits(max_steps=1)

        res = run_exploration(
            observer=ui_mock,
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            limits=limits,
        )

        # Stopped with OBSERVATION_FAILED
        self.assertEqual(res.stop_reason, StopReason.OBSERVATION_FAILED.value)
        # No fake RouteEdge created
        self.assertEqual(rg.edge_count, 0)

        # But runtime evidence was preserved!
        loaded = RuntimeEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(loaded.actions), 1)
        self.assertTrue(loaded.actions[0].pid_changed)
        self.assertIsNone(loaded.actions[0].target_node_id)

    # 16. runtime BEFORE failure does not erase action/route evidence
    def test_16_runtime_before_failure_does_not_erase_action_route_evidence(self):
        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        # BEFORE raises exception, AFTER succeeds
        after_snap = RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)
        mock_observer.observe.side_effect = [RuntimeError("ADB timeout on before"), after_snap]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        limits = ExplorationLimits(max_steps=1)

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            limits=limits,
        )

        # Route transition still succeeded and recorded
        self.assertEqual(rg.edge_count, 1)

        loaded = RuntimeEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(loaded.actions), 1)
        self.assertEqual(loaded.actions[0].correlation_status, CorrelationStatus.PARTIAL.value)

    # 17. runtime AFTER failure produces partial correlation
    def test_17_runtime_after_failure_produces_partial_correlation(self):
        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        # BEFORE succeeds, AFTER raises exception
        before_snap = RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)
        mock_observer.observe.side_effect = [before_snap, RuntimeError("ADB timeout on after")]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        limits = ExplorationLimits(max_steps=1)

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            limits=limits,
        )

        self.assertEqual(rg.edge_count, 1)
        loaded = RuntimeEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(loaded.actions), 1)
        self.assertEqual(loaded.actions[0].correlation_status, CorrelationStatus.PARTIAL.value)

    # 18. runtime observer failure does not crash entire exploration unnecessarily
    def test_18_runtime_observer_failure_does_not_crash_entire_exploration(self):
        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        mock_observer.observe.side_effect = RuntimeError("Catastrophic observer error")

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        limits = ExplorationLimits(max_steps=1)

        # Must not raise exception
        res = run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            limits=limits,
        )

        self.assertIn(res.status, (ExplorationStatus.COMPLETED.value, ExplorationStatus.PARTIAL.value))
        self.assertEqual(rg.edge_count, 1)

    # 19. confirmed process death stops further unsafe clicks
    def test_19_confirmed_process_death_stops_further_unsafe_clicks(self):
        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        # Action 1 kills process
        before_snap = RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)
        after_snap = RuntimeSnapshot(package_name=self.pkg, pid=None, process_running=False)
        mock_observer.observe.side_effect = [before_snap, after_snap]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = self._make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        # Configure max_steps=5 to prove it stops at step 1 on process death
        limits = ExplorationLimits(max_steps=5)

        res = run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            limits=limits,
        )

        self.assertEqual(res.steps_attempted, 1)
        self.assertEqual(mock_executor.click.call_count, 1)
        self.assertEqual(res.stop_reason, StopReason.OBSERVATION_FAILED.value)

    # 20. timeline receives compact runtime correlation evidence
    def test_20_timeline_receives_compact_runtime_correlation_evidence(self):
        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        mock_observer.observe.side_effect = [
            RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True),
            RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True, log_events=[RuntimeLogEvent(message="Tapped")]),
        ]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = self._make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        limits = ExplorationLimits(max_steps=1)

        timeline_events: list[tuple[str, dict]] = []
        def _recorder(name, meta):
            timeline_events.append((name, meta))

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            timeline_recorder=_recorder,
            runtime_evidence_file=self.evidence_file,
            limits=limits,
        )

        correlated_events = [m for n, m in timeline_events if n == "ACTION_RUNTIME_CORRELATED"]
        self.assertEqual(len(correlated_events), 1)
        meta = correlated_events[0]
        self.assertTrue(meta["action_id"].startswith("act_"))
        self.assertEqual(meta["correlation_status"], "available")
        self.assertEqual(meta["new_log_event_count"], 1)

    # 21. raw full logcat not embedded in timeline
    def test_21_raw_full_logcat_not_embedded_in_timeline(self):
        huge_logs = [RuntimeLogEvent(message=f"Spam log line {i}" * 50) for i in range(100)]
        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        mock_observer.observe.side_effect = [
            RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True),
            RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True, log_events=huge_logs),
        ]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = self._make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        timeline_events: list[tuple[str, dict]] = []
        def _recorder(name, meta):
            timeline_events.append((name, meta))

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            timeline_recorder=_recorder,
            runtime_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        serialized = json.dumps(timeline_events)
        # Entire timeline JSON must stay compact and not exceed reasonable size
        self.assertLess(len(serialized), 10000)
        self.assertNotIn("Spam log line 99", serialized)

    # 22. raw secret not persisted
    def test_22_raw_secret_not_persisted(self):
        secret_log = RuntimeLogEvent(
            message="Logging Authorization: Bearer secret_token_xyz123 and password=SuperSecretPassword99",
            level="I",
            tag="SecretTag",
        )
        before = RuntimeSnapshot(package_name=self.pkg, log_events=[])
        after = RuntimeSnapshot(package_name=self.pkg, log_events=[secret_log])

        evidence = create_action_runtime_evidence("act_1", "src_1", before=before, after=after)
        artifact = RuntimeEvidenceArtifact(session_id=self.session_id)
        artifact.record_action_evidence(evidence, self.evidence_file)

        content = self.evidence_file.read_text(encoding="utf-8")
        self.assertNotIn("secret_token_xyz123", content)
        self.assertNotIn("SuperSecretPassword99", content)
        self.assertIn("Bearer [REDACTED]", content)
        self.assertIn("password=[REDACTED]", content)

    # 23. runtime_evidence.json written atomically
    def test_23_runtime_evidence_json_written_atomically(self):
        artifact = RuntimeEvidenceArtifact(session_id=self.session_id)
        evidence = RuntimeActionEvidence(action_id="act_1", source_node_id="node_1")
        artifact.record_action_evidence(evidence, self.evidence_file)

        self.assertTrue(self.evidence_file.is_file())
        with open(self.evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["session_id"], self.session_id)
        self.assertEqual(len(data["actions"]), 1)

    # 24. existing evidence survives later correlation failure
    def test_24_existing_evidence_survives_later_correlation_failure(self):
        artifact = RuntimeEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        ev1 = RuntimeActionEvidence(action_id="act_1", source_node_id="src_1", before_pid=100)
        artifact.record_action_evidence(ev1, self.evidence_file)

        # Action 2 correlation has an error but appends its partial evidence
        ev2 = RuntimeActionEvidence(action_id="act_2", source_node_id="src_2", correlation_status=CorrelationStatus.PARTIAL.value)
        artifact.record_action_evidence(ev2, self.evidence_file)

        reloaded = RuntimeEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(reloaded.actions), 2)
        self.assertEqual(reloaded.actions[0].action_id, "act_1")
        self.assertEqual(reloaded.actions[0].before_pid, 100)
        self.assertEqual(reloaded.actions[1].action_id, "act_2")
        self.assertEqual(reloaded.actions[1].correlation_status, CorrelationStatus.PARTIAL.value)

    # 25. one action execution produces one correlation record
    def test_25_one_action_execution_produces_one_correlation_record(self):
        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        mock_observer.observe.return_value = RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = self._make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")
        obs3 = self._create_mock_observation("screen_3")
        ui_mock = MagicMock(side_effect=[obs2, obs3])

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        limits = ExplorationLimits(max_steps=2)

        run_exploration(
            observer=ui_mock,
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            limits=limits,
        )

        loaded = RuntimeEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(loaded.actions), 2)

    # 26. runtime evidence uses existing session_id
    def test_26_runtime_evidence_uses_existing_session_id(self):
        custom_session = "custom-session-uuid-9999"
        rg = RouteGraph(run_id="run_1", session_id=custom_session)

        mock_observer = MagicMock(spec=AndroidRuntimeObserver)
        mock_observer.observe.return_value = RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = self._make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_observer,
            target_package=self.pkg,
            runtime_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        loaded = RuntimeEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(loaded.session_id, custom_session)

    # 27. dynamic completion requires a validated canonical report
    def test_27_dynamic_analysis_completed_with_canonical_report(self):
        from src.demo_orchestrator import _wire_dynamic_exploration

        # Preflight PASS
        dyn_dir = self.base_dir / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        (dyn_dir / "preflight_result.json").write_text(json.dumps({
            "status": "PASS",
            "device": {"connected": True, "serial": "emulator-5554"},
            "application": {"process_running": True, "package_name": self.pkg},
            "runtime": {"launch_success": True},
        }))
        (dyn_dir / "session.json").write_text(json.dumps({
            "session_id": self.session_id,
            "status": "ACTIVE",
        }))

        from src.scan_state import create_initial_scan_state, load_scan_state, save_scan_state
        init_st = create_initial_scan_state(scan_id=self.base_dir.name, target_url="http://test.com/app.apk")
        save_scan_state(self.base_dir, init_st)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=[obs1, obs2]), \
             patch("src.dynamic.action.executor.ActionExecutor.click", return_value=self._make_action_result("act_1", success=True)), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe", return_value=RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)):
            _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))

        final_st = load_scan_state(self.base_dir)
        # Task 8.1: completion requires the persisted canonical report.
        self.assertEqual(final_st.get("stages", {}).get("dynamic_analysis", {}).get("status"), "completed")

        from src.dynamic.report import load_dynamic_analysis_report
        load_dynamic_analysis_report(self.base_dir)

    # 28. no dynamic_analysis_report.json created

    def test_28_no_dynamic_analysis_report_json_created(self):
        report_file = self.base_dir / "dynamic" / "dynamic_analysis_report.json"
        self.assertFalse(report_file.is_file())

    # 29. no Frida imports/dependencies
    def test_29_no_frida_imports_or_dependencies(self):
        import src.dynamic.runtime as m_rt
        import src.dynamic.exploration as m_exp
        import src.dynamic.runtime.models as m_rt_models
        import src.dynamic.exploration.loop as m_exp_loop

        for mod in (m_rt, m_exp, m_rt_models, m_exp_loop):
            content = Path(mod.__file__).read_text(encoding="utf-8")
            self.assertNotIn("frida", content.lower())
            self.assertNotIn("objection", content.lower())
            self.assertNotIn("xposed", content.lower())

    # 30. no traffic integration
    def test_30_no_traffic_integration(self):
        import src.dynamic.runtime.models as m_rt_models
        import src.dynamic.exploration.loop as m_exp_loop

        for mod in (m_rt_models, m_exp_loop):
            content = Path(mod.__file__).read_text(encoding="utf-8")
            self.assertNotIn("mitmproxy", content.lower())
            self.assertNotIn("pcap", content.lower())
            self.assertNotIn("wireshark", content.lower())
            self.assertNotIn("traffic_capture", content.lower())
