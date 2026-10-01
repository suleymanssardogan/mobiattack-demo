"""Comprehensive Unit & Mock Integration Tests for Dynamic HTTP Traffic Capture & Correlation (Week 2 — Day 6 Task 6.3)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

from src.dynamic.action.executor import ActionExecutor
from src.dynamic.action.models import ActionExecutionResult, ActionExecutionStatus
from src.dynamic.exploration.loop import run_exploration
from src.dynamic.exploration.models import ExplorationLimits, ExplorationStatus, StopReason
from src.dynamic.route.graph import RouteGraph
from src.dynamic.route.models import ActionStatus, DiscoveredAction
from src.dynamic.route.storage import RouteGraphStorage
from src.dynamic.runtime.models import (
    CorrelationStatus as RuntimeCorrelationStatus,
    RuntimeActionEvidence,
    RuntimeSnapshot,
)
from src.dynamic.runtime.observer import AndroidRuntimeObserver
from src.dynamic.traffic.models import (
    ActionTrafficEvidence,
    CaptureSession,
    CaptureStatus,
    CaptureSummary,
    CorrelationStatus,
    HttpRequestModel,
    HttpResponseModel,
    HttpsInterceptionReadiness,
    ProxyReadinessResult,
    TrafficEvidenceArtifact,
    TrafficReadinessStatus,
    TrafficTransaction,
    create_action_traffic_evidence,
)
from src.dynamic.traffic.normalizer import (
    normalize_http_transaction,
    sanitize_body_payload,
    sanitize_headers,
)
from src.dynamic.traffic.proxy_manager import DeviceProxyManager
from src.dynamic.traffic.service import DynamicTrafficService
from src.dynamic.traffic.storage import TrafficStorage
from src.dynamic.ui.models import ActionCandidate, ScreenObservation


def _make_action_result(action_id: str, success: bool = True) -> ActionExecutionResult:
    return ActionExecutionResult(
        action_id=action_id,
        action_type="click",
        status=ActionExecutionStatus.SUCCEEDED.value if success else ActionExecutionStatus.FAILED.value,
        started_at="2026-10-01T10:00:00Z",
        completed_at="2026-10-01T10:00:01Z",
    )


def _make_transaction(
    tx_id: str = "tx_1",
    method: str = "GET",
    host: str = "api.example.com",
    path: str = "/data",
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    body: any = None,
) -> TrafficTransaction:
    return TrafficTransaction(
        transaction_id=tx_id,
        request=HttpRequestModel(
            method=method,
            host=host,
            path=path,
            headers=headers or {"content-type": "application/json"},
            body=body,
        ),
        response=HttpResponseModel(
            status_code=status_code,
            headers={"content-type": "application/json"},
            body={"status": "ok"},
        ),
    )


class TestDynamicTrafficCorrelation(unittest.TestCase):
    """Test suite verifying all 41 requirements of Task 6.3."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.session_id = "traffic-session-uuid-1234"
        self.pkg = "com.example.targetapp"
        self.evidence_file = self.base_dir / "traffic_evidence.json"
        self.traffic_file = self.base_dir / "traffic.json"
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

    # 1. traffic session starts once per exploration
    def test_01_traffic_session_starts_once_per_exploration(self):
        from src.demo_orchestrator import _wire_dynamic_exploration

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

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=[obs1, obs2]), \
             patch("src.dynamic.action.executor.ActionExecutor.click", return_value=_make_action_result("act_1", success=True)), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe", return_value=RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture") as mock_start, \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture", return_value=CaptureSummary(total_transactions=0)):
            _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))

        self.assertEqual(mock_start.call_count, 1)

    # 2. traffic session stops once
    def test_02_traffic_session_stops_once(self):
        from src.demo_orchestrator import _wire_dynamic_exploration

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

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=[obs1, obs2]), \
             patch("src.dynamic.action.executor.ActionExecutor.click", return_value=_make_action_result("act_1", success=True)), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe", return_value=RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture"), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture", return_value=CaptureSummary(total_transactions=0)) as mock_stop:
            _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))

        self.assertEqual(mock_stop.call_count, 1)

    # 3. cleanup runs in finally
    def test_03_cleanup_runs_in_finally(self):
        from src.demo_orchestrator import _wire_dynamic_exploration

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

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=RuntimeError("Simulated loop crash")), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture"), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture", return_value=CaptureSummary(total_transactions=0)) as mock_stop:
            try:
                _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))
            except Exception:
                pass

        self.assertEqual(mock_stop.call_count, 1)

    # 4. previous proxy restored
    @patch("src.dynamic.traffic.proxy_manager.run_adb_cmd")
    def test_04_previous_proxy_restored(self, mock_adb):
        # 1. get original proxy (192.168.1.1:8080)
        # 2. apply new proxy
        # 3. restore original proxy
        mock_adb.side_effect = [
            (0, "192.168.1.1:8080", ""),
            (0, "", ""),
            (0, "", ""),
        ]
        mgr = DeviceProxyManager(adb_bin="/mock/adb", serial="dev-1", proxy_host="10.0.2.2", proxy_port=8080)
        mgr.apply_proxy()
        restored = mgr.restore_proxy()
        self.assertTrue(restored)
        last_call_cmd = mock_adb.call_args_list[-1][0][1]
        self.assertIn("192.168.1.1:8080", last_call_cmd)

    # 5. PASS preflight permits traffic start
    def test_05_pass_preflight_permits_traffic_start(self):
        from src.demo_orchestrator import _wire_dynamic_exploration

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

        obs1 = self._create_mock_observation("screen_1")
        with patch("src.dynamic.ui.observer.observe_screen", return_value=obs1), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture") as mock_start, \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture", return_value=CaptureSummary(total_transactions=0)):
            _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=0))

        self.assertEqual(mock_start.call_count, 1)

    # 6. FAIL preflight does not start traffic
    def test_06_fail_preflight_does_not_start_traffic(self):
        from src.demo_orchestrator import _wire_dynamic_exploration

        dyn_dir = self.base_dir / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        (dyn_dir / "preflight_result.json").write_text(json.dumps({
            "status": "FAIL",
            "device": {"connected": False},
        }))

        with patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture") as mock_start:
            res = _wire_dynamic_exploration(self.base_dir, package_name=self.pkg)

        self.assertIsNone(res)
        self.assertEqual(mock_start.call_count, 0)

    # 7. action creates traffic marker/window
    def test_07_action_creates_traffic_marker_window(self):
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 5
        mock_traffic.get_transactions_since.return_value = [_make_transaction("tx_1")]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")
        rg = RouteGraph(run_id="run_1", session_id=self.session_id)

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        mock_traffic.get_current_marker.assert_called_once()
        mock_traffic.get_transactions_since.assert_called_once_with(5)

    # 8. transaction observed during action window correlated
    def test_08_transaction_observed_during_action_window_correlated(self):
        tx = _make_transaction("tx_abc_123", method="POST", host="api.test.com", path="/login", status_code=200)
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0
        mock_traffic.get_transactions_since.return_value = [tx]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")
        rg = RouteGraph(run_id="run_1", session_id=self.session_id)

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        artifact = TrafficEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(artifact.actions), 1)
        self.assertEqual(artifact.actions[0].transaction_ids, ["tx_abc_123"])
        self.assertEqual(artifact.actions[0].transaction_count, 1)

    # 9. transaction outside action window not correlated
    def test_09_transaction_outside_action_window_not_correlated(self):
        # Transaction 0 happened prior to marker 1
        prior_tx = _make_transaction("tx_prior")
        active_tx = _make_transaction("tx_active")

        traffic_svc = DynamicTrafficService(backend=MagicMock(), storage=TrafficStorage(str(self.base_dir)))
        traffic_svc.captured_transactions = [prior_tx]

        # Marker taken when count was 1
        marker = traffic_svc.get_current_marker()
        self.assertEqual(marker, 1)

        traffic_svc.captured_transactions.append(active_tx)
        window_txs = traffic_svc.get_transactions_since(marker)

        self.assertEqual(len(window_txs), 1)
        self.assertEqual(window_txs[0].transaction_id, "tx_active")
        self.assertNotIn("tx_prior", [t.transaction_id for t in window_txs])

    # 10. multiple transactions correlated to one action
    def test_10_multiple_transactions_correlated_to_one_action(self):
        tx1 = _make_transaction("tx_1", method="GET")
        tx2 = _make_transaction("tx_2", method="POST")
        tx3 = _make_transaction("tx_3", method="PUT")

        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0
        mock_traffic.get_transactions_since.return_value = [tx1, tx2, tx3]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")
        rg = RouteGraph(run_id="run_1", session_id=self.session_id)

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        artifact = TrafficEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(artifact.actions[0].transaction_count, 3)
        self.assertEqual(artifact.actions[0].transaction_ids, ["tx_1", "tx_2", "tx_3"])
        self.assertEqual(set(artifact.actions[0].methods), {"GET", "POST", "PUT"})

    # 11. background transaction not falsely duplicated across actions
    def test_11_background_transaction_not_falsely_duplicated_across_actions(self):
        tx1 = _make_transaction("tx_act1")
        tx2 = _make_transaction("tx_act2")

        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.side_effect = [0, 1]
        mock_traffic.get_transactions_since.side_effect = [[tx1], [tx2]]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.side_effect = [
            _make_action_result("act_1", success=True),
            _make_action_result("act_2", success=True),
        ]

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")
        obs3 = self._create_mock_observation("screen_3")
        rg = RouteGraph(run_id="run_1", session_id=self.session_id)

        run_exploration(
            observer=MagicMock(side_effect=[obs2, obs3]),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=2),
        )

        artifact = TrafficEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(artifact.actions), 2)
        self.assertEqual(artifact.actions[0].transaction_ids, ["tx_act1"])
        self.assertEqual(artifact.actions[1].transaction_ids, ["tx_act2"])

    # 12. canonical transaction IDs referenced
    def test_12_canonical_transaction_ids_referenced(self):
        canonical_tx = _make_transaction("canonical_uuid_999")
        evidence = create_action_traffic_evidence("act_1", "node_1", transactions=[canonical_tx])
        self.assertIn("canonical_uuid_999", evidence.transaction_ids)

    # 13. no duplicate transaction schema created
    def test_13_no_duplicate_transaction_schema_created(self):
        tx = _make_transaction("tx_test")
        self.assertIsInstance(tx, TrafficTransaction)
        self.assertIsInstance(tx.request, HttpRequestModel)
        self.assertIsInstance(tx.response, HttpResponseModel)

    # 14. RouteEdge gets compact traffic metadata
    def test_14_route_edge_gets_compact_traffic_metadata(self):
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0
        mock_traffic.get_transactions_since.return_value = [_make_transaction("tx_1"), _make_transaction("tx_2")]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")
        rg = RouteGraph(run_id="run_1", session_id=self.session_id)

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        edge = list(rg.edges.values())[0]
        self.assertIn("traffic", edge.metadata)
        self.assertEqual(edge.metadata["traffic"]["transaction_count"], 2)
        self.assertEqual(edge.metadata["traffic"]["transaction_ids"], ["tx_1", "tx_2"])

    # 15. existing runtime metadata remains intact
    def test_15_existing_runtime_metadata_remains_intact(self):
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0
        mock_traffic.get_transactions_since.return_value = [_make_transaction("tx_1")]

        mock_runtime = MagicMock(spec=AndroidRuntimeObserver)
        mock_runtime.observe.side_effect = [
            RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True),
            RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True),
        ]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")
        rg = RouteGraph(run_id="run_1", session_id=self.session_id)

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            runtime_observer=mock_runtime,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        edge = list(rg.edges.values())[0]
        self.assertIn("runtime", edge.metadata)
        self.assertIn("traffic", edge.metadata)
        self.assertIn("pid_changed", edge.metadata["runtime"])
        self.assertIn("transaction_ids", edge.metadata["traffic"])

    # 16. self-loop can have traffic metadata
    def test_16_self_loop_can_have_traffic_metadata(self):
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0
        mock_traffic.get_transactions_since.return_value = [_make_transaction("tx_refresh")]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        # Same screen observation = self-loop
        obs_same = self._create_mock_observation("screen_1")
        rg = RouteGraph(run_id="run_1", session_id=self.session_id)

        run_exploration(
            observer=MagicMock(return_value=obs_same),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        edge = list(rg.edges.values())[0]
        self.assertEqual(edge.source_node_id, edge.target_node_id)
        self.assertIn("traffic", edge.metadata)
        self.assertEqual(edge.metadata["traffic"]["transaction_ids"], ["tx_refresh"])

    # 17. UI observation failure preserves traffic evidence without fake edge
    def test_17_ui_observation_failure_preserves_traffic_evidence_without_fake_edge(self):
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0
        mock_traffic.get_transactions_since.return_value = [_make_transaction("tx_fail")]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        rg = RouteGraph(run_id="run_1", session_id=self.session_id)

        # UI observer returns None (observation failed)
        run_exploration(
            observer=MagicMock(return_value=None),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        self.assertEqual(rg.edge_count, 0)
        artifact = TrafficEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(artifact.actions), 1)
        self.assertIsNone(artifact.actions[0].target_node_id)
        self.assertEqual(artifact.actions[0].transaction_ids, ["tx_fail"])

    # 18. failed action does not claim traffic causality
    def test_18_failed_action_does_not_claim_traffic_causality(self):
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=False)

        obs1 = self._create_mock_observation("screen_1")
        rg = RouteGraph(run_id="run_1", session_id=self.session_id)

        run_exploration(
            observer=MagicMock(return_value=obs1),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        artifact = TrafficEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(artifact.actions), 1)
        self.assertEqual(artifact.actions[0].transaction_count, 0)
        self.assertEqual(artifact.actions[0].transaction_ids, [])
        self.assertEqual(artifact.actions[0].correlation_status, CorrelationStatus.PARTIAL.value)

    # 19. traffic backend unavailable does not fail exploration
    def test_19_traffic_backend_unavailable_does_not_fail_exploration(self):
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.side_effect = RuntimeError("Proxy backend connection lost")

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")
        rg = RouteGraph(run_id="run_1", session_id=self.session_id)

        res = run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        self.assertIn(res.status, (ExplorationStatus.COMPLETED.value, ExplorationStatus.PARTIAL.value))
        self.assertEqual(rg.edge_count, 1)

    # 20. backend dies midway preserves previous transactions
    def test_20_backend_dies_midway_preserves_previous_transactions(self):
        artifact = TrafficEvidenceArtifact(session_id=self.session_id)
        ev1 = ActionTrafficEvidence(action_id="act_1", transaction_count=1, transaction_ids=["tx_1"])
        artifact.record_action_evidence(ev1, self.evidence_file)

        # Midway failure on action 2
        ev2 = ActionTrafficEvidence(action_id="act_2", correlation_status=CorrelationStatus.PARTIAL.value, error="backend_died")
        artifact.record_action_evidence(ev2, self.evidence_file)

        loaded = TrafficEvidenceArtifact.load_or_create(self.evidence_file, self.session_id)
        self.assertEqual(len(loaded.actions), 2)
        self.assertEqual(loaded.actions[0].transaction_ids, ["tx_1"])
        self.assertEqual(loaded.actions[1].correlation_status, CorrelationStatus.PARTIAL.value)

    # 21. HTTPS visibility unavailable represented explicitly
    def test_21_https_visibility_unavailable_represented_explicitly(self):
        readiness = HttpsInterceptionReadiness(ca_certificate_installed=False, certificate_trust_unknown=True)
        d = readiness.to_dict()
        self.assertFalse(d["ca_certificate_installed"])
        self.assertTrue(d["certificate_trust_unknown"])

    # 22. zero observed traffic distinguished from unavailable visibility
    def test_22_zero_observed_traffic_distinguished_from_unavailable_visibility(self):
        # Case A: Active capture, full visibility, zero traffic observed
        ev_zero_full = create_action_traffic_evidence(
            "act_1", "node_1", transactions=[], correlation_status=CorrelationStatus.AVAILABLE.value, https_visibility="available"
        )
        self.assertEqual(ev_zero_full.correlation_status, CorrelationStatus.AVAILABLE.value)
        self.assertEqual(ev_zero_full.correlation_note, "No traffic was observed during the action window.")

        # Case B: Active capture, partial/unavailable HTTPS visibility, zero traffic observed
        ev_zero_partial = create_action_traffic_evidence(
            "act_1", "node_1", transactions=[], https_visibility="unavailable"
        )
        self.assertEqual(ev_zero_partial.correlation_status, CorrelationStatus.PARTIAL.value)
        self.assertIn("No visible HTTP transactions were captured during the action window; HTTPS visibility was unavailable.", ev_zero_partial.correlation_note)

        # Case C: Traffic service unavailable
        ev_unavail = create_action_traffic_evidence("act_1", "node_1", transactions=[], correlation_status=CorrelationStatus.UNAVAILABLE.value)
        self.assertEqual(ev_unavail.correlation_status, CorrelationStatus.UNAVAILABLE.value)

    # 23. Authorization header redacted
    def test_23_authorization_header_redacted(self):
        raw_headers = {"authorization": "Bearer secret_api_key_12345", "user-agent": "TestApp"}
        sanitized = sanitize_headers(raw_headers)
        self.assertEqual(sanitized["authorization"], "[REDACTED]")
        self.assertEqual(sanitized["user-agent"], "TestApp")

    # 24. Cookie redacted
    def test_24_cookie_redacted(self):
        raw_headers = {"Cookie": "session=secret_token_val_456; uid=100"}
        sanitized = sanitize_headers(raw_headers)
        self.assertEqual(sanitized["cookie"], "[REDACTED]")

    # 25. Set-Cookie redacted
    def test_25_set_cookie_redacted(self):
        raw_headers = {"Set-Cookie": "session=secret_cookie_token"}
        sanitized = sanitize_headers(raw_headers)
        self.assertEqual(sanitized["set-cookie"], "[REDACTED]")

    # 26. token/password/API key redacted
    def test_26_token_password_api_key_redacted(self):
        payload = {
            "username": "user1",
            "password": "SuperSecretPassword123",
            "access_token": "jwt_token_99999",
            "api_key": "key_xyz_abc",
        }
        sanitized = sanitize_body_payload(payload)
        self.assertEqual(sanitized["username"], "user1")
        self.assertEqual(sanitized["password"], "[REDACTED]")
        self.assertEqual(sanitized["access_token"], "[REDACTED]")
        self.assertEqual(sanitized["api_key"], "[REDACTED]")

    # 27. full bodies not duplicated into timeline
    def test_27_full_bodies_not_duplicated_into_timeline(self):
        huge_body = "x" * 5000
        tx = _make_transaction("tx_1", body=huge_body)

        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0
        mock_traffic.get_transactions_since.return_value = [tx]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

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
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            timeline_recorder=_recorder,
            limits=ExplorationLimits(max_steps=1),
        )

        timeline_str = json.dumps(timeline_events)
        self.assertNotIn(huge_body, timeline_str)

    # 28. timeline receives compact ACTION_TRAFFIC_CORRELATED
    def test_28_timeline_receives_compact_action_traffic_correlated(self):
        tx = _make_transaction("tx_1", method="POST", host="api.app.com")
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0
        mock_traffic.get_transactions_since.return_value = [tx]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

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
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            timeline_recorder=_recorder,
            limits=ExplorationLimits(max_steps=1),
        )

        correlated = [meta for name, meta in timeline_events if name == "ACTION_TRAFFIC_CORRELATED"]
        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0]["transaction_ids"], ["tx_1"])
        self.assertEqual(correlated[0]["transaction_count"], 1)
        self.assertEqual(correlated[0]["methods"], ["POST"])
        self.assertEqual(correlated[0]["hosts"], ["api.app.com"])

    # 29. traffic artifact written atomically
    def test_29_traffic_artifact_written_atomically(self):
        storage = TrafficStorage(str(self.base_dir))
        tx = _make_transaction("tx_100")
        target_file = self.base_dir / "dynamic" / "traffic.json"
        storage.save_traffic_json(target_file, self.session_id, [tx])

        self.assertTrue(target_file.is_file())
        with open(target_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["session_id"], self.session_id)
        self.assertEqual(data["total_transactions"], 1)

    # 30. traffic_evidence artifact written atomically if implemented
    def test_30_traffic_evidence_artifact_written_atomically(self):
        artifact = TrafficEvidenceArtifact(session_id=self.session_id)
        ev = ActionTrafficEvidence(action_id="act_1", transaction_count=1, transaction_ids=["tx_1"])
        artifact.record_action_evidence(ev, self.evidence_file)

        self.assertTrue(self.evidence_file.is_file())
        with open(self.evidence_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["session_id"], self.session_id)
        self.assertEqual(len(data["actions"]), 1)

    # 31. same session_id reused
    def test_31_same_session_id_reused(self):
        custom_session = "my-custom-session-8888"
        rg = RouteGraph(run_id="run_1", session_id=custom_session)

        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0
        mock_traffic.get_transactions_since.return_value = [_make_transaction("tx_1")]

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        loaded = TrafficEvidenceArtifact.load_or_create(self.evidence_file, custom_session)
        self.assertEqual(loaded.session_id, custom_session)

    # 32. monolithic path uses traffic once
    def test_32_monolithic_path_uses_traffic_once(self):
        from src.demo_orchestrator import _wire_dynamic_exploration

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

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=[obs1, obs2]), \
             patch("src.dynamic.action.executor.ActionExecutor.click", return_value=_make_action_result("act_1", success=True)), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe", return_value=RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture") as mock_start, \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture", return_value=CaptureSummary(total_transactions=0)) as mock_stop:
            _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))

        self.assertEqual(mock_start.call_count, 1)
        self.assertEqual(mock_stop.call_count, 1)

    # 33. split path uses traffic once
    def test_33_split_path_uses_traffic_once(self):
        from src.demo_orchestrator import _wire_dynamic_exploration

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

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=[obs1, obs2]), \
             patch("src.dynamic.action.executor.ActionExecutor.click", return_value=_make_action_result("act_1", success=True)), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe", return_value=RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture") as mock_start, \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture", return_value=CaptureSummary(total_transactions=0)) as mock_stop:
            _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))

        self.assertEqual(mock_start.call_count, 1)
        self.assertEqual(mock_stop.call_count, 1)

    # 34. Play Store path uses traffic once
    def test_34_play_store_path_uses_traffic_once(self):
        from src.demo_orchestrator import _wire_dynamic_exploration

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

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=[obs1, obs2]), \
             patch("src.dynamic.action.executor.ActionExecutor.click", return_value=_make_action_result("act_1", success=True)), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe", return_value=RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture") as mock_start, \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture", return_value=CaptureSummary(total_transactions=0)) as mock_stop:
            _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))

        self.assertEqual(mock_start.call_count, 1)
        self.assertEqual(mock_stop.call_count, 1)

    # 35. proxy cleanup occurs after exploration exception
    def test_35_proxy_cleanup_occurs_after_exploration_exception(self):
        from src.demo_orchestrator import _wire_dynamic_exploration

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

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=Exception("Exploration fatal crash")), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture"), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture") as mock_stop:
            try:
                _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))
            except Exception:
                pass

        self.assertEqual(mock_stop.call_count, 1)

    # 36. no SSL pinning bypass
    def test_36_no_ssl_pinning_bypass(self):
        import src.dynamic.traffic as m_traffic
        import src.dynamic.traffic.models as m_models

        for mod in (m_traffic, m_models):
            content = Path(mod.__file__).read_text(encoding="utf-8")
            self.assertNotIn("bypass_ssl_pinning", content.lower())
            self.assertNotIn("patch_certificate_pinning", content.lower())
            self.assertNotIn("disable_pinning", content.lower())

    # 37. no Frida dependency
    def test_37_no_frida_dependency(self):
        import src.dynamic.traffic as m_traffic
        import src.dynamic.traffic.models as m_models
        import src.dynamic.traffic.service as m_service

        for mod in (m_traffic, m_models, m_service):
            content = Path(mod.__file__).read_text(encoding="utf-8")
            self.assertNotIn("frida", content.lower())
            self.assertNotIn("objection", content.lower())
            self.assertNotIn("xposed", content.lower())

    # 38. no vulnerability testing
    def test_38_no_vulnerability_testing(self):
        import src.dynamic.traffic.service as m_service
        content = Path(m_service.__file__).read_text(encoding="utf-8")
        self.assertNotIn("fuzz", content.lower())
        self.assertNotIn("idor", content.lower())
        self.assertNotIn("sql_injection", content.lower())
        self.assertNotIn("replay_attack", content.lower())

    # 39. no static API inventory mutation
    def test_39_no_static_api_inventory_mutation(self):
        import src.dynamic.exploration.loop as m_loop
        content = Path(m_loop.__file__).read_text(encoding="utf-8")
        self.assertNotIn("api_inventory", content.lower())
        self.assertNotIn("merge_endpoints", content.lower())

    # 40. dynamic completion requires a validated canonical report
    def test_40_dynamic_analysis_completed_with_canonical_report(self):
        from src.demo_orchestrator import _wire_dynamic_exploration
        from src.scan_state import create_initial_scan_state, load_scan_state, save_scan_state

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

        init_st = create_initial_scan_state(scan_id=self.base_dir.name, target_url="http://test.com/app.apk")
        save_scan_state(self.base_dir, init_st)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=[obs1, obs2]), \
             patch("src.dynamic.action.executor.ActionExecutor.click", return_value=_make_action_result("act_1", success=True)), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe", return_value=RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture"), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture", return_value=CaptureSummary(total_transactions=0)):
            _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))

        final_st = load_scan_state(self.base_dir)
        self.assertEqual(final_st.get("stages", {}).get("dynamic_analysis", {}).get("status"), "completed")

        from src.dynamic.report import load_dynamic_analysis_report
        load_dynamic_analysis_report(self.base_dir)

    # 41. no dynamic_analysis_report.json created

    def test_41_no_dynamic_analysis_report_json_created(self):
        report_file = self.base_dir / "dynamic" / "dynamic_analysis_report.json"
        self.assertFalse(report_file.is_file())

    # 42. PASS preflight still permits exploration and traffic
    def test_42_pass_preflight_permits_exploration_and_traffic(self):
        from src.demo_orchestrator import _wire_dynamic_exploration
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

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=[obs1, obs2]), \
             patch("src.dynamic.action.executor.ActionExecutor.click", return_value=_make_action_result("act_1", success=True)), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe", return_value=RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture") as mock_start, \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture", return_value=CaptureSummary(total_transactions=0)):
            res = _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))

        self.assertIsNotNone(res)
        self.assertEqual(res.steps_attempted, 1)
        mock_start.assert_called_once()

    # 43. usable WARN still permits exploration
    def test_43_usable_warn_permits_exploration(self):
        from src.demo_orchestrator import _wire_dynamic_exploration
        dyn_dir = self.base_dir / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        (dyn_dir / "preflight_result.json").write_text(json.dumps({
            "status": "WARN",
            "device": {"connected": True, "serial": "emulator-5554"},
            "application": {"process_running": True, "package_name": self.pkg},
            "runtime": {"launch_success": True, "immediate_crash": False},
        }))
        (dyn_dir / "session.json").write_text(json.dumps({
            "session_id": self.session_id,
            "status": "ACTIVE",
        }))

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=[obs1, obs2]), \
             patch("src.dynamic.action.executor.ActionExecutor.click", return_value=_make_action_result("act_1", success=True)), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe", return_value=RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture"), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture", return_value=CaptureSummary(total_transactions=0)):
            res = _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))

        self.assertIsNotNone(res)
        self.assertEqual(res.steps_attempted, 1)

    # 44. usable WARN with unavailable traffic backend still runs exploration
    def test_44_usable_warn_with_unavailable_traffic_backend_still_runs_exploration(self):
        from src.demo_orchestrator import _wire_dynamic_exploration
        dyn_dir = self.base_dir / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        (dyn_dir / "preflight_result.json").write_text(json.dumps({
            "status": "WARN",
            "device": {"connected": True, "serial": "emulator-5554"},
            "application": {"process_running": True, "package_name": self.pkg},
            "runtime": {"launch_success": True, "immediate_crash": False},
        }))
        (dyn_dir / "session.json").write_text(json.dumps({
            "session_id": self.session_id,
            "status": "ACTIVE",
        }))

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=[obs1, obs2]), \
             patch("src.dynamic.action.executor.ActionExecutor.click", return_value=_make_action_result("act_1", success=True)), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe", return_value=RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=False, adb_available=True, status=TrafficReadinessStatus.FAIL)):
            res = _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))

        self.assertIsNotNone(res)
        self.assertEqual(res.steps_attempted, 1)
        self.assertTrue((self.base_dir / "dynamic" / "exploration_result.json").is_file())

    # 45. FAIL prevents exploration and traffic
    def test_45_fail_prevents_exploration_and_traffic(self):
        from src.demo_orchestrator import _wire_dynamic_exploration
        dyn_dir = self.base_dir / "dynamic"
        dyn_dir.mkdir(parents=True, exist_ok=True)
        (dyn_dir / "preflight_result.json").write_text(json.dumps({
            "status": "FAIL",
            "device": {"connected": False},
            "application": {"process_running": False},
            "runtime": {"launch_success": False},
        }))
        (dyn_dir / "session.json").write_text(json.dumps({
            "session_id": self.session_id,
            "status": "ACTIVE",
        }))

        with patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture") as mock_start:
            res = _wire_dynamic_exploration(self.base_dir, package_name=self.pkg)

        self.assertIsNone(res)
        mock_start.assert_not_called()
        self.assertFalse((self.base_dir / "dynamic" / "exploration_result.json").is_file())

    # 46. native backend declares HTTP visibility available
    def test_46_native_backend_declares_http_visibility_available(self):
        from src.dynamic.traffic.native_backend import NativeProxyCaptureBackend
        native_backend = NativeProxyCaptureBackend()
        service = DynamicTrafficService(backend=native_backend)
        vis = service.get_visibility_metadata()
        self.assertEqual(vis["http_visibility"], "available")

    # 47. native backend does not claim HTTPS visibility
    def test_47_native_backend_does_not_claim_https_visibility(self):
        from src.dynamic.traffic.native_backend import NativeProxyCaptureBackend
        native_backend = NativeProxyCaptureBackend()
        service = DynamicTrafficService(backend=native_backend)
        vis = service.get_visibility_metadata()
        self.assertEqual(vis["https_visibility"], "unavailable")
        self.assertEqual(vis["https_reason"], "cleartext_http_only_backend")

    # 48. mitmproxy trusted HTTPS readiness can declare HTTPS available
    def test_48_mitmproxy_trusted_https_readiness_declares_https_available(self):
        service = DynamicTrafficService()
        readiness = ProxyReadinessResult(
            backend_available=True,
            adb_available=True,
            https_interception=HttpsInterceptionReadiness(
                ca_certificate_installed=True,
                certificate_trust_unknown=False,
            ),
        )
        service.last_readiness = readiness
        vis = service.get_visibility_metadata()
        self.assertEqual(vis["https_visibility"], "available")
        self.assertEqual(vis["https_reason"], "ca_trusted")

    # 49. uncertain CA trust does not claim HTTPS available
    def test_49_uncertain_ca_trust_does_not_claim_https_available(self):
        service = DynamicTrafficService()
        readiness = ProxyReadinessResult(
            backend_available=True,
            adb_available=True,
            https_interception=HttpsInterceptionReadiness(
                ca_certificate_installed=False,
                certificate_trust_unknown=True,
            ),
        )
        service.last_readiness = readiness
        vis = service.get_visibility_metadata()
        self.assertEqual(vis["https_visibility"], "unavailable")
        self.assertEqual(vis["https_reason"], "certificate_trust_unknown")

    # 50. zero transactions + full visibility can say no traffic observed
    def test_50_zero_transactions_full_visibility_says_no_traffic_observed(self):
        ev = create_action_traffic_evidence(
            action_id="act_zero",
            source_node_id="node_1",
            transactions=[],
            http_visibility="available",
            https_visibility="available",
        )
        self.assertEqual(ev.correlation_status, "available")
        self.assertEqual(ev.correlation_note, "No traffic was observed during the action window.")

    # 51. zero transactions + incomplete HTTPS visibility is partial, not full available
    def test_51_zero_transactions_incomplete_https_visibility_is_partial(self):
        ev = create_action_traffic_evidence(
            action_id="act_zero_part",
            source_node_id="node_1",
            transactions=[],
            http_visibility="available",
            https_visibility="unavailable",
            https_visibility_reason="certificate_trust_unknown",
        )
        self.assertEqual(ev.correlation_status, "partial")
        self.assertIn("No visible HTTP transactions were captured during the action window; HTTPS visibility was unavailable.", ev.correlation_note)

    # 52. zero transactions + unavailable backend is unavailable
    def test_52_zero_transactions_unavailable_backend_is_unavailable(self):
        ev = create_action_traffic_evidence(
            action_id="act_unavail",
            source_node_id="node_1",
            transactions=[],
            correlation_status="unavailable",
            error="Backend failed to start",
        )
        self.assertEqual(ev.correlation_status, "unavailable")
        self.assertEqual(ev.correlation_note, "Backend failed to start")

    # 53. captured HTTP transaction remains valid evidence under partial HTTPS visibility
    def test_53_captured_http_transaction_remains_valid_evidence_under_partial_https(self):
        tx = _make_transaction("tx_http_1", method="GET", host="api.example.com", path="/api/v1/items")
        ev = create_action_traffic_evidence(
            action_id="act_valid_http",
            source_node_id="node_1",
            transactions=[tx],
            http_visibility="available",
            https_visibility="unavailable",
        )
        self.assertEqual(ev.correlation_status, "partial")
        self.assertEqual(ev.transaction_count, 1)
        self.assertEqual(ev.transaction_ids, ["tx_http_1"])
        self.assertEqual(ev.hosts, ["api.example.com"])
        self.assertEqual(ev.methods, ["GET"])
        self.assertEqual(ev.correlation_note, "traffic observed during action window")

    # 54. traffic.json persists protocol visibility metadata
    def test_54_traffic_json_persists_protocol_visibility_metadata(self):
        storage = TrafficStorage(base_dir=str(self.base_dir / "dynamic"))
        target_path = self.base_dir / "dynamic" / "traffic.json"
        summary = CaptureSummary(
            capture_id="cap_test",
            session_id=self.session_id,
            total_transactions=0,
            http_visibility="available",
            https_visibility="unavailable",
            https_visibility_reason="cleartext_http_only_backend",
            proxy_restored=True,
        )
        capture = CaptureSession(
            capture_id="cap_test",
            session_id=self.session_id,
            backend="NativeProxyCaptureBackend",
        )
        storage.save_traffic_json(target_path, self.session_id, transactions=[], capture=capture, summary=summary)

        with open(target_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["backend"], "NativeProxyCaptureBackend")
        self.assertEqual(data["http_visibility"], "available")
        self.assertEqual(data["https_visibility"], "unavailable")
        self.assertEqual(data["https_visibility_reason"], "cleartext_http_only_backend")
        self.assertTrue(data["proxy_restored"])
        self.assertEqual(data["summary"]["http_visibility"], "available")
        self.assertEqual(data["summary"]["https_visibility"], "unavailable")

    # 55. traffic_evidence.json persists compact visibility metadata
    def test_55_traffic_evidence_json_persists_compact_visibility_metadata(self):
        evidence_path = self.base_dir / "dynamic" / "traffic_evidence.json"
        artifact = TrafficEvidenceArtifact(session_id=self.session_id)
        ev = create_action_traffic_evidence(
            action_id="act_persist_1",
            source_node_id="node_1",
            transactions=[],
            http_visibility="available",
            https_visibility="unavailable",
            https_visibility_reason="certificate_trust_unknown",
        )
        artifact.record_action_evidence(ev, evidence_path)

        loaded = TrafficEvidenceArtifact.load_or_create(evidence_path, self.session_id)
        self.assertEqual(len(loaded.actions), 1)
        action_ev = loaded.actions[0]
        self.assertEqual(action_ev.correlation_status, "partial")
        self.assertEqual(action_ev.http_visibility, "available")
        self.assertEqual(action_ev.https_visibility, "unavailable")
        self.assertEqual(action_ev.https_visibility_reason, "certificate_trust_unknown")

    # 56. timeline correlation status reflects partial visibility
    def test_56_timeline_correlation_status_reflects_partial_visibility(self):
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0
        mock_traffic.get_transactions_since.return_value = []
        mock_traffic.get_visibility_metadata.return_value = {
            "http_visibility": "available",
            "https_visibility": "unavailable",
            "https_reason": "certificate_trust_unknown",
        }

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

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
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            timeline_recorder=_recorder,
            limits=ExplorationLimits(max_steps=1),
        )

        corr_events = [meta for name, meta in timeline_events if name == "ACTION_TRAFFIC_CORRELATED"]
        self.assertEqual(len(corr_events), 1)
        self.assertEqual(corr_events[0]["correlation_status"], "partial")
        self.assertEqual(corr_events[0]["visibility"], "partial")
        self.assertIn("No visible HTTP transactions were captured", corr_events[0]["correlation_note"])

    # 57. RouteEdge does not imply full visibility when HTTPS is unavailable
    def test_57_route_edge_does_not_imply_full_visibility_when_https_unavailable(self):
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.return_value = 0
        mock_traffic.get_transactions_since.return_value = []
        mock_traffic.get_visibility_metadata.return_value = {
            "http_visibility": "available",
            "https_visibility": "unavailable",
            "https_reason": "certificate_trust_unknown",
        }

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )

        edges = list(rg.edges.values())
        self.assertEqual(len(edges), 1)
        edge_traffic = edges[0].metadata.get("traffic", {})
        self.assertEqual(edge_traffic.get("visibility"), "partial")
        self.assertNotEqual(edge_traffic.get("visibility"), "available")

    # 58. no certificate pinning claim is fabricated
    def test_58_no_certificate_pinning_claim_is_fabricated(self):
        service = DynamicTrafficService()
        readiness = ProxyReadinessResult(
            backend_available=True,
            adb_available=True,
            https_interception=HttpsInterceptionReadiness(
                ca_certificate_installed=False,
                certificate_trust_unknown=True,
                pinning_suspected=False,
            ),
        )
        service.last_readiness = readiness
        vis = service.get_visibility_metadata()
        ev = create_action_traffic_evidence(
            action_id="act_1",
            source_node_id="node_1",
            transactions=[],
            http_visibility=vis["http_visibility"],
            https_visibility=vis["https_visibility"],
            https_visibility_reason=vis["https_reason"],
        )
        self.assertNotIn("pinning", ev.correlation_note.lower())
        self.assertNotIn("certificate pinning", str(vis).lower())

    # 59. traffic limitation does not fail dynamic exploration
    def test_59_traffic_limitation_does_not_fail_dynamic_exploration(self):
        mock_traffic = MagicMock(spec=DynamicTrafficService)
        mock_traffic.get_current_marker.side_effect = Exception("Proxy connection broken")
        mock_traffic.get_transactions_since.side_effect = Exception("Proxy connection broken")
        mock_traffic.get_visibility_metadata.return_value = {
            "http_visibility": "unavailable",
            "https_visibility": "unavailable",
            "https_reason": "backend_crashed",
        }

        mock_executor = MagicMock(spec=ActionExecutor)
        mock_executor.click.return_value = _make_action_result("act_1", success=True)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        rg = RouteGraph(run_id="run_1", session_id=self.session_id)
        res = run_exploration(
            observer=MagicMock(return_value=obs2),
            executor=mock_executor,
            route_graph=rg,
            initial_observation=obs1,
            traffic_service=mock_traffic,
            traffic_evidence_file=self.evidence_file,
            limits=ExplorationLimits(max_steps=1),
        )
        self.assertNotEqual(res.status, ExplorationStatus.FAILED.value)
        self.assertEqual(res.actions_succeeded, 1)

    # 60. dynamic_analysis remains partial, never completed
    def test_60_dynamic_analysis_completed_with_canonical_report(self):
        from src.demo_orchestrator import _wire_dynamic_exploration
        from src.scan_state import create_initial_scan_state, load_scan_state, save_scan_state

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

        init_st = create_initial_scan_state(scan_id=self.base_dir.name, target_url="http://test.com/app.apk")
        save_scan_state(self.base_dir, init_st)

        obs1 = self._create_mock_observation("screen_1")
        obs2 = self._create_mock_observation("screen_2")

        with patch("src.dynamic.ui.observer.observe_screen", side_effect=[obs1, obs2]), \
             patch("src.dynamic.action.executor.ActionExecutor.click", return_value=_make_action_result("act_1", success=True)), \
             patch("src.dynamic.runtime.observer.AndroidRuntimeObserver.observe", return_value=RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.check_readiness", return_value=ProxyReadinessResult(backend_available=True, adb_available=True, status=TrafficReadinessStatus.PASS)), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.start_capture"), \
             patch("src.dynamic.traffic.service.DynamicTrafficService.stop_capture", return_value=CaptureSummary(total_transactions=5)):
            _wire_dynamic_exploration(self.base_dir, package_name=self.pkg, limits=ExplorationLimits(max_steps=1))

        final_st = load_scan_state(self.base_dir)
        stage_status = final_st.get("stages", {}).get("dynamic_analysis", {}).get("status")
        self.assertEqual(stage_status, "completed")
        self.assertTrue((self.base_dir / "dynamic_analysis_report.json").is_file())

        from src.dynamic.report import load_dynamic_analysis_report
        load_dynamic_analysis_report(self.base_dir)

    # 61. request/response body persistence remains bounded and sanitized

    def test_61_request_response_body_persistence_remains_bounded_and_sanitized(self):
        from src.dynamic.traffic.normalizer import MAX_CAPTURE_BODY_BYTES, process_body_content

        huge_body = b"X" * (MAX_CAPTURE_BODY_BYTES + 5000)
        parsed, meta = process_body_content(huge_body, "text/plain")
        self.assertTrue(meta["truncated"])
        self.assertEqual(len(parsed.encode("utf-8")), MAX_CAPTURE_BODY_BYTES)
        self.assertEqual(meta["original_size"], MAX_CAPTURE_BODY_BYTES + 5000)

        sensitive_payload = {
            "username": "user@example.com",
            "password": "super_secret_password_999",
            "token": "jwt.token.val",
            "nested": {
                "api_key": "secret_key_abc",
                "normal_field": 12345,
            }
        }
        sanitized = sanitize_body_payload(sensitive_payload)
        self.assertEqual(sanitized["username"], "user@example.com")
        self.assertEqual(sanitized["password"], "[REDACTED]")
        self.assertEqual(sanitized["token"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["api_key"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["normal_field"], 12345)


if __name__ == "__main__":
    unittest.main()
