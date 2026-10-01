"""Comprehensive unit tests for Route Graph & State Model (Week 1 — Day 5 Task 5.1).

Verifies all 27 deterministic requirements:
1. empty graph created.
2. first observation creates root node.
3. same screen_identity deduplicates node.
4. visit_count increments.
5. different hierarchy/screen_identity creates new node.
6. same activity + different screen identities create different nodes.
7. clickable actions discovered.
8. input actions discovered.
9. duplicate action candidate deduplicates.
10. newly discovered action merges into existing node.
11. disappearing action not deleted from historical graph.
12. action_id deterministic.
13. node_id deterministic.
14. synthetic transition creates edge.
15. duplicate transition increments observation_count.
16. self-loop allowed.
17. system dialog node accepted.
18. wrong-package node accepted and marked.
19. route graph serializes to JSON.
20. route graph load round-trip.
21. atomic write.
22. corrupted JSON handled explicitly.
23. no password raw text persisted.
24. no raw XML persisted.
25. no host absolute path persisted.
26. no tap/ADB action executed.
27. graph primitive does not mutate scan_state.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from src.dynamic.route.graph import RouteGraph, SCHEMA_VERSION
from src.dynamic.route.models import (
    ActionStatus,
    DiscoveredAction,
    RouteEdge,
    RouteNode,
    compute_action_id,
    compute_edge_id,
    compute_node_id,
)
from src.dynamic.route.storage import (
    RouteGraphCorruptionError,
    RouteGraphError,
    RouteGraphStorage,
)
from src.dynamic.ui.models import ActionCandidate, ScreenObservation, UiNode
from src.scan_state import create_initial_scan_state, load_scan_state, save_scan_state


def _make_obs(
    screen_identity: str = "screen_hash_1",
    pkg: str = "com.example.app",
    activity: str = "com.example.app.MainActivity",
    target_pkg: str = "com.example.app",
    is_target_pkg: bool = True,
    is_dialog: bool = False,
    actions: list[ActionCandidate] | None = None,
) -> ScreenObservation:
    """Helper creating a synthetic ScreenObservation for tests."""
    cands = actions or []
    clickable = sum(1 for a in cands if a.action_type == "click")
    inputs = sum(1 for a in cands if a.action_type == "input")
    return ScreenObservation(
        screen_identity=screen_identity,
        foreground_package=pkg,
        foreground_activity=activity,
        target_package=target_pkg,
        is_target_package=is_target_pkg,
        is_dialog_or_system=is_dialog,
        timestamp="2026-10-01T10:00:00+00:00",
        clickable_count=clickable,
        input_count=inputs,
        action_candidates=cands,
    )


def _make_candidate(
    node_id: str = "btn_1",
    res_id: str = "com.example.app:id/submit",
    cls_name: str = "android.widget.Button",
    text: str = "Submit",
    action_type: str = "click",
    bounds: tuple[int, int, int, int] = (10, 20, 100, 60),
) -> ActionCandidate:
    """Helper creating a synthetic ActionCandidate."""
    cx = (bounds[0] + bounds[2]) // 2
    cy = (bounds[1] + bounds[3]) // 2
    return ActionCandidate(
        node_id=node_id,
        resource_id=res_id,
        class_name=cls_name,
        text=text,
        content_desc="",
        bounds=bounds,
        center_x=cx,
        center_y=cy,
        action_type=action_type,
    )


class TestDynamicRouteGraph(unittest.TestCase):
    """Test suite for RouteGraph, RouteNode, DiscoveredAction, and RouteGraphStorage."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. empty graph created
    def test_01_empty_graph_created(self):
        graph = RouteGraph(graph_id="test_graph", run_id="run_101")
        self.assertEqual(graph.graph_id, "test_graph")
        self.assertEqual(graph.run_id, "run_101")
        self.assertEqual(graph.node_count, 0)
        self.assertEqual(graph.edge_count, 0)
        self.assertEqual(graph.discovered_action_count, 0)
        self.assertIsNone(graph.root_node_id)
        self.assertIsNone(graph.current_node_id)

    # 2. first observation creates root node
    def test_02_first_observation_creates_root_node(self):
        graph = RouteGraph(run_id="run_101")
        obs = _make_obs(screen_identity="screen_root")
        node = graph.observe_screen(obs)

        self.assertEqual(graph.node_count, 1)
        self.assertEqual(graph.root_node_id, node.route_node_id)
        self.assertEqual(graph.current_node_id, node.route_node_id)
        self.assertEqual(node.screen_identity, "screen_root")
        self.assertEqual(node.visit_count, 1)

    # 3. same screen_identity deduplicates node
    def test_03_same_screen_identity_deduplicates_node(self):
        graph = RouteGraph()
        obs1 = _make_obs(screen_identity="screen_a")
        obs2 = _make_obs(screen_identity="screen_a")

        node1 = graph.observe_screen(obs1)
        node2 = graph.observe_screen(obs2)

        self.assertEqual(graph.node_count, 1)
        self.assertEqual(node1.route_node_id, node2.route_node_id)
        self.assertIs(node1, node2)

    # 4. visit_count increments
    def test_04_visit_count_increments(self):
        graph = RouteGraph()
        obs = _make_obs(screen_identity="screen_a")

        node = graph.observe_screen(obs)
        self.assertEqual(node.visit_count, 1)

        graph.observe_screen(obs)
        self.assertEqual(node.visit_count, 2)

        graph.observe_screen(obs)
        self.assertEqual(node.visit_count, 3)

    # 5. different hierarchy/screen_identity creates new node
    def test_05_different_screen_identity_creates_new_node(self):
        graph = RouteGraph()
        obs_a = _make_obs(screen_identity="screen_a")
        obs_b = _make_obs(screen_identity="screen_b")

        node_a = graph.observe_screen(obs_a)
        node_b = graph.observe_screen(obs_b)

        self.assertEqual(graph.node_count, 2)
        self.assertNotEqual(node_a.route_node_id, node_b.route_node_id)
        self.assertEqual(graph.root_node_id, node_a.route_node_id)
        self.assertEqual(graph.current_node_id, node_b.route_node_id)

    # 6. same activity + different screen identities create different nodes
    def test_06_same_activity_different_screen_identities(self):
        graph = RouteGraph()
        obs1 = _make_obs(screen_identity="ident_login_tab", activity="com.example.MainActivity")
        obs2 = _make_obs(screen_identity="ident_home_tab", activity="com.example.MainActivity")

        node1 = graph.observe_screen(obs1)
        node2 = graph.observe_screen(obs2)

        self.assertEqual(graph.node_count, 2)
        self.assertEqual(node1.activity, "com.example.MainActivity")
        self.assertEqual(node2.activity, "com.example.MainActivity")
        self.assertNotEqual(node1.route_node_id, node2.route_node_id)

    # 7. clickable actions discovered
    def test_07_clickable_actions_discovered(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_login", text="Log In", action_type="click")
        obs = _make_obs(screen_identity="screen_login", actions=[btn])

        node = graph.observe_screen(obs)
        self.assertEqual(len(node.actions), 1)

        act = list(node.actions.values())[0]
        self.assertEqual(act.action_type, "click")
        self.assertEqual(act.ui_node_id, "btn_login")
        self.assertEqual(act.text, "Log In")
        self.assertEqual(act.status, ActionStatus.DISCOVERED.value)

    # 8. input actions discovered
    def test_08_input_actions_discovered(self):
        graph = RouteGraph()
        field = _make_candidate(
            node_id="input_user",
            res_id="com.example:id/username",
            cls_name="android.widget.EditText",
            text="",
            action_type="input",
        )
        obs = _make_obs(screen_identity="screen_login", actions=[field])

        node = graph.observe_screen(obs)
        self.assertEqual(len(node.actions), 1)

        act = list(node.actions.values())[0]
        self.assertEqual(act.action_type, "input")
        self.assertEqual(act.ui_node_id, "input_user")
        self.assertEqual(act.status, ActionStatus.DISCOVERED.value)

    # 9. duplicate action candidate deduplicates
    def test_09_duplicate_action_candidate_deduplicates(self):
        graph = RouteGraph()
        btn1 = _make_candidate(node_id="btn_1", text="Submit", action_type="click")
        btn2 = _make_candidate(node_id="btn_1", text="Submit", action_type="click")
        obs = _make_obs(screen_identity="screen_a", actions=[btn1, btn2])

        node = graph.observe_screen(obs)
        # Should deduplicate to 1 action based on deterministic action_id
        self.assertEqual(len(node.actions), 1)

    # 10. newly discovered action merges into existing node
    def test_10_newly_discovered_action_merges_into_existing_node(self):
        graph = RouteGraph()
        btn1 = _make_candidate(node_id="btn_1", text="One")
        obs1 = _make_obs(screen_identity="screen_a", actions=[btn1])
        node = graph.observe_screen(obs1)
        self.assertEqual(len(node.actions), 1)

        btn2 = _make_candidate(node_id="btn_2", text="Two")
        obs2 = _make_obs(screen_identity="screen_a", actions=[btn1, btn2])
        graph.observe_screen(obs2)

        self.assertEqual(len(node.actions), 2)
        act_ids = {a.ui_node_id for a in node.actions.values()}
        self.assertEqual(act_ids, {"btn_1", "btn_2"})

    # 11. disappearing action not deleted from historical graph
    def test_11_disappearing_action_not_deleted_from_historical_graph(self):
        graph = RouteGraph()
        btn1 = _make_candidate(node_id="btn_dynamic", text="Limited Time Offer")
        obs1 = _make_obs(screen_identity="screen_a", actions=[btn1])
        node = graph.observe_screen(obs1)
        self.assertEqual(len(node.actions), 1)

        # Re-observe without btn1
        obs2 = _make_obs(screen_identity="screen_a", actions=[])
        graph.observe_screen(obs2)

        # Historical action must remain
        self.assertEqual(len(node.actions), 1)
        self.assertIn("btn_dynamic", [a.ui_node_id for a in node.actions.values()])

    # 12. action_id deterministic
    def test_12_action_id_deterministic(self):
        id1 = compute_action_id("screen_hash_1", "btn_submit", "click")
        id2 = compute_action_id("screen_hash_1", "btn_submit", "click")
        id3 = compute_action_id("screen_hash_1", "btn_submit", "input")

        self.assertEqual(id1, id2)
        self.assertNotEqual(id1, id3)
        self.assertTrue(id1.startswith("act_"))

    # 13. node_id deterministic
    def test_13_node_id_deterministic(self):
        id1 = compute_node_id("screen_hash_1")
        id2 = compute_node_id("screen_hash_1")
        id3 = compute_node_id("screen_hash_2")

        self.assertEqual(id1, id2)
        self.assertNotEqual(id1, id3)
        self.assertTrue(id1.startswith("node_"))

    # 14. synthetic transition creates edge
    def test_14_synthetic_transition_creates_edge(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_next", text="Next")
        obs_a = _make_obs(screen_identity="screen_a", actions=[btn])
        node_a = graph.observe_screen(obs_a)

        obs_b = _make_obs(screen_identity="screen_b")

        edge = graph.record_transition(
            source_node=node_a,
            action=list(node_a.actions.values())[0],
            target_observation=obs_b,
        )

        self.assertEqual(graph.edge_count, 1)
        self.assertEqual(edge.source_node_id, node_a.route_node_id)
        self.assertEqual(edge.target_node_id, graph.get_node_by_identity("screen_b").route_node_id)
        self.assertEqual(edge.observation_count, 1)

    # 15. duplicate transition increments observation_count
    def test_15_duplicate_transition_increments_observation_count(self):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_next")
        obs_a = _make_obs(screen_identity="screen_a", actions=[btn])
        obs_b = _make_obs(screen_identity="screen_b")

        node_a = graph.observe_screen(obs_a)
        action = list(node_a.actions.values())[0]

        edge1 = graph.record_transition(node_a, action, obs_b)
        self.assertEqual(edge1.observation_count, 1)

        edge2 = graph.record_transition(node_a, action, obs_b)
        self.assertEqual(edge2.observation_count, 2)
        self.assertEqual(graph.edge_count, 1)
        self.assertEqual(edge1.edge_id, edge2.edge_id)

    # 16. self-loop allowed
    def test_16_self_loop_allowed(self):
        graph = RouteGraph()
        toggle = _make_candidate(node_id="switch_dark_mode")
        obs_a = _make_obs(screen_identity="screen_settings", actions=[toggle])
        node_a = graph.observe_screen(obs_a)
        action = list(node_a.actions.values())[0]

        edge = graph.record_transition(node_a, action, obs_a)
        self.assertEqual(edge.source_node_id, edge.target_node_id)
        self.assertEqual(graph.edge_count, 1)

    # 17. system dialog node accepted
    def test_17_system_dialog_node_accepted(self):
        graph = RouteGraph()
        obs_dialog = _make_obs(
            screen_identity="perm_dialog_hash",
            pkg="com.google.android.permissioncontroller",
            activity="com.android.permissioncontroller.permission.ui.GrantPermissionsActivity",
            is_dialog=True,
            is_target_pkg=False,
        )

        node = graph.observe_screen(obs_dialog)
        self.assertTrue(node.is_dialog_or_system)
        self.assertFalse(node.is_target_package)
        self.assertEqual(graph.node_count, 1)

    # 18. wrong-package node accepted and marked
    def test_18_wrong_package_node_accepted_and_marked(self):
        graph = RouteGraph()
        obs_ext = _make_obs(
            screen_identity="external_browser_hash",
            pkg="com.android.chrome",
            activity="com.google.android.apps.chrome.Main",
            is_dialog=False,
            is_target_pkg=False,
        )

        node = graph.observe_screen(obs_ext)
        self.assertFalse(node.is_target_package)
        self.assertFalse(node.is_dialog_or_system)
        self.assertEqual(node.package_name, "com.android.chrome")

    # 19. route graph serializes to JSON
    def test_19_route_graph_serializes_to_json(self):
        graph = RouteGraph(graph_id="g1", run_id="r1", session_id="s1")
        btn = _make_candidate(node_id="b1")
        obs_a = _make_obs(screen_identity="s_a", actions=[btn])
        obs_b = _make_obs(screen_identity="s_b")

        node_a = graph.observe_screen(obs_a)
        graph.record_transition(node_a, list(node_a.actions.values())[0], obs_b)

        d = graph.to_dict()
        self.assertEqual(d["schema_version"], SCHEMA_VERSION)
        self.assertEqual(d["graph_id"], "g1")
        self.assertEqual(d["run_id"], "r1")
        self.assertEqual(d["node_count"], 2)
        self.assertEqual(d["edge_count"], 1)

        # JSON dump must succeed without circular references
        dumped = json.dumps(d, indent=2)
        self.assertIn('"schema_version": "1.0"', dumped)
        self.assertIn('"s_a"', dumped)

    # 20. route graph load round-trip
    def test_20_route_graph_load_round_trip(self):
        storage = RouteGraphStorage(base_dir=self.output_dir)
        graph = RouteGraph(graph_id="roundtrip_g", run_id="run_rt")
        btn = _make_candidate(node_id="btn_go", text="Go")
        obs_a = _make_obs(screen_identity="sa", actions=[btn])
        obs_b = _make_obs(screen_identity="sb")

        node_a = graph.observe_screen(obs_a)
        graph.record_transition(node_a, list(node_a.actions.values())[0], obs_b)

        saved_path = storage.save_graph(graph)
        self.assertTrue(saved_path.is_file())

        loaded = storage.load_graph(saved_path)
        self.assertEqual(loaded.graph_id, "roundtrip_g")
        self.assertEqual(loaded.run_id, "run_rt")
        self.assertEqual(loaded.node_count, 2)
        self.assertEqual(loaded.edge_count, 1)
        self.assertEqual(loaded.discovered_action_count, 1)

        node_loaded = loaded.get_node_by_identity("sa")
        self.assertIsNotNone(node_loaded)
        self.assertEqual(len(node_loaded.actions), 1)

    # 21. atomic write
    def test_21_atomic_write(self):
        storage = RouteGraphStorage(base_dir=self.output_dir)
        graph = RouteGraph(graph_id="atomic_g")
        obs = _make_obs(screen_identity="screen_atomic")
        graph.observe_screen(obs)

        target_file = (self.output_dir / "dynamic" / "route_graph.json").resolve()

        with patch("os.replace", wraps=os.replace) as mock_replace:
            saved = storage.save_graph(graph, file_path=target_file)
            self.assertEqual(saved, target_file)
            mock_replace.assert_called_once()

        self.assertTrue(target_file.is_file())

    # 22. corrupted JSON handled explicitly
    def test_22_corrupted_json_handled_explicitly(self):
        storage = RouteGraphStorage(base_dir=self.output_dir)
        corrupted_file = self.output_dir / "dynamic" / "route_graph.json"
        corrupted_file.parent.mkdir(parents=True, exist_ok=True)

        # Test empty file
        corrupted_file.write_text("", encoding="utf-8")
        with self.assertRaises(RouteGraphCorruptionError) as ctx:
            storage.load_graph(corrupted_file)
        self.assertIn("empty", str(ctx.exception).lower())

        # Test invalid JSON syntax
        corrupted_file.write_text("{broken json syntax ...", encoding="utf-8")
        with self.assertRaises(RouteGraphCorruptionError) as ctx:
            storage.load_graph(corrupted_file)
        self.assertIn("syntax", str(ctx.exception).lower())

        # Test missing schema fields
        corrupted_file.write_text('{"foo": "bar"}', encoding="utf-8")
        with self.assertRaises(RouteGraphCorruptionError) as ctx:
            storage.load_graph(corrupted_file)
        self.assertIn("missing", str(ctx.exception).lower())

    # 23. no password raw text persisted
    def test_23_no_password_raw_text_persisted(self):
        graph = RouteGraph()
        pwd_field = _make_candidate(
            node_id="edit_pwd",
            res_id="com.example.app:id/password_input",
            cls_name="android.widget.EditText",
            text="SuperSecretPassword123!",
            action_type="input",
        )
        obs = _make_obs(screen_identity="screen_login", actions=[pwd_field])
        graph.observe_screen(obs)

        data = graph.to_dict()
        dumped = json.dumps(data)
        self.assertNotIn("SuperSecretPassword123!", dumped)

    # 24. no raw XML persisted
    def test_24_no_raw_xml_persisted(self):
        graph = RouteGraph()
        obs = _make_obs(screen_identity="screen_a")
        graph.observe_screen(obs)

        data = graph.to_dict()
        dumped = json.dumps(data)
        self.assertNotIn("<hierarchy", dumped)
        self.assertNotIn("<?xml", dumped)
        self.assertNotIn("raw_xml", dumped)

    # 25. no host absolute path persisted
    def test_25_no_host_absolute_path_persisted(self):
        graph = RouteGraph()
        host_path_btn = _make_candidate(
            node_id="btn_open",
            res_id="/Users/alice/Library/Android/sdk/platform-tools",
            text="Open /Users/alice/secret/file.apk",
        )
        obs = _make_obs(screen_identity="screen_host", actions=[host_path_btn])
        graph.observe_screen(obs)

        data = graph.to_dict()
        dumped = json.dumps(data)
        self.assertNotIn("/Users/alice", dumped)
        self.assertIn("<host_path>", dumped)

    # 26. no tap/ADB action executed
    @patch("subprocess.run")
    @patch("subprocess.Popen")
    def test_26_no_tap_adb_action_executed(self, mock_popen, mock_run):
        graph = RouteGraph()
        btn = _make_candidate(node_id="btn_tap_me", text="Tap")
        obs_a = _make_obs(screen_identity="sa", actions=[btn])
        obs_b = _make_obs(screen_identity="sb")

        node = graph.observe_screen(obs_a)
        graph.record_transition(node, list(node.actions.values())[0], obs_b)

        # Neither subprocess.run nor subprocess.Popen may be called
        mock_run.assert_not_called()
        mock_popen.assert_not_called()

    # 27. graph primitive does not mutate scan_state
    def test_27_graph_primitive_does_not_mutate_scan_state(self):
        # Setup initial scan_state.json
        state_dir = self.output_dir / "scan_dir"
        state_dir.mkdir(parents=True, exist_ok=True)
        init_state = create_initial_scan_state(
            scan_id="test_scan_42",
            target_url="http://example.com/app.apk",
            platform="android",
        )
        save_scan_state(state_dir, init_state)

        # Run RouteGraph operations
        storage = RouteGraphStorage(base_dir=state_dir)
        graph = RouteGraph(run_id="test_scan_42")
        obs = _make_obs(screen_identity="screen_isolated")
        graph.observe_screen(obs)
        storage.save_graph(graph, file_path=state_dir / "dynamic" / "route_graph.json")

        # Verify scan_state.json was untouched and retains 'not_available'
        loaded_state = load_scan_state(state_dir)
        self.assertEqual(loaded_state["stages"]["dynamic_analysis"]["status"], "not_available")
        self.assertFalse(loaded_state["artifacts"]["dynamic_analysis_report"]["available"])
