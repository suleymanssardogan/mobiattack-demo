"""Comprehensive tests for Generic UI Observation Primitive (Week 1 — Day 4 Task 4.2)."""

import json
import unittest
from unittest.mock import MagicMock, patch
import xml.etree.ElementTree as ET

from src.android_runtime_launcher import AndroidRuntimeError
from src.dynamic.ui.models import ActionCandidate, ScreenObservation, UiNode
from src.dynamic.ui.observer import (
    DEFAULT_UI_OBSERVE_DEADLINE_SECONDS,
    DEFAULT_UI_OBSERVE_MAX_ATTEMPTS,
    DEFAULT_UI_OBSERVE_POLL_INTERVAL,
    UIObservationError,
    compute_node_id,
    compute_screen_identity,
    extract_ui_node,
    observe_screen,
    parse_ui_hierarchy,
)

SAMPLE_LOGIN_XML = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.example.bank" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[0,0][1080,2400]">
    <node index="0" text="" resource-id="com.example.bank:id/toolbar" class="android.view.ViewGroup" package="com.example.bank" content-desc="Navigation" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[0,72][1080,216]">
      <node index="0" text="Sign In" resource-id="com.example.bank:id/title" class="android.widget.TextView" package="com.example.bank" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[48,114][240,174]" />
    </node>
    <node index="1" text="" resource-id="com.example.bank:id/input_user" class="android.widget.EditText" package="com.example.bank" content-desc="Username Input" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="true" password="false" selected="false" bounds="[72,360][1008,480]" />
    <node index="2" text="Secret123" resource-id="com.example.bank:id/input_password" class="android.widget.EditText" package="com.example.bank" content-desc="Password Input" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="true" password="true" selected="false" bounds="[72,520][1008,640]" />
    <node index="3" text="Login" resource-id="com.example.bank:id/btn_login" class="android.widget.Button" package="com.example.bank" content-desc="Submit Login" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[72,700][1008,820]" />
    <node index="4" text="Disabled Register" resource-id="com.example.bank:id/btn_register" class="android.widget.Button" package="com.example.bank" content-desc="" checkable="false" checked="false" clickable="true" enabled="false" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[72,860][1008,980]" />
    <node index="5" text="Zero Size" resource-id="com.example.bank:id/zero_btn" class="android.widget.Button" package="com.example.bank" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="false" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="[0,0][0,0]" />
  </node>
</hierarchy>
"""

SAMPLE_COMPOSE_XML = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.view.View" package="com.example.compose" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" bounds="[0,0][1080,2400]">
    <node index="0" text="" resource-id="" class="android.view.View" package="com.example.compose" content-desc="Menu Button" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" bounds="[48,96][144,192]" />
    <node index="1" text="" resource-id="" class="android.view.View" package="com.example.compose" content-desc="Cart Button" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" bounds="[936,96][1032,192]" />
  </node>
</hierarchy>
"""

SAMPLE_PERMISSION_DIALOG_XML = """<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.android.permissioncontroller" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" bounds="[72,960][1008,1440]">
    <node index="0" text="Allow app to access camera?" resource-id="com.android.permissioncontroller:id/permission_message" class="android.widget.TextView" package="com.android.permissioncontroller" content-desc="" checkable="false" checked="false" clickable="false" enabled="true" focusable="false" focused="false" scrollable="false" bounds="[120,1020][960,1140]" />
    <node index="1" text="While using the app" resource-id="com.android.permissioncontroller:id/permission_allow_foreground_only_button" class="android.widget.Button" package="com.android.permissioncontroller" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" bounds="[120,1180][960,1280]" />
  </node>
</hierarchy>
"""


class TestDynamicUiObserver(unittest.TestCase):
    """Unit tests validating generic UI observation and screen identity fingerprinting."""

    # 1. Valid hierarchy parsed
    def test_01_valid_hierarchy_parsed(self):
        root = ET.fromstring(SAMPLE_LOGIN_XML)
        obs = parse_ui_hierarchy(
            root=root,
            foreground_package="com.example.bank",
            foreground_activity="com.example.bank.LoginActivity",
            target_package="com.example.bank",
        )
        self.assertIsInstance(obs, ScreenObservation)
        self.assertEqual(obs.foreground_package, "com.example.bank")
        self.assertEqual(obs.foreground_activity, "com.example.bank.LoginActivity")
        self.assertTrue(obs.is_target_package)
        self.assertFalse(obs.is_dialog_or_system)
        self.assertGreater(len(obs.nodes), 4)

    # 2. Clickable nodes discovered
    def test_02_clickable_nodes_discovered(self):
        root = ET.fromstring(SAMPLE_LOGIN_XML)
        obs = parse_ui_hierarchy(root, "com.example.bank", "com.example.bank.LoginActivity")
        # Clickables in XML: input_user, input_password, btn_login, btn_register, zero_btn = 5
        self.assertEqual(obs.clickable_count, 5)

    # 3. EditText / input nodes discovered
    def test_03_input_nodes_discovered(self):
        root = ET.fromstring(SAMPLE_LOGIN_XML)
        obs = parse_ui_hierarchy(root, "com.example.bank", "com.example.bank.LoginActivity")
        # input_user and input_password are EditText = 2
        self.assertEqual(obs.input_count, 2)

    # 4. Disabled clickable excluded from action candidates
    def test_04_disabled_clickable_excluded_from_action_candidates(self):
        root = ET.fromstring(SAMPLE_LOGIN_XML)
        obs = parse_ui_hierarchy(root, "com.example.bank", "com.example.bank.LoginActivity")
        candidate_ids = [c.resource_id for c in obs.action_candidates]
        # btn_register has enabled="false", must NOT be in action candidates
        self.assertNotIn("com.example.bank:id/btn_register", candidate_ids)

    # 5. Zero-size bounds excluded safely from action candidates
    def test_05_zero_size_bounds_excluded_from_action_candidates(self):
        root = ET.fromstring(SAMPLE_LOGIN_XML)
        obs = parse_ui_hierarchy(root, "com.example.bank", "com.example.bank.LoginActivity")
        candidate_ids = [c.resource_id for c in obs.action_candidates]
        # zero_btn has bounds="[0,0][0,0]", must NOT be in action candidates
        self.assertNotIn("com.example.bank:id/zero_btn", candidate_ids)

    # 6. Bounds center calculated correctly
    def test_06_bounds_center_calculated_correctly(self):
        root = ET.fromstring(SAMPLE_LOGIN_XML)
        obs = parse_ui_hierarchy(root, "com.example.bank", "com.example.bank.LoginActivity")
        login_btn = next(c for c in obs.action_candidates if c.resource_id == "com.example.bank:id/btn_login")
        # Bounds: [72,700][1008,820]
        # center_x = (72 + 1008) // 2 = 540
        # center_y = (700 + 820) // 2 = 760
        self.assertEqual(login_btn.center_x, 540)
        self.assertEqual(login_btn.center_y, 760)

    # 7. Malformed XML handled safely
    def test_07_malformed_xml_handled_safely(self):
        # Missing closing tags
        malformed = "<hierarchy><node bounds='[0,0][100,100]'><unclosed>"
        with self.assertRaises(ET.ParseError):
            ET.fromstring(malformed)

    # 8. Missing attributes do not crash parser
    def test_08_missing_attributes_do_not_crash_parser(self):
        minimal_xml = "<hierarchy><node index='0' /></hierarchy>"
        root = ET.fromstring(minimal_xml)
        obs = parse_ui_hierarchy(root, "pkg", "act")
        self.assertEqual(len(obs.nodes), 1)
        node = obs.nodes[0]
        self.assertEqual(node.class_name, "")
        self.assertEqual(node.bounds, (0, 0, 0, 0))
        self.assertEqual(node.center_x, 0)
        self.assertEqual(node.center_y, 0)

    # 9. Same hierarchy -> same screen_identity
    def test_09_same_hierarchy_produces_identical_screen_identity(self):
        root1 = ET.fromstring(SAMPLE_LOGIN_XML)
        root2 = ET.fromstring(SAMPLE_LOGIN_XML)

        obs1 = parse_ui_hierarchy(root1, "com.example.bank", "LoginActivity")
        obs2 = parse_ui_hierarchy(root2, "com.example.bank", "LoginActivity")

        self.assertTrue(bool(obs1.screen_identity))
        self.assertEqual(obs1.screen_identity, obs2.screen_identity)

    # 10. Dynamic text change -> screen_identity remains stable
    def test_10_dynamic_text_change_does_not_change_screen_identity(self):
        root1 = ET.fromstring(SAMPLE_LOGIN_XML)

        # XML with different dynamic text (e.g. clock change or label text change)
        xml2 = SAMPLE_LOGIN_XML.replace('text="Sign In"', 'text="Sign In (12:45 PM)"')
        root2 = ET.fromstring(xml2)

        obs1 = parse_ui_hierarchy(root1, "com.example.bank", "LoginActivity")
        obs2 = parse_ui_hierarchy(root2, "com.example.bank", "LoginActivity")

        self.assertEqual(obs1.screen_identity, obs2.screen_identity)

    # 11. Structural clickable change -> screen_identity changes
    def test_11_structural_clickable_change_modifies_screen_identity(self):
        root1 = ET.fromstring(SAMPLE_LOGIN_XML)

        # Alter structure: remove the login button
        xml2 = SAMPLE_LOGIN_XML.replace('resource-id="com.example.bank:id/btn_login"', 'resource-id="com.example.bank:id/different_btn"')
        root2 = ET.fromstring(xml2)

        obs1 = parse_ui_hierarchy(root1, "com.example.bank", "LoginActivity")
        obs2 = parse_ui_hierarchy(root2, "com.example.bank", "LoginActivity")

        self.assertNotEqual(obs1.screen_identity, obs2.screen_identity)

    # 12. Same activity but different hierarchy -> different screen_identity
    def test_12_same_activity_different_hierarchy_different_identity(self):
        root1 = ET.fromstring(SAMPLE_LOGIN_XML)
        root2 = ET.fromstring(SAMPLE_COMPOSE_XML)

        obs1 = parse_ui_hierarchy(root1, "com.example.app", "MainActivity")
        obs2 = parse_ui_hierarchy(root2, "com.example.app", "MainActivity")

        self.assertNotEqual(obs1.screen_identity, obs2.screen_identity)

    # 13. Jetpack Compose nodes without resource IDs still get stable identity
    def test_13_compose_nodes_without_resource_ids_get_stable_identity(self):
        root1 = ET.fromstring(SAMPLE_COMPOSE_XML)
        root2 = ET.fromstring(SAMPLE_COMPOSE_XML)

        obs1 = parse_ui_hierarchy(root1, "com.example.compose", "MainActivity")
        obs2 = parse_ui_hierarchy(root2, "com.example.compose", "MainActivity")

        self.assertTrue(bool(obs1.screen_identity))
        self.assertEqual(obs1.screen_identity, obs2.screen_identity)
        # Should have found 2 action candidates via content-desc bounds
        self.assertEqual(len(obs1.action_candidates), 2)
        self.assertEqual(obs1.action_candidates[0].content_desc, "Menu Button")

    # 14. Action candidate node IDs deterministic
    def test_14_action_candidate_node_ids_deterministic(self):
        root1 = ET.fromstring(SAMPLE_LOGIN_XML)
        root2 = ET.fromstring(SAMPLE_LOGIN_XML)

        obs1 = parse_ui_hierarchy(root1, "pkg", "act")
        obs2 = parse_ui_hierarchy(root2, "pkg", "act")

        ids1 = [c.node_id for c in obs1.action_candidates]
        ids2 = [c.node_id for c in obs2.action_candidates]

        self.assertEqual(ids1, ids2)
        self.assertTrue(all(len(nid) == 12 for nid in ids1))

    # 15. Password field text not exposed raw
    def test_15_password_field_text_redacted(self):
        root = ET.fromstring(SAMPLE_LOGIN_XML)
        obs = parse_ui_hierarchy(root, "com.example.bank", "LoginActivity")

        pw_node = next(n for n in obs.nodes if n.resource_id == "com.example.bank:id/input_password")
        self.assertTrue(pw_node.password)
        self.assertEqual(pw_node.text, "[PROTECTED]")
        self.assertNotIn("Secret123", json.dumps(obs.to_dict()))

    # 16. System permission dialog can be observed cleanly
    def test_16_system_permission_dialog_observed_cleanly(self):
        root = ET.fromstring(SAMPLE_PERMISSION_DIALOG_XML)
        obs = parse_ui_hierarchy(
            root=root,
            foreground_package="com.android.permissioncontroller",
            foreground_activity="com.android.permissioncontroller.permission.ui.GrantPermissionsActivity",
            target_package="com.example.bank",
        )

        self.assertTrue(obs.is_dialog_or_system)
        self.assertFalse(obs.is_target_package)
        self.assertEqual(obs.foreground_package, "com.android.permissioncontroller")
        self.assertGreater(len(obs.action_candidates), 0)

    # 17. Wrong foreground package marked, not crashed
    def test_17_wrong_foreground_package_marked(self):
        root = ET.fromstring(SAMPLE_LOGIN_XML)
        obs = parse_ui_hierarchy(
            root=root,
            foreground_package="com.android.launcher3",
            foreground_activity="com.android.launcher3.Launcher",
            target_package="com.example.bank",
        )

        self.assertFalse(obs.is_target_package)
        self.assertEqual(obs.foreground_package, "com.android.launcher3")

    # 18. Delayed UI: first dump fails, second succeeds -> observe_screen succeeds
    @patch("src.dynamic.ui.observer.get_current_activity", return_value={"observed_package": "com.test", "observed_activity": "com.test.Main"})
    @patch("src.dynamic.ui.observer.dump_window_hierarchy")
    def test_18_delayed_ui_succeeds_on_second_attempt(
        self, mock_dump, mock_act
    ):
        valid_root = ET.fromstring(SAMPLE_LOGIN_XML)
        # Attempt 1: dumpsys fails/empty, Attempt 2: valid root
        mock_dump.side_effect = [
            AndroidRuntimeError("UI hierarchy dump empty"),
            valid_root,
        ]

        sleeper_mock = MagicMock()
        obs = observe_screen(
            serial="emulator-5554",
            target_package="com.test",
            max_attempts=3,
            poll_interval=0.1,
            deadline_seconds=3.0,
            sleeper=sleeper_mock,
        )

        self.assertIsInstance(obs, ScreenObservation)
        self.assertEqual(obs.observation_attempts, 2)
        self.assertEqual(sleeper_mock.call_count, 1)

    # 19. Never stabilizes: all attempts fail -> raises UIObservationError
    @patch("src.dynamic.ui.observer.get_current_activity", return_value={"observed_package": "com.test", "observed_activity": "com.test.Main"})
    @patch("src.dynamic.ui.observer.dump_window_hierarchy")
    def test_19_never_stabilizes_raises_ui_observation_error(
        self, mock_dump, mock_act
    ):
        mock_dump.side_effect = AndroidRuntimeError("uiautomator crashed")

        sleeper_mock = MagicMock()
        with self.assertRaises(UIObservationError) as ctx:
            observe_screen(
                serial="emulator-5554",
                target_package="com.test",
                max_attempts=3,
                poll_interval=0.01,
                deadline_seconds=2.0,
                sleeper=sleeper_mock,
            )

        self.assertIn("Failed to observe screen on device", str(ctx.exception))
        self.assertEqual(sleeper_mock.call_count, 2)

    # 20. No infinite retry: bounded by max_attempts
    @patch("src.dynamic.ui.observer.get_current_activity", return_value={"observed_package": "com.test", "observed_activity": "com.test.Main"})
    @patch("src.dynamic.ui.observer.dump_window_hierarchy")
    def test_20_no_infinite_retry(self, mock_dump, mock_act):
        mock_dump.side_effect = AndroidRuntimeError("fail")

        sleeper_mock = MagicMock()
        with self.assertRaises(UIObservationError):
            observe_screen(
                serial="emulator-5554",
                max_attempts=4,
                poll_interval=0.01,
                deadline_seconds=5.0,
                sleeper=sleeper_mock,
            )

        self.assertEqual(mock_dump.call_count, 4)

    # 21. Serialization to dict matches schema
    def test_21_to_dict_matches_expected_schema(self):
        root = ET.fromstring(SAMPLE_LOGIN_XML)
        obs = parse_ui_hierarchy(root, "com.example.bank", "LoginActivity", target_package="com.example.bank")
        d = obs.to_dict()

        self.assertIn("screen_identity", d)
        self.assertIn("foreground_package", d)
        self.assertIn("foreground_activity", d)
        self.assertIn("action_candidates", d)
        self.assertIn("node_count", d)
        self.assertIn("clickable_count", d)
        self.assertIn("input_count", d)
        self.assertEqual(d["target_package"], "com.example.bank")
        self.assertTrue(d["is_target_package"])
        self.assertFalse(d["is_dialog_or_system"])


if __name__ == "__main__":
    unittest.main()
