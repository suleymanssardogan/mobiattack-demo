"""Bounded Play Store loading retries and stray install-button regression."""
import xml.etree.ElementTree as ET
from unittest.mock import patch
from src.play_store_ui_automator import inspect_play_store_hierarchy, attempt_play_store_ui_install

HOME = ET.fromstring('<hierarchy><node package="com.android.vending" text="Sponsored"/><node package="com.android.vending" text="Install" bounds="[10,10][110,70]"/></hierarchy>')
DETAILS = ET.fromstring('<hierarchy><node package="com.android.vending" text="About this app"/><node package="com.android.vending" text="Install" bounds="[10,10][110,70]"/></hierarchy>')
BLOCKED = ET.fromstring('<hierarchy><node package="com.android.vending" text="Sign in to your Google Account"/></hierarchy>')


def test_homepage_ad_is_not_an_install_target():
    result = inspect_play_store_hierarchy(HOME, 'com.kiloo.subwaysurf')
    assert result.is_blocked and result.install_button_bounds is None
    assert not result.package_context_verified


def test_loading_then_details_taps_once():
    with patch('src.play_store_ui_automator.dump_window_hierarchy', side_effect=[HOME, HOME, DETAILS]) as dump, patch('src.play_store_ui_automator.time.sleep'), patch('src.play_store_ui_automator.tap_screen_bounds', return_value=(60, 40)) as tap:
        result = attempt_play_store_ui_install('device', 'com.kiloo.subwaysurf', 'adb')
    assert result['status'] == 'install_triggered'
    assert dump.call_count == 3
    tap.assert_called_once()


def test_unknown_screen_retries_bounded_and_never_taps():
    with patch('src.play_store_ui_automator.dump_window_hierarchy', return_value=HOME) as dump, patch('src.play_store_ui_automator.time.sleep'), patch('src.play_store_ui_automator.tap_screen_bounds') as tap:
        result = attempt_play_store_ui_install('device', 'com.kiloo.subwaysurf', 'adb')
    assert result['status'] == 'blocked'
    assert dump.call_count == 4
    tap.assert_not_called()


def test_known_blocker_stops_without_retry_or_tap():
    with patch('src.play_store_ui_automator.dump_window_hierarchy', return_value=BLOCKED) as dump, patch('src.play_store_ui_automator.time.sleep') as wait, patch('src.play_store_ui_automator.tap_screen_bounds') as tap:
        result = attempt_play_store_ui_install('device', 'com.kiloo.subwaysurf', 'adb')
    assert result['reason'] == 'sign_in_required'
    dump.assert_called_once()
    wait.assert_not_called()
    tap.assert_not_called()
