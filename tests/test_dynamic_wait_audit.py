"""D16 audit probes document current behavior without real ADB/network/sleep."""
from collections import Counter
from pathlib import Path
import subprocess
from unittest.mock import patch
import xml.etree.ElementTree as ET
from examples.task_d16.audit_waits import inventory, CLASSES
from src.dynamic.preflight.runtime_health import check_runtime_health
from src.dynamic.ui.observer import observe_screen
from src.dynamic.action.executor import ActionExecutor


def test_inventory_exclusive_complete_classification_and_reproducible():
    first=inventory()
    assert first==inventory()
    assert first['counts']==dict(Counter(r['classification'] for r in first['occurrences']))
    assert set(first['counts']) <= CLASSES
    assert all(r['problem'] and r['preferred_state_event'] and r['deadline_role'] for r in first['occurrences'])
    assert len({(r['file'],r['line']) for r in first['occurrences']})==len(first['occurrences'])


def test_fixed_sleep_sites_removed():
    loop = Path('src/dynamic/exploration/loop.py').read_text()
    proxy = Path('src/dynamic/traffic/mitmproxy_backend.py').read_text()
    assert 'sleeper(cfg.action_settle_delay)' not in loop
    assert 'time.sleep(0.6)' not in proxy


def test_runtime_ready_state_returns_without_sleep():
    with patch('src.dynamic.preflight.runtime_health._find_process_pid',return_value=42), \
         patch('src.dynamic.preflight.runtime_health._scan_recent_fatal_logs',return_value=(False,[])), \
         patch('src.dynamic.preflight.runtime_health._check_foreground_status',return_value=True):
        sleeps=[]
        baseline,foreground,error,_=check_runtime_health('fake-adb','fake-device','app.training',
                                                       clock=lambda:0,sleeper=sleeps.append)
    assert baseline.launch_success and foreground and error is None and sleeps==[]


def test_runtime_outer_deadline_bounds_actual_nested_queries():
    now=[0.0]
    def runner(*args, **kwargs):
        now[0] += kwargs['timeout']
        raise subprocess.TimeoutExpired(args[0], kwargs['timeout'])
    with patch('subprocess.run', side_effect=runner):
        baseline,_,error,_=check_runtime_health('fake-adb','fake-device','app.training',
                                              deadline_seconds=8,clock=lambda:now[0],sleeper=lambda _:None)
    assert now[0] == 8 and not baseline.launch_success and baseline.pid is None and error is not None


def test_ui_outer_deadline_bounds_nested_queries():
    import pytest
    from src.dynamic.ui.observer import UIObservationError
    now=[0.0]
    def runner(*args, **kwargs):
        now[0] += kwargs['timeout']
        raise subprocess.TimeoutExpired(args[0], kwargs['timeout'])
    with patch('subprocess.run', side_effect=runner), patch('src.android_runtime_launcher.resolve_adb_executable',return_value='fake-adb'):
        with pytest.raises(UIObservationError):
            observe_screen('fake-device','fake-adb','app.training',deadline_seconds=8,
                           clock=lambda:now[0],sleeper=lambda _:None)
    assert now[0] == 8


def test_action_timeout_is_not_repeated():
    with patch('src.dynamic.action.executor.resolve_adb_executable',return_value='fake-adb'), \
         patch('src.dynamic.action.executor.subprocess.run',side_effect=subprocess.TimeoutExpired(['fake-adb'],5)) as runner:
        result=ActionExecutor('fake-device','fake-adb',max_attempts=2)._run_bounded_adb_action(
            'audit_action','click',['fake-adb','input','tap','1','1'],5,'audit',{})
    assert not result.is_success and result.attempts == runner.call_count == 1


def test_traffic_wait_and_cleanup_are_bounded():
    loop=Path('src/dynamic/exploration/loop.py').read_text()
    assert 'wait_transactions_since(traffic_marker)' in loop
    proxy=Path('src/dynamic/traffic/mitmproxy_backend.py').read_text()
    assert 'process.wait()' not in proxy
    assert 'time.sleep(' not in proxy
