"""D17 state/deadline regressions: fake ADB/UI, bounded threads, no device actions."""
import io
import subprocess
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.dynamic.deadline import Deadline, budget, bounded_timeout, current_deadline
from src.dynamic.action.completion import wait_for_completion
from src.dynamic.traffic.service import DynamicTrafficService
from src.dynamic.traffic.mitmproxy_backend import MitmproxyCaptureBackend
from src.dynamic.traffic.native_backend import NativeProxyCaptureBackend
from src.dynamic.traffic.models import TrafficException
from src.dynamic.runtime.observer import AndroidRuntimeObserver
from src.dynamic.exploration.loop import run_exploration
from src.dynamic.exploration.models import ExplorationLimits
from src.dynamic.action.models import ActionExecutionResult
from src.dynamic.route.graph import RouteGraph
from tests.test_dynamic_exploration_loop import _make_obs, _make_candidate


def test_nested_budget_never_refreshes_outer_ceiling():
    now = [0.0]
    with budget(8, clock=lambda: now[0]):
        assert bounded_timeout(30) == 8
        now[0] = 3
        with budget(30):
            assert bounded_timeout(30) == 5
            now[0] = 8
            with pytest.raises(subprocess.TimeoutExpired):
                bounded_timeout(30)
    assert current_deadline() is None


def test_explicit_deadline_uses_its_clock_and_resets_after_failure():
    now = [100.0]
    deadline = Deadline(8, clock=lambda: now[0])
    with pytest.raises(ValueError), budget(30, deadline=deadline):
        assert bounded_timeout(30) == 8
        raise ValueError('test')
    assert current_deadline() is None


def test_actual_nested_ui_dump_and_cleanup_share_budget():
    from src.play_store_ui_automator import dump_window_hierarchy
    now, limits = [0.0], []
    def runner(cmd, **kwargs):
        limits.append(kwargs['timeout'])
        now[0] += min(3, kwargs['timeout'])
        return subprocess.CompletedProcess(cmd, 0, '<hierarchy/>', '')
    with patch('src.play_store_ui_automator.resolve_adb_executable', return_value='fake-adb'), patch('subprocess.run', side_effect=runner), budget(8, clock=lambda: now[0]):
        dump_window_hierarchy('device', 'fake-adb')
    assert limits == [8, 5, 2] and now[0] == 8


@pytest.mark.parametrize('change', ['screen', 'activity', 'dialog'])
def test_postcondition_state_change(change):
    obs = _make_obs(screen_identity='before')
    source = SimpleNamespace(screen_identity='before', activity=obs.foreground_activity)
    if change == 'screen':
        obs.screen_identity = 'after'
    elif change == 'activity':
        obs.foreground_activity = 'NextActivity'
    else:
        obs.is_dialog_or_system = True
    result = wait_for_completion(lambda: obs, source, sleeper=lambda _: pytest.fail('ready state must not sleep'))
    assert result.confirmed and result.attempts == 1


def test_unchanged_ui_requires_explicit_postcondition():
    obs = _make_obs(screen_identity='same')
    source = SimpleNamespace(screen_identity='same', activity=obs.foreground_activity)
    result = wait_for_completion(lambda: obs, source, max_attempts=2, sleeper=lambda _: None)
    assert not result.confirmed
    result = wait_for_completion(lambda: obs, source, no_navigation=lambda o: o.screen_identity == 'same')
    assert result.condition == 'explicit_no_navigation_postcondition'


def test_ambiguous_timeout_then_observed_transition_never_resends():
    before = _make_obs(screen_identity='before', actions=[_make_candidate()])
    after = _make_obs(screen_identity='after')
    observations = iter([before, after])
    executor = SimpleNamespace(click=MagicMock(return_value=ActionExecutionResult(
        action_id='action', action_type='click', status='timed_out', started_at='t0', completed_at='t1')))
    graph = RouteGraph()
    result = run_exploration(observer=lambda: next(observations), executor=executor,
                             route_graph=graph, limits=ExplorationLimits(max_steps=1))
    assert executor.click.call_count == 1
    assert graph.edge_count == 1 and result.actions_succeeded == 1


def test_failed_postcondition_retains_runtime_and_traffic_evidence():
    before = _make_obs(screen_identity='before', actions=[_make_candidate()])
    observations = iter([before])
    executor = SimpleNamespace(click=MagicMock(return_value=ActionExecutionResult(
        action_id='action', action_type='click', status='timed_out', started_at='t0', completed_at='t1')))
    traffic = SimpleNamespace(get_current_marker=lambda: 0, get_visibility_metadata=lambda: {},
                              wait_transactions_since=MagicMock(return_value=[]), last_traffic_wait={'observation': 'not_observed'})
    recorder = MagicMock()
    graph = RouteGraph()
    result = run_exploration(observer=lambda: next(observations), executor=executor,
                             route_graph=graph, limits=ExplorationLimits(max_steps=1),
                             traffic_service=traffic, timeline_recorder=recorder, sleeper=lambda _: None)
    assert graph.edge_count == 0 and result.actions_failed == 1
    traffic.wait_transactions_since.assert_called_once_with(0)
    assert 'ACTION_TRAFFIC_CORRELATED' in str(recorder.mock_calls)


def traffic_service():
    with patch('src.dynamic.traffic.service.find_adb_binary', return_value='fake-adb'):
        return DynamicTrafficService(backend=SimpleNamespace(pending_count=0))


def test_delayed_transaction_wakes_wait_and_drains():
    service = traffic_service()
    tx = object()
    def arrive():
        with service._transactions_changed:
            service.captured_transactions.append(tx)
            service._transactions_changed.notify_all()
    timer = threading.Timer(.03, arrive)
    timer.start()
    started = time.monotonic()
    result = service.wait_transactions_since(0, timeout_seconds=.3, quiet_seconds=.02)
    timer.join(timeout=.3)
    assert result == [tx] and time.monotonic()-started < .3
    assert service.last_traffic_wait['correlation_semantics'] == 'observed_not_caused'


def test_empty_traffic_is_not_observed_and_possible_late_arrivals_explicit():
    service = traffic_service()
    assert service.wait_transactions_since(0, timeout_seconds=.01) == []
    assert service.last_traffic_wait['observation'] == 'not_observed'
    assert service.last_traffic_wait['late_arrivals_possible']


def test_inflight_traffic_not_silently_drained():
    service = traffic_service()
    service.backend.pending_count = 1
    service.captured_transactions.append(object())
    service.wait_transactions_since(0, timeout_seconds=.01, quiet_seconds=0)
    assert service.last_traffic_wait['in_flight_state'] == 'pending'


@pytest.mark.parametrize('ready', [True, False])
def test_proxy_readiness_requires_ack_and_live_process(ready):
    backend = MitmproxyCaptureBackend()
    backend.executable_path = "fake-mitmdump"
    process = MagicMock()
    process.poll.return_value = None
    process.stdout = io.StringIO('MOBIATTACK_EVIDENCE {"event":"ready"}\n' if ready else '')
    process.stderr = io.StringIO('')
    with patch.object(backend, 'check_available', return_value=True), patch('src.dynamic.traffic.mitmproxy_backend.is_port_in_use', return_value=False), patch('subprocess.Popen', return_value=process), patch.object(backend, 'stop'):
        if ready:
            backend.start(timeout_seconds=.2)
            assert backend._startup_ready
        else:
            with pytest.raises(TrafficException):
                backend.start(timeout_seconds=.2)


def test_proxy_cleanup_terminate_kill_and_readers_share_budget():
    now, waits = [0.0], []
    backend = MitmproxyCaptureBackend()
    backend.executable_path = "fake-mitmdump"
    process = MagicMock()
    process.pid = None
    process.poll.return_value = None
    def wait(*, timeout):
        waits.append(timeout)
        now[0] += timeout
        raise subprocess.TimeoutExpired('proxy', timeout)
    process.wait.side_effect = wait
    backend.process = process
    with budget(4, clock=lambda: now[0]):
        backend.stop()
    assert waits == [2, 2] and now[0] == 4
    assert backend.cleanup_state == 'partial'
    process.kill.assert_called_once()


def test_native_cleanup_does_not_block_on_shutdown():
    backend = NativeProxyCaptureBackend()
    release = threading.Event()
    server = SimpleNamespace(clients_lock=threading.Lock(), clients=set(),
                             shutdown=lambda: release.wait(.5), server_close=lambda: None)
    backend.server = server
    started = time.monotonic()
    try:
        backend.stop(timeout_seconds=.02)
        assert time.monotonic() - started < .2
        assert backend.cleanup_state == 'partial' and backend.server is server
    finally:
        release.set()


def test_runtime_requeries_pid_on_every_observation():
    observer = AndroidRuntimeObserver('device', 'fake-adb')
    with patch.object(observer, '_resolve_adb', return_value='fake-adb'), patch.object(observer, '_query_pid', side_effect=[42, None, 77]), patch.object(observer, '_query_foreground', return_value=('', '', False)), patch.object(observer, '_collect_bounded_logs', return_value=([], False, False)):
        first, dead, restarted = [observer.observe('training') for _ in range(3)]
    assert first.pid == 42
    assert dead.pid is None and not dead.process_running
    assert restarted.pid == 77


@pytest.mark.parametrize('seconds', [-1, float('inf'), float('nan')])
def test_deadline_rejects_unbounded_or_invalid_budget(seconds):
    with pytest.raises(ValueError):
        Deadline(seconds)


def test_unchanged_existing_dialog_is_not_a_new_postcondition():
    obs = _make_obs(screen_identity='dialog')
    obs.is_dialog_or_system = True
    source = SimpleNamespace(screen_identity='dialog', activity=obs.foreground_activity, is_dialog_or_system=True)
    result = wait_for_completion(lambda: obs, source, max_attempts=1, sleeper=lambda _: None)
    assert not result.confirmed


def test_nested_deadline_absolute_end_cannot_drift():
    now = [0.0]
    def clock():
        now[0] += .001
        return now[0]
    with budget(8, clock=clock) as outer:
        with budget(30) as inner:
            assert inner.end <= outer.end



def test_unavailable_runtime_state_is_not_a_success_postcondition():
    from src.dynamic.runtime.models import RuntimeSnapshot
    obs = _make_obs(screen_identity='same')
    source = SimpleNamespace(screen_identity='same', activity=obs.foreground_activity)
    runtime = SimpleNamespace(observe=lambda _: RuntimeSnapshot(package_name='training', diagnostics=['unavailable']))
    result = wait_for_completion(lambda: obs, source, runtime_observer=runtime,
        before_runtime=RuntimeSnapshot(package_name='training', pid=42, foreground_activity='Main'),
        max_attempts=1, sleeper=lambda _: None)
    assert not result.confirmed



def test_native_remaining_client_work_marks_cleanup_partial():
    backend = NativeProxyCaptureBackend()
    client = MagicMock()
    server = SimpleNamespace(clients_lock=threading.Lock(), clients={client},
        shutdown=lambda: None, server_close=lambda: None)
    backend.server = server
    backend.stop(timeout_seconds=.1)
    assert backend.cleanup_state == 'partial'
    assert backend.server is server
