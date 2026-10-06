"""D19 transport isolation and evidence-only capability contracts."""
import json
from unittest.mock import patch
import pytest

from src.dynamic.runtime.execution_target import (Capability, ExecutionTarget, TargetType,
    EmulatorTargetAdapter, select_transport, save_target, load_target, resolve_run_transport,
    verify_run_target, record_capabilities, environment_summary)
from src.dynamic.preflight.device_check import check_connected_device
from src.dynamic.preflight.models import ErrorCode
from src.android_runtime_launcher import launch_android_app, AndroidRuntimeError
from src.demo_orchestrator import _runtime_with_availability
from src.dynamic.report.models import load_dynamic_analysis_report, DynamicReportError
from src.web.report_summary import load_report_summary


def test_emulator_adapter_observed_metadata():
    props = {'ro.kernel.qemu': '1', 'ro.product.cpu.abilist': 'arm64-v8a,x86_64', 'ro.build.version.sdk': '35'}
    calls = []
    def query(args, serial):
        calls.append(serial)
        return 0, props[args[-1]], ''
    target = EmulatorTargetAdapter().describe('device-A', query, {'pid': 42, 'foreground_verified': True})
    assert target.target_type == TargetType.EMULATOR
    assert target.abis == ['arm64-v8a', 'x86_64'] and target.api_level == 35
    assert set(calls) == {'device-A'}
    assert target.capabilities['pid_observation'].state == 'available'
    assert target.capabilities['traffic_capture'].state == 'unknown'
    assert target.capabilities['proxy_configuration'].state == 'unknown'


@pytest.mark.parametrize('kind', [TargetType.CLOUD_DEVICE])
def test_placeholders_do_not_execute(kind):
    target = ExecutionTarget.selected('device-A', kind, availability='available')
    with patch('src.android_runtime_launcher.select_target_device') as select:
        with pytest.raises(AndroidRuntimeError, match='target unavailable'):
            launch_android_app(None, 'training.app', '.Main', skip_install=True, execution_target=target)
    select.assert_not_called()


def test_unknown_preserved_and_type_does_not_grant_capabilities():
    for kind in TargetType:
        target = ExecutionTarget.selected('device-A', kind)
        assert all(c.state == 'unknown' for c in target.capabilities.values())
    target = EmulatorTargetAdapter().describe('emulator-5554', lambda *a, **k: (1, '', ''))
    assert target.target_type == TargetType.UNKNOWN and target.api_level is None and target.abis == []


@pytest.mark.parametrize('entries,selection,expected', [
    ([], None, 'DEVICE_NOT_FOUND'),
    ([('A', 'device'), ('B', 'device')], None, 'MULTIPLE_DEVICES'),
    ([('A', 'offline')], 'A', 'DEVICE_OFFLINE'),
    ([('B', 'device')], 'A', 'DEVICE_NOT_FOUND')])
def test_no_or_ambiguous_or_disappeared_target(entries, selection, expected):
    with pytest.raises(ValueError, match=expected): select_transport(entries, selection)


def test_explicit_selection_is_stable():
    entries = [('B', 'device'), ('A', 'device')]
    assert select_transport(entries, 'A') == select_transport(entries[::-1], 'A') == 'A'
    assert ExecutionTarget.selected('A').target_id == ExecutionTarget.selected('A').target_id
    assert ExecutionTarget.selected('A').target_id != ExecutionTarget.selected('B').target_id


def test_preflight_multiple_targets_no_silent_choice():
    with patch('src.dynamic.preflight.device_check.run_adb_cmd', return_value=(0, 'List of devices attached\nA device\nB device', '')) as run:
        device, reason, message = check_connected_device('adb')
    assert not device.connected and reason == ErrorCode.MULTIPLE_DEVICES
    assert run.call_count == 1 and 'explicit selection' in message


def test_session_transport_conflict_rejected(tmp_path):
    save_target(tmp_path, ExecutionTarget.selected('A', TargetType.EMULATOR, availability='available'))
    assert resolve_run_transport(tmp_path, 'A', 'A') == 'A'
    with pytest.raises(ValueError, match='TARGET_IDENTITY_MISMATCH'):
        resolve_run_transport(tmp_path, 'A', 'B')
    record = json.loads((tmp_path/'dynamic/runtime_availability.json').read_text())
    assert record['backend_reason_code'] == 'TARGET_IDENTITY_MISMATCH'
    assert record['target_serial'] == 'A'
    with pytest.raises(ValueError, match='TARGET_UNAVAILABLE'):
        resolve_run_transport(tmp_path/'empty')


def test_disappearing_target_never_uses_another_device(tmp_path):
    target = ExecutionTarget.selected('A', TargetType.EMULATOR, availability='available')
    save_target(tmp_path, target)
    with pytest.raises(ValueError, match='TARGET_UNAVAILABLE'):
        verify_run_target(tmp_path, lambda args: (0, 'List of devices attached\nB device', ''))
    assert load_target(tmp_path).availability == 'unavailable'
    evidence = json.loads((tmp_path/'dynamic/runtime_availability.json').read_text())
    assert evidence['target_serial'] == 'A' and evidence['execution_target_id'] == target.target_id
    assert evidence['reason_code'] == 'RUNTIME_OBSERVATION_UNAVAILABLE'


def test_successful_recheck_keeps_selected_identity(tmp_path):
    save_target(tmp_path, ExecutionTarget.selected('A', availability='available'))
    verify_run_target(tmp_path, lambda args: (0, 'List of devices attached\nB device\nA device', ''))
    assert load_target(tmp_path).adb_serial == 'A'


def test_explicit_capability_observations_and_atomic_roundtrip(tmp_path):
    target = ExecutionTarget.selected('A', TargetType.EMULATOR, availability='available')
    save_target(tmp_path, target)
    record_capabilities(tmp_path, {'http_capture':'available', 'https_capture':'unavailable'}, 'traffic_backend')
    loaded = load_target(tmp_path)
    assert loaded.capabilities['https_capture'].state == 'unavailable'
    assert loaded.capabilities['http_capture'].source == 'traffic_backend'
    assert loaded.capabilities['host_reachability'].state == 'unknown'
    assert not list((tmp_path/'dynamic').glob('*.tmp'))


@pytest.mark.parametrize('kwargs', [{'availability':'fake'}, {'adb_serial':'/Users/private'}, {'api_level':False}, {'capabilities':{}}, {'abis':['/secret']}])
def test_malformed_target_rejected(kwargs):
    with pytest.raises((TypeError, ValueError)):
        values = ExecutionTarget.selected('A').to_dict()
        values.update(kwargs)
        ExecutionTarget.from_dict(values)


@pytest.mark.parametrize('kind', [TargetType.EMULATOR, TargetType.PHYSICAL_DEVICE])
def test_target_linked_d18_report_and_ui_without_transport_leak(tmp_path, kind):
    target = ExecutionTarget.selected('private-serial', kind, availability='available')
    save_target(tmp_path, target)
    error = AndroidRuntimeError('raw secret', 'ABI_UNSUPPORTED', evidence={'source':'package_manager'})
    with patch('src.demo_orchestrator.launch_android_app', side_effect=error):
        result = _runtime_with_availability(tmp_path, 'training.app', '.Main')
    assert result['runtime_availability']['execution_target_id'] == target.target_id
    report = load_dynamic_analysis_report(tmp_path)
    assert report['runtime_availability']['reason_code'] == 'ABI_UNSUPPORTED'
    assert report['execution_environment']['availability'] == 'available' # target ready, app incompatible
    summary = load_report_summary(tmp_path)
    assert 'private-serial' not in json.dumps(summary) and 'raw secret' not in json.dumps(summary)
    assert summary['dynamic_summary']['execution_environment']['label'] == 'Current execution environment'
    target.adb_serial = 'other-device'
    save_target(tmp_path, target)
    with pytest.raises(DynamicReportError, match='transport'):
        load_dynamic_analysis_report(tmp_path)


def test_target_summary_rejects_serial_fields(tmp_path):
    summary = environment_summary(ExecutionTarget.selected('private-serial'))
    assert 'private-serial' not in json.dumps(summary)
    assert 'adb_serial' not in summary


def test_proxy_reachability_not_inferred_from_emulator_type():
    from src.dynamic.traffic.service import DynamicTrafficService
    from src.dynamic.traffic.models import ProxyReadinessResult
    from src.dynamic.preflight.models import DeviceInfo
    from unittest.mock import MagicMock
    backend = MagicMock(); backend.check_available.return_value = True
    with patch('src.dynamic.traffic.service.check_connected_device', return_value=(DeviceInfo(connected=True, serial='A', is_emulator=True), None, None)), patch('src.dynamic.traffic.service.is_port_in_use', return_value=False), patch('src.dynamic.traffic.service.run_adb_cmd', return_value=(1,'','')) as query:
        service = DynamicTrafficService(backend=backend, storage=MagicMock(), adb_bin='adb')
        result = service.check_readiness(device_serial='A')
    assert not result.device_reachable_proxy
    assert query.call_args.kwargs['serial'] == 'A'


def test_unavailable_capability_blocks_launch_before_adb():
    target = ExecutionTarget.selected('A', TargetType.EMULATOR, availability='available')
    target.capabilities['app_launch'] = Capability('unavailable', 'OBSERVED', 'target_preflight')
    with patch('src.android_runtime_launcher.select_target_device') as select:
        with pytest.raises(AndroidRuntimeError) as error:
            launch_android_app(None, 'training.app', '.Main', skip_install=True, execution_target=target)
    assert error.value.backend_reason_code == 'TARGET_CAPABILITY_UNAVAILABLE'
    select.assert_not_called()


def test_preflight_placeholder_no_execution():
    from src.dynamic.preflight.service import DynamicPreflightService
    target = ExecutionTarget.selected('A', TargetType.CLOUD_DEVICE, availability='available')
    with patch('src.dynamic.preflight.service.check_connected_device') as check:
        result = DynamicPreflightService(adb_bin='adb').run_preflight('training.app', execution_target=target)
    assert result.status.value == 'FAIL'
    check.assert_not_called()


def test_canonical_target_ref_requires_artifact(tmp_path):
    target = ExecutionTarget.selected('A', TargetType.EMULATOR, availability='available')
    save_target(tmp_path, target)
    with patch('src.demo_orchestrator.launch_android_app', side_effect=AndroidRuntimeError('failed')):
        _runtime_with_availability(tmp_path, 'training.app', '.Main')
    (tmp_path/'dynamic/execution_target.json').unlink()
    with pytest.raises(DynamicReportError, match='target evidence'):
        load_dynamic_analysis_report(tmp_path)
