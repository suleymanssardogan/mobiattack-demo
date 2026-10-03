"""D18 synthetic execution-target limitations; no device changes or bypasses."""
import copy
import json
import subprocess
import zipfile
from unittest.mock import patch, MagicMock

import pytest

from src.android_runtime_launcher import AndroidRuntimeError, AndroidDeviceUnavailableError, install_apk, launch_android_app
from src.demo_orchestrator import _runtime_with_availability, run_demo
from src.dynamic.runtime.availability import availability, install_reason, save_availability
from src.dynamic.report.generator import build_dynamic_analysis_report
from src.dynamic.report.models import DynamicReportError, save_dynamic_analysis_report, load_dynamic_analysis_report
from src.scan_state import ScanStateCheckpointer, load_scan_state, sync_dynamic_report_artifact
from src.web.report_summary import load_report_summary


@pytest.mark.parametrize('reason', ['INSTALL_FAILED', 'ABI_UNSUPPORTED', 'LAUNCHER_UNRESOLVED',
    'APP_LAUNCH_FAILED', 'PROCESS_EXITED', 'APP_CRASHED', 'EMULATOR_UNSUPPORTED',
    'DEVICE_FEATURE_UNAVAILABLE', 'INTEGRITY_ENVIRONMENT_REJECTED', 'RUNTIME_OBSERVATION_UNAVAILABLE'])
def test_explicit_backend_limitation_retains_reason_and_provenance(tmp_path, reason):
    error = AndroidRuntimeError('password=PRIVATE_VALUE /Users/private/debug', reason,
                                evidence={'source': 'observed_backend'})
    with patch('src.demo_orchestrator.launch_android_app', side_effect=error):
        result = _runtime_with_availability(tmp_path, 'training.app', 'training.app.Main')
    record = result['runtime_availability']
    assert record['reason_code'] == reason
    report = load_dynamic_analysis_report(tmp_path)
    assert report['runtime_availability'] == record
    assert report['report_status'] == 'unavailable' and report['session'] == {}
    assert 'PRIVATE_VALUE' not in json.dumps(report)
    assert '/Users/private' not in json.dumps(report)
    assert report['evidence']['runtime_availability'] == 'dynamic/runtime_availability.json'
    summary = load_report_summary(tmp_path)
    assert summary['dynamic_summary']['runtime_status'] == 'unavailable'
    assert record['message'] in summary['dynamic_summary']['coverage_limitations']


@pytest.mark.parametrize('foreground,status', [(True, 'available'), (False, 'partial')])
def test_supported_runtime_requires_process_evidence(tmp_path, foreground, status):
    metadata = {'status': 'runtime_launch_verified', 'runtime': {'pid': 42, 'process_survived': True,
                'foreground_verified': foreground}}
    with patch('src.demo_orchestrator.launch_android_app', return_value=metadata):
        result = _runtime_with_availability(tmp_path, 'training.app', 'training.app.Main')
    assert result['runtime_availability']['status'] == status
    assert result['runtime_availability']['reason_code'] == 'SUPPORTED'


def test_am_start_success_without_pid_does_not_qualify(tmp_path):
    with patch('src.demo_orchestrator.launch_android_app', return_value={'launch': {'success': True}, 'runtime': {'pid': None}}):
        result = _runtime_with_availability(tmp_path, 'training.app', 'training.app.Main')
    assert result['status'] == 'unavailable'
    assert result['runtime_availability']['reason_code'] == 'RUNTIME_OBSERVATION_UNAVAILABLE'


def test_missing_launcher_never_launches_or_guesses(tmp_path):
    with patch('src.demo_orchestrator.launch_android_app') as launcher:
        result = _runtime_with_availability(tmp_path, 'training.app', None)
    launcher.assert_not_called()
    assert result['runtime_availability']['reason_code'] == 'LAUNCHER_UNRESOLVED'


def test_device_unavailable_retains_existing_backend_code(tmp_path):
    with patch('src.demo_orchestrator.launch_android_app', side_effect=AndroidDeviceUnavailableError('Unavailable', 'adb_not_found')):
        result = _runtime_with_availability(tmp_path, 'training.app', 'training.app.Main')
    assert result['runtime_availability']['backend_reason_code'] == 'ADB_NOT_FOUND'


def test_integrity_library_or_generic_failure_does_not_imply_rejection(tmp_path):
    with patch('src.demo_orchestrator.launch_android_app', side_effect=ValueError('Play Integrity SDK present')):
        result = _runtime_with_availability(tmp_path, 'training.app', 'training.app.Main')
    assert result['runtime_availability']['reason_code'] == 'UNKNOWN'


@pytest.mark.parametrize('token,reason', [('INSTALL_FAILED_NO_MATCHING_ABIS', 'ABI_UNSUPPORTED'),
    ('INSTALL_FAILED_OLDER_SDK', 'INSTALL_INCOMPATIBLE'), ('INSTALL_FAILED_INVALID_APK', 'INSTALL_FAILED')])
def test_install_failure_mapping_is_explicit(token, reason):
    assert install_reason(f'Failure [{token}]') == (reason, token)
    assert install_reason('lib/arm64-v8a/library.so') == ('INSTALL_FAILED', 'INSTALL_FAILED')


def test_real_installer_abi_error_records_available_abi_metadata(tmp_path):
    apk = tmp_path / 'training.apk'
    with zipfile.ZipFile(apk, 'w') as archive:
        archive.writestr('lib/arm64-v8a/training.so', b'not executed')
    with patch('subprocess.run', side_effect=[subprocess.CompletedProcess([], 1, 'Failure [INSTALL_FAILED_NO_MATCHING_ABIS]', ''),
        subprocess.CompletedProcess([], 0, 'x86_64,x86', '')]):
        with pytest.raises(AndroidRuntimeError) as caught:
            install_apk('fake-adb', 'device', apk)
    assert caught.value.reason_code == 'ABI_UNSUPPORTED'
    assert caught.value.evidence['app_abis'] == ['arm64-v8a']
    assert caught.value.evidence['device_abis'] == ['x86', 'x86_64']


def test_native_library_presence_does_not_preempt_success(tmp_path):
    apk = tmp_path / 'training.apk'; apk.write_bytes(b'test fixture')
    with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'Success', '')) as runner:
        assert install_apk('fake-adb', 'device', apk)['success']
    assert runner.call_count == 1


@pytest.mark.parametrize('pid_sequence,log,reason', [([42, None], '', 'PROCESS_EXITED'), ([42], 'FATAL EXCEPTION', 'APP_CRASHED'),
                                                   ([None], '', 'APP_LAUNCH_FAILED')])
def test_start_success_then_absent_or_exited_process_is_not_supported(pid_sequence, log, reason):
    with patch('src.android_runtime_launcher.resolve_adb_executable', return_value='fake-adb'), \
         patch('src.android_runtime_launcher.select_target_device', return_value='device'), \
         patch('src.android_runtime_launcher.launch_activity', return_value={'success': True}), \
         patch('src.android_runtime_launcher.query_process_pid', side_effect=pid_sequence if len(pid_sequence)>1 else None,
               return_value=pid_sequence[0]), \
         patch('src.android_runtime_launcher.get_current_activity', return_value={'observed_package':'training.app'}), \
         patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, log, '')):
        with pytest.raises(AndroidRuntimeError) as caught:
            launch_android_app(None, 'training.app', 'training.app.Main', skip_install=True,
                               grant_permissions=False, max_wait_seconds=.01, poll_interval=.01)
    assert caught.value.reason_code == reason


@pytest.mark.parametrize('field', ['session', 'exploration', 'coverage', 'raw_debug'])
def test_unavailable_report_cannot_fabricate_execution_or_leak_debug(field):
    record = availability('APP_CRASHED', evidence={'source':'logcat'})
    report = build_dynamic_analysis_report('run', {'runtime_availability': record})
    if field == 'session': report['session'] = {'session_id': 'invented'}
    elif field == 'exploration': report['exploration']['screens_observed'] = 1
    elif field == 'coverage': report['coverage']['runtime_observation'] = 'available'
    else: report['raw_debug'] = 'secret'
    from src.dynamic.report.models import validate_dynamic_analysis_report
    with pytest.raises(DynamicReportError): validate_dynamic_analysis_report(report)


def test_missing_or_mismatched_availability_reference_is_invalid(tmp_path):
    record = availability('APP_CRASHED', evidence={'source':'logcat'})
    save_dynamic_analysis_report(tmp_path, build_dynamic_analysis_report(tmp_path.name, {'runtime_availability': record}))
    with pytest.raises(DynamicReportError): load_dynamic_analysis_report(tmp_path)
    save_availability(tmp_path, availability('PROCESS_EXITED', evidence={'source':'process_query'}))
    with pytest.raises(DynamicReportError): load_dynamic_analysis_report(tmp_path)


@pytest.mark.parametrize('launcher,reason', [('training.app.Main', 'INSTALL_FAILED'), (None, 'LAUNCHER_UNRESOLVED')])
def test_full_pipeline_preserves_static_and_continues_without_dynamic(tmp_path, launcher, reason):
    apk = tmp_path / 'downloads/app.apk'; apk.parent.mkdir(); apk.write_bytes(b'APK')
    raw, decoded = tmp_path/'raw', tmp_path/'decoded'
    raw.mkdir(); decoded.mkdir(); (decoded/'AndroidManifest.xml').write_text('<manifest/>')
    static = {'app': {'package_name':'training.app', 'launcher_activity':launcher}, 'api_candidates':[],
              'permissions': [], 'activities':[], 'structure':{}, 'network_indicators':{}}
    checkpointer = ScanStateCheckpointer(tmp_path, tmp_path.name, 'http://example.invalid/app.apk')
    checkpointer.init_state()
    with patch('src.demo_orchestrator.acquire_apk', return_value={'saved_path':str(apk), 'filename':'app.apk'}), \
         patch('src.demo_orchestrator.preprocess_apk', return_value={'raw_apk':{'output_dir':str(raw)}, 'apktool':{'output_dir':str(decoded)}}), \
         patch('src.demo_orchestrator.build_static_context', return_value=copy.deepcopy(static)), \
         patch('src.demo_orchestrator.launch_android_app', side_effect=AndroidRuntimeError('failed', 'INSTALL_FAILED')), \
         patch('src.demo_orchestrator._wire_dynamic_exploration') as exploration:
        result = run_demo('http://example.invalid/app.apk', tmp_path, progress_callback=checkpointer.on_pipeline_progress)
    assert result['demo_status'] == 'completed'
    assert result['static_analysis'] == static
    assert result['runtime']['runtime_availability']['reason_code'] == reason
    exploration.assert_not_called()
    assert (tmp_path/'static_analysis_report.json').is_file()
    state = load_scan_state(tmp_path)
    assert state['stages']['static_analysis']['status'] == 'completed'
    assert state['overall_status'] != 'failed'
    assert state['stages']['dynamic_analysis']['status'] == 'not_available'
    assert load_dynamic_analysis_report(tmp_path)['runtime_availability']['reason_code'] == reason


@pytest.mark.parametrize('terminal', [True, False])
def test_runtime_failure_callback_never_fails_completed_static(tmp_path, terminal):
    checkpointer = ScanStateCheckpointer(tmp_path, tmp_path.name, 'http://example.invalid/app.apk')
    checkpointer.init_state()
    checkpointer.on_pipeline_progress('static_analysis', 'success', 'Static completed')
    if terminal:
        checkpointer.on_failure('runtime', 'unsupported execution environment')
    else:
        checkpointer.on_pipeline_progress('runtime', 'failed', 'unsupported execution environment')
    state = load_scan_state(tmp_path)
    assert state['stages']['static_analysis']['status'] == 'completed'
    assert state['overall_status'] != 'failed'
    assert state['stages']['dynamic_analysis']['status'] == 'not_available'



def test_unavailable_report_cannot_complete_stage_and_survives_recovery(tmp_path):
    from src.scan_state import create_initial_scan_state, save_scan_state, recover_scan_state, ScanStateValidationError
    record = availability('APP_CRASHED', evidence={'source': 'logcat'})
    save_availability(tmp_path, record)
    save_dynamic_analysis_report(tmp_path, build_dynamic_analysis_report(tmp_path.name, {'runtime_availability': record}))
    state = create_initial_scan_state(tmp_path.name, 'http://example.invalid/app.apk')
    sync_dynamic_report_artifact(state, tmp_path)
    assert state['stages']['dynamic_analysis']['status'] == 'not_available'
    state['stages']['dynamic_analysis']['status'] = 'completed'
    with pytest.raises(ScanStateValidationError): save_scan_state(tmp_path, state)
    recovered = recover_scan_state(tmp_path)
    assert recovered['stages']['dynamic_analysis']['status'] == 'not_available'


@pytest.mark.parametrize('app,key', [('OWASP_Kotlin','owasp'), ('Wikipedia','wikipedia'), ('Flashlight','flashlight')])
def test_existing_training_app_launcher_fixture_identity_preserved(app, key):
    from pathlib import Path
    from src.android_runtime_launcher import normalize_component_name
    root = Path(__file__).resolve().parents[1]
    historical = json.loads((root/'examples/task_c1/real_checkpoint.json').read_text())[key]
    static = json.loads((root/f'examples/task_c10/{app}_static_report.json').read_text())['application']
    assert historical['runtime'] is True  # historical evidence, not a new live execution
    assert static['launcher_status'] == 'resolved'
    assert static['launcher_activity'] == historical['activity']
    assert normalize_component_name(static['package_name'], static['launcher_activity']) == (
        static['package_name']+'/'+historical['activity'])
    if app == 'Wikipedia':
        assert static['launcher_target_activity'] == 'org.wikipedia.main.MainActivity'
        assert static['launcher_activity'] != static['launcher_target_activity']
    if app == 'Flashlight':
        assert historical['split_count'] == 5



def test_preflight_observation_failure_is_not_a_crash_or_process_exit():
    from src.dynamic.preflight.runtime_health import check_runtime_health
    from src.dynamic.preflight.models import ErrorCode
    with patch('src.dynamic.preflight.runtime_health.run_adb_cmd', return_value=(1, '', 'unavailable')):
        baseline, foreground, reason, _ = check_runtime_health('fake-adb', 'device', 'training.app')
    assert reason == ErrorCode.RUNTIME_OBSERVATION_UNAVAILABLE
    assert not baseline.launch_success and not baseline.immediate_crash and not foreground
    assert baseline.pid is None
