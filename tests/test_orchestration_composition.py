"""Composition regressions across single/split targets and stage failures."""
from unittest.mock import Mock

import pytest

from src import demo_orchestrator as demo


@pytest.mark.parametrize('split', [False, True])
def test_single_and_split_share_runtime_and_result_contract(tmp_path, monkeypatch, split):
    """Both preparation paths preserve target ownership, port and report ordering."""
    raw = tmp_path / 'raw'
    decoded = tmp_path / 'decoded'
    raw.mkdir()
    decoded.mkdir()
    (decoded / 'AndroidManifest.xml').write_text('<manifest/>')
    apk = tmp_path / 'target.apk'
    apk.write_bytes(b'fixture')
    acq = {'filename': 'target.apk', 'saved_path': str(apk), 'size_bytes': 7}
    if split:
        acq.update(package_layout='split', source_type='play_store', components=[])
    prep = {'raw_apk': {'output_dir': str(raw)}, 'apktool': {'output_dir': str(decoded)}}
    context = {'app': {'package_name': 'training.example', 'launcher_activity': '.Main'}, 'api_candidates': []}
    acquisition = Mock(return_value=acq)
    monkeypatch.setattr(demo, 'acquire_apk', acquisition)
    monkeypatch.setattr(demo, 'acquire_play_store_app', acquisition)
    monkeypatch.setattr(demo, 'preprocess_apk', Mock(return_value=prep))
    monkeypatch.setattr(demo, 'preprocess_package_set', Mock(return_value=prep))
    monkeypatch.setattr(demo, 'build_static_context', Mock(return_value=context))
    monkeypatch.setattr(demo, 'build_split_static_context', Mock(return_value=context))
    runtime = Mock(return_value={'status': 'success', 'runtime': {'pid': 42}})
    session = Mock(return_value={'raw_observation': 'initial_screen'})
    exploration = Mock()
    monkeypatch.setattr(demo, '_runtime_with_availability', runtime)
    monkeypatch.setattr(demo, '_wire_dynamic_session', session)
    monkeypatch.setattr(demo, '_wire_dynamic_exploration', exploration)
    order = []
    def report(**kwargs):
        assert kwargs['run_dir'] == tmp_path
        assert kwargs['run_id'] == tmp_path.name
        order.append('report')
    monkeypatch.setattr('src.report_generator.generate_reports', report)
    monkeypatch.setattr(demo, '_finalize_scan_state_post_run', lambda root: order.append('state'))
    events = []
    def progress(stage, state, message, data):
        events.append((stage, state))
        if stage == 'demo':
            order.append('completed')
    url = 'https://play.google.com/store/apps/details?id=training.example' if split else 'https://example.com/target.apk'
    result = demo.run_demo(url, tmp_path, adb_serial='test-device', traffic_proxy_port=18080,
                           progress_callback=progress)
    assert result['acquisition'] is acq
    assert result['preprocessing'] is prep
    assert result['static_analysis'] is context
    assert result['input']['adb_serial'] == 'test-device'
    assert result['input']['source_type'] == ('play_store' if split else 'direct_apk')
    assert runtime.call_count == session.call_count == exploration.call_count == 1
    assert runtime.call_args.kwargs['adb_serial'] == 'test-device'
    assert runtime.call_args.kwargs.get('skip_install', False) is split
    assert runtime.call_args.kwargs['apk_path'] == (None if split else apk)
    assert exploration.call_args.kwargs['initial_observation'] == 'initial_screen'
    assert exploration.call_args.kwargs['traffic_proxy_port'] == 18080
    assert order == ['report', 'state', 'completed']
    assert events[-1] == ('demo', 'completed')


def test_acquisition_pins_selected_transport_without_touching_another_device(tmp_path):
    from src.orchestration.acquisition import acquire_android_target
    acquire = Mock(return_value={'package_layout': 'split'})
    direct = Mock()
    result = acquire_android_target(
        'original', {'type': 'play_store', 'package_name': 'training.example', 'normalized_url': 'normalized'},
        tmp_path, None, 300, 'manual', 180, None, acquire_apk=direct,
        acquire_play_store_app=acquire, get_connected_devices=Mock(return_value=[('device-a', 'device')]),
    )
    assert result == ('normalized', {'package_layout': 'split'}, 'device-a')
    assert acquire.call_args.kwargs['serial'] == 'device-a'
    assert acquire.call_args.kwargs['timeout_seconds'] == 60
    direct.assert_not_called()


def test_report_failure_preserves_collected_result_and_finalizes_state(tmp_path, monkeypatch):
    from src.orchestration.results import finish_android_run
    monkeypatch.setattr('src.report_generator.generate_reports', Mock(side_effect=OSError('disk full')))
    finalize = Mock()
    runtime = {'status': 'unavailable', 'runtime_availability': {'status': 'unavailable'}}
    result = finish_android_run(
        url='https://example.com/target.apk', platform='android', adb_serial='device-a',
        reinstall=False, grant_permissions=False, acq_meta={}, prep_meta={}, static_context={},
        runtime_meta=runtime, demo3_scan=None, root_path=tmp_path, progress_callback=None,
        default_source_type='direct_apk', _finalize_scan_state_post_run=finalize,
    )
    assert result['runtime'] is runtime
    assert result['input']['adb_serial'] == 'device-a'
    assert 'dynamic_analysis_report' not in result
    finalize.assert_called_once_with(tmp_path)


def test_preprocessing_failure_preserves_stage_and_cause(tmp_path):
    from src.orchestration.preparation import prepare_split_target
    cause = RuntimeError('decoder failed')
    static = Mock()
    with pytest.raises(demo.DemoOrchestrationError) as exc:
        prepare_split_target({}, tmp_path, 8, None,
                             preprocess_package_set=Mock(side_effect=cause), build_split_static_context=static)
    assert exc.value.stage == 'preprocessing'
    assert exc.value.cause is cause
    static.assert_not_called()
