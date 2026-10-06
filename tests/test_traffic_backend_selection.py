"""Explicit modes and unavailable-backend identity; no capability fallback."""
from unittest.mock import patch
import json
import pytest
from src.dynamic.traffic.backend_selection import select_capture_backend,validate_traffic_mode
from src.dynamic.traffic.mitmproxy_backend import MitmproxyCaptureBackend
from src.dynamic.traffic.native_backend import NativeProxyCaptureBackend
from src.dynamic.traffic.service import DynamicTrafficService
from src.dynamic.traffic.storage import TrafficStorage
from src.dynamic.traffic.models import CaptureSummary
from src.demo_orchestrator import run_demo


def test_https_default_selects_mitm_even_when_missing():
    with patch('src.dynamic.traffic.mitmproxy_backend.find_mitmproxy_binary',return_value=None),patch('src.dynamic.traffic.backend_selection.NativeProxyCaptureBackend') as native:
        backend=select_capture_backend()
        assert isinstance(backend,MitmproxyCaptureBackend) and not backend.check_available()
        native.assert_not_called()


def test_native_is_explicit():
    with patch('src.dynamic.traffic.backend_selection.MitmproxyCaptureBackend') as mitm:
        assert isinstance(select_capture_backend('native_http'),NativeProxyCaptureBackend)
        mitm.assert_not_called()


@pytest.mark.parametrize('mode',['auto','fallback','bad',None])
def test_invalid_mode_rejected_before_acquisition(tmp_path,mode):
    with patch('src.demo_orchestrator.acquire_apk') as acquire:
        with pytest.raises(ValueError):run_demo('http://example.test/a.apk',tmp_path,traffic_mode=mode)
    acquire.assert_not_called()


def test_ca_configuration_is_explicit(monkeypatch,tmp_path):
    monkeypatch.setenv('MITMPROXY_CA_DIR',str(tmp_path))
    assert select_capture_backend().ca_directory==tmp_path


def test_service_default_has_no_native_fallback():
    with patch('src.dynamic.traffic.mitmproxy_backend.find_mitmproxy_binary',return_value=None):
        service=DynamicTrafficService()
        assert isinstance(service.backend,MitmproxyCaptureBackend)
        vis=service.get_visibility_metadata()
        assert vis['https_visibility']=='unavailable'
        assert vis['https_reason']=='capture_backend_unavailable'


def test_failed_capture_keeps_selected_identity_in_report(tmp_path):
    from src.dynamic.report import build_dynamic_analysis_report
    from src.dynamic.runtime.availability import availability
    p=tmp_path/'traffic.json'
    TrafficStorage().save_traffic_json(p,'session-current',[],backend_name='MitmproxyCaptureBackend',summary=CaptureSummary(session_id='session-current',http_visibility='unavailable',http_visibility_reason='MITMPROXY_NOT_FOUND',https_visibility='unavailable',https_visibility_reason='capture_backend_unavailable'))
    traffic=json.loads(p.read_text())
    report=build_dynamic_analysis_report('run',{
        'session':{'session_id':'session-current','package_name':'lab.app','status':'ACTIVE'},
        'exploration':{'status':'partial','stop_reason':'observation_failed'},
        'runtime_availability':availability('SUPPORTED',status='available',package_name='lab.app',evidence={'source':'runtime_launcher','pid':1,'process_survived':True,'foreground_verified':True}),
        'traffic':traffic})
    assert report['traffic']['backend']=='mitmproxy'
    assert report['traffic']['http_visibility_reason']=='MITMPROXY_NOT_FOUND'
    assert report['traffic']['https_visibility_reason']=='capture_backend_unavailable'
    assert report['traffic']['total_transactions']==0


def test_demo_facade_passes_explicit_mode(tmp_path):
    from src.demo_orchestrator import _wire_dynamic_exploration
    with patch('src.demo_orchestrator._exploration_wiring._wire_dynamic_exploration') as wire:
        _wire_dynamic_exploration(tmp_path,'lab.app',traffic_mode='native_http')
    assert wire.call_args.kwargs['traffic_mode']=='native_http'


def test_web_demo_mode_is_explicit(tmp_path):
    from src.demo_web_server import DemoWebServer
    assert DemoWebServer(runs_root=tmp_path).traffic_mode=='https'
    assert DemoWebServer(runs_root=tmp_path,traffic_mode='native_http').traffic_mode=='native_http'
    with pytest.raises(ValueError):DemoWebServer(runs_root=tmp_path,traffic_mode='auto')
