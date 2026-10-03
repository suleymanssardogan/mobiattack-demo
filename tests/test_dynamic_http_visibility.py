"""D24 capability states, verified proxy configuration, and zero-traffic reports."""
from unittest.mock import MagicMock, patch
import pytest
from src.dynamic.traffic.proxy_manager import DeviceProxyManager
from src.dynamic.traffic.models import TrafficException, CaptureSession, CaptureStatus
from src.dynamic.traffic.service import DynamicTrafficService
from src.dynamic.traffic.native_backend import NativeProxyCaptureBackend


@pytest.mark.parametrize('actual',['null','wrong:18080'])
def test_write_success_without_matching_readback_rejected(actual):
    with patch('src.dynamic.traffic.proxy_manager.run_adb_cmd',side_effect=[(0,':0',''),(0,'',''),(0,actual,''),(0,'',''),(0,':0','')]):
        manager=DeviceProxyManager('adb','device',proxy_port=18080)
        with pytest.raises(TrafficException,match='readback'):manager.apply_proxy()
        assert not manager.configured and not manager.readback_verified


def test_unreadable_prior_state_does_not_overwrite_proxy():
    with patch('src.dynamic.traffic.proxy_manager.run_adb_cmd',return_value=(1,'','error')) as command:
        with pytest.raises(TrafficException,match='prior proxy'):DeviceProxyManager('adb','device').apply_proxy()
        assert command.call_count==1
        manager=DeviceProxyManager("adb","device")
        assert manager.restore_proxy() is False
        assert command.call_count==1


def test_restore_readback_must_match():
    with patch('src.dynamic.traffic.proxy_manager.run_adb_cmd',side_effect=[(0,'',''),(0,'wrong:123','')]):
        manager=DeviceProxyManager('adb','device');manager.previous_proxy='old:456';manager.backup_verified=True
        assert not manager.restore_proxy()


def test_available_zero_is_not_unavailable_and_dead_backend_is_unavailable():
    backend=NativeProxyCaptureBackend();service=DynamicTrafficService(backend=backend,adb_bin='adb')
    assert service.get_visibility_metadata()['http_visibility']=='unknown'
    service.active_capture=CaptureSession(status=CaptureStatus.ACTIVE)
    service.proxy_mgr=MagicMock(configured=True,readback_verified=True)
    with patch.object(backend,'is_alive',return_value=True):
        assert service.get_visibility_metadata()['http_visibility']=='available'
        assert service.captured_transactions==[]
    with patch.object(backend,'is_alive',return_value=False):
        assert service.get_visibility_metadata()['http_visibility']=='unavailable'
    assert service.get_visibility_metadata()['https_visibility']=='unavailable'


def test_demo_has_separate_configurable_traffic_port():
    from src.demo_web_server import DemoWebServer
    assert DemoWebServer(port=8080).traffic_proxy_port==18080
    assert DemoWebServer(traffic_proxy_port=18085).traffic_proxy_port==18085
    with pytest.raises(ValueError):DemoWebServer(traffic_proxy_port=0)


def test_unavailable_reason_survives_report_projection():
    from tests.test_dynamic_analysis_report import sources
    from src.dynamic.report import build_dynamic_analysis_report
    data=sources.__wrapped__()
    data['traffic'].update(http_visibility='unavailable',http_visibility_reason='PROXY_PORT_IN_USE')
    report=build_dynamic_analysis_report('d24',data)
    assert report['traffic']['http_visibility_reason']=='PROXY_PORT_IN_USE'
    assert report['coverage']['http_visibility']=='unavailable'
