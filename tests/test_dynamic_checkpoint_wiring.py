"""D20 regression: live service visibility, not nonexistent readiness or CA assumptions."""
from unittest.mock import MagicMock
from src.demo_orchestrator import _wire_api_correlation
from src.dynamic.traffic.service import DynamicTrafficService


def test_captured_traffic_uses_service_visibility_without_readiness_result(tmp_path):
    service = DynamicTrafficService(backend=MagicMock(), storage=MagicMock(), adb_bin='adb')
    service.captured_transactions = [{'transaction_id':'tx_observed', 'session_id':'session_A',
        'request': {'method':'GET', 'url':'http://example.test/profile', 'host':'example.test', 'path':'/profile',
                    'scheme':'http', 'port':80}, 'response': {'status_code':200}}]
    service.get_visibility_metadata = MagicMock(return_value={'http_visibility':'available',
        'https_visibility':'unknown', 'https_reason':'no_https_transaction_available_to_verify'})
    assert not hasattr(service, 'readiness_result')
    result = _wire_api_correlation(tmp_path, 'session_A', traffic_service=service)
    assert result is not None
    service.get_visibility_metadata.assert_called_once()
    assert (tmp_path/'dynamic/api_correlation.json').is_file()
    assert (tmp_path/'dynamic/endpoint_contexts.json').is_file()
    assert result.summary.https_visibility == 'unknown'
    assert result.summary.dynamic_endpoint_count == 1


def test_real_capture_backend_names_preserved_as_safe_labels():
    from src.dynamic.report import build_dynamic_analysis_report
    from tests.test_dynamic_analysis_report import sources
    for backend, label in [('NativeProxyCaptureBackend','native_http'), ('MitmproxyCaptureBackend','mitmproxy')]:
        data = sources.__wrapped__()
        data['traffic']['backend'] = backend
        report = build_dynamic_analysis_report('checkpoint', data)
        assert report['traffic']['backend'] == label
