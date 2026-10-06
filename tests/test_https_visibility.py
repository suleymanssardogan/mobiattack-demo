"""HTTPS visibility and sanitized mitmdump bridge; no live network in unit tests."""
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from src.dynamic.traffic.https_visibility import HttpsVisibility, check_ca_trust
from src.dynamic.traffic.mitmproxy_backend import MitmproxyCaptureBackend
from src.dynamic.traffic.native_backend import NativeProxyCaptureBackend
from src.dynamic.traffic.service import DynamicTrafficService
from src.dynamic.traffic.models import CaptureSession, CaptureStatus, create_action_traffic_evidence
from src.dynamic.traffic.storage import TrafficStorage
from src.dynamic.traffic.mitmproxy_addon import CaptureAddon


@pytest.mark.parametrize('trust,success,failed,state',[
    ('unknown',0,0,'unknown'),('trusted',0,0,'unknown'),('not_installed',0,0,'unavailable'),
    ('trusted',1,0,'available'),('unknown',1,0,'partial'),('trusted',1,1,'partial'),
    ('unknown',0,1,'unavailable')])
def test_visibility_requires_transaction_evidence(trust,success,failed,state):
    tracker=HttpsVisibility(ca_trust=trust,verified_transactions=success,tls_failures=failed)
    assert tracker.metadata()[0]==state
    assert tracker.metadata()[1]


def test_failed_backend_overrides_previous_success():
    tracker=HttpsVisibility(ca_trust='trusted',verified_transactions=2,backend_failed=True)
    assert tracker.metadata()==('unavailable','capture_backend_failure')


def backend(tmp_path):
    return MitmproxyCaptureBackend(executable_path='/missing/mitmdump',ca_directory=tmp_path)


def event(response=True):
    return {'event':'transaction','transaction':{
        'transaction_id':'tx_https','request':{'scheme':'https','host':'example.invalid','port':443,
        'method':'GET','path':'/test?token=SECRET','query':{'token':'SECRET'},'headers':{'Authorization':'SECRET'},
        'body':'SECRET'},'response':{'status_code':200,'headers':{'Set-Cookie':'SECRET'},'body':'SECRET'} if response else None}}


def test_bridge_emits_sanitized_transactions_and_counts_real_responses(tmp_path):
    b=backend(tmp_path);callback=Mock();b._on_transaction=callback
    b.process_event_line('MOBIATTACK_EVIDENCE '+json.dumps(event()))
    assert b.https.verified_transactions==1
    callback.assert_called_once()
    assert 'SECRET' not in json.dumps(b.captured_transactions[0].to_dict())
    assert b.captured_transactions[0].request.path=='/test'


def test_error_bridge_does_not_promote_https_or_make_200(tmp_path):
    b=backend(tmp_path)
    b.process_event_line('MOBIATTACK_EVIDENCE '+json.dumps(event(False)))
    b.process_event_line('MOBIATTACK_EVIDENCE '+json.dumps({'event':'tls_failure','side':'client'}))
    assert b.https.verified_transactions==0
    assert b.captured_transactions[0].response is None
    assert b.https.metadata()[0]=='unavailable'


def test_internal_response_excluded_from_verified_count(tmp_path):
    b=backend(tmp_path);e=event();e['transaction']['response']['internal']=True
    b.process_event_line('MOBIATTACK_EVIDENCE '+json.dumps(e))
    assert b.https.verified_transactions==0 and b.captured_transactions[0].response is None


def test_direct_ingest_is_not_live_capture_verification(tmp_path):
    b=backend(tmp_path)
    b.ingest_raw_flow({'url':'https://example.invalid/'},{'status_code':200},'c')
    assert b.https.verified_transactions==0


def test_malformed_bridge_is_explicit_failure_without_raw_logs(tmp_path):
    b=backend(tmp_path)
    b.process_event_line('ordinary log contains SECRET')
    b.process_event_line('MOBIATTACK_EVIDENCE {broken')
    assert b.https.backend_failed and not b.captured_transactions


def test_start_uses_addon_and_verified_upstream_tls(tmp_path):
    b=backend(tmp_path);b.executable_path='/fake/mitmdump'
    process=Mock(stdout=iter(['MOBIATTACK_EVIDENCE {"event":"ready"}\n']),stderr=iter([]));process.poll.return_value=None
    with patch('src.dynamic.traffic.mitmproxy_backend.subprocess.Popen',return_value=process) as popen, \
         patch('src.dynamic.traffic.mitmproxy_backend.is_port_in_use',return_value=False), \
         patch('src.dynamic.traffic.mitmproxy_backend.time.sleep'):
        b.start(listen_port=18080)
        cmd=popen.call_args.args[0]
        assert 'ssl_insecure=false' in cmd and 'ssl_insecure=true' not in cmd
        assert any('mitmproxy_addon.py' in arg for arg in cmd)
        assert b.https.metadata()[0]=='unknown'
        b.stop()


def test_native_still_does_not_claim_https():
    service=DynamicTrafficService(backend=NativeProxyCaptureBackend())
    assert service.get_visibility_metadata()['https_visibility']=='unavailable'


def test_startup_or_ca_presence_alone_never_available(tmp_path):
    b=backend(tmp_path);b.executable_path='/fake/mitmdump';b.https.ca_trust='trusted'
    b.is_alive=Mock(return_value=True)
    s=DynamicTrafficService(backend=b);s.active_capture=CaptureSession(status=CaptureStatus.ACTIVE)
    assert s.get_visibility_metadata()['https_visibility']=='unknown'


def test_ca_check_missing_cert_is_unknown_and_read_only(tmp_path):
    with patch('src.dynamic.traffic.https_visibility.run_adb_cmd') as adb:
        assert check_ca_trust('adb','s',tmp_path/'missing.pem')[0]=='unknown'
        adb.assert_not_called()


def test_stop_persists_visibility_and_failure_evidence(tmp_path):
    b=backend(tmp_path);b.executable_path='/fake/mitmdump';b.https=HttpsVisibility(ca_trust='trusted',verified_transactions=1,tls_failures=1)
    b.is_alive=Mock(return_value=True);b.stop=Mock()
    s=DynamicTrafficService(backend=b,storage=TrafficStorage(str(tmp_path)))
    s.active_capture=CaptureSession(session_id='s',status=CaptureStatus.ACTIVE)
    summary=s.stop_capture()
    assert summary.https_visibility=='partial'
    s.storage.save_traffic_json(tmp_path/'traffic.json','s',[],s.active_capture,summary)
    assert json.loads((tmp_path/'traffic.json').read_text())['https_visibility']=='partial'


@pytest.mark.parametrize('state',['unknown','partial','unavailable'])
def test_zero_transactions_remain_not_observed(state):
    evidence=create_action_traffic_evidence('a','r',transactions=[],https_visibility=state)
    assert evidence.transaction_count==0 and state in evidence.correlation_note
    assert 'no network' not in evidence.correlation_note.lower()


def test_addon_does_not_export_proxy_generated_response(capsys):
    flow=SimpleNamespace(response=Mock(),server_conn=SimpleNamespace(timestamp_tcp_setup=None))
    CaptureAddon().response(flow)
    assert capsys.readouterr().out==''


def test_unknown_visibility_survives_canonical_dynamic_report():
    from src.dynamic.report.generator import build_dynamic_analysis_report
    report=build_dynamic_analysis_report('s', {
        'session':{'session_id':'s','status':'ACTIVE','package_name':'training'},
        'exploration':{'status':'partial','screens_observed':1},
        'traffic':{'schema_version':'1.0','transactions':[], 'http_visibility':'available','https_visibility':'unknown'}
    })
    assert report['coverage']['https_visibility']=='unknown'
    assert report['analysis_coverage']=='partial'


@pytest.mark.parametrize('store_state,expected',[('trusted','trusted'),('empty','not_installed'),('denied','unknown')])
def test_ca_inspection_compares_certificate_without_store_writes(store_state,expected):
    cert=Path(__file__).parent/'fixtures/https_visibility/public-test-ca.pem'
    pem=cert.read_text()
    calls=[]
    def adb(binary,args,serial):
        calls.append(args)
        assert args[1] in ('ls','cat')
        if store_state=='denied': return 1,'','Permission denied'
        if args[1]=='ls': return 0,('deadbeef.0' if store_state=='trusted' else ''),''
        return 0,pem,''
    with patch('src.dynamic.traffic.https_visibility.subprocess.run',return_value=Mock(returncode=0,stdout='deadbeef')), \
         patch('src.dynamic.traffic.https_visibility.run_adb_cmd',side_effect=adb):
        assert check_ca_trust('adb','emulator',cert)[0]==expected
    assert calls


@pytest.mark.parametrize('reason,expected', [
    ('cleartext_http_only_backend', 'supports HTTP only'),
    ('capture_backend_unavailable', 'backend is unavailable'),
    ('ca_not_installed', 'CA is not installed'),
    ('tls_interception_failed_ca_or_app_trust_unverified', 'trust have not been verified'),
    ('no_https_transaction_available_to_verify', 'No real HTTPS transaction'),
])
def test_summary_explains_known_https_reason_without_claiming_pinning(reason, expected):
    from src.web.report_summary import build_report_summary
    report = {'coverage': {'http_visibility': 'available', 'https_visibility': 'unavailable'},
              'traffic': {'https_visibility_reason': reason}}
    summary = build_report_summary(dynamic_report=report)['dynamic_summary']
    notes = ' '.join(summary['coverage_limitations'])
    assert expected in notes
    assert 'pinning' not in notes.lower()
    assert summary['traffic_visibility']['http_visibility'] == 'available'
    assert summary['traffic_visibility']['https_visibility'] == 'unavailable'


def test_summary_does_not_render_unknown_https_diagnostics_or_override_available():
    from src.web.report_summary import build_report_summary
    for state, reason in [('unknown', '/tmp/private.pem token=SECRET'),
                          ('available', 'cleartext_http_only_backend')]:
        summary = build_report_summary(dynamic_report={
            'coverage': {'https_visibility': state},
            'traffic': {'https_visibility_reason': reason}})['dynamic_summary']
        notes = ' '.join(summary['coverage_limitations'])
        assert 'SECRET' not in notes and '/tmp' not in notes
        assert 'supports HTTP only' not in notes
        assert summary['traffic_visibility']['https_visibility'] == state
