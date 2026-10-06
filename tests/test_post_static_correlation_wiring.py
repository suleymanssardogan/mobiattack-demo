"""Final artifact ordering, no repeat scan/traffic or cross-run fallback."""
import json
from pathlib import Path
from unittest.mock import patch

from src.orchestration.results import refresh_post_static_correlation


def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(data))


def fixture(root):
    write(root/'static_analysis_report.json',{'run_id':root.name,'api_candidates':[{
        'candidate_id':'static_signup','framework':'Fuel','method':'POST','base_url':'http://127.0.0.1',
        'path':'/signup','full_url':'http://127.0.0.1/signup','source_file':'smali/Register.smali',
        'evidence':{'request_call_line':10}}]})
    write(root/'dynamic/session.json',{'session_id':'session_fresh','status':'COMPLETED'})
    write(root/'dynamic/traffic.json',{'session_id':'session_fresh','transactions':[],
        'http_visibility':'available','https_visibility':'unavailable'})


def test_static_only_context_recovered_after_static_report_is_written(tmp_path):
    root=tmp_path/'fresh';fixture(root)
    before=(root/'dynamic/traffic.json').read_bytes()
    with patch('socket.socket') as sock,patch('subprocess.run') as process:
        assert refresh_post_static_correlation(root) is not None
    sock.assert_not_called();process.assert_not_called()
    contexts=json.loads((root/'dynamic/endpoint_contexts.json').read_text())
    assert len(contexts['endpoints'])==1
    context=contexts['endpoints'][0]
    assert context['path']=='/signup' and context['dynamic']['observed'] is False
    assert context['static']['static_candidate_id']=='static_signup'
    assert (root/'dynamic/traffic.json').read_bytes()==before
    refresh_post_static_correlation(root)
    assert json.loads((root/'dynamic/endpoint_contexts.json').read_text())['endpoints'][0]['endpoint_context_id']==context['endpoint_context_id']


def test_wrong_run_static_artifact_never_replaces_current_context(tmp_path):
    root=tmp_path/'fresh';fixture(root)
    write(root/'dynamic/endpoint_contexts.json',{'original_evidence':True})
    static=json.loads((root/'static_analysis_report.json').read_text());static['run_id']='old_run'
    write(root/'static_analysis_report.json',static)
    assert refresh_post_static_correlation(root) is None
    assert json.loads((root/'dynamic/endpoint_contexts.json').read_text())=={'original_evidence':True}


def test_missing_static_does_not_fallback_to_sibling_report(tmp_path):
    root=tmp_path/'fresh';root.mkdir();fixture(tmp_path/'old')
    write(root/'dynamic/session.json',{'session_id':'session_fresh'})
    assert refresh_post_static_correlation(root) is None
    assert not (root/'dynamic/endpoint_contexts.json').exists()
