from copy import deepcopy
import json
from unittest.mock import patch
import uuid

import pytest

from scripts.labs.auth_baseline_lab import (
    TRAINING_ACCOUNT, TRAINING_PASSWORD, TrainingAuthLab, make_server, validate_baseline_artifacts)
from src.dynamic.traffic.normalizer import normalize_http_transaction
from src.dynamic.correlation.api_correlator import correlate_static_dynamic_apis
from src.dynamic.context.endpoint_context_builder import build_endpoint_contexts

HOST='192.168.1.154'
PORT=18081


def fixture():
    run=str(uuid.uuid4());lab=TrainingAuthLab(run)
    status,login=lab.login({'auth_user':TRAINING_ACCOUNT,'password':TRAINING_PASSWORD})
    token=login['access_token']
    profile_status,profile=lab.profile('Bearer '+token)
    txs=[]
    for path,method,body,response,headers,trace in [
        ('/login','POST',{'auth_user':TRAINING_ACCOUNT,'password':TRAINING_PASSWORD},login,{},'lab_login_fixture'),
        ('/profile','GET',None,profile,{'Authorization':'Bearer '+token},'lab_profile_fixture')]:
        tx=normalize_http_transaction({'method':method,'scheme':'http','host':HOST,'port':PORT,'path':path,
            'headers':{'Content-Type':'application/json','X-Lab-Run-ID':run,**headers},'body':body},
            {'status_code':200,'headers':{'Content-Type':'application/json','X-Lab-Trace-ID':trace},'body':response},'fixture_capture')
        tx.session_id=run;txs.append(tx.to_dict())
        lab.receipt(trace,method,path,200,path=='/profile',path=='/profile')
    traffic={'session_id':run,'transactions':txs}
    correlation=correlate_static_dynamic_apis([],txs,session_id=run)
    contexts=build_endpoint_contexts(correlation,txs)
    return lab,traffic,contexts,{'session_id':run}


def check(lab,traffic,contexts,session):
    return validate_baseline_artifacts(traffic,contexts,session,lab.receipts,host=HOST,port=PORT)


def test_fixed_training_login_and_authenticated_read_only_profile():
    lab=TrainingAuthLab(str(uuid.uuid4()))
    status,login=lab.login({'auth_user':TRAINING_ACCOUNT,'password':TRAINING_PASSWORD})
    assert status==200
    status,profile=lab.profile('Bearer '+login['access_token'])
    assert status==200 and profile['authenticated'] is True
    assert profile['purpose']=='read_only_training_profile'
    assert 'access_token' not in profile


def test_missing_auth_behavior_unit_only_no_http_request():
    lab=TrainingAuthLab(str(uuid.uuid4()))
    assert lab.profile(None)[0]==401
    assert lab.profile('Bearer invalid')[0]==401
    assert lab.profile('Bearer ü')[0]==401


def test_single_acquisition_no_chaining_or_second_login():
    lab=TrainingAuthLab(str(uuid.uuid4()))
    creds={'auth_user':TRAINING_ACCOUNT,'password':TRAINING_PASSWORD}
    assert lab.login(creds)[0]==200
    assert lab.login(creds)[0]==409


@pytest.mark.parametrize('body',[None,{}, {'auth_user':TRAINING_ACCOUNT,'password':'incorrect'},
                                 {'auth_user':TRAINING_ACCOUNT,'password':TRAINING_PASSWORD,'role':'admin'}])
def test_strict_training_login_shape_and_identity(body):
    lab=TrainingAuthLab(str(uuid.uuid4()))
    assert lab.login(body)[0] in (400,401)
    assert lab._tokens==set()


def test_fixture_canonical_baseline_metadata_is_grounded_and_secret_free():
    lab,traffic,contexts,session=fixture()
    baseline=check(lab,traffic,contexts,session)
    assert baseline['eligible_baseline'] and baseline['authorization_presence']
    assert not baseline['security_test_executed']
    stored=json.dumps([traffic,contexts.to_dict(),lab.receipts,baseline])
    for secret in (TRAINING_ACCOUNT,TRAINING_PASSWORD,*lab._tokens):
        assert secret not in stored
    profile=next(e for e in contexts.endpoints if e.path=='/profile')
    assert profile.auth['authorization_header_present'] is True
    assert profile.auth['bearer_token_present'] is None  # Redaction preserves unknown semantics.
    assert not profile.static


@pytest.mark.parametrize('change',['no_login','no_profile','no_response','non200','session','run_header',
                                  'trace','receipt_run','receipt_source','auth_receipt','auth_header',
                                  'password','token','host','port','synthetic','internal','duplicate','body'])
def test_missing_or_synthetic_or_unowned_evidence_cannot_be_eligible(change):
    lab,traffic,contexts,session=fixture()
    login,profile=traffic['transactions']
    if change=='no_login': traffic['transactions']=[profile]
    if change=='no_profile': traffic['transactions']=[login]
    if change=='no_response': profile['response']=None
    if change=='non200': profile['response']['status_code']=502
    if change=='session': profile['session_id']='another'
    if change=='run_header': profile['request']['headers']['x-lab-run-id']='another'
    if change=='trace': profile['response']['headers']['x-lab-trace-id']='fabricated'
    if change=='receipt_run': lab.receipts[1]['run_id']='another'
    if change=='receipt_source': lab.receipts[1]['source']='synthetic'
    if change=='auth_receipt': lab.receipts[1]['auth_valid']=False
    if change=='auth_header': profile['request']['headers'].pop('authorization')
    if change=='password': login['request']['body']['password']='raw'
    if change=='token': login['response']['body']['access_token']='raw'
    if change=='host': profile['request']['host']='external.example'
    if change=='port': profile['request']['port']=8080
    if change=='synthetic': profile['response']['synthetic']=True
    if change=='internal': profile['internal']=True
    if change=='duplicate': traffic['transactions'].append(deepcopy(profile))
    if change=='body': profile['response']['body']={'status':200}
    with pytest.raises(ValueError):
        check(lab,traffic,contexts,session)


def test_200_alone_cannot_be_eligible_without_authentication_and_receipt():
    lab,traffic,contexts,session=fixture()
    lab.receipts=[]
    with pytest.raises(ValueError):
        check(lab,traffic,contexts,session)


@pytest.mark.parametrize('field,value',[('session_id','another'),('host','external.example'),('port',8080)])
def test_canonical_context_and_session_ownership_checked(field,value):
    lab,traffic,contexts,session=fixture()
    if field=='session_id': contexts.session_id=value
    else:
        setattr(next(e for e in contexts.endpoints if e.path=='/profile'),field,value)
    with pytest.raises(ValueError):
        check(lab,traffic,contexts,session)


@pytest.mark.parametrize('address',['0.0.0.0','8.8.8.8'])
def test_lab_never_binds_public_or_unspecified_address(address):
    with patch('scripts.labs.auth_baseline_lab.ThreadingHTTPServer') as server:
        with pytest.raises(ValueError):
            make_server(address,PORT,TrainingAuthLab(str(uuid.uuid4())))
    server.assert_not_called()


def test_browser_page_only_one_login_and_one_authenticated_read_no_secret_storage():
    page=TrainingAuthLab(str(uuid.uuid4())).page().decode()
    assert page.count("fetch('/login'")==1 and page.count("fetch('/profile'")==1
    assert "'Authorization':'Bearer '+session.access_token" in page
    assert 'localStorage' not in page and 'document.cookie' not in page
    assert 'button.disabled=true' in page


def test_backend_receipts_metadata_only_and_bounded():
    lab=TrainingAuthLab(str(uuid.uuid4()))
    for index in range(32):
        lab.receipt(str(index),'GET','/profile',200,True,True)
    with pytest.raises(ValueError):
        lab.receipt('extra','GET','/profile',200,True,True)
    assert not any('password' in r or 'token' in r or 'authorization' in r for r in lab.receipts)


def test_saved_live_lab_artifacts_have_valid_refs_and_no_credentials():
    """Optional artifact check; this test sends no requests and runs no emulator."""
    import os
    from pathlib import Path
    from src.dynamic.context.models import EndpointContextArtifact
    from src.dynamic.correlation.models import ApiCorrelationResult
    root=os.environ.get('MOBIATTACK_AUTH_LAB_ARTIFACTS')
    if not root:
        pytest.skip('Live lab artifact path not supplied')
    root=Path(root)
    baseline=json.loads((root/'baseline.json').read_text())
    traffic=json.loads((root/'dynamic/traffic.json').read_text())
    session=json.loads((root/'dynamic/session.json').read_text())
    receipts=json.loads((root/'lab_receipts.json').read_text())
    contexts=EndpointContextArtifact.load(root/'dynamic/endpoint_contexts.json')
    corr=ApiCorrelationResult.load(root/'dynamic/api_correlation.json')
    route=json.loads((root/'route_evidence.json').read_text())
    tool=json.loads((root/'lab_acquisition_result.json').read_text())
    profile=next(e for e in contexts.endpoints if e.path=='/profile')
    checked=validate_baseline_artifacts(traffic,contexts,session,receipts,host=profile.host,port=profile.port)
    assert all(baseline[k]==v for k,v in checked.items())
    assert corr.session_id==baseline['session_id']==route['session_id']==tool['session_id']
    assert baseline['action_id']==route['action_id']
    assert profile.evidence_refs['action_ids']==[baseline['action_id']]
    assert any(r['source_node_id']==baseline['route_id'] for r in profile.route_context)
    assert tool['evidence_ref']==baseline['tool_result_ref']
    assert traffic['proxy_restored'] and not tool['security_test_executed']
    assert len(receipts)==2 and {r['path'] for r in receipts}=={'/login','/profile'}
    assert not baseline['secret_persisted']
    for path in root.rglob('*'):
        if path.is_file():
            contents=path.read_bytes()
            assert TRAINING_ACCOUNT.encode() not in contents
            assert TRAINING_PASSWORD.encode() not in contents
