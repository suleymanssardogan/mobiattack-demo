"""Local baseline/logout fixtures; all adversarial post-logout variants use mocks."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import threading
import uuid
from unittest.mock import Mock, patch

import pytest
from scripts.labs.auth_baseline_lab import TrainingSessionLab, make_server
from scripts.labs.execute_session_invalidation import acquire_case
from src.dynamic.security.contracts import check_request_safety, validate_result
from src.dynamic.security.executor import DeterministicSecurityExecutor
from src.dynamic.security.session_invalidation import validate_session_invalidation, PROTECTED_BODY
from src.dynamic.security.reporting import security_result_artifact, save_security_results, build_security_section, validate_security_section


@pytest.fixture
def case():
    lab=TrainingSessionLab(str(uuid.uuid4()));server=make_server('127.0.0.1',0,lab)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield acquire_case(server)
    finally:server.shutdown();server.server_close();thread.join(timeout=2)


def perform(case,status=401,body=None):
    backend,request,context,registry,_,_=case
    if body is None:body={'error':'session_invalidated'}
    trace='lab_session_variant';alias,credential=backend.lab.principal(backend.raw_baseline['request']['headers']['authorization'])
    state=dict(backend.lab.sessions[credential])
    backend.lab.receipts.append({'trace_id':trace,'run_id':request.session_id,'method':'GET','path':'/profile',
        'status':status,'auth_present':True,'auth_valid':status==200,'source':'local_training_backend_actual_response',
        'principal_alias':alias,'credential_ref':credential,'generation':1,
        'response_sha256':hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest(),
        'state_before':{'evidence_ref':'state_'+trace+'_before','session_id':request.session_id,'trace_id':trace,**state},
        'state_after':{'evidence_ref':'state_'+trace+'_after','session_id':request.session_id,'trace_id':trace,**state}})
    connection=Mock();response=connection.getresponse.return_value
    response.status=status;response.read.return_value=json.dumps(body).encode()
    response.getheaders.return_value=[('Content-Type','application/json'),('X-Lab-Trace-ID',trace)]
    with patch('src.dynamic.security.session_invalidation.HTTPConnection',return_value=connection) as transport:
        execution=DeterministicSecurityExecutor(session_backend=backend).execute(request,context,registry,session_id=request.session_id)
    assert execution.execution_status=='completed' and transport.call_count==1
    return backend,request,context,execution,connection


def test_real_baseline_logout_and_safe_credential_identity(case):
    backend,request,context,registry,_,_=case
    assert backend.baseline['response']['status_code']==200 and backend.baseline['response']['body']==PROTECTED_BODY
    assert backend.logout['response']['status_code']==200 and backend.logout['response']['body']=={'logout':'completed'}
    ref=backend.lifecycle['credential_ref']
    assert ref.startswith('principal_session_') and backend.lifecycle['generation']==1
    assert backend.lab.sessions[ref]['active'] is False and backend.lab.sessions[ref]['reason']=='logout'
    assert backend.eligible(request,context,registry)
    assert check_request_safety(request,context,registry,controlled_session_lab=backend)['decision']=='eligible_for_future_policy_review'
    assert len(backend.lab._principal_sessions)==1 # no second login/refresh


def test_old_credential_identical_request_once_and_enforced(case):
    backend,request,context,execution,connection=perform(case)
    result=backend.validate(request,execution)
    assert result.outcome=='validated' and result.reason_codes==('SESSION_INVALIDATION_ENFORCED',)
    validate_result(request,execution,result,backend.evidence,session_evidence=backend.bundle)
    connection.putrequest.assert_called_once_with('GET','/profile',skip_host=True,skip_accept_encoding=True)
    assert dict(call.args for call in connection.putheader.call_args_list)==backend.raw_baseline['request']['headers']
    connection.endheaders.assert_called_once_with()
    refs=[r['credential_ref'] for r in backend.bundle.variant_receipts if r['path']=='/profile']
    assert refs==[backend.lifecycle['credential_ref']]*2
    with patch('src.dynamic.security.session_invalidation.HTTPConnection') as transport:
        again=DeterministicSecurityExecutor(session_backend=backend).execute(request,context,backend.evidence,session_id=request.session_id)
    assert again.execution_status=='blocked';transport.assert_not_called()


@pytest.mark.parametrize('status,body,outcome,reason',[
    (200,PROTECTED_BODY,'rejected','SESSION_INVALIDATION_NOT_ENFORCED'),
    (200,{'ok':True},'inconclusive','INSUFFICIENT_RESPONSE_COMPARISON'),
    (302,{'page':'login'},'inconclusive','INSUFFICIENT_RESPONSE_COMPARISON'),
    (401,{'error':'generic'},'inconclusive','INSUFFICIENT_RESPONSE_COMPARISON')])
def test_real_protected_access_proof_not_status_alone(case,status,body,outcome,reason):
    backend,request,context,execution,_=perform(case,status,body)
    result=backend.validate(request,execution)
    assert result.outcome==outcome and result.reason_codes==(reason,)
    section=build_security_section(security_result_artifact(request,execution,backend.evidence,backend.bundle,result),request.session_id,[context.to_dict()])
    validate_security_section(section,request.session_id,{context.endpoint_context_id})
    assert section['results'][0]['finding_created'] is False
    assert section['results'][0]['logout_evidence_refs']['response']


@pytest.mark.parametrize('change,reason',[
    ('baseline','MISSING_BASELINE_EVIDENCE'),('logout','MISSING_LOGOUT_EVIDENCE'),
    ('logout_state','LOGOUT_NOT_PROVEN'),('logout_body','LOGOUT_NOT_PROVEN'),
    ('session','CROSS_SESSION_EVIDENCE'),('receipt_session','CROSS_SESSION_EVIDENCE'),
    ('synthetic','SYNTHETIC_RESPONSE'),('logout_synthetic','SYNTHETIC_RESPONSE'),
    ('receipt_synthetic','SYNTHETIC_RESPONSE'),('new_credential','CREDENTIAL_IDENTITY_MISMATCH'),
    ('new_generation','CREDENTIAL_IDENTITY_MISMATCH'),('unknown_credential','CREDENTIAL_IDENTITY_MISMATCH'),
    ('path','UNEXPECTED_REQUEST_MUTATION'),('method','UNEXPECTED_REQUEST_MUTATION'),
    ('query','UNEXPECTED_REQUEST_MUTATION'),('header','UNEXPECTED_REQUEST_MUTATION'),
    ('state','MISSING_STATE_EVIDENCE'),('state_session','CROSS_SESSION_EVIDENCE'),
    ('state_ref','MISSING_REQUIRED_EVIDENCE'),('hash','INSUFFICIENT_RESPONSE_COMPARISON'),
    ('expired','BASELINE_EXPIRED')])
def test_incomplete_mismatched_evidence_never_promotes(case,change,reason):
    backend,request,_,execution,_=perform(case)
    bundle=deepcopy(backend.bundle);registry=dict(backend.evidence)
    if change=='baseline':bundle=replace(bundle,baseline=None)
    if change=='logout':bundle=replace(bundle,logout=None)
    if change=='logout_state':
        match=next(r for r in bundle.logout_receipts if r['path']=='/logout');match['state_after']['active']=True
    if change=='logout_body':
        bundle.logout['response']['body']={'logout':'maybe'}
        match=next(r for r in bundle.logout_receipts if r['path']=='/logout')
        match['response_sha256']=hashlib.sha256(json.dumps(bundle.logout['response']['body'],sort_keys=True).encode()).hexdigest()
    if change=='session':bundle.session['session_id']='other_session'
    if change=='receipt_session':bundle.variant_receipts[-1]['run_id']='other_session'
    if change=='synthetic':bundle.variant['response']['synthetic']=True
    if change=='logout_synthetic':bundle.logout['response']['internal']=True
    if change=='receipt_synthetic':bundle.variant_receipts[-1]['synthetic']=True
    if change=='new_credential':bundle.variant_receipts[-1]['credential_ref']='principal_session_'+'a'*32
    if change=='new_generation':bundle.variant_receipts[-1]['generation']=2
    if change=='unknown_credential':bundle.variant_receipts[-1].pop('credential_ref')
    if change=='path':bundle.variant['request']['path']='/account'
    if change=='method':bundle.variant['request']['method']='POST'
    if change=='query':bundle.variant['request']['query']={'object_id':'1'}
    if change=='header':bundle.variant['request']['headers']['x-extra']='unexpected'
    if change=='state':bundle.variant_receipts[-1].pop('state_after')
    if change=='state_session':bundle.variant_receipts[-1]['state_after']['session_id']='other_session'
    if change=='state_ref':registry.pop(bundle.variant_receipts[-1]['state_after']['evidence_ref'])
    if change=='hash':bundle.variant_receipts[-1]['response_sha256']='bad'
    if change=='expired':bundle.variant['response']['timestamp']='2099-01-01T00:00:00+00:00'
    result=validate_session_invalidation(request,execution,registry,bundle)
    assert result.outcome in {'blocked','inconclusive'} and result.reason_codes==(reason,)
    if change in {'new_credential','new_generation','unknown_credential'}:assert result.outcome=='inconclusive'


@pytest.mark.parametrize('change',['baseline','logout','logout_state','registry_state','expired','identity','public','session','synthetic','logout_synthetic','receipt_session'])
def test_preconditions_block_before_replay(case,change):
    backend,request,context,registry,_,_=case
    if change=='baseline':backend.baseline={}
    if change=='logout':backend.logout={}
    if change=='logout_state':backend.lab.receipts[-1]['state_after']['active']=True
    if change=='registry_state':backend.lab.sessions[backend.lifecycle['credential_ref']]['active']=True
    if change=='expired':backend.lab.sessions[backend.lifecycle['credential_ref']]['expires_at']='2000-01-01T00:00:00+00:00'
    if change=='identity':backend.raw_baseline['request']['headers']['authorization']='Bearer unknown'
    if change=='public':context.host='api.example.com'
    if change=='session':backend.session['session_id']='other_session'
    if change=='synthetic':backend.baseline['synthetic']=True
    if change=='logout_synthetic':backend.logout['response']['synthetic']=True
    if change=='receipt_session':backend.lab.receipts[-1]['run_id']='other_session'
    with patch('src.dynamic.security.session_invalidation.HTTPConnection') as transport:
        result=DeterministicSecurityExecutor(session_backend=backend).execute(request,context,registry,session_id=request.session_id)
    assert result.execution_status=='blocked' and not result.evidence_refs;transport.assert_not_called()


@pytest.mark.parametrize('risk',['passive','medium','high','destructive'])
def test_risk_boundary(case,risk):
    backend,request,context,registry,_,_=case
    with patch('src.dynamic.security.session_invalidation.HTTPConnection') as transport:
        result=DeterministicSecurityExecutor(session_backend=backend).execute(replace(request,risk_class=risk),context,registry,session_id=request.session_id)
    assert result.execution_status=='blocked';transport.assert_not_called()


def test_no_backend_public_policy_and_failure_without_retry(case):
    backend,request,context,registry,_,_=case
    assert check_request_safety(request,context,registry)['decision']=='blocked'
    assert DeterministicSecurityExecutor().execute(request,context,registry,session_id=request.session_id).execution_status=='blocked'
    with patch('src.dynamic.security.session_invalidation.HTTPConnection',side_effect=TimeoutError) as transport:
        result=DeterministicSecurityExecutor(session_backend=backend).execute(request,context,registry,session_id=request.session_id)
        again=DeterministicSecurityExecutor(session_backend=backend).execute(request,context,registry,session_id=request.session_id)
    assert result.execution_status=='failed' and not result.evidence_refs
    assert again.execution_status=='blocked' and transport.call_count==1


def test_sanitization_atomic_persistence_endpoint_and_logout_links(case,tmp_path):
    backend,request,context,execution,_=perform(case)
    original=context.to_dict();result=backend.validate(request,execution)
    artifact=security_result_artifact(request,execution,backend.evidence,backend.bundle,result)
    path=save_security_results(tmp_path,artifact);text=path.read_text()
    assert backend.raw_baseline['request']['headers']['authorization'][7:] not in text
    assert 'training_A_password' not in text and not list(path.parent.glob('.tmp_security_*'))
    section=build_security_section(json.loads(text),request.session_id,[context.to_dict()]);validate_security_section(section,request.session_id,{context.endpoint_context_id})
    row=section['results'][0]
    assert row['endpoint_context_id']==context.endpoint_context_id and row['finding_created'] is False
    assert row['logout_evidence_refs']['response'] in row['evidence_refs']
    assert row['result_message']=='Session invalidation after logout confirmed'
    assert row['tested_relationship']['transition']=='authenticated_to_logged_out'
    assert context.to_dict()==original and not context.static
    forged=deepcopy(artifact);forged['records'][0]['evidence']['logout']['request']['headers']['authorization']='Bearer private_secret'
    with pytest.raises(ValueError):save_security_results(tmp_path/'unsafe',forged)
    section['results'][0]['logout_evidence_refs']['response']=None
    with pytest.raises(ValueError):validate_security_section(section,request.session_id,{context.endpoint_context_id})


def test_recorded_real_smoke_report_offline(tmp_path):
    from scripts.labs.execute_object_authorization import finalize_report
    from src.dynamic.report import validate_dynamic_analysis_report
    root=tmp_path/'recorded';shutil.copytree('examples/session_invalidation_d23',root)
    with patch('socket.socket') as socket, patch('subprocess.run') as process:report=finalize_report(root)
    socket.assert_not_called();process.assert_not_called();validate_dynamic_analysis_report(report)
    row=report['security_results']['results'][0]
    assert row['reason_codes']==['SESSION_INVALIDATION_ENFORCED'] and row['finding_created'] is False
    assert report['coverage']['ui_exploration']=='unavailable'
    summary=json.loads((root/'report_summary.json').read_text())
    assert summary['dynamic_security_report']['results'][0]['comparison']=='200 / 401'
    assert summary['dynamic_security_report']['results'][0]['evidence_available']=='YES'


def test_proven_session_failure_serializes_without_finding_or_fake_ui(case):
    from src.dynamic.report import build_dynamic_analysis_report
    backend,request,context,execution,_=perform(case,200,PROTECTED_BODY)
    result=backend.validate(request,execution)
    sources={'session':{'session_id':request.session_id,'status':'COMPLETED'},'endpoint_contexts':case[4].to_dict(),
             'api_correlation':case[5].to_dict(),'security_results':security_result_artifact(request,execution,backend.evidence,backend.bundle,result)}
    report=build_dynamic_analysis_report('controlled_failure',sources)
    assert report['security_results']['results'][0]['validation_outcome']=='rejected'
    assert report['security_results']['results'][0]['finding_created'] is False
    assert report['analysis_coverage']=='partial'


def test_ambiguous_real_observation_keeps_inconclusive_canonical_report(case):
    from src.dynamic.report import build_dynamic_analysis_report, validate_dynamic_analysis_report
    backend,request,context,execution,_=perform(case,200,{'ok':True})
    result=backend.validate(request,execution)
    sources={'session':{'session_id':request.session_id,'status':'COMPLETED'},'endpoint_contexts':case[4].to_dict(),
             'api_correlation':case[5].to_dict(),'security_results':security_result_artifact(request,execution,backend.evidence,backend.bundle,result)}
    report=build_dynamic_analysis_report('ambiguous_local_response',sources)
    validate_dynamic_analysis_report(report)
    assert report['security_results']['results'][0]['validation_outcome']=='inconclusive'
    assert report['analysis_coverage']=='partial' and report['exploration']['steps_attempted']==0
    assert report['security_results']['results'][0]['finding_created'] is False
    # A missing receipt hash cannot stand in for a real, bound observation.
    sources['security_results']['records'][0]['evidence']['variant_receipts'][-1]['response_sha256']='missing'
    from src.dynamic.report import DynamicReportError
    with pytest.raises(DynamicReportError):build_dynamic_analysis_report('unproven_observation',sources)


def test_report_rejects_logout_aliasing_baseline_and_unsafe_logout(case):
    backend,request,context,execution,_=perform(case)
    result=backend.validate(request,execution)
    section=build_security_section(security_result_artifact(request,execution,backend.evidence,backend.bundle,result),request.session_id,[context.to_dict()])
    section['results'][0]['logout_evidence_refs']=dict(section['results'][0]['baseline_evidence_refs'])
    with pytest.raises(ValueError):validate_security_section(section,request.session_id,{context.endpoint_context_id})
    forged=deepcopy(backend.bundle);forged.logout['request']['headers']['authorization']='Bearer private_secret'
    with pytest.raises(ValueError):security_result_artifact(request,execution,backend.evidence,forged,result)


def test_logout_future_or_synthetic_receipt_blocks_before_replay(case):
    backend,request,context,registry,_,_=case
    backend.logout['response']['timestamp']='2099-01-01T00:00:00+00:00'
    with patch('src.dynamic.security.session_invalidation.HTTPConnection') as transport:
        result=DeterministicSecurityExecutor(session_backend=backend).execute(request,context,registry,session_id=request.session_id)
    assert result.execution_status=='blocked';transport.assert_not_called()


def test_recreating_backend_cannot_repeat_replay_in_same_lab(case):
    from src.dynamic.security.session_invalidation import LocalLabSessionInvalidation
    backend,request,context,execution,_=perform(case)
    clone=LocalLabSessionInvalidation(server=backend.server,baseline=backend.baseline,raw_baseline=backend.raw_baseline,
        logout=backend.logout,context=context,session=backend.session,lifecycle=backend.lifecycle)
    with patch('src.dynamic.security.session_invalidation.HTTPConnection') as transport:
        result=DeterministicSecurityExecutor(session_backend=clone).execute(request,context,backend.evidence,session_id=request.session_id)
    assert result.execution_status=='blocked';transport.assert_not_called()
