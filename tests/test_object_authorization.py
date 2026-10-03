"""Fixed local ownership validation. Unit variants use mocked transport; no public traffic."""
from copy import deepcopy
from dataclasses import replace
import hashlib
from http.client import HTTPConnection
import json
from pathlib import Path
import threading
import uuid
from unittest.mock import Mock, patch

import pytest
from scripts.labs.auth_baseline_lab import TrainingObjectLab, make_server
from scripts.labs.execute_object_authorization import acquire_case
from src.dynamic.security.contracts import EvidenceReference, check_request_safety, validate_result
from src.dynamic.security.executor import DeterministicSecurityExecutor
from src.dynamic.security.object_authorization import (ObjectAuthorizationEvidence, resource_variant,
    validate_object_authorization, LocalLabObjectAuthorization)
from src.dynamic.security.reporting import (security_result_artifact, save_security_results,
    build_security_section, validate_security_section)


@pytest.fixture
def case():
    lab=TrainingObjectLab(str(uuid.uuid4()));server=make_server('127.0.0.1',0,lab)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield acquire_case(server)
    finally:server.shutdown();server.server_close();thread.join(timeout=2)


def perform(case,status=403,body=None):
    backend,request,context,registry,_,_=case
    if body is None:body={'error':'object_access_denied','resource_id':'2002'}
    trace='lab_variant_fixture';alias,credential=backend.lab.principal(backend.raw_baseline['request']['headers']['authorization'])
    backend.lab.receipts.append({'trace_id':trace,'run_id':request.session_id,'method':'GET','path':'/orders/2002',
        'status':status,'auth_present':True,'auth_valid':True,'source':'local_training_backend_actual_response',
        'principal_alias':alias,'credential_ref':credential,'resource_id':'2002','owner_alias':'user_B',
        'response_sha256':hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest(),
        'response_resource_id':body.get('resource_id'),'response_owner_alias':body.get('owner_alias')})
    connection=Mock();response=connection.getresponse.return_value
    response.status=status;response.read.return_value=json.dumps(body).encode()
    response.getheaders.return_value=[('Content-Type','application/json'),('X-Lab-Trace-ID',trace)]
    with patch('src.dynamic.security.object_authorization.HTTPConnection',return_value=connection) as transport:
        execution=DeterministicSecurityExecutor(object_backend=backend).execute(request,context,registry,session_id=request.session_id)
    assert execution.execution_status=='completed'
    assert transport.call_count==1
    return backend,request,context,registry,execution,connection


def test_two_principals_resource_ownership_and_real_own_baseline(case):
    backend,request,context,registry,_,_=case
    assert backend.ownership['resources']=={'1001':'user_A','2002':'user_B'}
    assert backend.baseline['response']['body']['owner_alias']=='user_A'
    assert backend.baseline['response']['status_code']==200 and context.dynamic['observed']
    assert backend.eligible(request,context,registry)
    assert check_request_safety(request,context,registry,controlled_object_lab=backend)['decision']=='eligible_for_future_policy_review'
    # Independently authenticate B and verify its configured own resource.
    connection=HTTPConnection(backend.host,backend.port,timeout=3)
    try:
        connection.request('POST','/login',json.dumps({'auth_user':'user_B','password':'training_B_password'}),
            headers={'X-Lab-Run-ID':request.session_id,'Content-Type':'application/json'})
        response=connection.getresponse();token=json.loads(response.read())['access_token']
        connection.request('GET','/orders/2002',headers={'X-Lab-Run-ID':request.session_id,'Authorization':'Bearer '+token})
        response=connection.getresponse();assert response.status==200
        assert json.loads(response.read())['owner_alias']=='user_B'
    finally:connection.close()


def test_one_variant_only_resource_changed_and_denial_validated(case):
    backend,request,context,registry,execution,connection=perform(case)
    result=backend.validate(request,execution)
    assert result.outcome=='validated' and result.reason_codes==('OBJECT_AUTHORIZATION_ENFORCED',)
    validate_result(request,execution,result,backend.evidence,object_evidence=backend.bundle)
    connection.putrequest.assert_called_once_with('GET','/orders/2002',skip_host=True,skip_accept_encoding=True)
    sent=dict(call.args for call in connection.putheader.call_args_list)
    assert sent==backend.raw_baseline['request']['headers']
    with patch('src.dynamic.security.object_authorization.HTTPConnection') as transport:
        again=DeterministicSecurityExecutor(object_backend=backend).execute(request,context,registry,session_id=request.session_id)
    assert again.execution_status=='blocked';transport.assert_not_called()


@pytest.mark.parametrize('status,body,outcome,reason', [
    (200,{'resource_id':'2002','owner_alias':'user_B','purpose':'protected_training_order'},'rejected','OBJECT_AUTHORIZATION_NOT_ENFORCED'),
    (200,{'ok':True},'inconclusive','INSUFFICIENT_RESPONSE_COMPARISON'),
    (403,{'error':'generic_denial'},'inconclusive','INSUFFICIENT_RESPONSE_COMPARISON'),
    (302,{'page':'login'},'inconclusive','INSUFFICIENT_RESPONSE_COMPARISON')])
def test_response_content_and_ownership_required_not_status_alone(case,status,body,outcome,reason):
    backend,request,_,_,execution,_=perform(case,status,body)
    result=backend.validate(request,execution)
    assert result.outcome==outcome and result.reason_codes==(reason,)
    artifact=security_result_artifact(request,execution,backend.evidence,backend.bundle,result)
    section=build_security_section(artifact,request.session_id,[backend.context.to_dict()])
    assert section['results'][0]['finding_created'] is False


@pytest.mark.parametrize('change,reason', [
    ('baseline','MISSING_BASELINE_EVIDENCE'),('ownership','MISSING_OWNERSHIP_EVIDENCE'),
    ('session','CROSS_SESSION_EVIDENCE'),('synthetic','SYNTHETIC_RESPONSE'),
    ('method','UNEXPECTED_REQUEST_MUTATION'),('headers','UNEXPECTED_REQUEST_MUTATION'),
    ('credential','UNEXPECTED_REQUEST_MUTATION'),('receipt_hash','INSUFFICIENT_RESPONSE_COMPARISON')])
def test_corrupt_or_missing_proof_never_promotes(case,change,reason):
    backend,request,_,_,execution,_=perform(case)
    data=deepcopy(backend.bundle)
    if change=='baseline':data=replace(data,baseline=None)
    if change=='ownership':data=replace(data,ownership={})
    if change=='session':data.session['session_id']='other_session'
    if change=='synthetic':data.variant['synthetic']=True
    if change=='method':data.variant['request']['method']='POST'
    if change=='headers':data.variant['request']['headers']['x-unexpected']='changed'
    if change=='credential':data.variant_receipts[-1]['credential_ref']='principal_session_other'
    if change=='receipt_hash':data.variant_receipts[-1]['response_sha256']='bad'
    result=validate_object_authorization(request,execution,backend.evidence,data)
    assert result.outcome in {'blocked','inconclusive'} and result.reason_codes==(reason,)


@pytest.mark.parametrize('change',['baseline','ownership','session','synthetic','public','auth','receipt','receipt_session','receipt_synthetic'])
def test_preconditions_block_before_transport(case,change):
    backend,request,context,registry,_,_=case
    if change=='baseline':backend.baseline={}
    if change=='ownership':backend.ownership={}
    if change=='session':backend.session['session_id']='other_session'
    if change=='synthetic':backend.baseline['synthetic']=True
    if change=='public':context.host='api.example.com'
    if change=='auth':backend.raw_baseline['request']['headers']['authorization']='Bearer unknown'
    if change=='receipt':backend.lab.receipts[-1]['source']='model_output'
    if change=='receipt_session':backend.lab.receipts[-1]['run_id']='other_session'
    if change=='receipt_synthetic':backend.lab.receipts[-1]['synthetic']=True
    with patch('src.dynamic.security.object_authorization.HTTPConnection') as transport:
        result=DeterministicSecurityExecutor(object_backend=backend).execute(request,context,registry,session_id=request.session_id)
    assert result.execution_status=='blocked' and not result.evidence_refs
    transport.assert_not_called()


def test_public_target_gate_and_backend_absence_block(case):
    backend,request,context,registry,_,_=case
    assert check_request_safety(request,context,registry)['decision']=='blocked'
    with patch('src.dynamic.security.object_authorization.HTTPConnection') as transport:
        result=DeterministicSecurityExecutor().execute(request,context,registry,session_id=request.session_id)
    assert result.execution_status=='blocked';transport.assert_not_called()


def test_sanitization_persistence_context_attachment_and_report(case,tmp_path):
    backend,request,context,registry,execution,_=perform(case)
    original=context.to_dict();result=backend.validate(request,execution)
    artifact=security_result_artifact(request,execution,backend.evidence,backend.bundle,result)
    path=save_security_results(tmp_path,artifact)
    text=path.read_text();secret=backend.raw_baseline['request']['headers']['authorization'][7:]
    assert secret not in text and 'training_A_password' not in text and 'training_B_password' not in text
    section=build_security_section(json.loads(text),request.session_id,[context.to_dict()])
    validate_security_section(section,request.session_id,{context.endpoint_context_id})
    row=section['results'][0]
    assert row['endpoint_context_id']==context.endpoint_context_id and row['finding_created'] is False
    assert row['result_message']=='Object authorization enforcement confirmed'
    assert row['tested_relationship']['resource_owner_alias']=='user_B'
    assert context.to_dict()==original and context.static.get('static_candidate_id') is None
    broken=deepcopy(artifact);broken['records'][0]['evidence']['ownership']={}
    assert build_security_section(broken,request.session_id,[context.to_dict()])['results'][0]['validation_outcome']!='validated'


def test_no_raw_secret_or_ownerless_evidence_can_be_validated(case):
    backend,request,_,_,execution,_=perform(case)
    registry=dict(backend.evidence);registry.pop(backend.ownership['evidence_ref'])
    result=validate_object_authorization(request,execution,registry,backend.bundle)
    assert result.outcome!='validated'
    forged=replace(backend.bundle,variant=deepcopy(backend.bundle.variant))
    forged.variant['request']['headers']['authorization']='Bearer secret'
    assert validate_object_authorization(request,execution,backend.evidence,forged).outcome=='blocked'


def test_recorded_live_case_in_canonical_dynamic_report_without_fake_ui(tmp_path):
    from scripts.labs.execute_object_authorization import finalize_report
    from src.dynamic.report import validate_dynamic_analysis_report
    import shutil
    root=Path('examples/object_authorization_d21')
    shutil.copytree(root/'dynamic',tmp_path/'dynamic')
    with patch('socket.socket') as socket, patch('subprocess.run') as process:
        report=finalize_report(tmp_path)
    socket.assert_not_called();process.assert_not_called()
    validate_dynamic_analysis_report(report)
    row=report['security_results']['results'][0]
    assert row['validation_outcome']=='validated' and row['reason_codes']==['OBJECT_AUTHORIZATION_ENFORCED']
    assert row['finding_created'] is False
    assert report['analysis_coverage']=='partial' and report['coverage']['ui_exploration']=='unavailable'
    assert report['exploration']['steps_attempted']==0
    assert 'exploration' not in report['evidence']
    assert row['endpoint_context_id']==report['endpoint_contexts'][0]['endpoint_context_id']
    summary=json.loads((tmp_path/'report_summary.json').read_text())
    assert summary['dynamic_security_report']['results'][0]['evidence_available']=='YES'
    assert summary['dynamic_security_report']['results'][0]['comparison']=='200 / 403'


def test_missing_security_source_cannot_replace_ui_execution():
    from src.dynamic.report import build_dynamic_analysis_report, DynamicReportError
    root=Path('examples/object_authorization_d21/dynamic')
    sources={key:json.loads((root/(key+'.json')).read_text()) for key in ('session','endpoint_contexts','security_results')}
    sources['security_results']['records'][0]['evidence']['variant']=None
    with pytest.raises(DynamicReportError):build_dynamic_analysis_report('incomplete_lab',sources)


def test_report_rejects_unbacked_cross_user_disclosure_and_preserves_conservative_result(case):
    backend,request,context,_,execution,_=perform(case,200,{'resource_id':'2002','owner_alias':'user_B','purpose':'protected_training_order'})
    result=backend.validate(request,execution)
    artifact=security_result_artifact(request,execution,backend.evidence,backend.bundle,result)
    section=build_security_section(artifact,request.session_id,[context.to_dict()])
    validate_security_section(section,request.session_id,{context.endpoint_context_id})
    section['results'][0]['variant_evidence_refs']['response']=None
    with pytest.raises(ValueError):validate_security_section(section,request.session_id,{context.endpoint_context_id})
    conservative=replace(result,outcome='inconclusive',criterion='insufficient_evidence',coverage='partial',reason_codes=('INSUFFICIENT_RESPONSE_COMPARISON',))
    artifact['records'][0]['validation']=conservative.to_dict()
    assert build_security_section(artifact,request.session_id,[context.to_dict()])['results'][0]['validation_outcome']=='inconclusive'


@pytest.mark.parametrize('risk',['passive','medium','high','destructive'])
def test_object_active_execution_requires_low_risk(case,risk):
    backend,request,context,registry,_,_=case
    with patch('src.dynamic.security.object_authorization.HTTPConnection') as transport:
        result=DeterministicSecurityExecutor(object_backend=backend).execute(replace(request,risk_class=risk),context,registry,session_id=request.session_id)
    assert result.execution_status=='blocked';transport.assert_not_called()


def test_transport_failure_no_fake_evidence_or_retry(case):
    backend,request,context,registry,_,_=case
    with patch('src.dynamic.security.object_authorization.HTTPConnection',side_effect=TimeoutError) as transport:
        result=DeterministicSecurityExecutor(object_backend=backend).execute(request,context,registry,session_id=request.session_id)
        again=DeterministicSecurityExecutor(object_backend=backend).execute(request,context,registry,session_id=request.session_id)
    assert result.execution_status=='failed' and not result.evidence_refs
    assert again.execution_status=='blocked';assert transport.call_count==1
