"""Controlled role validation. Variant transports are mocked except recorded smoke."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import threading
import uuid
from unittest.mock import Mock, patch

import pytest
from scripts.labs.auth_baseline_lab import TrainingFunctionLab, make_server
from scripts.labs.execute_function_authorization import acquire_case
from src.dynamic.security.contracts import check_request_safety, validate_result, EvidenceReference
from src.dynamic.security.executor import DeterministicSecurityExecutor
from src.dynamic.security.function_authorization import validate_function_authorization
from src.dynamic.security.reporting import security_result_artifact, save_security_results, build_security_section, validate_security_section


@pytest.fixture
def case():
    lab=TrainingFunctionLab(str(uuid.uuid4()));server=make_server('127.0.0.1',0,lab)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield acquire_case(server)
    finally:lab.reset();server.shutdown();server.server_close();thread.join(timeout=2)


def perform(case,status=403,body=None,changed=False):
    backend,request,context,registry,_,_=case
    if body is None:body={'error':'function_access_denied','function':'training_toggle'}
    trace='lab_function_fixture';alias,credential=backend.lab.principal(backend.normal_authorization)
    before=dict(backend.lab.state);after={'enabled':True,'revision':2} if changed else before
    backend.lab.receipts.append({'trace_id':trace,'run_id':request.session_id,'method':'POST','path':'/lab/admin/toggle',
        'status':status,'auth_present':True,'auth_valid':True,'source':'local_training_backend_actual_response',
        'principal_alias':alias,'role':'user','credential_ref':credential,
        'response_sha256':hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest(),
        'state_before':{'evidence_ref':'state_'+trace+'_before','session_id':request.session_id,'trace_id':trace,**before},
        'state_after':{'evidence_ref':'state_'+trace+'_after','session_id':request.session_id,'trace_id':trace,**after}})
    connection=Mock();response=connection.getresponse.return_value
    response.status=status;response.read.return_value=json.dumps(body).encode()
    response.getheaders.return_value=[('Content-Type','application/json'),('X-Lab-Trace-ID',trace)]
    with patch('src.dynamic.security.function_authorization.HTTPConnection',return_value=connection) as transport:
        execution=DeterministicSecurityExecutor(function_backend=backend).execute(request,context,registry,session_id=request.session_id)
    assert execution.execution_status=='completed' and transport.call_count==1
    return backend,request,context,execution,connection


def test_admin_real_baseline_normal_user_role_and_reset(case):
    backend,request,context,registry,_,_=case
    assert backend.privileges['principals']['user_A']['role']=='user'
    assert backend.privileges['principals']['user_B']['role']=='admin'
    assert backend.baseline['response']['status_code']==200
    assert backend.lab.state=={'enabled':True,'revision':1}
    assert backend.eligible(request,context,registry)
    assert check_request_safety(request,context,registry,controlled_function_lab=backend)['decision']=='eligible_for_future_policy_review'
    backend.lab.reset();assert backend.lab.state=={'enabled':False,'revision':0}
    assert not backend.eligible(request,context,registry) # stale state requires a fresh baseline


def test_same_semantics_only_principal_changed_once_and_denial_validated(case):
    backend,request,context,execution,connection=perform(case)
    result=backend.validate(request,execution)
    assert result.outcome=='validated' and result.reason_codes==('FUNCTION_AUTHORIZATION_ENFORCED',)
    validate_result(request,execution,result,backend.evidence,function_evidence=backend.bundle)
    connection.putrequest.assert_called_once_with('POST','/lab/admin/toggle',skip_host=True,skip_accept_encoding=True)
    sent=dict(call.args for call in connection.putheader.call_args_list)
    expected=dict(backend.raw_baseline['request']['headers']);expected['authorization']=backend.normal_authorization
    assert sent==expected
    connection.endheaders.assert_called_once_with(backend.raw_baseline['request']['body'].encode())
    with patch('src.dynamic.security.function_authorization.HTTPConnection') as transport:
        again=DeterministicSecurityExecutor(function_backend=backend).execute(request,context,backend.evidence,session_id=request.session_id)
    assert again.execution_status=='blocked';transport.assert_not_called()


@pytest.mark.parametrize('status,body,changed,outcome,reason',[
    (200,{'function':'training_toggle','applied':True,'enabled':True,'revision':2},True,'rejected','FUNCTION_AUTHORIZATION_NOT_ENFORCED'),
    (200,{'ok':True},False,'inconclusive','INSUFFICIENT_RESPONSE_COMPARISON'),
    (200,{'function':'training_toggle','applied':True,'enabled':True,'revision':2},False,'inconclusive','INSUFFICIENT_RESPONSE_COMPARISON'),
    (302,{'page':'login'},False,'inconclusive','INSUFFICIENT_RESPONSE_COMPARISON'),
    (403,{'error':'generic'},False,'inconclusive','INSUFFICIENT_RESPONSE_COMPARISON'),
    (403,{'error':'function_access_denied','function':'training_toggle'},True,'inconclusive','INSUFFICIENT_RESPONSE_COMPARISON')])
def test_effect_and_response_proof_not_status_only(case,status,body,changed,outcome,reason):
    backend,request,context,execution,_=perform(case,status,body,changed)
    result=backend.validate(request,execution)
    assert result.outcome==outcome and result.reason_codes==(reason,)
    section=build_security_section(security_result_artifact(request,execution,backend.evidence,backend.bundle,result),request.session_id,[context.to_dict()])
    validate_security_section(section,request.session_id,{context.endpoint_context_id})
    assert section['results'][0]['finding_created'] is False


@pytest.mark.parametrize('change,reason',[
    ('baseline','MISSING_BASELINE_EVIDENCE'),('privileges','MISSING_PRIVILEGE_EVIDENCE'),
    ('role','MISSING_PRIVILEGE_EVIDENCE'),('session','CROSS_SESSION_EVIDENCE'),
    ('receipt_session','CROSS_SESSION_EVIDENCE'),('synthetic','SYNTHETIC_RESPONSE'),
    ('receipt_synthetic','SYNTHETIC_RESPONSE'),('body','UNEXPECTED_REQUEST_MUTATION'),
    ('header','UNEXPECTED_REQUEST_MUTATION'),('method','UNEXPECTED_REQUEST_MUTATION'),
    ('credential','UNEXPECTED_REQUEST_MUTATION'),('state','MISSING_STATE_EVIDENCE'),
    ('state_session','CROSS_SESSION_EVIDENCE'),('state_trace','REFERENCE_MISMATCH'),
    ('state_ref','MISSING_REQUIRED_EVIDENCE'),('hash','INSUFFICIENT_RESPONSE_COMPARISON')])
def test_corrupt_evidence_no_promotion(case,change,reason):
    backend,request,_,execution,_=perform(case)
    bundle=deepcopy(backend.bundle);registry=dict(backend.evidence)
    if change=='baseline':bundle=replace(bundle,baseline=None)
    if change=='privileges':bundle=replace(bundle,privileges={})
    if change=='role':bundle.privileges['principals']['user_A']['role']='unknown'
    if change=='session':bundle.session['session_id']='other_session'
    if change=='receipt_session':bundle.variant_receipts[-1]['run_id']='other_session'
    if change=='synthetic':bundle.variant['response']['synthetic']=True
    if change=='receipt_synthetic':bundle.variant_receipts[-1]['synthetic']=True
    if change=='body':bundle.variant['request']['body']['enabled']=False
    if change=='header':bundle.variant['request']['headers']['x-extra']='unexpected'
    if change=='method':bundle.variant['request']['method']='GET'
    if change=='credential':bundle.variant_receipts[-1]['credential_ref']=bundle.privileges['principals']['user_B']['credential_ref']
    if change=='state':bundle.variant_receipts[-1].pop('state_after')
    if change=='state_session':bundle.variant_receipts[-1]['state_after']['session_id']='other_session'
    if change=='state_trace':bundle.variant_receipts[-1]['state_after']['trace_id']='other_trace'
    if change=='state_ref':registry.pop(bundle.variant_receipts[-1]['state_after']['evidence_ref'])
    if change=='hash':bundle.variant_receipts[-1]['response_sha256']='wrong'
    result=validate_function_authorization(request,execution,registry,bundle)
    assert result.outcome in {'blocked','inconclusive'} and result.reason_codes==(reason,)


@pytest.mark.parametrize('change',['baseline','privilege','role','normal_identity','admin_identity','public','session','state','synthetic','receipt_session','receipt_synthetic'])
def test_preconditions_block_without_sending(case,change):
    backend,request,context,registry,_,_=case
    if change=='baseline':backend.baseline={}
    if change=='privilege':backend.privileges['function']['required_role']='unknown'
    if change=='role':backend.privileges['principals']['user_A']['role']='unknown'
    if change=='normal_identity':backend.normal_authorization='Bearer unknown'
    if change=='admin_identity':backend.raw_baseline['request']['headers']['authorization']=backend.normal_authorization
    if change=='public':context.host='api.example.com'
    if change=='session':backend.session['session_id']='other_session'
    if change=='state':backend.lab.state['revision']=3
    if change=='synthetic':backend.baseline['synthetic']=True
    if change=='receipt_session':backend.lab.receipts[-1]['run_id']='other_session'
    if change=='receipt_synthetic':backend.lab.receipts[-1]['synthetic']=True
    with patch('src.dynamic.security.function_authorization.HTTPConnection') as transport:
        result=DeterministicSecurityExecutor(function_backend=backend).execute(request,context,registry,session_id=request.session_id)
    assert result.execution_status=='blocked' and not result.evidence_refs;transport.assert_not_called()


@pytest.mark.parametrize('risk',['passive','medium','high','destructive'])
def test_risk_boundary(case,risk):
    backend,request,context,registry,_,_=case
    with patch('src.dynamic.security.function_authorization.HTTPConnection') as transport:
        result=DeterministicSecurityExecutor(function_backend=backend).execute(replace(request,risk_class=risk),context,registry,session_id=request.session_id)
    assert result.execution_status=='blocked';transport.assert_not_called()


def test_no_backend_policy_blocked_and_transport_failure_not_secure(case):
    backend,request,context,registry,_,_=case
    assert check_request_safety(request,context,registry)['decision']=='blocked'
    assert DeterministicSecurityExecutor().execute(request,context,registry,session_id=request.session_id).execution_status=='blocked'
    with patch('src.dynamic.security.function_authorization.HTTPConnection',side_effect=TimeoutError) as transport:
        result=DeterministicSecurityExecutor(function_backend=backend).execute(request,context,registry,session_id=request.session_id)
        again=DeterministicSecurityExecutor(function_backend=backend).execute(request,context,registry,session_id=request.session_id)
    assert result.execution_status=='failed' and not result.evidence_refs
    assert again.execution_status=='blocked' and transport.call_count==1


def test_atomic_sanitized_persistence_endpoint_attachment_report(case,tmp_path):
    backend,request,context,execution,_=perform(case)
    before=context.to_dict();result=backend.validate(request,execution)
    path=save_security_results(tmp_path,security_result_artifact(request,execution,backend.evidence,backend.bundle,result))
    text=path.read_text()
    assert backend.normal_authorization[7:] not in text
    assert backend.raw_baseline['request']['headers']['authorization'][7:] not in text
    assert 'training_A_password' not in text and 'training_B_password' not in text
    assert not list(path.parent.glob('.tmp_security_*'))
    section=build_security_section(json.loads(text),request.session_id,[context.to_dict()])
    validate_security_section(section,request.session_id,{context.endpoint_context_id})
    row=section['results'][0]
    assert row['endpoint_context_id']==context.endpoint_context_id and row['finding_created'] is False
    assert row['result_message']=='Function authorization enforcement confirmed'
    assert row['tested_relationship']['normal_role']=='user' and row['tested_relationship']['privileged_role']=='admin'
    assert context.to_dict()==before and not context.static


def test_recorded_live_smoke_revalidates_without_transport(tmp_path):
    from scripts.labs.execute_object_authorization import finalize_report
    from src.dynamic.report import validate_dynamic_analysis_report
    import shutil
    root=tmp_path/'recorded_smoke'
    shutil.copytree('examples/function_authorization_d22',root)
    with patch('socket.socket') as socket, patch('subprocess.run') as process:
        report=finalize_report(root)
    socket.assert_not_called();process.assert_not_called()
    validate_dynamic_analysis_report(report)
    row=report['security_results']['results'][0]
    assert row['reason_codes']==['FUNCTION_AUTHORIZATION_ENFORCED'] and row['finding_created'] is False
    assert report['coverage']['ui_exploration']=='unavailable' and report['exploration']['steps_attempted']==0
    summary=json.loads((root/'report_summary.json').read_text())
    assert summary['dynamic_security_report']['results'][0]['comparison']=='200 / 403'
    assert summary['dynamic_security_report']['results'][0]['evidence_available']=='YES'


def test_evidence_backed_failure_visible_in_canonical_report_without_ui(case):
    from src.dynamic.report import build_dynamic_analysis_report, validate_dynamic_analysis_report
    backend,request,context,execution,_=perform(case,200,{'function':'training_toggle','applied':True,'enabled':True,'revision':2},True)
    result=backend.validate(request,execution)
    sources={'session':{'session_id':request.session_id,'status':'COMPLETED'},
        'endpoint_contexts':case[4].to_dict(),'api_correlation':case[5].to_dict(),
        'security_results':security_result_artifact(request,execution,backend.evidence,backend.bundle,result)}
    with patch('socket.socket') as socket:
        report=build_dynamic_analysis_report('controlled_failure',sources)
    socket.assert_not_called();validate_dynamic_analysis_report(report)
    assert report['security_results']['results'][0]['reason_codes']==['FUNCTION_AUTHORIZATION_NOT_ENFORCED']
    assert report['security_results']['results'][0]['finding_created'] is False
    assert report['analysis_coverage']=='partial' and report['coverage']['ui_exploration']=='unavailable'


def test_missing_state_prevents_success_promotion_and_recorded_inconclusive_stays_visible(case):
    backend,request,context,execution,_=perform(case,200,{'function':'training_toggle','applied':True,'enabled':True,'revision':2},True)
    bundle=deepcopy(backend.bundle);bundle.variant_receipts[-1].pop('state_after')
    assert validate_function_authorization(request,execution,backend.evidence,bundle).reason_codes==('MISSING_STATE_EVIDENCE',)
    result=backend.validate(request,execution)
    conservative=replace(result,outcome='inconclusive',criterion='insufficient_evidence',coverage='partial',reason_codes=('INSUFFICIENT_RESPONSE_COMPARISON',))
    artifact=security_result_artifact(request,execution,backend.evidence,backend.bundle,conservative)
    assert build_security_section(artifact,request.session_id,[context.to_dict()])['results'][0]['validation_outcome']=='inconclusive'


def test_raw_auth_or_unbound_success_rejected(case):
    backend,request,context,execution,_=perform(case)
    bundle=deepcopy(backend.bundle);bundle.variant['request']['headers']['authorization']='Bearer private_secret'
    assert validate_function_authorization(request,execution,backend.evidence,bundle).reason_codes==('UNREDACTED_EVIDENCE',)
    result=backend.validate(request,execution)
    section=build_security_section(security_result_artifact(request,execution,backend.evidence,backend.bundle,result),request.session_id,[context.to_dict()])
    section['results'][0]['variant_evidence_refs']['response']=None
    with pytest.raises(ValueError):validate_security_section(section,request.session_id,{context.endpoint_context_id})
