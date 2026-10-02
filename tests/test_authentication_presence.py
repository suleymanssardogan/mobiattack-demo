from copy import deepcopy
from http.server import HTTPServer
import json
from unittest.mock import Mock, patch

import pytest

from scripts.labs.execute_auth_presence import load_baseline, atomic_json
from src.dynamic.security.authentication_presence import LocalLabAuthenticationPresence, auth_removal_variant
from src.dynamic.security.contracts import DynamicTestRequest, EvidenceReference
from src.dynamic.security.executor import DeterministicSecurityExecutor

BASE = 'examples/auth_lab_d10_2'


def setup_case():
    manifest, context, baseline, session = load_baseline(BASE)
    server = object.__new__(HTTPServer)
    server.server_address = (context.host, 18081)
    records = []
    backend = LocalLabAuthenticationPresence(server=server, receipts=records, baseline=baseline, context=context, session_id=session['session_id'])
    registry = {ref: EvidenceReference(ref, context.endpoint_context_id, kind, session['session_id']) for ref,kind in [
        (manifest['protected_request_ref'], 'request'), (manifest['protected_response_ref'], 'response'),
        (context.endpoint_context_id, 'context'), (session['session_id'], 'runtime')]}
    request = DynamicTestRequest('AUTHENTICATION_PRESENCE', context.endpoint_context_id, 'authentication_presence',
                                'Evaluate expected lab authentication enforcement', tuple(registry), 'validate_authentication_presence', 'low', session['session_id'])
    return backend, request, context, registry, records


def mock_response(backend, records, status=401, body=None, receipt=True):
    if body is None: body = {'error':'authentication_required'}
    trace = 'lab_test_variant'
    connection = Mock()
    response = connection.getresponse.return_value
    response.status = status
    response.read.return_value = json.dumps(body).encode()
    response.getheaders.return_value = [('Content-Type','application/json'), ('X-Lab-Trace-ID',trace)]
    if receipt:
        records.append({'trace_id':trace, 'run_id':backend.session_id, 'method':'GET', 'path':'/profile',
                        'status':status, 'auth_present':False, 'auth_valid':False, 'source':'local_training_backend_actual_response'})
    return connection


def execute_case(backend, request, context, registry, connection):
    with patch('src.dynamic.security.authentication_presence.HTTPConnection', return_value=connection) as transport:
        result = DeterministicSecurityExecutor(auth_backend=backend).execute(request, context, registry, session_id=request.session_id)
    return result, transport


def test_baseline_refs_are_validated_against_actual_artifacts():
    m,c,b,s = load_baseline(BASE)
    assert c.endpoint_context_id == m['endpoint_context_id']
    assert b['response']['status_code'] == 200
    assert b['request']['headers']['authorization'] == '[REDACTED]'
    assert b['session_id'] == s['session_id']


def test_only_auth_is_removed_without_changing_input():
    _,_,baseline,_ = load_baseline(BASE)
    original = deepcopy(baseline)
    variant = auth_removal_variant(baseline)
    assert baseline == original
    expected = deepcopy(baseline['request'])
    del expected['headers']['authorization']
    assert variant == expected


@pytest.mark.parametrize('key,value', [('method','POST'),('path','/account'),('scheme','https'),('port',8080),('query',{'id':'1'}),('body',{'id':'1'})])
def test_no_other_request_mutations_supported(key,value):
    _,_,baseline,_ = load_baseline(BASE)
    baseline['request'][key] = value
    with pytest.raises(ValueError): auth_removal_variant(baseline)


@pytest.mark.parametrize('headers', [{}, {'cookie':'[REDACTED]','authorization':'[REDACTED]'}, {'Authorization':'a','authorization':'b'}, {'authorization':'x','other':'[REDACTED]'}, {'authorization':'x','other':'a\r\nb'}, {'authorization':'x','x-api-key':'secret'}])
def test_ambiguous_or_unreconstructable_auth_rejected(headers):
    _,_,baseline,_ = load_baseline(BASE)
    baseline['request']['headers'] = headers
    with pytest.raises(ValueError): auth_removal_variant(baseline)


def test_expected_enforcement_real_receipt_and_complete_evidence():
    backend,request,context,registry,records = setup_case()
    connection = mock_response(backend,records)
    original = deepcopy(registry)
    result,transport = execute_case(backend,request,context,registry,connection)
    assert result.execution_status == 'completed'
    validation = backend.validate(request,result)
    assert validation.outcome == 'validated'
    assert backend.comparison['expected_auth_enforcement_observed']
    assert not backend.comparison['finding_generated']
    assert set(request.required_evidence_refs).issubset(validation.evidence_refs)
    assert result.observed_request_ref in validation.evidence_refs
    assert result.observed_response_ref in validation.evidence_refs
    assert backend.execution_ref in validation.evidence_refs
    assert registry == original
    transport.assert_called_once_with(context.host,18081,timeout=3)
    connection.putrequest.assert_called_once_with('GET','/profile',skip_host=True,skip_accept_encoding=True)
    assert dict((call.args for call in connection.putheader.call_args_list)) == backend.variant_request['headers']
    assert backend.comparison['historical_baseline'] and not backend.comparison['authenticated_session_currently_reverified']


@pytest.mark.parametrize('status,body', [(200,{'authenticated':True,'profile':{'display_name':'Training User'}}), (200,{'ok':True}), (302,{}), (500,{'error':'server_failure'}), (401,{'error':'other'})])
def test_200_or_difference_alone_never_validates(status,body):
    backend,request,context,registry,records = setup_case()
    result,_ = execute_case(backend,request,context,registry,mock_response(backend,records,status,body))
    assert result.execution_status == 'completed'
    assert backend.validate(request,result).outcome == 'inconclusive'
    assert not backend.comparison['status_200_alone_sufficient']


def test_missing_actual_server_receipt_cannot_complete():
    backend,request,context,registry,records = setup_case()
    result,_ = execute_case(backend,request,context,registry,mock_response(backend,records,receipt=False))
    assert result.execution_status == 'failed'
    assert result.observed_response_ref is None and not result.evidence_refs
    with pytest.raises(ValueError): backend.validate(request,result)


@pytest.mark.parametrize('failure,status', [(TimeoutError('secret'),'failed'), (ConnectionRefusedError('secret'),'failed'), (InterruptedError('secret'),'interrupted')])
def test_transport_failure_no_fake_evidence_or_raw_errors(failure,status):
    backend,request,context,registry,records = setup_case()
    connection = Mock(); connection.getresponse.side_effect = failure
    result,transport = execute_case(backend,request,context,registry,connection)
    assert result.execution_status == status
    assert result.observed_response_ref is None and not result.evidence_refs
    assert 'secret' not in json.dumps(result.to_dict())
    transport.assert_called_once()
    connection.close.assert_called_once()


def test_single_use_no_retry_after_success():
    backend,request,context,registry,records = setup_case()
    connection = mock_response(backend,records)
    first,_ = execute_case(backend,request,context,registry,connection)
    second,transport = execute_case(backend,request,context,registry,connection)
    assert first.execution_status == 'completed' and second.execution_status == 'failed'
    transport.assert_not_called()


@pytest.mark.parametrize('risk', ['medium','high','destructive'])
def test_risk_boundary_precedes_network(risk):
    backend,request,context,registry,_ = setup_case()
    payload = request.to_dict(); payload['risk_class'] = risk
    with patch('src.dynamic.security.authentication_presence.HTTPConnection') as transport:
        result = DeterministicSecurityExecutor(auth_backend=backend).execute(payload,context,registry,session_id=request.session_id)
    assert result.execution_status == 'blocked'
    transport.assert_not_called()
    assert not backend.used


def test_missing_evidence_and_cross_session_prevent_transport():
    backend,request,context,registry,_ = setup_case()
    with patch('src.dynamic.security.authentication_presence.HTTPConnection') as transport:
        for evidence,owner in [({},request.session_id),(registry,'other_session')]:
            with pytest.raises(ValueError):
                DeterministicSecurityExecutor(auth_backend=backend).execute(request,context,evidence,session_id=owner)
    transport.assert_not_called()


@pytest.mark.parametrize('synthetic_side', ['transaction','request','response'])
def test_synthetic_baseline_excluded(synthetic_side):
    manifest,context,baseline,session = load_baseline(BASE)
    target = baseline if synthetic_side == 'transaction' else baseline[synthetic_side]
    target['synthetic'] = True
    server = object.__new__(HTTPServer); server.server_address=(context.host,18081)
    with pytest.raises(ValueError):
        LocalLabAuthenticationPresence(server=server,receipts=[],baseline=baseline,context=context,session_id=session['session_id'])


def test_secret_not_sent_or_stored_in_variant():
    backend,request,context,registry,records = setup_case()
    backend.baseline['request']['headers']['authorization'] = 'Bearer PRIVATE_TEST_SECRET'
    result,_ = execute_case(backend,request,context,registry,mock_response(backend,records))
    assert result.execution_status == 'completed'
    assert 'PRIVATE_TEST_SECRET' not in json.dumps(backend.transaction.to_dict())
    assert 'authorization' not in backend.transaction.request.headers


def test_atomic_artifact_writer(tmp_path):
    target=tmp_path/'result.json'
    atomic_json(target,{'status':'completed'})
    assert json.loads(target.read_text()) == {'status':'completed'}
    assert len(list(tmp_path.iterdir())) == 1


@pytest.mark.parametrize('mutation', ['variant_header','context_path'])
def test_post_construction_mutation_never_reaches_network(mutation):
    backend,request,context,registry,_ = setup_case()
    if mutation == 'variant_header': backend.variant_request['headers']['authorization']='secret'
    else: context.path='/other'
    result,transport=execute_case(backend,request,context,registry,Mock())
    assert result.execution_status=='failed'
    transport.assert_not_called()


def test_persisted_live_run_has_complete_bound_evidence():
    from pathlib import Path
    from src.dynamic.security.contracts import DynamicTestExecutionResult, DynamicValidationResult, validate_result
    from src.dynamic.context.models import EndpointContext
    root=Path('examples/auth_presence_d10_3')
    if not root.exists(): pytest.skip('Live smoke artifacts not present')
    read=lambda name:json.loads((root/name).read_text())
    request=DynamicTestRequest.from_dict(read('test_request.json'))
    data=read('execution_result.json'); execution_ref=data.pop('evidence_ref')
    execution=DynamicTestExecutionResult.from_dict(data)
    result=DynamicValidationResult.from_dict(read('validation_result.json'))
    registry={k:EvidenceReference(**v) for k,v in read('evidence_registry.json').items()}
    validate_result(request,execution,result,registry)
    assert execution_ref in result.evidence_refs and execution_ref in execution.tool_refs
    baseline=read('baseline_transaction.json'); variant=read('variant_transaction.json')
    context=EndpointContext(**read('endpoint_context.json'))
    assert baseline['session_id']==variant['session_id']==request.session_id==read('session_evidence.json')['session_id']
    assert baseline['request']['request_id'] in result.evidence_refs
    assert baseline['response']['headers']['x-lab-trace-id'] in result.evidence_refs
    assert variant['request']['request_id']==execution.observed_request_ref
    assert variant['response']['headers']['x-lab-trace-id']==execution.observed_response_ref
    assert context.endpoint_context_id in result.evidence_refs and request.session_id in result.evidence_refs
    expected=auth_removal_variant(baseline)
    for key in ('method','scheme','host','port','path','query','headers','body'):
        assert variant['request'][key]==expected[key]
    assert baseline['response']['status_code']==200 and variant['response']['status_code']==401
    receipt=read('lab_receipts.json')
    assert len(receipt)==1 and receipt[0]['trace_id']==execution.observed_response_ref
    assert receipt[0]['auth_present'] is False and receipt[0]['source']=='local_training_backend_actual_response'
    assert read('comparison.json')['expected_auth_enforcement_observed'] is True
    assert read('provenance.json')['session_mode']=='historical_baseline_continuation'
    assert not (root/'agent_report.json').exists()
    for p in root.iterdir():
        if p.is_file():
            text=p.read_text()
            assert 'local_lab_password' not in text and 'local_lab_user' not in text
            assert 'Bearer ' not in text
    assert result.outcome=='validated'
