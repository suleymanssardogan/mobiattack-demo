from dataclasses import replace
from unittest.mock import patch

import pytest

from src.dynamic.context.models import EndpointContext
from src.dynamic.security.contracts import (
    ACTIONS, DynamicTestRequest, DynamicTestExecutionResult, DynamicValidationResult,
    EvidenceReference, check_request_safety, validate_execution, validate_result,
)

CTX = EndpointContext('ctx_orders', 'api.example.com', '/orders/{id}')
START = '2026-10-02T12:00:00+00:00'
END = '2026-10-02T12:00:01+00:00'
REGISTRY = {ref: EvidenceReference(ref, CTX.endpoint_context_id, kind, 'session_1')
            for ref, kind in [('ctx_evidence','context'), ('req_1','request'), ('resp_1','response'),
                              ('tool_1','tool'), ('control_1','control'), ('compare_1','comparison')]}


def request(**kw):
    values=dict(test_id='OBJECT_AUTHORIZATION', endpoint_context_id='ctx_orders',
                test_category='object_authorization', purpose='Evaluate controlled object access behavior',
                required_evidence_refs=('ctx_evidence',), requested_action='validate_object_access_behavior',
                risk_class='low', session_id='session_1')
    values.update(kw)
    return DynamicTestRequest(**values)


def execution(**kw):
    values=dict(test_id='OBJECT_AUTHORIZATION', endpoint_context_id='ctx_orders',
                execution_status='completed', observed_request_ref='req_1', observed_response_ref='resp_1',
                evidence_refs=('req_1','resp_1'), tool_refs=('tool_1',), started_at=START,
                finished_at=END, session_id='session_1')
    values.update(kw)
    return DynamicTestExecutionResult(**values)


def result(**kw):
    values=dict(test_id='OBJECT_AUTHORIZATION', endpoint_context_id='ctx_orders', outcome='validated',
                evidence_refs=('req_1','resp_1','control_1','compare_1'), criterion='controlled_behavior_check',
                coverage='available', created_at=END, session_id='session_1')
    values.update(kw)
    return DynamicValidationResult(**values)


def test_valid_contract_chain_roundtrips_without_execution():
    req,exe,res=request(),execution(),result()
    for model in (req,exe,res):
        assert type(model).from_dict(model.to_dict())==model
    assert check_request_safety(req,CTX,REGISTRY)['decision']=='eligible_for_future_policy_review'
    validate_execution(req,exe,REGISTRY)
    validate_result(req,exe,res,REGISTRY)


@pytest.mark.parametrize('category', list(ACTIONS))
def test_only_initial_categories_and_abstract_actions(category):
    req=request(test_category=category,requested_action=sorted(ACTIONS[category])[0])
    assert req.test_category==category


@pytest.mark.parametrize('changes', [
    {'required_evidence_refs':()}, {'required_evidence_refs':('',)}, {'endpoint_context_id':'bad_context'},
    {'endpoint_context_id':'ctx_'}, {'test_category':'arbitrary_attack'}, {'risk_class':'safe'},
    {'requested_action':'GET /orders/2'}, {'requested_action':'curl https://example.com'},
    {'requested_action':'change user_id to 123'}, {'requested_action':{'body':'payload'}},
    {'purpose':'POST /orders/2'}, {'purpose':'password=secret-value'}, {'purpose':''}])
def test_invalid_request_rejected(changes):
    with pytest.raises((ValueError,TypeError)):
        request(**changes)


@pytest.mark.parametrize('risk', ['passive','low','medium','high','destructive'])
def test_risk_boundary_never_approves_or_executes(risk):
    with patch('subprocess.run') as subprocess_call:
        decision=check_request_safety(request(risk_class=risk),CTX,REGISTRY)
    subprocess_call.assert_not_called()
    assert not decision['automatic_execution_allowed']
    assert decision['policy_version']=='dynamic_security_v1'
    assert decision['decision']==('eligible_for_future_policy_review' if risk in {'passive','low'} else 'blocked')


@pytest.mark.parametrize('which', ['endpoint','session','missing','malformed_record'])
def test_request_reference_integrity(which):
    registry=dict(REGISTRY)
    if which=='endpoint': registry['ctx_evidence']=EvidenceReference('ctx_evidence','ctx_other','context','session_1')
    if which=='session': registry['ctx_evidence']=EvidenceReference('ctx_evidence','ctx_orders','context','other_session')
    if which=='missing': registry.pop('ctx_evidence')
    if which=='malformed_record': registry['ctx_evidence']={'ref':'ctx_evidence'}
    with pytest.raises(ValueError):
        check_request_safety(request(),CTX,registry)


def test_wrong_endpoint_context_rejected():
    with pytest.raises(ValueError):
        check_request_safety(request(),replace(CTX,endpoint_context_id='ctx_other'),REGISTRY)


@pytest.mark.parametrize('changes', [
    {'evidence_refs':()}, {'observed_request_ref':None}, {'observed_response_ref':None},
    {'execution_status':'secure'}, {'finished_at':'2026-10-02T11:00:00+00:00'},
    {'started_at':'invalid'}, {'failure_reason':'unexpected_failure'}])
def test_execution_without_observation_or_invalid_status_rejected(changes):
    with pytest.raises(ValueError):
        execution(**changes)


@pytest.mark.parametrize('status', ['failed','blocked','unavailable','interrupted'])
def test_noncompleted_execution_preserves_failure_without_claiming_security(status):
    exe=execution(execution_status=status,observed_request_ref=None,observed_response_ref=None,
                  evidence_refs=(),tool_refs=(),failure_reason='coverage_unavailable')
    validate_execution(request(),exe,REGISTRY)
    inconclusive=result(outcome='inconclusive',criterion='insufficient_evidence',coverage='unavailable',
                        evidence_refs=('ctx_evidence',))
    validate_result(request(),exe,inconclusive,REGISTRY)
    with pytest.raises(ValueError):
        validate_result(request(),exe,result(),REGISTRY)


@pytest.mark.parametrize('field,value', [('test_id','OTHER'),('endpoint_context_id','ctx_other'),
                                        ('session_id','other'),('tool_refs',('req_1',))])
def test_execution_identity_and_tool_kind_rejected(field,value):
    with pytest.raises(ValueError):
        validate_execution(request(),execution(**{field:value}),REGISTRY)


def test_execution_hallucinated_reference_and_wrong_observation_kind_rejected():
    with pytest.raises(ValueError):
        validate_execution(request(),execution(tool_refs=('fake_tool',)),REGISTRY)
    registry=dict(REGISTRY)
    registry['resp_1']=EvidenceReference('resp_1','ctx_orders','tool','session_1')
    with pytest.raises(ValueError):
        validate_execution(request(),execution(),registry)


@pytest.mark.parametrize('changes', [
    {'evidence_refs':()}, {'outcome':'secure'}, {'outcome':'vulnerable'},
    {'coverage':'partial'}, {'coverage':'unavailable'}, {'coverage':'unknown'},
    {'criterion':'changed_response'}, {'criterion':'tool_said_vulnerable'}])
def test_validation_without_evidence_or_based_on_incomplete_coverage_rejected(changes):
    with pytest.raises(ValueError):
        result(**changes)


@pytest.mark.parametrize('refs', [('tool_1',),('req_1','resp_1'),('resp_1','compare_1'),
                                  ('req_1','resp_1','control_1'),('fake',)])
def test_changed_response_and_tool_output_alone_never_validate(refs):
    with pytest.raises(ValueError):
        validate_result(request(),execution(),result(evidence_refs=refs),REGISTRY)


def test_validation_requires_same_execution_observations():
    registry=dict(REGISTRY)
    registry['req_2']=EvidenceReference('req_2','ctx_orders','request','session_1')
    with pytest.raises(ValueError):
        validate_result(request(),execution(),result(evidence_refs=('req_2','resp_1','control_1','compare_1')),registry)


@pytest.mark.parametrize('field,value', [('test_id','OTHER'),('endpoint_context_id','ctx_other'),
                                        ('session_id','other'),('created_at',START)])
def test_validation_identity_and_chronology_rejected(field,value):
    with pytest.raises(ValueError):
        validate_result(request(),execution(),result(**{field:value}),REGISTRY)


def test_blocked_validation_preserves_policy_evidence():
    exe=execution(execution_status='blocked',observed_request_ref=None,observed_response_ref=None,
                  evidence_refs=(),tool_refs=(),failure_reason='policy_blocked')
    res=result(outcome='blocked',criterion='policy_or_execution_blocked',coverage='unavailable',
               evidence_refs=('ctx_evidence',))
    validate_result(request(),exe,res,REGISTRY)


@pytest.mark.parametrize('cls,fixture', [(DynamicTestRequest,request),(DynamicTestExecutionResult,execution),
                                       (DynamicValidationResult,result)])
@pytest.mark.parametrize('field', ['raw_request','payload','headers','password','finding','severity','poc','execute_now'])
def test_forbidden_fields_rejected_by_strict_schema(cls,fixture,field):
    data=fixture().to_dict()
    data[field]='secret_or_claim'
    with pytest.raises(ValueError):
        cls.from_dict(data)


def test_schema_version_missing_fields_and_bounded_refs():
    with pytest.raises(ValueError):
        DynamicTestRequest.from_dict({'schema_version':'2.0'})
    with pytest.raises(ValueError):
        DynamicTestExecutionResult.from_dict({'test_id':'test_1'})
    with pytest.raises(ValueError):
        request(required_evidence_refs=tuple(f'ev_{i}' for i in range(129)))
    req=request(required_evidence_refs=('ctx_evidence','ctx_evidence'))
    assert req.required_evidence_refs==('ctx_evidence',)
