from copy import deepcopy
from unittest.mock import Mock, patch

import pytest

from src.dynamic.context.models import EndpointContext
from src.dynamic.security import DeterministicSecurityExecutor
from src.dynamic.security.contracts import (
    ACTIONS, DynamicTestRequest, DynamicTestExecutionResult, EvidenceReference,
)

START = '2026-10-02T12:00:00+00:00'
FINISH = '2026-10-02T12:00:01+00:00'
CTX = EndpointContext('ctx_orders', 'api.example.com', '/orders/{id}')
EVIDENCE = {'baseline': EvidenceReference('baseline', 'ctx_orders', 'context', 'session_1')}


def payload(**changes):
    data = dict(test_id='PARAMETER_CONSISTENCY', endpoint_context_id='ctx_orders',
                test_category='parameter_consistency', purpose='Evaluate controlled object behavior',
                required_evidence_refs=['baseline'], requested_action='validate_parameter_consistency',
                risk_class='low', session_id='session_1')
    data.update(changes)
    return data


def executor():
    return DeterministicSecurityExecutor(clock=Mock(side_effect=[START, FINISH]))


def run(data=None, **options):
    return executor().execute(data or payload(), CTX, EVIDENCE, session_id='session_1', **options)


@pytest.mark.parametrize('risk', ['passive', 'low'])
def test_passive_and_low_reach_dispatch_without_live_backend(risk):
    runner = executor()
    with patch.object(runner, '_dispatch', wraps=runner._dispatch) as dispatch:
        result = runner.execute(payload(risk_class=risk), CTX, EVIDENCE, session_id='session_1')
    dispatch.assert_called_once()
    assert result.execution_status == 'unavailable'
    assert result.failure_reason == 'security_backend_unavailable'
    assert result.observed_request_ref is None and result.observed_response_ref is None
    assert result.evidence_refs == result.tool_refs == ()


@pytest.mark.parametrize('risk', ['medium', 'high', 'destructive'])
def test_higher_risks_never_dispatch(risk):
    runner = executor()
    with patch.object(runner, '_dispatch') as dispatch:
        result = runner.execute(payload(risk_class=risk), CTX, EVIDENCE, session_id='session_1')
    dispatch.assert_not_called()
    assert result.execution_status == 'blocked'
    assert result.failure_reason == 'risk_not_automatically_executable'
    assert not result.evidence_refs and not result.tool_refs


@pytest.mark.parametrize('changes,reason', [
    ({'requested_action': 'not_supported'}, 'unsupported_action'),
    ({'requested_action': 'GET /orders/2'}, 'unsupported_action'),
    ({'requested_action': 'curl https://example.com/'}, 'unsupported_action'),
    ({'test_category': 'unknown_category'}, 'unsupported_category'),
    ({'requested_action': 'validate_session_dependency'}, 'unsupported_action')])
def test_unsupported_routing_blocked_without_weakening_contract(changes,reason):
    data=payload(**changes)
    with pytest.raises(ValueError):
        DynamicTestRequest.from_dict(data)
    runner=executor()
    with patch.object(runner,'_dispatch') as dispatch:
        result=runner.execute(data,CTX,EVIDENCE,session_id='session_1')
    dispatch.assert_not_called()
    assert result.execution_status=='blocked' and result.failure_reason==reason
    assert result.test_id==data['test_id'] and result.session_id=='session_1'


@pytest.mark.parametrize('changes', [
    {'required_evidence_refs':[]}, {'required_evidence_refs':['fake']},
    {'endpoint_context_id':'invalid'}, {'endpoint_context_id':'ctx_other'},
    {'session_id':'other_session'}, {'risk_class':'invalid'}, {'requested_action':{'payload':'raw'}},
    {'test_id':'bad/id'}, {'purpose':'password=secret'}, {'raw_request':'GET /orders/2'},
    {'schema_version':'2.0'}, {'headers':{'Authorization':'secret'}}])
def test_malformed_or_ungrounded_request_is_validation_failure(changes):
    runner=executor()
    with patch.object(runner,'_dispatch') as dispatch:
        with pytest.raises(ValueError):
            runner.execute(payload(**changes),CTX,EVIDENCE,session_id='session_1')
    dispatch.assert_not_called()
    runner._clock.assert_not_called()


def test_unsupported_routing_does_not_hide_malformed_envelope():
    with pytest.raises(ValueError):
        run(payload(test_category='unknown',required_evidence_refs=[]))
    with pytest.raises(ValueError):
        run(payload(requested_action='unknown',purpose='password=secret'))
    with pytest.raises(ValueError):
        run(payload(requested_action='unknown',required_evidence_refs=['fake']))


@pytest.mark.parametrize('record', [
    EvidenceReference('baseline','ctx_other','context','session_1'),
    EvidenceReference('baseline','ctx_orders','context','other_session'),
    EvidenceReference('baseline','ctx_orders','context',None),
    EvidenceReference('wrong_key','ctx_orders','context','session_1'),
    {'ref':'baseline'}])
def test_cross_endpoint_or_session_evidence_rejected(record):
    with pytest.raises(ValueError):
        executor().execute(payload(),CTX,{'baseline':record},session_id='session_1')


def test_session_owner_must_be_independent_and_explicit():
    for session in (None,'other_session'):
        with pytest.raises(ValueError):
            executor().execute(payload(),CTX,EVIDENCE,session_id=session)


def test_unscoped_request_allowed_only_with_unscoped_evidence():
    evidence={'baseline':EvidenceReference('baseline','ctx_orders','context')}
    result=executor().execute(payload(session_id=None),CTX,evidence)
    assert result.execution_status=='unavailable' and result.session_id is None
    with pytest.raises(ValueError):
        executor().execute(payload(session_id=None),CTX,evidence,session_id='session_1')


@pytest.mark.parametrize('error,status,reason', [
    (TimeoutError('password=secret'), 'failed','execution_timeout'),
    (InterruptedError('raw token'), 'interrupted','execution_interrupted'),
    (KeyboardInterrupt(), 'interrupted','execution_interrupted'),
    (RuntimeError('cookie=secret'), 'failed','execution_failed')])
def test_failure_never_becomes_success_or_fake_evidence(error,status,reason):
    runner=executor()
    with patch.object(runner,'_dispatch',side_effect=error):
        result=runner.execute(payload(),CTX,EVIDENCE,session_id='session_1')
    assert result.execution_status==status and result.failure_reason==reason
    assert not result.evidence_refs and not result.tool_refs
    assert result.observed_request_ref is None and result.observed_response_ref is None
    assert 'secret' not in str(result.to_dict())


@pytest.mark.parametrize('output', [{'status':'completed','response':200}, 'fake success', True])
def test_arbitrary_backend_output_cannot_synthesize_success(output):
    runner=executor()
    with patch.object(runner,'_dispatch',return_value=output):
        result=runner.execute(payload(),CTX,EVIDENCE,session_id='session_1')
    assert result.execution_status=='failed' and result.failure_reason=='unexpected_backend_output'
    assert result.evidence_refs==()


def test_even_valid_baseline_evidence_cannot_be_promoted_to_new_execution():
    evidence={**EVIDENCE,'req_1':EvidenceReference('req_1','ctx_orders','request','session_1'),
              'resp_1':EvidenceReference('resp_1','ctx_orders','response','session_1')}
    fake=DynamicTestExecutionResult(test_id='PARAMETER_CONSISTENCY',endpoint_context_id='ctx_orders',
         execution_status='completed',observed_request_ref='req_1',observed_response_ref='resp_1',
         evidence_refs=('req_1','resp_1'),tool_refs=(),started_at=START,finished_at=FINISH,session_id='session_1')
    runner=executor()
    with patch.object(runner,'_dispatch',return_value=fake):
        result=runner.execute(payload(),CTX,evidence,session_id='session_1')
    assert result.execution_status=='failed' and result.evidence_refs==()


def test_deterministic_timestamps_identity_and_input_preservation():
    data=payload()
    before=deepcopy(data)
    evidence=dict(EVIDENCE)
    result=run(data)
    assert result==run(data)
    assert result.started_at==START and result.finished_at==FINISH
    assert (result.test_id,result.endpoint_context_id,result.session_id)==(data['test_id'],'ctx_orders','session_1')
    assert data==before and EVIDENCE==evidence
    assert DynamicTestExecutionResult.from_dict(result.to_dict())==result


def test_wall_clock_rollback_cannot_invert_timestamps():
    runner=DeterministicSecurityExecutor(clock=Mock(side_effect=[FINISH,START]))
    result=runner.execute(payload(),CTX,EVIDENCE,session_id='session_1')
    assert result.finished_at==result.started_at==FINISH


@pytest.mark.parametrize('category', list(ACTIONS))
def test_all_canonical_actions_remain_unimplemented_and_do_not_send_requests(category):
    with patch('socket.socket') as socket_call, patch('subprocess.run') as subprocess_call:
        for action in ACTIONS[category]:
            result=run(payload(test_category=category,requested_action=action))
            assert result.execution_status == ('blocked' if category in {'object_authorization','function_authorization','session_handling'} else 'unavailable')
            assert not set(result.to_dict()) & {'finding','severity','poc','is_vulnerable'}
    socket_call.assert_not_called()
    subprocess_call.assert_not_called()


def test_typed_objects_revalidated_at_boundary():
    req=DynamicTestRequest.from_dict(payload())
    object.__setattr__(req,'risk_class','destructive')
    result=run(req)
    assert result.execution_status=='blocked'
    object.__setattr__(req,'required_evidence_refs',())
    with pytest.raises(ValueError):
        run(req)


def test_no_fabricated_result_for_invalid_input_type_or_missing_fields():
    with pytest.raises(ValueError):
        executor().execute('invalid',CTX,EVIDENCE)
    with pytest.raises(ValueError):
        executor().execute({'test_id':'test_1'},CTX,EVIDENCE)
    with pytest.raises(ValueError):
        executor().execute(payload(),CTX,[],session_id='session_1')
