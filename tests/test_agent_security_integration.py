"""Bounded offline orchestration: real gates/validators, stub model/transport."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.agent.security_integration import ExecutionBinding, run_agent_validation
from src.agent.policy import EvidenceRecord, PreconditionRecord
from src.agent.context_analyst import analyze_endpoint_context
from src.agent.test_planner import plan_endpoint_tests
from src.dynamic.context.models import EndpointContext
from src.dynamic.security.contracts import DynamicTestRequest, DynamicTestExecutionResult, EvidenceReference
from src.dynamic.security.executor import DeterministicSecurityExecutor
from src.dynamic.security.session_invalidation import LocalLabSessionInvalidation, SessionInvalidationEvidence
from src.dynamic.traffic.normalizer import sanitize_transaction_data
from tests.context_analyst_fakes import FakeModelClient, TIME
from tests.test_planner_fakes import PlannerFake
from tests.test_context_analyst_input import endpoint


@pytest.fixture
def controlled():
    row=json.loads(Path('examples/session_invalidation_d23/dynamic/security_results.json').read_text())['records'][0]
    data=deepcopy(row['evidence']);context=EndpointContext(**data['context'])
    # Synthetic bearer-presence metadata for planning, not a new live observation.
    context.auth['bearer_token_present']=True
    context.auth['request_auth_states']=['present']
    context.auth['authenticated_state']='unknown'
    data['context']=context
    for name in ('baseline','variant','logout'):data[name]=sanitize_transaction_data(data[name])
    proof=SessionInvalidationEvidence(**data)
    request=DynamicTestRequest.from_dict(row['request'])
    execution=DynamicTestExecutionResult.from_dict(row['execution'])
    registry={k:EvidenceReference(**v) for k,v in row['registry'].items()}
    refs=[('dynamic/endpoint_contexts.json#endpoint_context_id='+context.endpoint_context_id,'endpoint_context')]
    refs += [('dynamic/traffic.json#transaction_id='+tx,'traffic_transaction') for tx in context.evidence_refs['transaction_ids']]
    index={ref:EvidenceRecord(ref,context.endpoint_context_id,kind) for ref,kind in refs}
    # No socket/server is created. Only transport dispatch is doubled.
    backend=object.__new__(LocalLabSessionInvalidation)
    backend.eligible=Mock(return_value=True)
    backend.run=Mock(return_value=execution)
    backend.evidence=registry;backend.bundle=proof
    executor=DeterministicSecurityExecutor(session_backend=backend)
    analyst=analyze_endpoint_context(context,FakeModelClient(),created_at=TIME)
    planner=plan_endpoint_tests(context,analyst,PlannerFake(),catalog_test_ids=['AUTHENTICATION_PRESENCE','OBJECT_AUTHORIZATION','FUNCTION_AUTHORIZATION','SESSION_HANDLING'],created_at=TIME)
    assert planner.status=='completed'
    prereqs={key:PreconditionRecord(key,context.endpoint_context_id,tuple(index))
             for p in planner.proposals for key in p.required_context if key!='auth'}
    return context,request,execution,registry,index,prereqs,backend,executor


def run(controlled,**overrides):
    c,r,e,registry,index,prereqs,backend,executor=controlled
    kwargs=dict(evidence_index=index,precondition_index=prereqs,
        execution_bindings={'SESSION_HANDLING':ExecutionBinding(r,registry)},
        executor=executor,session_id=r.session_id,controlled_lab=True,created_at=TIME)
    kwargs.update(overrides)
    analyst_client=kwargs.pop('analyst_client',FakeModelClient())
    planner_client=kwargs.pop('planner_client',PlannerFake())
    with patch('socket.socket') as socket,patch('subprocess.run') as process:
        result=run_agent_validation(c,analyst_client,planner_client,**kwargs)
    socket.assert_not_called();process.assert_not_called()
    return result


def test_complete_pipeline_real_policy_executor_validator_report(controlled):
    result=run(controlled)
    assert result.analyst.status==result.planner.status=='completed'
    assert all(p.test_id in {'AUTHENTICATION_PRESENCE','OBJECT_AUTHORIZATION','FUNCTION_AUTHORIZATION','SESSION_HANDLING'} for p in result.planner.proposals)
    assert result.policy.allow_count>=1
    controlled[-2].run.assert_called_once()
    assert len(result.executions)==len(result.artifacts)==1
    row=result.security_report['results'][0]
    assert row['validation_outcome']=='validated'
    assert row['reason_codes']==['SESSION_INVALIDATION_ENFORCED']
    assert row['finding_created'] is False


@pytest.mark.parametrize('defect',['missing_refs','missing_preconditions','public','not_opted_in','backend_missing','binding_missing','cross_session','risk','action','test'])
def test_no_dispatch_when_any_authority_boundary_fails(controlled,defect):
    c,r,e,registry,index,prereqs,backend,executor=controlled
    overrides={}
    if defect=='missing_refs':overrides['evidence_index']={}
    elif defect=='missing_preconditions':overrides['precondition_index']={}
    elif defect=='public':c.host='api.example.com'
    elif defect=='not_opted_in':overrides['controlled_lab']=False
    elif defect=='backend_missing':overrides['executor']=None
    elif defect=='binding_missing':overrides['execution_bindings']={}
    else:
        changes={'cross_session':{'session_id':'other_session'},'risk':{'risk_class':'passive'},
            'action':{'requested_action':'compare_authenticated_baseline_behavior','test_category':'authentication_presence'},
            'test':{'test_id':'UNSUPPORTED_TEST'}}
        overrides['execution_bindings']={'SESSION_HANDLING':ExecutionBinding(replace(r,**changes[defect]),registry)}
    result=run(controlled,**overrides)
    backend.run.assert_not_called()
    assert not result.executions and not result.artifacts


@pytest.mark.parametrize('role',['analyst','planner'])
@pytest.mark.parametrize('mode',['error','malformed'])
def test_unavailable_or_malformed_agent_never_dispatches(controlled,role,mode):
    client_type=FakeModelClient if role=='analyst' else PlannerFake
    client=client_type(error=RuntimeError('private provider error')) if mode=='error' else client_type(transform=lambda data,request:{'finding':True,'execute_now':True})
    result=run(controlled,**{role+'_client':client})
    controlled[-2].run.assert_not_called()
    assert result.status=='stopped' and not result.artifacts
    assert len(client.requests)<=2
    assert 'private provider error' not in repr(result)


@pytest.mark.parametrize('defect',['synthetic','missing','cross_session'])
def test_completed_executor_cannot_override_evidence_validator(controlled,defect):
    backend=controlled[-2]
    if defect=='synthetic':backend.bundle.variant['response']['synthetic']=True
    elif defect=='missing':backend.bundle=replace(backend.bundle,variant=None)
    else:backend.bundle.variant['session_id']='other_session'
    result=run(controlled)
    backend.run.assert_called_once()
    if result.security_report['results']:
        assert result.security_report['results'][0]['validation_outcome'] in {'blocked','inconclusive'}
        assert result.security_report['results'][0]['finding_created'] is False
    else:
        assert 'EXECUTION_OR_EVIDENCE_REJECTED' in result.reason_codes
        assert result.security_report['coverage']=='unavailable'


def test_unknown_auth_remains_unknown_and_no_plan_forced(controlled):
    c=controlled[0];c.auth={key:None for key in ('authorization_header_present','bearer_token_present','cookie_present','session_cookie_present','api_key_header_present')}
    result=run(controlled)
    controlled[-2].run.assert_not_called()
    assert result.status=='no_relevant_tests'


def test_model_receives_only_sanitized_metadata_and_four_test_families(controlled):
    c=controlled[0];c.request['body']={'password':'SECRET_MARKER'};c.auth['raw_token']='SECRET_MARKER'
    analyst_client=FakeModelClient();planner_client=PlannerFake()
    result=run(controlled,analyst_client=analyst_client,planner_client=planner_client)
    for request in analyst_client.requests+planner_client.requests:
        assert 'SECRET_MARKER' not in json.dumps(request.input_data)
    assert {t['test_id'] for t in planner_client.requests[0].input_data['available_tests']}<=set(['AUTHENTICATION_PRESENCE','OBJECT_AUTHORIZATION','FUNCTION_AUTHORIZATION','SESSION_HANDLING'])
    assert 'SECRET_MARKER' not in json.dumps(result.security_report)


def test_executor_failure_stays_visible_without_fake_transactions(controlled):
    controlled[-2].run.side_effect=TimeoutError()
    result=run(controlled)
    assert result.executions[0].execution_status=='failed'
    row=result.security_report['results'][0]
    assert row['validation_outcome']!='validated' and row['finding_created'] is False
    assert row['variant_evidence_refs']=={'request':None,'response':None}


def test_passive_auth_review_never_upgraded_to_active_auth_removal(controlled):
    c,r,e,registry,index,prereqs,backend,executor=controlled
    auth=replace(r,test_id='AUTHENTICATION_PRESENCE',test_category='authentication_presence',
                 requested_action='validate_authentication_presence')
    result=run(controlled,execution_bindings={'AUTHENTICATION_PRESENCE':ExecutionBinding(auth,registry)})
    backend.run.assert_not_called()
    assert 'EXECUTION_BINDING_MISMATCH' in result.reason_codes
    assert not result.executions


def test_medium_object_proposal_remains_policy_denied(controlled):
    c=controlled[0];c.request['query_keys']=['order_id']
    result=run(controlled)
    proposals={p.test_id:p for p in result.planner.proposals}
    assert 'OBJECT_AUTHORIZATION' in proposals
    decisions={d.test_id:d for d in result.policy.decisions}
    assert decisions['OBJECT_AUTHORIZATION'].decision=='deny'
    assert decisions['OBJECT_AUTHORIZATION'].reason_code=='RISK_NOT_ALLOWED'


def test_invalid_dynamic_registry_stops_without_transport(controlled):
    binding=ExecutionBinding(controlled[1],{})
    result=run(controlled,execution_bindings={'SESSION_HANDLING':binding})
    controlled[-2].run.assert_not_called()
    assert 'EXECUTION_OR_EVIDENCE_REJECTED' in result.reason_codes


def test_session_safety_gate_remains_authoritative_after_agent_allow(controlled):
    controlled[-2].eligible.return_value=False
    result=run(controlled)
    controlled[-2].run.assert_not_called()
    assert result.policy.allow_count>=1
    assert result.executions[0].execution_status=='blocked'
    assert result.security_report['results'][0]['validation_outcome']!='validated'
