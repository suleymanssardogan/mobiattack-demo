"""Failure recovery at the Agent boundary; no live transports or findings."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from tests.test_agent_security_integration import controlled, run
from tests.context_analyst_fakes import FakeModelClient
from tests.test_planner_fakes import PlannerFake
from src.agent.security_integration.reliability import ExecutionGuard
from src.agent.security_integration import ExecutionBinding
from src.dynamic.security.contracts import EvidenceReference


@pytest.mark.parametrize('role',['analyst','planner'])
@pytest.mark.parametrize('failure,code', [(ConnectionError('SECRET_PROVIDER_MESSAGE'),'PROVIDER_UNAVAILABLE'),
    (TimeoutError('SECRET_PROVIDER_MESSAGE'),'TIMEOUT'),
    (InterruptedError('SECRET_PROVIDER_MESSAGE'),'INTERRUPTED'),(KeyboardInterrupt(),'INTERRUPTED')])
def test_provider_failure_explicit_safe_and_no_retry_execution(controlled,role,failure,code):
    cls=FakeModelClient if role=='analyst' else PlannerFake
    client=cls(error=failure)
    result=run(controlled,**{role+'_client':client})
    controlled[-2].run.assert_not_called()
    assert result.status=='stopped' and not result.executions and not result.artifacts
    assert result.reason_codes==(role.upper()+'_'+code,)
    assert result.agent_state==('unavailable' if role=='analyst' else 'partial')
    assert len(client.requests)==1
    trace=result.to_dict()
    assert trace['public_agent_analysis']=='not_available'
    assert trace['security_report']['coverage']=='unavailable'
    assert not trace['security_report']['results']
    assert 'SECRET_PROVIDER_MESSAGE' not in json.dumps(trace)


@pytest.mark.parametrize('role',['analyst','planner'])
def test_malformed_output_retries_only_twice_and_no_fallback_plan(controlled,role):
    cls=FakeModelClient if role=='analyst' else PlannerFake
    client=cls(transform=lambda data,req:{'finding':True,'tool_args':{},'execute_now':True})
    result=run(controlled,**{role+'_client':client})
    controlled[-2].run.assert_not_called()
    assert len(client.requests)==2
    assert result.status=='stopped' and not result.executions
    assert (result.analyst if role=='analyst' else result.planner).status=='invalid_output'
    assert not (result.planner.proposals if result.planner else ())


def test_unsupported_primitive_rejected_before_policy_dispatch(controlled):
    def unsupported(data,request):
        data['proposals'][0]['test_id']='INPUT_VALIDATION'
        return data
    client=PlannerFake(transform=unsupported)
    result=run(controlled,planner_client=client)
    controlled[-2].run.assert_not_called()
    assert result.planner.status=='invalid_output' and result.policy is None


@pytest.mark.parametrize('role',['analyst','planner'])
@pytest.mark.parametrize('kind',['endpoint','timestamp','reference'])
def test_stale_model_output_never_reaches_executor(controlled,role,kind):
    def stale(data,request):
        if kind=='endpoint':data['endpoint_context_id']='ctx_previous_run'
        elif role=='analyst':
            if kind=='timestamp':data['observation']['created_at']='2020-01-01T00:00:00Z'
            else:data['observation']['evidence_refs'].append('dynamic/traffic.json#transaction_id=tx_previous_session')
        else:
            if kind=='timestamp':data['proposals'][0]['created_at']='2020-01-01T00:00:00Z'
            else:data['proposals'][0]['evidence_refs'].append('dynamic/traffic.json#transaction_id=tx_previous_session')
        return data
    cls=FakeModelClient if role=='analyst' else PlannerFake
    result=run(controlled,**{role+'_client':cls(transform=stale)})
    controlled[-2].run.assert_not_called()
    assert result.status=='stopped' and not result.executions


def test_cross_session_registry_cannot_be_used_for_dispatch(controlled):
    registry={k:replace(v,session_id='previous_session') for k,v in controlled[3].items()}
    result=run(controlled,execution_bindings={'SESSION_HANDLING':ExecutionBinding(controlled[1],registry)})
    controlled[-2].run.assert_not_called()
    assert result.status=='stopped' and not result.executions


def test_missing_policy_evidence_stays_partial_no_execution(controlled):
    result=run(controlled,evidence_index={})
    controlled[-2].run.assert_not_called()
    assert result.policy.needs_evidence_count>0
    assert result.agent_state=='partial' and not result.artifacts


def test_repeated_call_same_executor_cannot_duplicate_dispatch(controlled):
    first=run(controlled);second=run(controlled)
    controlled[-2].run.assert_called_once()
    assert first.executions and not second.executions
    assert 'DUPLICATE_EXECUTION_BLOCKED' in second.reason_codes


def test_timeout_cannot_be_retried_by_restarting_agent_stage(controlled):
    controlled[-2].run.side_effect=TimeoutError()
    first=run(controlled);second=run(controlled)
    controlled[-2].run.assert_called_once()
    assert first.executions[0].execution_status=='failed'
    assert first.security_report['results'][0]['validation_outcome']!='validated'
    assert 'DUPLICATE_EXECUTION_BLOCKED' in second.reason_codes


def test_interrupted_dispatch_does_not_release_claim_or_fabricate_evidence(controlled,monkeypatch):
    executor=controlled[-1]
    def interrupted(*args,**kwargs):raise KeyboardInterrupt()
    monkeypatch.setattr(executor,'execute',interrupted)
    result=run(controlled)
    assert result.reason_codes[-1]=='EXECUTION_INTERRUPTED'
    assert not result.artifacts and not result.executions
    second=run(controlled)
    assert 'DUPLICATE_EXECUTION_BLOCKED' in second.reason_codes


def test_interrupted_model_stage_can_be_explicitly_resumed_once(controlled):
    interrupted=run(controlled,planner_client=PlannerFake(error=KeyboardInterrupt()))
    assert not interrupted.executions
    resumed=run(controlled)
    controlled[-2].run.assert_called_once()
    assert resumed.security_report['results'][0]['validation_outcome']=='validated'


@pytest.mark.parametrize('role',['analyst','planner'])
def test_single_schema_retry_can_recover_without_duplicate_execution(controlled,role):
    calls=[]
    def once(data,request):
        calls.append(request.attempt)
        return {'malformed':True} if request.attempt==1 else data
    cls=FakeModelClient if role=='analyst' else PlannerFake
    result=run(controlled,**{role+'_client':cls(transform=once)})
    controlled[-2].run.assert_called_once()
    assert calls==[1,2]
    assert len(result.executions)==1


def test_execution_claim_is_atomic_and_capacity_fails_closed(controlled):
    guard=ExecutionGuard(max_claims=1);request=controlled[1]
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes=list(pool.map(lambda _:guard.claim(request),range(16)))
    assert outcomes.count(None)==1
    assert outcomes.count('DUPLICATE_EXECUTION_BLOCKED')==15
    assert guard.claim(replace(request,session_id='next_session'))=='EXECUTION_GUARD_EXHAUSTED'


def test_failures_preserve_input_evidence_files_and_deterministic_trace(controlled):
    path=Path('examples/session_invalidation_d23/dynamic/security_results.json')
    original=hashlib.sha256(path.read_bytes()).hexdigest()
    before=deepcopy(controlled[:6])
    first=run(controlled,planner_client=PlannerFake(error=ConnectionError('hidden')))
    second=run(controlled,planner_client=PlannerFake(error=ConnectionError('hidden')))
    assert first.to_dict()==second.to_dict()
    assert controlled[:6]==before
    assert hashlib.sha256(path.read_bytes()).hexdigest()==original
    controlled[-2].run.assert_not_called()


def test_unavailable_context_does_not_contact_model_or_execute(controlled):
    from src.agent.security_integration import run_agent_validation
    analyst=FakeModelClient();planner=PlannerFake()
    result=run_agent_validation(None,analyst,planner,evidence_index={})
    assert result.analyst.status=='input_invalid' and result.agent_state=='unavailable'
    assert not analyst.requests and not planner.requests and not result.executions


def test_failed_execution_cannot_claim_available_agent_coverage(controlled):
    def session_only(data,request):
        data['proposals']=[p for p in data['proposals'] if p['test_id']=='SESSION_HANDLING']
        return data
    controlled[-2].run.side_effect=TimeoutError()
    result=run(controlled,planner_client=PlannerFake(transform=session_only))
    assert result.status=='completed' # processing finished, validation did not
    assert result.agent_state=='partial'
    assert result.security_report['results'][0]['finding_created'] is False


def test_real_ollama_timeout_code_is_classified_without_error_text(controlled):
    from src.agent.ollama_model_client import OllamaClientError
    result=run(controlled,analyst_client=FakeModelClient(error=OllamaClientError('TIMEOUT')))
    assert result.reason_codes==('ANALYST_TIMEOUT',)
    controlled[-2].run.assert_not_called()
