"""A1-Lite selection only; no model/provider, policy decision or execution."""
from copy import deepcopy
import json
from unittest.mock import patch
import pytest

from src.agent.models import ContractError
from src.agent.model_client import ModelReply
from src.agent.policy import PreconditionRecord
from src.agent.context_analyst import build_context_analyst_input
from src.agent.test_planner import select_validation_primitive
from tests.test_context_analyst_input import endpoint


def facts(context,*names):
    ref=build_context_analyst_input(context).evidence_refs['transactions'][0]
    return tuple(PreconditionRecord(name,context.endpoint_context_id,(ref,)) for name in names)


@pytest.mark.parametrize('kind,names',[
    ('authentication_presence',('protected_authenticated_baseline',)),
    ('object_authorization',('protected_authenticated_baseline','two_principal_resource_ownership')),
    ('function_authorization',('proven_role_relationship','privileged_function_baseline')),
    ('session_handling',('authenticated_session','logout_lifecycle'))])
def test_supported_primitive_selected_with_grounded_metadata(endpoint,kind,names):
    before=deepcopy(endpoint)
    result=select_validation_primitive(endpoint,preconditions=facts(endpoint,*names))
    assert result.status=='completed' and result.plan.selected_test_type==kind
    assert result.plan.applicable is True and not result.plan.missing_evidence
    assert result.plan.endpoint_context_id==endpoint.endpoint_context_id
    assert result.plan.reason_code=='APPLICABLE_FOR_PLANNING'
    assert endpoint==before
    assert result==select_validation_primitive(endpoint,preconditions=tuple(reversed(facts(endpoint,*names))))


def test_auth_presence_or_admin_path_alone_does_not_invent_relationships(endpoint):
    endpoint.path='/admin/users/disable'
    assert select_validation_primitive(endpoint).status=='inconclusive'
    for kind in ['authentication_presence','object_authorization','function_authorization','session_handling']:
        result=select_validation_primitive(endpoint,requested_test_type=kind)
        assert result.plan.applicable is False and result.plan.missing_evidence


@pytest.mark.parametrize('change,missing',[
    ('auth_unknown','auth_presence_metadata'),('traffic_unavailable','runtime_baseline'),
    ('capability_missing','validation_capability')])
def test_unknown_and_unavailable_context_remains_missing(endpoint,change,missing):
    metadata=facts(endpoint,'protected_authenticated_baseline');options={}
    if change=='auth_unknown':endpoint.auth={key:None for key in endpoint.auth}
    if change=='traffic_unavailable':options['coverage_metadata']={'traffic_available':False}
    if change=='capability_missing':options['available_primitives']=[]
    result=select_validation_primitive(endpoint,preconditions=metadata,**options)
    assert result.plan.applicable is False and missing in result.plan.missing_evidence


def test_partial_relationship_preserves_missing_baseline(endpoint):
    result=select_validation_primitive(endpoint,preconditions=facts(endpoint,'proven_role_relationship'))
    assert result.plan.selected_test_type=='function_authorization' and not result.plan.applicable
    assert 'privileged_function_baseline' in result.plan.missing_evidence
    result=select_validation_primitive(endpoint,preconditions=facts(endpoint,'logout_lifecycle'))
    assert result.plan.selected_test_type=='session_handling' and not result.plan.applicable
    assert 'authenticated_session' in result.plan.missing_evidence


@pytest.mark.parametrize('kind',['input_validation','parameter_consistency','AI_SMART_HACK'])
def test_unsupported_request_rejected(endpoint,kind):
    with pytest.raises(ContractError,match='UNSUPPORTED_VALIDATION_PRIMITIVE'):
        select_validation_primitive(endpoint,requested_test_type=kind)


@pytest.mark.parametrize('change',['extra_field','wrong_endpoint','override_missing','bad_bool','unsupported_kind','null'])
def test_malformed_or_semantically_invalid_model_output_rejected(endpoint,change):
    expected=select_validation_primitive(endpoint,requested_test_type='authentication_presence').plan.to_dict()
    raw=deepcopy(expected)
    if change=='extra_field':raw['finding']='vulnerable'
    if change=='wrong_endpoint':raw['endpoint_context_id']='ctx_other'
    if change=='override_missing':raw.update(applicable=True,missing_evidence=[],reason_code='APPLICABLE_FOR_PLANNING')
    if change=='bad_bool':raw['applicable']=0
    if change=='unsupported_kind':raw['selected_test_type']='input_validation'
    if change=='null':raw=None
    result=select_validation_primitive(endpoint,requested_test_type='authentication_presence',model_output=ModelReply(raw))
    assert result.status=='invalid_output' and result.plan is None
    assert result.reason_code=='OUTPUT_REJECTED'


def test_existing_model_reply_compatible_but_cannot_supply_evidence(endpoint):
    metadata=facts(endpoint,'protected_authenticated_baseline')
    expected=select_validation_primitive(endpoint,preconditions=metadata).plan.to_dict()
    assert select_validation_primitive(endpoint,preconditions=metadata,model_output=ModelReply(expected)).plan.applicable
    assert select_validation_primitive(endpoint,requested_test_type='authentication_presence',model_output=ModelReply(expected)).status=='invalid_output'


def test_cross_endpoint_or_hallucinated_preconditions_rejected(endpoint):
    ref=build_context_analyst_input(endpoint).evidence_refs['transactions'][0]
    for record in [PreconditionRecord('protected_authenticated_baseline','ctx_other',(ref,)),
                   PreconditionRecord('protected_authenticated_baseline',endpoint.endpoint_context_id,('dynamic/traffic.json#transaction_id=hallucinated',))]:
        result=select_validation_primitive(endpoint,preconditions=(record,))
        assert result.status=='input_invalid' and result.plan is None
    # Plain dictionaries, including model-authored prerequisite claims, are not a trusted resolver input.
    result=select_validation_primitive(endpoint,preconditions=({'name':'protected_authenticated_baseline'},))
    assert result.status=='input_invalid' and result.plan is None


def test_unavailable_has_no_plan_and_no_authority_side_effects(endpoint):
    with patch('socket.socket') as socket, patch('subprocess.run') as process, \
            patch('src.agent.policy.evaluate_proposal') as policy, \
            patch('src.dynamic.security.executor.DeterministicSecurityExecutor.execute') as execute, \
            patch('src.dynamic.security.contracts.validate_result') as validator:
        unavailable=select_validation_primitive(endpoint,agent_available=False)
        selected=select_validation_primitive(endpoint,preconditions=facts(endpoint,'protected_authenticated_baseline'))
        assert unavailable.to_dict()=={'status':'unavailable','reason_code':'AGENT_UNAVAILABLE','plan':None}
        assert selected.plan.applicable
    for call in [socket,process,policy,execute,validator]:call.assert_not_called()
    for data in [unavailable.to_dict(),selected.to_dict()]:
        assert not set(data.get('plan') or {}) & {'finding','severity','execute_now','approved_for_execution','validated','requested_action'}


def test_raw_secrets_and_unrelated_metadata_not_forwarded(endpoint):
    metadata=facts(endpoint,'protected_authenticated_baseline')
    endpoint.request['headers']={'Authorization':'Bearer PRIVATE_TOKEN'}
    endpoint.request['body']={'password':'PRIVATE_PASSWORD'}
    endpoint.response['body']={'refresh_token':'PRIVATE_REFRESH'}
    endpoint.static['source_file']='/Users/private/PRIVATE_PATH.smali'
    text=json.dumps(select_validation_primitive(endpoint,preconditions=metadata).to_dict())
    for secret in ['PRIVATE_TOKEN','PRIVATE_PASSWORD','PRIVATE_REFRESH','PRIVATE_PATH','/Users/private']:
        assert secret not in text
