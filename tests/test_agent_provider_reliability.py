"""Provider failures stop planning without touching evidence or dispatching."""
from io import BytesIO
from unittest.mock import MagicMock,patch
import json
import pytest
from src.agent.model_client import ModelMetadata,ModelReply,ProviderAvailability
from src.agent.ollama_model_client import OllamaModelClient,OllamaClientError
from tests.test_ollama_model_client import mock_reply,request,body
from tests.test_agent_security_integration import controlled,run
from tests.test_context_analyst_input import endpoint
from tests.context_analyst_fakes import FakeModelClient
from tests.test_planner_fakes import PlannerFake

@pytest.mark.parametrize('raw,available,reason',[
    (b'{"models":[{"name":"qwen2.5:7b"}]}',True,'AVAILABLE'),
    (b'{"models":[]}',False,'MODEL_UNAVAILABLE'),
    (b'{"models":[{"name":"other"}]}',False,'MODEL_UNAVAILABLE'),
    (b'[]',False,'MALFORMED_RESPONSE'),(b'',False,'EMPTY_RESPONSE')])
def test_bounded_model_availability_has_no_generation(raw,available,reason):
    c=OllamaModelClient(timeout=30);mock_reply(c,raw)
    result=c.check_availability()
    assert (result.available,result.reason_code)==(available,reason)
    assert result.identity.model=='qwen2.5:7b'
    args,kwargs=c._opener.open.call_args
    assert args[0].full_url.endswith('/api/tags') and args[0].get_method()=='GET'
    assert args[0].data is None and kwargs['timeout']==3

@pytest.mark.parametrize('error,reason',[(TimeoutError('SECRET'),'TIMEOUT'),(ConnectionError('SECRET'),'PROVIDER_UNAVAILABLE')])
def test_availability_transport_error_is_safe(error,reason):
    c=OllamaModelClient();c._opener.open=MagicMock(side_effect=error)
    r=c.check_availability()
    assert not r.available and r.reason_code==reason and 'SECRET' not in str(r)

@pytest.mark.parametrize('role',['analyst','planner'])
@pytest.mark.parametrize('code',['TIMEOUT','MODEL_UNAVAILABLE','MALFORMED_RESPONSE','EMPTY_RESPONSE'])
def test_provider_failure_exact_reason_identity_and_no_execution(controlled,role,code):
    identity=ModelMetadata(provider='local',model='qwen2.5:7b')
    class Broken:
        def __init__(self):self.calls=0
        def generate(self,request):self.calls+=1;raise OllamaClientError(code)
    client=Broken();client.identity=identity
    result=run(controlled,**{role+'_client':client})
    controlled[-2].run.assert_not_called()
    assert result.reason_codes==(role.upper()+'_'+code,)
    assert result.agent_state==('unavailable' if role=='analyst' else 'partial')
    assert (result.analyst if role=='analyst' else result.planner).model_metadata==identity
    assert client.calls==1 and not result.executions and not result.artifacts


def test_missing_model_prevents_chat(controlled):
    c=OllamaModelClient();mock_reply(c,b'{"models":[]}')
    r=run(controlled,analyst_client=c)
    assert r.reason_codes==('ANALYST_MODEL_UNAVAILABLE',)
    assert c._opener.open.call_count==1
    controlled[-2].run.assert_not_called()


def test_empty_reply_stops_without_schema_retry(controlled):
    class Empty:
        def generate(self,request):return ModelReply(' ')
    r=run(controlled,analyst_client=Empty())
    assert r.reason_codes==('ANALYST_EMPTY_RESPONSE',) and r.analyst.attempts==1
    controlled[-2].run.assert_not_called()


def test_body_read_cannot_refresh_entire_deadline():
    c=OllamaModelClient(timeout=2);now=[0.0]
    response=MagicMock()
    def chunk(size):now[0]+=1.1;return b'x'
    response.read1.side_effect=chunk
    response.__enter__.return_value=response
    c._opener.open=MagicMock(return_value=response)
    with patch('src.agent.ollama_model_client.monotonic',side_effect=lambda:now[0]):
        with pytest.raises(OllamaClientError,match='TIMEOUT'):c.generate(request())
    assert response.read1.call_count==2 and c._opener.open.call_count==1


def test_static_dynamic_evidence_files_untouched_on_timeout(controlled,tmp_path):
    paths=[tmp_path/n for n in ['static_analysis_report.json','dynamic_analysis_report.json','endpoint_contexts.json']]
    for p in paths:p.write_bytes(b'{"preserved_evidence":true}')
    before=[p.read_bytes() for p in paths]
    r=run(controlled,analyst_client=FakeModelClient(error=TimeoutError()))
    assert [p.read_bytes() for p in paths]==before
    assert not r.executions and r.agent_state=='unavailable'


def test_provider_availability_contract_rejects_ambiguous_state():
    with pytest.raises(ValueError):ProviderAvailability('false','AVAILABLE',ModelMetadata())


def test_uncertain_failure_is_sticky_without_second_provider_call():
    from src.agent.security_integration.reliability import FailureAwareClient
    raw=FakeModelClient(error=TimeoutError())
    wrapper=FailureAwareClient(raw)
    for _ in range(2):
        with pytest.raises(RuntimeError):wrapper.generate(request())
    assert wrapper.failure=='TIMEOUT' and len(raw.requests)==1


def test_broken_identity_property_cannot_break_failure_reporting(controlled):
    class Broken:
        @property
        def identity(self):raise RuntimeError('SECRET_INTERNAL_ERROR')
        def generate(self,request):raise TimeoutError()
    result=run(controlled,analyst_client=Broken())
    assert result.agent_state=='unavailable' and result.reason_codes==('ANALYST_TIMEOUT',)
    assert 'SECRET_INTERNAL_ERROR' not in json.dumps(result.to_dict())
    controlled[-2].run.assert_not_called()
