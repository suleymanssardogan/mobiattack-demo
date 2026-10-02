"""Mocked HTTP only: no live service, downloads or execution."""
import json
import socket
from unittest.mock import MagicMock
from urllib.error import HTTPError, URLError

import pytest

from src.agent.model_client import ModelMetadata, ModelReply, ModelRequest
from src.agent.ollama_model_client import OllamaClientError, OllamaModelClient, MAX_RESPONSE_BYTES
from src.agent.context_analyst import analyze_endpoint_context
from tests.test_context_analyst_input import endpoint
from tests.context_analyst_fakes import TIME


def request(correction=None):
    return ModelRequest('context_analyst_v1', 'Existing canonical instruction', {'endpoint_context_id': 'ctx_1'},
                        {'type': 'object'}, 1, correction)


def body(**extra):
    return {'model': 'qwen2.5:7b', 'done': True, 'message': {'role': 'assistant', 'content': '{"ok": true}',
            'thinking': 'PRIVATE_THOUGHT'}, 'prompt_eval_count': 23, 'eval_count': 17, **extra}


def mock_reply(client, raw):
    reply = MagicMock()
    reply.__enter__.return_value.read.return_value = raw
    client._opener.open = MagicMock(return_value=reply)


def test_protocol_request_schema_correction_metadata_and_no_thinking():
    client = OllamaModelClient(timeout=11)
    mock_reply(client, json.dumps(body()).encode())
    result = client.generate(request('Existing retry correction'))
    assert isinstance(result, ModelReply) and isinstance(result.metadata, ModelMetadata)
    assert result.data == '{"ok": true}' and 'PRIVATE_THOUGHT' not in str(result)
    assert result.metadata.provider == 'local' and result.metadata.input_tokens == 23
    assert result.metadata.output_tokens == 17 and result.metadata.latency_ms >= 0
    args, kwargs = client._opener.open.call_args
    wire = json.loads(args[0].data)
    assert args[0].full_url == 'http://127.0.0.1:11434/api/chat' and kwargs['timeout'] == 11
    assert wire['format'] == request().output_schema and wire['stream'] is False and wire['think'] is False
    assert wire['messages'][-1]['content'] == 'Existing retry correction'
    assert 'tools' not in wire and args[0].get_header('Authorization') is None


@pytest.mark.parametrize('error,code', [
    (socket.timeout('secret'), 'TIMEOUT'), (URLError(socket.timeout('secret')), 'TIMEOUT'),
    (URLError('secret'), 'CONNECTION_ERROR'), (OSError('secret'), 'CONNECTION_ERROR'),
    (HTTPError('http://secret', 404, 'secret', {}, None), 'MODEL_UNAVAILABLE'),
    (HTTPError('http://secret', 500, 'secret', {}, None), 'HTTP_ERROR')])
def test_clean_transport_errors(error, code):
    client = OllamaModelClient(); client._opener.open = MagicMock(side_effect=error)
    with pytest.raises(OllamaClientError) as exc: client.generate(request())
    assert str(exc.value) == code and 'secret' not in str(exc.value)
    assert client._opener.open.call_count == 1  # retries belong to runtime


@pytest.mark.parametrize('raw,code', [
    (b'not json', 'MALFORMED_RESPONSE'), (b'[]', 'MALFORMED_RESPONSE'),
    (b'{"done":true,"done":false}', 'MALFORMED_RESPONSE'),
    (json.dumps(body(message={'role':'assistant','content':None})).encode(), 'MALFORMED_RESPONSE'),
    (json.dumps(body(message={'role':'assistant','content':'{}','tool_calls':[{}]})).encode(), 'MALFORMED_RESPONSE'),
    (json.dumps(body(done=False)).encode(), 'MALFORMED_RESPONSE'),
    (json.dumps(body(done_reason='length')).encode(), 'OUTPUT_TRUNCATED'),
    (json.dumps(body(model='other')).encode(), 'MODEL_MISMATCH'),
    (json.dumps(body(eval_count=-1)).encode(), 'MALFORMED_RESPONSE'),
    (json.dumps({'error':'PRIVATE_SERVER_ERROR'}).encode(), 'PROVIDER_ERROR'),
    (b'x'*(MAX_RESPONSE_BYTES+1), 'RESPONSE_TOO_LARGE')])
def test_malformed_envelope_and_bounds(raw, code):
    client = OllamaModelClient(); mock_reply(client, raw)
    with pytest.raises(OllamaClientError) as exc: client.generate(request())
    assert str(exc.value) == code


@pytest.mark.parametrize('config', [
    {'base_url':'https://cloud.example.com'}, {'base_url':'http://user:secret@localhost:11434'},
    {'base_url':'http://localhost:11434/?secret=1'}, {'timeout':0}, {'timeout':301},
    {'timeout':float('nan')}, {'timeout':True}, {'model':'../secret'}])
def test_invalid_or_nonlocal_config_rejected(config):
    with pytest.raises(OllamaClientError, match='CONFIG_INVALID'): OllamaModelClient(**config)


def test_environment_config_and_no_proxy_or_redirect(monkeypatch):
    monkeypatch.setenv('MOBIATTACK_OLLAMA_BASE_URL','http://localhost:11435')
    monkeypatch.setenv('MOBIATTACK_OLLAMA_MODEL','qwen2.5:14b')
    monkeypatch.setenv('MOBIATTACK_OLLAMA_TIMEOUT','30')
    c=OllamaModelClient.from_env()
    assert (c.base_url,c.model,c.timeout)==('http://localhost:11435','qwen2.5:14b',30)
    handler=next(h for h in c._opener.handlers if hasattr(h,'redirect_request'))
    assert handler.redirect_request(None,None,302,'',{},'https://external.example') is None
    assert not any(type(h).__name__=='ProxyHandler' and h.proxies for h in c._opener.handlers)


def test_invalid_model_json_uses_existing_bounded_runtime_retry(endpoint):
    c=OllamaModelClient(); mock_reply(c,json.dumps(body(message={'role':'assistant','content':'INVALID_JSON'})).encode())
    r=analyze_endpoint_context(endpoint,c,created_at=TIME)
    assert r.status=='invalid_output' and r.attempts==2 and c._opener.open.call_count==2
    assert not r.hypotheses and 'INVALID_JSON' not in json.dumps(r.to_dict())


def test_client_works_with_existing_runtime_validator(endpoint):
    # Unit fixture only; the separately run live smoke never uses this double.
    from tests.context_analyst_fakes import valid_output
    class TransportClient(OllamaModelClient):
        def generate(self, req):
            mock_reply(self,json.dumps(body(message={'role':'assistant','content':json.dumps(valid_output(req))})).encode())
            return super().generate(req)
    r=analyze_endpoint_context(endpoint,TransportClient(),created_at=TIME)
    assert r.status=='completed' and r.model_metadata.provider=='local'


def test_large_grammar_string_limit_retains_canonical_runtime_schema():
    from dataclasses import replace
    schema={'type':'object','properties':{'text':{'type':'string','minLength':1,'maxLength':2048}}}
    req=replace(request(),output_schema=schema)
    c=OllamaModelClient();mock_reply(c,json.dumps(body()).encode());c.generate(req)
    wire=json.loads(c._opener.open.call_args.args[0].data)
    assert 'maxLength' not in wire['format']['properties']['text']
    assert json.loads(wire['messages'][1]['content'])['output_schema']==schema
    assert req.output_schema['properties']['text']['maxLength']==2048


def test_server_duration_metadata_and_missing_optional_tokens():
    c=OllamaModelClient()
    mock_reply(c,json.dumps(body(total_duration=2_000_000_000,prompt_eval_count=None,eval_count=None)).encode())
    r=c.generate(request())
    assert r.metadata.latency_ms==2000 and r.metadata.input_tokens is None and r.metadata.output_tokens is None


def test_nonserializable_input_and_request_bound_fail_cleanly():
    from dataclasses import replace
    c=OllamaModelClient();c._opener.open=MagicMock()
    with pytest.raises(OllamaClientError,match='REQUEST_INVALID'):
        c.generate(replace(request(),input_data={'secret':object()}))
    with pytest.raises(OllamaClientError,match='REQUEST_TOO_LARGE'):
        c.generate(replace(request(),input_data={'text':'x'*1_048_576}))
    c._opener.open.assert_not_called()
