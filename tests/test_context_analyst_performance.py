"""Offline projection/transport tests; canonical validation remains authoritative."""
import json
from dataclasses import replace

from src.agent.context_analyst.input_builder import build_context_analyst_input
from src.agent.context_analyst.model_context import build_model_context
from src.agent.context_analyst import analyze_endpoint_context
from src.agent.context_analyst.validation import output_schema
from src.agent.context_analyst.prompts import INSTRUCTION
from src.agent.model_client import ModelRequest
from src.agent.ollama_model_client import OllamaModelClient, _grammar_schema
from tests.context_analyst_fakes import FakeModelClient, TIME
from tests.test_context_analyst_input import endpoint
from tests.test_ollama_model_client import mock_reply, body


def test_projection_preserves_catalogs_refs_unknowns_and_provenance(endpoint):
    context = build_context_analyst_input(endpoint)
    original = context.to_dict()
    projected = build_model_context(context)
    for key in ('fact_catalog', 'hypothesis_catalog', 'evidence_refs', 'coverage',
                'static_context', 'auth_context', 'runtime_context', 'visibility', 'endpoint'):
        assert projected[key] == original[key]
    for section in ('dynamic_context', 'request_context', 'response_context'):
        assert {k: v for k, v in original[section].items() if v != [] and v != {}} == projected[section]
    projected['endpoint']['path'] = '/changed'
    assert context.to_dict() == original


def test_only_empty_collections_omitted_preserving_shapes_and_false(endpoint):
    context = build_context_analyst_input(endpoint)
    context = replace(context, request_context={'body_shapes': [{'type': 'object'}],
                        'body_present': None, 'empty': [], 'auth_absent': False, 'size': 0})
    projected = build_model_context(context)
    assert projected['request_context'] == {'body_shapes': [{'type': 'object'}],
                        'body_present': None, 'auth_absent': False, 'size': 0}


def test_compact_analyst_keeps_full_grammar_and_runtime_schema(endpoint):
    context = build_context_analyst_input(endpoint)
    schema = output_schema(context, TIME)
    request = ModelRequest('context_analyst_v1', INSTRUCTION, build_model_context(context), schema, 1)
    client = OllamaModelClient()
    wire = json.loads(client._payload(request))
    prose_schema = json.loads(wire['messages'][1]['content'])['output_schema']
    assert wire['format'] == _grammar_schema(schema)
    assert 'enum' not in prose_schema['properties']['observation']['properties']['facts']['items']
    assert wire['format']['properties']['observation']['properties']['facts']['items']['enum']
    assert request.output_schema == schema
    assert len(wire['messages'][1]['content']) < len(json.dumps({'input': context.to_dict(), 'output_schema': schema}))


def test_projection_deterministic_and_sanitized(endpoint):
    endpoint.request['body'] = 'PRIVATE_PASSWORD_TOKEN'
    context = build_context_analyst_input(endpoint)
    assert build_model_context(context) == build_model_context(context)
    assert 'PRIVATE_PASSWORD_TOKEN' not in json.dumps(build_model_context(context))


def test_compact_context_still_rejects_missing_fact_and_hallucinated_ref(endpoint):
    def missing(data, request):
        data['observation']['facts'].pop()
        return data
    def hallucinated(data, request):
        data['observation']['evidence_refs'].append('fake_ref')
        return data
    for transform in (missing, hallucinated):
        result = analyze_endpoint_context(endpoint, FakeModelClient(transform=transform), created_at=TIME)
        assert result.status == 'invalid_output' and not result.hypotheses


def test_planner_transport_unchanged():
    schema = {'type': 'object', 'properties': {'test_id': {'enum': ['OBJECT_AUTHORIZATION']}}}
    request = ModelRequest('test_planner_v1', 'Existing planner instruction', {'fact_catalog': []}, schema, 1)
    wire = json.loads(OllamaModelClient()._payload(request))
    assert wire['messages'][1]['content'] == json.dumps({'input': request.input_data, 'output_schema': schema}, sort_keys=True, allow_nan=False)
    assert wire['options'] == {'temperature': 0, 'seed': 0, 'num_ctx': 16384, 'num_predict': 4096}


def test_timing_metadata_is_numeric_only_and_resets_on_failure():
    client = OllamaModelClient()
    request = ModelRequest('context_analyst_v1', 'instruction', {}, {'type': 'object'}, 1)
    mock_reply(client, json.dumps(body(load_duration=10, prompt_eval_duration=20, eval_duration=30,
                                     arbitrary='PRIVATE', thinking='PRIVATE')).encode())
    client.generate(request)
    assert client.last_generation_metrics == {'load_duration': 10, 'prompt_eval_duration': 20,
                                             'eval_duration': 30, 'prompt_eval_count': 23, 'eval_count': 17}
    mock_reply(client, b'INVALID')
    try:
        client.generate(request)
    except RuntimeError:
        pass
    assert client.last_generation_metrics == {}
