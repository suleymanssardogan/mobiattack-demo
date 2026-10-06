"""Compact selection never replaces canonical grounding or Planner rules."""
from copy import deepcopy
import json
import pytest

from src.agent.context_analyst import analyze_endpoint_context, ContextAnalystResult
from src.agent.context_analyst.compact import COMPACT_VERSION, compact_output_schema
from src.agent.context_analyst.input_builder import build_context_analyst_input
from src.agent.context_analyst.persistence import save_context_analyses, load_context_analyses
from src.agent.model_client import ModelMetadata, ModelReply
from src.agent.models import ContractError
from src.agent.test_planner.input_builder import build_test_planner_input
from tests.context_analyst_fakes import FakeModelClient, TIME
from tests.test_context_analyst_input import endpoint


class CompactClient:
    def __init__(self, transform=None): self.transform = transform; self.requests = []
    def generate(self, request):
        self.requests.append(request)
        source = request.input_data
        data = {'schema_version': COMPACT_VERSION, 'endpoint_context_id': source['endpoint_context_id'],
                'endpoint_role': 'resource_endpoint' if 'resource_endpoint' in source['supported_roles'] else 'unknown',
                'concerns': sorted(source['hypothesis_catalog'])}
        if self.transform: data = self.transform(data, request)
        return ModelReply(data, ModelMetadata('fake', 'fixture-v1'))


def run(endpoint, client=None):
    return analyze_endpoint_context(endpoint, client or CompactClient(), created_at=TIME)


def test_small_output_and_lossless_planner_compatibility(endpoint):
    compact = run(endpoint)
    legacy = run(endpoint, FakeModelClient())
    assert compact.status == legacy.status == 'completed'
    assert compact.observation == legacy.observation
    assert compact.hypotheses == legacy.hypotheses
    assert compact.coverage_gaps == legacy.coverage_gaps
    assert compact.analysis_id == legacy.analysis_id
    assert build_test_planner_input(endpoint, compact) == build_test_planner_input(endpoint, legacy)
    snapshot = compact.compact_context
    assert snapshot['evidence_refs'] == list(compact.input_evidence_refs)
    assert snapshot['auth_session_state']['authenticated_state'] == 'unknown'
    assert snapshot['coverage_state'] == ('partial' if compact.coverage_gaps else 'no_recorded_gaps')
    assert snapshot['applicable_security_concerns'] == sorted(h.hypothesis_type for h in compact.hypotheses)
    assert ContextAnalystResult.from_dict(compact.to_dict()) == compact


@pytest.mark.parametrize('field,value', [
    ('endpoint_context_id', 'wrong'), ('endpoint_role', 'administrator'),
    ('concerns', ['invented']), ('concerns', ['session_behavior_candidate', 'session_behavior_candidate']),
    ('finding', True), ('evidence_refs', ['invented']), ('reasoning', 'PRIVATE'),
    ('tool_calls', [{}]), ('auth_session_state', {'authenticated': True})])
def test_model_cannot_override_runtime_evidence_or_semantics(endpoint, field, value):
    def mutate(data, request): data[field] = value; return data
    result = run(endpoint, CompactClient(mutate))
    assert result.status == 'invalid_output' and not result.hypotheses
    assert result.compact_context is None and result.attempts == 2


def test_empty_concerns_do_not_force_plans_and_keep_gaps(endpoint):
    endpoint.visibility['https_visibility'] = 'unavailable'
    def empty(data, request): data['concerns'] = []; return data
    result = run(endpoint, CompactClient(empty))
    assert result.status == 'completed' and not result.hypotheses and result.coverage_gaps
    assert not build_test_planner_input(endpoint, result).proposal_candidates


def test_runtime_preserves_all_unknowns_and_coverage(endpoint):
    endpoint.dynamic['observed'] = False
    endpoint.dynamic['available_transaction_count'] = 0
    endpoint.evidence_refs['transaction_ids'] = []
    endpoint.auth = {k: None for k in endpoint.auth}
    endpoint.runtime_context = {'evidence_available': False}
    result = run(endpoint)
    assert result.status == 'completed'
    assert set(result.compact_context['auth_session_state'].values()) == {'unknown'}
    assert 'runtime_traffic' not in result.compact_context['observed_capabilities']
    assert 'runtime_events' not in result.compact_context['observed_capabilities']
    assert result.compact_context['unresolved_facts']
    assert result.compact_context['coverage_state'] == 'partial'


def test_persisted_compact_tampering_rejected(endpoint):
    result = run(endpoint)
    for field, value in [('auth_session_state', {'authenticated_state': 'present'}),
                         ('evidence_refs', ['invented']), ('coverage_state', 'secure'),
                         ('applicable_security_concerns', ['invented']),
                         ('observed_capabilities', []), ('endpoint_context_id', 'wrong')]:
        data = deepcopy(result.to_dict()); data['compact_context'][field] = value
        with pytest.raises(ContractError): ContextAnalystResult.from_dict(data)


def test_compact_persistence_and_evidence_roundtrip(endpoint, tmp_path):
    result = run(endpoint)
    save_context_analyses(tmp_path, [result])
    restored = load_context_analyses(tmp_path)[0]
    assert restored == result and restored.compact_context == result.compact_context
    assert build_test_planner_input(endpoint, restored) == build_test_planner_input(endpoint, result)


def test_duplicate_json_key_and_raw_secret_extra_rejected(endpoint):
    def bad_json(data, request):
        return '{"schema_version":"context_analyst_compact_v1","concerns":[],"concerns":[]}'
    assert run(endpoint, CompactClient(bad_json)).status == 'invalid_output'
    def secret(data, request): data['password'] = 'PRIVATE_PASSWORD'; return data
    result = run(endpoint, CompactClient(secret))
    assert result.status == 'invalid_output' and 'PRIVATE_PASSWORD' not in json.dumps(result.to_dict())


def test_compact_output_has_no_prose_refs_or_source_copies(endpoint):
    schema = compact_output_schema(build_context_analyst_input(endpoint))
    assert set(schema['properties']) == {'schema_version', 'endpoint_context_id', 'endpoint_role', 'concerns'}
    assert schema['additionalProperties'] is False
    assert 'statement' not in json.dumps(schema) and 'source_file' not in json.dumps(schema)
