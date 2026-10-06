"""Versioned semantic selection plus deterministic, evidence-backed result view.

The model selects role/concern types only. Existing observations, coverage and
hypothesis descriptors are compiled from the trusted snapshot, then passed through
THE SAME canonical validator. No missing or invented model semantics are repaired.
"""
from dataclasses import replace
import json

from .models import MAX_OUTPUT_BYTES
from .validation import (OutputInvalid, _scan, _unique_object, gap_id, record_id,
                         validate_model_output)

COMPACT_VERSION = 'context_analyst_compact_v1'


def compact_output_schema(context):
    concerns = sorted(context.hypothesis_catalog)
    return {'type': 'object', 'additionalProperties': False,
            'required': ['schema_version', 'endpoint_context_id', 'endpoint_role', 'concerns'],
            'properties': {
                'schema_version': {'const': COMPACT_VERSION},
                'endpoint_context_id': {'const': context.endpoint_context_id},
                'endpoint_role': {'type': 'string', 'enum': list(context.supported_roles)},
                'concerns': {'type': 'array', 'uniqueItems': True, 'maxItems': len(concerns),
                             'items': {'type': 'string', 'enum': concerns}} if concerns else
                            {'type': 'array', 'maxItems': 0}}}


def _parse(data):
    if isinstance(data, str):
        if len(data.encode()) > MAX_OUTPUT_BYTES:
            raise OutputInvalid('OUTPUT_SIZE_EXCEEDED')
        try:
            data = json.loads(data, object_pairs_hook=_unique_object)
        except OutputInvalid:
            raise
        except (ValueError, TypeError, RecursionError):
            raise OutputInvalid('SCHEMA_INVALID') from None
    _scan(data)
    return data


def _unresolved(facts, auth, gaps):
    refs = list(gaps) + ['auth.' + k for k, v in auth.items() if v == 'unknown']
    for section in ('Request', 'Response'):
        if f'{section} body presence metadata: unknown.' in facts:
            refs.append(section.lower() + '.body_present')
    if 'Runtime event evidence is unavailable; event absence is unknown.' in facts:
        refs.append('runtime.event_metadata')
    if 'HTTPS visibility: unknown.' in facts:
        refs.append('visibility.https')
    if any(f.endswith('methods: unknown.') for f in facts):
        refs.append('endpoint.methods')
    return sorted(refs)


def compact_snapshot(context, role, concerns):
    """Compact canonical facts are runtime-owned, not model-generated evidence."""
    auth = {k: 'present' if v is True else 'absent' if v is False else 'unknown'
            for k, v in context.auth_context.items()}
    auth['authenticated_state'] = 'unknown'  # Presence never proves authentication.
    capabilities = []
    for name, present in (
        ('runtime_traffic', context.dynamic_context['runtime_confirmed']),
        ('runtime_events', context.runtime_context['evidence_available']),
        ('request_body', context.request_context['body_present']),
        ('response_body', context.response_context['body_present']),
        ('query_parameters', bool(context.request_context['query_keys'])),
        ('resource_identifiers', bool(context.request_context['resource_identifier_keys']))):
        if present is True:
            capabilities.append(name)
    gaps = sorted(gap_id(context.endpoint_context_id, g) for g in context.coverage['gaps'])
    return {'schema_version': COMPACT_VERSION, 'endpoint_context_id': context.endpoint_context_id,
            'context_ref': context.evidence_refs['endpoint_context'][0], 'endpoint_role': role,
            'coverage_state': 'partial' if gaps else 'no_recorded_gaps',
            'observed_capabilities': sorted(capabilities), 'auth_session_state': auth,
            'evidence_refs': list(context.evidence_universe),
            'applicable_security_concerns': sorted(concerns),
            'unresolved_facts': _unresolved([f['statement'] for f in context.fact_catalog], auth, gaps)}


def validate_analyst_reply(data, context, *, created_at, metadata, attempts, errors=()):
    parsed = _parse(data)
    if isinstance(parsed, dict) and parsed.get('schema_version') == COMPACT_VERSION:
        if set(parsed) != {'schema_version', 'endpoint_context_id', 'endpoint_role', 'concerns'}:
            raise OutputInvalid('SCHEMA_INVALID')
        if parsed['endpoint_context_id'] != context.endpoint_context_id:
            raise OutputInvalid('ENDPOINT_MISMATCH')
        role = parsed['endpoint_role']
        if not isinstance(role, str) or role not in context.supported_roles:
            raise OutputInvalid('UNSUPPORTED_ENDPOINT_ROLE')
        concerns = parsed['concerns']
        if (not isinstance(concerns, list) or any(not isinstance(c, str) or c not in context.hypothesis_catalog for c in concerns)):
            raise OutputInvalid('UNSUPPORTED_HYPOTHESIS')
        if len(concerns) != len(set(concerns)):
            raise OutputInvalid('DUPLICATE_HYPOTHESIS_TYPE')
        eid = context.endpoint_context_id
        gaps = [{'gap_id': gap_id(eid, g), 'endpoint_context_id': eid, **g, 'blocked_test_ids': []}
                for g in context.coverage['gaps']]
        refs = sorted({r for f in context.fact_catalog for r in f['evidence_refs']})
        parsed = {'schema_version': '1.0', 'endpoint_context_id': eid, 'endpoint_role': role,
            'observation': {'observation_id': record_id('obs', eid), 'endpoint_context_id': eid,
                'facts': [f['statement'] for f in context.fact_catalog], 'evidence_refs': refs,
                'coverage_gaps': [g['gap_id'] for g in gaps], 'created_at': created_at},
            'hypotheses': [{'hypothesis_type': c, **context.hypothesis_catalog[c]} for c in sorted(concerns)],
            'coverage_gaps': gaps}
    # Strict legacy compatibility also permits migration of existing fixtures.
    # Rich input is never silently reduced/repaired before canonical validation.
    result = validate_model_output(parsed, context, created_at=created_at, metadata=metadata,
                                   attempts=attempts, errors=errors)
    snapshot = compact_snapshot(context, result.endpoint_role, [h.hypothesis_type for h in result.hypotheses])
    return replace(result, compact_context=snapshot)


def validate_compact_context(snapshot, result):
    """Persisted compact view must agree with its strict Planner-compatible record."""
    from src.agent.models import ContractError
    keys = {'schema_version', 'endpoint_context_id', 'context_ref', 'endpoint_role', 'coverage_state',
            'observed_capabilities', 'auth_session_state', 'evidence_refs',
            'applicable_security_concerns', 'unresolved_facts'}
    if not isinstance(snapshot, dict) or set(snapshot) != keys:
        raise ContractError('Invalid compact context fields')
    auth_keys = {'api_key_header_present', 'authorization_header_present', 'bearer_token_present',
                 'cookie_present', 'session_cookie_present', 'authenticated_state'}
    auth = snapshot['auth_session_state']
    if (not isinstance(auth, dict) or set(auth) != auth_keys
            or any(v not in ('present', 'absent', 'unknown') for v in auth.values())
            or auth['authenticated_state'] != 'unknown'):
        raise ContractError('Invalid compact auth states')
    gaps = sorted(g.gap_id for g in result.coverage_gaps)
    facts = result.observation.facts
    observed = []
    rules = {
        'runtime_traffic': lambda f: f == 'Runtime traffic confirmed this endpoint in the supplied context.',
        'request_body': lambda f: f == 'Request body presence metadata: observed.',
        'response_body': lambda f: f == 'Response body presence metadata: observed.',
        'query_parameters': lambda f: f.startswith('Observed query key names:'),
        'resource_identifiers': lambda f: f.startswith('Resource identifier names are present:')}
    for name, match in rules.items():
        if any(match(f) for f in facts): observed.append(name)
    if 'Runtime event evidence is unavailable; event absence is unknown.' not in facts:
        observed.append('runtime_events')
    for name in sorted(auth_keys - {'authenticated_state'}):
        state = {'present': 'present', 'absent': 'not observed', 'unknown': 'unknown'}[auth[name]]
        if f'Authentication metadata {name}: {state}; correctness is unknown.' not in facts:
            raise ContractError('Compact auth differs from canonical facts')
    expected = {
        'schema_version': COMPACT_VERSION, 'endpoint_context_id': result.endpoint_context_id,
        'context_ref': f'dynamic/endpoint_contexts.json#endpoint_context_id={result.endpoint_context_id}',
        'endpoint_role': result.endpoint_role, 'coverage_state': 'partial' if gaps else 'no_recorded_gaps',
        'observed_capabilities': sorted(observed), 'auth_session_state': auth,
        'evidence_refs': list(result.input_evidence_refs),
        'applicable_security_concerns': sorted(h.hypothesis_type for h in result.hypotheses),
        'unresolved_facts': _unresolved(facts, auth, gaps)}
    if snapshot != expected:
        raise ContractError('Compact context differs from canonical evidence')
