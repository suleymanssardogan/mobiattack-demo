"""Explicit offline migration of the recorded D10 lab, never arbitrary evidence.

Only reviewed immutable fixture digests are eligible. Changed legacy payloads
remain untouched and fail strict validation. No credentials are reconstructed;
redacted legacy credentials cannot produce credential identity references.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json

from src.dynamic.traffic.auth_metadata import observe_auth
from src.dynamic.traffic.normalizer import sanitize_transaction_data

VERSION = 'sanitized_auth_v2'
LEGACY_DIGESTS = frozenset(['60ed96663731564830cc104f4f13f977b7a93f156ebad76916d1e498ee103fa8', 'c19fa09acaab5e47779d26e75c03abc79ce2a0d2bf113ced36c64654aefd3c33'])


def payload_digest(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def adapt_auth_presence_evidence(evidence):
    """Return a new bundle; original historical artifacts are never overwritten."""
    payloads = {}
    migrations = {}
    for role in ('baseline', 'variant'):
        original = getattr(evidence, role)
        payload = deepcopy(original)
        if isinstance(payload, dict) and payload_digest(payload) in LEGACY_DIGESTS:
            for name in ('request', 'response'):
                part = payload[name]
                part['auth_metadata'] = observe_auth(part.get('headers'), payload.get('session_id'), response=name=='response')
            payload = sanitize_transaction_data(payload)
            migrations[role] = {'source_digest':payload_digest(original), 'sanitized_digest':payload_digest(payload)}
        payloads[role] = payload
    # Preserve an existing migration on idempotent calls.
    return replace(evidence, **payloads, auth_contract_version=VERSION,
                   auth_migration=migrations or evidence.auth_migration)


def migrate_recorded_auth_artifact(artifact):
    """Opt-in upgrade for historical source records; loaders/writers stay strict.

    Execution decisions, ownership records and recorded outcomes are untouched.
    Consumers must still recompute validation from the resulting evidence.
    """
    from src.dynamic.context.models import EndpointContext
    from src.dynamic.security.validation import AuthPresenceEvidence
    result = deepcopy(artifact)
    for record in result.get('records', []):
        if record.get('request', {}).get('test_category') != 'authentication_presence':
            continue
        data = deepcopy(record['evidence'])
        data['context'] = EndpointContext(**data['context'])
        evidence = adapt_auth_presence_evidence(AuthPresenceEvidence(**data))
        record['evidence'].update(baseline=evidence.baseline, variant=evidence.variant,
            auth_contract_version=evidence.auth_contract_version, auth_migration=evidence.auth_migration)
    return result
