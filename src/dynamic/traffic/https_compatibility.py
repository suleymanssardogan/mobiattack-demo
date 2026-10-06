"""Scoped, deterministic HTTPS compatibility classification from safe observations."""
from dataclasses import dataclass
import re

REASONS = {
    'https_available': ('available', 'USER_CA_TRUSTED'),
    'user_ca_not_trusted': ('unavailable', 'USER_CA_NOT_TRUSTED_BY_APP'),
    'trust_scope_unknown': ('unknown', 'CA_TRUST_SCOPE_UNKNOWN'),
    'tls_interception_unavailable': ('unavailable', 'TLS_INTERCEPTION_UNAVAILABLE'),
    'suspected_pinning': ('unavailable', 'PINNING_SUSPECTED'),
    'confirmed_pinning': ('unavailable', 'PINNING_CONFIRMED'),
}
OBSERVATIONS = {'user_ca_identity_verified', 'real_https_transaction',
                'app_trust_anchor_rejected', 'tls_interception_failed',
                'pinning_specific_signal', 'explicit_certificate_pinning_failure',
                'trust_scope_unverified'}

@dataclass(frozen=True)
class HttpsCompatibility:
    package_name: str
    session_id: str
    classification: str
    evidence_refs: tuple[str, ...]
    observations: tuple[tuple[str, str], ...]

    @property
    def visibility(self):
        return REASONS[self.classification][0]

    def to_dict(self):
        return {'package_name': self.package_name, 'session_id': self.session_id,
                'classification': self.classification, 'visibility': self.visibility,
                'reason_code': REASONS[self.classification][1],
                'evidence_refs': list(self.evidence_refs), 'scope': 'observed_application_only',
                'evidence': {ref: {'observation': kind, 'package_name': self.package_name,
                                  'session_id': self.session_id} for ref, kind in self.observations}}


def classify_https_compatibility(package_name, session_id, evidence_refs, evidence_index):
    """Consume normalized runtime evidence; generic TLS failure never implies pinning.

    Evidence producers must distinguish an app's explicit pinning diagnostic from
    an ordinary trust-anchor failure. Raw logs/credentials are not accepted here.
    """
    if (not isinstance(package_name, str) or not re.fullmatch(r'[A-Za-z0-9_.]+', package_name)
            or not isinstance(session_id, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]+', session_id)
            or not evidence_refs):
        raise ValueError('HTTPS compatibility requires scope and evidence')
    kinds = set()
    observations = []
    for ref in evidence_refs:
        if not isinstance(ref, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]+', ref):
            raise ValueError('Invalid HTTPS evidence reference')
        row = evidence_index.get(ref)
        if not row or row.get('package_name') != package_name or row.get('session_id') != session_id:
            raise ValueError('HTTPS compatibility evidence ownership mismatch')
        kind = row.get('observation')
        if kind not in OBSERVATIONS:
            raise ValueError('Unknown HTTPS compatibility observation')
        kinds.add(kind)
        observations.append((ref, kind))
    # An evidenced trust-anchor rejection is not evidence of pinning.
    if 'app_trust_anchor_rejected' in kinds:
        classification = ('user_ca_not_trusted' if 'user_ca_identity_verified' in kinds
                          else 'trust_scope_unknown')
    elif 'explicit_certificate_pinning_failure' in kinds:
        classification = 'confirmed_pinning'
    elif 'pinning_specific_signal' in kinds:
        classification = 'suspected_pinning'
    elif {'real_https_transaction', 'user_ca_identity_verified'} <= kinds:
        classification = 'https_available'
    elif 'real_https_transaction' in kinds:
        classification = 'trust_scope_unknown'
    elif 'tls_interception_failed' in kinds:
        classification = 'tls_interception_unavailable'
    else:
        classification = 'trust_scope_unknown'
    return HttpsCompatibility(package_name, session_id, classification, tuple(sorted(set(evidence_refs))), tuple(sorted(set(observations))))


def validate_compatibility_metadata(value, session_id):
    if value is None:
        return None
    if not isinstance(value, dict) or value.get('classification') not in REASONS:
        raise ValueError('Invalid HTTPS compatibility classification')
    state, reason = REASONS[value['classification']]
    refs = value.get('evidence_refs')
    if (value.get('session_id') != session_id or not value.get('package_name')
            or value.get('scope') != 'observed_application_only'
            or value.get('visibility') != state or value.get('reason_code') != reason
            or not isinstance(refs, list) or not refs or any(not isinstance(r, str) or not r for r in refs)):
        raise ValueError('Invalid HTTPS compatibility scope/evidence')
    result = classify_https_compatibility(value['package_name'], session_id, refs, value.get('evidence') or {})
    if result.classification != value['classification']:
        raise ValueError('HTTPS compatibility classification contradicts evidence')
    return result.to_dict()
