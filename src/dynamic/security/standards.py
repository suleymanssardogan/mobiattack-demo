"""Curated descriptive OWASP traceability, reviewed 2026-10-02.

No execution, evidence, risk or compliance decisions depend on these mappings.
See STANDARDS.md for scope limits and the official reference provenance. Empty
specific references mean no exact mapping was established, not no applicable risk.
"""
from dataclasses import dataclass
import re
from types import MappingProxyType

MAPPING_VERSION = 'dynamic_security_standards_v1'
REFERENCE_SOURCES = MappingProxyType({
    'MASVS-AUTH': 'https://mas.owasp.org/MASVS/07-MASVS-AUTH/',
    'MASVS-AUTH-1': 'https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/',
    'MASVS-CODE': 'https://mas.owasp.org/MASVS/10-MASVS-CODE/',
})


@dataclass(frozen=True)
class StandardsMapping:
    masvs_category: str
    masvs_control_refs: tuple[str, ...] = ()
    mastg_test_refs: tuple[str, ...] = ()
    maswe_refs: tuple[str, ...] = ()

    def to_dict(self):
        return {'masvs_category': self.masvs_category,
                'masvs_control_refs': list(self.masvs_control_refs),
                'mastg_test_refs': list(self.mastg_test_refs),
                'maswe_refs': list(self.maswe_refs)}


_AUTH = StandardsMapping('MASVS-AUTH', ('MASVS-AUTH-1',))
_CODE = StandardsMapping('MASVS-CODE')
_MAPPINGS = MappingProxyType({
    'authentication_presence': _AUTH,
    'object_authorization': _AUTH,
    'function_authorization': _AUTH,
    'session_handling': _AUTH,
    'parameter_consistency': _CODE,
    'input_validation': _CODE,
})
_PATTERNS = {
    'masvs_control_refs': re.compile(r'MASVS-[A-Z]+-[1-9][0-9]*'),
    'mastg_test_refs': re.compile(r'MASTG-TEST-[0-9]{4}'),
    'maswe_refs': re.compile(r'MASWE-[0-9]{4}'),
}


def standards_for_category(test_category):
    if not isinstance(test_category, str) or test_category not in _MAPPINGS:
        raise ValueError('Unsupported standards mapping category')
    return _MAPPINGS[test_category].to_dict()


def validate_standards_metadata(metadata, test_category):
    """Reject malformed, unverified or category-inappropriate references.

    Syntax alone does not establish an official identifier or a suitable mapping.
    Specific refs may be empty; non-empty refs must belong to the curated mapping.
    """
    expected = standards_for_category(test_category)
    if not isinstance(metadata, dict) or set(metadata) != set(expected):
        raise ValueError('Invalid standards metadata fields')
    if metadata['masvs_category'] != expected['masvs_category']:
        raise ValueError('Unknown or mismatched MASVS category')
    for field, pattern in _PATTERNS.items():
        refs = metadata[field]
        if not isinstance(refs, list) or len(refs) > 32 or any(not isinstance(ref, str) or not pattern.fullmatch(ref) for ref in refs):
            raise ValueError('Malformed standards reference')
        if len(set(refs)) != len(refs) or not set(refs).issubset(expected[field]):
            raise ValueError('Unverified or inappropriate standards reference')
