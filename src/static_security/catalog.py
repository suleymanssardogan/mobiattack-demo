"""Versioned catalog and fail-closed evidence gate, independent of any model/provider."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath

CATEGORIES = frozenset('MASVS-' + name for name in (
    'STORAGE', 'CRYPTO', 'AUTH', 'NETWORK', 'PLATFORM', 'CODE', 'RESILIENCE', 'PRIVACY'))
EVIDENCE_TIERS = frozenset({'fact', 'indicator', 'candidate', 'finding_eligible'})
RULES = frozenset({'never', 'explicit_debuggable', 'explicit_cleartext_policy', 'proven_http_call'})
# Only the semantic mapping actually verified for these controls is allowlisted.
VERIFIED_REFS = {'masvs_control_refs': {'MASVS-NETWORK-1': 'MASVS-NETWORK'},
                 'maswe_refs': {}, 'mastg_test_refs': {}}
SOURCES = frozenset({'https://mas.owasp.org/MASVS/',
                    'https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/'})
REASON_CONTROLS = {
    'MANIFEST_DEBUGGABLE_TRUE': 'STATIC-CODE-DEBUG',
    'MANIFEST_CLEARTEXT_ALLOWED': 'STATIC-NET-CLEARTEXT',
    'NETWORK_CONFIG_CLEARTEXT_ALLOWED': 'STATIC-NET-CLEARTEXT',
    'HTTP_NETWORK_CALL_CONTEXT': 'STATIC-NET-HTTP-CALL',
    'NETWORK_CONFIG_REQUIRES_REVIEW': 'STATIC-NET-CONFIG',
    'NETWORK_POLICY_REQUIRES_RUNTIME_CONFIRMATION': 'STATIC-NET-HTTP-CALL',
    'EXPORTED_COMPONENT_REQUIRES_USAGE_REVIEW': 'STATIC-PLATFORM-EXPORT',
    'BACKUP_ENABLED_DATA_SCOPE_UNKNOWN': 'STATIC-STORAGE-BACKUP',
    'EXACT_ROOT_BINARY_PATH': 'STATIC-RESILIENCE-ROOT',
    'PERMISSION_DECLARATION_ONLY': 'STATIC-PRIVACY-PERMISSION',
}


def validate_catalog(catalog):
    if not isinstance(catalog, dict) or set(catalog) != {'schema_version', 'catalog_version', 'controls'}:
        raise ValueError('INVALID_CATALOG_SCHEMA')
    if catalog['schema_version'] != '1.0' or catalog['catalog_version'] != 'static_controls_v1':
        raise ValueError('INVALID_CATALOG_VERSION')
    if not isinstance(catalog['controls'], list):
        raise ValueError('INVALID_CONTROLS')
    required = {'control_id', 'title', 'masvs_category', 'standards', 'official_sources',
                'evidence_requirements', 'finding_eligibility_rule', 'default_severity_guidance',
                'reason_code', 'remediation_template', 'analysis_type', 'coverage_state', 'coverage_reason'}
    ids = set()
    for row in catalog['controls']:
        if not isinstance(row, dict) or set(row) != required:
            raise ValueError('INVALID_CONTROL_SCHEMA')
        for field in required - {'standards', 'official_sources', 'evidence_requirements', 'default_severity_guidance'}:
            if not isinstance(row[field], str) or not row[field].strip():
                raise ValueError('MISSING_CONTROL_FIELD')
        if row['control_id'] in ids:
            raise ValueError('DUPLICATE_CONTROL')
        ids.add(row['control_id'])
        if row['masvs_category'] not in CATEGORIES or row['analysis_type'] != 'static':
            raise ValueError('INVALID_CATEGORY_OR_ANALYSIS_TYPE')
        if row['coverage_state'] not in {'supported', 'partial', 'unsupported'}:
            raise ValueError('INVALID_COVERAGE')
        if row['finding_eligibility_rule'] not in RULES:
            raise ValueError('UNKNOWN_ELIGIBILITY_RULE')
        expected_category = {'explicit_debuggable': 'MASVS-CODE', 'explicit_cleartext_policy': 'MASVS-NETWORK', 'proven_http_call': 'MASVS-NETWORK'}.get(row['finding_eligibility_rule'])
        if expected_category and row['masvs_category'] != expected_category:
            raise ValueError('INVALID_RULE_CATEGORY')
        if row['coverage_state'] == 'unsupported' and row['finding_eligibility_rule'] != 'never':
            raise ValueError('UNSUPPORTED_FINDING_RULE')
        if row['default_severity_guidance'] not in {None, 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}:
            raise ValueError('INVALID_SEVERITY_GUIDANCE')
        for field, allowed in (('official_sources', SOURCES), ('evidence_requirements',
                               {'manifest_attribute', 'network_security_configuration', 'manifest_component', 'static_network_call', 'code_call', 'static_string'})):
            values = row[field]
            if not isinstance(values, list) or not values or any(not isinstance(v, str) or v not in allowed for v in values):
                raise ValueError('INVALID_' + field.upper())
        standards = row['standards']
        if not isinstance(standards, dict) or set(standards) != {'masvs_category', *VERIFIED_REFS} or standards['masvs_category'] != row['masvs_category']:
            raise ValueError('INVALID_STANDARDS_SCHEMA')
        for field, allowed in VERIFIED_REFS.items():
            refs = standards[field]
            if not isinstance(refs, list) or any(not isinstance(ref, str) or allowed.get(ref) != row['masvs_category'] for ref in refs):
                raise ValueError('UNVERIFIED_STANDARD_REFERENCE')
        if standards['masvs_control_refs'] and row['finding_eligibility_rule'] not in {'explicit_cleartext_policy', 'proven_http_call'}:
            raise ValueError('UNVERIFIED_SEMANTIC_MAPPING')
    if {row['masvs_category'] for row in catalog['controls']} != CATEGORIES:
        raise ValueError('INCOMPLETE_CATEGORY_COVERAGE')
    return deepcopy(catalog)


def load_catalog():
    return validate_catalog(json.loads(Path(__file__).with_name('control_catalog.json').read_text()))


def control_for_reason(reason):
    ident = REASON_CONTROLS.get(reason)
    return next((r for r in load_catalog()['controls'] if r['control_id'] == ident), None)


def provenance_ref(record):
    """Correlation-side deterministic reference to the exact static evidence record."""
    payload = {k: record.get(k) for k in ('source', 'component', 'observed_value', 'reason_code', 'evidence_type')}
    return 'static_control_evidence_' + sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:24]


def finding_is_eligible(record):
    """Tier labels alone never authorize promotion; exact rule/evidence must qualify."""
    if not isinstance(record, dict) or record.get('evidence_tier') != 'finding_eligible':
        return False
    control = control_for_reason(record.get('reason_code'))
    if not control or control['coverage_state'] == 'unsupported' or control['finding_eligibility_rule'] == 'never':
        return False
    if record.get('control_id') != control['control_id'] or not _standards_match(record.get('standards'), control['standards']):
        return False
    if record.get('evidence_type') not in control['evidence_requirements']:
        return False
    source, component = record.get('source'), record.get('component')
    if not isinstance(source, str) or not source or '\\' in source or ':' in source or PurePosixPath(source).is_absolute() or '..' in source.split('/'):
        return False
    if not isinstance(component, str) or not component:
        return False
    if record.get('provenance_refs') != [provenance_ref(record)]:
        return False
    reason, value = record.get('reason_code'), record.get('observed_value')
    if reason == 'MANIFEST_DEBUGGABLE_TRUE':
        return source == 'AndroidManifest.xml' and component == 'application.android:debuggable' and value is True
    if reason == 'MANIFEST_CLEARTEXT_ALLOWED':
        return source == 'AndroidManifest.xml' and component == 'application.android:usesCleartextTraffic' and value is True
    if reason == 'NETWORK_CONFIG_CLEARTEXT_ALLOWED':
        return source.startswith('res/xml/') and source.endswith('.xml') and value is True
    if reason == 'HTTP_NETWORK_CALL_CONTEXT':
        import re
        from src.vulnerability_evaluator import _http_endpoint
        return bool(re.fullmatch(r'network call at line [1-9][0-9]*', component)) and _http_endpoint(value) and '?' not in value and '#' not in value
    return False


def coverage_records(records):
    """Coverage states describe implementation, never a control PASS/security verdict."""
    result = []
    for control in load_catalog()['controls']:
        matched = [r for r in records if r.get('control_id') == control['control_id']]
        result.append({'control_id': control['control_id'], 'masvs_category': control['masvs_category'],
                       'coverage_state': control['coverage_state'], 'coverage_reason': control['coverage_reason'],
                       'assessment_state': 'not_evaluated' if control['coverage_state'] == 'unsupported' else
                           ('finding_present' if any(r.get('classification') == 'finding' for r in matched) else
                            ('requires_review' if matched else 'unknown')),
                       'evidence_refs': sorted({ref for r in matched for ref in r.get('provenance_refs', []) + r.get('supporting_provenance_refs', [])})})
    return result


def _standards_match(actual, expected):
    # Legacy findings carry an empty CWE list; no new exact CWE mapping is allowed.
    if not isinstance(actual, dict):
        return False
    clean = dict(actual)
    if 'cwe_refs' in clean and clean.pop('cwe_refs') != []:
        return False
    return clean == expected


def validate_evidence_record(record):
    """Validate a catalog evidence record without promoting its evidence tier."""
    if not isinstance(record, dict) or record.get('evidence_tier') not in EVIDENCE_TIERS:
        raise ValueError('INVALID_EVIDENCE_TIER')
    control = control_for_reason(record.get('reason_code'))
    if not control or record.get('control_id') != control['control_id']:
        raise ValueError('UNKNOWN_CONTROL_OR_REASON')
    if not _standards_match(record.get('standards'), control['standards']):
        raise ValueError('INVALID_EVIDENCE_STANDARDS')
    expected_classification = 'finding' if record['evidence_tier'] == 'finding_eligible' else record['evidence_tier']
    if record.get('classification') != expected_classification:
        raise ValueError('CLASSIFICATION_TIER_MISMATCH')
    if record.get('classification') == 'finding' and not finding_is_eligible(record):
        raise ValueError('EVIDENCE_NOT_FINDING_ELIGIBLE')
    return deepcopy(record)
