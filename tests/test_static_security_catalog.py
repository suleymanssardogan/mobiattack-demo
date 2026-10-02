import copy
import json
from pathlib import Path
import pytest
from src.static_security.catalog import (
    CATEGORIES, EVIDENCE_TIERS, load_catalog, validate_catalog, validate_evidence_record,
    finding_is_eligible, provenance_ref, coverage_records)
from src.vulnerability_evaluator import evaluate_vulnerabilities
from src.report_generator import build_static_analysis_report


def debug_result():
    return evaluate_vulnerabilities({'manifest': {'application': {'debuggable': True}}})


def test_catalog_machine_readable_deterministic_and_complete():
    raw = json.loads((Path(__file__).parents[1] / 'src/static_security/control_catalog.json').read_text())
    assert validate_catalog(raw) == load_catalog() == load_catalog()
    assert {r['masvs_category'] for r in raw['controls']} == CATEGORIES
    assert len(raw['controls']) == 16
    assert all(r['analysis_type'] == 'static' for r in raw['controls'])
    assert raw['controls'] == sorted(raw['controls'], key=lambda r: r['control_id'])


@pytest.mark.parametrize('field,value', [
    ('coverage_state', 'passed'), ('analysis_type', 'dynamic'), ('masvs_category', 'MASVS-FAKE'),
    ('evidence_requirements', []), ('finding_eligibility_rule', 'guess'),
    ('official_sources', ['https://example.com/']), ('reason_code', ''),
    ('default_severity_guidance', 'SECURE')])
def test_catalog_invalid_fields_rejected(field, value):
    catalog = load_catalog()
    catalog['controls'][0][field] = value
    with pytest.raises(ValueError):
        validate_catalog(catalog)


@pytest.mark.parametrize('field,refs', [
    ('masvs_control_refs', ['MASVS-AUTH-99']), ('masvs_control_refs', ['MASVS-NETWORK-1']),
    ('maswe_refs', ['MASWE-9999']), ('maswe_refs', ['MASWE-0005']),
    ('mastg_test_refs', ['MASTG-TEST-9999']), ('mastg_test_refs', 'MASTG-TEST-0001')])
def test_guessed_or_unverified_semantic_refs_rejected(field, refs):
    catalog = load_catalog()
    catalog['controls'][0]['standards'][field] = refs
    with pytest.raises(ValueError):
        validate_catalog(catalog)


def test_official_mapping_allowlist_only():
    for row in load_catalog()['controls']:
        assert row['standards']['maswe_refs'] == row['standards']['mastg_test_refs'] == []
        assert row['standards']['masvs_control_refs'] in ([], ['MASVS-NETWORK-1'])
        if row['standards']['masvs_control_refs']:
            assert row['masvs_category'] == 'MASVS-NETWORK'


@pytest.mark.parametrize('tier', sorted(EVIDENCE_TIERS))
def test_all_tiers_supported_only_finding_eligible_may_promote(tier):
    row = debug_result()['findings'][0]
    row['evidence_tier'] = tier
    row['classification'] = 'fact' if tier == 'fact' else ('finding' if tier == 'finding_eligible' else tier)
    assert validate_evidence_record(row) == row
    assert finding_is_eligible(row) is (tier == 'finding_eligible')


@pytest.mark.parametrize('tier', ['indicator', 'candidate', 'fact', 'unknown'])
def test_claimed_finding_with_weak_tier_rejected(tier):
    row = debug_result()['findings'][0]
    row['evidence_tier'] = tier
    with pytest.raises(ValueError):
        validate_evidence_record(row)


@pytest.mark.parametrize('field,value', [
    ('observed_value', False), ('source', '/tmp/AndroidManifest.xml'), ('source', '../manifest'),
    ('source', None), ('component', 'other'), ('provenance_refs', []), ('reason_code', 'INVENTED'),
    ('evidence_type', 'library_presence')])
def test_finding_tier_alone_cannot_bypass_rule(field, value):
    row = debug_result()['findings'][0]
    row[field] = value
    assert not finding_is_eligible(row)


def test_unsupported_cannot_acquire_finding_rule():
    catalog = load_catalog()
    row = next(r for r in catalog['controls'] if r['control_id'] == 'STATIC-PLATFORM-WEBVIEW')
    row['finding_eligibility_rule'] = 'explicit_debuggable'
    with pytest.raises(ValueError):
        validate_catalog(catalog)


def test_candidates_cannot_self_upgrade():
    result = evaluate_vulnerabilities({'manifest': {'application': {'allow_backup': True}},
                                     'permissions': ['android.permission.CAMERA'],
                                     'network_indicators': {'path_candidates': ['/system/bin/su']}})
    assert not result['findings']
    for row in result['candidates'] + result['indicators']:
        assert validate_evidence_record(row) == row
        row['classification'] = 'finding'
        row['evidence_tier'] = 'finding_eligible'
        assert not finding_is_eligible(row)


def test_no_evidence_and_unsupported_never_pass():
    records = coverage_records([])
    assert all(r['assessment_state'] in {'unknown', 'not_evaluated'} for r in records)
    assert all(r['assessment_state'] == 'not_evaluated' for r in records if r['coverage_state'] == 'unsupported')
    assert all('passed' not in r.values() for r in records)


def test_unknown_manifest_does_not_mean_secure():
    result = evaluate_vulnerabilities({'manifest': {'application': {'debuggable': None}}})
    debug = next(r for r in result['control_coverage'] if r['control_id'] == 'STATIC-CODE-DEBUG')
    assert debug['assessment_state'] == 'unknown'
    assert not result['findings']


def test_source_refs_reproducible_and_report_preserved():
    source = {'platform': 'android', 'manifest': {'application': {'debuggable': True}}}
    before = copy.deepcopy(source)
    result = evaluate_vulnerabilities(source)
    row = result['findings'][0]
    assert row['provenance_refs'] == [provenance_ref(row)]
    assert finding_is_eligible(row)
    assert source == before
    report = build_static_analysis_report('catalog', report_dict=source)
    assert report['vulnerabilities']['control_coverage'] == result['control_coverage']
    assert report['vulnerabilities']['findings'][0]['provenance_refs'] == row['provenance_refs']
    assert 'poc' not in row


@pytest.mark.parametrize('state', ['unresolved', 'partial'])
def test_unresolved_api_flow_never_promoted(state):
    row = {'method': 'POST', 'full_url': 'http://127.0.0.1/signup', 'source_file': 'smali/Request.smali',
           'request_line': 10, 'resolution_state': state}
    assert not evaluate_vulnerabilities({'api_candidates': [row]})['findings']


def test_library_names_algorithm_strings_do_not_create_findings():
    result = evaluate_vulnerabilities({'frameworks': ['crypto', 'WebView'],
            'network_indicators': {'path_candidates': ['/supersonicads', 'MD5', 'SHA1'], 'network_urls': ['http://a']},
            'api_candidates': [{'method': 'POST', 'path': '/signup', 'framework': 'Fuel'}]})
    assert not result['findings']
    assert not result['candidates']
    assert result['indicators'][0]['evidence_tier'] == 'indicator'


def test_network_config_finding_exact_source_and_refs():
    source = {'manifest': {'application': {'network_security_config': '@xml/network'},
              'network_security_policy': {'status': 'resolved', 'cleartext_permissions': [
                  {'value': True, 'source': 'res/xml/network.xml', 'component': 'base-config'}]}}}
    row = evaluate_vulnerabilities(source)['findings'][0]
    assert finding_is_eligible(row)
    assert row['control_id'] == 'STATIC-NET-CLEARTEXT'
    assert row['standards']['masvs_control_refs'] == ['MASVS-NETWORK-1']
    assert row['reason_code'] == 'NETWORK_CONFIG_CLEARTEXT_ALLOWED'


@pytest.mark.parametrize('field,value', [('control_id', 'STATIC-CRYPTO-WEAK'),
    ('standards', {'masvs_category': 'MASVS-CODE', 'masvs_control_refs': ['MASVS-CODE-99']})])
def test_finding_gate_rejects_forged_catalog_mapping(field, value):
    row = debug_result()['findings'][0]
    row[field] = value
    assert not finding_is_eligible(row)
    with pytest.raises(ValueError):
        validate_evidence_record(row)


def test_duplicate_catalog_control_rejected():
    catalog = load_catalog()
    catalog['controls'].append(copy.deepcopy(catalog['controls'][0]))
    with pytest.raises(ValueError, match='DUPLICATE_CONTROL'):
        validate_catalog(catalog)
