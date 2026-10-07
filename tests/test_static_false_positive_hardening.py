from copy import deepcopy
import json
from pathlib import Path
import pytest
from src.api_candidate_extractor import extract_api_candidates
from src.vulnerability_evaluator import evaluate_vulnerabilities, classify_ip
from src.report_generator import build_static_analysis_report
from src.static_security.catalog import load_catalog, finding_is_eligible


def call(url='http://api.company.com/profile', source='smali/app/Network.smali', line=12, **extra):
    return {'method': 'GET', 'full_url': url, 'source_file': source, 'request_line': line,
            'resolution_state': 'resolved', **extra}


@pytest.mark.parametrize('value', [
 'http://docs.company.com', 'http://www.w3.org/2001/XMLSchema', 'http://example.com/sample',
 'http://localhost/profile', 'http://127.0.0.1/signup', 'file:///android_asset/web.html',
 'http://sdk.analytics.com', 'http://unused.company.com', 'http://a'])
def test_network_literals_never_findings(value):
    result = evaluate_vulnerabilities({'network_indicators': {'network_urls': [
        {'value': value, 'source_file': 'res/values/strings.xml'}]}})
    assert not result['findings']
    assert all('severity' not in row for row in result['indicators'])


@pytest.mark.parametrize('value', ['/supersonicads', '/super', 'su', '/system/bin/su',
    'RootChecker', 'debugCheck', 'MD5', 'SHA1', 'SHA256', 'SharedPreferences',
    'accounts.db', 'token', 'password', 'secret', 'login', 'analytics_id'])
def test_resilience_crypto_storage_auth_privacy_noise(value):
    result = evaluate_vulnerabilities({'network_indicators': {'path_candidates': [value]},
                                     'libraries': [value], 'variables': [value],
                                     'coverage_limitations': [value]})
    assert not result['findings']
    assert all('severity' not in row for row in result['indicators'] + result['candidates'])
    if value == '/system/bin/su':
        assert result['candidates'][0]['reason_code'] == 'EXACT_ROOT_BINARY_PATH'


@pytest.mark.parametrize('context', ['comment', 'documentation', 'resource', 'unused_literal'])
def test_non_executable_provenance_cannot_claim_call(context):
    assert not evaluate_vulnerabilities({'api_candidates': [call(evidence_context=context)]})['findings']


@pytest.mark.parametrize('source', ['res/values/strings.xml', 'assets/help.html', 'README.md'])
def test_resource_fake_call_metadata_rejected(source):
    assert not evaluate_vulnerabilities({'api_candidates': [call(source=source)]})['findings']


@pytest.mark.parametrize('extra', [{'ownership': 'third_party'},
    {'source_component': 'Lokhttp3/internal/Helper;'},
    {'source_component': 'Lcom/android/volley/Helper;'},
    {'source_component': 'Lio/ktor/client/Helper;'}])
def test_explicit_third_party_is_context_not_first_party_finding(extra):
    result = evaluate_vulnerabilities({'api_candidates': [call(**extra)]})
    assert not result['findings']
    assert result['indicators'][0]['ownership'] == 'third_party'
    assert 'severity' not in result['indicators'][0]


def test_unknown_owner_never_guessed_from_domain_or_framework():
    result = evaluate_vulnerabilities({'api_candidates': [call(framework='okhttp')]})
    assert result['findings'][0]['ownership'] == 'unknown'
    assert finding_is_eligible(result['findings'][0])


def test_legitimate_cleartext_call_positive_and_noise_isolated():
    result = evaluate_vulnerabilities({'api_candidates': [call()],
        'network_indicators': {'network_urls': ['http://unused.company.com']}})
    assert len(result['findings']) == 1
    assert result['findings'][0]['reason_code'] == 'HTTP_NETWORK_CALL_CONTEXT'
    assert result['findings'][0]['severity'] == 'HIGH'


def test_duplicates_do_not_raise_severity_or_count():
    one = evaluate_vulnerabilities({'api_candidates': [call()]})
    many = evaluate_vulnerabilities({'api_candidates': [call()] * 30})
    assert one == many


def test_distinct_components_not_merged_and_reorder_stable():
    inputs = [call(), call(source='smali/app/Other.smali')]
    a = evaluate_vulnerabilities({'api_candidates': inputs})
    b = evaluate_vulnerabilities({'api_candidates': inputs[::-1]})
    assert a == b
    assert len(a['findings']) == 2
    assert len({r['finding_instance_id'] for r in a['findings']}) == 2


def test_global_policy_and_calls_one_issue_all_evidence_preserved():
    inputs = [call(), call(source='smali/app/Other.smali')]
    source = {'manifest': {'application': {'uses_cleartext_traffic': True}}, 'api_candidates': inputs}
    before = deepcopy(source)
    result = evaluate_vulnerabilities(source)
    assert source == before
    assert len(result['findings']) == 1
    row = result['findings'][0]
    assert len(row['supporting_evidence']) == 3
    assert len(row['supporting_provenance_refs']) == 3
    assert row['severity'] == 'HIGH'
    assert finding_is_eligible(row)
    assert result == evaluate_vulnerabilities({**source, 'api_candidates': inputs[::-1]})


def test_separate_config_scopes_preserved_duplicates_suppressed():
    first = {'value': True, 'source': 'res/xml/network.xml', 'component': 'domain-config[1]'}
    second = {**first, 'component': 'domain-config[2]'}
    source = {'manifest': {'application': {'network_security_config': '@xml/network'},
        'network_security_policy': {'status': 'resolved', 'cleartext_permissions': [first, second, first]}}}
    res = evaluate_vulnerabilities(source)
    assert not res['findings']
    rows = res['candidates']
    assert len(rows) == 2
    assert {r['component'] for r in rows} == {first['component'], second['component']}


def test_merged_framework_provenance_not_lost():
    origins = [call(evidence_ref='ref_fuel', framework='Fuel'), call(evidence_ref='ref_okhttp', framework='okhttp')]
    result = evaluate_vulnerabilities({'api_candidates': [{**origins[0], 'provenance': origins}]})
    assert len(result['findings']) == 1
    refs = {ref for r in result['findings'][0]['supporting_evidence'] for ref in r.get('source_evidence_refs', [])}
    assert refs == {'ref_fuel', 'ref_okhttp'}


def test_stale_findings_secrets_and_noise_not_in_static_report():
    source = {'platform': 'android', 'manifest': {'application': {'debuggable': True}},
        'network_indicators': {'network_urls': ['http://noise.company.com/?token=RAW_SECRET']},
        'vulnerabilities': {'findings': [{'id': 'fake', 'severity': 'CRITICAL', 'evidence': 'RAW_SECRET'}]},
        'api_candidates': [call('http://api.company.com/profile?password=RAW_SECRET')]}
    report = build_static_analysis_report('c9', report_dict=source)
    serialized = json.dumps(report['vulnerabilities'])
    assert 'RAW_SECRET' not in serialized and 'fake' not in serialized
    assert all(r['classification'] == 'finding' for r in report['vulnerabilities']['findings'])
    assert all(r['evidence_tier'] == 'finding_eligible' for r in report['vulnerabilities']['findings'])
    for row in report['vulnerabilities']['findings']:
        assert row['impact'].endswith('.') and row['remediation'].endswith('.') and row['evidence'].endswith('.')


def test_coverage_and_unsupported_controls_never_pass_or_findings():
    result = evaluate_vulnerabilities({'coverage': {'status': 'partial'}, 'crypto_calls': ['MD5']})
    assert not result['findings']
    assert all(r['assessment_state'] in {'unknown', 'not_evaluated'} for r in result['control_coverage'])
    assert len(load_catalog()['controls']) == 16
    assert classify_ip('127.0.0.1') == 'loopback'


def test_comment_only_smali_and_resources_not_api_candidates(tmp_path):
    smali = tmp_path / 'smali'; smali.mkdir()
    (smali / 'Noise.smali').write_text(''' .class public Lapp/Noise;
.super Ljava/lang/Object;
.method public probe()V
# const-string v0, "http://api.company.com/profile"
# invoke-static {v0}, Lcom/github/kittinunf/fuel/Fuel;->get(Ljava/lang/String;)V
# invoke-virtual {v1, v0}, Lokhttp3/Request$Builder;->url(Ljava/lang/String;)Lokhttp3/Request$Builder;
# invoke-direct {v1, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
return-void
.end method
''')
    resources = tmp_path / 'res/values'; resources.mkdir(parents=True)
    (resources / 'strings.xml').write_text('<resources><string name="url">http://unused.company.com/profile</string></resources>')
    assert extract_api_candidates(tmp_path)['api_candidates'] == []


def test_same_http_issue_multiple_call_lines_merge_all_refs():
    inputs = [call(line=12), call(line=25)]
    result = evaluate_vulnerabilities({'api_candidates': inputs})
    assert len(result['findings']) == 1
    row = result['findings'][0]
    assert row['affected_items'] == ['network call at line 12', 'network call at line 25']
    assert len(row['supporting_provenance_refs']) == 2
    assert finding_is_eligible(row)
    assert result == evaluate_vulnerabilities({'api_candidates': inputs[::-1]})


def test_distinct_source_components_remain_distinct():
    inputs = [call(source_component='Lapp/One;'), call(source_component='Lapp/Two;')]
    assert len(evaluate_vulnerabilities({'api_candidates': inputs})['findings']) == 2


def test_top_level_unresolved_cannot_borrow_resolved_provenance():
    candidate = {**call(), 'resolution_state': 'unresolved', 'provenance': [call()]}
    assert not evaluate_vulnerabilities({'api_candidates': [candidate]})['findings']
