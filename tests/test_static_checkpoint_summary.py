"""C10 regressions: Static summary must reflect existing C7/C8 metadata."""
from copy import deepcopy
from src.web.report_summary import build_report_summary
from src.static_security.catalog import coverage_records


def test_static_summary_preserves_all_supported_merged_frameworks():
    source = {'api_candidates': [{'framework': 'Fuel', 'frameworks':
        ['Fuel', 'Retrofit', 'okhttp', 'volley', 'httpurlconnection', 'ktor', 'fake']} ]}
    before = deepcopy(source)
    summary = build_report_summary(source)['static_summary']
    assert summary['frameworks_detected'] == ['Fuel', 'Retrofit', 'httpurlconnection', 'ktor', 'okhttp', 'volley']
    assert summary['api_candidates_count'] == 1
    assert source == before


def test_static_summary_exposes_catalog_and_unresolved_coverage_without_pass():
    source = {'api_candidates': [], 'vulnerabilities': {'control_coverage': coverage_records([])},
              'api_discovery': {'retrofit': {'unresolved_declarations': [{'path': '/orders'}]}}}
    summary = build_report_summary(source)['static_summary']
    text = ' '.join(summary['coverage_limitations'])
    assert 'MASVS-CRYPTO' in text and 'partial or unavailable' in text
    assert 'unresolved networking is not absence' in text
    assert summary['api_candidates_count'] == 0
    assert 'secure' not in text.lower()


def test_static_summary_legacy_single_framework_preserved():
    summary = build_report_summary({'api_candidates': [{'framework':'okhttp'}]})['static_summary']
    assert summary['frameworks_detected'] == ['okhttp']


def test_canonical_static_report_split_metadata_order_stable():
    from src.report_generator import build_static_analysis_report
    pipeline = {'static_analysis': {'app': {'package_name': 'app.training'}, 'package_layout': 'split',
        'split_count': 2, 'manifest': {'package_name': 'app.training'}, 'structure': {}},
        'acquisition': {'package_layout': 'split', 'components': [
            {'filename': 'base.apk', 'role': 'base'}, {'filename': 'split_config.en.apk', 'role': 'config'}]},
        'preprocessing': {'components': [
            {'filename': 'base.apk', 'role': 'base'}, {'filename': 'split_config.en.apk', 'role': 'config'}]}}
    first = build_static_analysis_report('c10', pipeline_result=deepcopy(pipeline))
    pipeline['acquisition']['components'].reverse()
    pipeline['preprocessing']['components'].reverse()
    second = build_static_analysis_report('c10', pipeline_result=deepcopy(pipeline))
    first.pop('generated_at', None); second.pop('generated_at', None)
    assert first == second
