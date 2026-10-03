"""M4 inventory is evidence, not a proven API or framework inference from docs."""
from pathlib import Path
import pytest
from src.network_indicator_extractor import extract_network_indicators
from src.demo3.pattern_extractor import extract_candidates_from_text
from src.api_candidate_extractor import extract_api_candidates
from src.static_inventory import indicator_context, runtime_technologies, FLUTTER_COVERAGE
from src.report_generator import build_static_analysis_report
from src.web.report_summary import build_report_summary


@pytest.mark.parametrize('value',['config.ar','config.be','config.bg','config.de','config.tr','config.uk'])
def test_split_identifier_not_network_domain(tmp_path,value):
    p=tmp_path/'res/xml';p.mkdir(parents=True)
    line=f'<entry key="locale" split="{value}" />'
    (p/'splits0.xml').write_text(line)
    assert extract_network_indicators(tmp_path)['domains']==[]
    assert not any(r.type=='domain' for r in extract_candidates_from_text(line,'res/xml/splits0.xml',1))


def test_legitimate_country_domain_and_non_metadata_config_hostname_kept(tmp_path):
    (tmp_path/'hosts.txt').write_text('api.example.tr config.tr')
    assert {r['value'] for r in extract_network_indicators(tmp_path)['domains']}=={'api.example.tr','config.tr'}
    assert any(r.type=='domain' for r in extract_candidates_from_text('api.example.tr','hosts.txt',1))


@pytest.mark.parametrize('url,context',[
    ('https://developer.android.com/reference/android/view/View','framework_documentation'),
    ('https://docs.flutter.dev/deployment/android','framework_documentation'),
    ('https://github.com/flutter/flutter/issues/165510','framework_repository_or_issue_tracker')])
def test_documentation_retained_with_provenance_without_endpoint(tmp_path,url,context):
    (tmp_path/'notes.txt').write_text(url)
    row=extract_network_indicators(tmp_path)['network_urls'][0]
    assert row['inventory_context']==context and row['backend_confirmed'] is False
    assert row['source_file']=='notes.txt' and row['line_number']==1
    assert extract_api_candidates(tmp_path)['api_candidates']==[]
    summary=build_report_summary({'network_indicators':{'network_urls':[row]},'api_candidates':[]})
    assert summary['static_summary']['network_indicators']['hosts']==[]


def test_flutter_embedding_proven_without_documentation_inference():
    structure={'components':[{'source_apk':'base.apk','assets':['assets/flutter_assets/AssetManifest.bin']},
        {'source_apk':'split_config.arm64_v8a.apk','native_libraries':['lib/arm64-v8a/libflutter.so']} ]}
    tech=runtime_technologies(structure)
    assert tech[0]['name']=='Flutter' and len(tech[0]['evidence'])==2
    report=build_static_analysis_report('flutter',report_dict={'platform':'android','structure':structure,'api_candidates':[]})
    assert report['runtime_technologies']==tech and report['api_candidates']==[]
    assert FLUTTER_COVERAGE in report['limitations']
    summary=build_report_summary(report)['static_summary']
    assert summary['runtime_technologies']==['Flutter'] and summary['frameworks_detected']==[]
    assert FLUTTER_COVERAGE in summary['coverage_limitations']
    assert runtime_technologies({'assets':['assets/docs.flutter.dev.txt']})==[]
    no_flutter=build_report_summary({'network_indicators':{'network_urls':['https://docs.flutter.dev/']}})['static_summary']
    assert no_flutter['runtime_technologies']==[] and FLUTTER_COVERAGE not in no_flutter['coverage_limitations']


def test_license_and_flutter_channel_are_not_confirmed_backend():
    assert indicator_context('https://license.vendor.com','assets/LICENSE.txt')=='documentation_or_license'
    assert indicator_context('io.flutter.network','smali/Flutter.smali')=='framework_metadata'


def test_inventory_labels_are_indicators_and_api_count_separate():
    template=Path('src/templates/dashboard.html').read_text()
    assert 'canonical network indicators</span>' in template
    assert 'canonical candidates</span>' not in template
    assert 'Indicator hosts (unconfirmed)' in template
    assert "pair('API candidates', stat.api_candidates_count)" in template
