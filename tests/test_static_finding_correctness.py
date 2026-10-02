import json
from pathlib import Path
import pytest
from src.vulnerability_evaluator import evaluate_vulnerabilities, classify_ip
from src.manifest_parser import parse_manifest
from src.web.report_summary import build_report_summary
from src.report_generator import build_static_analysis_report

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('value,expected', [('127.0.0.1','loopback'),('127.8.9.1','loopback'),('::1','loopback'),('10.1.2.3','RFC1918 private'),('172.16.0.1','RFC1918 private'),('192.168.1.1','RFC1918 private'),('169.254.1.1','link-local'),('8.8.8.8','public'),('10.999.0.1','invalid')])
def test_ip_ranges(value, expected):
    assert classify_ip(value) == expected

@pytest.mark.parametrize('path,expected', [('/supersonicads',False),('/sure/thing',False),('/system/bin/super',False),('/system/bin/su',True),('/sbin/su',True),('/su/bin/su',True)])
def test_exact_root_paths_remain_non_findings(path, expected):
    result = evaluate_vulnerabilities({'network_indicators': {'path_candidates': [{'value':path,'source_file':'smali/Test.smali'}]}})
    assert not result['findings']
    assert bool(result['candidates']) == expected

@pytest.mark.parametrize('url', ['http://a','http://example.com/test','http://real-api.company.com/endpoint'])
def test_http_strings_are_only_indicators(url):
    result = evaluate_vulnerabilities({'network_indicators': {'network_urls': [url]}})
    assert not result['findings']
    assert result['indicators'][0]['classification'] == 'indicator'


def test_api_candidate_without_call_provenance_not_finding():
    assert not evaluate_vulnerabilities({'api_candidates':[{'method':'GET','full_url':'http://real.company.com/test'}]})['findings']


def test_owasp_network_call_and_debuggable_still_supported():
    source = json.loads((ROOT/'demo_runs/preset_android_monolithic/static_analysis_report.json').read_text())
    source['manifest'] = {'application':{'debuggable': True}}
    result = evaluate_vulnerabilities(source)
    assert {row['id'] for row in result['findings']} == {'SEC-CODE-01','SEC-NET-01'}
    for row in result['findings']:
        for key in ('finding_type','severity','evidence_type','source','component','observed_value','reason_code','standards','impact','remediation'):
            assert key in row
        assert row['classification'] == 'finding'
    assert source['api_candidates'][0]['path'] == '/signup'


def test_manifest_security_facts_and_unknowns(tmp_path):
    path = tmp_path/'AndroidManifest.xml'
    path.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="training.app">
      <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="34"/>
      <uses-permission-sdk-23 android:name="android.permission.CAMERA" android:maxSdkVersion="32"/>
      <application android:debuggable="true" android:allowBackup="false" android:usesCleartextTraffic="@bool/unknown" android:enabled="false">
        <activity android:name=".Main" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
        <service android:name=".Service" android:exported="false"/><receiver android:name=".Receiver"/>
        <provider android:name=".Provider" android:exported="true" android:readPermission="training.permission.READ"/>
        <activity-alias android:name=".Alias" android:targetActivity=".Main"/>
      </application></manifest>''')
    result = parse_manifest(path)
    assert result['min_sdk']==23 and result['target_sdk']==34
    assert result['application']['debuggable'] is True
    assert result['application']['allow_backup'] is False
    assert result['application']['uses_cleartext_traffic'] is None
    assert result['permissions']==['android.permission.CAMERA']
    assert len(result['components'])==5
    assert result['launcher_activity'] is None
    assert all(row['enabled_effective'] is False for row in result['components'])
    assert result['providers'][0]['read_permission']=='training.permission.READ'


def test_nsc_overrides_manifest_flag_without_guessing(tmp_path):
    path = tmp_path/'AndroidManifest.xml'
    path.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="training.app"><application android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/net"/></manifest>')
    result = evaluate_vulnerabilities({'manifest':parse_manifest(path)})
    assert not result['findings']
    folder=tmp_path/'res/xml';folder.mkdir(parents=True)
    (folder/'net.xml').write_text('<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>')
    assert not evaluate_vulnerabilities({'manifest':parse_manifest(path)})['findings']
    (folder/'net.xml').write_text('<network-security-config><domain-config cleartextTrafficPermitted="true"><domain>training.local</domain></domain-config></network-security-config>')
    row=evaluate_vulnerabilities({'manifest':parse_manifest(path)})['findings'][0]
    assert row['reason_code']=='NETWORK_CONFIG_CLEARTEXT_ALLOWED'
    assert row['source']=='res/xml/net.xml'


def test_complete_report_sentences():
    text='A complete concise sentence with relevant supporting details, which exceeds the old display limit and must remain readable in full without cutting the last words or the final period.'
    result=build_report_summary({'vulnerabilities':{'findings':[{'title':'Issue','description':text,'evidence':text,'remediation':text}]}})
    row=result['static_security_report']['findings'][0]
    assert row['impact']==text and row['evidence']==text and row['remediation']==text


def test_static_report_does_not_reuse_stale_false_findings():
    source={'platform':'android','network_indicators':{'network_urls':['http://a']},
            'vulnerabilities':{'findings':[{'id':'stale','severity':'HIGH'}]}}
    result=build_static_analysis_report('test', report_dict=source)
    assert result['vulnerabilities']['findings']==[]


def test_apktool_sdk_metadata_is_explicit_and_does_not_override_manifest(tmp_path):
    path=tmp_path/'AndroidManifest.xml'
    path.write_text('<manifest package="training.app"><application/></manifest>')
    (tmp_path/'apktool.yml').write_text("sdkInfo:\n  minSdkVersion: '23'\n  targetSdkVersion: 34\nversionInfo:\n  targetSdkVersion: 99\n")
    result=parse_manifest(path)
    assert result['min_sdk']==23 and result['target_sdk']==34
    assert result['sdk_evidence']['target_sdk']=='apktool.yml: sdkInfo.targetSdkVersion'
    path.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="training.app"><uses-sdk android:targetSdkVersion="30"/><application/></manifest>')
    assert parse_manifest(path)['target_sdk']==30


def test_unresolved_manifest_boolean_and_sdk_not_guessed(tmp_path):
    path=tmp_path/'AndroidManifest.xml'
    path.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="training.app"><uses-sdk android:targetSdkVersion="@integer/sdk"/><application android:debuggable="@bool/debug"/></manifest>')
    (tmp_path/'apktool.yml').write_text('sdkInfo:\n  targetSdkVersion: 34\n')
    result=parse_manifest(path)
    assert result['target_sdk'] is None and result['application']['debuggable'] is None
    assert not evaluate_vulnerabilities({'manifest':result})['findings']


def test_denying_manifest_keeps_network_call_candidate():
    source={'manifest':{'application':{'uses_cleartext_traffic':False}},'api_candidates':[
        {'method':'GET','full_url':'http://api.company.com/profile','source_file':'smali/Network.smali','request_line':12}]}
    result=evaluate_vulnerabilities(source)
    assert not result['findings']
    assert result['candidates'][0]['reason_code']=='NETWORK_POLICY_REQUIRES_RUNTIME_CONFIRMATION'
