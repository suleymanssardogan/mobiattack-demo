"""C1 identity and isolation regressions; no network or security execution."""
import copy
import json
from pathlib import Path
from unittest.mock import patch
import pytest
from src.android_identity import canonical_candidates, canonical_components, AndroidIdentityError
from src.manifest_parser import parse_manifest
from src.android_runtime_launcher import normalize_component_name, AndroidRuntimeError
from src.url_classifier import classify_input_url
from src.split_static_context_builder import build_split_static_context
from src.split_acquirer import acquire_split_package_set
from src.play_store_acquirer import PlayStoreAcquisitionError


@pytest.mark.parametrize('url', [
 'https://play.google.com/store/apps/details?id=org.example',
 'https://play.google.com/store/apps/details?utm_source=demo&id=org.example&hl=tr',
 'https://play.google.com/store/apps/details/?id=org.example#tracking'])
def test_equivalent_play_urls(url):
    result = classify_input_url(url)
    assert result['normalized_url'] == 'https://play.google.com/store/apps/details?id=org.example'
    assert result['package_name'] == 'org.example'


@pytest.mark.parametrize('url', ['https://play.google.com/store/apps/detailsX?id=org.example',
 'https://play.google.com/store/apps/details?id=org.example&id=org.other',
 'https:///file.apk', 'https://user:password@example.com/file.apk'])
def test_invalid_android_urls(url):
    assert classify_input_url(url)['type'] == 'unsupported'


def manifest(tmp_path, application):
    path = tmp_path/'AndroidManifest.xml'
    path.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example"><application '+application+'</application></manifest>')
    return path


FILTER = '<intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>'


def test_alias_identity_and_target_are_preserved(tmp_path):
    data = parse_manifest(manifest(tmp_path, '><activity android:name=".Main"/><activity-alias android:name=".Alias" android:targetActivity=".Main">'+FILTER+'</activity-alias>'))
    assert data['launcher_activity'] == 'org.example.Alias'
    assert data['launcher_target_activity'] == 'org.example.Main'
    assert normalize_component_name(data['package_name'],data['launcher_activity']) == 'org.example/org.example.Alias'


@pytest.mark.parametrize('enabled', ['false', '@bool/enabled'])
def test_disabled_or_unresolved_application_enabled_blocks_launcher(tmp_path, enabled):
    data = parse_manifest(manifest(tmp_path, 'android:enabled="'+enabled+'"><activity android:name=".Main">'+FILTER+'</activity>'))
    assert data['launcher_activity'] is None
    assert data['launcher_status'] == 'LAUNCHER_UNRESOLVED'


@pytest.mark.parametrize('name', ['unknown', '.unknown', 'org.example.unknown'])
def test_unknown_never_executable(name):
    with pytest.raises(AndroidRuntimeError,match='LAUNCHER_UNRESOLVED'):
        normalize_component_name('org.example',name)


def test_launcher_and_manifest_declaration_order_independent(tmp_path):
    activities=['<activity android:name=".Z">'+FILTER+'</activity>','<activity android:name=".A">'+FILTER+'</activity>']
    first=parse_manifest(manifest(tmp_path,'>'+''.join(activities)))
    second=parse_manifest(manifest(tmp_path,'>'+''.join(reversed(activities))))
    assert first['launcher_activity']==second['launcher_activity']=='org.example.A'


def test_component_inventory_is_canonical():
    components=[{'filename':'split_config.en.apk','role':'config_locale'}, {'filename':'base.apk','role':'base'}]
    assert canonical_components(components)==canonical_components(list(reversed(components)))
    assert components[0]['filename']=='split_config.en.apk'


@pytest.mark.parametrize('components,code', [
 ([{'filename':'split_config.en.apk','role':'config_locale'}],'BASE_APK_NOT_FOUND'),
 ([{'filename':'base.apk','role':'base'},{'filename':'base.apk','role':'base'}],'SPLIT_SET_INCOMPLETE')])
def test_incomplete_or_duplicate_inventory_rejected(components, code):
    with pytest.raises(AndroidIdentityError) as error:canonical_components(components)
    assert error.value.reason_code==code


def test_candidate_ids_order_and_scan_isolation():
    a={'framework':'Fuel','method':'POST','base_url':'http://127.0.0.1','path':'/signup','source_file':'smali/A.smali','request_line':12}
    b={**a,'path':'/other','source_file':'smali/B.smali'}
    first=canonical_candidates([a,b])
    canonical_candidates([{**b,'base_url':'http://unrelated.example'}])
    assert first==canonical_candidates([b,a])
    assert 'candidate_id' not in a
    assert first[0]['candidate_id']!=first[1]['candidate_id']


@pytest.mark.parametrize('package,version,code', [('org.other','1','PACKAGE_MISMATCH'),('org.example','2','PACKAGE_MISMATCH')])
def test_manifest_package_and_version_mismatch_rejected(tmp_path, package, version, code):
    components=[]
    for name,pkg,v,role in [('base.apk','org.example','1','base'),('split_config.en.apk',package,version,'config_locale')]:
        folder=tmp_path/name
        folder.mkdir()
        (folder/'AndroidManifest.xml').write_text(f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{pkg}" android:versionCode="{v}"/>')
        components.append({'filename':name,'role':role,'preprocessing':{'apktool_dir':str(folder)}})
    with pytest.raises(AndroidIdentityError) as error:
        build_split_static_context({'package_name':'org.example','components':components},tmp_path/'unified')
    assert error.value.reason_code==code


def test_duplicate_acquisition_leaves_no_publishable_package_set(tmp_path):
    with patch('src.play_store_acquirer.pull_device_apk') as pull:
        with pytest.raises(PlayStoreAcquisitionError) as error:
            acquire_split_package_set('org.example',tmp_path,'device','adb',remote_paths=['/a/base.apk','/b/base.apk'])
        assert error.value.reason_code=='SPLIT_SET_INCOMPLETE'
        pull.assert_not_called()
    assert not (tmp_path/'package_set').exists()


def test_prior_package_set_is_never_reused_or_overwritten(tmp_path):
    existing=tmp_path/'package_set'
    existing.mkdir()
    record=existing/'package_set.json';record.write_text('old user artifact')
    with pytest.raises(PlayStoreAcquisitionError):
        acquire_split_package_set('org.other',tmp_path,'device','adb',remote_paths=['/a/base.apk'])
    assert record.read_text()=='old user artifact'


def test_preflight_never_monkey_launches_unresolved_component():
    from src.dynamic.preflight.app_launcher import launch_application
    with patch('src.dynamic.preflight.app_launcher.run_adb_cmd', return_value=(0, 'No activity found', '')) as command:
        result=launch_application('adb','device','org.example')
    assert result[0] is False
    assert result[2].value=='LAUNCHER_UNRESOLVED'
    assert all('monkey' not in call.args[1] for call in command.call_args_list)


def test_preflight_rejects_foreign_package_component():
    from src.dynamic.preflight.app_launcher import launch_application
    with patch('src.dynamic.preflight.app_launcher.run_adb_cmd') as command:
        result=launch_application('adb','device','org.example','org.other/.Main')
        command.assert_not_called()
    assert result[0] is False


def test_failed_pull_rolls_back_entire_package_set(tmp_path):
    with patch('src.play_store_acquirer.pull_device_apk',side_effect=PlayStoreAcquisitionError('pull failed')):
        with pytest.raises(PlayStoreAcquisitionError) as error:
            acquire_split_package_set('org.example',tmp_path,'device','adb',remote_paths=['/a/base.apk'])
    assert error.value.reason_code=='SPLIT_SET_INCOMPLETE'
    assert list(tmp_path.iterdir())==[]


def test_split_merge_order_and_caller_isolation(tmp_path):
    from tests.test_split_static_context_builder import TestSplitStaticContextBuilder
    fixture=TestSplitStaticContextBuilder();fixture.setUp()
    try:
        original=copy.deepcopy(fixture.package_set)
        first=build_split_static_context(original,tmp_path/'first')
        reordered=copy.deepcopy(original);reordered['components'].reverse()
        second=build_split_static_context(reordered,tmp_path/'second')
        assert first==second
        assert original==fixture.package_set
    finally:fixture.tearDown()


def test_split_manifest_cannot_masquerade_as_authoritative_base(tmp_path):
    folder=tmp_path/'base';folder.mkdir()
    (folder/'AndroidManifest.xml').write_text('<manifest package="org.example" split="config.en"/>')
    package={'package_name':'org.example','components':[{'filename':'base.apk','role':'base','preprocessing':{'apktool_dir':str(folder)}}]}
    with pytest.raises(AndroidIdentityError) as error:
        build_split_static_context(package,tmp_path/'unified')
    assert error.value.reason_code=='BASE_APK_NOT_FOUND'
