import copy
import json
from pathlib import Path
import pytest
from src.manifest_parser import parse_manifest
from src.static_permission_usage import extract_permission_usage, load_catalog
from src.vulnerability_evaluator import evaluate_vulnerabilities

SMS = 'Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V'
CAMERA = 'Landroid/hardware/Camera;->open(I)Landroid/hardware/Camera;'
QUERY = 'Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;'

def fixture(tmp_path, signatures=(), permissions=(), extra='', owner='La/Main;'):
    manifest = tmp_path / 'AndroidManifest.xml'
    manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="a"><uses-sdk android:targetSdkVersion="33"/>'+''.join('<uses-permission android:name="android.permission.'+p+'"/>' for p in permissions)+'<application><activity android:name="a.Main"/></application></manifest>')
    smali = tmp_path / 'smali/a/Main.smali'; smali.parent.mkdir(parents=True, exist_ok=True)
    smali.write_text('.class public '+owner+'\n.super Landroid/app/Activity;\n.method public test()V\n'+extra+'\n'+''.join(' invoke-virtual {v0, v1, v2, v3, v4, v5}, '+s+'\n' for s in signatures)+'.end method\n')
    return parse_manifest(manifest), smali


def test_catalog_version_sources_and_all_groups():
    catalog = load_catalog()
    assert catalog['catalog_version'] == 'android_permission_api_v1'
    assert {'location','camera','microphone','contacts','sms','storage_media','bluetooth','notifications'} <= {r['category'] for r in catalog['entries']}
    assert all(r['official_source'].startswith('https://developer.android.com/') for r in catalog['entries'])

@pytest.mark.parametrize('entry', [r for r in load_catalog()['entries'] if r['context_rule'] in ('direct','any_of')], ids=lambda r:r['signature'])
def test_exact_supported_call_and_declaration(tmp_path, entry):
    manifest, _ = fixture(tmp_path, [entry['signature']], [entry['permissions'][0].split('.')[-1]])
    result = extract_permission_usage(tmp_path, manifest)
    row = result['evidence'][0]
    assert row['declaration_state'] == 'matching_declaration'
    assert row['source'] == 'smali/a/Main.smali' and row['method'] == 'test()V' and row['line'] > 0
    assert row['application_linkage'] == 'manifest_component'
    assert row['usage_state'] == 'usage_observed'
    assert row['finding_created'] is False and row['runtime_confirmed'] is False


def test_missing_declaration_indicator_not_finding(tmp_path):
    manifest,_=fixture(tmp_path,[SMS])
    row=extract_permission_usage(tmp_path,manifest)['evidence'][0]
    assert row['declaration_state']=='used_without_matching_declaration' and row['classification']=='indicator'
    assert not evaluate_vulnerabilities({'permission_usage': {'evidence':[row]}})['findings']


def test_declaration_only_not_unused_or_finding(tmp_path):
    manifest,_=fixture(tmp_path,permissions=['CAMERA'])
    result=extract_permission_usage(tmp_path,manifest)
    assert not result['evidence']
    assert result['declarations'][0]['usage_state']=='usage_not_observed_in_analyzed_code'
    assert result['declarations'][0]['classification']=='metadata'

@pytest.mark.parametrize('noise', ['const-string v0, "'+SMS+'"', '# invoke-virtual {v0}, '+SMS, '.local v0, "android.hardware.Camera":Ljava/lang/String;', 'invoke-virtual {v0}, '+CAMERA.replace('(I)', '(Ljava/lang/String;)')])
def test_string_class_comment_and_wrong_overload_not_usage(tmp_path, noise):
    manifest,_=fixture(tmp_path,extra=noise)
    assert not extract_permission_usage(tmp_path,manifest)['evidence']


def test_unlinked_sdk_not_missing_declaration_claim(tmp_path):
    manifest,_=fixture(tmp_path,[CAMERA],owner='Lcom/google/sdk/Camera;')
    row=extract_permission_usage(tmp_path,manifest)['evidence'][0]
    assert row['code_origin']=='sdk_library' and row['application_linkage']=='unlinked'
    assert row['classification']=='metadata'


def test_bounded_dependency_linkage_provenance(tmp_path):
    manifest,_=fixture(tmp_path,['Lcom/google/sdk/Camera;->capture()V'])
    sdk=tmp_path/'smali/sdk.smali'
    sdk.write_text('.class public Lcom/google/sdk/Camera;\n.method public capture()V\n invoke-static {v0}, '+CAMERA+'\n.end method')
    row=extract_permission_usage(tmp_path,manifest)['evidence'][0]
    assert row['code_origin']=='sdk_library' and row['application_linkage']=='direct_call_chain'
    assert row['linkage_provenance'][0]['method']=='test()V'


def test_contacts_requires_uri_provenance(tmp_path):
    manifest,_=fixture(tmp_path,[QUERY],permissions=['READ_CONTACTS'])
    row=extract_permission_usage(tmp_path,manifest)['evidence'][0]
    assert row['possible_permissions']==[] and row['access_context']=='unresolved_or_alternative_access'
    manifest,_=fixture(tmp_path,[QUERY],permissions=['READ_CONTACTS'],extra='sget-object v1, Landroid/provider/ContactsContract$Contacts;->CONTENT_URI:Landroid/net/Uri;')
    row=extract_permission_usage(tmp_path,manifest)['evidence'][0]
    assert row['uri_context']=='contacts' and row['manifest_refs']


def test_uri_overwrite_and_branch_invalidate(tmp_path):
    for suffix in ['const/4 v1, 0x0','if-eqz v0, :other','invoke-static {}, Lunknown/X;->x()V']:
        manifest,_=fixture(tmp_path,[QUERY],extra='sget-object v1, Landroid/provider/ContactsContract$Contacts;->CONTENT_URI:Landroid/net/Uri;\n'+suffix)
        assert extract_permission_usage(tmp_path,manifest)['evidence'][0]['possible_permissions']==[]


def test_media_uri_context_no_read_permission_guess(tmp_path):
    manifest,_=fixture(tmp_path,[QUERY],extra='sget-object v1, Landroid/provider/MediaStore$Images$Media;->CONTENT_URI:Landroid/net/Uri;')
    row=extract_permission_usage(tmp_path,manifest)['evidence'][0]
    assert row['uri_context']=='media' and row['classification']=='metadata'
    assert row['access_context']=='unresolved_or_alternative_access'


def test_conditional_sdk_notifications_and_bluetooth(tmp_path):
    entries=[r for r in load_catalog()['entries'] if r['category'] in ('notifications','bluetooth')]
    manifest,_=fixture(tmp_path,[r['signature'] for r in entries])
    rows=extract_permission_usage(tmp_path,manifest)['evidence']
    assert all(r['classification']=='metadata' and r['target_sdk']==33 for r in rows)
    assert all(r['access_context']=='unresolved_or_alternative_access' for r in rows)


def test_manifest_flags_scoped_permissions_not_false_mismatch(tmp_path):
    manifest,_=fixture(tmp_path,[CAMERA],permissions=['CAMERA'])
    manifest['permission_declarations'][0]['max_sdk']=22
    row=extract_permission_usage(tmp_path,manifest)['evidence'][0]
    assert row['declaration_state']=='conditional_declaration'
    path=tmp_path/'AndroidManifest.xml'
    path.write_text(path.read_text().replace('android:name="android.permission.CAMERA"','android:name="android.permission.CAMERA" android:usesPermissionFlags="neverForLocation"'))
    assert parse_manifest(path)['permission_declarations'][0]['uses_permission_flags']=='neverForLocation'


def test_determinism_no_secret_and_source_apk_scope(tmp_path):
    manifest,_=fixture(tmp_path,[SMS],extra='const-string v9, "private-token-value"')
    first=extract_permission_usage(tmp_path,manifest)
    assert first==extract_permission_usage(tmp_path,manifest)
    assert 'private-token-value' not in json.dumps(first)
    second=extract_permission_usage(tmp_path,manifest,source_apk='split.apk')
    assert first['evidence'][0]['evidence_id']!=second['evidence'][0]['evidence_id']


def test_manifest_unavailable_does_not_assert_missing(tmp_path):
    manifest,_=fixture(tmp_path,[SMS]);manifest['manifest_available']=False
    assert extract_permission_usage(tmp_path,manifest)['evidence'][0]['classification']=='metadata'


def test_duplicate_component_is_ambiguous(tmp_path):
    manifest,path=fixture(tmp_path,[SMS]);(tmp_path/'smali/duplicate.smali').write_text(path.read_text())
    assert all(r['classification']=='metadata' for r in extract_permission_usage(tmp_path,manifest)['evidence'])


def test_symlink_excluded(tmp_path):
    manifest,path=fixture(tmp_path,[SMS]);path.rename(tmp_path/'source.txt');path.symlink_to(tmp_path/'source.txt')
    result=extract_permission_usage(tmp_path,manifest)
    assert not result['evidence'] and 'unsafe_source_skipped' in result['coverage']['limitations']


def test_report_preserves_metadata_without_finding(tmp_path):
    from src.report_generator import build_report_dict
    manifest,_=fixture(tmp_path,[SMS]);result=extract_permission_usage(tmp_path,manifest)
    report=build_report_dict('permission-smoke', {'static_analysis':{'permission_usage':result}})
    assert report['permission_usage']==result


def test_range_call_uri_and_alias(tmp_path):
    manifest,path=fixture(tmp_path,extra='sget-object v7, Landroid/provider/ContactsContract$Contacts;->CONTENT_URI:Landroid/net/Uri;\nmove-object v1, v7\ninvoke-virtual/range {v0 .. v5}, '+QUERY)
    assert extract_permission_usage(tmp_path,manifest)['evidence'][0]['uri_context']=='contacts'


def test_fake_provider_class_cannot_prove_permission(tmp_path):
    manifest,_=fixture(tmp_path,[QUERY],extra='sget-object v1, Landroid/provider/ContactsContractFake;->CONTENT_URI:Landroid/net/Uri;')
    assert extract_permission_usage(tmp_path,manifest)['evidence'][0]['possible_permissions']==[]


def test_depth_and_cycle_are_bounded(tmp_path):
    manifest,_=fixture(tmp_path,['La/Helper1;->test()V'])
    for number in range(1,6):
        target='La/Helper'+str(number+1)+';->test()V' if number<5 else SMS
        (tmp_path/f'smali/helper{number}.smali').write_text(f'.class public La/Helper{number};\n.method public test()V\n invoke-static {{v0}}, {target}\n invoke-static {{v0}}, La/Main;->test()V\n.end method')
    row=extract_permission_usage(tmp_path,manifest)['evidence'][0]
    assert row['application_linkage']=='unlinked' and row['classification']=='metadata'


def test_budget_limit_honest(tmp_path,monkeypatch):
    import src.static_permission_usage as module
    manifest,_=fixture(tmp_path,[SMS,CAMERA]);monkeypatch.setattr(module,'MAX_CALLS',1)
    result=extract_permission_usage(tmp_path,manifest)
    assert len(result['evidence'])==1
    assert 'analysis_budget_reached' in result['coverage']['limitations']


def test_sdk_declaration_context_preserved(tmp_path):
    manifest,_=fixture(tmp_path,[SMS],permissions=['SEND_SMS'])
    manifest['permission_declarations'][0]['tag']='uses-permission-sdk-23'
    result=extract_permission_usage(tmp_path,manifest)
    assert result['evidence'][0]['declaration_state']=='conditional_declaration'
    assert result['evidence'][0]['manifest_refs']==manifest['permission_declarations']


def test_canonical_report_preserves_permission_refs(tmp_path):
    from src.report_generator import build_report_dict, build_static_analysis_report
    manifest,_=fixture(tmp_path,[SMS]);metadata=extract_permission_usage(tmp_path,manifest)
    base=build_report_dict('permission-smoke',{'static_analysis':{'permission_usage':metadata}})
    canonical=build_static_analysis_report('permission-smoke', report_dict=base)
    assert canonical['permission_usage']==metadata


def test_input_declaration_order_stable(tmp_path):
    manifest,_=fixture(tmp_path,[SMS],permissions=['SEND_SMS','CAMERA'])
    first=extract_permission_usage(tmp_path,manifest)
    manifest['permission_declarations'].reverse()
    assert first==extract_permission_usage(tmp_path,manifest)


def test_single_static_context_pipeline_wiring(tmp_path):
    from src.static_context_builder import build_static_context
    manifest,_=fixture(tmp_path,[SMS],permissions=['SEND_SMS'])
    raw=tmp_path/'raw';raw.mkdir();(raw/'classes.dex').write_bytes(b'dex\n035\x00')
    context=build_static_context(tmp_path/'AndroidManifest.xml',raw,tmp_path)
    assert context['permission_usage']['evidence'][0]['declaration_state']=='matching_declaration'


def test_split_union_declarations_and_scoped_provenance(tmp_path):
    from src.static_permission_usage import aggregate_permission_usage
    one=tmp_path/'base';one.mkdir();base,_=fixture(one,permissions=['CAMERA'])
    two=tmp_path/'feature';two.mkdir();feature,_=fixture(two,[CAMERA])
    manifests=[{'source_apk':'base.apk','manifest':base},{'source_apk':'feature.apk','manifest':feature}]
    metadata=aggregate_permission_usage([('feature.apk',two),('base.apk',one)],manifests,base)
    row=metadata['evidence'][0]
    assert row['declaration_state']=='matching_declaration'
    assert row['source_apk']=='feature.apk' and row['manifest_refs'][0]['source_apk']=='base.apk'
    assert metadata==aggregate_permission_usage([('base.apk',one),('feature.apk',two)],list(reversed(manifests)),base)


def test_intent_alternative_not_protected_use(tmp_path):
    entry=next(r for r in load_catalog()['entries'] if r['context_rule']=='alternative')
    manifest,_=fixture(tmp_path,[entry['signature']])
    row=extract_permission_usage(tmp_path,manifest)['evidence'][0]
    assert row['possible_permissions']==[] and row['classification']=='metadata'
    assert row['access_context']=='unresolved_or_alternative_access'
