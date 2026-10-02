from copy import deepcopy
import json
import pytest
from src.api_candidate_canonicalizer import canonicalize_api_candidates as canonical, bind_source_apk
from src.api_candidate_extractor import extract_api_candidates
from tests.test_okhttp_candidate_extractor import probe,builder,url,build


def candidate(framework='Fuel',uri='https://EXAMPLE.com:443/api',method='GET',source='smali/Probe.smali',line=10,**extra):
    return dict(framework=framework,method=method,path='/api',full_url=uri,base_url=None,
                source_file=source,source_component='Ltraining/Probe;',request_line=line,
                evidence={'request_call_line':line,'path_value':uri},**extra)


def test_same_endpoint_across_frameworks_one_identity():
    a=candidate();b=candidate('okhttp',source='smali/Other.smali',line=22)
    rows=canonical([a,b,a,deepcopy(b)])
    assert len(rows)==1
    row=rows[0]
    assert row['frameworks']==['Fuel','okhttp']
    assert len(row['provenance'])==len(set(row['evidence_refs']))==2
    assert row['scheme']=='https' and row['host']=='example.com' and row['port']==443
    assert row['full_url']=='https://example.com/api'
    assert {r['evidence']['request_call_line'] for r in row['provenance']}=={10,22}


def test_methods_and_schemes_ports_stay_distinct():
    values=[candidate(method='GET'),candidate(method='POST'),candidate(uri='http://example.com/api'),candidate(uri='https://example.com:8443/api')]
    rows=canonical(values)
    assert len(rows)==4 and len({r['candidate_id'] for r in rows})==4


@pytest.mark.parametrize('uri,port,full',[('http://example.com:80/api',80,'http://example.com/api'),('https://example.com:443/api',443,'https://example.com/api'),('https://example.com:8443/api',8443,'https://example.com:8443/api')])
def test_effective_ports(uri,port,full):
    a=canonical([candidate(uri=uri)])[0]
    b=canonical([candidate(uri=full)])[0]
    assert a['port']==port and a['full_url']==full and a['candidate_id']==b['candidate_id']


def test_query_values_not_identity_or_persisted():
    a=candidate(uri='https://example.com/search?q=VALUE&token=SECRET')
    b=candidate('okhttp',uri='https://example.com/search?token=OTHER&q=')
    rows=canonical([a,b])
    assert len(rows)==1 and rows[0]['query_keys']==['q','token']
    assert all(marker not in json.dumps(rows) for marker in ('VALUE','SECRET','OTHER'))
    assert canonical([a])[0]['candidate_id']==canonical([b])[0]['candidate_id']
    assert rows[0]['query_shape']['q']['value_present'] is True


def test_query_names_and_multiplicity_are_identity_shape():
    rows=canonical([candidate(uri='https://example.com/api?q=a'),candidate(uri='https://example.com/api?q=a&q=b'),candidate(uri='https://example.com/api?other=a')])
    assert len(rows)==3 and len({r['candidate_id'] for r in rows})==3


def test_encoded_path_normalization_preserves_slash_templates_case_and_literals():
    assert len(canonical([candidate(uri='https://example.com/%75sers/%7e'),candidate(uri='https://example.com/users/~')]))==1
    assert len(canonical([candidate(uri='https://example.com/a%2fb'),candidate(uri='https://example.com/a/b')]))==2
    assert len(canonical([candidate(uri='https://example.com/users/%7bid%7d'),candidate(uri='https://example.com/users/{id}')]))==2
    assert len(canonical([candidate(uri='https://example.com/Users/123'),candidate(uri='https://example.com/users/123')]))==2
    assert len(canonical([candidate(uri='https://example.com/users/123'),candidate(uri='https://example.com/users/456')]))==2
    assert canonical([candidate(uri='https://example.com/a%2fb')])[0]['path']=='/a%2Fb'


def test_dot_segments_and_duplicate_slashes_not_guessed_equivalent():
    assert len(canonical([candidate(uri='https://example.com/a/../b'),candidate(uri='https://example.com/b')]))==2
    assert len(canonical([candidate(uri='https://example.com/a//b'),candidate(uri='https://example.com/a/b')]))==2


def test_order_idempotence_and_input_immutable():
    values=[candidate(),candidate('okhttp'),candidate(uri='http://example.com/api'),candidate(method='POST')]
    original=deepcopy(values)
    first=canonical(values)
    assert first==canonical(list(reversed(values)))==canonical(first)
    assert values==original
    assert canonical([candidate('volley')])[0]['candidate_id']==canonical([candidate()])[0]['candidate_id']


def test_partial_unresolved_do_not_gain_authority_or_merge_unknown_sources():
    a=candidate(uri=None);a['path']='/users/{id}'
    b={**a,'source_file':'smali/Other.smali'}
    rows=canonical([a,b])
    assert len(rows)==2 and all(r['resolution_state']=='partial' for r in rows)
    assert all(r['host'] is None and r['full_url'] is None for r in rows)
    explicit=candidate(resolution_state='unresolved')
    assert canonical([explicit])[0]['resolution_state']=='unresolved'


@pytest.mark.parametrize('uri',['file:///android_asset/a','https://user:password@example.com/a','https://example.com:0/a','https://[invalid','https://example.com/a%xx'])
def test_invalid_url_cannot_be_resolved(uri):
    row=canonical([candidate(uri=uri)])[0]
    assert row['resolution_state']=='unresolved' and row['full_url'] is None


def test_unknown_method_and_authority_conflicts_not_promoted():
    assert canonical([candidate(method=None)])[0]['resolution_state']=='partial'
    row=canonical([candidate(scheme='http')])[0]
    assert row['resolution_state']=='unresolved' and row['normalization_reason']=='AUTHORITY_CONFLICT'


def test_same_endpoint_across_splits_keeps_sources_and_identity():
    a=bind_source_apk(canonical([candidate()])[0],'base.apk')
    b=bind_source_apk(canonical([candidate('okhttp')])[0],'feature.apk')
    rows=canonical([b,a])
    assert len(rows)==1
    assert {r['source_apk'] for r in rows[0]['provenance']}=={'base.apk','feature.apk'}
    assert rows[0]['candidate_id']==canonical([candidate()])[0]['candidate_id']
    assert canonical(rows)==rows


def test_real_extractor_fuel_okhttp_integration(tmp_path):
    ops='const-string v7, "https://example.com:443/api?q=ONE&token=SECRET"\ninvoke-static {v7}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;\n'+builder()+url('https://example.com/api?token=OTHER&q=TWO')+build()
    probe(tmp_path,ops)
    result=extract_api_candidates(tmp_path)
    row,=result['api_candidates']
    assert row['frameworks']==['Fuel','okhttp'] and len(row['provenance'])==2
    assert 'SECRET' not in json.dumps(result) and 'OTHER' not in json.dumps(result)
    assert row['source_component']=='Ltraining/Probe;'
    assert result==extract_api_candidates(tmp_path)


def test_unbound_retrofit_declaration_coverage_survives_static_report(tmp_path):
    from src.static_context_builder import build_static_context
    from src.report_generator import build_static_analysis_report
    manifest=tmp_path/'AndroidManifest.xml'
    manifest.write_text('<manifest package="training.test"><application/></manifest>')
    raw=tmp_path/'raw';raw.mkdir()
    (tmp_path/'Service.smali').write_text('.class public interface abstract Ltraining/Service;\n.super Ljava/lang/Object;\n.method public abstract signup()V\n.annotation runtime Lretrofit2/http/POST;\nvalue = "/signup"\n.end annotation\n.end method\n')
    context=build_static_context(manifest,raw,tmp_path)
    assert not context['api_candidates']
    coverage=context['api_discovery']['retrofit']
    assert len(coverage['unresolved_declarations'])==1
    assert coverage['unresolved_declarations'][0]['resolution_state']=='unresolved'
    assert coverage['coverage']['partial']
    report=build_static_analysis_report('c7',pipeline_result={'static_analysis':context})
    assert report['api_discovery']['retrofit']==coverage
    assert not report['api_candidates']


def test_all_six_frameworks_share_one_canonical_endpoint(tmp_path):
    from tests.test_ktor_bounded_provenance import write,func,ktor,CLIENT,CONT
    from tests.test_volley_urlconnection_extractor import volley,connection,method,use
    from tests.test_retrofit_candidate_extractor import service,factory
    ops='const-string v7, "https://example.com/api"\ninvoke-static {v7}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;\n'
    ops+=builder()+url('https://example.com/api')+build()
    ops+=volley(url='https://example.com/api')+connection()+method()+use()
    ops+=ktor().replace('https://example.com/api?q=VALUE&token=SECRET','https://example.com/api')
    write(tmp_path,func('root',ops,CLIENT+CONT))
    service(tmp_path,path='/api')
    factory(tmp_path,base='https://example.com/v1/')
    result=extract_api_candidates(tmp_path)
    row,=result['api_candidates']
    assert row['frameworks']==['Fuel','Retrofit','httpurlconnection','ktor','okhttp','volley']
    assert len(row['provenance'])==6
    assert row['resolution_state']=='resolved' and row['path']=='/api'
    assert result==extract_api_candidates(tmp_path)


def test_retrofit_literal_query_shape_preserved_without_values(tmp_path):
    from tests.test_retrofit_candidate_extractor import service,factory
    service(tmp_path,path='/search?q=PRIVATE&token=SECRET')
    factory(tmp_path)
    result=extract_api_candidates(tmp_path)
    row,=result['api_candidates']
    assert row['query_keys']==['q','token'] and row['query_shape_known']
    assert 'PRIVATE' not in json.dumps(result) and 'SECRET' not in json.dumps(result)
    assert row['resolution_state']=='resolved'


def test_legacy_removed_query_metadata_stays_unknown():
    source=candidate()
    source['evidence']['query_values_removed']=True
    row,=canonical([source])
    assert row['query_shape_known'] is False and row['resolution_state']=='partial'
    assert len(canonical([source,candidate('okhttp')]))==2


def test_framework_alias_and_evidence_only_enrichment_stable_id():
    a=candidate('OkHttp');b=candidate('okhttp',source='smali/Added.smali',line=99)
    assert len(canonical([a,b]))==1
    assert canonical([a])[0]['candidate_id']==canonical([a,b])[0]['candidate_id']
    assert canonical([a,b])[0]['frameworks']==['okhttp']


def test_canonical_report_retains_merged_provenance_and_ref_ids():
    from src.report_generator import build_static_analysis_report
    rows=canonical([candidate(),candidate('okhttp')])
    report=build_static_analysis_report('c7',pipeline_result={'static_analysis':{'api_candidates':rows,'app':{'package_name':'training.test'}}})
    assert report['api_candidates']==rows


def test_actual_split_context_deduplicates_with_full_source_binding(tmp_path):
    from src.split_static_context_builder import build_split_static_context
    components=[]
    for filename,role in [('base.apk','base'),('feature.apk','feature')]:
        decoded=tmp_path/filename;decoded.mkdir()
        raw=decoded/'raw';raw.mkdir()
        (decoded/'AndroidManifest.xml').write_text('<manifest package="training.test"><application/></manifest>')
        probe(decoded,builder()+url()+build())
        components.append({'filename':filename,'role':role,'has_dex':True,'preprocessing':{'apktool_dir':str(decoded),'raw_apk_dir':str(raw),'apktool_status':'success'}})
    context=build_split_static_context({'package_name':'training.test','components':components},tmp_path/'unified')
    row,=context['api_candidates']
    assert {p['source_apk'] for p in row['provenance']}=={'base.apk','feature.apk'}
    assert len(row['evidence_refs'])==2
    reversed_context=build_split_static_context({'package_name':'training.test','components':list(reversed(components))},tmp_path/'reordered')
    assert context['api_candidates']==reversed_context['api_candidates']


def test_ipv6_and_unicode_path_equivalent_forms():
    a=candidate(uri='https://[2001:DB8:0:0:0:0:0:1]:443/café',host='2001:DB8:0:0:0:0:0:1')
    b=candidate('okhttp',uri='https://[2001:db8::1]/caf%c3%a9',host='2001:db8::1')
    row,=canonical([a,b])
    assert row['host']=='2001:db8::1'
    assert row['full_url']=='https://[2001:db8::1]/caf%C3%A9'
