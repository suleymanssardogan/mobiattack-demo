import json
from pathlib import Path
import pytest
from src.okhttp_candidate_extractor import extract_okhttp
from src.api_candidate_extractor import extract_api_candidates

B = 'Lokhttp3/Request$Builder;'
U = 'Lokhttp3/HttpUrl;'


def probe(tmp_path, operations, name='Probe.smali'):
    path=tmp_path/name
    path.write_text('.class public Ltraining/Probe;\n.super Ljava/lang/Object;\n.method public static call(Lokhttp3/RequestBody;)V\n.locals 10\n'+operations+'\nreturn-void\n.end method\n')
    return path


def builder(register='v0'):
    return f'new-instance {register}, {B}\ninvoke-direct {{{register}}}, {B}-><init>()V\n'


def url(value='https://example.com/api', register='v0', argument='v1'):
    return f'const-string {argument}, "{value}"\ninvoke-virtual {{{register}, {argument}}}, {B}->url(Ljava/lang/String;){B}\n'


def build(register='v0'):
    return f'invoke-virtual {{{register}}}, {B}->build()Lokhttp3/Request;\n'

@pytest.mark.parametrize('verb,method', [('get','GET'),('post','POST'),('put','PUT'),('patch','PATCH'),('delete','DELETE'),('head','HEAD')])
def test_direct_verbs(tmp_path, verb, method):
    args='v0' if verb in {'get','delete','head'} else 'v0, p0'
    signature='()' if verb in {'get','delete','head'} else '(Lokhttp3/RequestBody;)'
    path=probe(tmp_path,builder()+url()+f'invoke-virtual {{{args}}}, {B}->{verb}{signature}{B}\n'+build())
    row=extract_okhttp(tmp_path)['api_candidates'][0]
    assert row['method']==method and row['full_url']=='https://example.com/api'
    assert row['scheme']=='https' and row['host']=='example.com' and row['port']==443
    assert row['framework']=='okhttp' and row['resolution_state']=='resolved'
    assert path.read_text().splitlines()[row['request_line']-1].startswith('invoke-virtual')
    assert row['evidence']['builder_allocation_line']==5
    assert row['evidence']['method_origin']=='explicit_method_call'


def test_default_get_is_proven_by_no_arg_constructor(tmp_path):
    probe(tmp_path,builder()+url()+build())
    row=extract_okhttp(tmp_path)['api_candidates'][0]
    assert row['method']=='GET' and row['evidence']['method_origin']=='constructor_default_GET'

@pytest.mark.parametrize('operation', ['parse','get'])
def test_http_url_literal(tmp_path, operation):
    probe(tmp_path,builder()+f'const-string v1, "https://example.com:8443/api"\ninvoke-static {{v1}}, {U}->{operation}(Ljava/lang/String;){U}\nmove-result-object v2\ninvoke-virtual {{v0, v2}}, {B}->url({U}){B}\n'+build())
    row=extract_okhttp(tmp_path)['api_candidates'][0]
    assert row['port']==8443 and row['full_url']=='https://example.com:8443/api'
    assert [e['kind'] for e in row['evidence']['url_trace']]==['url_literal','http_url_parse','builder_url']


def test_java_url_literal(tmp_path):
    probe(tmp_path,builder()+'new-instance v2, Ljava/net/URL;\nconst-string v1, "https://example.com/api"\ninvoke-direct {v2, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V\n'+f'invoke-virtual {{v0, v2}}, {B}->url(Ljava/net/URL;){B}\n'+build())
    assert extract_okhttp(tmp_path)['api_candidates'][0]['full_url']=='https://example.com/api'


def test_relative_resolve_requires_proven_base(tmp_path):
    probe(tmp_path,builder()+f'const-string v1, "https://example.com/v1/"\ninvoke-static {{v1}}, {U}->parse(Ljava/lang/String;){U}\nmove-result-object v2\nconst-string v3, "profile?q=something&token=SECRET_MARKER"\ninvoke-virtual {{v2, v3}}, {U}->resolve(Ljava/lang/String;){U}\nmove-result-object v4\ninvoke-virtual {{v0, v4}}, {B}->url({U}){B}\n'+build())
    result=extract_okhttp(tmp_path)
    assert result['api_candidates'][0]['path']=='/v1/profile'
    assert result['api_candidates'][0]['query_keys']==['q','token']
    assert 'SECRET_MARKER' not in json.dumps(result) and 'something' not in json.dumps(result)


def test_two_builder_isolation_and_alias(tmp_path):
    probe(tmp_path,builder('v0')+url('https://a.example.com/first')+builder('v3')+url('http://b.example.com:8081/second','v3','v4')+f'invoke-virtual {{v3, p0}}, {B}->post(Lokhttp3/RequestBody;){B}\nmove-result-object v5\n'+build('v0')+build('v5'))
    rows=extract_okhttp(tmp_path)['api_candidates']
    assert {(r['method'],r['host'],r['path']) for r in rows}=={('GET','a.example.com','/first'),('POST','b.example.com','/second')}
    assert len({r['evidence']['builder_allocation_line'] for r in rows})==2


def test_no_builder_presence_or_unrelated_url_is_not_candidate(tmp_path):
    probe(tmp_path,'const-string v1, "https://example.com/api"\n')
    assert extract_okhttp(tmp_path)['api_candidates']==[]


def test_unknown_wrapper_escape_and_unresolved_url(tmp_path):
    probe(tmp_path,builder()+url()+f'invoke-static {{v0}}, Ltraining/Wrapper;->rewrite({B})V\n'+build())
    result=extract_okhttp(tmp_path)
    assert not result['api_candidates'] and result['unresolved']
    assert all(r['resolution_state']=='unresolved' for r in result['unresolved'])
    probe(tmp_path,builder()+f'invoke-static {{}}, Ltraining/Wrapper;->url()Ljava/lang/String;\nmove-result-object v1\ninvoke-virtual {{v0, v1}}, {B}->url(Ljava/lang/String;){B}\n'+build())
    assert not extract_okhttp(tmp_path)['api_candidates']

@pytest.mark.parametrize('operations', [':label\n', 'if-eqz p0, :exit\n:exit\n', 'iput-object v0, p0, Ltraining/Wrapper;->field:Ljava/lang/Object;\n', f'invoke-virtual/range {{v0 .. v1}}, {B}->url(Ljava/lang/String;){B}\n'])
def test_unsupported_flow_cannot_cross_bind(tmp_path, operations):
    probe(tmp_path,builder()+url()+operations+build())
    assert not extract_okhttp(tmp_path)['api_candidates']

@pytest.mark.parametrize('value', ['file:///android_asset/index.html','content://x/profile','https://user:password@example.com/api','https://example.com/secret/TOKEN_VALUE','https://example.com:invalid/api','http://example.com:0/api','http://invalid_host/api','https://example.com/a/../b'])
def test_invalid_and_sensitive_urls_stay_unresolved(tmp_path,value):
    probe(tmp_path,builder()+url(value)+build())
    result=extract_okhttp(tmp_path)
    assert not result['api_candidates']
    assert value not in json.dumps(result)


def test_query_values_not_persisted_and_port_normalized(tmp_path):
    probe(tmp_path,builder()+url('https://example.com:443/search?q=VALUE&token=SECRET&q=OTHER&empty=')+build())
    result=extract_okhttp(tmp_path)
    row=result['api_candidates'][0]
    assert row['full_url']=='https://example.com/search'
    assert row['query_keys']==['empty','q','token']
    assert row['query_shape']['q']=={'count':2,'value_present':True}
    assert row['query_shape']['empty']=={'count':1,'value_present':False}
    assert all(s not in json.dumps(result) for s in ('VALUE','SECRET','OTHER'))


def test_unknown_method_overwrites_previous_method(tmp_path):
    probe(tmp_path,builder()+url()+f'invoke-virtual {{v0, v7, p0}}, {B}->method(Ljava/lang/String;Lokhttp3/RequestBody;){B}\n'+build())
    assert not extract_okhttp(tmp_path)['api_candidates']


def test_reassigned_register_cannot_retain_builder(tmp_path):
    probe(tmp_path,builder()+url()+'const/4 v0, 0x0\n'+build())
    assert not extract_okhttp(tmp_path)['api_candidates']


def test_missing_move_result_cannot_use_stale_url(tmp_path):
    probe(tmp_path,builder()+f'const-string v1, "https://example.com/api"\ninvoke-static {{v1}}, {U}->parse(Ljava/lang/String;){U}\nconst/4 v3, 0x0\nmove-result-object v2\ninvoke-virtual {{v0, v2}}, {B}->url({U}){B}\n'+build())
    assert not extract_okhttp(tmp_path)['api_candidates']


def test_stable_ids_order_and_api_integration(tmp_path):
    probe(tmp_path,builder()+url('https://b.example.com/b')+build(),'Z.smali')
    probe(tmp_path,builder()+url('https://a.example.com/a')+build(),'A.smali')
    first=extract_api_candidates(tmp_path)
    second=extract_api_candidates(tmp_path)
    assert first==second
    assert len(first['api_candidates'])==2
    assert all(r['candidate_id'].startswith('static_') for r in first['api_candidates'])
    assert len({r['candidate_id'] for r in first['api_candidates']})==2


def test_method_literal_and_builder_alias(tmp_path):
    probe(tmp_path,builder()+url()+'move-object v4, v0\nconst-string v5, "OPTIONS"\n'+f'invoke-virtual {{v4, v5, p0}}, {B}->method(Ljava/lang/String;Lokhttp3/RequestBody;){B}\n'+build('v0'))
    assert extract_okhttp(tmp_path)['api_candidates'][0]['method']=='OPTIONS'


def test_methods_do_not_share_register_state(tmp_path):
    path=probe(tmp_path,builder()+url())
    with path.open('a') as out:
        out.write('.method public static other()V\n.locals 2\n'+build()+'return-void\n.end method\n')
    assert not extract_okhttp(tmp_path)['api_candidates']


def test_request_clone_is_not_direct_builder(tmp_path):
    probe(tmp_path,f'invoke-virtual {{p0}}, Lokhttp3/Request;->newBuilder(){B}\nmove-result-object v0\n'+url()+build())
    assert not extract_okhttp(tmp_path)['api_candidates']


@pytest.mark.parametrize('relative', ['//other.example/api','https://other.example/api','../api','//[invalid'])
def test_unproven_or_cross_host_relative_is_not_guessed(tmp_path, relative):
    probe(tmp_path,builder()+f'const-string v1, "http://example.com/base/"\ninvoke-static {{v1}}, {U}->get(Ljava/lang/String;){U}\nmove-result-object v2\nconst-string v3, "{relative}"\ninvoke-virtual {{v2, v3}}, {U}->resolve(Ljava/lang/String;){U}\nmove-result-object v4\ninvoke-virtual {{v0, v4}}, {B}->url({U}){B}\n'+build())
    assert not extract_okhttp(tmp_path)['api_candidates']


def test_static_context_retains_candidates_and_unresolved_diagnostics(tmp_path):
    from src.static_context_builder import build_static_context
    root=tmp_path/'decoded'
    root.mkdir()
    raw=tmp_path/'raw'
    raw.mkdir()
    manifest=root/'AndroidManifest.xml'
    manifest.write_text('<manifest package="training.test"><application/></manifest>')
    probe(root,builder()+url()+build(),'Resolved.smali')
    probe(root,builder()+build(),'Unresolved.smali')
    result=build_static_context(manifest,raw,root)
    assert len(result['api_candidates'])==1
    assert result['api_discovery']['okhttp']['unresolved'][0]['reason']=='REQUEST_URL_OR_METHOD_UNRESOLVED'
    assert result['api_discovery']['okhttp']['coverage']['partial'] is True


def test_split_context_retains_per_component_diagnostics(tmp_path):
    from src.split_static_context_builder import build_split_static_context
    decoded=tmp_path/'decoded'
    decoded.mkdir()
    raw=tmp_path/'raw'
    raw.mkdir()
    (decoded/'AndroidManifest.xml').write_text('<manifest package="training.test"><application/></manifest>')
    probe(decoded,builder()+build())
    package={'package_name':'training.test','components':[{'filename':'base.apk','role':'base','has_dex':True,'preprocessing':{'apktool_dir':str(decoded),'raw_apk_dir':str(raw),'apktool_status':'success'}}]}
    result=build_split_static_context(package,tmp_path/'unified')
    diagnostics=result['api_discovery']['components'][0]
    assert diagnostics['source_apk']=='base.apk'
    assert diagnostics['okhttp']['unresolved']


def test_size_limit_is_explicit(tmp_path, monkeypatch):
    import src.okhttp_candidate_extractor as module
    probe(tmp_path,builder()+url()+build())
    monkeypatch.setattr(module,'MAX_FILE_BYTES',1)
    result=extract_okhttp(tmp_path)
    assert not result['api_candidates'] and result['coverage']['partial']
    assert result['coverage']['skipped'][0]['reason']=='source_or_size_boundary'


def test_library_presence_and_interceptor_do_not_emit(tmp_path):
    probe(tmp_path,f'const-class v0, {B}\nconst-string v1, "https://library.example/sample"\ninvoke-interface {{p0}}, Lokhttp3/Interceptor$Chain;->request()Lokhttp3/Request;\n')
    assert extract_api_candidates(tmp_path)['api_candidates']==[]


def test_header_secrets_not_in_candidate_or_diagnostics(tmp_path):
    probe(tmp_path,builder()+url()+'const-string v2, "Authorization"\nconst-string v3, "Bearer SECRET_CREDENTIAL"\n'+f'invoke-virtual {{v0, v2, v3}}, {B}->header(Ljava/lang/String;Ljava/lang/String;){B}\n'+build())
    result=extract_api_candidates(tmp_path)
    assert len(result['api_candidates'])==1
    assert 'SECRET_CREDENTIAL' not in json.dumps(result)


def test_built_request_snapshot_not_cross_bound_by_later_changes(tmp_path):
    probe(tmp_path,builder()+url('http://example.com:80/first')+build()+url('https://example.com/second')+f'invoke-virtual {{v0, p0}}, {B}->post(Lokhttp3/RequestBody;){B}\n'+build())
    rows=extract_okhttp(tmp_path)['api_candidates']
    assert {(r['method'],r['full_url']) for r in rows}=={('GET','http://example.com/first'),('POST','https://example.com/second')}


def test_unreachable_or_missing_component_cannot_emit(tmp_path):
    path=probe(tmp_path,'return-void\n'+builder()+url()+build())
    assert not extract_okhttp(tmp_path)['api_candidates']
    path.write_text(path.read_text().replace('.class public Ltraining/Probe;\n',''))
    assert not extract_okhttp(tmp_path)['api_candidates']
