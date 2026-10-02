import json
from pathlib import Path
import pytest
from src.volley_urlconnection_extractor import extract_volley_urlconnection as extract
from src.api_candidate_extractor import extract_api_candidates

S = 'Lcom/android/volley/toolbox/StringRequest;'
Q = 'Lcom/android/volley/RequestQueue;'
R = 'Lcom/android/volley/Request;'
L = 'Lcom/android/volley/Response$Listener;Lcom/android/volley/Response$ErrorListener;'
U = 'Ljava/net/URL;'
C = 'Ljava/net/URLConnection;'
H = 'Ljava/net/HttpURLConnection;'


def probe(root, ops, name='Probe.smali'):
    path = root/name
    path.write_text('.class public Ltraining/Probe;\n.super Ljava/lang/Object;\n.method public static call()V\n.locals 16\n'+ops+'\nreturn-void\n.end method\n')
    return path


def volley(verb=0, url='http://example.com/data', reg='v0', method='v1', value='v2'):
    return f'new-instance {reg}, {S}\nconst/4 {method}, {hex(verb)}\nconst-string {value}, "{url}"\ninvoke-direct {{{reg}, {method}, {value}, v14, v15}}, {S}-><init>(ILjava/lang/String;{L})V\n'


def connection(url='https://example.com/api', u='v0', literal='v1', conn='v2'):
    return f'new-instance {u}, {U}\nconst-string {literal}, "{url}"\ninvoke-direct {{{u}, {literal}}}, {U}-><init>(Ljava/lang/String;)V\ninvoke-virtual {{{u}}}, {U}->openConnection(){C}\nmove-result-object {conn}\ncheck-cast {conn}, {H}\n'


def method(verb='GET', conn='v2', literal='v3'):
    return f'const-string {literal}, "{verb}"\ninvoke-virtual {{{conn}, {literal}}}, {H}->setRequestMethod(Ljava/lang/String;)V\n'


def use(conn='v2'):
    return f'invoke-virtual {{{conn}}}, {H}->connect()V\n'


@pytest.mark.parametrize('code,verb',list(enumerate(['GET','POST','PUT','DELETE','HEAD','OPTIONS','TRACE','PATCH'])))
def test_volley_direct_methods(tmp_path, code, verb):
    source=probe(tmp_path,volley(code))
    row=extract(tmp_path)['api_candidates'][0]
    assert (row['framework'],row['method'],row['full_url'])==('volley',verb,'http://example.com/data')
    assert row['source_component']=='Ltraining/Probe;'
    assert '-><init>' in source.read_text().splitlines()[row['request_line']-1]
    assert row['evidence']['queue_add_refs']==[]


@pytest.mark.parametrize('name,body',[('JsonObjectRequest','Lorg/json/JSONObject;'),('JsonArrayRequest','Lorg/json/JSONArray;')])
def test_json_request_explicit_range(tmp_path,name,body):
    owner='Lcom/android/volley/toolbox/'+name+';'
    probe(tmp_path,f'new-instance v0, {owner}\nconst/4 v1, 0x1\nconst-string v2, "https://example.com/json"\nconst/4 v3, 0x0\nconst/4 v4, 0x0\nconst/4 v5, 0x0\ninvoke-direct/range {{v0 .. v5}}, {owner}-><init>(ILjava/lang/String;{body}{L})V\n')
    assert extract(tmp_path)['api_candidates'][0]['method']=='POST'


@pytest.mark.parametrize('name',['StringRequest','JsonObjectRequest','JsonArrayRequest'])
def test_explicit_constructor_default_get(tmp_path,name):
    owner='Lcom/android/volley/toolbox/'+name+';'
    probe(tmp_path,f'new-instance v0, {owner}\nconst-string v1, "https://example.com/data"\ninvoke-direct {{v0,v1,v2,v3}}, {owner}-><init>(Ljava/lang/String;{L})V\n')
    assert extract(tmp_path)['api_candidates'][0]['method']=='GET'


def test_enum_constant(tmp_path):
    ops=volley().replace('const/4 v1, 0x0', 'sget v1, Lcom/android/volley/Request$Method;->POST:I')
    probe(tmp_path,ops)
    assert extract(tmp_path)['api_candidates'][0]['method']=='POST'


def test_volley_two_requests_queue_isolation(tmp_path):
    probe(tmp_path,volley(0,'https://a.example/a')+volley(1,'https://b.example/b','v4','v5','v6')+f'new-instance v7, {Q}\ninvoke-direct {{v7,v14,v15}}, {Q}-><init>(Lcom/android/volley/Cache;Lcom/android/volley/Network;)V\nmove-object v8, v4\ninvoke-virtual {{v7,v8}}, {Q}->add({R}){R}\n')
    rows=extract(tmp_path)['api_candidates']
    a=next(r for r in rows if r['host']=='a.example')
    b=next(r for r in rows if r['host']=='b.example')
    assert a['method']=='GET' and not a['evidence']['queue_add_refs']
    assert b['method']=='POST' and len(b['evidence']['queue_add_refs'])==1


@pytest.mark.parametrize('code',[-1,8,100])
def test_unknown_volley_method_unresolved(tmp_path,code):
    probe(tmp_path,volley().replace('const/4 v1, 0x0',f'const v1, {code}'))
    result=extract(tmp_path)
    assert not result['api_candidates']
    assert result['discovery_diagnostics']['volley']['unresolved']


def test_unknown_queue_not_fabricated(tmp_path):
    probe(tmp_path,volley()+f'invoke-virtual {{v7,v0}}, {Q}->add({R}){R}\n')
    assert not extract(tmp_path)['api_candidates'][0]['evidence']['queue_add_refs']


@pytest.mark.parametrize('ops',[f'const-class v0, {S}\nconst-string v1, "https://example.com/library"\n',f'new-instance v0, {Q}\n',f'new-instance v0, Ltraining/CustomRequest;\nconst-string v1, "https://example.com/wrapper"\ninvoke-direct {{v0,v1}}, Ltraining/CustomRequest;-><init>(Ljava/lang/String;)V\n'])
def test_volley_presence_url_and_custom_wrapper_not_candidate(tmp_path,ops):
    probe(tmp_path,ops)
    assert not extract(tmp_path)['api_candidates']


@pytest.mark.parametrize('verb',['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
def test_http_explicit_methods(tmp_path,verb):
    source=probe(tmp_path,connection()+method(verb)+use())
    row=extract(tmp_path)['api_candidates'][0]
    assert (row['framework'],row['method'],row['scheme'],row['port'])==('httpurlconnection',verb,'https',443)
    assert row['evidence']['open_connection_line']<row['evidence']['method_line']<row['request_line']
    assert '->connect()V' in source.read_text().splitlines()[row['request_line']-1]


def test_http_connections_isolated_with_alias(tmp_path):
    probe(tmp_path,connection('http://a.example:80/a')+method()+connection('https://b.example:8443/b','v4','v5','v6')+method('POST','v6','v7')+'move-object v8, v2\n'+use('v8')+use('v6'))
    rows=extract(tmp_path)['api_candidates']
    assert {(r['method'],r['full_url']) for r in rows}=={('GET','http://a.example/a'),('POST','https://b.example:8443/b')}
    assert len({r['evidence']['allocation_line'] for r in rows})==2


@pytest.mark.parametrize('ops',[connection(),connection()+use(),connection()+method('UNKNOWN')+use(),f'new-instance v0, {U}\nconst-string v1, "https://example.com/alone"\ninvoke-direct {{v0,v1}}, {U}-><init>(Ljava/lang/String;)V\n',f'invoke-virtual {{v0}}, {C}->getInputStream()Ljava/io/InputStream;\n'])
def test_http_unknown_method_or_no_http_usage_not_candidate(tmp_path,ops):
    probe(tmp_path,ops)
    assert not extract(tmp_path)['api_candidates']


def test_unknown_method_replaces_old_method(tmp_path):
    probe(tmp_path,connection()+method()+f'invoke-virtual {{v2,v8}}, {H}->setRequestMethod(Ljava/lang/String;)V\n'+use())
    assert not extract(tmp_path)['api_candidates']


@pytest.mark.parametrize('extra',[f'invoke-static {{v2}}, Ltraining/Wrapper;->rewrite({H})V\n','iput-object v2, v4, Ltraining/Store;->connection:Ljava/lang/Object;\n','if-eqz v2, :done\n:done\n'])
def test_http_unsupported_flow_cannot_guess(tmp_path,extra):
    probe(tmp_path,connection()+method()+extra+use())
    assert not extract(tmp_path)['api_candidates']


def test_generic_urlconnection_without_http_evidence_not_candidate(tmp_path):
    ops=connection().replace(f'check-cast v2, {H}\n','')
    probe(tmp_path,ops+f'invoke-virtual {{v2}}, {C}->getInputStream()Ljava/io/InputStream;\n')
    assert not extract(tmp_path)['api_candidates']


@pytest.mark.parametrize('framework',['volley','http'])
def test_sanitized_queries_and_deterministic_integration(tmp_path,framework):
    url='https://example.com:443/search?q=VALUE&token=SECRET&q=OTHER&empty='
    ops=volley(url=url) if framework=='volley' else connection(url)+method()+use()
    probe(tmp_path,ops)
    first=extract_api_candidates(tmp_path)
    assert first==extract_api_candidates(tmp_path)
    row=first['api_candidates'][0]
    assert row['full_url']=='https://example.com/search'
    assert row['query_keys']==['empty','q','token']
    assert row['query_shape']['q']=={'count':2,'value_present':True}
    assert row['candidate_id'].startswith('static_')
    assert not any(value in json.dumps(first) for value in ('VALUE','SECRET','OTHER'))


@pytest.mark.parametrize('url',['file:///android_asset/index.html','content://store/item','data:text/plain,hello','https://user:SECRET@example.com/a','https://example.com:invalid/a'])
def test_non_http_and_secret_url_rejected(tmp_path,url):
    probe(tmp_path,volley(url=url)+connection(url)+method()+use())
    assert not extract(tmp_path)['api_candidates']


def test_http_output_get_does_not_guess_post(tmp_path):
    probe(tmp_path,connection()+method()+f'invoke-virtual {{v2}}, {H}->getOutputStream()Ljava/io/OutputStream;\n')
    assert not extract(tmp_path)['api_candidates']


def test_runtime_option_does_not_change_method_silently(tmp_path):
    probe(tmp_path,connection()+method()+f'const/4 v4, 0x1\ninvoke-virtual {{v2,v4}}, {C}->setDoOutput(Z)V\n'+use())
    assert not extract(tmp_path)['api_candidates']


def test_state_cannot_cross_methods(tmp_path):
    p=probe(tmp_path,connection()+method())
    with p.open('a') as out: out.write('.method public static second()V\n.locals 10\n'+use()+'.end method\n')
    assert not extract(tmp_path)['api_candidates']


def test_body_dependent_json_constructor_unknown_is_unresolved(tmp_path):
    owner='Lcom/android/volley/toolbox/JsonObjectRequest;'
    ops=f'new-instance v0, {owner}\nconst-string v1, "https://example.com/json"\ninvoke-direct {{v0,v1,v2,v3,v4}}, {owner}-><init>(Ljava/lang/String;Lorg/json/JSONObject;{L})V\n'
    probe(tmp_path,ops)
    assert not extract(tmp_path)['api_candidates']
    probe(tmp_path,ops.replace('invoke-direct {','const/4 v2, 0x0\ninvoke-direct {'))
    assert extract(tmp_path)['api_candidates'][0]['method']=='GET'


def test_queue_factory_provenance(tmp_path):
    probe(tmp_path,volley()+f'invoke-static {{v7}}, Lcom/android/volley/toolbox/Volley;->newRequestQueue(Landroid/content/Context;){Q}\nmove-result-object v8\ninvoke-virtual {{v8,v0}}, {Q}->add({R}){R}\n')
    assert extract(tmp_path)['api_candidates'][0]['evidence']['queue_add_refs']


def test_queue_cannot_link_escaped_request(tmp_path):
    probe(tmp_path,volley()+f'invoke-static {{v0}}, Ltraining/Wrapper;->rewrite({R})V\ninvoke-static {{v7}}, Lcom/android/volley/toolbox/Volley;->newRequestQueue(Landroid/content/Context;){Q}\nmove-result-object v8\ninvoke-virtual {{v8,v0}}, {Q}->add({R}){R}\n')
    assert not extract(tmp_path)['api_candidates'][0]['evidence']['queue_add_refs']


def test_unknown_method_connection_does_not_borrow_from_other(tmp_path):
    probe(tmp_path,connection()+method('POST')+connection('http://other.example/unknown','v4','v5','v6')+use('v6'))
    assert not extract(tmp_path)['api_candidates']


def test_unknown_request_method_does_not_borrow_from_other(tmp_path):
    second=volley(1,'https://other.example/unknown','v4','v5','v6').replace('const/4 v5, 0x1\n','')
    probe(tmp_path,volley()+second)
    assert len(extract(tmp_path)['api_candidates'])==1


def test_http_header_secret_not_persisted(tmp_path):
    probe(tmp_path,connection()+method()+'const-string v4, "Authorization"\nconst-string v5, "Bearer SECRET_CREDENTIAL"\n'+f'invoke-virtual {{v2,v4,v5}}, {C}->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V\n'+use())
    result=extract(tmp_path)
    assert len(result['api_candidates'])==1 and 'SECRET_CREDENTIAL' not in json.dumps(result)


def test_output_stream_get_cannot_later_be_reported_as_get(tmp_path):
    probe(tmp_path,connection()+method()+f'invoke-virtual {{v2}}, {H}->getOutputStream()Ljava/io/OutputStream;\n'+use())
    assert not extract(tmp_path)['api_candidates']


@pytest.mark.parametrize('framework',['volley','http'])
def test_static_context_preserves_framework_metadata(tmp_path,framework):
    from src.static_context_builder import build_static_context
    raw=tmp_path/'raw'
    raw.mkdir()
    manifest=tmp_path/'AndroidManifest.xml'
    manifest.write_text('<manifest package="training.test"><application/></manifest>')
    probe(tmp_path,volley() if framework=='volley' else connection()+method()+use())
    result=build_static_context(manifest,raw,tmp_path)
    assert result['api_candidates'][0]['framework']==('volley' if framework=='volley' else 'httpurlconnection')
    assert {'volley','httpurlconnection'}<=result['api_discovery'].keys()


def test_scan_boundary_explicit(tmp_path,monkeypatch):
    import src.volley_urlconnection_extractor as module
    probe(tmp_path,volley()+connection()+method()+use())
    monkeypatch.setattr(module,'MAX_FILE_BYTES',1)
    result=extract(tmp_path)
    assert not result['api_candidates']
    assert all(d['coverage']['partial'] for d in result['discovery_diagnostics'].values())
