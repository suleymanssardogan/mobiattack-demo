import json
import pytest
from src.api_candidate_extractor import extract_api_candidates
from src.bounded_api_provenance import extract_bounded_candidates
from tests.test_okhttp_candidate_extractor import builder,url,build,B
from tests.test_volley_urlconnection_extractor import volley,connection,method,use
from src.ktor_candidate_extractor import CLIENT,BUILDER,URL_BUILDER,HTTP_METHOD,COMPANION,CONT

F='Lio/ktor/client/request/BuildersKt;'
OWNER='Ltraining/Api;'


def write(root,methods,fields=''):
    (root/'Api.smali').write_text('.class public final '+OWNER+'\n.super Ljava/lang/Object;\n'+fields+'\n'+methods)


def func(name,body,args='',returns='V',flags='public static',locals=16):
    return f'.method {flags} {name}({args}){returns}\n.locals {locals}\n'+body+('\nreturn-void\n' if returns=='V' else '\n')+'.end method\n'


def ktor(verb='get',reg='v0',urlreg='v1'):
    return f'new-instance {reg}, {BUILDER}\ninvoke-direct {{{reg}}}, {BUILDER}-><init>()V\nconst-string {urlreg}, "https://example.com/api?q=VALUE&token=SECRET"\ninvoke-static {{{reg}, {urlreg}}}, Lio/ktor/client/request/HttpRequestKt;->url({BUILDER}Ljava/lang/String;)V\ninvoke-static {{p0, {reg}, p1}}, {F}->{verb}({CLIENT}{BUILDER}{CONT})Ljava/lang/Object;\n'


@pytest.mark.parametrize('verb',['get','post'])
def test_direct_ktor(tmp_path,verb):
    write(tmp_path,func('root',ktor(verb),CLIENT+CONT))
    result=extract_api_candidates(tmp_path)
    row=result['api_candidates'][0]
    assert (row['framework'],row['method'],row['full_url'])==('ktor',verb.upper(),'https://example.com/api')
    assert row['query_keys']==['q','token'] and 'SECRET' not in json.dumps(result) and 'VALUE' not in json.dumps(result)


def test_string_default_block_call(tmp_path):
    write(tmp_path,func('root',f'const-string v1, "https://example.com/string"\nconst/4 v4, 0x2\ninvoke-static {{p0,v1,v2,p1,v4,v5}}, {F}->get$default({CLIENT}Ljava/lang/String;Lkotlin/jvm/functions/Function1;{CONT}ILjava/lang/Object;)Ljava/lang/Object;\n',CLIENT+CONT))
    assert extract_api_candidates(tmp_path)['api_candidates'][0]['method']=='GET'


def test_request_dsl_explicit_method_and_url_builder(tmp_path):
    ops=f'new-instance v0, {BUILDER}\ninvoke-direct {{v0}}, {BUILDER}-><init>()V\ninvoke-virtual {{v0}}, {BUILDER}->getUrl(){URL_BUILDER}\nmove-result-object v1\nconst-string v2, "https://example.com/dsl"\ninvoke-static {{v1,v2}}, Lio/ktor/http/URLUtilsKt;->takeFrom({URL_BUILDER}Ljava/lang/String;){URL_BUILDER}\nsget-object v3, {HTTP_METHOD}->Companion:{COMPANION}\ninvoke-virtual {{v3}}, {COMPANION}->getPost(){HTTP_METHOD}\nmove-result-object v4\ninvoke-virtual {{v0,v4}}, {BUILDER}->setMethod({HTTP_METHOD})V\ninvoke-static {{p0,v0,p1}}, {F}->request({CLIENT}{BUILDER}{CONT})Ljava/lang/Object;\n'
    write(tmp_path,func('root',ops,CLIENT+CONT))
    assert extract_api_candidates(tmp_path)['api_candidates'][0]['method']=='POST'


@pytest.mark.parametrize('ops',[f'const-class v0, {CLIENT}\nconst-string v1, "https://example.com/unrelated"\n',ktor().replace('get('+CLIENT+BUILDER,'request('+CLIENT+BUILDER),ktor().replace('https://example.com/api?q=VALUE&token=SECRET','file:///asset/a'),ktor().replace('invoke-direct {v0}, '+BUILDER+'-><init>()V\n','')])
def test_ktor_unsupported_no_candidate(tmp_path,ops):
    write(tmp_path,func('root',ops,CLIENT+CONT))
    assert not extract_api_candidates(tmp_path)['api_candidates']


def helper_request():
    return builder()+f'invoke-virtual {{v0,p0}}, {B}->url(Ljava/lang/String;){B}\n'+build()


def test_one_hop_literal_to_parameter(tmp_path):
    caller='const-string v1, "https://example.com/users"\n'+f'invoke-static {{v1}}, {OWNER}->helper(Ljava/lang/String;)V\n'
    write(tmp_path,func('root',caller)+func('helper',helper_request(),'Ljava/lang/String;'))
    result=extract_api_candidates(tmp_path)
    row=result['api_candidates'][0]
    assert row['full_url']=='https://example.com/users'
    assert row['evidence']['source_method']=='helper(Ljava/lang/String;)V'
    assert any(e['kind']=='helper_call' for e in row['evidence']['bounded_provenance'])
    source=(tmp_path/row['source_file']).read_text().splitlines()
    assert '->build()' in source[row['request_line']-1]
    assert result==extract_api_candidates(tmp_path)


def test_direct_return_object(tmp_path):
    caller=f'invoke-static {{}}, {OWNER}->make(){B}\nmove-result-object v2\n'+build('v2')
    helper=builder()+url('https://example.com/returned')+'return-object v0\n'
    write(tmp_path,func('root',caller)+func('make',helper,returns=B))
    row=extract_api_candidates(tmp_path)['api_candidates'][0]
    assert row['full_url']=='https://example.com/returned'
    assert any(e['kind']=='return_binding' for e in row['evidence']['bounded_provenance'])


def test_immutable_field(tmp_path):
    ops=builder()+f'sget-object v1, {OWNER}->BASE:Ljava/lang/String;\ninvoke-virtual {{v0,v1}}, {B}->url(Ljava/lang/String;){B}\n'+build()
    write(tmp_path,func('root',ops),'.field public static final BASE:Ljava/lang/String; = "https://example.com/final"')
    row=extract_api_candidates(tmp_path)['api_candidates'][0]
    assert row['path']=='/final'
    assert any(e['kind']=='static_final_field' for e in row['evidence']['bounded_provenance'])


def test_literal_concat(tmp_path):
    ops=builder()+'const-string v1, "https://example.com"\nconst-string v2, "/concat"\ninvoke-virtual {v1,v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;\nmove-result-object v3\n'+f'invoke-virtual {{v0,v3}}, {B}->url(Ljava/lang/String;){B}\n'+build()
    write(tmp_path,func('root',ops))
    assert extract_api_candidates(tmp_path)['api_candidates'][0]['path']=='/concat'


@pytest.mark.parametrize('field,extra',[('.field public static BASE:Ljava/lang/String; = "https://example.com/bad"',''),('.field public static final BASE:Ljava/lang/String; = "https://example.com/bad"',func('change',f'const-string v1, "https://other.example/bad"\nsput-object v1, {OWNER}->BASE:Ljava/lang/String;\n'))])
def test_mutable_field_rejected(tmp_path,field,extra):
    ops=builder()+f'sget-object v1, {OWNER}->BASE:Ljava/lang/String;\ninvoke-virtual {{v0,v1}}, {B}->url(Ljava/lang/String;){B}\n'+build()
    write(tmp_path,func('root',ops)+extra,field)
    assert not extract_api_candidates(tmp_path)['api_candidates']


def test_ambiguous_callers(tmp_path):
    def caller(url):return 'const-string v1, "'+url+'"\n'+f'invoke-static {{v1}}, {OWNER}->helper(Ljava/lang/String;)V\n'
    write(tmp_path,func('root',caller('https://a.example/a'))+func('second',caller('https://b.example/b'))+func('helper',helper_request(),'Ljava/lang/String;'))
    result=extract_api_candidates(tmp_path)
    assert not result['api_candidates']
    assert any(g['reason']=='AMBIGUOUS_CALLERS' for g in result['discovery_diagnostics']['bounded_provenance']['unresolved'])


def test_branch_dependent_helper_rejected(tmp_path):
    caller='const-string v1, "https://example.com/a"\n'+f'invoke-static {{v1}}, {OWNER}->helper(Ljava/lang/String;)V\n'
    write(tmp_path,func('root',caller)+func('helper','if-eqz p0, :end\n'+helper_request()+':end\n','Ljava/lang/String;'))
    assert not extract_api_candidates(tmp_path)['api_candidates']


@pytest.mark.parametrize('depth,expected',[(3,1),(4,0)])
def test_depth_limit(tmp_path,depth,expected):
    methods=func('root','const-string v1, "https://example.com/depth"\n'+f'invoke-static {{v1}}, {OWNER}->h1(Ljava/lang/String;)V\n')
    for i in range(1,depth+1):
        body=helper_request() if i==depth else f'invoke-static {{p0}}, {OWNER}->h{i+1}(Ljava/lang/String;)V\n'
        methods+=func('h'+str(i),body,'Ljava/lang/String;')
    write(tmp_path,methods)
    result=extract_api_candidates(tmp_path)
    assert len(result['api_candidates'])==expected
    if not expected:assert any(g['reason']=='DEPTH_LIMIT' for g in result['discovery_diagnostics']['bounded_provenance']['unresolved'])


def test_cycle_stops(tmp_path):
    body=f'invoke-static {{p0}}, {OWNER}->cycle(Ljava/lang/String;)V\n'+helper_request()
    write(tmp_path,func('cycle',body,'Ljava/lang/String;'))
    result=extract_api_candidates(tmp_path)
    assert not result['api_candidates']
    assert any(g['reason']=='CYCLE_DETECTED' for g in result['discovery_diagnostics']['bounded_provenance']['unresolved'])


@pytest.mark.parametrize('framework,body',[('volley',volley()),('httpurlconnection',connection()+method()+use()),('okhttp',builder()+url()+build())])
def test_existing_direct_rows_unchanged(tmp_path,framework,body):
    from src.api_candidate_canonicalizer import canonicalize_api_candidates
    from src.okhttp_candidate_extractor import extract_okhttp
    from src.volley_urlconnection_extractor import extract_volley_urlconnection
    write(tmp_path,func('root',body))
    before=extract_okhttp(tmp_path)['api_candidates'] if framework=='okhttp' else extract_volley_urlconnection(tmp_path)['api_candidates']
    result=extract_api_candidates(tmp_path)
    assert [r for r in result['api_candidates'] if r['framework']==framework]==canonicalize_api_candidates(before)


def test_literal_string_builder_concat(tmp_path):
    ops=builder()+'new-instance v1, Ljava/lang/StringBuilder;\ninvoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V\nconst-string v2, "https://example.com"\ninvoke-virtual {v1,v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\nmove-result-object v3\nconst-string v4, "/joined"\ninvoke-virtual {v3,v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\ninvoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\nmove-result-object v5\n'+f'invoke-virtual {{v0,v5}}, {B}->url(Ljava/lang/String;){B}\n'+build()
    write(tmp_path,func('root',ops))
    assert extract_api_candidates(tmp_path)['api_candidates'][0]['path']=='/joined'


def test_literal_return_then_caller_use(tmp_path):
    ops=builder()+f'invoke-static {{}}, {OWNER}->endpoint()Ljava/lang/String;\nmove-result-object v1\ninvoke-virtual {{v0,v1}}, {B}->url(Ljava/lang/String;){B}\n'+build()
    write(tmp_path,func('root',ops)+func('endpoint','const-string v0, "https://example.com/return-url"\nreturn-object v0\n',returns='Ljava/lang/String;'))
    assert extract_api_candidates(tmp_path)['api_candidates'][0]['path']=='/return-url'


@pytest.mark.parametrize('framework',['volley','http','ktor'])
def test_cross_framework_helper_parameter(tmp_path,framework):
    if framework=='volley':
        ops=volley().replace('const-string v2, "http://example.com/data"\n','move-object v2, p0\n')
        args='Ljava/lang/String;';actual='v1';callerargs=''
    elif framework=='http':
        ops=connection().replace('const-string v1, "https://example.com/api"\n','move-object v1, p0\n')+method()+use()
        args='Ljava/lang/String;';actual='v1';callerargs=''
    else:
        ops=ktor().replace('const-string v1, "https://example.com/api?q=VALUE&token=SECRET"\n','move-object v1, p2\n')
        args=CLIENT+CONT+'Ljava/lang/String;';actual='p0,p1,v1';callerargs=CLIENT+CONT
    caller='const-string v1, "https://example.com/wrapped"\n'+f'invoke-static {{{actual}}}, {OWNER}->helper({args})V\n'
    write(tmp_path,func('root',caller,callerargs)+func('helper',ops,args))
    row=extract_api_candidates(tmp_path)['api_candidates'][0]
    assert row['framework']==('httpurlconnection' if framework=='http' else framework)
    assert row['path']=='/wrapped' and row['evidence']['bounded_provenance']


@pytest.mark.parametrize('unknown',[f'invoke-static {{}}, Ltraining/Config;->url()Ljava/lang/String;\nmove-result-object v1\n', 'invoke-virtual {v2,v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;\nmove-result-object v1\n', 'invoke-virtual {v2,v3,v4}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;\nmove-result-object v1\n'])
def test_unknown_return_config_collection_reflection_stop(tmp_path,unknown):
    write(tmp_path,func('root',builder()+unknown+f'invoke-virtual {{v0,v1}}, {B}->url(Ljava/lang/String;){B}\n'+build()))
    assert not extract_api_candidates(tmp_path)['api_candidates']


def test_callee_parameter_write_does_not_overwrite_caller_value(tmp_path):
    ops='const-string v1, "https://example.com/original"\n'+f'invoke-static {{v1}}, {OWNER}->helper(Ljava/lang/String;)V\n'+builder()+f'invoke-virtual {{v0,v1}}, {B}->url(Ljava/lang/String;){B}\n'+build()
    write(tmp_path,func('root',ops)+func('helper','const-string p0, "https://other.example/reassigned"\n','Ljava/lang/String;'))
    rows=extract_api_candidates(tmp_path)['api_candidates']
    assert len(rows)==1 and rows[0]['full_url']=='https://example.com/original'


def test_incomplete_index_cannot_resolve_ambiguous_callers(tmp_path,monkeypatch):
    import src.bounded_api_provenance as module
    write(tmp_path,func('root','const-string v1, "https://example.com/a"\n'+f'invoke-static {{v1}}, {OWNER}->helper(Ljava/lang/String;)V\n')+func('helper',helper_request(),'Ljava/lang/String;'))
    (tmp_path/'Oversize.smali').write_text('x'*2000)
    monkeypatch.setattr(module,'MAX_BYTES',1500)
    result=extract_bounded_candidates(tmp_path)
    assert not result['api_candidates']
    assert result['discovery_diagnostics']['bounded_provenance']['coverage']['partial']
