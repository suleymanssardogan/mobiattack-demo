import json
from pathlib import Path
import pytest
from src.static_webview_metadata import extract_webview_metadata
from src.vulnerability_evaluator import evaluate_vulnerabilities

WEB='Landroid/webkit/WebView;'
SET='Landroid/webkit/WebSettings;'
SIG='onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V'

def smali(root,name,body,*,parent='Landroid/app/Activity;',symbol='run()V',static=True):
 p=root/'smali'/f'{name}.smali';p.parent.mkdir(parents=True,exist_ok=True)
 p.write_text(f'.class public Ltest/{name};\n.super {parent}\n.method public '+('static ' if static else '')+symbol+'\n.locals 8\n'+body+'\nreturn-void\n.end method')
 return p

def manifest(root):
 (root/'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test"><application><activity android:name="test.Main"/></application></manifest>')

def setup():
 return f'''new-instance v0, {WEB}
invoke-direct {{v0, p0}}, {WEB}-><init>(Landroid/content/Context;)V
invoke-virtual {{v0}}, {WEB}->getSettings(){SET}
move-result-object v1
const/4 v2, 0x1
invoke-virtual {{v1, v2}}, {SET}->setJavaScriptEnabled(Z)V'''

def linked(root,behavior='proceed',*,app=True,branch=False,client='Client',bad_handler=False):
 if app:manifest(root)
 body='if-eqz p1, :end\n:end\n' if branch else ''
 body+=(f'invoke-virtual {{{"p3" if bad_handler else "p2"}}}, Landroid/webkit/SslErrorHandler;->{behavior}()V')
 smali(root,client,body,parent='Landroid/webkit/WebViewClient;',symbol=SIG,static=False)
 smali(root,'Main',setup()+f'\nnew-instance v3, Ltest/{client};\ninvoke-direct {{v3}}, Ltest/{client};-><init>()V\ninvoke-virtual {{v0, v3}}, {WEB}->setWebViewClient(Landroid/webkit/WebViewClient;)V',static=False)
 return extract_webview_metadata(root)

def eligible(result):return [r for r in result['evidence'] if r['evidence_tier']=='finding_eligible_evidence']

def test_js_and_url_same_instance(tmp_path):
 smali(tmp_path,'Main',setup()+f'\nconst-string v4, "https://api.example.test/search?token=SECRET&q=value#fragment"\ninvoke-virtual {{v0, v4}}, {WEB}->loadUrl(Ljava/lang/String;)V')
 result=extract_webview_metadata(tmp_path)
 setting=next(r for r in result['evidence'] if r['kind']=='webview_setting');url=next(r for r in result['evidence'] if r['kind']=='url_loading')
 assert setting['value']==1 and setting['webview_instance_id']==url['webview_instance_id']
 assert url['host']=='api.example.test' and url['query_keys']==['q','token']
 assert 'SECRET' not in json.dumps(result) and 'fragment' not in json.dumps(result)
 assert not eligible(result) and not evaluate_vulnerabilities({'webview_metadata':result})['findings']

@pytest.mark.parametrize('flag',['setAllowFileAccess','setAllowContentAccess','setAllowFileAccessFromFileURLs','setAllowUniversalAccessFromFileURLs'])
def test_file_settings_not_findings(tmp_path,flag):
 smali(tmp_path,'Main',setup()+f'\ninvoke-virtual {{v1, v2}}, {SET}->{flag}(Z)V')
 result=extract_webview_metadata(tmp_path)
 assert any(r.get('setting')==flag and r['value']==1 for r in result['evidence'])
 assert not eligible(result)

@pytest.mark.parametrize('mode',[0,1,2])
def test_mixed_content_modes(tmp_path,mode):
 smali(tmp_path,'Main',setup()+f'\nconst/4 v2, {mode}\ninvoke-virtual {{v1, v2}}, {SET}->setMixedContentMode(I)V')
 row=next(r for r in extract_webview_metadata(tmp_path)['evidence'] if r.get('setting')=='setMixedContentMode')
 assert row['value']==mode and row['evidence_tier']==('risky_indicator' if mode==0 else 'configuration_metadata')

@pytest.mark.parametrize('url,kind',[('file:///android_asset/test.html','local_asset'),('file:///sdcard/test.html','local_file'),('javascript:secret()','other_scheme')])
def test_local_file_url_and_other_schemes(tmp_path,url,kind):
 smali(tmp_path,'Main',setup()+f'\nconst-string v4, "{url}"\ninvoke-virtual {{v0, v4}}, {WEB}->loadUrl(Ljava/lang/String;)V')
 result=extract_webview_metadata(tmp_path);row=next(r for r in result['evidence'] if r['kind']=='url_loading')
 assert row['url_kind']==kind and not eligible(result)
 assert 'secret()' not in json.dumps(result)

def test_js_bridge_metadata_only(tmp_path):
 smali(tmp_path,'Main',setup()+f'\nnew-instance v3, Ltest/Bridge;\nconst-string v4, "Bridge"\ninvoke-virtual {{v0, v3, v4}}, {WEB}->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V')
 result=extract_webview_metadata(tmp_path);row=next(r for r in result['evidence'] if r['kind']=='javascript_interface')
 assert row['interface_type']=='Ltest/Bridge;' and row['interface_name_resolved'] and not eligible(result)

def test_linked_ssl_proceed_eligible_not_created_finding(tmp_path):
 result=linked(tmp_path);rows=eligible(result)
 assert len(rows)==1 and rows[0]['app_linked']
 assert set(rows[0]['callback_evidence_refs'])<=set(r['evidence_id'] for r in result['evidence'])
 assert rows[0]['finding_created'] is False and not evaluate_vulnerabilities({'webview_metadata':result})['findings']

@pytest.mark.parametrize('kwargs',[{'app':False},{'branch':True},{'bad_handler':True},{'behavior':'cancel'}])
def test_weak_ssl_evidence_not_eligible(tmp_path,kwargs):
 assert not eligible(linked(tmp_path,**kwargs))

def test_callback_presence_without_client_binding(tmp_path):
 smali(tmp_path,'Client','invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V',parent='Landroid/webkit/WebViewClient;',symbol=SIG,static=False)
 assert not eligible(extract_webview_metadata(tmp_path))

def test_handler_alias_proven(tmp_path):
 result=linked(tmp_path)
 path=tmp_path/'smali/Client.smali';path.write_text(path.read_text().replace('invoke-virtual {p2}', 'move-object v0, p2\ninvoke-virtual {v0}'))
 assert eligible(extract_webview_metadata(tmp_path))

def test_handler_replacement_not_proven(tmp_path):
 linked(tmp_path)
 path=tmp_path/'smali/Client.smali';path.write_text(path.read_text().replace('invoke-virtual {p2}', 'move-object p2, p3\ninvoke-virtual {p2}'))
 assert not eligible(extract_webview_metadata(tmp_path))

def test_multiple_webviews_isolated(tmp_path):
 smali(tmp_path,'Main',setup()+f'\nnew-instance v4, {WEB}\ninvoke-direct {{v4, p0}}, {WEB}-><init>(Landroid/content/Context;)V\nconst-string v5, "https://example.test"\ninvoke-virtual {{v4, v5}}, {WEB}->loadUrl(Ljava/lang/String;)V')
 result=extract_webview_metadata(tmp_path)
 setting=next(r for r in result['evidence'] if r['kind']=='webview_setting');url=next(r for r in result['evidence'] if r['kind']=='url_loading')
 assert setting['webview_instance_id']!=url['webview_instance_id']

def test_overwritten_register_does_not_reuse_setting(tmp_path):
 smali(tmp_path,'Main',setup()+f'\niget-object v1, p0, Ltest/Main;->settings:{SET}\ninvoke-virtual {{v1, v2}}, {SET}->setAllowFileAccess(Z)V')
 rows=extract_webview_metadata(tmp_path)['evidence'];row=next(r for r in rows if r.get('setting')=='setAllowFileAccess')
 assert row['webview_instance_id'] is None

def test_unknown_value_not_inferred_true(tmp_path):
 smali(tmp_path,'Main',setup()+f'\nmove v2, p1\ninvoke-virtual {{v1, v2}}, {SET}->setAllowFileAccess(Z)V')
 row=next(r for r in extract_webview_metadata(tmp_path)['evidence'] if r.get('setting')=='setAllowFileAccess')
 assert row['value'] is None

def test_class_name_only_not_detected(tmp_path):
 smali(tmp_path,'Main','const-string v0, "WebView addJavascriptInterface SslErrorHandler.proceed"')
 assert not extract_webview_metadata(tmp_path)['detected']

def test_unreachable_proceed_not_eligible(tmp_path):
 linked(tmp_path);p=tmp_path/'smali/Client.smali';p.write_text(p.read_text().replace('invoke-virtual {p2}', 'return-void\ninvoke-virtual {p2}'))
 assert not eligible(extract_webview_metadata(tmp_path))

def test_chrome_client_linkage(tmp_path):
 smali(tmp_path,'Main',setup()+f'\nnew-instance v3, Landroid/webkit/WebChromeClient;\ninvoke-direct {{v3}}, Landroid/webkit/WebChromeClient;-><init>()V\ninvoke-virtual {{v0, v3}}, {WEB}->setWebChromeClient(Landroid/webkit/WebChromeClient;)V')
 row=next(r for r in extract_webview_metadata(tmp_path)['evidence'] if r['kind']=='webchrome_client')
 assert row['client_type']=='Landroid/webkit/WebChromeClient;' and row['webview_instance_id']

def test_deterministic_and_relative_provenance(tmp_path):
 linked(tmp_path);a=extract_webview_metadata(tmp_path);assert a==extract_webview_metadata(tmp_path)
 assert str(tmp_path) not in json.dumps(a)
 assert all(r['line_number']>0 for r in a['evidence'])

def test_static_and_report_wiring(tmp_path):
 from src.static_context_builder import build_static_context
 from src.report_generator import build_static_analysis_report
 linked(tmp_path);raw=tmp_path/'raw';raw.mkdir()
 context=build_static_context(tmp_path/'AndroidManifest.xml',raw,tmp_path)
 assert context['webview_metadata']['evidence']
 report=build_static_analysis_report('webview',report_dict={'platform':'android',**context})
 assert report['webview_metadata']==context['webview_metadata']

def test_guard_throw_does_not_suppress_reachable_metadata(tmp_path):
 body=f'if-nez v0, :ready\nnew-instance v3, Ljava/lang/RuntimeException;\nthrow v3\n:ready\ncheck-cast v0, {WEB}\ninvoke-virtual {{v0}}, {WEB}->getSettings(){SET}\nmove-result-object v1\nconst/4 v2, 0x1\ninvoke-virtual {{v1, v2}}, {SET}->setJavaScriptEnabled(Z)V'
 smali(tmp_path,'Main',body)
 row=next(r for r in extract_webview_metadata(tmp_path)['evidence'] if r['kind']=='webview_setting')
 assert row['value']==1 and row['webview_instance_id']

def test_super_ssl_cancel_then_proceed_not_eligible(tmp_path):
 linked(tmp_path);p=tmp_path/'smali/Client.smali'
 p.write_text(p.read_text().replace('invoke-virtual {p2}', 'invoke-super {p0, p1, p2, p3}, Landroid/webkit/WebViewClient;->'+SIG+'\ninvoke-virtual {p2}'))
 assert not eligible(extract_webview_metadata(tmp_path))

def test_split_refs_are_scoped_and_preserved(tmp_path):
 from src.split_static_context_builder import build_split_static_context
 linked(tmp_path);raw=tmp_path/'raw';raw.mkdir()
 context=build_split_static_context({'package_name':'test','components':[{'filename':'base.apk','role':'base','has_dex':False,'preprocessing':{'apktool_status':'success','apktool_dir':str(tmp_path),'raw_apk_dir':str(raw)}}]},tmp_path/'unified')
 result=context['webview_metadata'];assert eligible(result)
 row=eligible(result)[0]
 assert row['source_apk']=='base.apk' and row['webview_instance_id'].startswith('base.apk:')
 assert set(row['callback_evidence_refs'])<=set(r['evidence_id'] for r in result['evidence'])

def test_other_calls_preserve_reference_not_effective_settings(tmp_path):
 smali(tmp_path,'Main',setup()+f'\ninvoke-virtual {{v0, v2}}, {WEB}->setVerticalScrollBarEnabled(Z)V\nconst-string v4, "file:///android_asset/test.html"\ninvoke-virtual {{v0, v4}}, {WEB}->loadUrl(Ljava/lang/String;)V')
 rows=extract_webview_metadata(tmp_path)['evidence'];setting=next(r for r in rows if r['kind']=='webview_setting');url=next(r for r in rows if r['kind']=='url_loading')
 assert setting['webview_instance_id']==url['webview_instance_id']
 assert 'effective_settings' not in url
