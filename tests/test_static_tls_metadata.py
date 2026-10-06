from datetime import date
import base64
import json
from pathlib import Path
import pytest
from src.static_tls_metadata import extract_static_tls_metadata
from src.static_context_builder import build_static_context
from src.report_generator import build_static_analysis_report
from src.vulnerability_evaluator import evaluate_vulnerabilities

HASH=base64.b64encode(b'x'*32).decode()
PIN='sha256/'+HASH

def config(root, body, *, linked=True, debug=False):
 (root/'res/xml').mkdir(parents=True,exist_ok=True)
 (root/'res/xml/net.xml').write_text('<network-security-config>'+body+'</network-security-config>')
 (root/'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="training.test"><application '+('android:networkSecurityConfig="@xml/net" ' if linked else '')+('android:debuggable="true" ' if debug else '')+'/></manifest>')

def code(root, body, declaration=''):
 p=root/'smali/test/Client.smali';p.parent.mkdir(parents=True,exist_ok=True)
 p.write_text('.class public Ltest/Client;\n'+declaration+'\n.method public static run()V\n'+body+'\nreturn-void\n.end method')
 return p

def flow(host='api.example.test',pin=PIN):
 return f'''new-instance v0, Lokhttp3/CertificatePinner$Builder;
invoke-direct {{v0}}, Lokhttp3/CertificatePinner$Builder;-><init>()V
const-string v1, "{host}"
const-string v2, "{pin}"
filled-new-array {{v2}}, [Ljava/lang/String;
move-result-object v3
invoke-virtual {{v0, v1, v3}}, Lokhttp3/CertificatePinner$Builder;->add(Ljava/lang/String;[Ljava/lang/String;)Lokhttp3/CertificatePinner$Builder;
move-result-object v0
invoke-virtual {{v0}}, Lokhttp3/CertificatePinner$Builder;->build()Lokhttp3/CertificatePinner;
move-result-object v4
new-instance v5, Lokhttp3/OkHttpClient$Builder;
invoke-direct {{v5}}, Lokhttp3/OkHttpClient$Builder;-><init>()V
invoke-virtual {{v5, v4}}, Lokhttp3/OkHttpClient$Builder;->certificatePinner(Lokhttp3/CertificatePinner;)Lokhttp3/OkHttpClient$Builder;
move-result-object v5
invoke-virtual {{v5}}, Lokhttp3/OkHttpClient$Builder;->build()Lokhttp3/OkHttpClient;'''

def extract(root): return extract_static_tls_metadata(root,as_of=date(2026,10,5))
def proven(result): return [r for r in result['evidence'] if r['classification']=='PROVEN_STATIC_PINNING_CONFIG']

def test_nsc_pin_scope_expiration_provenance(tmp_path):
 config(tmp_path,f'<domain-config><domain includeSubdomains="true">example.test</domain><pin-set expiration="2025-01-01"><pin digest="SHA-256">{HASH}</pin></pin-set></domain-config>')
 r=proven(extract(tmp_path))[0]
 assert r['expired'] is True and r['domains']==['example.test']
 assert r['scope_include_subdomains']=={'example.test':True}
 assert r['source_file']=='res/xml/net.xml' and r['manifest_ref']['value']=='@xml/net'
 assert r['runtime_enforcement']=='not_established' and r['finding_created'] is False

@pytest.mark.parametrize('hash,expiration',[('invalid','2050-01-01'),(HASH,'wrong-date')])
def test_invalid_pins_or_expiration_not_proven(tmp_path,hash,expiration):
 config(tmp_path,f'<domain-config><domain>example.test</domain><pin-set expiration="{expiration}"><pin digest="SHA-256">{hash}</pin></pin-set></domain-config>')
 result=extract(tmp_path)
 assert not proven(result) and result['evidence'][0]['classification']=='POSSIBLE_PINNING'

def test_unlinked_config_not_promoted(tmp_path):
 config(tmp_path,f'<domain-config><domain>example.test</domain><pin-set><pin digest="SHA-256">{HASH}</pin></pin-set></domain-config>',linked=False)
 assert not extract(tmp_path)['evidence']

def test_trust_anchors_debug_overrides_only_customization(tmp_path):
 config(tmp_path,'<base-config><trust-anchors><certificates src="@raw/ca"/><certificates src="system"/></trust-anchors></base-config><debug-overrides><trust-anchors><certificates src="user"/></trust-anchors></debug-overrides>',debug=True)
 rows=extract(tmp_path)['evidence'];assert len(rows)==4
 assert all(r['classification']=='TLS_CUSTOMIZATION' for r in rows)
 r=next(r for r in rows if r.get('certificate_source')=='user')
 assert r['debug_only'] and r['debuggable'] and r['override_pins']=='true'

def test_direct_okhttp_binding(tmp_path):
 code(tmp_path,flow());r=proven(extract(tmp_path))[0]
 assert r['bindings']==[{'host':'api.example.test','hashes':[PIN]}]
 assert r['source_method']=='run()V' and len(r['evidence_lines'])>=3

@pytest.mark.parametrize('replacement',[ 'const-string v2, "sha256/bad"','move-object v2, p0'])
def test_bad_unknown_pin_not_proven(tmp_path,replacement):
 code(tmp_path,flow().replace(f'const-string v2, "{PIN}"',replacement))
 assert not proven(extract(tmp_path))

def test_class_presence_and_hash_strings_do_not_promote(tmp_path):
 code(tmp_path,f'const-string v0, "{PIN}"\nconst-class v1, Lokhttp3/CertificatePinner;')
 assert not extract(tmp_path)['evidence']

def test_branch_not_resolved(tmp_path):
 code(tmp_path,flow()+'\nif-eqz v1, :end\n:end')
 assert not proven(extract(tmp_path))

def test_unbound_builder_not_proven(tmp_path):
 code(tmp_path,flow().split('new-instance v5')[0])
 assert not proven(extract(tmp_path))

def test_unknown_call_invalidates_receiver(tmp_path):
 code(tmp_path,flow().replace('invoke-virtual {v5}, Lokhttp3/OkHttpClient$Builder;->build()', 'invoke-static {v5}, Ltest/Unknown;->mutate(Ljava/lang/Object;)V\ninvoke-virtual {v5}, Lokhttp3/OkHttpClient$Builder;->build()'))
 assert not proven(extract(tmp_path))

def test_receiver_isolation(tmp_path):
 body=flow().replace('invoke-virtual {v0, v1, v3}', 'new-instance v8, Lokhttp3/CertificatePinner$Builder;\ninvoke-direct {v8}, Lokhttp3/CertificatePinner$Builder;-><init>()V\ninvoke-virtual {v8, v1, v3}')
 code(tmp_path,body.replace("move-result-object v0\n", ""));assert not proven(extract(tmp_path))

def test_array_flow(tmp_path):
 body=flow().replace('filled-new-array {v2}, [Ljava/lang/String;\nmove-result-object v3','const/4 v6, 0x1\nnew-array v3, v6, [Ljava/lang/String;\nconst/4 v6, 0x0\naput-object v2, v3, v6')
 code(tmp_path,body);assert len(proven(extract(tmp_path)))==1

def test_reassigned_url_register_not_stale(tmp_path):
 code(tmp_path,flow().replace('invoke-virtual {v0, v1, v3}', 'iget-object v1, p0, Ltest/Client;->host:Ljava/lang/String;\ninvoke-virtual {v0, v1, v3}'))
 assert not proven(extract(tmp_path))

def test_custom_tls_calls_not_pinning(tmp_path):
 code(tmp_path,'invoke-virtual {v0, v1, v2, v3}, Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V\ninvoke-virtual {v4, v5}, Ljavax/net/ssl/HttpsURLConnection;->setHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V')
 assert len(extract(tmp_path)['evidence'])==2 and not proven(extract(tmp_path))

def test_bundled_certificate_supporting_only(tmp_path):
 from cryptography import x509
 from cryptography.hazmat.primitives import hashes,serialization
 from cryptography.hazmat.primitives.asymmetric import rsa
 from cryptography.x509.oid import NameOID
 from datetime import datetime,timezone,timedelta
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'training.test')]);now=datetime.now(timezone.utc)
 cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now).not_valid_after(now+timedelta(days=1)).sign(key,hashes.SHA256())
 (tmp_path/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
 (tmp_path/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
 (tmp_path/'public.pub').write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
 (tmp_path/'public.der').write_bytes(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
 result=extract(tmp_path);assert len(result['evidence'])==3
 assert all(r['supporting_evidence_only'] for r in result['evidence']) and not proven(result)
 assert 'PRIVATE KEY' not in json.dumps(result) and 'PRIVATE_KEY_MATERIAL_EXCLUDED' in result['coverage']['limitations']

def test_deterministic_dedup(tmp_path):
 code(tmp_path,flow());assert extract(tmp_path)==extract(tmp_path)

def test_metadata_not_finding_and_report_preserved(tmp_path):
 config(tmp_path,'<base-config><trust-anchors><certificates src="system"/></trust-anchors></base-config>')
 code(tmp_path,flow());raw=tmp_path/'raw';raw.mkdir()
 ctx=build_static_context(tmp_path/'AndroidManifest.xml',raw,tmp_path)
 assert ctx['tls_metadata']['evidence']
 assert not evaluate_vulnerabilities(ctx)['findings']
 report=build_static_analysis_report('tls-test',report_dict={'platform':'android',**ctx})
 assert report['tls_metadata']==ctx['tls_metadata']

def test_nsc_no_expiration_and_nested_scope(tmp_path):
 config(tmp_path,f'<domain-config><domain>outer.test</domain><domain-config><domain>inner.test</domain><pin-set><pin digest="SHA-256">{HASH}</pin></pin-set></domain-config></domain-config>')
 r=proven(extract(tmp_path))[0]
 assert r['domains']==['inner.test'] and r['expiration'] is None and r['expired'] is None

def test_unknown_call_invalidates_pinner(tmp_path):
 code(tmp_path,flow().replace('new-instance v5,','invoke-static {v4}, Ltest/Unknown;->mutate(Ljava/lang/Object;)V\nnew-instance v5,'))
 assert not proven(extract(tmp_path))

def test_abstract_interface_not_promoted(tmp_path):
 p=code(tmp_path,'', '.implements Ljavax/net/ssl/HostnameVerifier;')
 p.write_text('.class public abstract Ltest/Client;\n.implements Ljavax/net/ssl/HostnameVerifier;\n.method public abstract verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z\n.end method')
 assert not extract(tmp_path)['evidence']

def test_symlink_boundary(tmp_path):
 target=tmp_path/'outside';target.mkdir();code(target,flow())
 scan=tmp_path/'scan';scan.mkdir();(scan/'Client.smali').symlink_to(target/'smali/test/Client.smali')
 result=extract(scan);assert not proven(result) and 'SOURCE_BOUNDARY' in result['coverage']['limitations']

def test_metadata_contains_no_private_paths_or_payloads(tmp_path):
 code(tmp_path,flow());result=extract(tmp_path)
 assert str(tmp_path) not in json.dumps(result)
 assert all(r['finding_created'] is False and r['runtime_enforcement']=='not_established' for r in result['evidence'])

@pytest.mark.parametrize('host',['https://api.example.test','api.example.test/path','api..test','-bad.test'])
def test_invalid_host_bindings_rejected(tmp_path,host):
 code(tmp_path,flow(host=host));assert not proven(extract(tmp_path))

def test_nsc_rejects_unsupported_digest(tmp_path):
 digest=base64.b64encode(b'x'*20).decode()
 config(tmp_path,f'<domain-config><domain>example.test</domain><pin-set><pin digest="SHA-1">{digest}</pin></pin-set></domain-config>')
 assert not proven(extract(tmp_path))

def test_assessment_date_does_not_change_evidence_identity(tmp_path):
 config(tmp_path,f'<domain-config><domain>example.test</domain><pin-set expiration="2027-01-01"><pin digest="SHA-256">{HASH}</pin></pin-set></domain-config>')
 first=extract_static_tls_metadata(tmp_path,as_of=date(2026,1,1))['evidence'][0]
 second=extract_static_tls_metadata(tmp_path,as_of=date(2028,1,1))['evidence'][0]
 assert first['evidence_id']==second['evidence_id'] and first['expired'] is False and second['expired'] is True

def test_split_provenance_and_canonical_report(tmp_path):
 from src.split_static_context_builder import build_split_static_context
 config(tmp_path,'<base-config><trust-anchors><certificates src="system"/></trust-anchors></base-config>')
 raw=tmp_path/'raw';raw.mkdir()
 context=build_split_static_context({'package_name':'training.test','components':[{'filename':'base.apk','role':'base','has_dex':False,'preprocessing':{'apktool_status':'success','apktool_dir':str(tmp_path),'raw_apk_dir':str(raw)}}]},tmp_path/'unified')
 rows=context['tls_metadata']['evidence']
 assert rows and all(r['source_apk']=='base.apk' for r in rows)
 report=build_static_analysis_report('split-tls',report_dict={'platform':'android',**context})
 assert report['tls_metadata']==context['tls_metadata']
