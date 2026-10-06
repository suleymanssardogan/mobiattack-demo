"""Bounded Flutter inventory stays separate from API and finding evidence."""
import json
from pathlib import Path
import pytest
from src.flutter_network_indicator_extractor import extract_flutter_network_indicators, FlutterInventoryLimits, COVERAGE_NOTE
from src.network_indicator_extractor import extract_network_indicators
from src.api_candidate_extractor import extract_api_candidates
from src.vulnerability_evaluator import evaluate_vulnerabilities
from src.static_context_builder import build_static_context
from src.report_generator import build_static_analysis_report
from src.static_inventory import FLUTTER_COVERAGE


def asset(root,name,data):
 p=root/'assets/flutter_assets'/name;p.parent.mkdir(parents=True,exist_ok=True)
 p.write_bytes(data if isinstance(data,bytes) else data.encode());return p

def native(root,data,name='libapp.so'):
 p=root/'lib/arm64-v8a'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);return p


def test_dotenv_redaction_and_secret_exclusion(tmp_path):
 asset(tmp_path,'.env','API_URL=https://api.example.test/search?q=hello&token=TOPSECRET#private\nAPI_KEY=secret.example.test\nPASSWORD=DO_NOT_KEEP\nACCESS_TOKEN_URL=https://secret.example.test')
 result=extract_flutter_network_indicators(tmp_path)
 assert len(result['network_urls'])==1
 row=result['network_urls'][0]
 assert row['query_keys']==['q','token'] and row['line_number']==1
 assert row['source_file']=='assets/flutter_assets/.env'
 assert 'TOPSECRET' not in json.dumps(result) and 'hello' not in json.dumps(result)
 assert 'secret.example.test' not in json.dumps(result) and 'private' not in json.dumps(result)
 assert row['backend_confirmed'] is False

@pytest.mark.parametrize('name',['settings.json','config.txt','settings.yaml','.env'])
def test_safe_text_assets_and_byte_offset(tmp_path,name):
 text=('BASE_URL=' if name=='.env' else 'ö start ')+ 'https://api.example.test/users'
 asset(tmp_path,name,text)
 row=extract_flutter_network_indicators(tmp_path)['network_urls'][0]
 assert row['byte_offset']==text.encode().index(b'https://')
 assert row['byte_offsets']==[row['byte_offset']]


def test_native_ascii_offsets_no_route_promotion_or_engine_scan(tmp_path):
 data=b'\x7fELF\x00https://api.example.test/api?token=SECRET\x00/api/users\x00'
 native(tmp_path,data);native(tmp_path,b'\x7fELF\x00https://engine.example.test\x00','libflutter.so')
 result=extract_flutter_network_indicators(tmp_path)
 row=result['network_urls'][0]
 assert len(result['network_urls'])==1 and row['line_number'] is None
 assert row['byte_offset']==5 and row['extraction_method']=='native_ascii_strings'
 assert 'SECRET' not in json.dumps(result) and 'engine.example.test' not in json.dumps(result)
 assert extract_api_candidates(tmp_path)['api_candidates']==[]
 assert 'path_candidates' not in result


def test_domains_noise_and_docs_retained(tmp_path):
 asset(tmp_path,'config.txt','api.example.tr config.json io.flutter.network\nhttps://docs.flutter.dev/deployment/android')
 result=extract_flutter_network_indicators(tmp_path)
 assert [r['value'] for r in result['domains']]==['api.example.tr']
 assert result['network_urls'][0]['inventory_context']=='framework_documentation'
 assert all(not r['backend_confirmed'] for r in result['network_urls']+result['domains'])


def test_dedup_preserves_occurrence_offsets_and_query_shape(tmp_path):
 asset(tmp_path,'config.txt','https://api.example.test/a?q=one\nhttps://api.example.test/a?q=UNIQUE_RAW_QUERY_VALUE\nhttps://api.example.test/a?other=three')
 first=extract_flutter_network_indicators(tmp_path)
 assert first==extract_flutter_network_indicators(tmp_path)
 assert len(first['network_urls'])==2
 repeated=next(r for r in first['network_urls'] if r['query_keys']==['q'])
 assert len(repeated['byte_offsets'])==2
 assert 'UNIQUE_RAW_QUERY_VALUE' not in json.dumps(first)

@pytest.mark.parametrize('kwargs,reason',[
 ({'max_text_bytes':4},'FILE_SIZE_LIMIT'),({'max_total_bytes':4},'TOTAL_BYTE_LIMIT'),
 ({'max_indicators':1},'INDICATOR_LIMIT'),({'max_strings':1},'STRING_LIMIT'),
 ({'max_string_bytes':4},'STRING_SIZE_LIMIT')])
def test_resource_limits_are_explicit(tmp_path,kwargs,reason):
 asset(tmp_path,'config.txt','https://api.example.test/a\nhttps://other.example.test/b')
 result=extract_flutter_network_indicators(tmp_path,limits=FlutterInventoryLimits(**kwargs))
 assert reason in result['coverage']['limit_reasons']
 assert result['coverage']['status']=='partial'


def test_file_entry_limits_invalid_elf_utf8_and_symlink(tmp_path):
 asset(tmp_path,'a.txt','https://api.example.test')
 asset(tmp_path,'b.txt','https://other.example.test')
 assert 'FILE_LIMIT' in extract_flutter_network_indicators(tmp_path,limits=FlutterInventoryLimits(max_files=1))['coverage']['limit_reasons']
 assert 'ENTRY_LIMIT' in extract_flutter_network_indicators(tmp_path,limits=FlutterInventoryLimits(max_entries=1))['coverage']['limit_reasons']
 native(tmp_path,b'not an ELF https://fake.example.test')
 asset(tmp_path,'bad.txt',b'\xffhttps://fake.example.test')
 out=extract_flutter_network_indicators(tmp_path)
 assert {'INVALID_ELF','UNREADABLE_OR_NON_UTF8'}<=set(out['coverage']['limit_reasons'])
 external=tmp_path/'external.txt';external.write_text('https://external.example.test')
 (tmp_path/'assets/flutter_assets/link.txt').symlink_to(external)
 assert 'external.example.test' not in json.dumps(extract_flutter_network_indicators(tmp_path))


def test_generic_integration_never_keeps_unredacted_duplicate(tmp_path):
 asset(tmp_path,'config.json','{"url":"https://api.example.test/a?token=SECRET"}')
 coverage={};out=extract_network_indicators(tmp_path,coverage=coverage)
 assert len(out['network_urls'])==1 and 'SECRET' not in json.dumps(out)
 assert coverage['flutter']['note']==COVERAGE_NOTE
 assert set(out)=={'network_urls','domains','ip_addresses','path_candidates','local_file_urls'}


def test_static_context_report_and_finding_boundary(tmp_path):
 decoded=tmp_path/'decoded';decoded.mkdir();raw=tmp_path/'raw';raw.mkdir()
 manifest=decoded/'AndroidManifest.xml'
 manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.training"><application/></manifest>')
 asset(decoded,'.env','API_URL=http://api.example.test/plain?token=SECRET')
 asset(raw,'.env','API_URL=http://api.example.test/plain?token=SECRET')
 context=build_static_context(manifest,raw,decoded)
 assert context['api_candidates']==[] and 'flutter' in context['api_discovery']
 assert evaluate_vulnerabilities(context)['findings']==[]
 report=build_static_analysis_report('f2',report_dict={'platform':'android',**context})
 assert FLUTTER_COVERAGE in report['limitations']
 assert report['api_candidates']==[] and report['vulnerabilities']['findings']==[]
 assert 'SECRET' not in json.dumps(report)
 assert report['network_indicators']['network_urls'][0]['byte_offset']>0


def test_query_without_slash_and_fragment_redaction(tmp_path):
 asset(tmp_path,'.env','API_URL=https://api.example.test?token=NO_PATH_SECRET#fragment')
 row=extract_flutter_network_indicators(tmp_path)['network_urls'][0]
 assert row['query_keys']==['token']
 assert 'NO_PATH_SECRET' not in row['value'] and 'fragment' not in row['value']


def test_unproven_libapp_name_does_not_assert_flutter(tmp_path):
 native(tmp_path,b'\x7fELF\x00https://api.example.test\x00')
 out=extract_flutter_network_indicators(tmp_path)
 assert out['network_urls']==[] and out['coverage']['detected'] is False


def test_utf16_and_binary_assets_not_promoted(tmp_path):
 asset(tmp_path,'AssetManifest.bin',b'https://fake.example.test')
 asset(tmp_path,'utf16.txt','https://hidden.example.test'.encode('utf-16'))
 result=extract_flutter_network_indicators(tmp_path)
 assert result['network_urls']==[]
 assert 'UNREADABLE_OR_NON_UTF8' in result['coverage']['limit_reasons']


def test_canonical_split_provenance_for_dexless_native_component(tmp_path):
 from src.split_static_context_builder import build_split_static_context
 root=tmp_path/'component';root.mkdir()
 (root/'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example.training"><application/></manifest>')
 asset(root,'.env','API_URL=https://api.example.test')
 native(root,b'\x7fELF\x00https://api.example.test/native\x00')
 native(root,b'\x7fELF','libflutter.so')
 component={'filename':'base.apk','role':'base','has_dex':False,'preprocessing':{'raw_apk_dir':str(root),'apktool_dir':str(root)}}
 ctx=build_split_static_context({'package_name':'example.training','components':[component]},unified_analysis_root=tmp_path/'out')
 rows=ctx['network_indicators']['network_urls']
 assert len(rows)==2 and all(r['source_apk']=='base.apk' for r in rows)
 assert ctx['api_candidates']==[]
 assert ctx['api_discovery']['components'][0]['flutter']['files_scanned']==2


def test_repeated_evidence_output_is_bounded(tmp_path):
 asset(tmp_path,'config.txt','\n'.join(['https://api.example.test']*5))
 result=extract_flutter_network_indicators(tmp_path,limits=FlutterInventoryLimits(max_occurrences=2))
 assert 'OCCURRENCE_LIMIT' in result['coverage']['limit_reasons']
 assert len(result['network_urls'][0]['byte_offsets'])==2


def test_url_userinfo_never_persisted_as_url_or_domain(tmp_path):
 asset(tmp_path,'.env','API_URL=https://credential.example.test:UNIQUE_PASSWORD@api.example.test/a?q=UNIQUE_QUERY#UNIQUE_FRAGMENT')
 result=extract_flutter_network_indicators(tmp_path)
 assert len(result['network_urls'])==1
 payload=json.dumps(result)
 assert 'credential.example.test' not in payload and 'UNIQUE_PASSWORD' not in payload
 assert 'UNIQUE_QUERY' not in payload and 'UNIQUE_FRAGMENT' not in payload
 assert result['domains']==[]
