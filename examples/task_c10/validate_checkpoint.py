"""Re-run existing local Static artifacts only; no acquisition/network/runtime."""
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from src.static_context_builder import build_static_context
from src.split_static_context_builder import build_split_static_context
from src.report_generator import build_static_analysis_report
from src.web.report_summary import build_report_summary
from src.vulnerability_evaluator import evaluate_vulnerabilities
from src.apk_acquirer import validate_apk_structure

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).parent
TEMP = Path('/tmp/mobiattack-c1-real-final')
APPS = {
 'OWASP Kotlin': ('mono', TEMP/'owasp_1/workspaces/MSTG-Android-Kotlin'),
 'Wikipedia': ('split', TEMP/'wikipedia/downloads/package_set/package_set.json'),
 'Flashlight': ('split', TEMP/'flashlight/downloads/package_set/package_set.json'),
 'AntennaPod': ('mono', ROOT/'demo_runs/task_9_5_3_app_011/workspaces/de.danoeh.antennapod'),
 'VulnBank': ('mono', ROOT/'demo_runs/task_9_5_3_app_005/workspaces/vulnbank3'),
 'Damn Vulnerable Bank': ('mono', ROOT/'demo_runs/task_9_5_3_app_006/workspaces/dvba_v1.1.0'),
}


def fingerprint(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def normalize(data):
    # Only volatile run/time/temp-output paths; list ordering is deliberately kept.
    if isinstance(data, dict):
        return {k: normalize(v) for k,v in data.items() if k not in {'generated_at','timestamp','created_at','run_id'}}
    if isinstance(data, list):
        return [normalize(v) for v in data]
    if isinstance(data, str):
        return data.replace(str(OUT/'repeat_a'), '<output>').replace(str(OUT/'repeat_b'), '<output>')
    return data


def run(name, kind, path, repeat):
    if kind == 'split':
        package = json.loads(path.read_text())
        if repeat == 'repeat_b':
            package['components'].reverse()
        context = build_split_static_context(package, OUT/repeat/name.replace(' ','_'))
    else:
        context = build_static_context(path/'apktool_out/AndroidManifest.xml', path/'raw_apk', path/'apktool_out')
    if kind == 'split':
        acquisition = deepcopy(package)
        preprocessing = {'components': [dict(filename=c['filename'], **c.get('preprocessing', {})) for c in package['components']],
                         'jadx': {'status': next(c.get('preprocessing', {}).get('jadx_status') for c in package['components'] if c['role']=='base')}}
    else:
        apk = next((path.parent.parent/'downloads').glob('*.apk'))
        acquisition = {'filename': apk.name, 'sha256': hashlib.sha256(apk.read_bytes()).hexdigest(),
                       'size_bytes': apk.stat().st_size, 'validation': validate_apk_structure(apk),
                       'source_type': 'existing_local_fixture', 'platform': 'android'}
        preprocessing = {}
    pipeline = {'static_analysis': deepcopy(context), 'acquisition': acquisition, 'preprocessing': preprocessing}
    report = build_static_analysis_report('c10_'+repeat, pipeline_result=pipeline)
    assert report['application']['package_name'] == context['manifest']['package_name']
    if kind == 'split':
        assert report['split_count'] == len(package['components'])
        assert len(report['apk_components']) == len(package['components'])
    summary = build_report_summary(report)
    return {'context': context, 'report': report, 'summary': summary}


def main():
    results={}
    for name,(kind,path) in APPS.items():
        required=[path] if kind=='split' else [path/'apktool_out/AndroidManifest.xml',path/'raw_apk']
        if not all(p.exists() for p in required):
            results[name]={'status':'NOT_RUN','reason':'Existing decoded/raw input unavailable','path':str(path)}
            print(name, 'NOT_RUN', flush=True)
            continue
        try:
            first=run(name,kind,path,'repeat_a')
            second=run(name,kind,path,'repeat_b')
            a,b=normalize(first),normalize(second)
            assert a==b, 'Static repeat/order mismatch'
            context=first['context'];report=first['report'];manifest=context['manifest']
            assert manifest['package_name'] and context['app']['package_name']==manifest['package_name']
            assert '.unknown' not in str(manifest.get('launcher_activity') or '')
            rows=context['api_candidates']
            assert len({r['candidate_id'] for r in rows})==len(rows)
            assert all(r.get('provenance') and r.get('evidence_refs') for r in rows)
            assert all('?' not in (r.get('full_url') or '') for r in rows)
            findings=report['vulnerabilities']['findings']
            assert all(r['evidence_tier']=='finding_eligible' and r['provenance_refs'] and r['standards'] for r in findings)
            assert not any(r['assessment_state']=='passed' for r in report['vulnerabilities']['control_coverage'])
            if name=='OWASP Kotlin':
                assert any(r['method']=='POST' and r['path']=='/signup' for r in rows)
                assert any(r['reason_code']=='MANIFEST_DEBUGGABLE_TRUE' for r in findings)
            counts={key:len(context['network_indicators'].get(key,[])) for key in ('network_urls','domains','ip_addresses','path_candidates','local_file_urls')}
            (OUT/(name.replace(' ','_')+'_static_report.json')).write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
            (OUT/(name.replace(' ','_')+'_summary.json')).write_text(json.dumps(first['summary'],indent=2,sort_keys=True)+'\n')
            results[name]={'status':'PASS','package':manifest['package_name'],'input_kind':kind,
                'split_count':context['split_count'] if kind=='split' else 1,
                'api_candidates':len(rows),'static_findings':len(findings),'network_indicators':counts,
                'repeat_match':True,'fingerprint':fingerprint(a),
                'section_fingerprints':{key:fingerprint(normalize(context.get(key))) for key in
                    ('manifest','structure','network_indicators','api_candidates','api_discovery')},
                'report_fingerprint':fingerprint(normalize(report)),
                'unresolved_coverage':context.get('api_discovery',{}),
                'report_status':report.get('status')}
            print(name,'PASS',len(rows),'candidates',len(findings),'findings',results[name]['fingerprint'],flush=True)
        except Exception as exc:
            results[name]={'status':'FAIL','reason':str(exc),'error_type':type(exc).__name__}
            print(name,'FAIL',type(exc).__name__,str(exc),flush=True)
        (OUT/'checkpoint.json').write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
    (OUT/'checkpoint.json').write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
    if any(r['status']=='FAIL' for r in results.values()):
        raise SystemExit(1)

if __name__=='__main__':
    main()
