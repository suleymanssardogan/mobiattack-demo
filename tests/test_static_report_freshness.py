"""M2: fresh static artifacts, explicit runs, and reset race isolation."""
import json
import shutil
import subprocess
from pathlib import Path
from urllib.request import urlopen
from urllib.error import HTTPError
import pytest
from src.report_generator import generate_reports
from src.static_context_builder import build_static_context
from src.vulnerability_evaluator import evaluate_vulnerabilities
from src.static_security.report_freshness import load_current_static_report
from src.web.report_summary import load_report_summary
from src.demo_web_server import DemoWebServer


def fresh_scan(root, run_id='fresh_m2'):
    directory=root/run_id; decoded=directory/'fixture'; decoded.mkdir(parents=True)
    (decoded/'AndroidManifest.xml').write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.training.m2"><uses-permission android:name="android.permission.INTERNET"/><application android:debuggable="true"><activity android:name=".MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity></application></manifest>''')
    smali=decoded/'smali'; smali.mkdir()
    (smali/'Network.smali').write_text('''.class public Lorg/training/Network;
.super Ljava/lang/Object;
.method public probe()V
.locals 2
const-string v0, "http://a"
const-string v0, "127.0.0.1"
const-string v0, "/supersonicads"
const-string v1, "http://api.company.com/profile"
invoke-static {v1}, Lcom/github/kittinunf/fuel/FuelKt;->get(Ljava/lang/String;)Lcom/github/kittinunf/fuel/core/Request;
return-void
.end method
''')
    raw=directory/'raw'; raw.mkdir(); (raw/'classes.dex').write_bytes(b'dex\n035\0')
    context=build_static_context(decoded/'AndroidManifest.xml',raw,decoded)
    result={'platform':'android','demo_status':'completed','static_analysis':context}
    result['vulnerabilities']=evaluate_vulnerabilities(result)
    generate_reports(directory,run_id,result)
    return directory


def test_fresh_extracted_fixture_and_rendered_summary_agree(tmp_path):
    directory=fresh_scan(tmp_path)
    canonical=load_current_static_report(directory,directory.name)
    report=json.loads((directory/'report.json').read_text())
    ids={row['id'] for row in canonical['vulnerabilities']['findings']}
    assert ids=={'SEC-CODE-01','SEC-NET-01'}
    assert report['vulnerabilities']['findings']==canonical['vulnerabilities']['findings']
    summary=load_report_summary(directory)
    assert len(summary['static_security_report']['findings'])==2
    assert all('127.0.0.1' not in row['component'] and '/supersonicads' not in row['component'] and row['component']!='http://a' for row in summary['static_security_report']['findings'])
    assert 'Hardcoded Private / Internal Network IP Addresses' not in (directory/'report.html').read_text()


@pytest.mark.parametrize('defect',['legacy','revision','run_id','corrupt','missing'])
def test_stale_or_mismatched_artifacts_unavailable_without_rewrite(tmp_path,defect):
    directory=fresh_scan(tmp_path);path=directory/'static_analysis_report.json'
    value=json.loads(path.read_text())
    if defect=='legacy':value.pop('static_evaluation_revision')
    if defect=='revision':value['static_evaluation_revision']='old'
    if defect=='run_id':value['run_id']='other_run'
    if defect=='corrupt':path.write_text('{')
    elif defect=='missing':path.unlink()
    else:path.write_text(json.dumps(value))
    before=path.read_bytes() if path.exists() else None
    with pytest.raises((ValueError,OSError)):load_current_static_report(directory,directory.name)
    summary=load_report_summary(directory)
    assert summary['static_security_report']['status']=='unavailable'
    assert summary['static_security_report']['findings']==[]
    assert (path.read_bytes() if path.exists() else None)==before


def test_explicit_run_routes_and_no_fallback(tmp_path,monkeypatch):
    directory=fresh_scan(tmp_path)
    other=fresh_scan(tmp_path,'other_m2')
    monkeypatch.setenv('VERCEL','1')
    server=DemoWebServer(port=0,runs_root=tmp_path);server.start()
    try:
        def get(path):
            with urlopen(server.base_url+path) as response:return json.load(response)
        assert get('/reports/fresh_m2/static_analysis_report.json')['run_id']=='fresh_m2'
        assert get('/api/summary/fresh_m2')['run_id']=='fresh_m2'
        assert get('/api/summary/fresh_m2')['static_security_report']==load_report_summary(directory)['static_security_report']
        value=json.loads((other/'static_analysis_report.json').read_text());value['run_id']='fresh_m2'
        (other/'static_analysis_report.json').write_text(json.dumps(value))
        with pytest.raises(HTTPError):get('/reports/other_m2/static_analysis_report.json')
        assert get('/api/summary/other_m2')['static_security_report']['findings']==[]
        with pytest.raises(HTTPError):get('/reports/missing_m2/static_analysis_report.json')
    finally:server.stop()


def test_reset_invalidates_pending_summary_and_next_run(tmp_path):
    node=shutil.which('node')
    if not node:pytest.skip('Node unavailable for frontend race test')
    template=Path('src/templates/dashboard.html').read_text()
    load=template.split('    async function loadCompactSummary(runId) {',1)[1].split('    function renderCompactSummary(runId)',1)[0]
    reset=template.split('    function resetDashboardToInitial() {',1)[1].split('    window.addEventListener("DOMContentLoaded"',1)[0]
    script='''const assert=require('assert');
let compactSummaryRequest=0, compactSummaryData=null, compactSummaryPage=0;
let currentRunId='old', pollTimer=null;
const panes={};const document={getElementById:id=>panes[id]||(panes[id]={style:{},textContent:'old',innerHTML:'old'})};
const window={demo3State:{currentRunId:'old',currentSha:'old'}};
const setBadge=()=>{},setMessage=()=>{},backendUrl=x=>x;
let resolve;let fetch=()=>new Promise(r=>resolve=r);let rendered=[];
const renderCompactSummary=id=>rendered.push(id);
'''+ 'async function loadCompactSummary(runId) {'+load+'function resetDashboardToInitial() {'+reset+'''
(async()=>{
const old=loadCompactSummary('old');resetDashboardToInitial();
assert.equal(window.demo3State.currentRunId,null);assert.equal(compactSummaryData,null);
resolve({ok:true,json:async()=>({run_id:'old'})});await old;assert.deepEqual(rendered,[]);
fetch=async()=>({ok:true,json:async()=>({run_id:'new'})});await loadCompactSummary('new');
assert.deepEqual(rendered,['new']);assert.equal(compactSummaryData.run_id,'new');
fetch=async()=>({ok:true,json:async()=>({run_id:'other'})});await loadCompactSummary('new');
assert.equal(panes.staticSecurityReport.textContent,'Report unavailable.');
})().catch(e=>{console.error(e);process.exit(1)});
'''
    subprocess.run([node,'-e',script],check=True,timeout=10)
