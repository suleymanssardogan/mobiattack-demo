"""Focused UI-R1 workflow, report isolation and permission coverage checks."""
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from src.runtime_permissions import grant_runtime_permissions, save_permission_observation
from src.web.report_summary import build_report_summary, load_report_summary
from src.url_classifier import classify_input_url

ROOT = Path(__file__).resolve().parents[1]


def test_controls_and_stage_views():
    html = (ROOT / 'src/templates/dashboard.html').read_text()
    for name in ('grantPermissions', 'adbSerial', 'installModeSection'):
        assert f'id="{name}"' not in html
    assert 'name="installMode"' not in html
    for label in ('Target Application URL', 'Quick Targets', 'Start Analysis', 'Reset View',
                  'Static Analysis Report', 'Dynamic Analysis Report'):
        assert label in html


def test_url_identity_and_invalid_inputs():
    canonical = 'https://play.google.com/store/apps/details?id=com.example.app'
    assert classify_input_url(canonical + '&hl=tr&utm_source=demo')['normalized_url'] == canonical
    assert classify_input_url('https://example.com/app.apk')['type'] == 'direct_apk'
    for url in ('file:///app.apk', 'https:///app.apk', 'https://example.com:invalid/app.apk',
                'https://example.com/page', 'https://bad host/app.apk', 'https://u:p@example.com/app.apk'):
        assert classify_input_url(url)['type'] == 'unsupported'


def test_stage_reports_independent_and_no_fabricated_poc():
    static = json.loads((ROOT / 'demo_runs/preset_android_monolithic/static_analysis_report.json').read_text())
    result = build_report_summary(static)
    assert result['static_security_report']['findings']
    assert result['dynamic_security_report']['results'] == []
    assert result['dynamic_security_report']['runtime_status'] == 'unavailable'
    assert 'poc' not in json.dumps(result).lower()
    result = load_report_summary(ROOT / 'examples/auth_standards_report_d13')
    row = result['dynamic_security_report']['results'][0]
    assert row['finding_created'] is False
    assert row['reason_code'] == 'AUTH_ENFORCEMENT_CONFIRMED'
    assert row['comparison'] == '200 / 401'


def test_projection_never_writes_canonical_artifacts(tmp_path):
    source = {'report_type': 'static_analysis', 'status': 'completed', 'vulnerabilities': {'findings': [
        {'title': 'Observed issue', 'evidence': 'token=SECRET', 'affected_items': ['/tmp/tool/private'],
         'description': 'password=SECRET', 'poc': 'fabricated', 'remediation': 'Fix configuration'}]}}
    artifact = tmp_path / 'static_analysis_report.json'
    artifact.write_text(json.dumps(source))
    before = artifact.read_bytes()
    result = load_report_summary(tmp_path)
    assert artifact.read_bytes() == before
    text = json.dumps(result)
    assert 'SECRET' not in text and '/tmp/' not in text and 'fabricated' not in text


def test_permission_grants_verified_and_denials_preserved(tmp_path):
    before = 'runtime permissions:\n  android.permission.CAMERA: granted=false\n  android.permission.RECORD_AUDIO: granted=false\n  android.permission.ACCESS_FINE_LOCATION: granted=true\n'
    after = before.replace('CAMERA: granted=false', 'CAMERA: granted=true')
    calls = []
    def command(args, **kwargs):
        calls.append(args)
        output = before if len(calls) == 1 else after if 'dumpsys' in args else ''
        return SimpleNamespace(returncode=0, stdout=output)
    with patch('src.runtime_permissions.subprocess.run', side_effect=command):
        result = grant_runtime_permissions('adb', 'device', 'training.app')
    assert result['granted'] == ['android.permission.CAMERA']
    assert result['already_granted'] == ['android.permission.ACCESS_FINE_LOCATION']
    assert result['unavailable'] == ['android.permission.RECORD_AUDIO']
    assert result['coverage'] == 'partial'
    assert all('root' not in call and 'appops' not in call for call in calls)
    save_permission_observation(tmp_path, result)
    assert json.loads((tmp_path / 'dynamic/runtime_permissions.json').read_text()) == result
    summary = load_report_summary(tmp_path)
    assert 'Some runtime permissions could not be granted or verified.' in summary['dynamic_summary']['coverage_limitations']


def test_permissions_unavailable_is_coverage_gap():
    with patch('src.runtime_permissions.subprocess.run', side_effect=subprocess.TimeoutExpired('adb', 1)):
        result = grant_runtime_permissions('adb', 'device', 'training.app')
    assert result['coverage'] == 'unavailable' and result['granted'] == []


def test_stage_rendering_is_escaped_and_independent(tmp_path):
    html = (ROOT / 'src/templates/dashboard.html').read_text()
    code = html.split('    function renderStageReports(data) {', 1)[1].split('    function renderAnalysisResults', 1)[0]
    summary = build_report_summary({'vulnerabilities': {'findings': [{'title': '<script>unsafe</script>'}]}})
    script = """const assert=require('assert');
const panes={staticSecurityReport:{},dynamicSecurityReport:{}};
const document={getElementById:id=>panes[id]};
function escapeHtml(v){return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function renderStageReports(data) {""" + code
    script += '\nrenderStageReports(' + json.dumps(summary) + ');\n'
    script += """assert(!panes.staticSecurityReport.innerHTML.includes('<script>'));
assert(panes.staticSecurityReport.innerHTML.includes('Static Analysis Report'));
assert(panes.dynamicSecurityReport.innerHTML.includes('No security validation results available'));
assert(!panes.staticSecurityReport.innerHTML.includes('Full dynamic'));
"""
    path = tmp_path / 'ui.js'
    path.write_text(script)
    outcome = subprocess.run(['node', str(path)], capture_output=True, text=True, timeout=10)
    assert outcome.returncode == 0, outcome.stderr
