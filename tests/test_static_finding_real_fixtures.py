"""Re-evaluate available real static artifacts without scanning/executing apps."""
import copy
import json
from pathlib import Path
import pytest
from src.manifest_parser import parse_manifest
from src.vulnerability_evaluator import evaluate_vulnerabilities

ROOT = Path(__file__).resolve().parents[1]
CASES = [
 ('OWASP', ROOT/'demo_runs/preset_android_monolithic/static_analysis_report.json', Path('/tmp/mobiattack-c1-real-final/owasp_1/workspaces/MSTG-Android-Kotlin/apktool_out/AndroidManifest.xml')),
 ('Wikipedia', Path('/tmp/mobiattack-c1-real-final/wikipedia/unified_a/static_context.json'), Path('/tmp/mobiattack-c1-real-final/wikipedia/processed/base/apktool_out/AndroidManifest.xml')),
 ('Flashlight', Path('/tmp/mobiattack-c1-real-final/flashlight/unified_a/static_context.json'), Path('/tmp/mobiattack-c1-real-final/flashlight/processed/base/apktool_out/AndroidManifest.xml')),
 ('Rotate Rings', ROOT/'demo_runs/run_1790956934_86b7a8/static_analysis_report.json', ROOT/'demo_runs/run_1790956934_86b7a8/workspaces/processed/base/apktool_out/AndroidManifest.xml'),
]

@pytest.mark.parametrize('alias,artifact,manifest', CASES)
def test_real_static_regression(alias, artifact, manifest):
    if not artifact.exists() or not manifest.exists():
        pytest.skip('Existing local decoded artifact is unavailable')
    source = json.loads(artifact.read_text())
    source['manifest'] = parse_manifest(manifest)
    before = copy.deepcopy(source)
    result = evaluate_vulnerabilities(source)
    assert source == before
    assert all(row['classification']=='finding' and row['source'] and row['reason_code'] for row in result['findings'])
    assert not any(row['id'] in {'SEC-NET-02','SEC-RESI-01','SEC-PERM-01','SEC-PLAT-02','SEC-CRYPTO-01'} for row in result['findings'])
    assert not any(row['observed_value']=='/supersonicads' for row in result['candidates'])
    if alias=='OWASP':
        assert {'SEC-CODE-01','SEC-NET-01'}.issubset({row['id'] for row in result['findings']})
        assert any(c.get('method')=='POST' and c.get('path')=='/signup' for c in source['api_candidates'])
    if alias=='Rotate Rings':
        assert any((row if isinstance(row,str) else row.get('value'))=='/supersonicads' for row in source['network_indicators']['path_candidates'])
