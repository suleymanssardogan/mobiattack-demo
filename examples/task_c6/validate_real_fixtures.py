"""Inspect existing decoded fixtures only, without acquisition/runtime/network."""
import json
from collections import Counter
from pathlib import Path
from src.api_candidate_extractor import extract_api_candidates
from src.okhttp_candidate_extractor import extract_okhttp
from src.volley_urlconnection_extractor import extract_volley_urlconnection
from src.retrofit_candidate_extractor import extract_retrofit
from src.android_identity import canonical_candidates
ROOT=Path(__file__).resolve().parents[2]
FIXTURES={
'AntennaPod':ROOT/'demo_runs/task_9_5_3_app_011/workspaces/de.danoeh.antennapod/apktool_out',
'VulnBank':ROOT/'demo_runs/task_9_5_3_app_005/workspaces/vulnbank3/apktool_out',
'Wikipedia':Path('/tmp/mobiattack-c1-real-final/wikipedia/processed/base/apktool_out'),
'Damn Vulnerable Bank':ROOT/'demo_runs/task_9_5_3_app_006/workspaces/dvba_v1.1.0/apktool_out'}

def measure():
    measurements={}
    for name,root in FIXTURES.items():
        result=extract_api_candidates(root)
        rows=result['api_candidates']
        before=canonical_candidates(extract_retrofit(root)['api_candidates']+extract_okhttp(root)['api_candidates']+extract_volley_urlconnection(root)['api_candidates'])
        by_id={row['candidate_id']:row for row in rows}
        assert all(by_id[row['candidate_id']]==row for row in before), 'Direct behavior changed'
        for row in rows:
            assert row['evidence'] and row['source_file']
            assert '?' not in (row.get('full_url') or '')
            source=(root/row['source_file']).read_text().splitlines()
            assert 'invoke-' in source[row['request_line']-1]
        diagnostics=result['discovery_diagnostics']
        measurements[name]={
            'canonical_candidates':len(rows),
            'candidates_by_framework':dict(sorted(Counter(row['framework'] for row in rows).items())),
            'candidates':rows,
            'direct_behavior_unchanged':True,
            'diagnostics':{k:{'unresolved_reason_counts':dict(sorted(Counter(g['reason'] for g in diagnostics[k]['unresolved']).items())), 'coverage':diagnostics[k]['coverage']} for k in ('ktor','bounded_provenance')}}
        print(name,len(rows),'canonical candidates',flush=True)
    return measurements
if __name__=='__main__':
    Path(__file__).with_name('real_fixture_validation.json').write_text(json.dumps(measure(),indent=2,sort_keys=True)+'\n')
