"""Read already-decoded fixtures; no acquisition, runtime or network activity."""
from collections import Counter
import json
from pathlib import Path
from src.api_candidate_extractor import extract_api_candidates
from src.android_identity import canonical_candidates
from src.retrofit_candidate_extractor import extract_retrofit

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = {
    'AntennaPod': ROOT/'demo_runs/task_9_5_3_app_011/workspaces/de.danoeh.antennapod/apktool_out',
    'VulnBank': ROOT/'demo_runs/task_9_5_3_app_005/workspaces/vulnbank3/apktool_out',
    'Wikipedia': Path('/tmp/mobiattack-c1-real-final/wikipedia/processed/base/apktool_out'),
    'OWASP MSTG Kotlin': ROOT/'demo_runs/task_9_5_2_app_001/workspaces/MSTG-Android-Kotlin/apktool_out',
}


def measure():
    measurements = {}
    for name, root in FIXTURES.items():
        result = extract_api_candidates(root)
        rows = result['api_candidates']
        okhttp = [row for row in rows if row['framework'] == 'okhttp']
        retrofit = canonical_candidates(extract_retrofit(root)['api_candidates'])
        assert retrofit == [row for row in rows if row['framework'] == 'Retrofit']
        assert result == extract_api_candidates(root), 'Non-deterministic extraction'
        for row in okhttp:
            lines = (root/row['source_file']).read_text().splitlines()
            evidence = row['evidence']
            assert 'new-instance' in lines[evidence['builder_allocation_line']-1]
            assert '->build()Lokhttp3/Request;' in lines[row['request_line']-1]
            assert evidence['url_trace'] and row['source_component']
            assert '?' not in row['full_url']
        if name == 'OWASP MSTG Kotlin':
            fuel = [row for row in rows if row['framework'] == 'Fuel']
            assert len(fuel) == 1
            assert (fuel[0]['method'], fuel[0]['path'], fuel[0]['base_url']) == ('POST', '/signup', 'http://127.0.0.1')
        diagnostics = result['discovery_diagnostics']['okhttp']
        measurements[name] = {
            'canonical_candidates': len(rows),
            'candidates_by_framework': dict(sorted(Counter(row['framework'] for row in rows).items())),
            'okhttp_candidates': okhttp,
            'unresolved_reason_counts': dict(sorted(Counter(row['reason'] for row in diagnostics['unresolved']).items())),
            'coverage': diagnostics['coverage'],
            'retrofit_unchanged': True,
            'provenance_verified': True,
            'deterministic': True,
        }
        print(name, len(okhttp), 'OkHttp candidates', flush=True)
    return measurements


if __name__ == '__main__':
    output = Path(__file__).with_name('real_fixture_validation.json')
    output.write_text(json.dumps(measure(), indent=2, sort_keys=True)+'\n')
