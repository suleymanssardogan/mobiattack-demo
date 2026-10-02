"""Existing decoded artifacts only: no download, runtime or network requests."""
from collections import Counter
import json
from pathlib import Path
from src.api_candidate_extractor import extract_api_candidates
from src.okhttp_candidate_extractor import extract_okhttp
from src.retrofit_candidate_extractor import extract_retrofit
from src.android_identity import canonical_candidates

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = {
    'Damn Vulnerable Bank': ROOT/'demo_runs/task_9_5_3_app_006/workspaces/dvba_v1.1.0/apktool_out',
    'Flashlight': Path('/tmp/mobiattack-c1-real-final/flashlight/processed/base/apktool_out'),
    'AntennaPod': ROOT/'demo_runs/task_9_5_3_app_011/workspaces/de.danoeh.antennapod/apktool_out',
}


def measure():
    measurements = {}
    for name, root in FIXTURES.items():
        result = extract_api_candidates(root)
        assert result == extract_api_candidates(root), 'Non-deterministic output'
        rows = result['api_candidates']
        assert [r for r in rows if r['framework']=='okhttp'] == extract_okhttp(root)['api_candidates']
        assert [r for r in rows if r['framework']=='Retrofit'] == canonical_candidates(extract_retrofit(root)['api_candidates'])
        new = [r for r in rows if r['framework'] in {'volley','httpurlconnection'}]
        for row in new:
            source = (root/row['source_file']).read_text().splitlines()
            assert row['source_component'] and row['evidence']['source_method']
            assert 'invoke-' in source[row['request_line']-1]
            assert '?' not in row['full_url']
        signals = Counter()
        for path in sorted(root.rglob('*.smali')):
            if path.stat().st_size > 2_000_000: continue
            try: text = path.read_text()
            except (OSError, UnicodeError): continue
            for framework, token in [('volley','Lcom/android/volley/'),('httpurlconnection','Ljava/net/HttpURLConnection;')]:
                if token in text: signals[framework] += 1
        diagnostics = result['discovery_diagnostics']
        measurements[name] = {
            'canonical_candidates':len(rows),
            'new_framework_candidates':new,
            'candidates_by_framework':dict(sorted(Counter(r['framework'] for r in rows).items())),
            'framework_signal_files':dict(sorted(signals.items())),
            'diagnostics':{k: {'unresolved_reason_counts':dict(sorted(Counter(r['reason'] for r in diagnostics[k]['unresolved']).items())), 'coverage':diagnostics[k]['coverage']} for k in ('volley','httpurlconnection')},
            'okhttp_unchanged':True, 'retrofit_unchanged':True, 'deterministic':True,
        }
        print(name, len(new), 'Volley/HttpURLConnection candidates', flush=True)
    return measurements


if __name__ == '__main__':
    Path(__file__).with_name('real_fixture_validation.json').write_text(json.dumps(measure(), indent=2, sort_keys=True)+'\n')
