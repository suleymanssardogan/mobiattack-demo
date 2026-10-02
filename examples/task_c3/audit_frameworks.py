"""Offline C3 audit only. Descriptor presence is not request execution or endpoint proof."""
import json
from collections import Counter
from pathlib import Path
import re
from src.api_candidate_extractor import extract_api_candidates
from src.retrofit_candidate_extractor import extract_retrofit
from src.manifest_parser import parse_manifest

ROOT = Path(__file__).resolve().parents[2]
APPS = {
 'OWASP MSTG Kotlin': ROOT/'demo_runs/task_9_5_2_app_001/workspaces/MSTG-Android-Kotlin/apktool_out',
 'Wikipedia': Path('/tmp/mobiattack-c1-real-final/wikipedia/processed/base/apktool_out'),
 'Flashlight': Path('/tmp/mobiattack-c1-real-final/flashlight/processed/base/apktool_out'),
 'AntennaPod': ROOT/'demo_runs/task_9_5_3_app_011/workspaces/de.danoeh.antennapod/apktool_out',
 'VulnBank': ROOT/'demo_runs/task_9_5_3_app_005/workspaces/vulnbank3/apktool_out',
 'Damn Vulnerable Bank': ROOT/'demo_runs/task_9_5_3_app_006/workspaces/dvba_v1.1.0/apktool_out',
}
PATTERNS = {
 'Fuel': r'Lcom/github/kittinunf/fuel/', 'Retrofit': r'Lretrofit2/',
 'OkHttp': r'L(?:okhttp3/|com/squareup/okhttp/)', 'Volley': r'Lcom/android/volley/',
 'Ktor': r'Lio/ktor/client/', 'HttpURLConnection': r'L(?:java/net/HttpURLConnection|javax/net/ssl/HttpsURLConnection);',
 'WebView': r'Landroid/webkit/WebView;', 'Raw socket': r'Ljava/net/(?:Socket|DatagramSocket|ServerSocket);',
}


def audit_app(root):
    manifest = parse_manifest(root/'AndroidManifest.xml')
    package_prefix = 'L' + manifest['package_name'].replace('.', '/') + '/'
    counts = {name: {'files': 0, 'invoke_lines': 0, 'app_owned_invoke_lines': 0, 'samples': [], 'string_marker_files': 0} for name in PATTERNS}
    native = {'native_methods': 0, 'shared_libraries': len(list((root/'lib').rglob('*.so'))), 'library_load_calls': 0}
    skipped = 0
    for path in sorted(root.rglob('*.smali')):
        if path.is_symlink() or path.stat().st_size > 2_000_000:
            skipped += 1
            continue
        text = path.read_text(errors='replace')
        owner = next((line.split()[-1] for line in text.splitlines() if line.startswith('.class ')), '')
        native['native_methods'] += len(re.findall(r'^\.method\s+[^\n]*\bnative\b', text, re.M))
        native['library_load_calls'] += len(re.findall(r'invoke-[^\n]+Ljava/lang/System;->load(?:Library)?\(', text))
        if re.search(r'const-string[^\n]+"(?:Volley|volley)"', text):
            counts['Volley']['string_marker_files'] += 1
        for name, pattern in PATTERNS.items():
            if not re.search(pattern, text):
                continue
            row = counts[name];row['files'] += 1
            calls = [number for number, line in enumerate(text.splitlines(), 1) if line.strip().startswith('invoke-') and re.search(pattern, line)]
            row['invoke_lines'] += len(calls)
            if owner.startswith(package_prefix):row['app_owned_invoke_lines'] += len(calls)
            if len(row['samples']) < 3:
                row['samples'].append({'source_file': path.relative_to(root).as_posix(), 'invoke_line': calls[0] if calls else None})
    extracted = extract_api_candidates(root)
    retrofit = extract_retrofit(root)
    candidates = extracted['api_candidates']
    unresolved = [row for row in candidates if not row.get('full_url')]
    result = {'package': manifest['package_name'], 'framework_signals': counts, 'native_signals': native,
        'audit_skipped_files': skipped, 'canonical_candidates': len(candidates),
        'candidates_by_framework': dict(Counter(row['framework'] for row in candidates)),
        'unresolved_candidates': len(unresolved), 'retrofit_declarations': len(retrofit['declarations']),
        'retrofit_unbound_declarations': retrofit['unbound_declaration_count'],
        'retrofit_skipped_files': len(retrofit['skipped']),
        'retrofit_unresolved_flow_reasons': dict(Counter(row['reason'] for row in retrofit['unresolved_flow'])),
        'candidate_missing_provenance': sum(not row.get('source_file') or not row.get('evidence') for row in candidates),
        'candidate_identity_fields': sorted({key for row in candidates for key in row}),
        'signals_are_not_runtime_confirmation': True}
    return result


if __name__ == '__main__':
    results = {}
    for name, root in APPS.items():
        if not root.is_dir():
            results[name] = {'status': 'local_artifact_unavailable'}
            continue
        results[name] = audit_app(root)
        row = results[name]
        print(name, 'candidates', row['canonical_candidates'], 'frameworks', row['candidates_by_framework'],
              'declarations/unbound', row['retrofit_declarations'], row['retrofit_unbound_declarations'], flush=True)
    (Path(__file__).parent/'measurements.json').write_text(json.dumps(results, indent=2, sort_keys=True)+'\n')
