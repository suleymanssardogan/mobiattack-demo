"""Bounded static permission/call metadata. No reachability or runtime claim."""
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import re

CATALOG_PATH = Path(__file__).with_name('static_security') / 'protected_api_catalog.json'
CALL = re.compile(r'^\s*invoke-(?:virtual|static|direct|interface|super)(?:/range)?\s+\{([^}]*)\},\s*(L[^;\s]+;->[^\s#]+)\s*(?:#.*)?$')
MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_CALLS = 30000, 2_000_000, 256_000_000, 100000
URI_FIELDS = {**{'Landroid/provider/ContactsContract$'+kind+';->CONTENT_URI:Landroid/net/Uri;': 'contacts' for kind in ('Contacts', 'RawContacts', 'Data')},
              **{'Landroid/provider/MediaStore$'+kind+'$Media;->CONTENT_URI:Landroid/net/Uri;': 'media' for kind in ('Images', 'Video', 'Audio')}}
SDK_PREFIXES = ('Landroid/', 'Landroidx/', 'Lcom/google/', 'Lkotlin/', 'Lcom/budiyev/android/codescanner/')


def load_catalog():
    catalog = json.loads(CATALOG_PATH.read_text())
    signatures = [r['signature'] for r in catalog['entries']]
    if len(signatures) != len(set(signatures)) or not catalog['catalog_version']:
        raise ValueError('Invalid protected API catalog')
    for row in catalog['entries']:
        if not re.fullmatch(r'L[^;\s]+;->[^\s]+\([^\s]*\)[^\s]+', row['signature']):
            raise ValueError('Invalid API signature')
        if not isinstance(row['api_min_sdk'], int) or row['api_min_sdk'] < 1:
            raise ValueError('Invalid API version')
        if row['category'] not in {'location','camera','microphone','contacts','sms','storage_media','bluetooth','notifications','alternative_access'}:
            raise ValueError('Unknown API category')
        if not isinstance(row['permissions'], list) or any(not p.startswith('android.permission.') for p in row['permissions']):
            raise ValueError('Invalid permission references')
        if row['context_rule'] not in {'direct', 'any_of', 'conditional', 'uri', 'bluetooth_scan', 'alternative'}:
            raise ValueError('Unknown permission context rule')
        if not row['official_source'].startswith('https://developer.android.com/'):
            raise ValueError('Unverified API source')
    return catalog


def _id(row):
    return 'permission_' + sha256(json.dumps(row, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:24]


def _read_calls(root, protected_signatures):
    calls, files, gaps, total = [], 0, [], 0
    units = Counter()
    for path in sorted(root.glob('smali*/**/*.smali')):
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            gaps.append('unsafe_source_skipped'); continue
        files += 1
        try:
            size = path.stat().st_size
        except OSError:
            gaps.append('unreadable_source_skipped'); continue
        total += size
        if files > MAX_FILES or total > MAX_TOTAL_BYTES or len(calls) >= MAX_CALLS:
            gaps.append('analysis_budget_reached'); break
        if size > MAX_FILE_BYTES:
            gaps.append('oversized_source_skipped'); continue
        try:
            lines = path.read_text(encoding='utf-8', errors='strict').splitlines()
        except (OSError, UnicodeError):
            gaps.append('unreadable_source_skipped'); continue
        component, method, values = None, None, {}
        for number, line in enumerate(lines, 1):
            if line.startswith('.class '):
                component = line.split()[-1]; units[component] += 1
            if line.startswith('.method '):
                method = line.split()[-1]; values = {}
            if line.startswith('.end method'):
                method = None; values = {}
            if not component or not method: continue
            clean = line.strip()
            if clean.startswith((':', 'if-', 'goto', 'packed-switch', 'sparse-switch', 'return', 'throw')):
                values = {}
            # Track only proven Contacts/MediaStore URI sources, never arbitrary values.
            field = re.match(r'sget-object (\w+), (L[^;]+;->[^\s]+)$', clean)
            if field: values[field[1]] = URI_FIELDS.get(field[2])
            move = re.match(r'move-object(?:/from16|/16)? (\w+), (\w+)$', clean)
            if move: values[move[1]] = values.get(move[2])
            call = CALL.match(line)
            if call:
                regs = [r.strip() for r in call[1].split(',')]
                if ' .. ' in call[1]:
                    register_range = re.fullmatch(r'([vp])(\d+) \.\. ([vp])(\d+)', call[1])
                    regs = []
                    if register_range and register_range[1] == register_range[3]:
                        start, end = int(register_range[2]), int(register_range[4])
                        if 0 <= end-start < 256:
                            regs = [register_range[1]+str(i) for i in range(start, end+1)]
                uri = values.get(regs[1]) if len(regs) > 1 else None
                # Platform/JVM calls outside this catalog cannot form application helper edges.
                # Discard them instead of exhausting the retained graph on unrelated APIs.
                if call[2] in protected_signatures or not call[2].startswith(('Landroid/', 'Ljava/', 'Ljavax/', 'Ldalvik/')):
                    calls.append({'component': component, 'method': method, 'line': number,
                                  'source': path.relative_to(root).as_posix(), 'signature': call[2], 'uri_context': uri})
                if len(calls) >= MAX_CALLS: gaps.append('analysis_budget_reached'); break
                # Unknown calls may mutate/escape URI references; no value inference across them.
                values = {}
            elif not (field or move):
                dest = re.match(r'(?:const[^ ]*|move[^ ]*|iget[^ ]*|sget[^ ]*|new-instance|aget[^ ]*)\s+(\w+)', clean)
                if dest: values.pop(dest[1], None)
    if not root.is_dir(): gaps.append('source_unavailable')
    if any(n > 1 for n in units.values()): gaps.append('duplicate_component_definitions')
    return calls, units, files, gaps


def extract_permission_usage(root, manifest, source_apk=None):
    """Manifest is parsed facts; input may include union declarations for split APKs."""
    root = Path(root)
    catalog = load_catalog()
    lookup = {r['signature']: r for r in catalog['entries']}
    calls, units, count, gaps = _read_calls(root, set(lookup))
    roots = {'L' + c['name'].replace('.', '/') + ';' for c in manifest.get('components', []) if c.get('name')}
    app_class = manifest.get('application', {}).get('class_name')
    if app_class: roots.add('L' + app_class.replace('.', '/') + ';')
    # Direct method edges only: no virtual dispatch, inheritance, callbacks or broad graph traversal.
    method_calls = {}
    for call in calls:
        method_calls.setdefault(call['component']+'->'+call['method'], []).append(call)
    links = {key: [] for key in method_calls if key.split('->')[0] in roots and units[key.split('->')[0]] == 1}
    for _ in range(3):
        new = {}
        for method, chain in sorted(links.items()):
            for call in method_calls[method]:
                target = call['signature']
                if target in method_calls and target not in links and units[target.split('->')[0]] == 1:
                    new.setdefault(target, chain + [{k: call[k] for k in ('source', 'component', 'method', 'line')}])
        if not new: break
        links.update(new)
    declarations = sorted(manifest.get('permission_declarations', []), key=lambda d: json.dumps(d, sort_keys=True))
    target_sdk = manifest.get('target_sdk')
    evidence = []
    for call in calls:
        entry = lookup.get(call['signature'])
        if not entry: continue
        method_key = call['component']+'->'+call['method']
        linkage = 'ambiguous_definition' if units[call['component']] != 1 else ('manifest_component' if call['component'] in roots else ('direct_call_chain' if method_key in links else 'unlinked'))
        sdk = call['component'].startswith(SDK_PREFIXES)
        rule, permissions = entry['context_rule'], list(entry['permissions'])
        resolved = rule in {'direct', 'any_of'}
        if rule == 'uri':
            resolved = call['uri_context'] == 'contacts'
            if call['uri_context'] is None: permissions = []
            if call['uri_context'] == 'media': permissions = ['android.permission.READ_EXTERNAL_STORAGE', 'android.permission.READ_MEDIA_IMAGES', 'android.permission.READ_MEDIA_VIDEO', 'android.permission.READ_MEDIA_AUDIO']
        if rule == 'bluetooth_scan':
            permissions = [permissions[0 if isinstance(target_sdk, int) and target_sdk >= 31 else 1]] if isinstance(target_sdk, int) else permissions
            resolved = False  # device SDK/location dependency cannot be inferred from target SDK.
        matches = [d for d in declarations if d.get('name') in permissions]
        unconditional = [d for d in matches if d.get('max_sdk') is None and d.get('tag') == 'uses-permission']
        # Do not upgrade an unlinked dependency, SDK-conditional declaration or unresolved URI.
        state = 'matching_declaration' if unconditional else ('conditional_declaration' if matches else 'context_unresolved')
        if not matches and resolved and linkage != 'unlinked' and units[call['component']] == 1 and manifest.get('manifest_available', True):
            state = 'used_without_matching_declaration'
        category = ('contacts' if call['uri_context'] == 'contacts' else ('storage_media' if call['uri_context'] == 'media' else 'provider_access_unresolved')) if rule == 'uri' else entry['category']
        row = {**call, 'category': category, 'possible_permissions': permissions,
               'declaration_state': state, 'manifest_refs': matches, 'target_sdk': target_sdk, 'min_sdk': manifest.get('min_sdk'),
               'api_min_sdk': entry['api_min_sdk'], 'device_sdk': None,
               'usage_state': 'usage_observed', 'usage_semantics': 'static_call_observed_not_runtime_execution',
               'code_origin': 'sdk_library' if sdk else ('manifest_component' if call['component'] in roots else 'unknown'), 'application_linkage': linkage,
               'linkage_provenance': links.get(method_key, []), 'context_note': entry['context_note'],
               'access_context': 'resolved' if resolved else 'unresolved_or_alternative_access',
               'classification': 'indicator' if state == 'used_without_matching_declaration' else 'metadata',
               'finding_created': False, 'runtime_confirmed': False, 'catalog_version': catalog['catalog_version']}
        if source_apk: row['source_apk'] = source_apk
        row['evidence_id'] = _id(row)
        evidence.append(row)
    evidence = sorted(evidence, key=lambda r: (r['source'], r['method'], r['line'], r['signature']))
    summary = []
    by_permission = defaultdict(list)
    for row in evidence:
        for permission in row['possible_permissions']:
            by_permission[permission].append(row)
    for declaration in sorted(declarations, key=lambda d: json.dumps(d, sort_keys=True)):
        associated = by_permission[declaration['name']]
        refs = [r['evidence_id'] for r in associated]
        summary.append({'permission': declaration['name'], 'declaration': declaration, 'classification': 'metadata',
                        'usage_state': 'usage_observed' if refs else 'usage_not_observed_in_analyzed_code',
                        'evidence_refs': refs, 'permission_requirement': 'context_dependent' if any(r['access_context'] != 'resolved' for r in associated) else ('catalog_supported' if refs else 'not_observed'), 'finding_created': False})
    return {'schema_version': '1.0', 'catalog_version': catalog['catalog_version'], 'evidence': evidence,
            'declarations': summary, 'coverage': {'status': 'partial', 'files_analyzed': min(count, MAX_FILES),
            'limitations': sorted(set(gaps + ['Bounded exact API catalog; unmatched overloads remain uncovered.',
                'No runtime execution, permission grant, or unused-permission certainty.',
                'Reflection/native/Dart, callback dispatch and deep call chains are not resolved.',
                'URI grants, intent delegation, device SDK and exemptions may require additional context.',
                'Manifest linkage is not proof of first-party authorship or runtime reachability.']))}}


def aggregate_permission_usage(inputs, manifest_evidence, base_manifest):
    """Share effective split declarations, scope evidence, keep absence component-local."""
    manifest = {
        'permission_declarations': [{**d, 'source_apk': m['source_apk']} for m in manifest_evidence for d in m['manifest'].get('permission_declarations', [])],
        'components': [c for m in manifest_evidence for c in m['manifest'].get('components', [])],
        'target_sdk': base_manifest.get('target_sdk'), 'min_sdk': base_manifest.get('min_sdk'),
        'manifest_available': bool(manifest_evidence),
    }
    components = [{'source_apk': filename, **extract_permission_usage(directory, manifest, source_apk=filename)}
                  for filename, directory in sorted(inputs, key=lambda item: item[0])]
    return {'schema_version': '1.0', 'catalog_version': load_catalog()['catalog_version'],
            'components': components, 'evidence': [r for c in components for r in c['evidence']],
            'coverage': {'status': 'partial', 'limitations': sorted({'Cross-split call edges unresolved; per-component usage absence is not global absence.'} |
                {note for c in components for note in c['coverage']['limitations']})}}
