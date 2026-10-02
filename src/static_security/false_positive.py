"""Bounded source ownership and non-executable context filtering; no URL guessing."""
from copy import deepcopy
from hashlib import sha256
import json


def network_origins(candidate):
    origins = candidate.get('provenance')
    if isinstance(origins, list) and origins:
        return [deepcopy(row) for row in origins if isinstance(row, dict)]
    return [deepcopy(candidate)]


def ownership(origin):
    # Explicit provenance wins. A domain, framework name, or package resemblance
    # alone never establishes application ownership.
    explicit = origin.get('ownership')
    if explicit in {'first_party', 'third_party'}:
        return explicit
    component = str(origin.get('source_component') or '').strip('L;').replace('.', '/')
    if component.startswith(('okhttp3/', 'com/android/volley/', 'io/ktor/client/')):
        return 'third_party'
    return 'unknown'


def executable_source(origin):
    source = origin.get('source_file') or origin.get('source')
    if not isinstance(source, str) or not source.endswith(('.smali', '.java', '.kt')):
        return False
    if origin.get('evidence_context') in {'comment', 'documentation', 'resource', 'unused_literal'}:
        return False
    return True


def evidence_key(row):
    return json.dumps(row, sort_keys=True, separators=(',', ':'))


def finalize_findings(findings):
    """Merge equivalent scope only. Keep every exact evidence record and stable IDs."""
    groups = {}
    for row in sorted(findings, key=evidence_key):
        if not row.get('control_id'):
            # Legacy non-static handling is intentionally outside this catalog.
            groups[evidence_key(row)] = deepcopy(row)
            continue
        scope = {k: row.get(k) for k in ('control_id', 'source', 'component', 'observed_value')}
        if row.get('reason_code') == 'HTTP_NETWORK_CALL_CONTEXT':
            scope['component'] = row.get('scope_component') or row.get('source')
        key = evidence_key(scope)
        if key not in groups:
            groups[key] = deepcopy(row)
        target = groups[key]
        target['affected_items'] = sorted(set(target.get('affected_items', []) + row.get('affected_items', [])))
        entries = target.get('supporting_evidence', []) + row.get('supporting_evidence', [])
        if not any(v.get('provenance_refs') == row.get('provenance_refs') for v in entries):
            entries.append({k: row.get(k) for k in ('source', 'component', 'observed_value', 'reason_code', 'evidence_type', 'provenance_refs', 'ownership')})
        target['supporting_evidence'] = [v for _, v in sorted({evidence_key(v): v for v in entries}.items())]
        target['supporting_provenance_refs'] = sorted({ref for v in target['supporting_evidence'] for ref in v.get('provenance_refs') or []})
        target['finding_instance_id'] = 'static_finding_' + sha256(key.encode()).hexdigest()[:24]
    return sorted(groups.values(), key=lambda r: (-{'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(r['severity'], 0), r['id'], r.get('finding_instance_id', '')))
