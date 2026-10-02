"""Canonical Android identities; deterministic, evidence-based, no device probing."""
import hashlib
import json
import re
from pathlib import PurePosixPath


class AndroidIdentityError(ValueError):
    def __init__(self, reason_code, message):
        super().__init__(message)
        self.reason_code = reason_code


def canonical_components(components, *, require_base=True):
    if not isinstance(components, list) or not components:
        raise AndroidIdentityError('SPLIT_SET_INCOMPLETE', 'Package set has no components.')
    names = []
    for component in components:
        name = component.get('filename')
        if not isinstance(name, str) or PurePosixPath(name).name != name or not name.endswith('.apk'):
            raise AndroidIdentityError('SPLIT_SET_INCOMPLETE', 'Invalid APK component name.')
        names.append(name)
    if len(set(names)) != len(names):
        raise AndroidIdentityError('SPLIT_SET_INCOMPLETE', 'Duplicate APK components.')
    bases = [c for c in components if c.get('role') == 'base']
    if len(bases) > 1 or (require_base and len(bases) != 1):
        raise AndroidIdentityError('BASE_APK_NOT_FOUND', 'Exactly one authoritative base APK is required.')
    return sorted(components, key=lambda c: (c.get('role') != 'base', c['filename']))


def canonical_candidates(candidates):
    result = []
    for candidate in candidates:
        row = dict(candidate)
        identity = {key: row.get(key) for key in ('framework', 'method', 'base_url', 'path', 'source_apk', 'source_file', 'request_line')}
        digest = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()[:24]
        row['candidate_id'] = 'static_' + digest
        result.append(row)
    return sorted(result, key=lambda row: (row.get('framework') or '', row.get('method') or '', row.get('base_url') or '', row.get('path') or '', row.get('source_apk') or '', row.get('source_file') or '', row.get('request_line') or 0))


def launch_component(package_name, activity_name):
    """Executable component from a declared manifest or PackageManager identity."""
    from src.manifest_parser import normalize_activity_name
    if not isinstance(package_name, str) or not package_name.strip() or not isinstance(activity_name, str) or not activity_name.strip():
        raise AndroidIdentityError('LAUNCHER_UNRESOLVED', 'Package/launcher evidence unavailable.')
    package_name = package_name.strip()
    activity_name = activity_name.strip()
    if '/' in activity_name:
        owner, activity_name = activity_name.split('/', 1)
        if owner != package_name:
            raise AndroidIdentityError('PACKAGE_MISMATCH', 'Launcher component belongs to another package.')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', package_name):
        raise AndroidIdentityError('PACKAGE_MISMATCH', 'Invalid Android package identity.')
    full_name = normalize_activity_name(activity_name, package_name)
    if not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+', full_name):
        raise AndroidIdentityError('LAUNCHER_UNRESOLVED', 'Launcher is not a literal class identity.')
    if full_name.lower().endswith('.unknown') or activity_name.lower() == 'unknown':
        raise AndroidIdentityError('LAUNCHER_UNRESOLVED', 'Unknown is not an executable component.')
    return package_name + '/' + full_name
