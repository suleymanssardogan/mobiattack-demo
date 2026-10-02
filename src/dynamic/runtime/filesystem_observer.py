"""Bounded, opt-in filesystem metadata spike. No contents, run-as, or root.

Paths are pseudonymized before leaving the adapter. Snapshots cover only three
app-scoped roots, at most depth three. Changes indicate temporal observation,
never causation or a vulnerability. This is not wired into production scans.
"""
from dataclasses import asdict, dataclass
import hashlib
from pathlib import PurePosixPath
import re
import shlex

from src.dynamic.preflight.device_check import run_adb_cmd
from src.dynamic.runtime.models import utc_now_iso


def _ref(prefix, value):
    return prefix + hashlib.sha256(value.encode()).hexdigest()[:24]


def _safe_path(relative):
    parts = PurePosixPath(relative).parts
    if relative.startswith('/') or '..' in parts or not parts:
        raise ValueError('Invalid relative metadata path')
    public = {'shared_prefs', 'databases', 'files', 'cache', 'code_cache'}
    return '/'.join(p if p in public else _ref('name_', p) for p in parts)


@dataclass
class FilesystemSnapshot:
    snapshot_id: str
    package: str
    session_id: str
    route_id: str
    action_id: str
    phase: str
    timestamp: str
    roots: dict
    coverage_gaps: list

    def to_dict(self):
        return asdict(self)


class FilesystemObserver:
    def __init__(self, adb_bin, serial, max_entries=500, timeout_seconds=3):
        if not 1 <= max_entries <= 500 or not 0 < timeout_seconds <= 5:
            raise ValueError('Snapshot bounds exceeded')
        self.adb_bin, self.serial = adb_bin, serial
        self.max_entries, self.timeout_seconds = max_entries, timeout_seconds

    def snapshot(self, package, session_id, route_id, action_id, phase):
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+', package):
            raise ValueError('Invalid package')
        if phase not in {'before', 'after'} or not all((session_id, route_id, action_id)):
            raise ValueError('Missing provenance or invalid phase')
        roots, gaps = {}, ['depth_limited_to_3', 'metadata_only_same_size_mtime_changes_not_detectable',
                           'inaccessible_storage_does_not_mean_no_filesystem_behavior']
        for scope, root in [('private', '/data/user/0/' + package),
                            ('external_files', '/sdcard/Android/data/' + package),
                            ('external_media', '/sdcard/Android/media/' + package)]:
            quoted = shlex.quote(root)
            script = (f'if [ -d {quoted} ] && [ -r {quoted} ] && [ -x {quoted} ]; then '
                      f"echo READY; find {quoted} -mindepth 1 -maxdepth 3 -exec stat -c '%F|%s|%Y|%n' {{}} \\; "
                      f'| head -n {self.max_entries + 1}; else echo INACCESSIBLE; fi')
            code, output, err = run_adb_cmd(self.adb_bin, ['shell', script], serial=self.serial,
                                            timeout_seconds=self.timeout_seconds)
            lines = output.splitlines()
            if code or not lines or lines[0] != 'READY':
                roots[scope] = {'status': 'unavailable', 'entries': {}}
                gaps.append(scope + ':access_unavailable_or_directory_not_present')
                continue
            partial = bool(err) or len(lines) - 1 > self.max_entries
            entries = {}
            for line in lines[1:self.max_entries + 1]:
                try:
                    kind, size, mtime, path = line.split('|', 3)
                    if kind not in {'regular file', 'directory'}:
                        partial = True
                        continue  # No symlink traversal / special file reads.
                    if not path.startswith(root + '/'):
                        raise ValueError('Outside scope')
                    path = _safe_path(path[len(root) + 1:])
                    size, mtime = int(size), int(mtime)
                    if size < 0 or mtime < 0:
                        raise ValueError('Invalid metadata')
                    entries[path] = {'kind': kind, 'size': size, 'mtime_epoch': mtime}
                except (ValueError, TypeError):
                    partial = True
            roots[scope] = {'status': 'partial' if partial else 'available',
                            'entries': dict(sorted(entries.items()))}
            if partial:
                gaps.append(scope + ':incomplete_or_entry_limit_or_metadata_error')
        timestamp = utc_now_iso()
        identity = '|'.join((package, session_id, route_id, action_id, phase, timestamp))
        return FilesystemSnapshot(_ref('fs_snapshot_', identity), package, session_id, route_id,
                                  action_id, phase, timestamp, roots, gaps)


def diff_snapshots(before, after):
    if (before.package, before.session_id, before.route_id, before.action_id) != (
            after.package, after.session_id, after.route_id, after.action_id):
        raise ValueError('Snapshot evidence chain mismatch')
    if before.phase != 'before' or after.phase != 'after' or after.timestamp < before.timestamp:
        raise ValueError('Invalid snapshot order')
    changes, gaps = [], sorted(set(before.coverage_gaps + after.coverage_gaps))
    for scope in sorted(set(before.roots) | set(after.roots)):
        pre, post = before.roots.get(scope, {}), after.roots.get(scope, {})
        if pre.get('status') != 'available' or post.get('status') != 'available':
            gaps.append(scope + ':diff_unavailable_incomplete_snapshot')
            continue
        left, right = pre['entries'], post['entries']
        for path in sorted(set(left) | set(right)):
            old, new = left.get(path), right.get(path)
            if old == new:
                continue
            change = 'created' if old is None else 'deleted' if new is None else 'modified'
            evidence = [before.snapshot_id, after.snapshot_id]
            changes.append({'evidence_ref': _ref('fs_change_', '|'.join(evidence + [scope, path, change])),
                            'path': scope + '/' + path, 'change_type': change,
                            'kind': (new or old)['kind'], 'before_metadata': old, 'after_metadata': new,
                            'timestamp': after.timestamp, 'session_id': after.session_id,
                            'route_id': after.route_id, 'action_id': after.action_id,
                            'snapshot_refs': evidence, 'linkage': 'observed_in_action_window',
                            'caused_by_action': 'unknown'})
    usable = sum(before.roots.get(s, {}).get('status') == 'available' and
                 after.roots.get(s, {}).get('status') == 'available' for s in after.roots)
    return {'status': 'partial' if usable else 'unavailable', 'changes': changes,
            'coverage_gaps': sorted(set(gaps)), 'no_changes_means': 'not_observed_in_accessible_bounded_scope'}
