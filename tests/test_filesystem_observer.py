import json
from unittest.mock import patch

import pytest

from src.dynamic.runtime.filesystem_observer import FilesystemObserver, diff_snapshots

PACKAGE = 'org.example.training'
ROOT = '/data/user/0/' + PACKAGE


def capture(lines='READY', code=0, err='', phase='before', **kwargs):
    with patch('src.dynamic.runtime.filesystem_observer.run_adb_cmd', return_value=(code, lines, err)):
        return FilesystemObserver('adb', 'device', **kwargs).snapshot(PACKAGE, 'sess', 'route', 'act', phase)


def pair(pre, post):
    before = capture(pre)
    after = capture(post, phase='after')
    # Only private is represented by these synthetic lines; external root validation rejects them.
    return before, after


def record(path='files/secret-token.db', size=1, mtime=2, kind='regular file'):
    return f'{kind}|{size}|{mtime}|{ROOT}/{path}'


def test_creation_has_metadata_and_temporal_provenance():
    result = diff_snapshots(*pair('READY', 'READY\n' + record()))
    change = result['changes'][0]
    assert change['change_type'] == 'created'
    assert change['session_id'] == 'sess' and change['action_id'] == 'act'
    assert len(change['snapshot_refs']) == 2
    assert change['caused_by_action'] == 'unknown'
    assert change['after_metadata']['size'] == 1
    assert 'secret-token' not in json.dumps(result)
    assert ROOT not in json.dumps(result)


@pytest.mark.parametrize('old,new,expected', [
    (record(), '', 'deleted'), (record(), record(size=2), 'modified'),
    (record(), record(mtime=3), 'modified'), ('', record(kind='directory'), 'created'),
    ('', record(path='shared_prefs/secret.xml'), 'created'),
    ('', record(path='databases/account.db'), 'created')])
def test_supported_changes(old, new, expected):
    result = diff_snapshots(*pair('READY\n' + old, 'READY\n' + new))
    assert len(result['changes']) == 1
    assert result['changes'][0]['change_type'] == expected


def test_inaccessible_does_not_infer_deletion_or_no_behavior():
    result = diff_snapshots(capture('READY\n' + record()), capture('INACCESSIBLE', phase='after'))
    assert result['changes'] == [] and result['status'] == 'unavailable'
    assert 'inaccessible_storage_does_not_mean_no_filesystem_behavior' in result['coverage_gaps']


@pytest.mark.parametrize('code,err', [(-1, 'timeout'), (1, 'permission denied')])
def test_adapter_failure_is_coverage_gap(code, err):
    snap = capture('', code=code, err=err)
    assert all(root['status'] == 'unavailable' for root in snap.roots.values())
    assert err not in json.dumps(snap.to_dict())


def test_entry_cap_and_timeout_are_bounded_metadata_only():
    with patch('src.dynamic.runtime.filesystem_observer.run_adb_cmd', return_value=(0, 'READY', '')) as adb:
        FilesystemObserver('adb', 'device', max_entries=2).snapshot(PACKAGE, 's', 'r', 'a', 'before')
    assert adb.call_count == 3
    for call in adb.call_args_list:
        command = call.args[1][1]
        assert '-maxdepth 3' in command and 'head -n 3' in command
        assert 'stat -c' in command
        assert all(term not in command for term in ['run-as', ' su ', 'cat ', 'chmod', 'root'])
        assert call.kwargs['timeout_seconds'] == 3


def test_limit_and_permission_errors_cannot_fabricate_deletions():
    before = capture('READY\n' + record())
    after = capture('READY\n' + record() + '\n' + record('files/second'), phase='after', max_entries=1)
    assert after.roots['private']['status'] == 'partial'
    assert diff_snapshots(before, after)['changes'] == []
    after = capture('READY', err='permission denied with secret path', phase='after')
    assert diff_snapshots(before, after)['changes'] == []
    assert 'secret path' not in json.dumps(after.to_dict())


@pytest.mark.parametrize('line', ['garbage secret', record('../outside'),
    'regular file|1|2|/elsewhere/secret', record(size=-1)])
def test_malformed_metadata_is_partial_and_never_persisted(line):
    snap = capture('READY\n' + line)
    assert snap.roots['private']['status'] == 'partial'
    assert snap.roots['private']['entries'] == {}


def test_symlinks_not_followed_or_persisted():
    snap = capture('READY\n' + record(kind='symbolic link'))
    assert snap.roots['private']['entries'] == {}


@pytest.mark.parametrize('field', ['package', 'session_id', 'route_id', 'action_id'])
def test_evidence_chain_mismatch_rejected(field):
    before, after = pair('READY', 'READY')
    setattr(after, field, 'other')
    with pytest.raises(ValueError):
        diff_snapshots(before, after)


def test_snapshot_order_rejected():
    before, after = pair('READY', 'READY')
    after.timestamp = '2000-01-01'
    with pytest.raises(ValueError):
        diff_snapshots(before, after)


def test_no_content_fields_and_unchanged_not_negative_evidence():
    before, after = pair('READY\n' + record(), 'READY\n' + record())
    data = before.to_dict()
    assert set(next(iter(data['roots']['private']['entries'].values()))) == {'kind', 'size', 'mtime_epoch'}
    result = diff_snapshots(before, after)
    assert result['changes'] == []
    assert result['no_changes_means'] == 'not_observed_in_accessible_bounded_scope'


@pytest.mark.parametrize('kwargs', [{'max_entries': 501}, {'max_entries': 0}, {'timeout_seconds': 6}])
def test_invalid_bounds_rejected(kwargs):
    with pytest.raises(ValueError):
        FilesystemObserver('adb', 'device', **kwargs)


def test_package_shell_injection_rejected_before_adb():
    with patch('src.dynamic.runtime.filesystem_observer.run_adb_cmd') as adb:
        with pytest.raises(ValueError):
            FilesystemObserver('adb', 'device').snapshot('org.app; cat /secret', 's', 'r', 'a', 'before')
    adb.assert_not_called()


def test_deterministic_diff_order():
    before, after = pair('READY', 'READY\n' + record('files/z') + '\n' + record('files/a'))
    assert diff_snapshots(before, after) == diff_snapshots(before, after)
    paths = [x['path'] for x in diff_snapshots(before, after)['changes']]
    assert paths == sorted(paths)


def test_symlink_replacement_cannot_appear_as_deleted_file():
    before, after = pair('READY\n' + record(), 'READY\n' + record(kind='symbolic link'))
    assert after.roots['private']['status'] == 'partial'
    assert diff_snapshots(before, after)['changes'] == []
