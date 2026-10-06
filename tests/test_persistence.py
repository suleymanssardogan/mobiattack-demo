"""Artifact integrity across serialization, filesystem failures and concurrent writers."""
from concurrent.futures import ThreadPoolExecutor
import json
from unittest.mock import patch

import pytest

from src.persistence import write_json_atomic


def test_unicode_and_nested_directory_round_trip(tmp_path):
    target = tmp_path / 'nested' / 'artifact.json'
    data = {'message': 'Güvenli gözlem', 'refs': ['tx_1']}
    assert write_json_atomic(target, data) == target
    assert json.loads(target.read_text()) == data
    assert 'Güvenli' in target.read_text()


@pytest.mark.parametrize('failure', ['serialization', 'replace', 'durability'])
def test_failure_preserves_previous_artifact_and_removes_scratch(tmp_path, failure):
    target = tmp_path / 'artifact.json'
    target.write_text('{"previous":true}')
    if failure == 'serialization':
        with pytest.raises(TypeError):
            write_json_atomic(target, {'unsupported': object()})
    else:
        operation = 'fsync' if failure == 'durability' else 'replace'
        with patch('src.persistence.os.' + operation, side_effect=OSError('disk failure')):
            with pytest.raises(OSError, match='disk failure'):
                write_json_atomic(target, {'new': True}, durable=True)
    assert json.loads(target.read_text()) == {'previous': True}
    assert not list(tmp_path.glob('.tmp_json_*'))


def test_strict_report_rejects_nan_without_replacing_valid_artifact(tmp_path):
    target = tmp_path / 'report.json'
    write_json_atomic(target, {'count': 0})
    with pytest.raises(ValueError):
        write_json_atomic(target, {'count': float('nan')}, allow_nan=False)
    assert json.loads(target.read_text()) == {'count': 0}


def test_concurrent_writers_never_mix_artifact_contents(tmp_path):
    target = tmp_path / 'artifact.json'
    def write(index):
        payload = {'writer': index, 'refs': [str(index)] * 200}
        write_json_atomic(target, payload)
        observed = json.loads(target.read_text())
        assert observed['refs'] == [str(observed['writer'])] * 200
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(write, range(20)))
    assert not list(tmp_path.glob('.tmp_json_*'))
