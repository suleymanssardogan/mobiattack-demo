"""Offline migration and value-free metadata integrity; no transport."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.dynamic.security.auth_evidence_contract import adapt_auth_presence_evidence
from src.dynamic.security.validation import load_recorded_auth_presence_case, validate_authentication_presence
from src.dynamic.security.reporting import security_result_artifact, build_security_section
from src.dynamic.traffic.auth_metadata import observe_auth
from src.dynamic.traffic.normalizer import sanitize_transaction_data


def case():
    return load_recorded_auth_presence_case('examples/auth_presence_d10_3', 'examples/auth_lab_d10_2')


def validate(parts):
    with patch('socket.socket') as socket, patch('subprocess.run') as process:
        result = validate_authentication_presence(*parts)
    socket.assert_not_called()
    process.assert_not_called()
    return result


def test_reviewed_migration_is_explicit_immutable_and_idempotent():
    *_, evidence = case()
    original = json.loads(Path('examples/auth_presence_d10_3/baseline_transaction.json').read_text())
    assert evidence.baseline != original
    assert evidence.auth_contract_version == 'sanitized_auth_v2'
    assert set(evidence.auth_migration) == {'baseline', 'variant'}
    assert adapt_auth_presence_evidence(evidence) == evidence
    assert evidence.baseline == sanitize_transaction_data(evidence.baseline)
    assert evidence.baseline['request']['auth_metadata']['state'] == 'present'
    assert evidence.variant['request']['auth_metadata']['state'] == 'absent'
    assert evidence.baseline['request']['auth_metadata']['token_type'] == 'unknown'
    assert evidence.baseline['request']['auth_metadata']['credential_refs'] == []
    assert json.loads(Path('examples/auth_presence_d10_3/baseline_transaction.json').read_text()) == original


@pytest.mark.parametrize('defect', ['secret', 'extra_header', 'query', 'synthetic'])
def test_changed_legacy_evidence_is_not_silently_repaired(defect):
    request, execution, registry, evidence = case()
    old = json.loads(Path('examples/auth_presence_d10_3/baseline_transaction.json').read_text())
    if defect == 'secret': old['request']['headers']['authorization'] = 'Bearer disposable_test_secret'
    elif defect == 'extra_header': old['request']['headers']['x-extra'] = 'changed'
    elif defect == 'query': old['request']['query'] = {'id':'2'}
    else: old['response']['synthetic'] = True
    adapted = adapt_auth_presence_evidence(replace(evidence, baseline=old, auth_migration={}))
    assert adapted.baseline == old
    assert validate((request, execution, registry, adapted)).outcome == 'blocked'


@pytest.mark.parametrize('defect', ['missing', 'unknown', 'cross_session', 'authenticated_claim', 'secret', 'absent_baseline', 'present_variant'])
def test_metadata_cannot_upgrade_incomplete_or_forged_auth(defect):
    request, execution, registry, evidence = case()
    metadata = evidence.baseline['request']['auth_metadata']
    if defect == 'missing': evidence.baseline['request'].pop('auth_metadata')
    elif defect == 'unknown': metadata['state']='unknown'
    elif defect == 'cross_session': metadata['session_id']='other_session'
    elif defect == 'authenticated_claim': metadata['authenticated_state']='authenticated'
    elif defect == 'secret': metadata['raw_token']='disposable_test_secret'
    elif defect == 'absent_baseline': metadata['state']='absent'
    else: evidence.variant['request']['auth_metadata']['state']='present'
    assert validate((request, execution, registry, evidence)).outcome == 'blocked'


def test_scoped_credential_reference_survives_validation_and_report():
    request, execution, registry, evidence = case()
    metadata = observe_auth({'authorization':'Bearer disposable_test_secret'}, request.session_id)
    evidence.baseline['request']['auth_metadata'] = metadata
    before = deepcopy(evidence)
    assert validate((request, execution, registry, evidence)).outcome == 'validated'
    artifact = security_result_artifact(request, execution, registry, evidence)
    assert evidence == before
    assert 'disposable_test_secret' not in json.dumps(artifact)
    assert artifact['records'][0]['evidence']['baseline']['request']['auth_metadata']['credential_refs'] == metadata['credential_refs']
    report = build_security_section(artifact, request.session_id, [evidence.context.to_dict()])
    assert report['results'][0]['validation_outcome'] == 'validated'
    assert report['results'][0]['finding_created'] is False


def test_unadapted_legacy_payload_cannot_validate_directly():
    request, execution, registry, evidence = case()
    old = json.loads(Path('examples/auth_presence_d10_3/baseline_transaction.json').read_text())
    assert validate((request, execution, registry, replace(evidence, baseline=old))).outcome == 'blocked'


def test_recorded_source_migration_is_explicit_and_never_trusts_saved_success():
    from src.dynamic.security.auth_evidence_contract import migrate_recorded_auth_artifact
    source = json.loads(Path('examples/auth_security_report_d12/dynamic/security_results.json').read_text())
    original = deepcopy(source)
    migrated = migrate_recorded_auth_artifact(source)
    assert source == original
    assert migrated['records'][0]['execution'] == original['records'][0]['execution']
    assert migrated['records'][0]['registry'] == original['records'][0]['registry']
    assert migrate_recorded_auth_artifact(migrated) == migrated
    record = migrated['records'][0]
    contexts = [record['evidence']['context']]
    assert build_security_section(migrated, migrated['session_id'], contexts)['results'][0]['validation_outcome'] == 'validated'
    record['evidence']['variant']['request']['auth_metadata']['state'] = 'unknown'
    assert build_security_section(migrated, migrated['session_id'], contexts)['results'][0]['validation_outcome'] == 'blocked'


def test_foreign_session_credential_reference_cannot_validate():
    request, execution, registry, evidence = case()
    evidence.baseline['request']['auth_metadata'] = observe_auth({'authorization':'Bearer disposable_test_secret'}, 'other_session')
    assert validate((request, execution, registry, evidence)).outcome == 'blocked'
