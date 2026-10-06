"""Metadata-only mapping and canonical serialization, no transport or executor."""
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.dynamic.security.contracts import ACTIONS
from src.dynamic.security.standards import standards_for_category, validate_standards_metadata
from src.dynamic.security.reporting import save_security_results
from src.dynamic.report import build_dynamic_analysis_report, validate_dynamic_analysis_report, DynamicReportError
from src.dynamic.report.generator import ARTIFACTS


@pytest.mark.parametrize('category', sorted(ACTIONS))
def test_all_supported_categories_have_descriptive_metadata(category):
    metadata=standards_for_category(category)
    validate_standards_metadata(metadata,category)
    assert set(metadata)=={'masvs_category','masvs_control_refs','mastg_test_refs','maswe_refs'}
    assert metadata['mastg_test_refs']==metadata['maswe_refs']==[]
    if category in {'input_validation','parameter_consistency'}:
        assert metadata['masvs_category']=='MASVS-CODE'
        assert metadata['masvs_control_refs']==[]
    else:
        assert metadata['masvs_category']=='MASVS-AUTH'
        assert metadata['masvs_control_refs']==['MASVS-AUTH-1']


def test_registry_cannot_be_changed_by_mutating_returned_metadata():
    first=standards_for_category('authentication_presence')
    first['masvs_control_refs'].append('MASVS-AUTH-999')
    first['masvs_category']='MASVS-FAKE'
    assert standards_for_category('authentication_presence')['masvs_control_refs']==['MASVS-AUTH-1']
    assert standards_for_category('session_handling')['masvs_category']=='MASVS-AUTH'


@pytest.mark.parametrize('category', ['unknown','AUTHENTICATION_PRESENCE',None,{},[]])
def test_unknown_test_category_never_gets_invented_mapping(category):
    with pytest.raises(ValueError):standards_for_category(category)


@pytest.mark.parametrize('field,value', [
    ('masvs_category','MASVS-UNKNOWN'), ('masvs_category','MASVS-CODE'),('masvs_category',None),
    ('masvs_control_refs',['MASVS-AUTH-999']), ('masvs_control_refs',['MASVS-AUTH-2']),
    ('masvs_control_refs',['MASVS-CODE-4']), ('masvs_control_refs',['MSTG-AUTH-1']),
    ('masvs_control_refs',['MASVS-AUTH-1','MASVS-AUTH-1']),
    ('masvs_control_refs','MASVS-AUTH-1'),('masvs_control_refs',[None]),
    ('mastg_test_refs',['MASTG-TEST-9999']), ('mastg_test_refs',['MASTG-TEST-0003']),
    ('mastg_test_refs',['https://mas.owasp.org/MASTG/']),('mastg_test_refs',['MASTG-KNOW-0056']),
    ('maswe_refs',['MASWE-9999']), ('maswe_refs',['MASWE-0018']), ('maswe_refs',['MASWE-0020']),
    ('maswe_refs',['MASWE-50']),('maswe_refs',None)])
def test_unknown_malformed_or_official_but_inappropriate_refs_rejected(field,value):
    metadata=standards_for_category('authentication_presence');metadata[field]=value
    with pytest.raises(ValueError):validate_standards_metadata(metadata,'authentication_presence')


@pytest.mark.parametrize('field', ['severity','compliance_certified','finding_created','execute_now'])
def test_metadata_cannot_carry_policy_or_finding_fields(field):
    metadata=standards_for_category('authentication_presence');metadata[field]=True
    with pytest.raises(ValueError):validate_standards_metadata(metadata,'authentication_presence')


def test_empty_specific_refs_allowed_and_missing_required_metadata_fields_rejected():
    metadata=standards_for_category('authentication_presence');metadata['masvs_control_refs']=[]
    validate_standards_metadata(metadata,'authentication_presence')
    metadata.pop('mastg_test_refs')
    with pytest.raises(ValueError):validate_standards_metadata(metadata,'authentication_presence')


def sources():
    root=Path('examples/auth_security_report_d12')
    artifacts={key:json.loads((root/'dynamic'/filename).read_text()) for key,filename in ARTIFACTS.items() if (root/'dynamic'/filename).exists()}
    prior=json.loads((root/'dynamic_analysis_report.json').read_text())
    from src.dynamic.security.auth_evidence_contract import migrate_recorded_auth_artifact
    artifacts['security_results']=migrate_recorded_auth_artifact(artifacts['security_results'])
    prior['traffic']['http_visibility_reason']=None
    # D20 preserves the actual backend label; historical execution/validation evidence is unchanged.
    assert artifacts['traffic']['backend'] == 'NativeProxyCaptureBackend'
    prior['traffic']['backend'] = 'native_http'
    return artifacts,prior


def build(artifacts,prior):
    with patch('socket.socket') as socket, patch('subprocess.run') as process:
        report=build_dynamic_analysis_report(prior['scan_id'],artifacts,generated_at=prior['generated_at'])
    socket.assert_not_called();process.assert_not_called()
    return report


def test_d10_3_serialization_changes_only_standards_metadata():
    artifacts,prior=sources();snapshot=deepcopy(artifacts)
    report=build(artifacts,prior)
    row=report['security_results']['results'][0]
    assert row['standards']==standards_for_category('authentication_presence')
    assert row['validation_outcome']=='validated' and row['reason_codes']==['AUTH_ENFORCEMENT_CONFIRMED']
    assert row['finding_created'] is False
    assert row['execution_status']=='completed' and row['risk_class']=='low'
    validate_dynamic_analysis_report(report)
    without=deepcopy(report)
    without['security_results']['results'][0].pop('standards')
    assert without['security_results']['results']==prior['security_results']['results']
    assert artifacts==snapshot  # Source execution, validation, refs and timestamps untouched.
    validate_dynamic_analysis_report(prior)  # Legacy rows remain backward-compatible.


@pytest.mark.parametrize('field,value', [('masvs_control_refs',['MASVS-AUTH-999']),('mastg_test_refs',['MASTG-TEST-9999']),('maswe_refs',['MASWE-0018']),('masvs_category','MASVS-CODE')])
def test_invalid_refs_cannot_enter_canonical_report(field,value):
    artifacts,prior=sources();report=build(artifacts,prior)
    report['security_results']['results'][0]['standards'][field]=value
    with pytest.raises(DynamicReportError):validate_dynamic_analysis_report(report)


def test_invalid_source_metadata_explicitly_corrupt_and_not_silently_serialized():
    artifacts,prior=sources()
    metadata=standards_for_category('authentication_presence');metadata['maswe_refs']=['MASWE-9999']
    artifacts['security_results']['records'][0]['standards']=metadata
    report=build(artifacts,prior)
    assert report['security_results']['coverage']=='unavailable'
    assert report['evidence_status']['security_results']=='corrupt'
    assert report['security_results']['results']==[]
    assert report['traffic']==prior['traffic']


def test_invalid_source_metadata_rejected_before_atomic_write(tmp_path):
    artifacts,_=sources()
    metadata=standards_for_category('authentication_presence');metadata['mastg_test_refs']=['MASTG-TEST-9999']
    artifacts['security_results']['records'][0]['standards']=metadata
    with pytest.raises(ValueError):save_security_results(tmp_path,artifacts['security_results'])
    assert not (tmp_path/'dynamic/security_results.json').exists()


def test_supported_metadata_persists_without_modifying_security_contracts(tmp_path):
    artifacts,_=sources();source=artifacts['security_results'];original=deepcopy(source)
    source['records'][0]['standards']=standards_for_category('authentication_presence')
    path=save_security_results(tmp_path,source)
    actual=json.loads(path.read_text());actual['records'][0].pop('standards')
    assert actual==original
