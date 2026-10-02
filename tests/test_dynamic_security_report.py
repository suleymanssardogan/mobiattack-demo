"""Canonical report wiring uses existing lab evidence, never transport."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.dynamic.report import build_dynamic_analysis_report, generate_dynamic_analysis_report, load_dynamic_analysis_report, validate_dynamic_analysis_report, DynamicReportError
from src.dynamic.report.generator import ARTIFACTS
from src.dynamic.security.reporting import security_result_artifact, save_security_results
from src.dynamic.security.validation import load_recorded_auth_presence_case
from src.dynamic.security.contracts import DynamicValidationResult


@pytest.fixture
def sources():
    root=Path('examples/auth_lab_d10_2')
    read=lambda name:json.loads((root/name).read_text())
    result={'session':read('dynamic/session.json'),'traffic':read('dynamic/traffic.json'),
        'traffic_correlation':read('dynamic/traffic_evidence.json'),'api_correlation':read('dynamic/api_correlation.json'),
        'endpoint_contexts':read('dynamic/endpoint_contexts.json')}
    # Counts derive from the real recorded action, not invented exploration.
    timeline=read('dynamic/timeline.json')
    actions=[e for e in timeline if e['name']=='ACTION_EXECUTED']
    result['exploration']={'status':'partial','stop_reason':'recorded_single_action',
        'steps_attempted':len(actions),'actions_succeeded':sum(e['metadata']['status']=='succeeded' for e in actions),
        'actions_failed':sum(e['metadata']['status']!='succeeded' for e in actions),
        'screens_observed':0,'transitions_recorded':0,'duration_seconds':None}
    request,execution,registry,evidence=load_recorded_auth_presence_case('examples/auth_presence_d10_3',root)
    result['security_results']=security_result_artifact(request,execution,registry,evidence)
    return result


def build(sources):
    with patch('socket.socket') as socket, patch('subprocess.run') as process:
        report=build_dynamic_analysis_report('lab_report',sources)
    socket.assert_not_called();process.assert_not_called()
    return report


def test_d10_3_in_canonical_report_with_reason_and_no_finding(sources):
    report=build(sources)
    validate_dynamic_analysis_report(report)
    section=report['security_results'];row=section['results'][0]
    assert section['result_count']==1 and section['coverage']=='available'
    assert row['validation_outcome']=='validated'
    assert row['execution_status']=='completed'
    assert row['reason_codes']==['AUTH_ENFORCEMENT_CONFIRMED']
    assert row['finding_created'] is False
    assert row['test_category']=='authentication_presence' and row['risk_class']=='low'
    assert row['baseline_evidence_refs']['request'] and row['baseline_evidence_refs']['response']
    assert row['variant_evidence_refs']['request'] and row['variant_evidence_refs']['response']
    assert row['execution_result_ref'] in row['evidence_refs']
    assert row['session_id']==report['session']['session_id']
    assert row['endpoint_context_id'] in {c['endpoint_context_id'] for c in report['endpoint_contexts']}
    for ref in row['evidence_refs']:
        assert section['evidence_index'][ref]['endpoint_context_id']==row['endpoint_context_id']
    assert 'HISTORICAL_BASELINE' in row['limitations']


def test_existing_sections_preserved_exactly(sources):
    before=deepcopy(sources);without=deepcopy(sources);without.pop('security_results')
    old=build(without);new=build(sources)
    assert sources==before
    for key in ('runtime','routes','exploration','traffic','traffic_correlation','api_correlation','endpoint_context_summary','endpoint_contexts','coverage','session'):
        assert old[key]==new[key]
    assert 'security_results' not in old
    validate_dynamic_analysis_report(old)  # Legacy v1 report remains loadable.


@pytest.mark.parametrize('missing', ['baseline','variant'])
def test_missing_payload_downgrades_recorded_success(sources,missing):
    sources['security_results']['records'][0]['evidence'][missing]=None
    row=build(sources)['security_results']['results'][0]
    assert row['validation_outcome']=='inconclusive'
    assert row['reason_codes']==['MISSING_'+missing.upper()+'_EVIDENCE']
    assert row[missing+'_evidence_refs']=={'request':None,'response':None}


def test_synthetic_variant_is_blocked_visible(sources):
    sources['security_results']['records'][0]['evidence']['variant']['response']['synthetic']=True
    report=build(sources);row=report['security_results']['results'][0]
    assert row['validation_outcome']=='blocked' and row['reason_codes']==['SYNTHETIC_RESPONSE']
    assert report['analysis_coverage']=='partial' and row['finding_created'] is False


@pytest.mark.parametrize('outcome,criterion,coverage', [('blocked','policy_or_execution_blocked','partial'),('inconclusive','insufficient_evidence','partial'),('rejected','criteria_not_met','available')])
def test_recorded_negative_outcomes_remain_visible(sources,outcome,criterion,coverage):
    record=sources['security_results']['records'][0]
    old=DynamicValidationResult.from_dict(record['validation'])
    record['validation']=replace(old,outcome=outcome,criterion=criterion,coverage=coverage,
        reason_codes=('INSUFFICIENT_RESPONSE_COMPARISON',)).to_dict()
    report=build(sources);row=report['security_results']['results'][0]
    assert row['validation_outcome']==outcome
    assert row['finding_created'] is False and report['analysis_coverage']=='partial'
    assert report['security_results']['coverage']=='partial'


@pytest.mark.parametrize('status', ['failed','blocked','unavailable','interrupted'])
def test_failed_execution_never_secure(sources,status):
    record=sources['security_results']['records'][0]
    record['execution'].update(execution_status=status,observed_request_ref=None,observed_response_ref=None,failure_reason='transport_unavailable')
    report=build(sources);row=report['security_results']['results'][0]
    assert row['execution_status']==status and row['validation_outcome']=='inconclusive'
    assert row['reason_codes']==['EXECUTION_NOT_COMPLETED']
    assert 'EXECUTION_NOT_COMPLETED' in row['limitations']
    assert report['analysis_coverage']=='partial'


@pytest.mark.parametrize('defect', ['cross_session','unknown_endpoint','unknown_version','malformed_record','empty_results'])
def test_corrupt_or_unavailable_security_does_not_erase_dynamic(sources,defect):
    source=sources['security_results'];record=source['records'][0]
    if defect=='cross_session': source['session_id']='other_session'
    elif defect=='unknown_endpoint': record['evidence']['context']['endpoint_context_id']='ctx_missing'
    elif defect=='unknown_version': source['schema_version']='2.0'
    elif defect=='malformed_record': record.pop('request')
    else: source['records']=[]
    report=build(sources)
    assert report['security_results']['coverage']=='unavailable'
    assert report['analysis_coverage']=='partial'
    assert report['traffic']['total_transactions']==3
    assert len(report['endpoint_contexts'])==2


@pytest.mark.parametrize('defect', ['no_refs','missing_baseline_ref','missing_variant_ref','finding','wrong_reason','cross_session','index_owner','false_complete','missing_comparison','raw_secret'])
def test_report_loader_rejects_invalid_security_metadata(sources,defect):
    report=build(sources);section=report['security_results'];row=section['results'][0]
    if defect=='no_refs': row['evidence_refs']=[]
    elif defect=='missing_baseline_ref': row['baseline_evidence_refs']['response']=None
    elif defect=='missing_variant_ref': row['variant_evidence_refs']['request']=None
    elif defect=='finding': row['finding_created']=True
    elif defect=='wrong_reason': row['reason_codes']=['AI_APPROVED']
    elif defect=='cross_session': row['session_id']='other_session'
    elif defect=='index_owner': section['evidence_index'][row['execution_result_ref']]['endpoint_context_id']='ctx_missing'
    elif defect=='false_complete': section['coverage']='partial';report['analysis_coverage']='complete'
    elif defect=='missing_comparison':
        for ref,value in section['evidence_index'].items():
            if value['kind']=='comparison': value['kind']='tool'
    else: row['authorization']='Bearer SECRET'
    with pytest.raises(DynamicReportError): validate_dynamic_analysis_report(report)


def test_canonical_facade_atomic_persistence_and_privacy(sources,tmp_path):
    run=tmp_path/'run';dyn=run/'dynamic';dyn.mkdir(parents=True)
    for name,filename in ARTIFACTS.items():
        if name in sources and name!='security_results': (dyn/filename).write_text(json.dumps(sources[name]))
    save_security_results(run,sources['security_results'])
    report=generate_dynamic_analysis_report(run)
    assert load_dynamic_analysis_report(run,run.name)==report
    assert not list(dyn.glob('.tmp_security_*')) and not list(run.glob('.tmp_dynamic_report_*'))
    text=(run/'dynamic_analysis_report.json').read_text()
    assert 'Bearer ' not in text and 'local_lab_password' not in text and 'local_lab_user' not in text
    assert '"body"' not in text and '"headers"' not in text
    assert not (run/'agent_report.json').exists()
    assert report['evidence']['security_results']=='dynamic/security_results.json'


def test_corrupt_security_json_remains_explicit_in_facade(sources,tmp_path):
    dyn=tmp_path/'dynamic';dyn.mkdir()
    for name,filename in ARTIFACTS.items():
        if name in sources: (dyn/filename).write_text(json.dumps(sources[name]))
    (dyn/'security_results.json').write_text('{broken')
    report=generate_dynamic_analysis_report(tmp_path)
    assert report['security_results']['coverage']=='unavailable'
    assert report['evidence_status']['security_results']=='corrupt'
    assert report['traffic']['total_transactions']==3


def test_only_security_incompleteness_also_forces_partial(sources):
    sources['exploration']['status']='completed'
    sources['runtime']={'actions':[{'correlation_status':'available'}]}
    sources['traffic']['https_visibility']='available'
    sources['security_results']['records'][0]['evidence']['variant']=None
    report=build(sources)
    assert all(value=='available' for value in report['coverage'].values())
    assert report['security_results']['coverage']=='partial'
    assert report['analysis_coverage']=='partial'


@pytest.mark.parametrize('defect', ['context_kind','session_kind','same_request','same_response','float_count'])
def test_public_evidence_binding_and_count_types_strict(sources,defect):
    report=build(sources);section=report['security_results'];row=section['results'][0]
    if defect=='context_kind': section['evidence_index'][row['endpoint_context_id']]['kind']='tool'
    elif defect=='session_kind': section['evidence_index'][row['session_id']]['kind']='context'
    elif defect=='same_request': row['variant_evidence_refs']['request']=row['baseline_evidence_refs']['request']
    elif defect=='same_response': row['variant_evidence_refs']['response']=row['baseline_evidence_refs']['response']
    else: section['result_count']=1.0
    with pytest.raises(DynamicReportError):validate_dynamic_analysis_report(report)


def test_source_writer_rejects_unredacted_secret_before_persistence(sources,tmp_path):
    sources['security_results']['records'][0]['evidence']['baseline']['request']['headers']['authorization']='Bearer private_secret'
    with pytest.raises(ValueError):save_security_results(tmp_path,sources['security_results'])
    assert not (tmp_path/'dynamic/security_results.json').exists()
