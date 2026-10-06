"""D11 offline regressions use the real, sanitized D10.3 lab capture."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.dynamic.security.contracts import DynamicValidationResult, EvidenceReference, validate_result
from src.dynamic.security.validation import (
    load_recorded_auth_presence_case, validate_authentication_presence,
)


def case():
    return load_recorded_auth_presence_case('examples/auth_presence_d10_3','examples/auth_lab_d10_2')


def evaluate(request, execution, registry, evidence):
    with patch('socket.socket') as socket, patch('subprocess.run') as process:
        result = validate_authentication_presence(request,execution,registry,evidence)
    socket.assert_not_called(); process.assert_not_called()
    return result


def test_real_d10_3_case_revalidates_without_network_or_secrets():
    request,execution,registry,evidence=case()
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome=='validated'
    assert result.reason_codes==('AUTH_ENFORCEMENT_CONFIRMED',)
    validate_result(request,execution,result,registry,auth_evidence=evidence)
    assert DynamicValidationResult.from_dict(result.to_dict())==result
    assert '[REDACTED]'==evidence.baseline['request']['headers']['authorization']
    assert 'Bearer ' not in json.dumps(result.to_dict())
    assert not any(k in result.to_dict() for k in ('finding','poc','severity','is_vulnerable'))


@pytest.mark.parametrize('role,code', [
    ('baseline_request','MISSING_BASELINE_EVIDENCE'), ('baseline_response','MISSING_BASELINE_EVIDENCE'),
    ('variant_request','MISSING_VARIANT_EVIDENCE'), ('variant_response','MISSING_VARIANT_EVIDENCE'),
    ('context','MISSING_ENDPOINT_EVIDENCE'), ('session','MISSING_SESSION_EVIDENCE'),
    ('execution','MISSING_EXECUTION_EVIDENCE'), ('control','MISSING_COMPARISON_EVIDENCE'),
    ('comparison','MISSING_COMPARISON_EVIDENCE')])
def test_every_required_registry_reference_is_enforced(role,code):
    request,execution,registry,evidence=case()
    refs={'baseline_request':evidence.baseline['request']['request_id'],
          'baseline_response':evidence.baseline['response']['headers']['x-lab-trace-id'],
          'variant_request':execution.observed_request_ref,'variant_response':execution.observed_response_ref,
          'context':request.endpoint_context_id,'session':request.session_id,'execution':evidence.execution_ref,
          'control':evidence.control_ref,'comparison':evidence.comparison_ref}
    registry.pop(refs[role])
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome=='inconclusive' and result.reason_codes==(code,)
    assert refs[role] not in result.evidence_refs


@pytest.mark.parametrize('side,field', [('baseline','request'),('baseline','response'),('variant','request'),('variant','response'),('baseline','transaction'),('variant','transaction')])
def test_missing_payload_is_inconclusive(side,field):
    request,execution,registry,evidence=case()
    if field=='transaction': evidence=replace(evidence,**{side:None})
    else: getattr(evidence,side).pop(field)
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome=='inconclusive'
    assert result.reason_codes==('MISSING_'+side.upper()+'_EVIDENCE',)


@pytest.mark.parametrize('location', ['baseline','variant','session','execution','registry','baseline_receipt','variant_receipt'])
def test_cross_session_is_blocked(location):
    request,execution,registry,evidence=case()
    if location in {'baseline','variant'}: getattr(evidence,location)['session_id']='other_session'
    elif location=='session': evidence.session['session_id']='other_session'
    elif location=='execution': execution=replace(execution,session_id='other_session')
    elif location=='registry': registry[execution.observed_response_ref]=replace(registry[execution.observed_response_ref],session_id='other_session')
    elif location=='baseline_receipt':
        next(r for r in evidence.baseline_receipts if r['path']=='/profile')['run_id']='other_session'
    else: evidence.variant_receipts[0]['run_id']='other_session'
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome=='blocked' and result.reason_codes==('CROSS_SESSION_EVIDENCE',)


@pytest.mark.parametrize('location', ['context','execution','registry','baseline','variant'])
def test_cross_endpoint_is_blocked(location):
    request,execution,registry,evidence=case()
    if location=='context': evidence.context.endpoint_context_id='ctx_other'
    elif location=='execution': execution=replace(execution,endpoint_context_id='ctx_other')
    elif location=='registry': registry[execution.observed_response_ref]=replace(registry[execution.observed_response_ref],endpoint_context_id='ctx_other')
    else: getattr(evidence,location)['request']['port']=18082
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome=='blocked' and result.reason_codes==('CROSS_ENDPOINT_EVIDENCE',)


@pytest.mark.parametrize('side', ['baseline','variant'])
@pytest.mark.parametrize('location', ['transaction','request','response','receipt'])
@pytest.mark.parametrize('marker', ['synthetic','internal'])
def test_synthetic_and_internal_evidence_never_validate(side,location,marker):
    request,execution,registry,evidence=case()
    payload=getattr(evidence,side)
    if location=='receipt':
        records=getattr(evidence,side+'_receipts')
        target=next(r for r in records if r['path']=='/profile')
    else: target=payload if location=='transaction' else payload[location]
    target[marker]=True
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome=='blocked' and result.reason_codes==('SYNTHETIC_RESPONSE',)


@pytest.mark.parametrize('field,value,code', [
    ('path','/account','CROSS_ENDPOINT_EVIDENCE'), ('method','POST','CROSS_ENDPOINT_EVIDENCE'),
    ('host','external.example','CROSS_ENDPOINT_EVIDENCE'),('scheme','https','CROSS_ENDPOINT_EVIDENCE'),
    ('query',{'id':'[REDACTED]'},'UNEXPECTED_REQUEST_MUTATION'),('body',{'id':'[REDACTED]'},'UNEXPECTED_REQUEST_MUTATION'),
    ('headers',{'x-lab-run-id':'other_session'},'CROSS_SESSION_EVIDENCE'),
    ('body_metadata',{'size':1,'truncated':False,'binary':False},'UNEXPECTED_REQUEST_MUTATION'),
    ('extra_request_field','extra','UNEXPECTED_REQUEST_MUTATION')])
def test_unauthorized_request_mutation_is_blocked(field,value,code):
    request,execution,registry,evidence=case()
    evidence.variant['request'][field]=value
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome=='blocked' and result.reason_codes==(code,)


@pytest.mark.parametrize('mode', ['auth_reintroduced','unrelated_header_removed','unrelated_header_changed','unrelated_header_added'])
def test_headers_must_differ_only_by_auth_removal(mode):
    request,execution,registry,evidence=case()
    headers=evidence.variant['request']['headers']
    if mode=='auth_reintroduced': headers['authorization']='[REDACTED]'
    elif mode=='unrelated_header_removed': headers.pop('accept')
    elif mode=='unrelated_header_changed': headers['accept']='application/json'
    else: headers['x-new-header']='extra'
    result=evaluate(request,execution,registry,evidence)
    code = 'UNREDACTED_EVIDENCE' if mode in {'unrelated_header_changed', 'unrelated_header_added'} else 'UNEXPECTED_REQUEST_MUTATION'
    assert result.reason_codes==(code,) and result.outcome=='blocked'


@pytest.mark.parametrize('side', ['baseline','variant'])
@pytest.mark.parametrize('defect', ['metadata_missing','truncated','binary','size_missing','status_missing','status_invalid','body_missing','content_type_missing'])
def test_response_comparison_requires_complete_metadata(side,defect):
    request,execution,registry,evidence=case()
    response=getattr(evidence,side)['response']
    if defect=='metadata_missing': response.pop('body_metadata')
    elif defect=='truncated': response['body_metadata']['truncated']=True
    elif defect=='binary': response['body_metadata']['binary']=True;response['body']=None
    elif defect=='size_missing': response['body_metadata'].pop('size')
    elif defect=='status_missing': response.pop('status_code')
    elif defect=='status_invalid': response['status_code']=2000
    elif defect=='body_missing': response.pop('body')
    else: response['headers'].pop('content-type')
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome!='validated'
    assert result.reason_codes in {('INSUFFICIENT_RESPONSE_COMPARISON',),('UNREDACTED_EVIDENCE',)}


@pytest.mark.parametrize('side', ['baseline','variant'])
def test_receipt_missing_or_duplicate_never_validates(side):
    request,execution,registry,evidence=case()
    for receipts in [[],getattr(evidence,side+'_receipts')*2]:
        changed=replace(evidence,**{side+'_receipts':receipts})
        result=evaluate(request,execution,registry,changed)
        assert result.outcome=='inconclusive'
        assert result.reason_codes==('MISSING_'+side.upper()+'_EVIDENCE',)


@pytest.mark.parametrize('status', ['failed','blocked','unavailable','interrupted'])
def test_failed_or_incomplete_execution_never_means_secure(status):
    request,execution,registry,evidence=case()
    execution=replace(execution,execution_status=status,observed_request_ref=None,observed_response_ref=None,failure_reason='transport_unavailable')
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome=='inconclusive' and result.reason_codes==('EXECUTION_NOT_COMPLETED',)


def test_200_alone_remains_inconclusive_even_with_receipt():
    request,execution,registry,evidence=case()
    response=evidence.variant['response']
    response['status_code']=200
    response['body']=deepcopy(evidence.baseline['response']['body'])
    response['body_metadata']=deepcopy(evidence.baseline['response']['body_metadata'])
    evidence.variant_receipts[0]['status']=200
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome=='inconclusive' and result.reason_codes==('INSUFFICIENT_RESPONSE_COMPARISON',)


def test_registry_labels_alone_cannot_upgrade_old_summary():
    request,execution,registry,evidence=case()
    result=evaluate(request,execution,registry,evidence)
    with pytest.raises(ValueError): validate_result(request,execution,result,registry)
    evidence=replace(evidence,variant=None)
    with pytest.raises(ValueError,match='MISSING_VARIANT_EVIDENCE'):
        validate_result(request,execution,result,registry,auth_evidence=evidence)


@pytest.mark.parametrize('role', ['baseline_request','baseline_response','context','session','execution','control','comparison'])
def test_removing_result_ref_cannot_preserve_validated(role):
    request,execution,registry,evidence=case()
    result=evaluate(request,execution,registry,evidence)
    ref={'baseline_request':evidence.baseline['request']['request_id'],
         'baseline_response':evidence.baseline['response']['headers']['x-lab-trace-id'],
         'context':request.endpoint_context_id,'session':request.session_id,'execution':evidence.execution_ref,
         'control':evidence.control_ref,'comparison':evidence.comparison_ref}[role]
    result=replace(result,evidence_refs=tuple(x for x in result.evidence_refs if x!=ref))
    with pytest.raises(ValueError): validate_result(request,execution,result,registry,auth_evidence=evidence)


def test_reason_codes_stable_and_schema_rejects_unknown_codes():
    request,execution,registry,evidence=case()
    result=evaluate(request,execution,registry,evidence)
    other=evaluate(request,execution,dict(reversed(list(registry.items()))),deepcopy(evidence))
    assert result.reason_codes==other.reason_codes
    with pytest.raises(ValueError): replace(result,reason_codes=('AI_APPROVED',))
    with pytest.raises(ValueError): replace(result,reason_codes=('MISSING_BASELINE_EVIDENCE',))


def test_raw_secrets_are_not_needed_and_unredacted_inputs_are_blocked():
    request,execution,registry,evidence=case()
    evidence.baseline['request']['headers']['authorization']='Bearer private_secret'
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome=='blocked' and result.reason_codes==('UNREDACTED_EVIDENCE',)
    assert 'private_secret' not in json.dumps(result.to_dict())


def test_evidence_kind_and_observation_reference_integrity():
    request,execution,registry,evidence=case()
    registry[execution.observed_response_ref]=replace(registry[execution.observed_response_ref],kind='tool')
    result=evaluate(request,execution,registry,evidence)
    assert result.reason_codes==('REFERENCE_MISMATCH',)


def test_recorded_comparison_boolean_is_not_authority(tmp_path):
    import shutil
    source=Path('examples/auth_presence_d10_3')
    copy=tmp_path/'case';shutil.copytree(source,copy)
    path=copy/'comparison.json'; data=json.loads(path.read_text())
    data['expected_auth_enforcement_observed']=False;data['auth_removed']=False
    path.write_text(json.dumps(data))
    request,execution,registry,evidence=load_recorded_auth_presence_case(copy,'examples/auth_lab_d10_2')
    assert evaluate(request,execution,registry,evidence).outcome=='validated'
    # The historical source is checked, so altered baseline copies cannot be substituted.
    path=copy/'baseline_transaction.json';data=json.loads(path.read_text())
    data['request']['headers']['accept']='other';path.write_text(json.dumps(data))
    with pytest.raises(ValueError,match='REFERENCE_MISMATCH'):
        load_recorded_auth_presence_case(copy,'examples/auth_lab_d10_2')


def test_no_evidence_cannot_produce_a_canonical_validated_result():
    request,execution,_,evidence=case()
    with pytest.raises(ValueError): evaluate(request,execution,{},evidence)


def test_contradictory_variant_receipt_cannot_confirm_enforcement():
    request,execution,registry,evidence=case()
    evidence.variant_receipts[0]['auth_valid']=True
    result=evaluate(request,execution,registry,evidence)
    assert result.outcome=='blocked' and result.reason_codes==('REFERENCE_MISMATCH',)
