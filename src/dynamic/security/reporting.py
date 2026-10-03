"""Evidence-checked projection into Dynamic reports; no requests or findings."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import tempfile

from src.dynamic.context.models import EndpointContext
from src.dynamic.security.contracts import (
    DynamicTestRequest, DynamicTestExecutionResult, DynamicValidationResult,
    EvidenceReference, VALIDATION_REASON_CODES, EXECUTION_STATUSES, OUTCOMES,
    RISK_CLASSES, ACTIONS, _id, _time,
)
from src.dynamic.security.validation import AuthPresenceEvidence, validate_authentication_presence
from src.dynamic.traffic.normalizer import sanitize_transaction_data
from src.dynamic.security.standards import standards_for_category, validate_standards_metadata

def _validator(category):
    if category=='session_handling':
        from src.dynamic.security.session_invalidation import validate_session_invalidation
        return validate_session_invalidation
    if category=='function_authorization':
        from src.dynamic.security.function_authorization import validate_function_authorization
        return validate_function_authorization
    if category=='object_authorization':
        from src.dynamic.security.object_authorization import validate_object_authorization
        return validate_object_authorization
    return validate_authentication_presence


def _relationship(category):
    if category=='session_handling':
        return {'principal_alias':'user_A','protected_resource':'profile','transition':'authenticated_to_logged_out','credential_generation':1}
    if category=='function_authorization':
        return {'normal_principal':'user_A','normal_role':'user','privileged_principal':'user_B',
                'privileged_role':'admin','function':'training_toggle'}
    return {'principal_alias':'user_A','resource_owner_alias':'user_B','baseline_resource_id':'1001','variant_resource_id':'2002'}


def _message(category,codes):
    if category=='session_handling':
        return ('Session invalidation after logout confirmed' if list(codes)==['SESSION_INVALIDATION_ENFORCED']
                else 'Session invalidation not enforced in controlled lab' if list(codes)==['SESSION_INVALIDATION_NOT_ENFORCED']
                else 'Session invalidation check incomplete')
    prefix='FUNCTION' if category=='function_authorization' else 'OBJECT'
    label='Function' if category=='function_authorization' else 'Object'
    return (label+' authorization enforcement confirmed' if list(codes)==[prefix+'_AUTHORIZATION_ENFORCED']
            else label+' authorization not enforced in controlled lab' if list(codes)==[prefix+'_AUTHORIZATION_NOT_ENFORCED']
            else label+' authorization check incomplete')


FILENAME = 'security_results.json'
LIMITATIONS = frozenset({'SECURITY_RESULTS_UNAVAILABLE', 'SECURITY_SOURCE_INVALID',
    'INCOMPLETE_SECURITY_VALIDATION', 'EXECUTION_NOT_COMPLETED', 'HISTORICAL_BASELINE',
    'OUTCOME_NOT_SECURITY_ASSURANCE'})


def security_result_artifact(request, execution, registry, evidence, validation=None):
    """Sanitized source record, separate from the compact public report section."""
    for payload in (evidence.baseline,evidence.variant,getattr(evidence,'logout',None)):
        if payload is not None and sanitize_transaction_data(payload) != payload:
            raise ValueError('Security source must already be sanitized')
    validate = _validator(request.test_category)
    result = validation or validate(request, execution, registry, evidence)
    return {'schema_version':'1.0', 'session_id':request.session_id, 'records':[{
        'request':request.to_dict(), 'execution':execution.to_dict(), 'validation':result.to_dict(),
        'standards':standards_for_category(request.test_category),
        'registry':{ref:asdict(record) for ref,record in sorted(registry.items())},
        'evidence':{'context':evidence.context.to_dict(), 'session':{'session_id':evidence.session['session_id']},
            'baseline':evidence.baseline, 'variant':evidence.variant,
            'baseline_receipts':evidence.baseline_receipts, 'variant_receipts':evidence.variant_receipts,
            'execution_ref':evidence.execution_ref, 'control_ref':evidence.control_ref,
            'comparison_ref':evidence.comparison_ref,
            **({'ownership':evidence.ownership} if request.test_category == 'object_authorization' else {'privileges':evidence.privileges} if request.test_category == 'function_authorization' else {'lifecycle':evidence.lifecycle,'logout':evidence.logout,'logout_receipts':evidence.logout_receipts} if request.test_category=='session_handling' else {})}}]}


def save_security_results(run_dir, artifact):
    """Atomic persistence under the existing canonical Dynamic artifact directory."""
    directory=Path(run_dir)/'dynamic';directory.mkdir(parents=True,exist_ok=True)
    if not isinstance(artifact,dict) or set(artifact)!={'schema_version','session_id','records'} or artifact.get('schema_version')!='1.0' or not isinstance(artifact.get('records'),list):
        raise ValueError('Invalid security artifact')
    _id(artifact['session_id'])
    for record in artifact['records']:
        if not isinstance(record,dict) or set(record) not in ({'request','execution','validation','registry','evidence'}, {'request','execution','validation','registry','evidence','standards'}):
            raise ValueError('Invalid security record')
        request=DynamicTestRequest.from_dict(record['request'])
        if 'standards' in record:
            validate_standards_metadata(record['standards'],request.test_category)
        DynamicTestExecutionResult.from_dict(record['execution'])
        DynamicValidationResult.from_dict(record['validation'])
        for payload in (record['evidence'].get('baseline'),record['evidence'].get('variant'),record['evidence'].get('logout')):
            if payload is not None and sanitize_transaction_data(payload)!=payload:
                raise ValueError('Unredacted security source')
    fd,temporary=tempfile.mkstemp(dir=directory,prefix='.tmp_security_',suffix='.json')
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(artifact,stream,indent=2,sort_keys=True,allow_nan=False)
            stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,directory/FILENAME)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return directory/FILENAME


def unavailable_security_section(reason='SECURITY_RESULTS_UNAVAILABLE'):
    return {'schema_version':'1.0','coverage':'unavailable','limitations':[reason],
            'result_count':0,'results':[],'evidence_index':{}}


def session_observation_complete(source, session_id, contexts):
    """A fully bound real replay may be reported even when its response is ambiguous.

    This checks the existing session inspector, not status codes or tool labels.
    It never turns an inconclusive observation into security assurance.
    """
    from src.dynamic.security.session_invalidation import SessionInvalidationEvidence, inspect_session_invalidation
    if not isinstance(source,dict) or source.get('session_id')!=session_id or not isinstance(source.get('records'),list) or len(source['records'])>128:
        return False
    canonical={c['endpoint_context_id']:c for c in contexts}
    for record in source['records']:
        try:
            request=DynamicTestRequest.from_dict(record['request'])
            if request.test_category!='session_handling' or request.session_id!=session_id:continue
            data=dict(record['evidence'])
            if data['context']!=canonical.get(request.endpoint_context_id):continue
            data['context']=EndpointContext(**data['context'])
            registry={ref:EvidenceReference(**value) for ref,value in record['registry'].items()}
            proof=inspect_session_invalidation(request,DynamicTestExecutionResult.from_dict(record['execution']),registry,SessionInvalidationEvidence(**data))
            if proof.outcome=='inconclusive' and proof.code=='INSUFFICIENT_RESPONSE_COMPARISON' and proof.refs:
                return True
        except (ValueError,TypeError,KeyError,AttributeError):
            continue
    return False


def build_security_section(source, session_id, contexts):
    """Recompute validated outcomes; recorded negative outcomes cannot be promoted."""
    if (not isinstance(source,dict) or source.get('schema_version')!='1.0'
            or source.get('session_id')!=session_id or not isinstance(source.get('records'),list)
            or len(source['records'])>128):
        return unavailable_security_section('SECURITY_SOURCE_INVALID')
    rows=[];index={};seen=set()
    canonical={c.get('endpoint_context_id'):c for c in contexts}
    try:
        for record in source['records']:
            request=DynamicTestRequest.from_dict(record['request'])
            if 'standards' in record:
                validate_standards_metadata(record['standards'],request.test_category)
            execution=DynamicTestExecutionResult.from_dict(record['execution'])
            recorded=DynamicValidationResult.from_dict(record['validation'])
            registry={ref:EvidenceReference(**value) for ref,value in record['registry'].items()}
            data=dict(record['evidence']);data['context']=EndpointContext(**data['context'])
            from src.dynamic.security.object_authorization import ObjectAuthorizationEvidence, validate_object_authorization
            from src.dynamic.security.function_authorization import FunctionAuthorizationEvidence
            from src.dynamic.security.session_invalidation import SessionInvalidationEvidence
            evidence=SessionInvalidationEvidence(**data) if request.test_category=='session_handling' else FunctionAuthorizationEvidence(**data) if request.test_category == 'function_authorization' else ObjectAuthorizationEvidence(**data) if request.test_category == 'object_authorization' else AuthPresenceEvidence(**data)
            if request.session_id!=session_id or evidence.context.to_dict()!=canonical.get(request.endpoint_context_id):
                raise ValueError('Cross-session/endpoint security record')
            validate = _validator(request.test_category)
            recomputed=validate(request,execution,registry,evidence,created_at=recorded.created_at)
            identity=(request.test_id,request.endpoint_context_id,request.session_id)
            if (recorded.test_id,recorded.endpoint_context_id,recorded.session_id)!=identity:
                raise ValueError('Recorded validation identity mismatch')
            # Preserve conservative recorded outcomes only after complete source
            # verification, never use a recorded success to override missing proof.
            result=recomputed
            if (recomputed.outcome=='validated' and recorded.outcome!='validated') or (recomputed.outcome=='rejected' and recorded.outcome in {'blocked','inconclusive'}):
                if not set(recomputed.evidence_refs).issubset(recorded.evidence_refs) or not recorded.reason_codes:
                    raise ValueError('Recorded negative result lacks bound evidence/reasons')
                result=recorded
            key=(request.endpoint_context_id,request.test_id,evidence.execution_ref)
            if key in seen: raise ValueError('Duplicate security result')
            seen.add(key)
            refs=list(result.evidence_refs)
            for ref in refs:
                owner=registry.get(ref)
                if not isinstance(owner,EvidenceReference) or owner.ref!=ref or owner.session_id!=session_id or owner.endpoint_context_id!=request.endpoint_context_id:
                    raise ValueError('Unbound report evidence')
                value=asdict(owner)
                if ref in index and index[ref]!=value: raise ValueError('Conflicting evidence owners')
                index[ref]=value
            def pair(payload):
                payload=payload or {};q=payload.get('request') or {};r=payload.get('response') or {}
                return {k:v if v in refs else None for k,v in {
                    'request':q.get('request_id'),'response':r.get('headers',{}).get('x-lab-trace-id')}.items()}
            limitations=[]
            if (evidence.variant or {}).get('attribution',{}).get('historical_baseline'):
                limitations.append('HISTORICAL_BASELINE')
            if result.outcome!='validated': limitations.append('OUTCOME_NOT_SECURITY_ASSURANCE')
            if execution.execution_status!='completed': limitations.append('EXECUTION_NOT_COMPLETED')
            rows.append({'test_id':request.test_id,'endpoint_context_id':request.endpoint_context_id,
                'test_category':request.test_category,'standards':standards_for_category(request.test_category),
                'execution_status':execution.execution_status,
                'validation_outcome':result.outcome,'reason_codes':list(result.reason_codes),
                'baseline_evidence_refs':pair(evidence.baseline),'variant_evidence_refs':pair(evidence.variant),
                'evidence_refs':refs,'execution_result_ref':evidence.execution_ref if evidence.execution_ref in refs else None,
                'session_id':request.session_id,'risk_class':request.risk_class,
                'timestamps':{'started_at':execution.started_at,'finished_at':execution.finished_at,'validated_at':result.created_at},
                'coverage':result.coverage,'limitations':sorted(limitations),'finding_created':False,
                **({'tested_relationship':_relationship(request.test_category),
                    'result_message':_message(request.test_category,result.reason_codes)} if request.test_category in {'object_authorization','function_authorization','session_handling'} else {}),
                **({'logout_evidence_refs':pair(evidence.logout)} if request.test_category=='session_handling' else {})})
    except (ValueError,TypeError,KeyError,AttributeError):
        return unavailable_security_section('SECURITY_SOURCE_INVALID')
    if not rows: return unavailable_security_section()
    rows.sort(key=lambda r:(r['endpoint_context_id'],r['test_id'],r['execution_result_ref'] or ''))
    coverage='available' if all(r['validation_outcome']=='validated' and r['coverage']=='available' for r in rows) else 'unavailable' if all(r['execution_status'] in {'blocked','unavailable'} for r in rows) else 'partial'
    return {'schema_version':'1.0','coverage':coverage,
        'limitations':[] if coverage=='available' else ['INCOMPLETE_SECURITY_VALIDATION'],
        'result_count':len(rows),'results':rows,'evidence_index':dict(sorted(index.items()))}


def validate_security_section(section, session_id, endpoints):
    """Strict public schema and reference closure, without raw payload exposure."""
    if not isinstance(section,dict) or set(section)!={'schema_version','coverage','limitations','result_count','results','evidence_index'} or section['schema_version']!='1.0' or section['coverage'] not in {'available','partial','unavailable'}:
        raise ValueError('Invalid security results section')
    if not isinstance(section['results'],list) or not isinstance(section['evidence_index'],dict) or not isinstance(section['result_count'],int) or isinstance(section['result_count'],bool) or section['result_count']!=len(section['results']):
        raise ValueError('Invalid security result counts')
    def limits(value):
        if not isinstance(value,list) or any(not isinstance(x,str) or x not in LIMITATIONS for x in value): raise ValueError('Invalid security limitation')
    limits(section['limitations'])
    index={ref:EvidenceReference(**entry) for ref,entry in section['evidence_index'].items()}
    for ref,owner in index.items():
        if ref!=owner.ref or owner.session_id!=session_id or owner.endpoint_context_id not in endpoints:
            raise ValueError('Invalid report evidence owner')
    seen=set()
    for row in section['results']:
        if not isinstance(row,dict):
            raise ValueError('Invalid security row')
        fields={'test_id','endpoint_context_id','test_category','execution_status','validation_outcome','reason_codes','baseline_evidence_refs','variant_evidence_refs','evidence_refs','execution_result_ref','session_id','risk_class','timestamps','coverage','limitations','finding_created'}
        object_fields = {'tested_relationship','result_message'} if row.get('test_category') in {'object_authorization','function_authorization','session_handling'} else set()
        if row.get('test_category')=='session_handling':object_fields=object_fields|{'logout_evidence_refs'}
        if not isinstance(row,dict) or set(row) not in (fields|object_fields, fields|object_fields|{'standards'}) or row['finding_created'] is not False or row['session_id']!=session_id or row['endpoint_context_id'] not in endpoints:
            raise ValueError('Invalid security row identity/boundary')
        _id(row['test_id'])
        if 'standards' in row:
            validate_standards_metadata(row['standards'],row['test_category'])
        if row['test_category'] not in ACTIONS or row['risk_class'] not in RISK_CLASSES or row['execution_status'] not in EXECUTION_STATUSES or row['validation_outcome'] not in OUTCOMES or row['coverage'] not in {'available','partial','unavailable','unknown'}:
            raise ValueError('Invalid security result vocabulary')
        codes=row['reason_codes']
        if not isinstance(codes,list) or not codes or any(not isinstance(code,str) or code not in VALIDATION_REASON_CODES for code in codes): raise ValueError('Missing/invalid security reason')
        refs=row['evidence_refs']
        if not isinstance(refs,list) or not refs or len(refs)>128 or len(set(refs))!=len(refs): raise ValueError('Missing security evidence')
        for ref in refs:
            if ref not in index or index[ref].endpoint_context_id!=row['endpoint_context_id']: raise ValueError('Unbound security evidence')
        for name in (('baseline_evidence_refs','variant_evidence_refs','logout_evidence_refs') if row['test_category']=='session_handling' else ('baseline_evidence_refs','variant_evidence_refs')):
            pair=row[name]
            if not isinstance(pair,dict) or set(pair)!={'request','response'}: raise ValueError('Invalid evidence pair')
            for kind,ref in pair.items():
                if ref is not None and (ref not in refs or index[ref].kind!=kind): raise ValueError('Invalid observation reference')
        times=row['timestamps']
        if not isinstance(times,dict) or set(times)!={'started_at','finished_at','validated_at'} or not _time(times['started_at'])<=_time(times['finished_at'])<=_time(times['validated_at']): raise ValueError('Invalid security timestamps')
        limits(row['limitations'])
        ref=row['execution_result_ref']
        if ref is not None and (ref not in refs or index[ref].kind!='tool'): raise ValueError('Missing execution reference')
        if object_fields:
            if row['tested_relationship'] != _relationship(row['test_category']) or row['result_message'] != _message(row['test_category'],codes):
                raise ValueError('Invalid controlled relationship metadata')
        conclusive_object_failure = (row['test_category'],codes) in [('object_authorization',['OBJECT_AUTHORIZATION_NOT_ENFORCED']),('function_authorization',['FUNCTION_AUTHORIZATION_NOT_ENFORCED']),('session_handling',['SESSION_INVALIDATION_NOT_ENFORCED'])]
        if conclusive_object_failure and row['validation_outcome']!='rejected':
            raise ValueError('Reason/outcome mismatch')
        if row['validation_outcome']=='validated' or conclusive_object_failure:
            required={row['endpoint_context_id'],session_id,ref,*row['baseline_evidence_refs'].values(),*row['variant_evidence_refs'].values()}
            if row['test_category']=='session_handling':required.update(row['logout_evidence_refs'].values())
            if None in required or not required.issubset(refs) or row['execution_status']!='completed' or row['coverage']!='available' or (row['test_category'],codes) not in [('authentication_presence',['AUTH_ENFORCEMENT_CONFIRMED']),('object_authorization',['OBJECT_AUTHORIZATION_ENFORCED']),('object_authorization',['OBJECT_AUTHORIZATION_NOT_ENFORCED']),('function_authorization',['FUNCTION_AUTHORIZATION_ENFORCED']),('function_authorization',['FUNCTION_AUTHORIZATION_NOT_ENFORCED']),('session_handling',['SESSION_INVALIDATION_NOT_ENFORCED']),('session_handling',['SESSION_INVALIDATION_ENFORCED'])] or row['risk_class']!='low': raise ValueError('Unbacked conclusive report result')
            if index[row['endpoint_context_id']].kind!='context' or index[session_id].kind!='runtime' or row['baseline_evidence_refs']['request']==row['variant_evidence_refs']['request'] or row['baseline_evidence_refs']['response']==row['variant_evidence_refs']['response']:
                raise ValueError('Invalid baseline/variant binding')
            if not {'control','comparison'}.issubset({index[x].kind for x in refs}): raise ValueError('Missing comparison evidence')
            if row['test_category']=='session_handling' and any(len({row[name][kind] for name in ('baseline_evidence_refs','logout_evidence_refs','variant_evidence_refs')})!=3 for kind in ('request','response')):
                raise ValueError('Invalid logout binding')
        elif 'AUTH_ENFORCEMENT_CONFIRMED' in codes or 'OBJECT_AUTHORIZATION_ENFORCED' in codes or 'FUNCTION_AUTHORIZATION_ENFORCED' in codes or 'SESSION_INVALIDATION_ENFORCED' in codes: raise ValueError('Reason/outcome mismatch')
        key=(row['endpoint_context_id'],row['test_id'],ref)
        if key in seen: raise ValueError('Duplicate report result')
        seen.add(key)
    if section['coverage']=='available' and (not section['results'] or any(r['validation_outcome']!='validated' or r['coverage']!='available' for r in section['results'])):
        raise ValueError('Security coverage overclaimed')
