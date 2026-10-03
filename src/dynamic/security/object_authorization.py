"""One resource substitution in a bound, controlled two-principal local lab.

No enumeration, generic replay, public-target transport or findings. Offline
validation recomputes identity/ownership/response proof from sanitized sources.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
from http.client import HTTPConnection
from http.server import HTTPServer
import ipaddress
import json
import threading
import uuid

from src.dynamic.security.validation import AuthPresenceEvidence, EvidenceInspection
from src.dynamic.security.contracts import (DynamicTestExecutionResult, DynamicValidationResult,
    EvidenceReference, _time, validate_execution, validate_result)
from src.dynamic.runtime.models import utc_now_iso
from src.dynamic.traffic.normalizer import normalize_http_transaction, sanitize_transaction_data


@dataclass(frozen=True)
class ObjectAuthorizationEvidence(AuthPresenceEvidence):
    ownership: dict


def resource_variant(baseline):
    q = deepcopy(baseline['request'])
    if (q.get('method'), q.get('scheme'), q.get('path')) != ('GET', 'http', '/orders/1001') or q.get('query') or q.get('body') is not None:
        raise ValueError('Only the fixed read-only resource pair is supported')
    q['path'] = '/orders/2002'
    if q.get('url'):
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(q['url'])
        if parts.path != '/orders/1001' or parts.query or parts.fragment:
            raise ValueError('Ambiguous request URL')
        q['url'] = urlunsplit(parts._replace(path='/orders/2002'))
    return q


def inspect_object_authorization(request, execution, registry, evidence):
    def fail(code, blocked=True): return EvidenceInspection(code, 'blocked' if blocked else 'inconclusive')
    if not isinstance(evidence, ObjectAuthorizationEvidence) or not evidence.baseline:
        return fail('MISSING_BASELINE_EVIDENCE')
    try:
        context, ownership = evidence.context, evidence.ownership
        if request.test_category != 'object_authorization' or request.requested_action != 'validate_object_access_behavior' or request.risk_class != 'low':
            return fail('ACTION_MISMATCH')
        if context.endpoint_context_id != request.endpoint_context_id or execution.endpoint_context_id != request.endpoint_context_id or execution.test_id != request.test_id:
            return fail('CROSS_ENDPOINT_EVIDENCE')
        if not request.session_id or evidence.session.get('session_id') != request.session_id or execution.session_id != request.session_id:
            return fail('CROSS_SESSION_EVIDENCE')
        if (not isinstance(ownership, dict) or set(ownership) != {'evidence_ref','session_id','source','host','port','principals','resources'}
            or ownership.get('source') != 'controlled_local_lab_configuration'
            or ownership.get('principals') != ['user_A','user_B']
            or ownership.get('resources') != {'1001':'user_A','2002':'user_B'}):
            return fail('MISSING_OWNERSHIP_EVIDENCE', False)
        if ownership['session_id'] != request.session_id:
            return fail('CROSS_SESSION_EVIDENCE')
        if ownership['evidence_ref'] != 'ownership_' + hashlib.sha256(request.session_id.encode()).hexdigest()[:20]:
            return fail('REFERENCE_MISMATCH')
        if not ipaddress.ip_address(context.host).is_loopback or (context.scheme,context.path,context.methods) != ('http','/orders/1001',['GET']) or (ownership['host'],ownership['port']) != (context.host,context.port):
            return fail('CROSS_ENDPOINT_EVIDENCE')
        baseline, variant = evidence.baseline, evidence.variant
        if not variant: return fail('MISSING_VARIANT_EVIDENCE', False)
        if execution.execution_status != 'completed': return fail('EXECUTION_NOT_COMPLETED', False)
        for payload in (baseline, variant):
            if payload.get('session_id') != request.session_id: return fail('CROSS_SESSION_EVIDENCE')
            if not isinstance(payload.get('response'),dict): return fail('MISSING_VARIANT_EVIDENCE', False)
            if any(x.get('synthetic') or x.get('internal') for x in (payload,payload['request'],payload['response'])):
                return fail('SYNTHETIC_RESPONSE')
            observation = payload.get('correlation',{}).get('response_observation',{})
            if observation and observation.get('state') != 'available': return fail('SYNTHETIC_RESPONSE')
            if sanitize_transaction_data(payload) != payload: return fail('UNREDACTED_EVIDENCE')
        bq,br,vq,vr = baseline['request'],baseline['response'],variant['request'],variant['response']
        brr,vrr = br['headers'].get('x-lab-trace-id'),vr['headers'].get('x-lab-trace-id')
        roles = [(bq.get('request_id'),'request'),(brr,'response'),(vq.get('request_id'),'request'),(vrr,'response'),
                 (context.endpoint_context_id,'context'),(request.session_id,'runtime'),
                 (ownership['evidence_ref'],'control'),(evidence.execution_ref,'tool'),
                 (evidence.control_ref,'control'),(evidence.comparison_ref,'comparison')]
        for ref,kind in roles:
            entry = registry.get(ref)
            if not isinstance(entry,EvidenceReference) or entry.ref != ref: return fail('MISSING_REQUIRED_EVIDENCE',False)
            if entry.session_id != request.session_id: return fail('CROSS_SESSION_EVIDENCE')
            if entry.endpoint_context_id != request.endpoint_context_id: return fail('CROSS_ENDPOINT_EVIDENCE')
            if entry.kind != kind or ref not in execution.evidence_refs: return fail('REFERENCE_MISMATCH')
        needed = {bq['request_id'],brr,context.endpoint_context_id,request.session_id,ownership['evidence_ref']}
        if not needed.issubset(request.required_evidence_refs): return fail('MISSING_BASELINE_EVIDENCE')
        if (execution.observed_request_ref,execution.observed_response_ref) != (vq['request_id'],vrr) or evidence.execution_ref not in execution.tool_refs:
            return fail('REFERENCE_MISMATCH')
        if bq['request_id'] == vq['request_id'] or brr == vrr: return fail('REFERENCE_MISMATCH')
        digest=hashlib.sha256(json.dumps([request.test_id,request.endpoint_context_id,request.session_id,bq['request_id']]).encode()).hexdigest()[:20]
        if (evidence.execution_ref,evidence.control_ref,evidence.comparison_ref) != ('execution_'+digest,'control_'+digest,'comparison_'+digest): return fail('REFERENCE_MISMATCH')
        if baseline['transaction_id'] not in context.evidence_refs.get('transaction_ids',[]) or not context.dynamic.get('observed') or not context.auth.get('authorization_header_present'):
            return fail('MISSING_BASELINE_EVIDENCE')
        if variant.get('attribution',{}).get('baseline_transaction_ref') != baseline['transaction_id']: return fail('REFERENCE_MISMATCH')
        expected=resource_variant(baseline)
        transient={'request_id','timestamp'}
        if {k:v for k,v in expected.items() if k not in transient} != {k:v for k,v in vq.items() if k not in transient}: return fail('UNEXPECTED_REQUEST_MUTATION')
        if (bq['scheme'],bq['host'],bq['port'],bq['path'],bq['method']) != (context.scheme,context.host,context.port,context.path,'GET'): return fail('CROSS_ENDPOINT_EVIDENCE')
        if bq.get('headers',{}).get('authorization') != '[REDACTED]' or vq.get('headers',{}).get('authorization') != '[REDACTED]': return fail('MISSING_BASELINE_EVIDENCE')
        if not (_time(br['timestamp']) <= _time(execution.started_at) <= _time(vq['timestamp']) <= _time(vr['timestamp']) <= _time(execution.finished_at)): return fail('REFERENCE_MISMATCH')
        verified=[]
        for tx,receipts,resource in [(baseline,evidence.baseline_receipts,'1001'),(variant,evidence.variant_receipts,'2002')]:
            q,r=tx['request'],tx['response']
            if q['headers'].get('x-lab-run-id') != request.session_id: return fail('CROSS_SESSION_EVIDENCE')
            if not isinstance(r.get('body'),dict) or r.get('headers',{}).get('content-type','').split(';')[0] != 'application/json': return fail('INSUFFICIENT_RESPONSE_COMPARISON',False)
            meta=r.get('body_metadata',{})
            if not isinstance(meta.get('size'),int) or meta['size'] <= 0 or meta.get('truncated') is not False or meta.get('binary') is not False: return fail('INSUFFICIENT_RESPONSE_COMPARISON',False)
            selected=[x for x in receipts if x.get('trace_id') == r['headers'].get('x-lab-trace-id')]
            if len(selected)!=1: return fail('MISSING_REQUIRED_EVIDENCE',False)
            receipt=selected[0]
            if receipt.get('synthetic') or receipt.get('internal'): return fail('SYNTHETIC_RESPONSE')
            if receipt.get('run_id') != request.session_id: return fail('CROSS_SESSION_EVIDENCE')
            if (receipt.get('source'),receipt.get('method'),receipt.get('path'),receipt.get('status'),receipt.get('principal_alias'),receipt.get('resource_id'),receipt.get('owner_alias')) != ('local_training_backend_actual_response','GET',q['path'],r['status_code'],'user_A',resource,ownership['resources'][resource]): return fail('REFERENCE_MISMATCH')
            if receipt.get('auth_valid') is not True or receipt.get('auth_present') is not True or not receipt.get('credential_ref'): return fail('MISSING_BASELINE_EVIDENCE')
            if receipt.get('response_sha256') != hashlib.sha256(json.dumps(r['body'],sort_keys=True).encode()).hexdigest(): return fail('INSUFFICIENT_RESPONSE_COMPARISON',False)
            if receipt.get('response_resource_id') != r['body'].get('resource_id') or receipt.get('response_owner_alias') != r['body'].get('owner_alias'): return fail('REFERENCE_MISMATCH')
            verified.append(receipt)
        if verified[0]['credential_ref'] != verified[1]['credential_ref']: return fail('UNEXPECTED_REQUEST_MUTATION')
        validate_execution(request,execution,registry)
        if br['status_code'] != 200 or br['body'] != {'resource_id':'1001','owner_alias':'user_A','purpose':'protected_training_order'}: return fail('MISSING_BASELINE_EVIDENCE')
        refs=frozenset(ref for ref,_ in roles)
        if vr['status_code'] == 403 and vr['body'] == {'error':'object_access_denied','resource_id':'2002'}:
            return EvidenceInspection('OBJECT_AUTHORIZATION_ENFORCED','validated',refs)
        if vr['status_code'] == 200 and vr['body'] == {'resource_id':'2002','owner_alias':'user_B','purpose':'protected_training_order'}:
            return EvidenceInspection('OBJECT_AUTHORIZATION_NOT_ENFORCED','rejected',refs)
        return fail('INSUFFICIENT_RESPONSE_COMPARISON',False)
    except (ValueError,KeyError,TypeError,AttributeError): return fail('INVALID_EVIDENCE')


def validate_object_authorization(request,execution,registry,evidence,*,created_at=None):
    inspection=inspect_object_authorization(request,execution,registry,evidence)
    refs=tuple(sorted(ref for ref in execution.evidence_refs+request.required_evidence_refs
        if isinstance(registry.get(ref),EvidenceReference) and registry[ref].session_id==request.session_id
        and registry[ref].endpoint_context_id==request.endpoint_context_id and registry[ref].ref==ref))
    if not refs: raise ValueError(inspection.code)
    timestamp=created_at or utc_now_iso()
    if _time(timestamp)<_time(execution.finished_at): timestamp=execution.finished_at
    result=DynamicValidationResult(request.test_id,request.endpoint_context_id,inspection.outcome,refs,
        {'validated':'controlled_behavior_check','rejected':'criteria_not_met','blocked':'policy_or_execution_blocked','inconclusive':'insufficient_evidence'}[inspection.outcome],
        'available' if inspection.outcome in {'validated','rejected'} else 'partial',timestamp,request.session_id,(inspection.code,))
    if result.outcome in {'validated','rejected'}: validate_result(request,execution,result,registry,object_evidence=evidence)
    return result


class LocalLabObjectAuthorization:
    def __init__(self,*,server,baseline,raw_baseline,context,session,ownership):
        from scripts.labs.auth_baseline_lab import TrainingObjectLab
        if not isinstance(server,HTTPServer) or type(getattr(server,'training_lab',None)) is not TrainingObjectLab:
            raise ValueError('Explicit controlled object lab required')
        host,port=server.server_address[:2]
        if not ipaddress.ip_address(host).is_loopback: raise ValueError('Loopback lab required')
        self.server,self.lab=server,server.training_lab
        self.host,self.port=host,port
        self.baseline=deepcopy(baseline);self.raw_baseline=deepcopy(raw_baseline)
        self.context=deepcopy(context);self.session=deepcopy(session);self.ownership=deepcopy(ownership)
        self.used=False;self.transaction=None;self.evidence={};self.bundle=None
        self._dispatch_lock=threading.Lock()

    def eligible(self,request,context,registry):
        try:
            q=self.baseline['request'];r=self.baseline['response']
            if (self.host,self.port) != self.server.server_address[:2] or not ipaddress.ip_address(self.host).is_loopback or self.server.training_lab is not self.lab:return False
            if self.ownership.get('resources') != {'1001':'user_A','2002':'user_B'} or self.ownership.get('principals') != ['user_A','user_B']:return False
            if any(x.get('synthetic') or x.get('internal') for x in (self.baseline,q,r)):return False
            if sanitize_transaction_data(self.baseline)!=self.baseline:return False
            if self.used or request.risk_class!='low' or request.requested_action!='validate_object_access_behavior':return False
            if (context.endpoint_context_id,context.host,context.port,context.scheme,context.path,context.methods)!=(self.context.endpoint_context_id,self.host,self.port,'http','/orders/1001',['GET']): return False
            if context.to_dict()!=self.context.to_dict() or request.session_id!=self.session['session_id'] or self.lab.run_id!=request.session_id:return False
            if self.ownership!=self.lab.ownership(self.host,self.port):return False
            identity=self.lab.principal(self.raw_baseline['request']['headers'].get('authorization'))
            if identity[0]!='user_A':return False
            normalized=normalize_http_transaction(self.raw_baseline['request'],self.raw_baseline['response'],'baseline_check',request.session_id).to_dict()
            # Identity/time are observational; all request/response metadata must agree.
            for kind in ['request','response']:
                skip={'request_id'} if kind=='request' else set()
                if {k:v for k,v in sanitize_transaction_data(normalized)[kind].items() if k not in skip}!={k:v for k,v in self.baseline[kind].items() if k not in skip}:return False
            if not context.dynamic.get('observed') or not context.auth.get('authorization_header_present') or self.baseline['transaction_id'] not in context.evidence_refs.get('transaction_ids',[]):return False
            if r['status_code']!=200 or r['body']!={'resource_id':'1001','owner_alias':'user_A','purpose':'protected_training_order'}:return False
            receipt=[x for x in self.lab.receipts if x['trace_id']==r['headers']['x-lab-trace-id']]
            if len(receipt)!=1 or receipt[0].get('principal_alias')!='user_A' or receipt[0].get('credential_ref')!=identity[1] or receipt[0].get('status')!=200 or receipt[0].get('auth_valid') is not True or receipt[0].get('path')!='/orders/1001' or receipt[0].get('source')!='local_training_backend_actual_response' or receipt[0].get('owner_alias')!='user_A' or receipt[0].get('response_sha256')!=hashlib.sha256(json.dumps(r['body'],sort_keys=True).encode()).hexdigest():return False
            if (receipt[0].get('synthetic') or receipt[0].get('internal')
                    or receipt[0].get('run_id')!=request.session_id
                    or receipt[0].get('auth_present') is not True
                    or receipt[0].get('method')!='GET'
                    or receipt[0].get('resource_id')!='1001'):return False
            observation=self.baseline.get('correlation',{}).get('response_observation',{})
            if observation and observation.get('state')!='available':return False
            if self.baseline.get('session_id')!=request.session_id:return False
            required={q['request_id']:'request',r['headers']['x-lab-trace-id']:'response',context.endpoint_context_id:'context',request.session_id:'runtime',self.ownership['evidence_ref']:'control'}
            if not set(required).issubset(request.required_evidence_refs):return False
            for ref,kind in required.items():
                if registry.get(ref)!=EvidenceReference(ref,context.endpoint_context_id,kind,request.session_id):return False
            resource_variant(self.raw_baseline)
            return True
        except (ValueError,KeyError,TypeError,AttributeError):return False

    def run(self,request,context,registry,started,clock=utc_now_iso):
        with self._dispatch_lock:
            if not self.eligible(request,context,registry):raise ValueError('Controlled lab prerequisites missing')
            raw=resource_variant(self.raw_baseline)
            self.used=True
        connection=HTTPConnection(self.host,self.port,timeout=3)
        try:
            connection.putrequest('GET',raw['path'],skip_host=True,skip_accept_encoding=True)
            for key,value in raw['headers'].items():connection.putheader(key,value)
            connection.endheaders();response=connection.getresponse();body=response.read(4097)
            if len(body)>4096:raise ValueError('Bounded response exceeded')
            returned={'status_code':response.status,'headers':dict(response.getheaders()),'body':body,'timestamp':clock()}
        finally:connection.close()
        raw['timestamp']=started
        tx=normalize_http_transaction(raw,returned,'capture_'+uuid.uuid4().hex,request.session_id)
        tx.attribution={'method':'deterministic_local_executor','baseline_transaction_ref':self.baseline['transaction_id']}
        self.transaction=sanitize_transaction_data(tx.to_dict())
        digest=hashlib.sha256(json.dumps([request.test_id,context.endpoint_context_id,request.session_id,self.baseline['request']['request_id']]).encode()).hexdigest()[:20]
        execution_ref,control_ref,comparison_ref='execution_'+digest,'control_'+digest,'comparison_'+digest
        self.evidence=dict(registry)
        for ref,kind in [(self.transaction['request']['request_id'],'request'),(self.transaction['response']['headers']['x-lab-trace-id'],'response'),(execution_ref,'tool'),(control_ref,'control'),(comparison_ref,'comparison')]:
            if ref in self.evidence:raise ValueError('Evidence collision')
            self.evidence[ref]=EvidenceReference(ref,context.endpoint_context_id,kind,request.session_id)
        refs=tuple(self.evidence)
        result=DynamicTestExecutionResult(request.test_id,context.endpoint_context_id,'completed',self.transaction['request']['request_id'],self.transaction['response']['headers']['x-lab-trace-id'],refs,(execution_ref,),started,clock(),None,request.session_id)
        validate_execution(request,result,self.evidence)
        self.bundle=ObjectAuthorizationEvidence(context,self.session,self.baseline,self.transaction,deepcopy(self.lab.receipts),deepcopy(self.lab.receipts),execution_ref,control_ref,comparison_ref,self.ownership)
        return result

    def validate(self,request,execution):
        return validate_object_authorization(request,execution,self.evidence,self.bundle)
