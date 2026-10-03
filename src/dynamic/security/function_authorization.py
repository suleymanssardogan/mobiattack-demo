"""Fixed local role substitution; offline proof of a disposable privileged effect.

Uses the existing deterministic executor/contracts. No endpoint discovery,
role spraying, public transport, raw-secret persistence, or findings.
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

FUNCTION = {'method':'POST','path':'/lab/admin/toggle','required_role':'admin',
            'disposable':True,'body':{'enabled':True}}


@dataclass(frozen=True)
class FunctionAuthorizationEvidence(AuthPresenceEvidence):
    privileges: dict


class ProofError(ValueError):
    pass


def _require(condition, code):
    if not condition: raise ProofError(code)


def _privileges(data, context, session):
    _require(isinstance(data,dict) and set(data)=={'evidence_ref','session_id','source','host','port','principals','function'},'MISSING_PRIVILEGE_EVIDENCE')
    _require(data['session_id']==session,'CROSS_SESSION_EVIDENCE')
    _require(data['source']=='controlled_local_lab_configuration' and data['function']==FUNCTION,'MISSING_PRIVILEGE_EVIDENCE')
    _require(data['evidence_ref']=='privilege_'+hashlib.sha256(session.encode()).hexdigest()[:20],'REFERENCE_MISMATCH')
    _require(ipaddress.ip_address(context.host).is_loopback and (context.host,context.port)==(data['host'],data['port'])
             and (context.scheme,context.path,context.methods)==('http',FUNCTION['path'],['POST']),'CROSS_ENDPOINT_EVIDENCE')
    identities=data['principals']
    _require(set(identities)=={'user_A','user_B'},'MISSING_PRIVILEGE_EVIDENCE')
    for alias,role in [('user_A','user'),('user_B','admin')]:
        item=identities[alias]
        _require(set(item)=={'role','credential_ref'} and item['role']==role and isinstance(item['credential_ref'],str)
                 and item['credential_ref'].startswith('principal_session_'),'MISSING_PRIVILEGE_EVIDENCE')
    _require(identities['user_A']['credential_ref']!=identities['user_B']['credential_ref'],'MISSING_PRIVILEGE_EVIDENCE')


def _receipt(payload, receipts, privileges, alias, context, session):
    _require(isinstance(payload,dict) and isinstance(payload.get('request'),dict) and isinstance(payload.get('response'),dict),'MISSING_BASELINE_EVIDENCE' if alias=='user_B' else 'MISSING_VARIANT_EVIDENCE')
    q,r=payload['request'],payload['response']
    _require(payload.get('session_id')==session,'CROSS_SESSION_EVIDENCE')
    _require(not any(part.get('synthetic') or part.get('internal') for part in (payload,q,r)),'SYNTHETIC_RESPONSE')
    observation=payload.get('correlation',{}).get('response_observation',{})
    _require(not observation or observation.get('state')=='available','SYNTHETIC_RESPONSE')
    _require(sanitize_transaction_data(payload)==payload,'UNREDACTED_EVIDENCE')
    _require((q['scheme'],q['host'],q['port'],q['method'],q['path'])==('http',context.host,context.port,'POST',FUNCTION['path']) and not q.get('query') and q.get('body')==FUNCTION['body'],'UNEXPECTED_REQUEST_MUTATION')
    _require(q['headers'].get('authorization')=='[REDACTED]' and q['headers'].get('x-lab-run-id')==session,'MISSING_BASELINE_EVIDENCE')
    _require(isinstance(r.get('body'),dict) and r['headers'].get('content-type','').split(';')[0]=='application/json','INSUFFICIENT_RESPONSE_COMPARISON')
    meta=r.get('body_metadata',{})
    _require(isinstance(meta.get('size'),int) and meta['size']>0 and meta.get('truncated') is False and meta.get('binary') is False,'INSUFFICIENT_RESPONSE_COMPARISON')
    trace=r['headers'].get('x-lab-trace-id')
    selected=[x for x in receipts if x.get('trace_id')==trace]
    _require(len(selected)==1,'MISSING_REQUIRED_EVIDENCE')
    receipt=selected[0]
    _require(not receipt.get('synthetic') and not receipt.get('internal'),'SYNTHETIC_RESPONSE')
    _require(receipt.get('run_id')==session,'CROSS_SESSION_EVIDENCE')
    identity=privileges['principals'][alias]
    _require((receipt.get('source'),receipt.get('method'),receipt.get('path'),receipt.get('status'))==('local_training_backend_actual_response','POST',q['path'],r['status_code']),'REFERENCE_MISMATCH')
    _require((receipt.get('principal_alias'),receipt.get('role'),receipt.get('credential_ref'))==(alias,identity['role'],identity['credential_ref']) and receipt.get('auth_valid') is True and receipt.get('auth_present') is True,'UNEXPECTED_REQUEST_MUTATION')
    _require(receipt.get('response_sha256')==hashlib.sha256(json.dumps(r['body'],sort_keys=True).encode()).hexdigest(),'INSUFFICIENT_RESPONSE_COMPARISON')
    for name in ['state_before','state_after']:
        state=receipt.get(name)
        _require(isinstance(state,dict) and set(state)=={'evidence_ref','session_id','trace_id','enabled','revision'},'MISSING_STATE_EVIDENCE')
        _require(state['session_id']==session,'CROSS_SESSION_EVIDENCE')
        _require(state['trace_id']==trace and state['evidence_ref']=='state_'+trace+('_before' if name=='state_before' else '_after'),'REFERENCE_MISMATCH')
        _require(isinstance(state['enabled'],bool) and type(state['revision']) is int and state['revision']>=0,'MISSING_STATE_EVIDENCE')
    return receipt


def _state(receipt,name):
    return {key:receipt[name][key] for key in ['enabled','revision']}


def _baseline(payload, receipt, context):
    _require(context.dynamic.get('observed') and context.auth.get('authorization_header_present')
             and payload['transaction_id'] in context.evidence_refs.get('transaction_ids',[]),'MISSING_BASELINE_EVIDENCE')
    _require(_state(receipt,'state_before')=={'enabled':False,'revision':0}
             and _state(receipt,'state_after')=={'enabled':True,'revision':1}
             and payload['response']['status_code']==200
             and payload['response']['body']=={'function':'training_toggle','applied':True,'enabled':True,'revision':1},'MISSING_BASELINE_EVIDENCE')


def inspect_function_authorization(request,execution,registry,evidence):
    def fail(code):
        return EvidenceInspection(code,'inconclusive' if code in {'MISSING_VARIANT_EVIDENCE','MISSING_PRIVILEGE_EVIDENCE','MISSING_STATE_EVIDENCE','INSUFFICIENT_RESPONSE_COMPARISON','MISSING_REQUIRED_EVIDENCE','EXECUTION_NOT_COMPLETED'} else 'blocked')
    if not isinstance(evidence,FunctionAuthorizationEvidence) or not evidence.baseline: return fail('MISSING_BASELINE_EVIDENCE')
    try:
        c=evidence.context;s=request.session_id
        _require(request.test_category=='function_authorization' and request.requested_action=='validate_function_access_behavior' and request.risk_class=='low','ACTION_MISMATCH')
        _require((execution.test_id,execution.endpoint_context_id,c.endpoint_context_id)==(request.test_id,request.endpoint_context_id,request.endpoint_context_id),'CROSS_ENDPOINT_EVIDENCE')
        _require(s and execution.session_id==s and evidence.session.get('session_id')==s,'CROSS_SESSION_EVIDENCE')
        _privileges(evidence.privileges,c,s)
        baseline=_receipt(evidence.baseline,evidence.baseline_receipts,evidence.privileges,'user_B',c,s)
        _baseline(evidence.baseline,baseline,c)
        _require(execution.execution_status=='completed','EXECUTION_NOT_COMPLETED')
        variant=_receipt(evidence.variant,evidence.variant_receipts,evidence.privileges,'user_A',c,s)
        bq,br=evidence.baseline['request'],evidence.baseline['response'];vq,vr=evidence.variant['request'],evidence.variant['response']
        # Redacted auth values are equal; server identity receipts independently
        # prove that the sole changed secret was B's credential replaced by A's.
        transient={'request_id','timestamp'}
        _require({k:v for k,v in bq.items() if k not in transient}=={k:v for k,v in vq.items() if k not in transient},'UNEXPECTED_REQUEST_MUTATION')
        _require(evidence.variant.get('attribution',{}).get('baseline_transaction_ref')==evidence.baseline['transaction_id'],'REFERENCE_MISMATCH')
        brr=br['headers']['x-lab-trace-id'];vrr=vr['headers']['x-lab-trace-id']
        _require(bq['request_id']!=vq['request_id'] and brr!=vrr,'REFERENCE_MISMATCH')
        digest=hashlib.sha256(json.dumps([request.test_id,c.endpoint_context_id,s,bq['request_id']]).encode()).hexdigest()[:20]
        _require((evidence.execution_ref,evidence.control_ref,evidence.comparison_ref)==('execution_'+digest,'control_'+digest,'comparison_'+digest),'REFERENCE_MISMATCH')
        roles=[(bq['request_id'],'request'),(brr,'response'),(vq['request_id'],'request'),(vrr,'response'),(c.endpoint_context_id,'context'),(s,'runtime'),(evidence.privileges['evidence_ref'],'control'),(evidence.execution_ref,'tool'),(evidence.control_ref,'control'),(evidence.comparison_ref,'comparison')]
        roles += [(r[name]['evidence_ref'],'control') for r in [baseline,variant] for name in ['state_before','state_after']]
        for ref,kind in roles:
            owner=registry.get(ref)
            _require(isinstance(owner,EvidenceReference) and owner.ref==ref,'MISSING_REQUIRED_EVIDENCE')
            _require(owner.session_id==s,'CROSS_SESSION_EVIDENCE')
            _require(owner.endpoint_context_id==c.endpoint_context_id,'CROSS_ENDPOINT_EVIDENCE')
            _require(owner.kind==kind and ref in execution.evidence_refs,'REFERENCE_MISMATCH')
        required={bq['request_id'],brr,c.endpoint_context_id,s,evidence.privileges['evidence_ref'],baseline['state_before']['evidence_ref'],baseline['state_after']['evidence_ref']}
        _require(required.issubset(request.required_evidence_refs),'MISSING_BASELINE_EVIDENCE')
        _require((execution.observed_request_ref,execution.observed_response_ref)==(vq['request_id'],vrr) and evidence.execution_ref in execution.tool_refs,'REFERENCE_MISMATCH')
        _require(_time(br['timestamp'])<=_time(execution.started_at)<=_time(vq['timestamp'])<=_time(vr['timestamp'])<=_time(execution.finished_at),'REFERENCE_MISMATCH')
        _require(_state(variant,'state_before')==_state(baseline,'state_after'),'MISSING_STATE_EVIDENCE')
        validate_execution(request,execution,registry)
        refs=frozenset(ref for ref,_ in roles)
        if vr['status_code']==403 and vr['body']=={'error':'function_access_denied','function':'training_toggle'} and _state(variant,'state_after')==_state(variant,'state_before'):
            return EvidenceInspection('FUNCTION_AUTHORIZATION_ENFORCED','validated',refs)
        after=_state(variant,'state_after')
        if vr['status_code']==200 and after=={'enabled':True,'revision':2} and vr['body']=={'function':'training_toggle','applied':True,**after}:
            return EvidenceInspection('FUNCTION_AUTHORIZATION_NOT_ENFORCED','rejected',refs)
        return fail('INSUFFICIENT_RESPONSE_COMPARISON')
    except ProofError as exc:return fail(str(exc))
    except (ValueError,TypeError,KeyError,AttributeError):return fail('INVALID_EVIDENCE')


def validate_function_authorization(request,execution,registry,evidence,*,created_at=None):
    proof=inspect_function_authorization(request,execution,registry,evidence)
    refs=tuple(sorted(ref for ref in execution.evidence_refs+request.required_evidence_refs if isinstance(registry.get(ref),EvidenceReference) and registry[ref]==EvidenceReference(ref,request.endpoint_context_id,registry[ref].kind,request.session_id)))
    if not refs:raise ValueError(proof.code)
    timestamp=created_at or utc_now_iso()
    if _time(timestamp)<_time(execution.finished_at):
        if created_at is not None:raise ValueError('Validation predates execution')
        timestamp=execution.finished_at
    result=DynamicValidationResult(request.test_id,request.endpoint_context_id,proof.outcome,refs,
        {'validated':'controlled_behavior_check','rejected':'criteria_not_met','blocked':'policy_or_execution_blocked','inconclusive':'insufficient_evidence'}[proof.outcome],
        'available' if proof.outcome in {'validated','rejected'} else 'partial',timestamp,request.session_id,(proof.code,))
    if result.outcome in {'validated','rejected'}:validate_result(request,execution,result,registry,function_evidence=evidence)
    return result


class LocalLabFunctionAuthorization:
    def __init__(self,*,server,baseline,raw_baseline,normal_authorization,context,session,privileges):
        from scripts.labs.auth_baseline_lab import TrainingFunctionLab
        if not isinstance(server,HTTPServer) or type(getattr(server,'training_lab',None)) is not TrainingFunctionLab or not ipaddress.ip_address(server.server_address[0]).is_loopback:
            raise ValueError('Explicit loopback function training lab required')
        self.server,self.lab=server,server.training_lab;self.host,self.port=server.server_address[:2]
        self.baseline,self.raw_baseline=deepcopy(baseline),deepcopy(raw_baseline)
        self.normal_authorization=normal_authorization # memory only
        self.context,self.session,self.privileges=deepcopy(context),deepcopy(session),deepcopy(privileges)
        self.used=False;self.transaction=None;self.evidence={};self.bundle=None;self._lock=threading.Lock()

    def eligible(self,request,context,registry):
        try:
            _require(not self.used and request.test_category=='function_authorization' and request.requested_action=='validate_function_access_behavior' and request.risk_class=='low','ACTION_MISMATCH')
            _require(self.server.training_lab is self.lab and self.server.server_address[:2]==(self.host,self.port) and ipaddress.ip_address(self.host).is_loopback,'CROSS_ENDPOINT_EVIDENCE')
            _require(context.to_dict()==self.context.to_dict() and request.endpoint_context_id==context.endpoint_context_id,'CROSS_ENDPOINT_EVIDENCE')
            _require(request.session_id==self.session['session_id']==self.lab.run_id,'CROSS_SESSION_EVIDENCE')
            _privileges(self.privileges,context,request.session_id)
            _require(self.privileges==self.lab.privileges(self.host,self.port),'MISSING_PRIVILEGE_EVIDENCE')
            _require(self.lab.principal(self.normal_authorization)==('user_A',self.privileges['principals']['user_A']['credential_ref']),'MISSING_PRIVILEGE_EVIDENCE')
            _require(self.lab.principal(self.raw_baseline['request']['headers']['authorization'])==('user_B',self.privileges['principals']['user_B']['credential_ref']),'MISSING_BASELINE_EVIDENCE')
            normalized=sanitize_transaction_data(normalize_http_transaction(self.raw_baseline['request'],self.raw_baseline['response'],'baseline_check',request.session_id).to_dict())
            for kind in ['request','response']:
                skip={'request_id'} if kind=='request' else set()
                _require({k:v for k,v in normalized[kind].items() if k not in skip}=={k:v for k,v in self.baseline[kind].items() if k not in skip},'MISSING_BASELINE_EVIDENCE')
            receipt=_receipt(self.baseline,self.lab.receipts,self.privileges,'user_B',context,request.session_id)
            _baseline(self.baseline,receipt,context)
            _require(self.lab.state==_state(receipt,'state_after'),'MISSING_STATE_EVIDENCE')
            refs={self.baseline['request']['request_id']:'request',self.baseline['response']['headers']['x-lab-trace-id']:'response',context.endpoint_context_id:'context',request.session_id:'runtime',self.privileges['evidence_ref']:'control',receipt['state_before']['evidence_ref']:'control',receipt['state_after']['evidence_ref']:'control'}
            _require(set(refs).issubset(request.required_evidence_refs),'MISSING_REQUIRED_EVIDENCE')
            for ref,kind in refs.items():_require(registry.get(ref)==EvidenceReference(ref,context.endpoint_context_id,kind,request.session_id),'MISSING_REQUIRED_EVIDENCE')
            return True
        except (ValueError,TypeError,KeyError,AttributeError):return False

    def run(self,request,context,registry,started,clock=utc_now_iso):
        with self._lock:
            if not self.eligible(request,context,registry):raise ValueError('Controlled function lab prerequisites missing')
            self.used=True
            raw=deepcopy(self.raw_baseline['request']);raw['headers']['authorization']=self.normal_authorization
        connection=HTTPConnection(self.host,self.port,timeout=3)
        try:
            connection.putrequest(raw['method'],raw['path'],skip_host=True,skip_accept_encoding=True)
            for key,value in raw['headers'].items():connection.putheader(key,value)
            connection.endheaders(raw['body'].encode())
            response=connection.getresponse();body=response.read(4097)
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
        roles=[(self.transaction['request']['request_id'],'request'),(self.transaction['response']['headers']['x-lab-trace-id'],'response'),(execution_ref,'tool'),(control_ref,'control'),(comparison_ref,'comparison')]
        receipts=deepcopy(self.lab.receipts)
        for receipt in receipts:
            if receipt.get('trace_id')==self.transaction['response']['headers']['x-lab-trace-id']:
                roles += [(receipt[name]['evidence_ref'],'control') for name in ['state_before','state_after'] if name in receipt]
        for ref,kind in roles:
            if ref in self.evidence:raise ValueError('Evidence collision')
            self.evidence[ref]=EvidenceReference(ref,context.endpoint_context_id,kind,request.session_id)
        result=DynamicTestExecutionResult(request.test_id,context.endpoint_context_id,'completed',self.transaction['request']['request_id'],self.transaction['response']['headers']['x-lab-trace-id'],tuple(self.evidence),(execution_ref,),started,clock(),None,request.session_id)
        validate_execution(request,result,self.evidence)
        self.bundle=FunctionAuthorizationEvidence(context,self.session,self.baseline,self.transaction,receipts,receipts,execution_ref,control_ref,comparison_ref,self.privileges)
        return result

    def validate(self,request,execution):
        return validate_function_authorization(request,execution,self.evidence,self.bundle)
