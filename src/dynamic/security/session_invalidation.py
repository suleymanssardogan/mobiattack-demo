"""One old-credential replay after proven revocation in an explicit local lab.

No token mutations, refresh/re-authentication, generic replay or findings.
Canonical request/execution/validation contracts and executor are reused.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
from http.client import HTTPConnection
from http.server import HTTPServer
import ipaddress
import json
import re
import uuid

from src.dynamic.security.validation import AuthPresenceEvidence, EvidenceInspection
from src.dynamic.security.function_authorization import ProofError, _require
from src.dynamic.security.contracts import (DynamicTestExecutionResult, DynamicValidationResult,
    EvidenceReference, _time, validate_execution, validate_result)
from src.dynamic.runtime.models import utc_now_iso
from src.dynamic.traffic.normalizer import normalize_http_transaction, sanitize_transaction_data

PROTECTED_BODY={'authenticated':True,'purpose':'read_only_training_profile','profile':{'display_name':'Training User A'}}


@dataclass(frozen=True)
class SessionInvalidationEvidence(AuthPresenceEvidence):
    lifecycle: dict
    logout: dict | None
    logout_receipts: list


def _lifecycle(data,context,session):
    _require(isinstance(data,dict) and set(data)=={'evidence_ref','session_id','source','host','port','principal_alias','credential_ref','generation','protected','logout'},'MISSING_LOGOUT_EVIDENCE')
    _require(data['session_id']==session,'CROSS_SESSION_EVIDENCE')
    _require(data['source']=='controlled_local_lab_configuration' and data['principal_alias']=='user_A'
        and type(data['generation']) is int and data['generation']==1
        and data['protected']=={'method':'GET','path':'/profile'}
        and data['logout']=={'method':'POST','path':'/logout'},'LOGOUT_NOT_PROVEN')
    _require(isinstance(data['credential_ref'],str) and re.fullmatch(r'principal_session_[0-9a-f]{32}',data['credential_ref']) is not None,'CREDENTIAL_IDENTITY_MISMATCH')
    _require(data['evidence_ref']=='lifecycle_'+hashlib.sha256(session.encode()).hexdigest()[:20],'REFERENCE_MISMATCH')
    _require(ipaddress.ip_address(context.host).is_loopback and (context.host,context.port)==(data['host'],data['port'])
        and (context.scheme,context.path,context.methods)==('http','/profile',['GET']),'CROSS_ENDPOINT_EVIDENCE')


def _state(receipt,which):
    return {key:value for key,value in receipt[which].items() if key not in {'evidence_ref','session_id','trace_id'}}


def _receipt(payload,receipts,lifecycle,context,session,kind):
    missing={'baseline':'MISSING_BASELINE_EVIDENCE','logout':'MISSING_LOGOUT_EVIDENCE','variant':'MISSING_VARIANT_EVIDENCE'}[kind]
    _require(isinstance(payload,dict) and isinstance(payload.get('request'),dict) and isinstance(payload.get('response'),dict),missing)
    q,r=payload['request'],payload['response']
    _require(_time(q['timestamp'])<=_time(r['timestamp']),'REFERENCE_MISMATCH')
    _require(payload.get('session_id')==session,'CROSS_SESSION_EVIDENCE')
    _require(not any(part.get('synthetic') or part.get('internal') for part in (payload,q,r)),'SYNTHETIC_RESPONSE')
    observation=payload.get('correlation',{}).get('response_observation',{})
    _require(not observation or observation.get('state')=='available','SYNTHETIC_RESPONSE')
    _require(sanitize_transaction_data(payload)==payload,'UNREDACTED_EVIDENCE')
    method,path,body=('POST','/logout',{}) if kind=='logout' else ('GET','/profile',None)
    _require((q['scheme'],q['host'],q['port'],q['method'],q['path'],q.get('body'))==('http',context.host,context.port,method,path,body) and not q.get('query'),'UNEXPECTED_REQUEST_MUTATION')
    _require(q['headers'].get('authorization')=='[REDACTED]' and q['headers'].get('x-lab-run-id')==session,'CREDENTIAL_IDENTITY_MISMATCH')
    _require(isinstance(r.get('body'),dict) and r['headers'].get('content-type','').split(';')[0]=='application/json','INSUFFICIENT_RESPONSE_COMPARISON')
    metadata=r.get('body_metadata',{})
    _require(type(metadata.get('size')) is int and metadata['size']>0 and metadata.get('binary') is False and metadata.get('truncated') is False,'INSUFFICIENT_RESPONSE_COMPARISON')
    trace=r['headers'].get('x-lab-trace-id');selected=[x for x in receipts if x.get('trace_id')==trace]
    _require(len(selected)==1,'MISSING_REQUIRED_EVIDENCE');receipt=selected[0]
    _require(not receipt.get('synthetic') and not receipt.get('internal'),'SYNTHETIC_RESPONSE')
    _require(receipt.get('run_id')==session,'CROSS_SESSION_EVIDENCE')
    _require((receipt.get('source'),receipt.get('method'),receipt.get('path'),receipt.get('status'))==('local_training_backend_actual_response',method,path,r['status_code']),'REFERENCE_MISMATCH')
    _require(receipt.get('principal_alias')=='user_A' and receipt.get('credential_ref')==lifecycle['credential_ref']
        and type(receipt.get('generation')) is int and receipt['generation']==1 and receipt.get('auth_present') is True,'CREDENTIAL_IDENTITY_MISMATCH')
    _require(receipt.get('response_sha256')==hashlib.sha256(json.dumps(r['body'],sort_keys=True).encode()).hexdigest(),'INSUFFICIENT_RESPONSE_COMPARISON')
    for name in ['state_before','state_after']:
        state=receipt.get(name)
        _require(isinstance(state,dict) and set(state)=={'evidence_ref','session_id','trace_id','credential_ref','generation','active','version','reason','expires_at'},'MISSING_STATE_EVIDENCE')
        _require(state['session_id']==session,'CROSS_SESSION_EVIDENCE')
        _require(state['trace_id']==trace and state['evidence_ref']=='state_'+trace+('_before' if name=='state_before' else '_after'),'REFERENCE_MISMATCH')
        _require(state['credential_ref']==lifecycle['credential_ref'] and type(state['generation']) is int and state['generation']==1,'CREDENTIAL_IDENTITY_MISMATCH')
        _require(type(state['active']) is bool and type(state['version']) is int and state['version'] in {1,2} and state['reason'] in {'login','logout'},'MISSING_STATE_EVIDENCE')
        _time(state['expires_at'])
    return receipt


def _baseline(payload,receipt,context):
    state=_state(receipt,'state_before')
    _require(context.dynamic.get('observed') and context.auth.get('authorization_header_present') and payload['transaction_id'] in context.evidence_refs.get('transaction_ids',[]),'MISSING_BASELINE_EVIDENCE')
    _require(payload['response']['status_code']==200 and payload['response']['body']==PROTECTED_BODY
        and receipt.get('auth_valid') is True and state==_state(receipt,'state_after')
        and state['active'] is True and state['version']==1 and state['reason']=='login','MISSING_BASELINE_EVIDENCE')
    _require(_time(payload['response']['timestamp'])<_time(state['expires_at']),'BASELINE_EXPIRED')


def _logout(payload,receipt,baseline):
    before=_state(baseline,'state_after');after={**before,'active':False,'version':2,'reason':'logout'}
    _require(payload['response']['status_code']==200 and payload['response']['body']=={'logout':'completed'}
        and receipt.get('auth_valid') is True and _state(receipt,'state_before')==before
        and _state(receipt,'state_after')==after,'LOGOUT_NOT_PROVEN')
    _require(_time(payload['response']['timestamp'])<_time(before['expires_at']),'BASELINE_EXPIRED')


def _roles(context,session,lifecycle,payloads,receipts):
    roles=[(context.endpoint_context_id,'context'),(session,'runtime'),(lifecycle['evidence_ref'],'control')]
    for payload,receipt in zip(payloads,receipts):
        roles.extend([(payload['request']['request_id'],'request'),(payload['response']['headers']['x-lab-trace-id'],'response')])
        roles.extend([(receipt[name]['evidence_ref'],'control') for name in ['state_before','state_after']])
    return roles


def inspect_session_invalidation(request,execution,registry,evidence):
    def fail(code):
        return EvidenceInspection(code,'inconclusive' if code in {'CREDENTIAL_IDENTITY_MISMATCH','MISSING_VARIANT_EVIDENCE','MISSING_STATE_EVIDENCE','INSUFFICIENT_RESPONSE_COMPARISON','MISSING_REQUIRED_EVIDENCE','EXECUTION_NOT_COMPLETED'} else 'blocked')
    if not isinstance(evidence,SessionInvalidationEvidence) or not evidence.baseline:return fail('MISSING_BASELINE_EVIDENCE')
    try:
        c=evidence.context;s=request.session_id
        _require(request.test_category=='session_handling' and request.requested_action=='validate_session_dependency' and request.risk_class=='low','ACTION_MISMATCH')
        _require((execution.test_id,execution.endpoint_context_id,c.endpoint_context_id)==(request.test_id,request.endpoint_context_id,request.endpoint_context_id),'CROSS_ENDPOINT_EVIDENCE')
        _require(s and execution.session_id==s and evidence.session.get('session_id')==s,'CROSS_SESSION_EVIDENCE')
        _lifecycle(evidence.lifecycle,c,s)
        baseline=_receipt(evidence.baseline,evidence.baseline_receipts,evidence.lifecycle,c,s,'baseline');_baseline(evidence.baseline,baseline,c)
        logout=_receipt(evidence.logout,evidence.logout_receipts,evidence.lifecycle,c,s,'logout');_logout(evidence.logout,logout,baseline)
        _require(execution.execution_status=='completed','EXECUTION_NOT_COMPLETED')
        variant=_receipt(evidence.variant,evidence.variant_receipts,evidence.lifecycle,c,s,'variant')
        bq,br=evidence.baseline['request'],evidence.baseline['response'];vq,vr=evidence.variant['request'],evidence.variant['response']
        transient={'request_id','timestamp'}
        _require({k:v for k,v in bq.items() if k not in transient}=={k:v for k,v in vq.items() if k not in transient},'UNEXPECTED_REQUEST_MUTATION')
        _require(evidence.variant.get('attribution',{}).get('baseline_transaction_ref')==evidence.baseline['transaction_id'] and evidence.variant.get('attribution',{}).get('logout_transaction_ref')==evidence.logout['transaction_id'],'REFERENCE_MISMATCH')
        _require(_state(variant,'state_before')==_state(variant,'state_after')==_state(logout,'state_after'),'LOGOUT_NOT_PROVEN')
        _require(_time(vr['timestamp'])<_time(_state(variant,'state_after')['expires_at']),'BASELINE_EXPIRED')
        _require(_time(br['timestamp'])<=_time(evidence.logout['request']['timestamp'])<=_time(evidence.logout['response']['timestamp'])<=_time(execution.started_at)<=_time(vq['timestamp'])<=_time(vr['timestamp'])<=_time(execution.finished_at),'REFERENCE_MISMATCH')
        digest=hashlib.sha256(json.dumps([request.test_id,c.endpoint_context_id,s,bq['request_id']]).encode()).hexdigest()[:20]
        _require((evidence.execution_ref,evidence.control_ref,evidence.comparison_ref)==('execution_'+digest,'control_'+digest,'comparison_'+digest),'REFERENCE_MISMATCH')
        required=_roles(c,s,evidence.lifecycle,[evidence.baseline,evidence.logout],[baseline,logout])
        _require({ref for ref,_ in required}.issubset(request.required_evidence_refs),'MISSING_REQUIRED_EVIDENCE')
        roles=_roles(c,s,evidence.lifecycle,[evidence.baseline,evidence.logout,evidence.variant],[baseline,logout,variant])
        roles.extend([(evidence.execution_ref,'tool'),(evidence.control_ref,'control'),(evidence.comparison_ref,'comparison')])
        _require(len({ref for ref,_ in roles})==len(roles),'REFERENCE_MISMATCH')
        for ref,kind in roles:
            owner=registry.get(ref)
            _require(isinstance(owner,EvidenceReference) and owner.ref==ref,'MISSING_REQUIRED_EVIDENCE')
            _require(owner.session_id==s,'CROSS_SESSION_EVIDENCE');_require(owner.endpoint_context_id==c.endpoint_context_id,'CROSS_ENDPOINT_EVIDENCE')
            _require(owner.kind==kind and ref in execution.evidence_refs,'REFERENCE_MISMATCH')
        for ref in request.required_evidence_refs:
            owner=registry.get(ref)
            _require(isinstance(owner,EvidenceReference) and owner.ref==ref and owner.session_id==s and owner.endpoint_context_id==c.endpoint_context_id and ref in execution.evidence_refs,'MISSING_REQUIRED_EVIDENCE')
        _require((execution.observed_request_ref,execution.observed_response_ref)==(vq['request_id'],vr['headers']['x-lab-trace-id']) and evidence.execution_ref in execution.tool_refs,'REFERENCE_MISMATCH')
        validate_execution(request,execution,registry)
        refs=frozenset(ref for ref,_ in roles)
        if vr['status_code']==401 and vr['body']=={'error':'session_invalidated'} and variant.get('auth_valid') is False:
            return EvidenceInspection('SESSION_INVALIDATION_ENFORCED','validated',refs)
        if vr['status_code']==200 and vr['body']==PROTECTED_BODY and variant.get('auth_valid') is True:
            return EvidenceInspection('SESSION_INVALIDATION_NOT_ENFORCED','rejected',refs)
        return EvidenceInspection('INSUFFICIENT_RESPONSE_COMPARISON','inconclusive',refs)
    except ProofError as exc:return fail(str(exc))
    except (ValueError,TypeError,KeyError,AttributeError):return fail('INVALID_EVIDENCE')


def validate_session_invalidation(request,execution,registry,evidence,*,created_at=None):
    proof=inspect_session_invalidation(request,execution,registry,evidence)
    refs=tuple(sorted(ref for ref in execution.evidence_refs+request.required_evidence_refs if isinstance(registry.get(ref),EvidenceReference) and registry[ref].ref==ref and registry[ref].session_id==request.session_id and registry[ref].endpoint_context_id==request.endpoint_context_id))
    if not refs:raise ValueError(proof.code)
    timestamp=created_at or utc_now_iso()
    if _time(timestamp)<_time(execution.finished_at):
        if created_at is not None:raise ValueError('Validation predates execution')
        timestamp=execution.finished_at
    result=DynamicValidationResult(request.test_id,request.endpoint_context_id,proof.outcome,refs,
        {'validated':'controlled_behavior_check','rejected':'criteria_not_met','blocked':'policy_or_execution_blocked','inconclusive':'insufficient_evidence'}[proof.outcome],
        'available' if proof.outcome in {'validated','rejected'} else 'partial',timestamp,request.session_id,(proof.code,))
    if result.outcome in {'validated','rejected'}:validate_result(request,execution,result,registry,session_evidence=evidence)
    return result


class LocalLabSessionInvalidation:
    def __init__(self,*,server,baseline,raw_baseline,logout,context,session,lifecycle):
        from scripts.labs.auth_baseline_lab import TrainingSessionLab
        if not isinstance(server,HTTPServer) or type(getattr(server,'training_lab',None)) is not TrainingSessionLab or not ipaddress.ip_address(server.server_address[0]).is_loopback:
            raise ValueError('Explicit loopback session training lab required')
        self.server,self.lab=server,server.training_lab;self.host,self.port=server.server_address[:2]
        self.baseline,self.raw_baseline,self.logout=deepcopy(baseline),deepcopy(raw_baseline),deepcopy(logout)
        self.context,self.session,self.lifecycle=deepcopy(context),deepcopy(session),deepcopy(lifecycle)
        self.used=False;self.transaction=None;self.evidence={};self.bundle=None;self._lock=self.lab.validation_lock

    def eligible(self,request,context,registry):
        try:
            _require(not self.used and not self.lab.validation_claimed and request.test_category=='session_handling' and request.requested_action=='validate_session_dependency' and request.risk_class=='low','ACTION_MISMATCH')
            _require(self.server.training_lab is self.lab and self.server.server_address[:2]==(self.host,self.port) and ipaddress.ip_address(self.host).is_loopback,'CROSS_ENDPOINT_EVIDENCE')
            _require(context.to_dict()==self.context.to_dict() and request.endpoint_context_id==context.endpoint_context_id,'CROSS_ENDPOINT_EVIDENCE')
            _require(request.session_id==self.session['session_id']==self.lab.run_id,'CROSS_SESSION_EVIDENCE')
            _lifecycle(self.lifecycle,context,request.session_id)
            _require(self.lifecycle==self.lab.lifecycle(self.host,self.port),'CREDENTIAL_IDENTITY_MISMATCH')
            _require(self.lab.principal(self.raw_baseline['request']['headers']['authorization'])==('user_A',self.lifecycle['credential_ref']),'CREDENTIAL_IDENTITY_MISMATCH')
            normalized=sanitize_transaction_data(normalize_http_transaction(self.raw_baseline['request'],self.raw_baseline['response'],'baseline_check',request.session_id).to_dict())
            for kind in ['request','response']:
                skip={'request_id'} if kind=='request' else set()
                _require({k:v for k,v in normalized[kind].items() if k not in skip}=={k:v for k,v in self.baseline[kind].items() if k not in skip},'MISSING_BASELINE_EVIDENCE')
            baseline=_receipt(self.baseline,self.lab.receipts,self.lifecycle,context,request.session_id,'baseline');_baseline(self.baseline,baseline,context)
            logout=_receipt(self.logout,self.lab.receipts,self.lifecycle,context,request.session_id,'logout');_logout(self.logout,logout,baseline)
            _require(_time(self.baseline['response']['timestamp'])<=_time(self.logout['request']['timestamp']),'REFERENCE_MISMATCH')
            _require(_time(self.logout['response']['timestamp'])<=_time(utc_now_iso()),'REFERENCE_MISMATCH')
            _require(self.lab.sessions[self.lifecycle['credential_ref']]==_state(logout,'state_after'),'LOGOUT_NOT_PROVEN')
            _require(_time(utc_now_iso())<_time(_state(logout,'state_after')['expires_at']),'BASELINE_EXPIRED')
            refs=_roles(context,request.session_id,self.lifecycle,[self.baseline,self.logout],[baseline,logout])
            _require({ref for ref,_ in refs}.issubset(request.required_evidence_refs),'MISSING_REQUIRED_EVIDENCE')
            for ref,kind in refs:_require(registry.get(ref)==EvidenceReference(ref,context.endpoint_context_id,kind,request.session_id),'MISSING_REQUIRED_EVIDENCE')
            return True
        except (ValueError,TypeError,KeyError,AttributeError):return False

    def run(self,request,context,registry,started,clock=utc_now_iso):
        with self._lock:
            if not self.eligible(request,context,registry):raise ValueError('Controlled session lab prerequisites missing')
            self.used=True;self.lab.validation_claimed=True
            raw=deepcopy(self.raw_baseline['request']) # same old auth, never login/refresh
        connection=HTTPConnection(self.host,self.port,timeout=3)
        try:
            connection.putrequest('GET','/profile',skip_host=True,skip_accept_encoding=True)
            for key,value in raw['headers'].items():connection.putheader(key,value)
            connection.endheaders();response=connection.getresponse();body=response.read(4097)
            if len(body)>4096:raise ValueError('Bounded response exceeded')
            returned={'status_code':response.status,'headers':dict(response.getheaders()),'body':body,'timestamp':clock()}
        finally:connection.close()
        raw['timestamp']=started
        tx=normalize_http_transaction(raw,returned,'capture_'+uuid.uuid4().hex,request.session_id)
        tx.attribution={'method':'deterministic_local_executor','baseline_transaction_ref':self.baseline['transaction_id'],'logout_transaction_ref':self.logout['transaction_id']}
        self.transaction=sanitize_transaction_data(tx.to_dict())
        digest=hashlib.sha256(json.dumps([request.test_id,context.endpoint_context_id,request.session_id,self.baseline['request']['request_id']]).encode()).hexdigest()[:20]
        execution_ref,control_ref,comparison_ref='execution_'+digest,'control_'+digest,'comparison_'+digest
        self.evidence=dict(registry);receipts=deepcopy(self.lab.receipts)
        roles=[(self.transaction['request']['request_id'],'request'),(self.transaction['response']['headers']['x-lab-trace-id'],'response'),(execution_ref,'tool'),(control_ref,'control'),(comparison_ref,'comparison')]
        for receipt in receipts:
            if receipt.get('trace_id')==self.transaction['response']['headers']['x-lab-trace-id']:
                roles += [(receipt[name]['evidence_ref'],'control') for name in ['state_before','state_after'] if name in receipt]
        for ref,kind in roles:
            if ref in self.evidence:raise ValueError('Evidence collision')
            self.evidence[ref]=EvidenceReference(ref,context.endpoint_context_id,kind,request.session_id)
        result=DynamicTestExecutionResult(request.test_id,context.endpoint_context_id,'completed',self.transaction['request']['request_id'],self.transaction['response']['headers']['x-lab-trace-id'],tuple(self.evidence),(execution_ref,),started,clock(),None,request.session_id)
        validate_execution(request,result,self.evidence)
        self.bundle=SessionInvalidationEvidence(context,self.session,self.baseline,self.transaction,receipts,receipts,execution_ref,control_ref,comparison_ref,self.lifecycle,self.logout,receipts)
        return result

    def validate(self,request,execution):
        return validate_session_invalidation(request,execution,self.evidence,self.bundle)
