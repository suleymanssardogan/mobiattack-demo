"""One real local baseline, proven logout, one old-session validation request."""
from http.client import HTTPConnection
import json
from pathlib import Path
import threading
import uuid

from scripts.labs.auth_baseline_lab import TrainingSessionLab, make_server
from scripts.labs.execute_auth_presence import atomic_json
from scripts.labs.execute_object_authorization import finalize_report
from src.dynamic.runtime.models import utc_now_iso
from src.dynamic.traffic.normalizer import normalize_http_transaction, sanitize_transaction_data
from src.dynamic.correlation.api_correlator import correlate_static_dynamic_apis
from src.dynamic.context.endpoint_context_builder import build_endpoint_contexts
from src.dynamic.security.contracts import DynamicTestRequest, EvidenceReference
from src.dynamic.security.executor import DeterministicSecurityExecutor
from src.dynamic.security.session_invalidation import (LocalLabSessionInvalidation,
    _lifecycle, _receipt, _baseline, _logout, _roles)
from src.dynamic.security.reporting import security_result_artifact, save_security_results


def acquire_case(server):
    lab=server.training_lab;host,port=server.server_address[:2];run=lab.run_id
    def send(method,path,headers,body=None):
        start=utc_now_iso();connection=HTTPConnection(host,port,timeout=3)
        try:
            connection.request(method,path,body=body,headers=headers)
            response=connection.getresponse();data=response.read(4097)
            if len(data)>4096:raise ValueError('Lab response too large')
            return {'request':{'method':method,'scheme':'http','host':host,'port':port,'path':path,
                'headers':{k.lower():v for k,v in headers.items()},'body':body,'timestamp':start},
                'response':{'status_code':response.status,'headers':dict(response.getheaders()),'body':data,'timestamp':utc_now_iso()}}
        finally:connection.close()
    def canonical(raw):
        return sanitize_transaction_data(normalize_http_transaction(raw['request'],raw['response'],'capture_'+uuid.uuid4().hex,run).to_dict())
    headers={'Host':f'{host}:{port}','X-Lab-Run-ID':run,'Content-Type':'application/json'}
    login=send('POST','/login',headers,json.dumps({'auth_user':'user_A','password':'training_A_password'}))
    if login['response']['status_code']!=200:raise ValueError('Training login failed')
    token=json.loads(login['response']['body'])['access_token'] # memory only, never refreshed
    protected={'Host':f'{host}:{port}','X-Lab-Run-ID':run,'Authorization':'Bearer '+token}
    raw=send('GET','/profile',protected);baseline=canonical(raw)
    correlation=correlate_static_dynamic_apis([], [baseline],session_id=run,http_visibility='available',https_visibility='unavailable')
    contexts=build_endpoint_contexts(correlation,[baseline]);context=contexts.endpoints[0]
    lifecycle=lab.lifecycle(host,port)
    _lifecycle(lifecycle,context,run)
    before=_receipt(baseline,lab.receipts,lifecycle,context,run,'baseline');_baseline(baseline,before,context)
    # No invalidation action is taken without a real, eligible protected baseline.
    logout=canonical(send('POST','/logout',{**protected,'Content-Type':'application/json'},'{}'))
    revoked=_receipt(logout,lab.receipts,lifecycle,context,run,'logout');_logout(logout,revoked,before)
    refs=dict(_roles(context,run,lifecycle,[baseline,logout],[before,revoked]))
    registry={ref:EvidenceReference(ref,context.endpoint_context_id,kind,run) for ref,kind in refs.items()}
    request=DynamicTestRequest('SESSION_HANDLING',context.endpoint_context_id,'session_handling',
        'Validate old credential rejection after proven local training logout',tuple(refs),'validate_session_dependency','low',run)
    backend=LocalLabSessionInvalidation(server=server,baseline=baseline,raw_baseline=raw,logout=logout,context=context,session={'session_id':run},lifecycle=lifecycle)
    if not backend.eligible(request,context,registry):raise ValueError('Session baseline or invalidation proof invalid')
    return backend,request,context,registry,contexts,correlation


def execute(out,port=0):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    lab=TrainingSessionLab(str(uuid.uuid4()));server=make_server('127.0.0.1',port,lab)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        backend,request,context,registry,contexts,correlation=acquire_case(server)
        execution=DeterministicSecurityExecutor(session_backend=backend).execute(request,context,registry,session_id=request.session_id)
        validation=backend.validate(request,execution)
        save_security_results(out,security_result_artifact(request,execution,backend.evidence,backend.bundle,validation))
        contexts.save_atomic(out/'dynamic/endpoint_contexts.json');correlation.save_atomic(out/'dynamic/api_correlation.json')
        atomic_json(out/'dynamic/traffic.json',{'session_id':request.session_id,'schema_version':'1.0','backend':'controlled_local_lab',
            'http_visibility':'available','https_visibility':'unavailable','transactions':[backend.baseline,backend.logout,backend.transaction]})
        for name,data in [('test_request',request.to_dict()),('execution_result',execution.to_dict()),
                          ('validation_result',validation.to_dict()),('lifecycle_evidence',backend.lifecycle)]:atomic_json(out/(name+'.json'),data)
        finalize_report(out)
        return validation,execution,backend
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--out',required=True);parser.add_argument('--port',type=int,default=0)
    args=parser.parse_args();result,execution,_=execute(args.out,args.port)
    print(json.dumps({'execution':execution.execution_status,'outcome':result.outcome,'reason_codes':result.reason_codes,'finding_created':False}))
