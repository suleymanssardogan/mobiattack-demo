"""Two training logins, one real privileged baseline, one role-only variant."""
from http.client import HTTPConnection
import json
from pathlib import Path
import threading
import uuid

from scripts.labs.auth_baseline_lab import TrainingFunctionLab, make_server
from scripts.labs.execute_auth_presence import atomic_json
from scripts.labs.execute_object_authorization import finalize_report
from src.dynamic.runtime.models import utc_now_iso
from src.dynamic.traffic.normalizer import normalize_http_transaction, sanitize_transaction_data
from src.dynamic.correlation.api_correlator import correlate_static_dynamic_apis
from src.dynamic.context.endpoint_context_builder import build_endpoint_contexts
from src.dynamic.security.contracts import DynamicTestRequest, EvidenceReference
from src.dynamic.security.executor import DeterministicSecurityExecutor
from src.dynamic.security.function_authorization import LocalLabFunctionAuthorization, FUNCTION
from src.dynamic.security.reporting import security_result_artifact, save_security_results


def acquire_case(server):
    lab=server.training_lab;host,port=server.server_address[:2];run=lab.run_id
    def send(path,headers,body):
        start=utc_now_iso();connection=HTTPConnection(host,port,timeout=3)
        try:
            connection.request('POST',path,body=body,headers=headers)
            response=connection.getresponse();data=response.read(4097)
            if len(data)>4096:raise ValueError('Lab response too large')
            return {'request':{'method':'POST','scheme':'http','host':host,'port':port,'path':path,
                'headers':{k.lower():v for k,v in headers.items()},'body':body,'timestamp':start},
                'response':{'status_code':response.status,'headers':dict(response.getheaders()),'body':data,'timestamp':utc_now_iso()}}
        finally:connection.close()
    headers={'Host':f'{host}:{port}','X-Lab-Run-ID':run,'Content-Type':'application/json'}
    tokens={}
    for alias in ['user_A','user_B']:
        login=send('/login',headers,json.dumps({'auth_user':alias,'password':'training_'+alias[-1]+'_password'}))
        if login['response']['status_code']!=200:raise ValueError('Training principal login failed')
        tokens[alias]=json.loads(login['response']['body'])['access_token'] # memory only
    body=json.dumps(FUNCTION['body'])
    protected={**headers,'Authorization':'Bearer '+tokens['user_B'],'Content-Length':str(len(body.encode()))}
    raw=send(FUNCTION['path'],protected,body)
    tx=normalize_http_transaction(raw['request'],raw['response'],'capture_'+uuid.uuid4().hex,run)
    baseline=sanitize_transaction_data(tx.to_dict())
    correlation=correlate_static_dynamic_apis([], [baseline], session_id=run,http_visibility='available',https_visibility='unavailable')
    contexts=build_endpoint_contexts(correlation,[baseline]);context=contexts.endpoints[0]
    privileges=lab.privileges(host,port)
    receipt=next(r for r in lab.receipts if r['trace_id']==baseline['response']['headers']['x-lab-trace-id'])
    refs={baseline['request']['request_id']:'request',receipt['trace_id']:'response',context.endpoint_context_id:'context',
        run:'runtime',privileges['evidence_ref']:'control',receipt['state_before']['evidence_ref']:'control',receipt['state_after']['evidence_ref']:'control'}
    registry={ref:EvidenceReference(ref,context.endpoint_context_id,kind,run) for ref,kind in refs.items()}
    request=DynamicTestRequest('FUNCTION_AUTHORIZATION',context.endpoint_context_id,'function_authorization',
        'Validate role enforcement for a disposable controlled lab function',tuple(refs),'validate_function_access_behavior','low',run)
    backend=LocalLabFunctionAuthorization(server=server,baseline=baseline,raw_baseline=raw,normal_authorization='Bearer '+tokens['user_A'],context=context,session={'session_id':run},privileges=privileges)
    if not backend.eligible(request,context,registry):raise ValueError('Privileged baseline or role proof invalid')
    return backend,request,context,registry,contexts,correlation


def execute(out,port=0):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    lab=TrainingFunctionLab(str(uuid.uuid4()));server=make_server('127.0.0.1',port,lab)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        backend,request,context,registry,contexts,correlation=acquire_case(server)
        execution=DeterministicSecurityExecutor(function_backend=backend).execute(request,context,registry,session_id=request.session_id)
        validation=backend.validate(request,execution)
        save_security_results(out,security_result_artifact(request,execution,backend.evidence,backend.bundle,validation))
        contexts.save_atomic(out/'dynamic/endpoint_contexts.json');correlation.save_atomic(out/'dynamic/api_correlation.json')
        atomic_json(out/'dynamic/traffic.json',{'session_id':request.session_id,'schema_version':'1.0','backend':'controlled_local_lab',
            'http_visibility':'available','https_visibility':'unavailable','transactions':[backend.baseline,backend.transaction]})
        for name,data in [('test_request',request.to_dict()),('execution_result',execution.to_dict()),
                          ('validation_result',validation.to_dict()),('privilege_evidence',backend.privileges)]:atomic_json(out/(name+'.json'),data)
        finalize_report(out)
        return validation,execution,backend
    finally:
        lab.reset();server.shutdown();server.server_close();thread.join(timeout=2)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--out',required=True);parser.add_argument('--port',type=int,default=0)
    args=parser.parse_args();result,execution,_=execute(args.out,args.port)
    print(json.dumps({'execution':execution.execution_status,'outcome':result.outcome,'reason_codes':result.reason_codes,'finding_created':False}))
