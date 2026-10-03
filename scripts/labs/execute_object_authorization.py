"""One fresh local two-principal baseline and one object-access variant. No emulator/public target."""
from http.client import HTTPConnection
import json
from pathlib import Path
import threading
import uuid

from scripts.labs.auth_baseline_lab import TrainingObjectLab, make_server
from scripts.labs.execute_auth_presence import atomic_json
from src.dynamic.runtime.models import utc_now_iso
from src.dynamic.traffic.normalizer import normalize_http_transaction, sanitize_transaction_data
from src.dynamic.correlation.api_correlator import correlate_static_dynamic_apis
from src.dynamic.context.endpoint_context_builder import build_endpoint_contexts
from src.dynamic.security.contracts import DynamicTestRequest, EvidenceReference
from src.dynamic.security.executor import DeterministicSecurityExecutor
from src.dynamic.security.object_authorization import LocalLabObjectAuthorization
from src.dynamic.security.reporting import security_result_artifact, save_security_results, build_security_section, validate_security_section
from src.dynamic.report import generate_dynamic_analysis_report
from src.web.report_summary import load_report_summary


def finalize_report(out):
    """Offline canonical report projection; never repeat a security request."""
    out=Path(out)
    source=json.loads((out/'dynamic/security_results.json').read_text())
    record=source['records'][0]
    execution=record['execution']
    atomic_json(out/'dynamic/session.json',{'session_id':source['session_id'],'status':'COMPLETED',
        'started_at':record['evidence']['baseline']['request']['timestamp'],'ended_at':execution['finished_at'],
        'metadata':{'controlled_local_lab':True,'android_ui_observed':False}})
    report=generate_dynamic_analysis_report(out)
    atomic_json(out/'report_summary.json',load_report_summary(out))
    return report


def acquire_case(server):
    lab=server.training_lab;host,port=server.server_address[:2]
    run=lab.run_id
    def send(method,path,headers,body=None):
        start=utc_now_iso();connection=HTTPConnection(host,port,timeout=3)
        try:
            connection.request(method,path,body=body,headers=headers)
            response=connection.getresponse();data=response.read(4097)
            if len(data)>4096:raise ValueError('Lab response too large')
            raw={'request':{'method':method,'scheme':'http','host':host,'port':port,'path':path,
                'headers':{k.lower():v for k,v in headers.items()},'body':body,'timestamp':start},
                'response':{'status_code':response.status,'headers':dict(response.getheaders()),'body':data,'timestamp':utc_now_iso()}}
            return raw
        finally:connection.close()
    headers={'Host':f'{host}:{port}','X-Lab-Run-ID':run,'Content-Type':'application/json'}
    credentials={'auth_user':'user_A','password':'training_A_password'}
    login=send('POST','/login',headers,json.dumps(credentials))
    token=json.loads(login['response']['body'])['access_token'] # memory only
    protected={'Host':f'{host}:{port}','X-Lab-Run-ID':run,'Authorization':'Bearer '+token}
    raw=send('GET','/orders/1001',protected)
    tx=normalize_http_transaction(raw['request'],raw['response'],'capture_'+uuid.uuid4().hex,run)
    canonical=sanitize_transaction_data(tx.to_dict())
    correlation=correlate_static_dynamic_apis([], [canonical], session_id=run, http_visibility='available',https_visibility='unavailable')
    contexts=build_endpoint_contexts(correlation,[canonical])
    context=contexts.endpoints[0];ownership=lab.ownership(host,port)
    refs={canonical['request']['request_id']:'request',canonical['response']['headers']['x-lab-trace-id']:'response',
          context.endpoint_context_id:'context',run:'runtime',ownership['evidence_ref']:'control'}
    registry={ref:EvidenceReference(ref,context.endpoint_context_id,kind,run) for ref,kind in refs.items()}
    request=DynamicTestRequest('OBJECT_AUTHORIZATION',context.endpoint_context_id,'object_authorization',
        'Validate expected cross-principal enforcement in the controlled training lab',tuple(refs),'validate_object_access_behavior','low',run)
    backend=LocalLabObjectAuthorization(server=server,baseline=canonical,raw_baseline=raw,context=context,session={'session_id':run},ownership=ownership)
    return backend,request,context,registry,contexts,correlation


def execute(out, port=0):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    lab=TrainingObjectLab(str(uuid.uuid4()));server=make_server('127.0.0.1',port,lab)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        backend,request,context,registry,contexts,correlation=acquire_case(server)
        execution=DeterministicSecurityExecutor(object_backend=backend).execute(request,context,registry,session_id=request.session_id)
        validation=backend.validate(request,execution)
        artifact=security_result_artifact(request,execution,backend.evidence,backend.bundle,validation)
        save_security_results(out,artifact)
        contexts.save_atomic(out/'dynamic/endpoint_contexts.json');correlation.save_atomic(out/'dynamic/api_correlation.json')
        atomic_json(out/'dynamic/traffic.json',{'session_id':request.session_id,'schema_version':'1.0','backend':'controlled_local_lab',
            'http_visibility':'available','https_visibility':'unavailable','transactions':[backend.baseline,backend.transaction]})
        section=build_security_section(artifact,request.session_id,[context.to_dict()])
        validate_security_section(section,request.session_id,{context.endpoint_context_id})
        for name,data in [('test_request',request.to_dict()),('execution_result',execution.to_dict()),
            ('validation_result',validation.to_dict()),('security_validation_summary',section),('ownership_evidence',backend.ownership)]:atomic_json(out/(name+'.json'),data)
        finalize_report(out)
        return validation,execution,backend
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--out',required=True);parser.add_argument('--port',type=int,default=0)
    args=parser.parse_args();result,execution,_=execute(args.out,args.port)
    print(json.dumps({'execution':execution.execution_status,'outcome':result.outcome,'reason_codes':result.reason_codes,'finding_created':False}))
