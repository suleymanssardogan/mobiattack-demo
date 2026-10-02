"""Acquire a real Android-browser baseline from the local lab, no DAST test.

Example: python -m scripts.labs.acquire_auth_baseline --bind <host-private-IP>
Requires an existing emulator/Chrome and uses proxy port 18080. All temporary
servers are stopped and the previous device proxy is restored on exit.
"""
import argparse
import json
from pathlib import Path
import threading
import time

from scripts.labs.auth_baseline_lab import (
    TRAINING_ACCOUNT, TRAINING_PASSWORD, TrainingAuthLab, make_server, validate_baseline_artifacts)
from src.dynamic.preflight.device_check import find_adb_binary, run_adb_cmd
from src.dynamic.session.manager import DynamicSessionManager
from src.dynamic.session.storage import SessionStorage
from src.dynamic.ui.observer import observe_screen
from src.dynamic.route.graph import RouteGraph
from src.dynamic.action.executor import ActionExecutor
from src.dynamic.runtime.observer import AndroidRuntimeObserver
from src.dynamic.traffic.service import DynamicTrafficService
from src.dynamic.traffic.native_backend import NativeProxyCaptureBackend
from src.dynamic.traffic.storage import TrafficStorage
from src.dynamic.traffic.models import TrafficEvidenceArtifact, create_action_traffic_evidence
from src.dynamic.correlation.api_correlator import correlate_static_dynamic_apis
from src.dynamic.context.endpoint_context_builder import build_endpoint_contexts


def acquire(bind, out, *, serial='emulator-5554', port=18081, proxy_port=18080):
    out=Path(out)
    out.mkdir(parents=True,exist_ok=False)  # Never overwrite previous evidence.
    adb=find_adb_binary()
    if not adb: raise RuntimeError('ADB unavailable')
    package='com.android.chrome'
    manager=DynamicSessionManager(SessionStorage(str(out/'dynamic'),run_scoped=True))
    session=manager.start_session(package,serial,metadata={'controlled_local_training_lab':True,'security_test_executed':False,'dynamic_analysis_completed':False})
    flow=manager.start_flow('Local authenticated baseline acquisition')
    lab=TrainingAuthLab(session.session_id)
    server=make_server(bind,port,lab)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    traffic=DynamicTrafficService(backend=NativeProxyCaptureBackend(),storage=TrafficStorage(str(out)),adb_bin=adb)
    started=False
    try:
        traffic.check_readiness(serial,proxy_port=proxy_port)
        traffic.start_capture(session,serial,proxy_port=proxy_port,in_scope_domains=[bind]);started=True
        code,_,_=run_adb_cmd(adb,['shell','am','start','-a','android.intent.action.VIEW','-d',f'http://{bind}:{port}/','-p',package],serial=serial)
        if code: raise RuntimeError('Lab browser launch failed')
        time.sleep(2)
        graph=RouteGraph(session_id=session.session_id)
        candidates=[]
        for attempt in range(3):
            screen=observe_screen(serial,adb_bin=adb,target_package=package,max_attempts=1)
            node=graph.observe_screen(screen)
            candidates=[a for a in node.actions.values() if (a.text or a.content_desc or '').strip()=='Login and load profile']
            if len(candidates)==1: break
            if attempt<2: time.sleep(1)
        if len(candidates)!=1: raise RuntimeError('Lab UI button not observable')
        action=candidates[0]
        flow.add_marker('LAB_LOGIN_PROFILE_STARTED',{'action_id':action.action_id,'route_id':node.route_node_id})
        result=ActionExecutor(serial,adb_bin=adb,max_attempts=1).click(action)
        flow.record_action('ACTION_EXECUTED',metadata={**result.to_timeline_metadata(),'route_id':node.route_node_id})
        if not result.is_success: raise RuntimeError('Lab UI action failed')
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            observed=[t for t in traffic.captured_transactions if t.request.host==bind and t.request.port==port and t.request.path=='/profile' and t.response is not None]
            if observed: break
            time.sleep(.1)
        time.sleep(.2)  # Let the real response callback finish persistence.
        after=observe_screen(serial,adb_bin=adb,target_package=package,max_attempts=1)
        target_node=graph.observe_screen(after)
        runtime=AndroidRuntimeObserver(serial=serial,adb_bin=adb).observe(package)
        selected=[t for t in traffic.captured_transactions if t.request.host==bind and t.request.port==port and t.request.path in ('/login','/profile')]
        action_evidence=create_action_traffic_evidence(action_id=action.action_id,source_node_id=node.route_node_id,target_node_id=target_node.route_node_id,transactions=selected,http_visibility='available',https_visibility='unavailable')
        evidence=TrafficEvidenceArtifact(session_id=session.session_id,actions=[action_evidence])
        evidence.save_atomic(out/'dynamic/traffic_evidence.json')
        route={'session_id':session.session_id,'source_node_id':node.route_node_id,'action_id':action.action_id,'target_node_id':target_node.route_node_id,
               'foreground_package':screen.foreground_package,'foreground_activity':screen.foreground_activity,'source':'existing_ui_observer_and_action_executor'}
        (out/'route_evidence.json').write_text(json.dumps(route,indent=2)+'\n')
        (out/'runtime.json').write_text(json.dumps({k:runtime.to_dict()[k] for k in ['timestamp','package_name','pid','process_running','foreground_package','foreground_activity','fatal_detected','crash_detected']},indent=2)+'\n')
    finally:
        if started:
            summary=traffic.stop_capture()
            traffic.storage.save_traffic_json(out/'dynamic/traffic.json',session.session_id,traffic.captured_transactions,traffic.active_capture,summary)
        server.shutdown();server.server_close();thread.join(timeout=3)
        manager.complete_session()
    data=json.loads((out/'dynamic/traffic.json').read_text())
    # Only lab requests enter the canonical correlation/context path. Browser
    # background transactions do not become training endpoint evidence.
    canonical=[t for t in data['transactions'] if t['request']['host']==bind and t['request']['port']==port and t['request']['path'] in ('/login','/profile')]
    correlation=correlate_static_dynamic_apis([],canonical,session_id=session.session_id,traffic_evidence=evidence,
                                            http_visibility=data['http_visibility'],https_visibility=data['https_visibility'])
    correlation.save_atomic(out/'dynamic/api_correlation.json')
    contexts=build_endpoint_contexts(correlation,canonical,traffic_evidence=evidence)
    contexts.save_atomic(out/'dynamic/endpoint_contexts.json')
    receipts=lab.receipts
    (out/'lab_receipts.json').write_text(json.dumps(receipts,indent=2)+'\n')
    baseline=validate_baseline_artifacts(data,contexts,session.to_dict(),receipts,host=bind,port=port)
    baseline.update({'action_id':action.action_id,'route_id':node.route_node_id,'tool_result_ref':'lab_acquisition_'+session.session_id.replace('-',''),
                     'backend':'NativeProxyCaptureBackend','lab_http_port':port,'proxy_port':proxy_port,'proxy_restored':data['proxy_restored']})
    # Check every persisted file against the fixed fixtures and ephemeral token;
    # scanning prints no secret values and fails closed if any escaped sanitizer.
    needles=[TRAINING_ACCOUNT.encode(),TRAINING_PASSWORD.encode(),*[token.encode() for token in lab._tokens]]
    if any(any(needle in p.read_bytes() for needle in needles) for p in out.rglob('*') if p.is_file()):
        raise RuntimeError('Secret persistence detected')
    baseline['secret_persisted']=False
    (out/'baseline.json').write_text(json.dumps(baseline,indent=2)+'\n')
    (out/'lab_acquisition_result.json').write_text(json.dumps({'evidence_ref':baseline['tool_result_ref'],'session_id':session.session_id,'endpoint_context_id':baseline['endpoint_context_id'],'status':'completed',
        'source':'live_android_ui_local_backend_capture','baseline_refs':baseline,'security_test_executed':False},indent=2)+'\n')
    print(json.dumps({'status':'PASS','endpoint':f'http://{bind}:{port}/profile','auth_presence':True,'secret_persisted':False,
                      'lab_transactions':len(canonical),'eligible_baseline':True,'proxy_restored':data['proxy_restored']}))
    return baseline


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--bind',required=True)
    parser.add_argument('--out',default='examples/auth_lab_d10_2')
    args=parser.parse_args()
    acquire(args.bind,args.out)
