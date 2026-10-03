"""Manual auth observation contracts; no credential input or real login requests."""
from dataclasses import replace
from unittest.mock import Mock
import json
import pytest
from src.dynamic.session.auth_intervention import auth_wall,wait_for_user_auth,safe_observation
from src.dynamic.ui.models import UiNode
from src.dynamic.runtime.models import RuntimeSnapshot
from src.dynamic.route.graph import RouteGraph
from src.dynamic.exploration.loop import run_exploration
from src.dynamic.exploration.models import ExplorationLimits
from tests.test_dynamic_exploration_loop import _make_obs,_make_candidate
from tests.test_exploration_frontier import executor


def wall():
    obs=_make_obs('login',actions=[_make_candidate('login',text='Login'),_make_candidate('user',action_type='input',text='USER_PRIVATE')])
    obs.nodes=[UiNode(node_id='user',editable=True,text='USER_PRIVATE'),UiNode(node_id='pwd',editable=True,password=True,text='PASSWORD_PRIVATE')]
    return obs


def post():
    obs=_make_obs('protected',activity='com.example.app.Protected',actions=[_make_candidate('info',text='About')])
    obs.nodes=[UiNode(node_id='protected',class_name='android.widget.FrameLayout',clickable=True)]
    return obs


def runtime(healthy=True):
    rt=Mock();rt.observe.return_value=RuntimeSnapshot('com.example.app',process_running=healthy,is_foreground=healthy)
    return rt


def ticking():
    class Clock:
        now=0
        def __call__(self):return self.now
        def sleep(self,t):self.now+=t
    return Clock()


def wait(observer,**kwargs):
    c=ticking()
    return wait_for_user_auth(wall(),observer,runtime(),session_id='session',package_name='com.example.app',
        clock=c,sleeper=c.sleep,timeout_seconds=1,**kwargs)


def test_structural_wall_and_label_only_rejection():
    assert auth_wall(wall())
    assert not auth_wall(_make_obs(actions=[_make_candidate(text='Login')]))
    assert not auth_wall(replace(wall(),action_candidates=[]))


def test_observed_transition_requires_healthy_runtime_and_two_observations(tmp_path):
    path=tmp_path/'auth.json';obs,e=wait(lambda:post(),evidence_path=path)
    assert obs.screen_identity=='protected' and e['state']=='AUTH_RESUME_READY'
    assert e['auth_presence'] is None and e['session_id']=='session'
    assert 'USER_PRIVATE' not in path.read_text() and 'PASSWORD_PRIVATE' not in path.read_text()


def test_text_change_alone_cannot_resume():
    changed=wall();changed.screen_identity='text_change';changed.action_candidates[0].text='Welcome'
    _,e=wait(lambda:changed)
    assert e['state']=='AUTH_TIMEOUT'


def test_missing_runtime_cannot_resume():
    c=ticking()
    obs,e=wait_for_user_auth(wall(),lambda:post(),None,session_id='session',package_name='com.example.app',timeout_seconds=.4,clock=c,sleeper=c.sleep)
    assert obs is None and e['state']=='AUTH_TIMEOUT'


def test_timeout_and_cancel_never_dispatch_credentials():
    for cancel,state in [(False,'AUTH_TIMEOUT'),(True,'AUTH_NOT_COMPLETED')]:
        e=executor();c=ticking();g=RouteGraph(session_id='session')
        r=run_exploration(lambda:wall(),e,g,initial_observation=wall(),runtime_observer=runtime(),
            limits=ExplorationLimits(deadline_seconds=2),auth_wait_seconds=.4,auth_cancelled=lambda:cancel,
            clock=c,sleeper=c.sleep)
        assert r.status=='partial' and r.stop_reason=='auth_intervention_not_completed'
        assert r.metadata['auth_interventions'][0]['state']==state
        e.click.assert_not_called();e.input.assert_not_called()
        assert 'PRIVATE' not in json.dumps(g.to_dict())


def test_manual_resume_same_graph_session_and_budget(tmp_path):
    sequence=iter([post(),post(),_make_obs('end')]);g=RouteGraph(session_id='session');e=executor();c=ticking();events=[]
    r=run_exploration(lambda:next(sequence),e,g,initial_observation=wall(),runtime_observer=runtime(),
        limits=ExplorationLimits(base_step_budget=1,hard_step_ceiling=3,deadline_seconds=4),
        auth_status_callback=events.append,clock=c,sleeper=c.sleep)
    assert r.steps_attempted==1 and g.session_id=='session'
    assert r.metadata['auth_interventions'][0]['state']=='AUTH_RESUME_READY'
    assert [ev['state'] for ev in events]==['AUTH_INTERVENTION_REQUIRED','WAITING_FOR_USER_AUTH','AUTH_STATE_OBSERVED','AUTH_RESUME_READY']
    assert r.metadata['budget']['base_step_budget']==1
    e.input.assert_not_called()


def test_traffic_watermark_visibility_and_ownership_preserved():
    from src.dynamic.traffic.service import DynamicTrafficService
    from src.dynamic.traffic.models import CaptureSession,HttpRequestModel,HttpResponseModel,TrafficTransaction
    service=DynamicTrafficService(adb_bin='/not/used');service.active_capture=CaptureSession(session_id='session')
    service.captured_transactions=[object()];service.http_visibility='available'
    _,e=wait(lambda:post(),traffic_service=service)
    assert e['traffic_watermark']==1 and service.get_current_marker()==1
    assert service.active_capture.session_id=='session' and service.http_visibility=='available'
    service.storage=Mock()
    tx=TrafficTransaction(request=HttpRequestModel(query={'username':'USER_PRIVATE'},body={'password':'PASSWORD_PRIVATE'},headers={'Cookie':'TOKEN_PRIVATE'}),response=HttpResponseModel(body='OTP_PRIVATE'))
    service._on_transaction_captured(tx)
    assert not any(v in json.dumps(tx.to_dict()) for v in ['USER_PRIVATE','PASSWORD_PRIVATE','TOKEN_PRIVATE','OTP_PRIVATE'])
    assert tx.request.query.keys()=={'username'}
    with pytest.raises(ValueError):service.enable_auth_privacy('other_session')


def test_external_surface_cannot_prove_auth_transition():
    _,e=wait(lambda:replace(post(),foreground_package='other',is_target_package=False))
    assert e['state']=='AUTH_TIMEOUT'


def test_input_privacy_does_not_mutate_observation():
    before=wall();clean=safe_observation(before)
    assert before.nodes[0].text=='USER_PRIVATE' and clean.nodes[0].text==''
    assert all(a.text=='' for a in clean.action_candidates if a.action_type=='input')

from tests.test_dynamic_analysis_report import sources,report

@pytest.mark.parametrize('state',['AUTH_TIMEOUT','AUTH_NOT_COMPLETED','AUTH_RESUME_READY'])
def test_report_only_projects_owned_safe_auth_status(sources,state):
    from src.dynamic.session.auth_intervention import MESSAGES
    sid=sources['session']['session_id']
    sources['exploration']['metadata']={'auth_interventions':[{'state':state,'session_id':sid,'password':'PASSWORD_PRIVATE'}]}
    r=report(sources)
    assert r['exploration']['authentication']=={'state':state,'message':MESSAGES[state]}
    assert 'PASSWORD_PRIVATE' not in json.dumps(r)


def test_cross_session_auth_status_not_reported(sources):
    sources['exploration']['metadata']={'auth_interventions':[{'state':'AUTH_RESUME_READY','session_id':'other'}]}
    assert 'authentication' not in report(sources)['exploration']
