"""Bounded manual authentication observation. No credential input or backend auth claim."""
from dataclasses import replace
import hashlib
import re
import time
from src.dynamic.deadline import budget
from src.dynamic.session.models import utc_now_iso
from src.persistence import write_json_atomic

STATES = {'AUTH_INTERVENTION_REQUIRED', 'WAITING_FOR_USER_AUTH', 'AUTH_STATE_OBSERVED',
          'AUTH_RESUME_READY', 'AUTH_TIMEOUT', 'AUTH_NOT_COMPLETED'}
MESSAGES = {s: 'Authentication required for deeper runtime coverage.' for s in STATES}
MESSAGES['WAITING_FOR_USER_AUTH'] = 'Authentication required — complete login in the app to continue.'
MESSAGES['AUTH_RESUME_READY'] = 'User-assisted authentication completed; Dynamic exploration resumed.'


def auth_wall(obs):
    return (obs.is_target_package and any(n.password and n.editable and n.visible and n.enabled for n in obs.nodes)
            and any(a.action_type == 'click' and re.search(r'\b(login|register|sign[ -]?in|sign[ -]?up)\b',
                ' '.join((a.text, a.content_desc)), re.I) for a in obs.action_candidates))


def safe_observation(obs):
    # Values are never copied into route/action artifacts, including username and OTP input.
    return replace(obs, nodes=[replace(n, text='', content_desc='') if n.editable or n.password else n for n in obs.nodes],
                   action_candidates=[replace(a, text='', content_desc='') if a.action_type=='input' else a for a in obs.action_candidates])


def structure(obs):
    return hashlib.sha256(repr([(n.node_id,n.class_name,n.resource_id,n.editable,n.password,n.clickable,n.selected)
                               for n in obs.nodes]).encode()).hexdigest()


def wait_for_user_auth(before, observer, runtime_observer, *, session_id, package_name,
                       traffic_service=None, timeout_seconds=20, cancelled=lambda:False,
                       publish=None, evidence_path=None, clock=time.monotonic, sleeper=time.sleep):
    if not session_id or before.foreground_package != package_name or not auth_wall(before):
        raise ValueError('AUTH_INTERVENTION_INPUT_INVALID')
    marker = traffic_service.get_current_marker() if traffic_service else None
    if traffic_service:
        # Fail closed if a capture adapter cannot guarantee manual-login privacy.
        traffic_service.enable_auth_privacy(session_id)
    evidence={'schema_version':'1.0','session_id':session_id,'pre_auth_state_id':before.screen_identity,
              'post_auth_state_id':None,'auth_presence':None,'traffic_watermark':marker,
              'evidence_refs':['dynamic/route_graph.json','dynamic/session.json'],
              'limitations':['UI transition is not proof of server authentication.',
                             'Manual authentication body/query/header values are withheld.']}
    def emit(state):
        evidence.update(state=state,message=MESSAGES[state],timestamp=utc_now_iso())
        if evidence_path:write_json_atomic(str(evidence_path),evidence)
        if publish:publish(dict(evidence))
    emit('AUTH_INTERVENTION_REQUIRED');emit('WAITING_FOR_USER_AUTH')
    candidate=None
    with budget(timeout_seconds,clock) as deadline:
        while deadline.remaining()>0:
            if cancelled():
                emit('AUTH_NOT_COMPLETED');return None,evidence
            try:
                obs=safe_observation(observer())
                runtime=runtime_observer.observe(package_name) if runtime_observer else None
                healthy=(runtime is not None and runtime.package_name==package_name and runtime.process_running
                         and runtime.is_foreground and not runtime.crash_detected and not runtime.fatal_detected)
                navigation=any(a.navigation_evidence for a in obs.action_candidates)
                transitioned=(healthy and obs.is_target_package and obs.foreground_package==package_name
                    and not any(n.password and n.visible for n in obs.nodes) and not auth_wall(obs)
                    and structure(obs)!=structure(before)
                    and (obs.foreground_activity!=before.foreground_activity or navigation))
                if transitioned and deadline.remaining()>0:
                    identity=(obs.screen_identity,structure(obs),obs.foreground_activity)
                    if candidate==identity:
                        evidence.update(post_auth_state_id=obs.screen_identity,
                            activity_changed=obs.foreground_activity!=before.foreground_activity)
                        emit('AUTH_STATE_OBSERVED');emit('AUTH_RESUME_READY')
                        return obs,evidence
                    candidate=identity
                else:candidate=None
            except Exception:
                candidate=None  # no exception strings or credential-bearing diagnostics persisted
            if deadline.remaining()>0:sleeper(min(.2,deadline.remaining()))
    emit('AUTH_TIMEOUT');return None,evidence
