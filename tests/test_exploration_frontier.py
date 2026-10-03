"""D28: explicit frontier accounting and bounded stop semantics."""
from unittest.mock import Mock
import pytest
from src.dynamic.exploration.frontier import build_frontier, exploration_summary
from src.dynamic.exploration.loop import run_exploration, select_next_action
from src.dynamic.exploration.models import ExplorationLimits
from src.dynamic.route.graph import RouteGraph
from src.dynamic.route.storage import RouteGraphStorage
from src.dynamic.action.models import ActionExecutionResult
from tests.test_dynamic_exploration_loop import _make_obs, _make_candidate


def executor():
    obj=Mock();obj.click.return_value=ActionExecutionResult('a','click','succeeded','2026-10-03T00:00:00Z','2026-10-03T00:00:01Z');return obj


def test_per_state_accounting_and_deterministic_order():
    g=RouteGraph();n=g.observe_screen(_make_obs(actions=[_make_candidate('a'),_make_candidate('b'),_make_candidate('c')]))
    ordered=sorted(n.actions.values(),key=lambda a:a.action_id);ordered[0].status='succeeded';ordered[1].status='failed'
    f=build_frontier(g);assert f['safe_actions_discovered']==3 and f['safe_actions_attempted']==2
    assert f['safe_actions_completed']==1 and f['safe_actions_failed']==1 and f['safe_actions_remaining']==1
    assert f['states'][0]['remaining_action_ids']==[ordered[2].action_id]
    assert select_next_action(n).action_id==ordered[2].action_id and not f['safe_frontier_exhausted']


def test_max_steps_with_pending_frontier_is_partial_and_persists(tmp_path):
    root=_make_obs('root',actions=[_make_candidate('a'),_make_candidate('b')]);g=RouteGraph(session_id='session')
    r=run_exploration(lambda:root,executor(),g,initial_observation=root,limits=ExplorationLimits(max_steps=1),no_navigation_postcondition=lambda obs:True,graph_storage=RouteGraphStorage(tmp_path/'dynamic'))
    assert r.status=='partial' and r.stop_reason=='max_steps'
    assert r.metadata['frontier']['safe_actions_remaining']==1
    assert 'step budget reached with 1 safe actions remaining' in r.metadata['exploration_summary']['note']
    import json
    f=json.loads((tmp_path/'dynamic/exploration_frontier.json').read_text());assert f['session_id']=='session' and f['safe_actions_remaining']==1


def test_max_steps_even_when_last_action_used_is_not_completed():
    root=_make_obs(actions=[_make_candidate()]);r=run_exploration(lambda:root,executor(),RouteGraph(),initial_observation=root,limits=ExplorationLimits(max_steps=1),no_navigation_postcondition=lambda obs:True)
    assert r.status=='partial' and r.stop_reason=='max_steps' and r.metadata['frontier']['safe_actions_remaining']==0


def test_exhausted_safe_frontier_completes_with_no_pending_action():
    root=_make_obs(actions=[_make_candidate()]);r=run_exploration(lambda:root,executor(),RouteGraph(),initial_observation=root,limits=ExplorationLimits(max_steps=3),no_navigation_postcondition=lambda obs:True)
    assert r.status=='completed' and r.metadata['frontier']['safe_frontier_exhausted']
    assert r.metadata['exploration_summary']['stop_kind']=='FRONTIER_EXHAUSTED'


def test_repeated_state_still_executes_unvisited_action_once():
    root=_make_obs(actions=[_make_candidate('a'),_make_candidate('b')]);e=executor()
    r=run_exploration(lambda:root,e,RouteGraph(),initial_observation=root,limits=ExplorationLimits(max_steps=5),no_navigation_postcondition=lambda obs:True)
    assert e.click.call_count==2 and r.status=='completed' and r.metadata['frontier']['safe_actions_remaining']==0
    assert len({call.args[0].action_id for call in e.click.call_args_list})==2


def test_other_state_pending_is_not_exhaustion():
    root=_make_obs('root',actions=[_make_candidate('a'),_make_candidate('b')]);leaf=_make_obs('leaf')
    r=run_exploration(lambda:leaf,executor(),RouteGraph(),initial_observation=root,limits=ExplorationLimits(max_steps=5))
    assert r.status=='partial' and r.metadata['frontier']['safe_actions_remaining']==1 and not r.metadata['frontier']['safe_frontier_exhausted']


def test_unsafe_only_frontier_is_completed_for_safe_scope_not_application():
    c=_make_candidate(text='Delete account');g=RouteGraph();root=_make_obs(actions=[c]);e=executor()
    r=run_exploration(lambda:root,e,g,initial_observation=root)
    e.click.assert_not_called();f=r.metadata['frontier']
    assert f['unsafe_skipped']==1 and f['safe_actions_discovered']==0 and f['safe_frontier_exhausted']
    assert r.status=='completed' and '1 actions were skipped' in r.metadata['exploration_summary']['note']
    assert f['scope']=='discovered_reachable_safe_ui_only'


@pytest.mark.parametrize('reason,phrase',[('deadline','operation deadline'),('max_depth','depth budget'),('repeated_state','repeated state')])
def test_stop_summary_distinguishes_boundaries(reason,phrase):
    f={'safe_actions_remaining':3,'safe_actions_discovered':4,'unsafe_skipped':0,'safe_frontier_exhausted':False,'observation_available':True}
    s=exploration_summary('partial',reason,f);assert phrase in s['note'] and s['safe_actions_remaining']==3
    assert 'fully explored' not in s['note'].lower()


def test_missing_observation_cannot_exhaust_or_complete():
    r=run_exploration(Mock(side_effect=ValueError('missing')),executor(),RouteGraph())
    assert r.status=='failed' and not r.metadata['frontier']['safe_frontier_exhausted']
    assert exploration_summary(r.status,r.stop_reason,r.metadata['frontier'])['stop_kind']=='OBSERVATION_UNAVAILABLE'


def test_historical_unknown_frontier_is_not_claimed_exhausted():
    s=exploration_summary('completed','no_actions',None);assert s['safe_frontier_exhausted'] is None


def test_action_order_does_not_use_geometry_or_input_order():
    candidates=[_make_candidate('a'),_make_candidate('b')];g1=RouteGraph();g2=RouteGraph()
    n1=g1.observe_screen(_make_obs(actions=candidates));n2=g2.observe_screen(_make_obs(actions=list(reversed(candidates))))
    assert select_next_action(n1).action_id==select_next_action(n2).action_id


from tests.test_dynamic_analysis_report import sources, report


def test_report_and_ui_expose_pending_frontier(sources):
    from src.web.report_summary import build_report_summary
    sources['exploration']['metadata']={'frontier':{'safe_actions_discovered':9,'safe_actions_remaining':3,'unsafe_skipped':2,'observation_available':True,'safe_frontier_exhausted':False}}
    result=report(sources);summary=build_report_summary(dynamic_report=result)['dynamic_summary']
    assert result['exploration']['stop_kind']=='MAX_STEPS' and result['exploration']['safe_actions_remaining']==3
    assert 'step budget reached with 3 safe actions remaining' in summary['exploration_note']
    assert summary['safe_actions_remaining']==3 and summary['exploration_stop_reason']=='MAX_STEPS'
    assert result['coverage']['ui_exploration']=='partial'


def test_completed_claim_with_pending_frontier_is_downgraded(sources):
    sources['exploration']['status']='completed';sources['exploration']['stop_reason']='no_actions'
    sources['exploration']['metadata']={'frontier':{'safe_actions_discovered':2,'safe_actions_remaining':1,'unsafe_skipped':0,'observation_available':True,'safe_frontier_exhausted':False}}
    result=report(sources);assert result['exploration']['status']=='partial' and result['coverage']['ui_exploration']=='partial'


def test_unknown_historical_frontier_cannot_claim_completed_scope(sources):
    sources['exploration']['status']='completed';sources['exploration']['stop_reason']='no_actions'
    result=report(sources);assert result['exploration']['status']=='partial' and result['exploration']['safe_actions_remaining'] is None


def test_unsafe_exhaustion_report_remains_safe_scope_only(sources):
    sources['exploration']['status']='completed';sources['exploration']['stop_reason']='unsafe_action_boundary'
    sources['exploration']['metadata']={'frontier':{'safe_actions_discovered':0,'safe_actions_remaining':0,'unsafe_skipped':2,'observation_available':True,'safe_frontier_exhausted':True}}
    result=report(sources);assert result['exploration']['status']=='completed'
    assert '2 actions were skipped' in result['exploration']['note'] and 'fully explored' not in result['exploration']['note'].lower()
