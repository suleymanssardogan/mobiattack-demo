"""D30 deterministic continuation and safety boundaries; no device calls."""
from unittest.mock import Mock
import pytest
from src.dynamic.exploration.loop import run_exploration
from src.dynamic.exploration.models import ExplorationLimits
from src.dynamic.runtime.models import RuntimeSnapshot
from src.dynamic.route.graph import RouteGraph
from src.dynamic.deadline import budget
from tests.test_exploration_frontier import executor
from tests.test_dynamic_exploration_loop import _make_obs, _make_candidate


def run(sequence, *, base=1, hard=5, runtime=True, stagnation=2, **kwargs):
    observations = iter(sequence[1:] or sequence)
    observer = lambda: next(observations)
    rt = Mock()
    rt.observe.return_value = RuntimeSnapshot('com.example.app', pid=42, process_running=True)
    return run_exploration(observer, executor(), RouteGraph(), initial_observation=sequence[0],
        limits=ExplorationLimits(base_step_budget=base, hard_step_ceiling=hard, max_depth=20,
                                 stagnation_actions=stagnation),
        runtime_observer=rt if runtime else None, target_package='com.example.app',
        no_navigation_postcondition=lambda obs: True, **kwargs)


def screen(i, count=2):
    return _make_obs(str(i), actions=[_make_candidate(str(j)) for j in range(count)])


def test_new_states_allow_extension_then_hard_ceiling():
    r=run([screen(i) for i in range(7)], base=2, hard=4)
    assert r.steps_attempted==4 and r.stop_reason=='hard_step_ceiling' and r.status=='partial'
    assert r.metadata['budget']['extension_actions']==2
    assert r.metadata['budget']['adaptive_extension_used']
    assert r.metadata['frontier']['safe_actions_remaining']>0
    assert r.metadata['exploration_summary']['hard_step_ceiling']==4


def test_known_state_does_not_extend_merely_for_pending_actions():
    root=screen(0,6);r=run([root]*10)
    assert r.steps_attempted==1 and r.stop_reason=='frontier_stagnated'


def test_progress_then_bounded_stagnation_stops_before_ceiling():
    root=screen(0);other=screen(1,6)
    r=run([root,other,other,other,other],hard=8)
    assert r.steps_attempted==3 and r.stop_reason=='frontier_stagnated'
    assert r.metadata['budget']['progress_steps']==[1]


def test_new_safe_action_on_known_state_is_progress():
    root=screen(0,1);expanded=screen(0,5)
    r=run([root,expanded,expanded,expanded], hard=2)
    assert r.steps_attempted==2 and r.stop_reason=='hard_step_ceiling'


def test_missing_runtime_blocks_extension():
    r=run([screen(i) for i in range(5)],runtime=False)
    assert r.steps_attempted==1 and r.stop_reason=='runtime_unavailable'
    assert not r.metadata['frontier']['safe_frontier_exhausted']


def test_exhaustion_is_safe_scope_only():
    r=run([screen(0,1),screen(1,0)])
    assert r.status=='completed' and r.metadata['frontier']['safe_frontier_exhausted']
    assert not r.metadata['budget']['adaptive_extension_used']


def test_deadline_precedes_all_other_budget_checks():
    with budget(0):
        r=run([screen(0)])
    assert r.steps_attempted==0 and r.stop_reason=='deadline'


def test_insufficient_remaining_deadline_cannot_extend():
    times=iter([0,0,0,59.5,59.5,59.5,59.5,59.5,59.5])
    r=run([screen(i) for i in range(4)], clock=lambda:next(times,59.5))
    assert r.steps_attempted==1 and r.stop_reason=='deadline'


def test_same_configuration_deterministic_and_unsafe_untouched():
    root=screen(0,4);root.action_candidates.append(_make_candidate('unsafe',text='Delete account'))
    outputs=[run([root]*6) for _ in range(2)]
    assert outputs[0].to_dict()['metadata']==outputs[1].to_dict()['metadata']
    assert outputs[0].metadata['frontier']['unsafe_skipped']==1
    assert outputs[0].steps_attempted==1


@pytest.mark.parametrize('options',[{'base_step_budget':0},{'hard_step_ceiling':2},
    {'stagnation_actions':0},{'minimum_extension_seconds':float('nan')}])
def test_invalid_budget_rejected(options):
    with pytest.raises(ValueError):ExplorationLimits(**options)


def test_report_serializes_budget_and_partial_reason(sources):
    from tests.test_dynamic_analysis_report import report
    sources['exploration']['stop_reason']='hard_step_ceiling'
    sources['exploration']['metadata']={'budget':{'base_step_budget':6,'hard_step_ceiling':16,
        'actions_attempted':16,'adaptive_extension_used':True},'frontier':{
        'safe_actions_remaining':4,'safe_actions_discovered':20,'unsafe_skipped':2,
        'observation_available':True,'safe_frontier_exhausted':False}}
    r=report(sources)
    assert r['exploration']['adaptive_extension_used'] is True
    assert r['exploration']['stop_kind']=='HARD_STEP_CEILING'
    assert r['coverage']['ui_exploration']=='partial'

from tests.test_dynamic_analysis_report import sources


def test_unavailable_runtime_after_real_progress_never_dispatches_extension():
    rt=Mock();rt.observe.return_value=RuntimeSnapshot('com.example.app',process_running=False)
    root=screen(0);leaf=screen(1);e=executor()
    r=run_exploration(lambda:leaf,e,RouteGraph(),initial_observation=root,
        runtime_observer=rt,limits=ExplorationLimits(base_step_budget=1,hard_step_ceiling=5))
    assert r.stop_reason=='runtime_unavailable' and e.click.call_count==1


def test_max_depth_still_prevents_adaptive_dispatch():
    root=screen(0);leaf=screen(1);e=executor()
    r=run_exploration(lambda:leaf,e,RouteGraph(),initial_observation=root,
        limits=ExplorationLimits(base_step_budget=1,hard_step_ceiling=5,max_depth=1))
    assert r.stop_reason=='max_depth' and e.click.call_count==1


def test_failed_observation_never_becomes_progress():
    root=screen(0);e=executor()
    r=run_exploration(Mock(side_effect=ValueError('unavailable')),e,RouteGraph(),initial_observation=root,
        limits=ExplorationLimits(base_step_budget=1,hard_step_ceiling=5),sleeper=lambda _:None)
    assert r.stop_reason=='observation_failed' and e.click.call_count==1
    assert not r.metadata['budget']['progress_steps']


def test_proven_frontier_navigation_counts_budget_but_not_progress():
    # root -> leaf -> root; root has no new actions but leaf has pending work.
    root=screen(0,1);leaf=screen(1,2);next_state=screen(2,1)
    r=run([root,leaf,root,leaf,next_state,next_state],base=2,hard=4,stagnation=3)
    assert r.steps_attempted==4 and r.stop_reason=='hard_step_ceiling'
    assert r.metadata['budget']['frontier_navigation_steps']==[3]
    assert r.metadata['budget']['progress_steps']==[1,4]


def test_navigation_rejects_ambiguous_recorded_transition():
    from src.dynamic.exploration.loop import select_frontier_navigation
    g=RouteGraph();root=g.observe_screen(screen(0,1));a=next(iter(root.actions.values()));a.status='succeeded'
    g.record_transition(root,a,screen(1));g.record_transition(root,a,screen(2))
    assert select_frontier_navigation(g,root,3) is None


def test_return_navigation_does_not_use_failed_or_unsafe_edges():
    from src.dynamic.exploration.loop import select_frontier_navigation
    g=RouteGraph();root=g.observe_screen(screen(0,1));a=next(iter(root.actions.values()))
    g.record_transition(root,a,screen(1));a.status='failed'
    assert select_frontier_navigation(g,root,3) is None
    a.status='succeeded';a.text='Delete account'
    assert select_frontier_navigation(g,root,3) is None


def test_navigation_requires_current_hierarchy_evidence():
    # Historical action still pending but absent from fresh hierarchy cannot be dispatched.
    root=screen(0,2);reduced=screen(0,0)
    r=run([root,reduced,reduced],base=1,hard=5)
    assert r.steps_attempted==1 and r.stop_reason=='frontier_stagnated'
