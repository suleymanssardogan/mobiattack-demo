"""Navigation-only discovery, state identity and bounded frontier regressions."""
import xml.etree.ElementTree as ET
from unittest.mock import Mock
import pytest
from src.dynamic.ui.observer import parse_ui_hierarchy
from src.dynamic.route.graph import RouteGraph
from src.dynamic.exploration.loop import run_exploration
from src.dynamic.exploration.models import ExplorationLimits, navigation_skip_reason
from src.dynamic.action.models import ActionExecutionResult
from tests.test_dynamic_exploration_loop import _make_obs, _make_candidate


def observe(xml):
    return parse_ui_hierarchy(ET.fromstring(xml), 'app', 'app.Main', 'app')


def test_clickable_parent_uses_child_caption_without_duplicate_action():
    obs=observe('<hierarchy><node class="android.widget.LinearLayout" clickable="true" enabled="true" resource-id="app:id/row" bounds="[0,0][200,100]"><node class="android.widget.TextView" text="About" clickable="false" bounds="[0,0][100,50]"/></node></hierarchy>')
    assert len(obs.action_candidates)==1
    assert obs.action_candidates[0].text=='About'
    route=RouteGraph().observe_screen(obs)
    assert navigation_skip_reason(next(iter(route.actions.values()))) is None


def test_parent_does_not_inherit_password_or_input_values():
    obs=observe('<hierarchy><node clickable="true" bounds="[0,0][100,100]"><node class="android.widget.EditText" password="true" text="secret" bounds="[0,0][50,50]"/></node></hierarchy>')
    assert obs.action_candidates[0].text==''


@pytest.mark.parametrize('label',['Open menu','Navigation drawer','About','Close','Details','Tabs'])
def test_toolbar_menu_dialog_controls_remain_discoverable(label):
    xml=f'<hierarchy><node class="android.widget.Button" clickable="true" enabled="true" content-desc="{label}" bounds="[1,2][99,80]"/></hierarchy>'
    assert len(observe(xml).action_candidates)==1


def test_disabled_invisible_and_arbitrary_views_are_not_actions():
    assert observe('<hierarchy><node clickable="true" enabled="false" bounds="[0,0][50,50]"/><node clickable="true" visible-to-user="false" bounds="[0,0][50,50]"/><node clickable="false" text="Menu" bounds="[0,0][50,50]"/></hierarchy>').action_candidates==[]


def test_accessibility_only_actions_report_unsupported_without_fake_tap():
    obs=observe('<hierarchy><node clickable="false" actions="ACTION_CLICK" bounds="[0,0][100,100]"/></hierarchy>')
    assert obs.action_candidates==[] and 'Accessibility-only' in obs.diagnostics[0]


def test_geometry_jitter_does_not_create_new_visited_state_or_action():
    xml='<hierarchy><node class="android.widget.Button" resource-id="app:id/menu" content-desc="Menu" clickable="true" bounds="[0,0][100,100]"/></hierarchy>'
    first=observe(xml);second=observe(xml.replace('[0,0][100,100]','[45,75][200,250]'))
    assert first.screen_identity==second.screen_identity
    assert first.action_candidates[0].node_id==second.action_candidates[0].node_id
    assert first.action_candidates[0].bounds!=second.action_candidates[0].bounds


@pytest.mark.parametrize('flag',['checked','selected','enabled'])
def test_same_screen_semantic_state_change_is_detected(flag):
    xml=f'<hierarchy><node class="android.widget.Button" clickable="true" {flag}="false" bounds="[0,0][50,50]"/></hierarchy>'
    assert observe(xml).screen_identity!=observe(xml.replace(f'{flag}="false"',f'{flag}="true"')).screen_identity


@pytest.mark.parametrize('label',['Login','Submit','Send message','Purchase','Delete account','Confirm','Do something','Secure root check'])
def test_unsafe_or_uncertain_controls_never_dispatch(label):
    c=_make_candidate(text=label);c.content_desc=''
    executor=Mock();graph=RouteGraph()
    result=run_exploration(lambda:_make_obs(actions=[c]),executor,graph,limits=ExplorationLimits(max_steps=2))
    executor.click.assert_not_called()
    assert result.stop_reason=='unsafe_action_boundary' and result.status=='completed'
    assert result.metadata['frontier']['unsafe_skipped']==1
    assert result.metadata['frontier']['safe_frontier_exhausted']
    assert result.metadata['skipped_actions']


def test_toggle_with_navigation_caption_is_not_automatically_executed():
    obs=observe('<hierarchy><node class="android.view.View" clickable="true" checkable="true" text="Menu" bounds="[0,0][100,100]"/></hierarchy>')
    assert obs.action_candidates[0].action_type=='toggle'


def test_frontier_not_exhausted_does_not_report_completed():
    root=_make_obs('root',actions=[_make_candidate('a'),_make_candidate('b')]);child=_make_obs('child')
    executor=Mock();executor.click.return_value=ActionExecutionResult(action_id='a',action_type='click',status='succeeded',started_at='2026-10-03T00:00:00Z',completed_at='2026-10-03T00:00:01Z')
    graph=RouteGraph();result=run_exploration(lambda:child,executor,graph,initial_observation=root,limits=ExplorationLimits(max_steps=3))
    assert result.status=='partial' and not result.metadata['safe_frontier_exhausted']
    assert graph.edge_count==1


def test_repeated_state_does_not_reexecute_attempted_action():
    root=_make_obs('root',actions=[_make_candidate('menu')]);executor=Mock()
    executor.click.return_value=ActionExecutionResult(action_id='a',action_type='click',status='succeeded',started_at='2026-10-03T00:00:00Z',completed_at='2026-10-03T00:00:01Z')
    graph=RouteGraph();result=run_exploration(lambda:root,executor,graph,initial_observation=root,limits=ExplorationLimits(max_steps=20),no_navigation_postcondition=lambda obs:True)
    assert executor.click.call_count==1 and result.stop_reason=='no_actions'
    assert result.metadata['safe_frontier_exhausted'] and graph.edge_count==1


def test_control_caption_change_is_meaningful_but_clock_counter_is_not():
    xml='<hierarchy><node class="android.widget.Button" clickable="true" text="Menu 10" bounds="[0,0][50,50]"/></hierarchy>'
    assert observe(xml).screen_identity==observe(xml.replace('Menu 10','Menu 11')).screen_identity
    assert observe(xml).screen_identity!=observe(xml.replace('Menu 10','Logout')).screen_identity


def test_visibility_changes_visited_state():
    xml='<hierarchy><node class="android.widget.Button" clickable="true" visible-to-user="true" bounds="[0,0][50,50]"/></hierarchy>'
    assert observe(xml).screen_identity!=observe(xml.replace('visible-to-user="true"','visible-to-user="false"')).screen_identity


def test_parent_navigation_description_does_not_hide_unsafe_child_caption():
    obs=observe('<hierarchy><node clickable="true" content-desc="Menu" bounds="[0,0][100,100]"><node class="android.widget.TextView" text="Submit" bounds="[0,0][50,50]"/></node></hierarchy>')
    action=next(iter(RouteGraph().observe_screen(obs).actions.values()))
    assert navigation_skip_reason(action)=='SIDE_EFFECT_BOUNDARY'


def test_parent_caption_change_changes_visited_state():
    xml='<hierarchy><node clickable="true" bounds="[0,0][100,100]"><node class="android.widget.TextView" text="About" bounds="[0,0][50,50]"/></node></hierarchy>'
    assert observe(xml).screen_identity!=observe(xml.replace('About','Logout')).screen_identity
