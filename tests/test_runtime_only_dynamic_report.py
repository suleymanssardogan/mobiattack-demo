"""Startup evidence survives UI failure without inventing exploration."""
import copy
import json
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

import pytest
from src.dynamic.report import build_dynamic_analysis_report, generate_dynamic_analysis_report, validate_dynamic_analysis_report, DynamicReportError
from src.dynamic.runtime.availability import availability
from src.dynamic.ui.observer import observe_screen, UIObservationError
from src.dynamic.exploration.loop import run_exploration
from src.dynamic.route.graph import RouteGraph

@pytest.fixture
def startup():
    return {'session': {'session_id':'session-current','package_name':'com.example.app','status':'ACTIVE'},
        'preflight': {'status':'PASS','application':{'package_name':'com.example.app','installed':True,'process_running':True,'foreground':True},'runtime':{'launch_success':True,'pid':42}},
        'runtime_availability': availability('SUPPORTED',status='available',package_name='com.example.app',evidence={'source':'runtime_launcher','pid':42,'process_survived':True,'foreground_verified':True}),
        'exploration': {'status':'partial','stop_reason':'observation_failed','steps_attempted':0,'screens_observed':0,'actions_succeeded':0,'actions_failed':0,'transitions_recorded':0,'metadata':{'frontier':{'observation_available':False}}}}

def test_runtime_only_report_persists_without_fake_counts(tmp_path,startup):
    from src.dynamic.report.generator import ARTIFACTS
    before=copy.deepcopy(startup)
    for key,value in startup.items():
        p=tmp_path/'dynamic'/ARTIFACTS[key];p.parent.mkdir(exist_ok=True);p.write_text(json.dumps(value))
    report=generate_dynamic_analysis_report(tmp_path)
    assert report['analysis_coverage']=='partial'
    assert report['coverage']['ui_exploration']=='unavailable'
    assert report['coverage']['runtime_observation']=='partial'
    assert report['exploration']['status']=='partial'
    assert report['exploration']['screens_observed']==report['exploration']['steps_attempted']==0
    assert report['endpoint_contexts']==[] and report['traffic']['total_transactions']==0
    assert report['runtime_availability']==startup['runtime_availability']
    assert 'startup evidence preserved' in report['exploration']['note']
    assert startup==before
    assert (tmp_path/'dynamic_analysis_report.json').exists()

@pytest.mark.parametrize('change',['missing','wrong_package','no_foreground','no_process','launch_only'])
def test_unproven_startup_cannot_bypass_execution_requirement(startup,change):
    if change=='missing': startup.pop('runtime_availability')
    elif change=='wrong_package': startup['runtime_availability']['package_name']='other.app'
    elif change=='launch_only': startup['runtime_availability']['evidence']={'source':'runtime_launcher','launch_succeeded':True}
    else: startup['runtime_availability']['evidence']['foreground_verified' if change=='no_foreground' else 'process_survived']=False
    with pytest.raises((DynamicReportError,ValueError)):
        build_dynamic_analysis_report('current',startup)

def test_report_validator_rechecks_runtime_proof(startup):
    report=build_dynamic_analysis_report('current',startup)
    report['runtime_availability']['evidence']['foreground_verified']=False
    with pytest.raises(DynamicReportError): validate_dynamic_analysis_report(report)

def test_successful_exploration_not_reclassified(startup):
    startup['exploration'].update(status='completed',stop_reason='completed',screens_observed=1,metadata={'frontier':{'observation_available':True,'safe_frontier_exhausted':True,'safe_actions_remaining':0}})
    report=build_dynamic_analysis_report('current',startup)
    assert report['exploration']['status']=='completed' and report['coverage']['ui_exploration']=='available'

def test_completed_dump_at_deadline_is_not_discarded():
    now=[0.0]
    def dump(**kwargs):
        now[0]=4.0
        return ET.fromstring('<hierarchy><node package="com.example.app" class="android.view.View" bounds="[0,0][10,10]" /></hierarchy>')
    with patch('src.dynamic.ui.observer.get_current_activity',return_value={'observed_package':'com.example.app'}),patch('src.dynamic.ui.observer.dump_window_hierarchy',side_effect=dump) as call:
        obs=observe_screen('fake',target_package='com.example.app',clock=lambda:now[0])
    assert len(obs.nodes)==1 and call.call_count==1

def test_failed_dumps_are_bounded_without_actions():
    now=[0.0]
    def dump(**kwargs): now[0]+=1;raise UIObservationError('not available')
    with patch('src.dynamic.ui.observer.get_current_activity',return_value={}),patch('src.dynamic.ui.observer.dump_window_hierarchy',side_effect=dump) as call:
        with pytest.raises(UIObservationError): observe_screen('fake',max_attempts=2,clock=lambda:now[0],sleeper=lambda n:None)
    assert call.call_count==2

def test_initial_ui_failure_is_partial_and_never_dispatches():
    observer=Mock(side_effect=UIObservationError('deadline exhausted'))
    executor=Mock()
    graph=RouteGraph()
    result=run_exploration(observer=observer,executor=executor,route_graph=graph)
    assert result.status=='partial' and result.stop_reason=='observation_failed'
    assert result.steps_attempted==result.screens_observed==result.actions_succeeded==0
    assert graph.node_count==0
    assert not executor.mock_calls
    observer.assert_called_once()

def test_empty_hierarchy_is_not_a_screen():
    with patch('src.dynamic.ui.observer.get_current_activity',return_value={'observed_package':'com.example.app'}),patch('src.dynamic.ui.observer.dump_window_hierarchy',return_value=ET.fromstring('<hierarchy/>')) as dump:
        with pytest.raises(UIObservationError): observe_screen('fake',target_package='com.example.app',max_attempts=2,sleeper=lambda n:None)
    assert dump.call_count==2
