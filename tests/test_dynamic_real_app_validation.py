"""Passive real-app validation report boundaries, without live device or Static work."""
from copy import deepcopy
import pytest
from tests.test_dynamic_analysis_report import sources, report
from src.web.report_summary import build_report_summary


def test_zero_observations_preserve_available_http_and_absence_uncertainty(sources):
    sources['traffic']['transactions']=[]
    sources['endpoint_contexts']['endpoints']=[]
    sources['traffic']['http_visibility']='available'
    sources['traffic']['https_visibility']='unavailable'
    r=report(sources)
    summary=build_report_summary(dynamic_report=r)['dynamic_summary']
    assert r['traffic']['http_visibility']=='available'
    assert r['traffic']['https_visibility']=='unavailable'
    assert 'No endpoints were observed in available traffic; this does not establish absence of network activity.' in summary['coverage_limitations']


@pytest.mark.parametrize('reason',['hard_step_ceiling','frontier_stagnated','deadline','repeated_state'])
def test_bounded_stops_remain_partial_and_frontier_visible(sources,reason):
    sources['exploration']['status']='partial';sources['exploration']['stop_reason']=reason
    sources['exploration']['metadata']={'budget':{'base_step_budget':6,'hard_step_ceiling':16,
        'actions_attempted':9,'adaptive_extension_used':True},'frontier':{
        'safe_actions_remaining':3,'safe_actions_discovered':12,'unsafe_skipped':2,
        'observation_available':True,'safe_frontier_exhausted':False}}
    r=report(sources)
    assert r['coverage']['ui_exploration']=='partial'
    assert r['exploration']['safe_actions_remaining']==3
    assert r['exploration']['adaptive_extension_used'] is True
    summary=build_report_summary(dynamic_report=r)['dynamic_summary']
    assert 'bounded extension yes' in summary['exploration_note']


def test_dynamic_can_report_without_static_candidates_or_contexts(sources):
    sources.pop('api_correlation',None);sources.pop('endpoint_contexts',None)
    r=report(sources)
    assert r['coverage']['endpoint_contexts']=='unavailable'
    assert r['endpoint_contexts']==[]


def test_report_generation_does_not_execute_validation_or_create_finding(sources):
    original=deepcopy(sources)
    r=report(sources)
    assert sources==original
    assert r.get('security_results',[])==[]
    assert not r.get('findings')
