import json
from copy import deepcopy

import pytest

from src.dynamic.runtime.function_observation import (
    FunctionTarget, InvocationWindow, build_invocation_observation, unavailable_observation)

TARGET = FunctionTarget('sg.vantagepoint.mstgkotlin.MainActivity', 'toggleFlag')
WINDOW = InvocationWindow('session_1', 'node_1', 'act_1', '2026-10-02T10:00:00+00:00', '2026-10-02T10:00:05+00:00')
EVENT = dict(source_kind='method_entry', mechanism='jdwp_method_entry', source_evidence_ref='fixture_event_1',
    class_name=TARGET.class_name, method_name=TARGET.method_name, session_id='session_1', route_id='node_1',
    action_id='act_1', timestamp='2026-10-02T10:00:02+00:00', invocation_count=1,
    argument_metadata=[{'type':'boolean','presence':'present'}, {'type':'object','presence':'present'}],
    return_metadata={'type':'boolean','presence':'present'})


def build(**changes):
    data=deepcopy(EVENT)
    data.update(changes)
    return build_invocation_observation(TARGET, WINDOW, **data)


def test_explicit_fixture_method_event_has_safe_temporal_provenance():
    data=build()
    assert data['invocation_count']==1
    assert data['session_id']==WINDOW.session_id and data['route_id']==WINDOW.route_id
    assert data['action_id']==WINDOW.action_id
    assert data['source_evidence_ref']=='fixture_event_1'
    assert data['caused_by_action']=='unknown'
    assert data['semantics']=='runtime_observation_only'
    assert data['return_metadata']=={'type':'boolean','presence':'present'}
    assert not set(data) & {'finding','severity','vulnerability','confirmed'}


@pytest.mark.parametrize('key,value', [
    ('source_kind','activity_transition'), ('source_kind','ui_action'), ('source_kind','generic_log'),
    ('mechanism','frida'), ('class_name','org.other.Class'), ('method_name','different'),
    ('session_id','another'), ('route_id','another'), ('action_id','another'),
    ('source_evidence_ref',''), ('timestamp','2026-10-02T10:00:06+00:00'),
    ('timestamp','2026-10-02T09:59:59+00:00'), ('timestamp','invalid'),
    ('invocation_count',0), ('invocation_count',1001), ('invocation_count',True)])
def test_invalid_or_inferred_evidence_rejected(key,value):
    with pytest.raises(ValueError):
        build(**{key:value})


@pytest.mark.parametrize('secret_field', ['value','password','token','cookie','credentials','raw_return','payload'])
def test_raw_argument_and_return_values_rejected(secret_field):
    unsafe={'type':'string','presence':'present',secret_field:'secret-that-must-not-persist'}
    with pytest.raises(ValueError):
        build(argument_metadata=[unsafe])
    with pytest.raises(ValueError):
        build(return_metadata=unsafe)


def test_shape_only_no_arbitrary_keys_or_type_names():
    data=build(argument_metadata=[{'type':'string','presence':'present','length':12},
                                 {'type':'object','presence':'unknown','item_count':2}],return_metadata=None)
    assert data['return_metadata'] is None
    with pytest.raises(ValueError):
        build(argument_metadata=[{'type':'secret-token','presence':'present'}])
    with pytest.raises(ValueError):
        build(argument_metadata=[{'type':'object','presence':'present','keys':['token']}])


@pytest.mark.parametrize('args', [[{'type':'unknown','presence':'unknown'}]*17,
    [{'type':'string','presence':'present','length':-1}],
    [{'type':'object','presence':'present','item_count':1000001}],
    [{'type':'string','presence':'secret'}]])
def test_metadata_bounds(args):
    with pytest.raises(ValueError):
        build(argument_metadata=args)


def test_unavailable_is_coverage_gap_not_negative_evidence_or_finding():
    data=unavailable_observation(TARGET,WINDOW)
    assert data['status']=='unavailable' and data['observations']==[]
    assert not data['instrumentation_enabled']
    assert 'no_observed_invocation_does_not_mean_method_never_executed' in data['coverage_gaps']
    assert data['window']['action_id']==WINDOW.action_id
    assert 'finding' not in json.dumps(data)


def test_reference_deterministic_and_source_specific():
    assert build()['evidence_ref']==build()['evidence_ref']
    assert build(source_evidence_ref='fixture_event_2')['evidence_ref']!=build()['evidence_ref']


def test_contract_copies_metadata_before_persistence():
    args=[{'type':'string','presence':'unknown'}]
    data=build(argument_metadata=args)
    args[0]['value']='secret'
    assert 'secret' not in json.dumps(data)


def test_provenance_and_window_validation():
    with pytest.raises(ValueError):
        InvocationWindow('', 'r', 'a',WINDOW.started_at,WINDOW.ended_at)
    with pytest.raises(ValueError):
        InvocationWindow('s','r','a',WINDOW.ended_at,WINDOW.started_at)
    with pytest.raises(ValueError):
        InvocationWindow('s','r','a','2026-10-02T10:00:00',WINDOW.ended_at)
    with pytest.raises(ValueError):
        FunctionTarget('/host/secret','method')


def test_observation_window_is_bounded():
    with pytest.raises(ValueError):
        InvocationWindow('s','r','a',WINDOW.started_at,'2026-10-02T10:01:00+00:00')
