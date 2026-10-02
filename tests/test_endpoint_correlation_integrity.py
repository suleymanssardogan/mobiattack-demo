"""D4 identity and evidence integrity regressions. No devices or network calls."""
import copy
import json

import pytest

from src.dynamic.correlation.api_correlator import correlate_static_dynamic_apis as correlate
from src.dynamic.correlation.models import ApiCorrelationResult
from src.dynamic.context import build_endpoint_contexts
from src.dynamic.traffic.models import TrafficEvidenceArtifact, ActionTrafficEvidence
from src.dynamic.runtime.models import RuntimeEvidenceArtifact, RuntimeActionEvidence


def candidate(scheme='https', port=None, path='/users/{id}', method='GET'):
    authority='api.example.com' + (f':{port}' if port is not None else '')
    return {'base_url':f'{scheme}://{authority}', 'path':path,'method':method,
            'framework':'Retrofit','source_file':'smali/Service.smali','request_line':10}


def transaction(scheme='https', port=None, path='/users/1', method='GET', tid='tx1', session='s'):
    return {'transaction_id':tid,'session_id':session,'request':{'scheme':scheme,'host':'api.example.com',
        'port':port,'method':method,'path':path,'timestamp':'2026-10-02T12:00:00Z',
        'headers':{'authorization':'[REDACTED]'},'body_metadata':{},'query':{}},
        'response':{'status_code':200,'headers':{},'body_metadata':{}}}


def context(static,txs,**kwargs):
    corr=correlate(static,txs,session_id='s',**kwargs)
    return corr,build_endpoint_contexts(corr,txs)


@pytest.mark.parametrize('static_scheme,dynamic_scheme',[('http','https'),('https','http')])
def test_protocol_mismatch_is_not_correlated(static_scheme,dynamic_scheme):
    corr, artifact=context([candidate(static_scheme)],[transaction(dynamic_scheme)])
    assert {e.match_type for e in corr.correlations}=={'static_only','dynamic_only'}
    assert len({e.endpoint_context_id for e in artifact.endpoints})==2


@pytest.mark.parametrize('static_port,dynamic_port',[(8443,443),(443,8443),(8443,9443)])
def test_nondefault_port_mismatch_is_not_correlated(static_port,dynamic_port):
    corr, artifact=context([candidate(port=static_port)],[transaction(port=dynamic_port)])
    assert corr.summary.correlated_count==0
    assert len({e.endpoint_context_id for e in artifact.endpoints})==2


@pytest.mark.parametrize('scheme,default',[('http',80),('https',443)])
@pytest.mark.parametrize('explicit_side',['static','dynamic','both','neither'])
def test_default_port_normalization(scheme,default,explicit_side):
    static_port=default if explicit_side in ('static','both') else None
    dynamic_port=default if explicit_side in ('dynamic','both') else None
    corr,artifact=context([candidate(scheme,static_port)],[transaction(scheme,dynamic_port)])
    assert corr.correlations[0].match_type=='template'
    assert artifact.endpoints[0].port==default
    assert artifact.endpoints[0].scheme==scheme
    assert artifact.endpoints[0].dynamic['observed']


def test_same_nondefault_port_and_serialized_transport():
    corr,artifact=context([candidate(port=8443)],[transaction(port=8443)])
    loaded=ApiCorrelationResult.from_dict(corr.to_dict())
    assert loaded.correlations[0].scheme=='https' and loaded.correlations[0].port==8443
    assert build_endpoint_contexts(loaded,[transaction(port=8443)]).endpoints[0].endpoint_context_id==artifact.endpoints[0].endpoint_context_id


def test_context_id_stable_under_reorder_and_enrichment():
    one=candidate(path='/signup',method='POST')
    two=candidate(path='/other')
    _,before=context([one,two],[])
    _,reordered=context([two,one],[])
    tx=transaction(path='/signup',method='POST')
    _,after=context([one,two],[tx])
    def identity(artifact): return next(e.endpoint_context_id for e in artifact.endpoints if e.path=='/signup')
    assert identity(before)==identity(reordered)==identity(after)


def test_unknown_static_method_id_not_changed_by_dynamic_method():
    static=candidate(path='/signup',method=None)
    _,before=context([static],[])
    _,after=context([static],[transaction(path='/signup',method='POST')])
    assert before.endpoints[0].endpoint_context_id==after.endpoints[0].endpoint_context_id


def test_dynamic_only_distinct_methods_do_not_merge_or_change_id():
    _,one=context([],[transaction(method='GET')])
    _,two=context([],[transaction(method='GET'),transaction(method='POST',tid='tx2')])
    assert len(two.endpoints)==2
    assert one.endpoints[0].endpoint_context_id==next(e.endpoint_context_id for e in two.endpoints if e.methods==['GET'])


def test_static_template_identity_stable_as_more_concrete_evidence_arrives():
    _,one=context([candidate()],[transaction()])
    _,two=context([candidate()],[transaction(),transaction(path='/users/2',tid='tx2')])
    assert one.endpoints[0].endpoint_context_id==two.endpoints[0].endpoint_context_id
    assert two.endpoints[0].dynamic['observation_count']==2


def chain(traffic_session='s',runtime_session='s',runtime_source='route1'):
    traffic=TrafficEvidenceArtifact(session_id=traffic_session,actions=[ActionTrafficEvidence(
        action_id='act1',source_node_id='route1',target_node_id='route2',transaction_ids=['tx1'])])
    runtime=RuntimeEvidenceArtifact(session_id=runtime_session,actions=[RuntimeActionEvidence(
        action_id='act1',source_node_id=runtime_source,target_node_id='route2',fatal_appeared=True)])
    tx=transaction()
    corr=correlate([candidate()],[tx],session_id='s',traffic_evidence=traffic)
    return corr,[tx],traffic,runtime


def test_valid_chain_preserves_action_route_runtime_refs():
    e=build_endpoint_contexts(*chain()).endpoints[0]
    assert e.evidence_refs['transaction_ids']==['tx1']
    assert e.evidence_refs['action_ids']==['act1']
    assert e.evidence_refs['runtime_action_ids']==['act1']
    assert e.runtime_context['fatal_observed']
    assert e.route_context[0]['source_node_id']=='route1'


@pytest.mark.parametrize('traffic_session,runtime_session,source',[
    ('foreign','s','route1'),('s','foreign','route1'),('s','s','foreign_route')])
def test_cross_session_or_unrelated_runtime_route_rejected(traffic_session,runtime_session,source):
    e=build_endpoint_contexts(*chain(traffic_session,runtime_session,source)).endpoints[0]
    assert not e.runtime_context['fatal_observed']
    assert not e.evidence_refs['runtime_action_ids']
    if traffic_session!='s':
        assert not e.action_context and not e.route_context and not e.evidence_refs['action_ids']


def test_builder_rejects_foreign_evidence_even_if_correlation_previously_had_routes():
    corr,txs,traffic,runtime=chain()
    traffic.session_id='foreign'
    e=build_endpoint_contexts(corr,txs,traffic,runtime).endpoints[0]
    assert not e.action_context and not e.route_context and not e.evidence_refs['runtime_action_ids']


def test_corrupt_route_link_rejected():
    corr,txs,traffic,runtime=chain()
    traffic.actions[0].source_node_id='unrelated'
    e=build_endpoint_contexts(corr,txs,traffic,runtime).endpoints[0]
    assert not e.evidence_refs['action_ids'] and not e.evidence_refs['runtime_action_ids']


@pytest.mark.parametrize('corruption',['missing','empty_request','host','path','method','scheme','port','session','duplicate','bad_response'])
def test_missing_or_invalid_payload_cannot_be_observed(corruption):
    corr,txs,traffic,runtime=chain()
    if corruption=='missing': txs=[]
    elif corruption=='empty_request':txs[0]['request']={}
    elif corruption=='session':txs[0]['session_id']='foreign'
    elif corruption=='duplicate':txs.append(copy.deepcopy(txs[0]))
    elif corruption=='bad_response':txs[0]['response']='invalid'
    else:
        txs[0]['request'][corruption]={'host':'other.example.com','path':'/different','method':'DELETE',
            'scheme':'http','port':9999}[corruption]
    e=build_endpoint_contexts(corr,txs,traffic,runtime).endpoints[0]
    assert not e.dynamic['observed']
    assert e.dynamic['observation_count']==0
    assert e.dynamic['missing_transaction_ids']==['tx1']
    assert not e.evidence_refs['transaction_ids']
    assert not e.evidence_refs['action_ids'] and not e.evidence_refs['runtime_action_ids']
    assert not e.response['observed_status_codes']
    assert 'unavailable' in e.dynamic['note']
    assert e.visibility['https_visibility']=='unavailable'


@pytest.mark.parametrize('path,value',[('/users/{id}','123'),('/users/:id','abc'),('/users/<id>','550e8400-e29b-41d4-a716-446655440000')])
def test_template_rules_preserved(path,value):
    corr,_=context([candidate(path=path)],[transaction(path='/users/'+value)])
    assert corr.correlations[0].match_type=='template' and corr.correlations[0].confidence=='medium'


def test_literal_numeric_mismatch_and_exact_confidence_preserved():
    corr,_=context([candidate(path='/users/123')],[transaction(path='/users/456')])
    assert corr.summary.correlated_count==0
    corr,_=context([candidate(path='/users/123')],[transaction(path='/users/123')])
    assert corr.correlations[0].match_type=='exact' and corr.correlations[0].confidence=='high'


def test_unknown_protocol_is_not_guessed():
    corr=correlate([{'host':'api.example.com','path':'/users/1','method':'GET'}],[transaction()],session_id='s')
    assert corr.summary.correlated_count==0


def test_cross_session_transaction_not_consumed_by_correlator():
    corr=correlate([candidate()],[transaction(session='foreign')],session_id='s')
    assert corr.summary.correlated_count==0 and corr.summary.dynamic_only_count==0


@pytest.mark.parametrize("host", ["::1", "::80", "::443"])
def test_ipv6_authority_and_port_identity_stable(host):
    static = candidate(port=8443)
    static['base_url'] = f'https://[{host}]:8443'
    tx = transaction(port=8443)
    tx['request']['host'] = host
    corr, enriched = context([static], [tx])
    _, before = context([static], [])
    assert corr.summary.correlated_count == 1
    assert before.endpoints[0].endpoint_context_id == enriched.endpoints[0].endpoint_context_id
    assert enriched.endpoints[0].port == 8443


@pytest.mark.parametrize('bad', [{}, {'transaction_id':'tx_bad','request':{}},
                               {'transaction_id':'tx_bad','request':'corrupt'}])
def test_corrupt_traffic_does_not_manufacture_endpoint_or_refs(bad):
    corr, artifact = context([candidate()], [bad])
    assert corr.summary.dynamic_only_count == 0
    assert not artifact.endpoints[0].dynamic['observed']
    assert artifact.endpoints[0].evidence_refs['transaction_ids'] == []


def test_method_mismatch_semantics_preserved_after_transport_hardening():
    corr, artifact = context([candidate(method='GET')], [transaction(method='POST')])
    assert corr.correlations[0].match_type == 'method_mismatch'
    assert corr.correlations[0].confidence == 'low'
    assert artifact.endpoints[0].methods == ['GET', 'POST']
    assert artifact.endpoints[0].dynamic['observed']
