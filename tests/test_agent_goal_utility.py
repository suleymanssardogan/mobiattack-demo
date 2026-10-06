"""Pure ranking and controlled offline pipeline; no live models/HTTP requests."""
from dataclasses import replace
from copy import deepcopy
from unittest.mock import patch
import json
import pytest

from src.agent.models import ContractError
from src.agent.planning.goals import PlanningGoal, GOAL_RELEVANCE, resolve_goal
from src.agent.planning.utility import rank_candidates, UtilityFactors
from src.agent.context_analyst import analyze_endpoint_context
from src.agent.test_planner import plan_endpoint_tests
from tests.context_analyst_fakes import FakeModelClient, TIME
from tests.test_planner_fakes import PlannerFake
from tests.test_agent_security_integration import controlled, run


def plans(controlled, goal=None):
    c = controlled[0]
    goal = resolve_goal(goal, c)
    analyst = analyze_endpoint_context(c, FakeModelClient(), goal=goal, created_at=TIME)
    planner = plan_endpoint_tests(c, analyst, PlannerFake(), goal=goal, created_at=TIME)
    return goal, analyst, planner


def rank(controlled, goal=None, **kwargs):
    g, a, p = plans(controlled, goal)
    return rank_candidates(g, controlled[0], a, p, evidence_index=kwargs.pop('evidence_index', controlled[4]),
                           precondition_index=kwargs.pop('precondition_index', controlled[5]), **kwargs)


@pytest.mark.parametrize('kind', sorted(GOAL_RELEVANCE))
def test_goal_roundtrip_and_scope(controlled, kind):
    goal = PlanningGoal(kind, controlled[0].endpoint_context_id)
    assert PlanningGoal.from_dict(goal.to_dict()) == goal
    assert goal.bind(controlled[0]) == goal
    assert set(goal.test_ids) <= {'AUTHENTICATION_PRESENCE', 'OBJECT_AUTHORIZATION', 'FUNCTION_AUTHORIZATION', 'SESSION_HANDLING'}


@pytest.mark.parametrize('kind,scope', [('fuzz', 'single_endpoint'), ('review_security_coverage', 'whole_scan')])
def test_unknown_goals_or_scope_rejected(kind, scope):
    with pytest.raises(ContractError): PlanningGoal(kind, 'ctx_1', scope)


def test_goal_mismatch_rejected_before_models(controlled):
    analyst = FakeModelClient(); planner = PlannerFake()
    with pytest.raises(ContractError):
        run(controlled, goal=PlanningGoal('assess_session_handling', 'ctx_other'),
            analyst_client=analyst, planner_client=planner)
    assert not analyst.requests and not planner.requests
    controlled[-2].run.assert_not_called()


def test_model_receives_goal_and_only_relevant_candidates(controlled):
    goal = PlanningGoal('assess_session_handling', controlled[0].endpoint_context_id)
    ac = FakeModelClient(); pc = PlannerFake()
    result = run(controlled, goal=goal, analyst_client=ac, planner_client=pc, controlled_lab=False)
    assert ac.requests[0].input_data['scan_goal'] == pc.requests[0].input_data['scan_goal'] == goal.to_dict()
    assert len(result.planner.proposals) >= 2
    assert {p.test_id for p in result.planner.proposals} <= set(goal.test_ids)
    assert result.goal == goal and result.ranking
    controlled[-2].run.assert_not_called()


def test_same_input_reorder_determinism_and_pure_no_network(controlled):
    g, a, p = plans(controlled)
    before = deepcopy(controlled[0])
    with patch('socket.socket') as socket, patch('subprocess.run') as process:
        r1 = rank_candidates(g, controlled[0], a, p, evidence_index=controlled[4], precondition_index=controlled[5])
        r2 = rank_candidates(g, controlled[0], a, replace(p, proposals=tuple(reversed(p.proposals))),
                             evidence_index=dict(reversed(list(controlled[4].items()))), precondition_index=controlled[5])
    assert r1 == r2 and controlled[0] == before
    assert r1.candidates[0].utility == max(c.utility for c in r1.candidates)
    socket.assert_not_called(); process.assert_not_called()
    assert all(0 <= c.confidence <= 100 for c in r1.candidates)
    assert all(0 <= f <= 100 for c in r1.candidates for f in c.to_dict()['factors'].values())


def test_policy_considers_highest_first_and_deny_overrides(controlled):
    controlled[0].request['query_keys'] = ['order_id']
    goal = PlanningGoal('assess_object_authorization', controlled[0].endpoint_context_id)
    import src.agent.policy_integration.service as gate
    order = []
    original = gate._evaluate
    def capture(proposal, *args, **kwargs):
        order.append(proposal['proposal_id'] if isinstance(proposal, dict) else proposal.proposal_id)
        return original(proposal, *args, **kwargs)
    with patch.object(gate, '_evaluate', side_effect=capture):
        result = run(controlled, goal=goal, controlled_lab=False)
    assert tuple(order) == result.ranking.proposal_order
    top = result.ranking.candidates[0]
    assert top.test_id == 'OBJECT_AUTHORIZATION'
    decision = next(d for d in result.policy.decisions if d.proposal_id == top.proposal_id)
    assert decision.decision == 'deny' and decision.reason_code == 'RISK_NOT_ALLOWED'
    assert result.policy.allow_count >= 1
    assert not result.executions and not result.artifacts
    controlled[-2].run.assert_not_called()


def test_needs_evidence_overrides_highest_utility(controlled):
    goal = PlanningGoal('assess_session_handling', controlled[0].endpoint_context_id)
    result = run(controlled, goal=goal, precondition_index={})
    assert result.ranking.candidates[0].test_id == 'SESSION_HANDLING'
    top = result.ranking.candidates[0].proposal_id
    assert next(d for d in result.policy.decisions if d.proposal_id == top).decision == 'needs_evidence'
    assert not result.executions and not result.artifacts
    controlled[-2].run.assert_not_called()


def test_utility_never_supplies_execution_or_finding_authority(controlled):
    result = run(controlled, goal=PlanningGoal('assess_session_handling', controlled[0].endpoint_context_id))
    controlled[-2].run.assert_called_once()  # Existing deterministic lab backend double.
    assert len(result.executions) == 1
    assert all(r['finding_created'] is False for r in result.security_report['results'])
    ranking = result.ranking.to_dict()
    assert ranking['priority_only'] is True
    assert 'approved_for_execution' not in ranking and 'finding' not in ranking
    assert result.to_dict()['utility_ranking'] == ranking
    assert result.policy.allow_count >= 1


def test_unknown_and_missing_evidence_reduce_confidence(controlled):
    full = rank(controlled)
    missing = rank(controlled, evidence_index={}, precondition_index={})
    by_id = {c.proposal_id: c for c in full.candidates}
    for c in missing.candidates:
        assert c.confidence < by_id[c.proposal_id].confidence
        assert c.factors.evidence_strength < by_id[c.proposal_id].factors.evidence_strength
        assert c.confidence_category == 'low'
    controlled[-2].run.assert_not_called()


def test_unknown_auth_reduces_strength_without_authenticated_claim(controlled):
    full = rank(controlled)
    controlled[0].auth['authorization_header_present'] = None
    controlled[0].auth['api_key_header_present'] = None
    partial = rank(controlled)
    by_test = {c.test_id: c for c in full.candidates}
    assert all(c.factors.evidence_strength < by_test[c.test_id].factors.evidence_strength for c in partial.candidates)
    assert all(0 <= c.confidence <= 100 for c in partial.candidates)


def test_duplicate_work_penalty_current_pass_only(controlled):
    initial = rank(controlled)
    pid = initial.candidates[0].proposal_id
    penalized = rank(controlled, duplicate_proposal_ids=(pid,))
    item = next(c for c in penalized.candidates if c.proposal_id == pid)
    assert item.utility < initial.candidates[0].utility
    assert item.factors.duplicate_work_penalty == 100 and item.factors.expected_coverage_gain == 0
    assert rank(controlled) == initial  # No retained memory/adaptation.
    with pytest.raises(ContractError): rank(controlled, duplicate_proposal_ids=('cross_endpoint',))


@pytest.mark.parametrize('bad', [-1, 101, True, 0.5])
def test_factor_bounds(bad):
    with pytest.raises(ContractError): UtilityFactors(bad, 0, 0, 0, 0, 0, 0)


def test_model_cannot_emit_final_utility_or_approval(controlled):
    def fake_score(data, request): data['utility'] = 99999; return data
    result = run(controlled, planner_client=PlannerFake(transform=fake_score))
    assert result.planner.status == 'invalid_output' and result.ranking is None
    controlled[-2].run.assert_not_called()


def test_goal_and_rank_trace_contains_no_raw_secret(controlled):
    controlled[0].auth['raw_token'] = 'PRIVATE_TOKEN'
    controlled[0].request['body'] = 'PRIVATE_PASSWORD'
    result = run(controlled, controlled_lab=False)
    assert 'PRIVATE_' not in json.dumps({'goal': result.goal.to_dict(), 'ranking': result.ranking.to_dict()})


def test_noncanonical_plan_or_unsupported_primitive_rejected(controlled):
    g, a, p = plans(controlled)
    p = replace(p, endpoint_context_id='ctx_other', proposals=(), coverage_gaps=(), status='no_relevant_tests')
    with pytest.raises(ContractError): rank_candidates(g, controlled[0], a, p, evidence_index=controlled[4])
    controlled[0].request['query_keys'] = ['order_id']
    goal = PlanningGoal('assess_authentication', controlled[0].endpoint_context_id)
    g2, a2, p2 = plans(controlled)
    with pytest.raises(ContractError):
        rank_candidates(goal, controlled[0], a2, p2, evidence_index=controlled[4])


def test_equal_utility_uses_stable_proposal_id_tiebreak(controlled, monkeypatch):
    import src.agent.planning.utility as scorer
    # Fixed bounded cost fixture creates a real tie, independent of input order.
    costs = dict(scorer.COST); costs['AUTHENTICATION_PRESENCE'] = 60
    monkeypatch.setattr(scorer, 'COST', costs)
    ranked = rank(controlled)
    assert len({c.utility for c in ranked.candidates}) == 1
    assert ranked.proposal_order == tuple(sorted(ranked.proposal_order))


def test_other_catalog_family_is_not_a_supported_primitive(controlled):
    c = controlled[0]; c.request['body_present'] = True; c.request['body_keys'] = ['search']
    analyst = analyze_endpoint_context(c, FakeModelClient(), created_at=TIME)
    full_catalog_plan = plan_endpoint_tests(c, analyst, PlannerFake(), created_at=TIME)
    assert any(p.test_id == 'INPUT_VALIDATION' for p in full_catalog_plan.proposals)
    with pytest.raises(ContractError):
        rank_candidates(resolve_goal(None, c), c, analyst, full_catalog_plan, evidence_index=controlled[4])


def test_bad_goal_catalog_cannot_be_silently_dropped(controlled):
    goal, analyst, _ = plans(controlled)
    with pytest.raises(ContractError):
        plan_endpoint_tests(controlled[0], analyst, PlannerFake(), goal=goal, catalog_test_ids=['MADE_UP'])
