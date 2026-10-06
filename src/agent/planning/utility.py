"""Pure deterministic priority estimates; no policy/execution/finding authority.

Factors are bounded 0..100. Coverage/information/cost are fixed conservative
planning priors, not measured security impact. Missing evidence lowers confidence.
Duplicate IDs are caller-owned CURRENT-PASS context, not learned/history state.
"""
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from types import MappingProxyType

from src.agent.models import ContractError
from src.agent.policy import EvidenceRecord, PreconditionRecord, _linked
from src.agent.test_catalog import TEST_CATALOG
from src.agent.test_planner import TestPlannerResult, build_test_planner_input
from src.agent.test_planner.validation import validate_model_output
from .goals import GOAL_RELEVANCE, SUPPORTED_PRIMITIVES, resolve_goal

UTILITY_VERSION = 'utility_v1'
RISK = MappingProxyType({'passive': 0, 'low': 25, 'medium': 60, 'high': 85, 'destructive': 100})
COST = MappingProxyType({'AUTHENTICATION_PRESENCE': 10, 'OBJECT_AUTHORIZATION': 60,
        'FUNCTION_AUTHORIZATION': 75, 'SESSION_HANDLING': 40})
COVERAGE = MappingProxyType({'AUTHENTICATION_PRESENCE': 35, 'OBJECT_AUTHORIZATION': 80,
            'FUNCTION_AUTHORIZATION': 80, 'SESSION_HANDLING': 65})


@dataclass(frozen=True)
class UtilityFactors:
    goal_relevance: int
    evidence_strength: int
    expected_coverage_gain: int
    expected_information_gain: int
    execution_risk: int
    execution_cost: int
    duplicate_work_penalty: int

    def __post_init__(self):
        if any(type(v) is not int or not 0 <= v <= 100 for v in asdict(self).values()):
            raise ContractError('Utility factors must be bounded integers')

    @property
    def score(self):
        return (4 * self.goal_relevance + 2 * self.evidence_strength + self.expected_coverage_gain
                + self.expected_information_gain - 2 * self.execution_risk
                - self.execution_cost - 2 * self.duplicate_work_penalty)


@dataclass(frozen=True)
class RankedCandidate:
    proposal_id: str
    test_id: str
    factors: UtilityFactors
    confidence: int
    missing_context: tuple[str, ...]

    @property
    def utility(self): return self.factors.score

    @property
    def confidence_category(self):
        return 'high' if self.confidence >= 75 else 'medium' if self.confidence >= 40 else 'low'

    def to_dict(self):
        return {**asdict(self), 'utility': self.utility, 'confidence_category': self.confidence_category}


@dataclass(frozen=True)
class UtilityRanking:
    goal_id: str
    endpoint_context_id: str
    candidates: tuple[RankedCandidate, ...]
    utility_version: str = UTILITY_VERSION

    @property
    def proposal_order(self): return tuple(c.proposal_id for c in self.candidates)

    def to_dict(self):
        return {'goal_id': self.goal_id, 'endpoint_context_id': self.endpoint_context_id,
                'utility_version': self.utility_version, 'priority_only': True,
                'candidates': [c.to_dict() for c in self.candidates]}


def rank_candidates(goal, context, analyst, planner, *, evidence_index,
                    precondition_index=None, duplicate_proposal_ids=()):
    goal = resolve_goal(goal, context)
    planner = TestPlannerResult.from_dict(planner.to_dict())
    if planner.endpoint_context_id != context.endpoint_context_id or planner.status not in {'completed', 'no_relevant_tests'}:
        raise ContractError('Unavailable/mismatched candidate plan')
    source = build_test_planner_input(context, analyst, catalog_test_ids=goal.test_ids)
    # Revalidate semantic grounding; the scorer cannot elevate arbitrary proposals.
    validate_model_output(json.loads(json.dumps({'schema_version': '1.0', 'endpoint_context_id': context.endpoint_context_id,
                           'proposals': [p.to_dict() for p in planner.proposals]})), source,
                          created_at=planner.created_at, metadata=planner.model_metadata, attempts=planner.attempts)
    if (not isinstance(duplicate_proposal_ids, (tuple, list, set, frozenset))
            or len(duplicate_proposal_ids) > 16
            or any(not isinstance(pid, str) for pid in duplicate_proposal_ids)
            or not set(duplicate_proposal_ids).issubset({p.proposal_id for p in planner.proposals})):
        raise ContractError('Invalid current-pass duplicate context')
    index = evidence_index if isinstance(evidence_index, Mapping) else {}
    prereqs = precondition_index if isinstance(precondition_index, Mapping) else {}
    verified = {ref for ref in source.evidence_refs if isinstance(index.get(ref), EvidenceRecord)
                and index[ref].reference == ref and _linked(index[ref], context)}
    safe = source.context
    auth_known = sum(v is not None for v in safe['auth_context'].values())
    baseline = (safe['dynamic_context']['runtime_confirmed'] is True
                and safe['coverage']['traffic_available'] is not False
                and bool(set(safe['evidence_refs']['transactions']) & verified))
    results = []
    for p in planner.proposals:
        if p.test_id not in SUPPORTED_PRIMITIVES:
            raise ContractError('Unsupported validation primitive')
        missing = []
        for name in p.required_context:
            if name == 'auth':
                satisfied = auth_known > 0
            elif name == 'dynamic.observed':
                satisfied = baseline
            else:
                record = prereqs.get(name)
                satisfied = (isinstance(record, PreconditionRecord) and record.name == name
                             and record.endpoint_context_id == context.endpoint_context_id
                             and set(record.evidence_refs).issubset(verified))
            if not satisfied: missing.append(name)
        strength = (50 * len(set(p.evidence_refs) & verified) // len(set(p.evidence_refs))
                    + 25 * int(baseline) + 25 * auth_known // len(safe['auth_context']))
        confidence = max(0, strength - 10 * min(10, len(missing)) - 5 * min(10, len(source.coverage_gaps)))
        duplicate = p.proposal_id in duplicate_proposal_ids
        factors = UtilityFactors(GOAL_RELEVANCE[goal.goal_type][p.test_id], strength,
            0 if duplicate else COVERAGE[p.test_id],
            min(100, 40 + 10 * (len(safe['auth_context']) - auth_known) + 5 * min(8, len(source.coverage_gaps))),
            RISK[TEST_CATALOG[p.test_id].risk_class], COST[p.test_id], 100 if duplicate else 0)
        results.append(RankedCandidate(p.proposal_id, p.test_id, factors, confidence, tuple(sorted(missing))))
    return UtilityRanking(goal.goal_id, context.endpoint_context_id,
                          tuple(sorted(results, key=lambda c: (-c.utility, c.proposal_id))))
