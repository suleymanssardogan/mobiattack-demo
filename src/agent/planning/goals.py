"""Closed, endpoint-scoped goals. Goals express intent, never permission."""
from dataclasses import asdict, dataclass
from types import MappingProxyType

from src.agent.models import ContractError, identifier
from src.dynamic.context.models import EndpointContext
from src.agent.context_analyst.validation import record_id

SUPPORTED_PRIMITIVES = ('AUTHENTICATION_PRESENCE', 'OBJECT_AUTHORIZATION',
                        'FUNCTION_AUTHORIZATION', 'SESSION_HANDLING')
# Fixed relevance priors; scores describe usefulness, not security impact.
GOAL_RELEVANCE = MappingProxyType({
    'review_security_coverage': MappingProxyType(dict.fromkeys(SUPPORTED_PRIMITIVES, 100)),
    'assess_authentication': MappingProxyType({'AUTHENTICATION_PRESENCE': 100, 'SESSION_HANDLING': 60}),
    'assess_object_authorization': MappingProxyType({'OBJECT_AUTHORIZATION': 100, 'AUTHENTICATION_PRESENCE': 60, 'SESSION_HANDLING': 40}),
    'assess_function_authorization': MappingProxyType({'FUNCTION_AUTHORIZATION': 100, 'AUTHENTICATION_PRESENCE': 60, 'SESSION_HANDLING': 40}),
    'assess_session_handling': MappingProxyType({'SESSION_HANDLING': 100, 'AUTHENTICATION_PRESENCE': 60}),
})


@dataclass(frozen=True)
class PlanningGoal:
    goal_type: str
    endpoint_context_id: str
    scope: str = 'single_endpoint'
    schema_version: str = '1.0'

    def __post_init__(self):
        identifier(self.endpoint_context_id, 'endpoint_context_id')
        if (not isinstance(self.goal_type, str) or self.goal_type not in GOAL_RELEVANCE
                or self.scope != 'single_endpoint' or self.schema_version != '1.0'):
            raise ContractError('Unsupported planning goal or scope')

    @property
    def goal_id(self):
        return record_id('goal', self.schema_version + self.endpoint_context_id + self.goal_type)

    @property
    def test_ids(self):
        return tuple(sorted(GOAL_RELEVANCE[self.goal_type]))

    def bind(self, endpoint_context):
        if self.endpoint_context_id != endpoint_context.endpoint_context_id:
            raise ContractError('Goal endpoint mismatch')
        return self

    def to_dict(self):
        return {**asdict(self), 'goal_id': self.goal_id}

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict) or set(data) != {'goal_type', 'endpoint_context_id', 'scope', 'schema_version', 'goal_id'}:
            raise ContractError('Invalid goal fields')
        result = cls(**{k: v for k, v in data.items() if k != 'goal_id'})
        if data['goal_id'] != result.goal_id:
            raise ContractError('Invalid goal ID')
        return result


def resolve_goal(goal, endpoint_context):
    if not isinstance(endpoint_context, EndpointContext):
        raise ContractError('EndpointContext required for goal scope')
    if goal is None:
        goal = PlanningGoal('review_security_coverage', endpoint_context.endpoint_context_id)
    if isinstance(goal, dict):
        goal = PlanningGoal.from_dict(goal)
    if not isinstance(goal, PlanningGoal):
        raise ContractError('PlanningGoal required')
    # Recheck frozen/serialized instances at the integration boundary.
    return PlanningGoal.from_dict(goal.to_dict()).bind(endpoint_context)
