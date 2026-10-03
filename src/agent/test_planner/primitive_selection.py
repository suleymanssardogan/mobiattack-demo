"""A1-Lite: deterministic selection view, never a TestProposal or execution approval.

PreconditionRecord inputs are caller-verified, endpoint-scoped metadata from the
existing trusted resolver boundary. Model output can never supply/replace them.
No providers, Policy Gate calls, evidence validation overrides or executors.
"""
from dataclasses import asdict, dataclass

from src.agent.context_analyst import build_context_analyst_input
from src.agent.model_client import ModelReply
from src.agent.models import ContractError, identifier
from src.agent.policy import PreconditionRecord

RULES = {
    'authentication_presence':('protected_authenticated_baseline',),
    'object_authorization':('protected_authenticated_baseline','two_principal_resource_ownership'),
    'function_authorization':('proven_role_relationship','privileged_function_baseline'),
    'session_handling':('authenticated_session','logout_lifecycle'),
}
SUPPORTED = tuple(sorted(RULES))
COMMON = ('runtime_baseline','auth_presence_metadata','validation_capability')
_UNSET = object()


@dataclass(frozen=True)
class PrimitiveSelection:
    """Read-only selection, with no action, severity, finding or approval fields."""
    selected_test_type: str
    applicable: bool
    reason_code: str
    required_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    endpoint_context_id: str

    def __post_init__(self):
        identifier(self.endpoint_context_id,'endpoint_context_id')
        if self.selected_test_type not in RULES or type(self.applicable) is not bool:
            raise ContractError('INVALID_PRIMITIVE_SELECTION')
        expected=tuple(sorted(COMMON+RULES[self.selected_test_type]))
        if (self.required_evidence!=expected or not isinstance(self.missing_evidence,tuple)
                or tuple(sorted(set(self.missing_evidence)))!=self.missing_evidence
                or not set(self.missing_evidence).issubset(expected)
                or self.applicable!= (not self.missing_evidence)
                or self.reason_code!=('APPLICABLE_FOR_PLANNING' if self.applicable else 'MISSING_REQUIRED_EVIDENCE')):
            raise ContractError('INVALID_PRIMITIVE_SELECTION')

    def to_dict(self):
        data=asdict(self)
        data['required_evidence']=list(self.required_evidence)
        data['missing_evidence']=list(self.missing_evidence)
        return data


@dataclass(frozen=True)
class PrimitiveSelectionResult:
    status: str
    reason_code: str
    plan: PrimitiveSelection | None = None

    def __post_init__(self):
        codes={'completed':'SELECTION_COMPLETED','inconclusive':'NO_SELECTION_EVIDENCE',
               'unavailable':'AGENT_UNAVAILABLE','input_invalid':'INPUT_INVALID','invalid_output':'OUTPUT_REJECTED'}
        if (self.status not in codes or self.reason_code!=codes[self.status]
                or (self.status=='completed')!=isinstance(self.plan,PrimitiveSelection)):
            raise ContractError('INVALID_SELECTION_RESULT')

    def to_dict(self):
        return {'status':self.status,'reason_code':self.reason_code,'plan':self.plan.to_dict() if self.plan else None}


def select_validation_primitive(endpoint_context, *, requested_test_type=None,
        preconditions=(), available_primitives=SUPPORTED, coverage_metadata=None,
        agent_available=True, model_output=_UNSET):
    """Choose one candidate; applicability is not permission to execute.

    Optional model output is checked against the deterministic selection, never
    used as evidence. Backend failure produces no invented selection. No model
    is contacted here. The existing broader Test Planner V1 remains unchanged.
    """
    if requested_test_type is not None and (not isinstance(requested_test_type,str) or requested_test_type not in RULES):
        raise ContractError('UNSUPPORTED_VALIDATION_PRIMITIVE')
    if type(agent_available) is not bool:raise ContractError('INVALID_AGENT_AVAILABILITY')
    if not agent_available:return PrimitiveSelectionResult('unavailable','AGENT_UNAVAILABLE')
    try:
        context=build_context_analyst_input(endpoint_context,coverage_metadata=coverage_metadata)
        if (not isinstance(available_primitives,(tuple,list)) or len(available_primitives)>4
                or any(not isinstance(t,str) or t not in RULES for t in available_primitives)
                or len(set(available_primitives))!=len(available_primitives)):
            raise ContractError('INVALID_CAPABILITY_METADATA')
        if not isinstance(preconditions,tuple) or len(preconditions)>8:
            raise ContractError('INVALID_PRECONDITION_METADATA')
        allowed_names={name for names in RULES.values() for name in names}
        facts={}
        for record in preconditions:
            if (not isinstance(record,PreconditionRecord) or record.name not in allowed_names
                    or record.name in facts or record.endpoint_context_id!=context.endpoint_context_id
                    or not set(record.evidence_refs).issubset(context.evidence_universe)):
                raise ContractError('UNBOUND_PRECONDITION_METADATA')
            # Typed metadata alone is not a proof: the caller must have resolved
            # its semantics, just as at the existing Policy precondition boundary.
            facts[record.name]=record
    except (ContractError,TypeError,ValueError,AttributeError,KeyError):
        return PrimitiveSelectionResult('input_invalid','INPUT_INVALID')
    chosen=requested_test_type
    if chosen is None:
        for name,kind in [('logout_lifecycle','session_handling'),('proven_role_relationship','function_authorization'),
                          ('privileged_function_baseline','function_authorization'),
                          ('two_principal_resource_ownership','object_authorization'),
                          ('protected_authenticated_baseline','authentication_presence')]:
            if name in facts:
                chosen=kind;break
    if chosen is None:
        if model_output is not _UNSET:return PrimitiveSelectionResult('invalid_output','OUTPUT_REJECTED')
        return PrimitiveSelectionResult('inconclusive','NO_SELECTION_EVIDENCE')
    present=set(facts)
    if (context.dynamic_context['runtime_confirmed'] is True and context.evidence_refs['transactions']
            and context.coverage['traffic_available'] is not False
            and not context.coverage['input_truncated']):
        present.add('runtime_baseline')
    if any(value is True for value in context.auth_context.values()):present.add('auth_presence_metadata')
    if chosen in available_primitives:present.add('validation_capability')
    required=tuple(sorted(COMMON+RULES[chosen]));missing=tuple(sorted(set(required)-present))
    plan=PrimitiveSelection(chosen,not missing,'MISSING_REQUIRED_EVIDENCE' if missing else 'APPLICABLE_FOR_PLANNING',
                            required,missing,context.endpoint_context_id)
    if model_output is not _UNSET:
        raw=model_output.data if isinstance(model_output,ModelReply) else model_output
        # Exact JSON schema and semantics; extra action/finding/approval fields,
        # coercible booleans and model alterations of missing evidence are rejected.
        expected=plan.to_dict()
        if (not isinstance(raw,dict) or set(raw)!=set(expected) or type(raw.get('applicable')) is not bool
                or raw!=expected):
            return PrimitiveSelectionResult('invalid_output','OUTPUT_REJECTED')
    return PrimitiveSelectionResult('completed','SELECTION_COMPLETED',plan)
