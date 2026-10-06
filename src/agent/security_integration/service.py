"""Explicit, single-endpoint bridge; models propose, deterministic gates decide.

Execution requests/registries/backends come from the trusted controlled-lab
caller, never from model output. Existing catalog risk/action semantics remain
unchanged: a passive metadata review cannot become an active auth-removal test.
"""
from copy import deepcopy
from dataclasses import dataclass
import ipaddress
from collections.abc import Mapping

from src.agent.context_analyst import analyze_endpoint_context
from src.agent.test_planner import plan_endpoint_tests
from src.agent.policy_integration import evaluate_test_plan
from src.agent.test_catalog import TEST_CATALOG
from src.dynamic.security.contracts import DynamicTestRequest, validate_execution
from src.dynamic.security.executor import DeterministicSecurityExecutor
from src.dynamic.security.reporting import security_result_artifact, build_security_section, unavailable_security_section

from .reliability import FailureAwareClient, guard_for

SUPPORTED_TEST_IDS = ('AUTHENTICATION_PRESENCE', 'OBJECT_AUTHORIZATION',
                      'FUNCTION_AUTHORIZATION', 'SESSION_HANDLING')


@dataclass(frozen=True)
class ExecutionBinding:
    """Caller-owned request and canonical registry; not an Agent output schema."""
    request: DynamicTestRequest
    evidence_registry: Mapping


@dataclass(frozen=True)
class AgentValidationRun:
    status: str
    analyst: object
    planner: object | None
    policy: object | None
    executions: tuple
    artifacts: tuple
    security_report: dict
    reason_codes: tuple[str, ...]


    @property
    def agent_state(self):
        if self.status == 'no_relevant_tests' and not self.reason_codes:
            return 'available'
        if (self.status == 'completed' and not self.reason_codes
                and self.security_report.get('coverage') == 'available'
                and all(e.execution_status == 'completed' for e in self.executions)):
            return 'available'
        return 'partial' if self.planner is not None or getattr(self.analyst, 'status', None) == 'completed' else 'unavailable'

    def to_dict(self):
        """Safe internal trace; no public Agent completion or finding authority."""
        return {'schema_version':'1.0', 'status':self.status, 'agent_state':self.agent_state,
            'public_agent_analysis':'not_available',
            'analyst':self.analyst.to_dict() if self.analyst is not None else None,
            'planner':self.planner.to_dict() if self.planner is not None else None,
            'policy':self.policy.to_dict() if self.policy is not None else None,
            'executions':[e.to_dict() for e in self.executions],
            'security_report':deepcopy(self.security_report), 'reason_codes':list(self.reason_codes)}


def run_agent_validation(context, analyst_client, planner_client, *, evidence_index,
                         precondition_index=None, execution_bindings=None,
                         executor=None, session_id=None, controlled_lab=False,
                         coverage_metadata=None, created_at=None):
    """One planning pass, at most one controlled execution, no autonomous loop.

    Missing bindings/backends stop explicitly. Policy decisions are recomputed,
    not accepted from the model/caller. ALLOW remains proposal eligibility; the
    executor independently checks its existing safety and lab preconditions.
    """
    context = deepcopy(context)
    analyst_client = FailureAwareClient(analyst_client)
    planner_client = FailureAwareClient(planner_client)
    analyst = analyze_endpoint_context(context, analyst_client,
        coverage_metadata=coverage_metadata, created_at=created_at)
    empty = unavailable_security_section()
    if analyst.status != 'completed':
        return AgentValidationRun('stopped', analyst, None, None, (), (), empty, ('ANALYST_'+analyst_client.failure if analyst_client.failure else 'ANALYST_UNAVAILABLE_OR_INVALID',))
    planner = plan_endpoint_tests(context, analyst, planner_client,
        catalog_test_ids=SUPPORTED_TEST_IDS, coverage_metadata=coverage_metadata, created_at=created_at)
    if planner.status not in {'completed', 'no_relevant_tests'}:
        return AgentValidationRun('stopped', analyst, planner, None, (), (), empty, ('PLANNER_'+planner_client.failure if planner_client.failure else 'PLANNER_UNAVAILABLE_OR_INVALID',))
    policy = evaluate_test_plan(context, analyst, planner, evidence_index,
        precondition_index=precondition_index, created_at=created_at)
    if policy.status == 'not_processed':
        return AgentValidationRun('stopped', analyst, planner, policy, (), (), empty, ('POLICY_NOT_PROCESSED',))
    if not planner.proposals:
        return AgentValidationRun('no_relevant_tests', analyst, planner, policy, (), (), empty, ())
    reasons = []
    executions, artifacts = [], []
    dispatched = False
    bindings = execution_bindings if isinstance(execution_bindings, Mapping) else {}
    decisions = {d.proposal_id:d for d in policy.decisions}
    for proposal in sorted(planner.proposals, key=lambda p:p.proposal_id):
        decision = decisions.get(proposal.proposal_id)
        if decision is None or decision.decision != 'allow':
            reasons.append('POLICY_DENIED' if decision and decision.decision=='deny' else 'POLICY_NEEDS_EVIDENCE')
            continue
        if proposal.test_id not in SUPPORTED_TEST_IDS:
            reasons.append('UNSUPPORTED_PRIMITIVE'); continue
        # Do not route any third-party/private-network app to active validation.
        try:
            local = ipaddress.ip_address(context.host).is_loopback
        except ValueError:
            local = False
        if controlled_lab is not True or not local or context.scheme != 'http':
            reasons.append('CONTROLLED_LOCAL_LAB_REQUIRED'); continue
        if type(executor) is not DeterministicSecurityExecutor:
            reasons.append('EXECUTOR_UNAVAILABLE'); continue
        binding = bindings.get(proposal.test_id)
        if not isinstance(binding, ExecutionBinding):
            reasons.append('EXECUTION_BINDING_UNAVAILABLE'); continue
        try:
            request = DynamicTestRequest.from_dict(binding.request.to_dict())
            entry = TEST_CATALOG[proposal.test_id]
            if (request.test_id != proposal.test_id or request.test_category != entry.category
                    or request.endpoint_context_id != context.endpoint_context_id
                    or not session_id or request.session_id != session_id
                    or request.risk_class != proposal.risk_class
                    or request.requested_action != proposal.requested_action.action):
                reasons.append('EXECUTION_BINDING_MISMATCH'); continue
            if dispatched:
                reasons.append('SINGLE_EXECUTION_BOUND'); continue
            claimed = guard_for(executor).claim(request)
            if claimed:
                reasons.append(claimed); continue
            dispatched = True
            execution = executor.execute(request, context, deepcopy(binding.evidence_registry), session_id=session_id)
            executions.append(execution)
            registry, evidence = executor.validation_evidence(request, context, binding.evidence_registry, execution)
            validate_execution(request, execution, registry)
            # The canonical serializer invokes the existing category validator.
            # No model outcome/finding/approval is an input at this boundary.
            artifact = security_result_artifact(request, execution, registry, evidence)
            artifacts.append(artifact)
        except (KeyboardInterrupt, InterruptedError):
            reasons.append('EXECUTION_INTERRUPTED'); break
        except (ValueError, TypeError, KeyError, AttributeError):
            reasons.append('EXECUTION_OR_EVIDENCE_REJECTED')
    source = {'schema_version':'1.0', 'session_id':session_id,
              'records':[r for a in artifacts for r in a['records']]}
    report = build_security_section(source, session_id, [context.to_dict()]) if artifacts else empty
    status = 'completed' if artifacts else 'stopped'
    return AgentValidationRun(status, analyst, planner, policy, tuple(executions), tuple(artifacts),
                              report, tuple(sorted(set(reasons))))
