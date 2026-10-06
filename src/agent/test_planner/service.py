"""Isolated proposal-only runtime. No policy invocation or execution."""
from datetime import datetime, timezone
from pathlib import Path

from src.agent.model_client import model_identity, AgentModelClient, ModelMetadata, ModelReply, ModelRequest
from src.agent.models import ContractError, identifier, timestamp
from src.agent.context_analyst.validation import record_id
from .input_builder import build_test_planner_input
from .models import PROMPT_VERSION, TestPlannerResult
from .validation import PlannerOutputInvalid, output_schema, result_from_proposals, validate_model_output

INSTRUCTION = Path(__file__).with_name("test_planner_v1.txt").read_text(encoding="utf-8")
CORRECTION = "Previous output violated schema. Return only valid structured output."


def plan_endpoint_tests(endpoint_context, analyst_result, model_client: AgentModelClient, *,
                        catalog_test_ids=None, coverage_metadata=None, max_attempts=2, created_at=None, goal=None):
    if type(max_attempts) is not int or not 1 <= max_attempts <= 2: raise ValueError("max_attempts must be 1 or 2")
    now = created_at or datetime.now(timezone.utc).isoformat(); timestamp(now)
    if goal is not None:
        from src.agent.planning.goals import resolve_goal
        goal = resolve_goal(goal, endpoint_context)
        if catalog_test_ids is not None:
            from src.agent.test_catalog import TEST_CATALOG
            if (not isinstance(catalog_test_ids, (list, tuple, set, frozenset))
                    or any(not isinstance(t, str) or t not in TEST_CATALOG for t in catalog_test_ids)):
                raise ContractError("Invalid goal catalog subset")
        catalog_test_ids = tuple(t for t in goal.test_ids if catalog_test_ids is None or t in catalog_test_ids)
    try:
        source = build_test_planner_input(endpoint_context, analyst_result, catalog_test_ids=catalog_test_ids,
                                          coverage_metadata=coverage_metadata)
    except (ContractError, ValueError, TypeError, AttributeError, RecursionError):
        eid = getattr(endpoint_context, "endpoint_context_id", None)
        try: identifier(eid, "endpoint_context_id")
        except ContractError: eid = "unknown_endpoint"
        return TestPlannerResult(record_id("planning", eid + "input_invalid" + now), eid, now, "input_invalid",
                                 validation_errors=("INPUT_INVALID",))
    if not source.proposal_candidates:
        return result_from_proposals(source, (), created_at=now, metadata=ModelMetadata())
    errors = []
    for attempt in range(1, max_attempts + 1):
        model_input = source.to_dict()
        if goal is not None:
            model_input["scan_goal"] = goal.to_dict()
        request = ModelRequest(PROMPT_VERSION, INSTRUCTION, model_input, output_schema(source, now), attempt,
                               CORRECTION if attempt > 1 else None)
        try: reply = model_client.generate(request)
        except Exception:
            return _failure(source, now, "model_error", attempt, errors + ["MODEL_ERROR"], metadata=model_identity(model_client))
        try:
            if not isinstance(reply, ModelReply): raise PlannerOutputInvalid("MODEL_REPLY_INVALID")
            return validate_model_output(reply.data, source, created_at=now, metadata=reply.metadata, attempts=attempt, errors=errors)
        except PlannerOutputInvalid as exc: errors.append(str(exc))
    return _failure(source, now, "invalid_output", max_attempts, errors)


def _failure(source, now, status, attempts, errors, metadata=None):
    return TestPlannerResult(record_id("planning", source.endpoint_context_id + status + now), source.endpoint_context_id,
        now, status, input_evidence_refs=source.evidence_refs, coverage_gaps=source.coverage_gaps,
        planning_notes=source.planning_notes, hypothesis_ids_considered=tuple(h["hypothesis_id"] for h in source.analyst["hypotheses"]),
        model_metadata=metadata or ModelMetadata(),
        catalog_test_ids_available=tuple(t["test_id"] for t in source.available_tests), validation_errors=tuple(errors), attempts=attempts)


def plan_endpoint_test_batch(endpoint_analyst_pairs, model_client, *, max_endpoints=16, **kwargs):
    if type(max_endpoints) is not int or not 1 <= max_endpoints <= 32: raise ValueError("Invalid batch limit")
    if not isinstance(endpoint_analyst_pairs, (list, tuple)) or len(endpoint_analyst_pairs) > max_endpoints:
        raise ContractError("Batch limit exceeded")
    if any(not isinstance(pair, (list, tuple)) or len(pair) != 2 for pair in endpoint_analyst_pairs):
        raise ContractError("Invalid endpoint/analyst pairs")
    ids = [getattr(pair[0], "endpoint_context_id", "") for pair in endpoint_analyst_pairs]
    if any(not isinstance(eid, str) for eid in ids) or len(ids) != len(set(ids)): raise ContractError("Invalid/duplicate endpoint IDs")
    return tuple(plan_endpoint_tests(e, a, model_client, **kwargs) for e, a in sorted(endpoint_analyst_pairs, key=lambda pair: pair[0].endpoint_context_id))
