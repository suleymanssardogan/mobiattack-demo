"""Isolated read-only Context Analyst runtime; no production pipeline wiring."""
from __future__ import annotations

from datetime import datetime, timezone

from src.agent.model_client import AgentModelClient, ModelReply, ModelRequest
from src.agent.models import ContractError, identifier, timestamp
from src.dynamic.context.models import EndpointContext
from .input_builder import build_context_analyst_input
from .models import ContextAnalystResult, PROMPT_VERSION
from .prompts import INSTRUCTION, RETRY_CORRECTION
from .validation import OutputInvalid, output_schema, record_id, validate_model_output


def analyze_endpoint_context(endpoint_context: EndpointContext, model_client: AgentModelClient, *,
                             coverage_metadata=None, available_evidence_refs=None,
                             max_attempts=2, created_at=None) -> ContextAnalystResult:
    if type(max_attempts) is not int or not 1 <= max_attempts <= 2:
        raise ValueError("max_attempts must be 1 or 2")
    now = created_at or datetime.now(timezone.utc).isoformat()
    timestamp(now)
    try:
        context = build_context_analyst_input(endpoint_context, coverage_metadata=coverage_metadata,
                                              available_evidence_refs=available_evidence_refs)
    except (ContractError, TypeError, ValueError, AttributeError, RecursionError):
        eid = getattr(endpoint_context, "endpoint_context_id", None)
        try:
            identifier(eid, "endpoint_context_id")
        except ContractError:
            eid = "unknown_endpoint"
        return ContextAnalystResult(record_id("analysis", eid + "input_invalid" + now), eid, "input_invalid", now,
                                    validation_errors=("INPUT_INVALID",))
    errors = []
    for attempt in range(1, max_attempts + 1):
        request = ModelRequest(PROMPT_VERSION, INSTRUCTION, context.to_dict(), output_schema(context, now),
                               attempt, RETRY_CORRECTION if attempt > 1 else None)
        try:
            reply = model_client.generate(request)
        except Exception:
            # Do not echo provider exceptions, raw inputs or credentials into trace.
            return ContextAnalystResult(record_id("analysis", context.endpoint_context_id + "model_error" + now),
                context.endpoint_context_id, "model_error", now, input_evidence_refs=context.evidence_universe,
                validation_errors=tuple(errors + ["MODEL_ERROR"]), attempts=attempt)
        try:
            if not isinstance(reply, ModelReply):
                raise OutputInvalid("MODEL_REPLY_INVALID")
            return validate_model_output(reply.data, context, created_at=now, metadata=reply.metadata,
                                         attempts=attempt, errors=errors)
        except OutputInvalid as exc:
            errors.append(str(exc))
    return ContextAnalystResult(record_id("analysis", context.endpoint_context_id + "invalid_output" + now),
        context.endpoint_context_id, "invalid_output", now, input_evidence_refs=context.evidence_universe,
        validation_errors=tuple(errors), attempts=max_attempts)


def analyze_endpoint_contexts(endpoint_contexts, model_client: AgentModelClient, *, max_endpoints=16, **kwargs):
    """Bounded batch, one endpoint per model request; failures retain other results."""
    if type(max_endpoints) is not int or not 1 <= max_endpoints <= 32:
        raise ValueError("max_endpoints must be between 1 and 32")
    if not isinstance(endpoint_contexts, (list, tuple)) or len(endpoint_contexts) > max_endpoints:
        raise ContractError("Batch endpoint bound exceeded")
    ids = [e.endpoint_context_id for e in endpoint_contexts if isinstance(e, EndpointContext) and isinstance(e.endpoint_context_id, str) and e.endpoint_context_id]
    if len(ids) != len(set(ids)):
        raise ContractError("Duplicate batch endpoint identity")
    ordered = sorted(endpoint_contexts, key=lambda e: e.endpoint_context_id if isinstance(e, EndpointContext) and isinstance(e.endpoint_context_id, str) else "")
    return tuple(analyze_endpoint_context(e, model_client, **kwargs) for e in ordered)
