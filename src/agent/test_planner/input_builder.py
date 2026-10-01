"""Deterministic relevance and current-context grounding before the model boundary."""
from dataclasses import asdict

from src.agent.models import ContractError, CoverageGap, RequestedAction
from src.agent.test_catalog import TEST_CATALOG
from src.agent.context_analyst import ContextAnalystResult, build_context_analyst_input
from src.agent.context_analyst.validation import gap_id, validate_model_output
from .models import TestPlannerInput

HYPOTHESIS_TEST_MAP = {
    "object_authorization_candidate": "OBJECT_AUTHORIZATION",
    "function_authorization_candidate": "FUNCTION_AUTHORIZATION",
    "authentication_behavior_candidate": "AUTHENTICATION_PRESENCE",
    "session_behavior_candidate": "SESSION_HANDLING",
    "input_validation_candidate": "INPUT_VALIDATION",
    "parameter_consistency_candidate": "PARAMETER_CONSISTENCY",
}
REASONS = {
    "OBJECT_AUTHORIZATION": "Resource identifiers and runtime observations support considering object authorization; authenticated baseline and ownership evidence remain required.",
    "FUNCTION_AUTHORIZATION": "Runtime administrative context supports considering function authorization; role-sensitive permission evidence remains required.",
    "AUTHENTICATION_PRESENCE": "Observed authentication-presence metadata supports a descriptive presence review; it does not establish authentication correctness.",
    "SESSION_HANDLING": "Session-related presence metadata and runtime evidence support considering session dependency; expected session behavior remains required.",
    "INPUT_VALIDATION": "Observed body input names and runtime evidence support considering input handling; expected input behavior remains required.",
    "PARAMETER_CONSISTENCY": "Multiple parameters or differing static/runtime methods support considering consistency; expected behavior remains required.",
}


def _coverage_metadata(gaps):
    metadata = {}
    for g in gaps:
        if g.kind == "traffic_unavailable": metadata["traffic_available"] = False
        if g.kind in {"max_steps", "max_depth"}: metadata["stop_reason"] = g.kind
        for kind, key in (("input_skipped", "input_action_skipped"), ("external_package", "external_package_boundary"), ("system_ui", "system_ui_boundary")):
            if g.kind == kind: metadata[key] = True
    return metadata


def build_test_planner_input(endpoint_context, analyst_result, *, catalog_test_ids=None,
                             coverage_metadata=None) -> TestPlannerInput:
    if not isinstance(analyst_result, ContextAnalystResult) or analyst_result.status != "completed":
        raise ContractError("Completed analyst result required")
    analyst = ContextAnalystResult.from_dict(analyst_result.to_dict())
    if endpoint_context.endpoint_context_id != analyst.endpoint_context_id:
        raise ContractError("Analyst endpoint mismatch")
    prior_metadata = _coverage_metadata(analyst.coverage_gaps)
    baseline = build_context_analyst_input(endpoint_context, coverage_metadata=prior_metadata,
                                          available_evidence_refs=analyst.input_evidence_refs)
    analyst_data = analyst.to_dict()
    # Reuse the accepted Analyst validator: typed output alone does not prove current grounding.
    validate_model_output({"schema_version": "1.0", "endpoint_context_id": analyst.endpoint_context_id,
        "endpoint_role": analyst.endpoint_role, "observation": analyst_data["observation"],
        "hypotheses": analyst_data["hypotheses"], "coverage_gaps": analyst_data["coverage_gaps"]},
        baseline, created_at=analyst.observation.created_at, metadata=analyst.model_metadata, attempts=analyst.attempts)
    merged_metadata = dict(prior_metadata)
    if coverage_metadata is not None:
        if not isinstance(coverage_metadata, dict): raise ContractError("Invalid coverage metadata")
        merged_metadata.update(coverage_metadata)
        if prior_metadata.get("traffic_available") is False: merged_metadata["traffic_available"] = False
    context = build_context_analyst_input(endpoint_context, coverage_metadata=merged_metadata,
                                         available_evidence_refs=analyst.input_evidence_refs)
    allowed = set(TEST_CATALOG)
    if catalog_test_ids is not None:
        if not isinstance(catalog_test_ids, (list, tuple, set, frozenset)) or len(catalog_test_ids) > len(TEST_CATALOG):
            raise ContractError("Invalid catalog subset")
        if any(not isinstance(t, str) or t not in TEST_CATALOG for t in catalog_test_ids):
            raise ContractError("Unknown catalog subset test")
        allowed = set(catalog_test_ids)
    runtime = context.dynamic_context["runtime_confirmed"] is True
    tx_evidence = bool(context.evidence_refs["transactions"])
    baseline_available = runtime and tx_evidence and context.coverage["traffic_available"] is not False
    request = context.request_context; auth = context.auth_context
    candidates, notes = [], []
    for h in sorted(analyst.hypotheses, key=lambda h: h.hypothesis_id):
        test_id = HYPOTHESIS_TEST_MAP.get(h.hypothesis_type)
        if test_id not in allowed: continue
        entry = TEST_CATALOG[test_id]
        if test_id != "AUTHENTICATION_PRESENCE" and not baseline_available:
            notes.append(f"{test_id}: runtime transaction baseline is unavailable; no proposal emitted."); continue
        if test_id == "OBJECT_AUTHORIZATION" and not request["resource_identifier_keys"]: continue
        if test_id == "SESSION_HANDLING" and not any(auth[k] is True for k in ("cookie_present", "session_cookie_present", "bearer_token_present")): continue
        if test_id == "AUTHENTICATION_PRESENCE" and not any(v is not None for v in auth.values()): continue
        if test_id == "INPUT_VALIDATION" and not (request["body_present"] is True and request["body_keys"]):
            notes.append("INPUT_VALIDATION: current catalog requires observed body input; no query-only proposal."); continue
        if test_id == "PARAMETER_CONSISTENCY" and not (len(request["query_keys"]) + len(request["body_keys"]) >= 2 or context.static_context["match_type"] == "method_mismatch"):
            continue
        if test_id == "FUNCTION_AUTHORIZATION":
            # A path name and credential presence do not establish role-sensitive permissions.
            notes.append("FUNCTION_AUTHORIZATION: independent role/permission evidence is unavailable; no proposal emitted."); continue
        required = set(entry.required_context) | set(h.required_evidence)
        if test_id == "OBJECT_AUTHORIZATION": required.update({"Authenticated baseline evidence", "Resource ownership evidence"})
        if test_id == "SESSION_HANDLING": required.add("Expected session lifecycle evidence")
        refs = set(h.evidence_refs) | set(context.evidence_refs["endpoint_context"])
        if test_id != "AUTHENTICATION_PRESENCE": refs.add(context.evidence_refs["transactions"][0])
        candidates.append({"hypothesis_id": h.hypothesis_id, "test_id": test_id, "reason": REASONS[test_id],
            "evidence_refs": sorted(refs), "required_context": sorted(required), "risk_class": entry.risk_class,
            "requested_action": RequestedAction(entry.abstract_action, execution_mode="proposal_only").to_dict()})
    test_ids = sorted({c["test_id"] for c in candidates})
    all_gaps = {g.gap_id: g for g in analyst.coverage_gaps}
    for d in context.coverage["gaps"]:
        g = CoverageGap(gap_id(context.endpoint_context_id, d), context.endpoint_context_id, d["kind"], d["description"], tuple(d["evidence_refs"]))
        all_gaps[g.gap_id] = g
    safe_context = context.to_dict()
    for key in ("fact_catalog", "hypothesis_catalog", "supported_roles"): safe_context.pop(key)
    safe_analyst = {"analysis_id": analyst.analysis_id, "endpoint_role": analyst.endpoint_role,
        "observation": analyst.observation.to_dict(), "hypotheses": [h.to_dict() for h in sorted(analyst.hypotheses, key=lambda h: h.hypothesis_id)]}
    return TestPlannerInput(context.endpoint_context_id, safe_context, safe_analyst,
        tuple(asdict(TEST_CATALOG[t]) for t in test_ids), tuple(sorted(candidates, key=lambda c: (c["hypothesis_id"], c["test_id"]))),
        tuple(all_gaps[key] for key in sorted(all_gaps)), tuple(sorted(set(notes))), context.evidence_universe)
