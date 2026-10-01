# Task 9.4 — Test Planner ↔ Policy Gate integration

### Files Changed

New: `src/agent/policy_integration/{__init__,models,service,persistence}.py`, `tests/test_agent_policy_integration.py`, `examples/task_9_4/` and this report. Updated: canonical `src/agent/models.py`, pure `src/agent/policy.py` and `SPEC.md`. No Planner, dynamic/static, orchestrator, scan-state or public serving implementation changes.

Inspected branch/main and dirty local work; fetched and pulled origin/main with fast-forward only. Repository was already current. Accepted earlier local work was preserved. No commit or push.

### Policy Integration Architecture

EndpointContext + ContextAnalystResult + TestPlannerResult (or bounded TestProposal[]) → deterministic input/grounding adapter → existing pure Policy Gate → canonical PolicyDecision[] in PolicyEvaluationResult. Explicit evaluation only; the Planner itself does not invoke policy and public orchestration remains unwired. One endpoint per evaluation, at most 16 proposals.

The existing caller-verified scan-scoped evidence index is retained. Human-readable Planner prerequisites can be supplied as explicit trusted PreconditionRecord metadata linked to canonical evidence. This is resolver metadata, not model assertions; the caller must verify the named prerequisite against authoritative evidence. No production resolver for expected behavior/ownership semantics is introduced. Missing proof is not inferred away.

### Canonical Decisions

allow: requirements satisfied, eligible for later consideration. deny: integrity/policy violation. needs_evidence: conceptually valid check with missing verified evidence/context. **POLICY ALLOW ≠ EXECUTE.** No execution or automatic-execution approval is emitted.

Failed Planner statuses yield not_processed with zero decisions; an empty valid plan yields no_proposals with zero. Individual malformed proposals in completed envelopes or the proposal-array adapter deny without dropping other decisions. No fabricated policy decision is attached to a failed Planner result.

### Reason Codes

Preserved canonical codes including ALLOWED, UNKNOWN_TEST, UNKNOWN_ENDPOINT_CONTEXT, MISSING_EVIDENCE, MISSING_REQUIRED_CONTEXT, PARAMETER_NOT_IN_EVIDENCE, RISK_NOT_ALLOWED, DESTRUCTIVE_ACTION, AUTO_EXECUTION_NOT_ALLOWED and SCHEMA_INVALID. Added only UNKNOWN_HYPOTHESIS and HALLUCINATED_EVIDENCE to distinguish lineage/reference violations from insufficient evidence. Missing-context reasons identify the prerequisite without private reasoning.

### Proposal Identity

Every processed decision references its source proposal_id. Canonical PolicyDecision now records policy_version and optional endpoint_context_id/hypothesis_id/test_id; the adapter populates source lineage. Deterministic IDs use the existing proposal/decision/reason-code/validated-ref convention plus policy version, excluding clocks. Repeated identical evaluation is stable.

### Endpoint Validation

Exact supplied endpoint identity. Cross-endpoint proposals deny and retain rejected source identity in the trace. Stale or invalid upstream grounding cannot authorize a proposal.

### Hypothesis Validation

Completed Analyst output is deterministically revalidated; the proposal must link a real hypothesis for this endpoint. Orphan/missing links deny. The Analyst is never rerun.

### Evidence Validation

Refs must belong to the bounded current evidence universe and resolve to the correct endpoint. Unknown/fabricated or cross-endpoint references deny. Known required refs absent from the verified index, and declared-but-unavailable transactions, need evidence. Invalid refs are never silently removed.

### Catalog Validation

Canonical immutable Test Catalog remains the source of truth. Unknown tests deny with UNKNOWN_TEST. The adapter also rechecks the Planner candidate/test/hypothesis relationship and its exact supplied reason and prerequisites.

### Risk Integrity

Risk must match catalog exactly. Passive/low may pass when prerequisites are verified; medium/high/destructive deny. Catalog automatic-execution metadata and legacy concrete-policy rules are preserved. proposal_only is conceptual eligibility and does not approve automatic execution, including for catalog entries whose automatic-execution flag is false.

### Required Context

Catalog dotted prerequisites are checked against actual EndpointContext. Planner human-readable missing prerequisites require explicit caller-verified, endpoint-linked PreconditionRecords; they cannot be removed or invented. Missing context returns MISSING_REQUIRED_CONTEXT. Header/cookie presence does not prove expected behavior, authenticated baseline or ownership.

### Required Evidence

Required evidence kinds and every proposed supporting ref are checked explicitly. Missing verified transaction or prerequisite evidence returns needs_evidence. Available evidence of the wrong endpoint is an integrity violation and denies.

### Parameter Validation

Unknown query/body key references deny with PARAMETER_NOT_IN_EVIDENCE. Existing path/resource identifier evidence continues to ground relevant hypotheses. Task 9.3 abstract actions still require empty mutation parameters; concrete parameter selections are not forwarded, even when their names exist. No parameter substitution or request construction is introduced.

### Abstract Action Validation

Uses existing catalog abstract_action vocabulary and RequestedAction proposal_only contract. Concrete host/path/method, raw HTTP instructions, curl, bodies, headers, SQL payloads, destructive instructions and unsupported actions deny. No duplicate proposal/action vocabulary.

### Coverage-Aware Policy

HTTPS visibility gaps do not globally deny checks. Relevant missing runtime evidence returns needs_evidence. Current evidence/coverage cannot be replaced by model prose; stale plans cannot authorize execution. No coverage gap becomes a vulnerability verdict.

### Unknown vs False

Unknown authentication metadata remains unknown. The pure Gate requires known presence metadata where auth is a catalog prerequisite; unknown does not satisfy it. Known absence may still support descriptive authentication-presence review, subject to remaining prerequisites.

### Policy Version

Canonical `policy_v1` recorded on each decision, wrapper and persistence envelope. Version participates in deterministic decision identity.

### Transparent Policy Trace

Product-safe trace exposes planning/endpoint/hypothesis/test/proposal/decision IDs, policy version, decision, reason code/reason and validated evidence refs. Proposal IDs link to the original proposed reason and preconditions. No chain-of-thought, finding, severity, approval flag or execution evidence.

### Persistence

Explicit atomic write to `demo_runs/<run_id>/agent/policy_decisions.json`. Repository-consistent envelope contains schema_version, policy_version and endpoint-sorted evaluations, each with proposal-sorted canonical decisions and verified counts. At most 64 endpoints / 2 MiB; callers serialize writes for a run. Temporary-file write, fsync, atomic replace and cleanup preserve the previous artifact on failure. Skipped results do not erase earlier evaluated records. Corrupt existing artifacts reject. No upstream artifact is rewritten.

### Product Stage Boundary

agent_analysis stays not_available. No agent_report.json or public stage completion. Persistence does not alter EndpointContext, context_analysis.json, test_plans.json, dynamic_analysis_report.json, dynamic evidence or scan_state.json.

### No-Execution Verification

One synthetic end-to-end pipeline produces ALLOW, NEEDS_EVIDENCE and DENY. During policy evaluation model generation, re-planning, Analyst re-run, socket/urlopen and subprocess execution are guarded to fail if called. Source AST checks disallow model/execution imports. Inputs remain unchanged and evaluation writes no artifacts by itself. No tools, executor, replay, mutation execution, fuzzing, verifier, PoC or findings.

### Focused Tests

**Focused tests: PASSED — 44 passed, 0 failed.**

`pytest tests/test_agent_policy_integration.py -q`

**Adjacent changed-contract suites: PASSED — 191 passed, 0 failed.**

`pytest tests/test_agent_policy.py tests/test_test_planner.py tests/test_agent_contracts.py -q`

These adjacent suites were required because canonical PolicyDecision and the existing Policy Gate changed. No historical dynamic/static/orchestrator/scan-state suite was run for Task 9.4.

### Full Regression Checkpoint Status

**Full regression checkpoint: NOT RUN — scheduled for later checkpoint.**

This task is not a checkpoint. No claim of repository-wide regression cleanliness is made.

### Example ALLOW

`examples/task_9_4/allow.json`: INPUT_VALIDATION, low risk, supplied abstract action and synthetic verified required-context evidence. Decision=allow, reason_code=ALLOWED. Nothing executes.

### Example DENY

`examples/task_9_4/deny.json`: OBJECT_AUTHORIZATION retains canonical medium risk. Decision=deny, reason_code=RISK_NOT_ALLOWED. Nothing executes.

### Example NEEDS_EVIDENCE

`examples/task_9_4/needs_evidence.json`: SESSION_HANDLING lacks expected/comparable session context. Decision=needs_evidence, reason_code=MISSING_REQUIRED_CONTEXT. No re-planning or execution.

### Example policy_decisions.json

`examples/task_9_4/agent/policy_decisions.json`: synthetic atomic persistence envelope for one endpoint. Contains all three decisions, canonical links, policy version and counts. Examples are offline schema fixtures, not real scan evidence or vulnerability validation.

### Diff Summary

Added explicit Planner-to-Policy adapter, typed evaluation/count/trace envelope, internal atomic persistence and focused synthetic tests/examples. Extended canonical PolicyDecision metadata and the existing pure Gate for abstract proposal evaluation. Existing concrete contract behavior remains covered by adjacent tests. No next-milestone architecture was implemented.

Task 9.4 completed. Policy decisions were integrated. Tool calling, executor, and active API testing were not started.
