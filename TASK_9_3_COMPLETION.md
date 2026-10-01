# Task 9.3 — Test Planner V1 completion report

### Files Changed

Task-specific changes: `src/agent/test_planner/{__init__,models,input_builder,validation,service,persistence}.py`, `test_planner_v1.txt`, canonical `src/agent/models.py` and `src/agent/test_catalog.py`, `tests/test_test_planner_input.py`, `tests/test_test_planner.py`, `tests/test_planner_fakes.py`, `SPEC.md`, this report and `examples/task_9_3/`. Existing accepted local changes from earlier tasks were preserved.

Repository preparation: inspected main and working tree, fetched origin and pulled current main with fast-forward only. GitHub/main was already current before implementation. No local work was discarded; no commit or push was made.

### Test Planner Architecture

Single EndpointContext → deterministic sanitized adapter + revalidated ContextAnalystResult → relevant canonical catalog candidates → shared model interface → strict validator → canonical TestProposal[] inside TestPlannerResult. Optional batch helper performs isolated endpoint calls, without whole-scan reasoning.

### Planner Input Boundary

Includes identity, role, sanitized request/response shapes and names, presence flags, correlation/runtime/visibility metadata, coverage, validated hypotheses and run-relative evidence refs. Reuses the Analyst sanitizer and current-source grounding validator. Rejects endpoint mismatches and stale observations. Raw credentials, body values, logs, filesystem paths and unrelated endpoints are excluded. JSON-detached input is bounded to 32 KiB.

### Catalog Filtering

Fixed hypothesis-type mapping; optional caller IDs only narrow the canonical subset. Runtime-dependent tests require actual transaction refs and available baseline coverage. Object checks require resource keys; session checks require session-related metadata; input validation requires observed body keys according to the existing catalog. Parameter consistency requires multiple parameters or method mismatch. Function authorization is withheld because current evidence cannot establish role/permission sensitivity independently of path naming. Authentication presence is descriptive review, not an assertion that login requires an Authorization header.

### Instruction Prompt

Canonical asset prohibits unknown tests, request construction, tool/network actions, mutations, findings, severity and execution approval. Requires evidence, supplied preconditions, exact risk and strict schema. Selecting no tests is valid. Supplied endpoint data is not instruction text.

### Prompt Version

`test_planner_v1` in request, result and persistence envelope.

### Model Client Reuse

Uses Task 9.2 AgentModelClient, ModelRequest, ModelReply and ModelMetadata. Offline PlannerFake inherits the existing fake boundary. No provider implementation or live provider is configured.

### Proposal Schema

Reuses TestProposal with all ten fields: proposal_id, hypothesis_id, endpoint_context_id, test_id, reason, evidence_refs, required_context, requested_action, risk_class and created_at. No second proposal schema. RequestedAction gains an abstract proposal_only mode, requiring empty host/path/method, no mutation and no parameters. Existing concrete action validation remains intact.

### Proposal Grounding

Each candidate joins a validated Analyst hypothesis, current EndpointContext evidence and immutable catalog entry. Reason and prerequisites are bounded deterministic summaries. The model may select relevant candidates or decline them, but cannot manufacture reasons, evidence, tests or prerequisites.

### Hypothesis Linking

Only supplied existing hypotheses may be referenced. Orphans and missing links reject. Source Analyst output is revalidated against the current endpoint before model use.

### Test ID Validation

Unknown IDs and canonical tests outside the relevant supplied subset reject. Caller subsets cannot add noncanonical IDs.

### Risk Integrity

Exact catalog risk is mandatory. OBJECT_AUTHORIZATION remains medium; FUNCTION_AUTHORIZATION remains high. Medium/destructive labels cannot be replaced by lower/passive labels. Catalog automatic-execution metadata remains unchanged and grants no Planner approval.

### Requested Action Boundary

Catalog-defined abstract actions only, with execution_mode=proposal_only. No concrete target, object substitution, URL, curl, HTTP method override, header or body construction. An abstract proposal denotes relevance for later consideration, not approval or execution.

### Coverage-Aware Planning

Coverage gaps are retained. Static-only, unavailable traffic and missing runtime transactions block runtime-dependent proposals. Presence does not prove authenticated baseline or ownership. Required evidence stays explicit; unknown remains distinct from known absent. HTTPS limits do not establish endpoint absence.

### No-Relevant-Test Semantics

no_relevant_tests is successful, has zero proposals and may bypass the model when no candidate survives. The model can also return an empty plan despite supplied candidates. No forced proposal.

### Evidence Reference Validation

Every proposal requires supplied valid refs and its candidate's support refs. Hallucinated or omitted supporting refs reject. Deterministic IDs use endpoint + hypothesis + test. Identical validated duplicates deduplicate; conflicting duplicates reject. Ordering is deterministic.

### Forbidden Fields

Unknown fields are forbidden throughout the output. Explicit finding/severity/cvss/confirmation/exploit/PoC, tool/curl/raw_request/payload-related execution fields, approval flags and private reasoning fields reject. Free-form execution text cannot enter the fixed reason/action/precondition fields.

### Failure Modes

completed, no_relevant_tests, input_invalid, invalid_output and model_error. Failures contain no proposals. Error codes avoid raw rejected output/provider exception leakage. Batch failure does not erase successful endpoints.

### Retry Policy

max_attempts defaults to two and is bounded to one or two. Invalid output gets at most one fixed correction; provider errors terminate immediately. Invalid input makes no model call.

### Persistence

Explicit save/load at demo_runs/<run_id>/agent/test_plans.json. Atomic temporary file, fsync and replace; successful endpoint merge with stable ordering. Failed attempts preserve previous successes. Corrupt artifacts reject rather than overwrite. Limits: 64 endpoint records, 2 MiB. Calls for the same run must be serialized by callers, as documented.

### Product Stage Boundary

No public state or serving/pipeline integration introduced. agent_analysis stays not_available. No agent_report.json. Prior successful records remain snapshots, not evidence that a newer failed attempt succeeded.

### Policy Gate Boundary

No invocation or integration. The existing pure Policy Gate implementation remains unchanged. Task 9.4 is not implemented.

### Tool Calling Boundary

No tools, executor, replay, active API tests, fuzzing, exploit, verifier, PoC or vulnerability confirmation. Tests forbid socket/network and Policy Gate calls during Planner invocation.

### Tests

New Planner input/runtime suites: **105 passed**. Tests cover privacy, relevance, schema/ID/risk/evidence/link checks, all forbidden field locations, abstract actions, duplicates, no relevant tests, unknown/coverage handling, bounded retries, fake-client reuse, batch isolation and atomic persistence/public-state preservation.

Command: `pytest tests/test_test_planner_input.py tests/test_test_planner.py -q --tb=short`

### Regressions

Combined required Planner, Context Analyst, Task 9.1 contracts, Policy Gate, endpoint context, static/dynamic API correlation, traffic/runtime correlation, dynamic report, scan-state/recovery, demo pipeline and orchestrator/iOS suites: **723 passed, 1 skipped, 18 subtests passed; 0 failed**. The skip is an optional ADB/device integration test. No active API testing was performed.

Command: `pytest tests/test_test_planner_input.py tests/test_test_planner.py tests/test_context_analyst_input.py tests/test_context_analyst.py tests/test_agent_contracts.py tests/test_agent_policy.py tests/test_endpoint_context_builder.py tests/test_static_dynamic_api_correlation.py tests/test_dynamic_traffic_correlation.py tests/test_dynamic_runtime_correlation.py tests/test_dynamic_analysis_report.py tests/test_scan_state.py tests/test_scan_state_integration.py tests/test_scan_state_recovery.py tests/test_demo_orchestrator.py tests/test_demo3_pipeline.py tests/test_demo3_adb_optional.py tests/test_ios_orchestrator_integration.py -q --tb=short`

### Example Planner Input

`examples/task_9_3/planner_input.json`: synthetic ctx_1 orders endpoint, validated hypotheses, traffic/context refs and object-only subset. Examples use offline fixtures, not real scan evidence.

### Example Valid TestProposal

`examples/task_9_3/valid_test_proposal.json`: OBJECT_AUTHORIZATION, medium risk, validate_object_access_behavior with proposal_only mode, linked hypothesis and supplied refs. Authenticated baseline/ownership prerequisites remain required. All ten canonical fields are included.

### Example No-Relevant-Test Result

`examples/task_9_3/no_relevant_tests.json`: status=no_relevant_tests, proposal_count=0, proposals=[], attempts=0.

### Example Rejected Hallucinated Proposal

`examples/task_9_3/rejected_hallucinated_proposal.json`: unknown transaction_id=tx_hallucinated ref yields invalid_output after two attempts, EVIDENCE_REF_NOT_SUPPLIED, no proposals.

### Diff Summary

Adds isolated Planner package, prompt, focused offline tests, examples and documentation. Extends the existing canonical action/catalog definitions only for abstract proposal semantics. No policy, public stage, executor or active-testing implementation change belongs to Task 9.3.

Task 9.3 completed. Test Planner runtime was introduced. Policy execution, tool calling, and active API testing were not started.
