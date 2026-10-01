# Task 9.1 completion — Agent Analysis specification and deterministic foundations

### Files Changed
Only new files were added for this task:
- `SPEC.md` — canonical specification at repository root.
- `src/agent/__init__.py` — explicit contract-only package boundary.
- `src/agent/models.py` — strict domain models, reference syntax, lifecycle and trace-link validation.
- `src/agent/test_catalog.py` — six immutable descriptive test contracts.
- `src/agent/policy.py` — pure proposal eligibility checks and evidence-index metadata.
- `tests/test_agent_contracts.py` — schemas, lifecycle, trace, privacy and specification tests.
- `tests/test_agent_policy.py` — policy, provenance, risk, endpoint and parameter checks.
- `TASK_9_1_COMPLETION.md` — this report.

Existing accepted local work from Tasks 7.1.1, 7.2, 8.1 and 8.1.1 was preserved. No production pipeline, dashboard, report generator or scan-state code was modified by Task 9.1.

### SPEC.md Structure
The root specification covers principles, canonical evidence, product pipeline, three reasoning roles, non-agent components, feedback/re-planning, autonomy, finding lifecycle, schemas, transparent trace, catalog/policy, lineage/privacy, coverage and future chaining/PoC/history milestones.

### Canonical Principles
All ten required principles are documented and tested, including no evidence/no finding, reproduction for confirmation, output/evidence distinctions, observation/causation distinction, incomplete coverage and mandatory provenance/policy.

### Agent Roles
Exactly three future reasoning roles: Context Analyst, Test Planner, Evidence Verifier. Their responsibilities and prohibited actions are explicit. No role runtime exists.

### Non-Agent Components
Policy Gate, Test Catalog and schema/domain validators are deterministic implementations. Evidence Store, Coverage Engine and Deterministic Executor responsibilities are specified without introducing new storage, orchestration or execution.

### Feedback Loop
Observe → Context Update → Reason / Plan → Policy Check → Act → Tool Output → Validate → Observe Again. Act remains a future phase; the compact Plan/Act/Observe/Re-plan loop is also documented.

### Re-plan Triggers
Seven allowed triggers are explicit. Re-planning is trigger-based, not continuous or automatic after every step. Denied, unavailable and inconclusive outcomes have stop semantics.

### Finding Lifecycle
Legal transitions are explicit and validated. Hypotheses cannot claim observed/validated/confirmed states. Validated promotion requires ValidationResult evidence; confirmed promotion additionally requires reproducibility with distinct reproduction references. This validates contract edges only, not actual evidence truth or finding creation.

### Transparent Validation
Structured trace references hypothesis, proposal, policy, optional execution/validation, criteria, facts, evidence, next decision and stop reason. Foreign-key, policy and evidence membership checks reject inconsistent traces. Extra fields such as hidden reasoning transcripts fail strict parsing.

### Vulnerability Chaining Future Contract
AttackPath, AttackPathStep and evidence-backed chain edges are documented as future milestone/backlog. No chain edge without evidence; every new action passes policy. No chain runtime was implemented.

### Historical Scan Future Contract
HistoricalFindingReference and changed endpoint/runtime/coverage processing are conceptual contracts. Historical evidence is not automatically current evidence; revalidation may be required. No active historical memory was implemented.

### PoC Contract
Future PoCRecord contains the requested conceptual fields. PoC requires deterministic execution, a reproducible sequence, evidence references and validated expected-vs-observed behavior. No PoC execution or artifact was created.

### Coverage Gaps
CoverageGap is independent, with stable kinds, optional endpoint identity, description, references and blocked tests. Missing-evidence gaps may honestly have no supporting reference. Gaps cannot imply secure/not-vulnerable conclusions.

### Test Catalog
Six immutable entries: AUTHENTICATION_PRESENCE, OBJECT_AUTHORIZATION, FUNCTION_AUTHORIZATION, SESSION_HANDLING, INPUT_VALIDATION, PARAMETER_CONSISTENCY. Every entry supplies required metadata, validation requirements and stop conditions. Entries contain no executable hooks.

### Risk Classes
passive, low, medium, high, destructive. V1 accepts only catalog-matching passive/low eligibility; automatic mode additionally requires the catalog flag. Medium/high/destructive remain blocked. Manual mode cannot bypass the risk block; destructive requests are blocked even when mislabeled.

### Schemas
Eight canonical models plus supporting RequestedAction and ParameterReference. Strict dictionary parsing rejects unknown fields, invalid types/enums/IDs/timestamps, missing actionable references and unsupported action types. ToolExecutionResult cannot itself claim validated/confirmed status. Future-only AttackPath/AttackPathStep/PoCRecord/HistoricalFindingReference live in SPEC, not runtime code.

### Policy Gate
Pure `evaluate_proposal` accepts an untrusted proposal and trusted scan-scoped context/evidence snapshots. Checks include known test/context, exact host/path and evidenced method, risk, whitelist, action/mutation, indexed and context-linked references, required evidence/context and evidenced query/body parameters. Missing prerequisites return needs_evidence; invalid/unsafe requests deny. Stable reason codes and deterministic decision IDs are used. ALLOW is contract eligibility, not execution or target authorization.

The caller must construct the evidence index from already resolved canonical artifacts for one scan. No filesystem, network, request mutation, LLM, tool execution or artifact mutation occurs inside the gate. The gate is not a new evidence loader or store. A future caller must also resolve hypothesis existence and operational scope before any execution.

### Evidence Lineage
Finding → ValidationResult → ToolExecutionResult → TestProposal → AgentHypothesis → EndpointContext → ApiCorrelation → TrafficTransaction / Static Candidate → Provenance. Policy rejects cross-endpoint, missing/unlinked transaction references and falsely attributed source candidate IDs. A correlation surrogate must not masquerade as a source-report ID.

### Privacy Boundary
Schemas carry summaries, metadata and references rather than credential values or raw requests. Extra payload/secret-value fields fail. Common accidental credential strings are rejected; pattern detection is not a substitute for upstream sanitization. Raw JADX/logs/traffic/route graphs and unnecessary historical scans are excluded from future agent inputs.

### Instruction Prompt Boundary
No production agent instruction prompts were created. Future prompt requirements are specified only.

### Tool Calling Boundary
No tool calling, executor, replay, fuzzing, exploitation, API execution, finding generation or agent orchestration was implemented or started.

### Agent State Boundary
No integration into scan state. `agent_analysis=not_available`, Agent Report unavailable. No `agent_report.json` was created.

### Tests
```sh
pytest tests/test_agent_contracts.py tests/test_agent_policy.py -q --tb=short
# 98 passed

pytest tests/test_endpoint_context_builder.py tests/test_static_dynamic_api_correlation.py tests/test_dynamic_analysis_report.py tests/test_scan_state.py tests/test_scan_state_integration.py tests/test_scan_state_recovery.py tests/test_demo_orchestrator.py tests/test_ios_orchestrator_integration.py tests/test_static_analysis_report.py -q --tb=short
# 292 passed, 1 skipped, 18 subtests passed
```
New coverage includes catalog IDs, passive/low eligibility, all blocked risks, invalid output, missing context/evidence, hallucinated targets, location-specific parameter checks, automatic whitelist, lifecycle/reproduction, independent coverage gaps, trace links, privacy, source-vs-surrogate provenance, no external runtime imports, blocked network calls, immutable inputs and unchanged Agent Analysis availability. A policy integration test consumes the actual existing EndpointContext builder output.

### Regressions
**390 passed, 18 subtests passed, 1 skipped, 0 failed.** The existing optional real-device orchestrator smoke test was skipped due to unavailable local prerequisites. No live security testing was run. `git diff --check` is clean.

### Diff Summary
Specification plus four contract-only package files, two focused test files and this completion report. No dependencies added, no existing artifact semantics changed, no commit/push performed. Repository/branch inspected; remote fetched; `git pull --ff-only origin main` reported already up to date; main is 0 ahead/0 behind. Local accepted changes were preserved.

Task 9.1 completed. Agent runtime, tool calling, and active API testing were not started.
