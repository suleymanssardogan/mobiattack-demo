# Task 9.2 completion — Context Analyst V1

### Files Changed
- Updated `SPEC.md` for the isolated Task 9.2 runtime and remaining milestone boundaries.
- Added `src/agent/model_client.py` (provider-neutral protocol and bounded metadata).
- Added `src/agent/context_analyst/`: `__init__.py`, `models.py`, `input_builder.py`, `prompts.py`, `context_analyst_v1.txt`, `validation.py`, `service.py`, `persistence.py`.
- Updated the agent package description and Task 9.1 package-inventory test for the new interface; canonical Task 9.1 domain fields remain unchanged.
- Added `tests/test_context_analyst_input.py`, `tests/test_context_analyst.py`, and offline helper `tests/context_analyst_fakes.py`.
- Added synthetic `examples/task_9_2/` input, valid/rejected outputs, internal persistence example and README.
- Added this completion report. Earlier accepted local changes were preserved.

### Context Analyst Architecture
One EndpointContext → deterministic sanitized input → versioned instruction/schema → AgentModelClient → strict deterministic validation → canonical observation/hypotheses/gaps. The service and bounded batch helper are isolated; no production scan wiring exists.

### Input Boundary
One endpoint per request. Canonical artifact loading reuses EndpointContextArtifact, selects an exact unique ID, checks run-path containment and file size, and does not send unrelated endpoints.

### Input Sanitization
Explicit allowlists exclude raw headers/credentials/bodies/logs/JADX, unrelated graph data and absolute source paths. Shapes retain only known type tags or unknown. Sorted collections, depth/node budgets, 32 KiB input limit and explicit truncation gaps bound model input. Source collections exceeding hard limits fail before a model call.

### Instruction Prompt
Production instruction is an application asset at `src/agent/context_analyst/context_analyst_v1.txt`. It prohibits invented facts, security verdicts, unsupported auth/authorization inference, TestProposal, test selection, executable recommendations, tools and private reasoning transcripts.

### Prompt Version
`context_analyst_v1` is recorded in requests, results, traces and the persisted artifact.

### Model Client Boundary
`AgentModelClient.generate(ModelRequest) -> ModelReply`. Requests carry sanitized detached data and output schema. Metadata carries only provider/model labels. There is no tool/action channel.

### Provider Decision
No existing clean provider abstraction was found. Added only the minimal interface; fake clients exist under tests. No live provider, SDK, network dependency, API key or credential-configuration change was introduced.

### Output Schema
ContextAnalystInput and ContextAnalystResult wrap the existing canonical AgentObservation, AgentHypothesis and CoverageGap. Canonical fields/required names inform the output schema; context-specific consistency is checked separately. The result wrapper carries role, status, IDs, version, timestamps, attempts, safe metadata and fixed diagnostic codes. No parallel canonical domain definitions were created.

### Observation Semantics
V1 observations must preserve the supplied supported fact catalog, including identity, static/runtime distinctions, method mismatch, unknown auth, shapes and visibility. New prose claims are rejected. Runtime events remain observations with causality unknown. Descriptive role is selected from supported roles; unknown is always allowed.

### Hypothesis Semantics
Seven bounded types are recognized. The model selects supported evidence-backed questions with their known statements, preconditions and required evidence. Every emitted hypothesis explicitly starts at hypothesis, never planned/validated/confirmed. Numeric/UUID path literals do not manufacture identifier templates. Static-only administrative paths alone do not support function/object authorization hypotheses.

### Coverage Gap Semantics
Known limitations must survive output validation as separate canonical CoverageGap records linked from the observation. Missing HTTPS/traffic/runtime/action/auth evidence and supplied exploration/boundary metadata remain explicit. This consumes existing metadata and is not a second Coverage Engine. Optional coverage questions never replace or promote gap records.

### Unknown vs False Handling
Absent auth flags, redacted subtype flags and unobservable static-only auth stay null. Body absence without observational evidence stays unknown. Unavailable runtime evidence cannot establish event absence. False values supported by observed metadata remain false and are described as not observed, not secure/absent globally.

### Evidence Reference Validation
The universe contains only canonical references derived from the selected context. Missing transaction IDs and falsely attributed static surrogate IDs are excluded. A caller-supplied availability set can only narrow it. Every output reference must exist in the original snapshot; mutating the client's detached copy cannot authorize a fabricated reference.

### Endpoint Identity Validation
Root output and every observation/hypothesis/gap must identify exactly the input endpoint. Deterministic record IDs and creation time are constrained. Mismatches reject the whole output.

### Forbidden Fields
Unknown fields fail at every record. Explicit boundaries cover severity/finding/vulnerability/CVSS/PoC/exploit, test_id/requested_action/mutations/auto_execute/test_plan, tool fields and private reasoning. Extra raw payload/credential fields are not accepted.

### Failure Modes
completed, invalid_output, model_error, input_invalid. Failure results carry no fabricated observation/hypotheses/gaps. Provider exceptions and rejected raw output are not echoed or persisted; traces contain fixed codes only.

### Retry Policy
At most two attempts; one attempt can be configured. Only invalid output retries with a fixed correction containing no rejected content. Provider errors stop. No unbounded loop.

### Persistence
Explicit `save_context_analyses` writes only successful results to `<run_dir>/agent/context_analysis.json`. Schema/version and endpoint-sorted analyses are stored atomically with bounded size/count. Successful records merge; failed endpoints do not erase others. A retained prior success keeps its original timestamp. Corrupt existing artifacts are rejected; failed replacement preserves the previous file and cleans temporary files. Callers serialize writes per run.

### Product Stage Boundary
No product state integration. Tests verify byte-for-byte unchanged scan_state.json, agent_analysis=not_available and Agent Report unavailable. No agent_report.json is created.

### Tool Calling Boundary
No tools, HTTP request execution, replay, fuzzing, active testing, exploit or executor exists. Tests block network calls while exercising the runtime.

### Test Planner Boundary
No TestProposal generation, Test Catalog selection or Policy Gate invocation. Tests explicitly fail if those APIs are invoked. Test Planner and Evidence Verifier runtimes remain absent.

### Finding Boundary
The role emits evidence-backed questions and observations only. Presence/status codes cannot establish authentication/authorization correctness. Unsafe prose and attempted lifecycle promotion are rejected. No finding, severity, confirmed vulnerability or PoC generation.

### Tests
```sh
pytest tests/test_context_analyst_input.py tests/test_context_analyst.py tests/test_agent_contracts.py tests/test_agent_policy.py -q --tb=short
# 225 passed

pytest tests/test_endpoint_context_builder.py tests/test_static_dynamic_api_correlation.py tests/test_dynamic_analysis_report.py tests/test_scan_state.py tests/test_scan_state_integration.py tests/test_scan_state_recovery.py tests/test_demo_orchestrator.py tests/test_ios_orchestrator_integration.py -q --tb=short
# 283 passed, 1 skipped, 18 subtests passed
```
Coverage includes privacy, shapes, exact identity and three-state semantics, explicit templates, supported hypotheses, hallucinated references, forbidden fields at multiple levels, omitted coverage/method facts, deterministic output, fake/provider failures, two-attempt bounds, batch isolation, atomic persistence failure and unchanged product state.

### Regressions
**508 passed, 18 subtests passed, 1 skipped, 0 failed.** The existing optional real-device orchestrator smoke test was skipped for unavailable local prerequisites. No live provider or active API testing was run. `git diff --check` is clean.

### Example Input
`examples/task_9_2/input.json`: GET `/orders/{id}`, authorization/cookie presence, unknown bearer/session subtype, observed runtime, typed shapes and canonical references. Synthetic fixture, not live scan evidence.

### Example Valid Output
`examples/task_9_2/valid_result.json`: completed fake-backed result, resource_endpoint role, preserved supported facts, hypothesis-state questions and safe metadata. It is not a security finding or Agent Report.

### Example Rejected Hallucinated Output
`examples/task_9_2/rejected_model_output.json` deliberately includes `dynamic/traffic.json#transaction_id=tx_fake_999`. `rejected_result.json` demonstrates invalid_output after two attempts with EVIDENCE_REF_NOT_SUPPLIED and no fabricated analysis. This is a synthetic documentation example; production code never stores rejected raw replies.

### Diff Summary
Isolated read-only Context Analyst runtime, bounded adapters/validators, versioned prompt, optional internal persistence, tests and documentation. No changes to canonical product-stage or static/dynamic artifact semantics, no live provider and no active execution. Repository and main were inspected, fetched and pulled with --ff-only; already up to date. Accepted dirty work was preserved. No commit or push requested.

Task 9.2 completed. Context Analyst runtime was introduced. Tool calling and active API testing were not started.
