# Task 8.1 — Canonical Dynamic Analysis Report V1

### Files Changed

- `src/dynamic/report/{__init__,models,generator}.py`: passive projection, canonical validation, atomic persistence.
- `src/report_generator.py`: facade in the existing report architecture.
- `src/demo_orchestrator.py`: finalized-evidence reporting and checkpoint ordering; artifact-aware dynamic updates.
- `src/scan_state.py`: physical report integrity, artifact-aware checkpointer, recovery reconciliation.
- `src/demo_web_server.py`: canonical read-only route and validated scan_state in live status responses.
- `src/templates/dashboard.html`: small canonical dynamic-stage override; no layout or report-page redesign.
- `tests/test_dynamic_analysis_report.py`: synthetic report/state/recovery/API/stage-adapter tests.
- Existing correlation/runtime/traffic/exploration wiring tests: migrate only the previous milestone's unconditional no-report/no-completion assertions.
- `examples/task_8_1/{dynamic_analysis_report.json,scan_state.json,README.md}` and this report.

Reviewed Task 7.1.1/7.2 local changes were preserved. Remote `main` was fetched and matches local HEAD at `750d82ed63e59bf51c3c982beb27d118bff162ab`; no rebase or overwrite was needed.

### Report Generator Architecture

The existing `src/report_generator.py` exposes `generate_dynamic_analysis_report(run_dir, target=None)` through a specialized passive `src/dynamic/report` module. The pure `build_dynamic_analysis_report(scan_id, artifacts, target=None, generated_at=None, source_errors=None)` projects existing canonical source dictionaries without mutating them. The file-backed facade loads finalized artifacts, writes the root report atomically, reloads it, and validates it. No new scanning logic or source schema copies were added.

Production ordering is finalized exploration/traffic evidence → API correlation → EndpointContext → canonical report persistence → integrity validation → availability checkpoint → dynamic stage completion. Missing optional correlation/context evidence remains explicitly unavailable rather than preventing a viable partial-coverage report.

### Canonical Schema

Root artifact: `dynamic_analysis_report.json`, schema version `1.0`, report_type `dynamic_analysis`, scan_id and generated_at. Sections: target, coverage, preflight, session, exploration, routes, runtime, traffic, traffic_correlation, api_correlation, endpoint_context_summary, compact endpoint_contexts, evidence and evidence_status. Integrity validates required sections, viability, coverage vocabulary, counts, endpoint rows, auth flag types and relative references, and rejects raw payload/finding fields.

### Report Status vs Coverage

`report_status=completed` means report projection/persistence succeeded. `analysis_coverage=partial` remains truthful when exploration or any reported capability is partial/unavailable/not_observed. `analysis_coverage=complete` requires all reported capability states to be available and no corrupt source artifacts. This does not assert complete security testing. Product dynamic completion is artifact-based, while actual exploration status and visibility remain unchanged in the report.

### Preflight Summary

Readiness status, observed launch/process booleans and recognized diagnostic codes only. Missing preflight yields unavailable readiness and null launch/process values. No commands, executable/install paths, warning payloads or fatal log snippets are copied. Session summary retains the evidence session ID, actual status and available timestamps without flows or timeline duplication.

### Exploration Summary

Preserves completed/partial/failed, stop reason, steps attempted, successful/failed actions, screens, transitions and duration. Minimum viability requires a valid executed session and exploration evidence with at least one positive screen, attempted step, successful action or recorded transition. A created-only session or essentially zero execution does not produce a completed canonical report. Failed exploration with actual evidence may still produce a successful partial-coverage report.

### Route Summary

Counts nodes, edges, discovered actions, self-loops and distinct system/external boundary nodes; retains root/current node references. It does not copy nodes, edges, UI text or the full graph.

### Runtime Summary

Aggregates usable available/partial action observations: correlated action-record count, PID changes, process deaths, activity changes, target fatal and crash appearances. Unavailable records cannot contribute positive signals. Counts refer to evidence windows, not security findings. No snapshots, diffs, compact events or raw logcat are retained.

### Traffic Summary

Backend, observed transaction/HTTP/HTTPS counts, sorted normalized hosts and host count, canonical HTTP/HTTPS visibility/reason, and proxy-restored metadata. Transaction counts derive from canonical stored records. Incomplete visibility carries an explicit note that unobserved requests may exist; zero captured records never becomes a claim of no network activity. Action traffic correlations receive compact available/partial/unavailable counts.

### API Correlation Summary

Preserves static candidate, dynamic endpoint, correlated, static-only and dynamic-only totals. Counts exact/template/method-mismatch entries and preserves the safe visibility note. Matching semantics remain those of Task 7.1.1; no fuzzy grouping or heuristic endpoint inference was introduced.

### Endpoint Context Summary

Counts contexts, runtime-observed contexts and static-only/dynamic-only entries. Compact rows retain context identity, host/path, separate static/observed methods, match type/confidence, observation/status metadata, boolean-or-null auth presence, action IDs and canonical evidence references. Request/response body shapes and values are not duplicated into report rows.

### Evidence References

Only validated available source artifacts receive fixed relative paths such as `dynamic/traffic.json`. Evidence status distinguishes available, missing and corrupt. Reference lists, methods, status codes, hosts and endpoint rows are sorted deterministically; generation time is the intentional timestamp exception.

### Privacy

Allowlisted compact projection excludes raw Authorization/Bearer/Cookie/API-key/password/session values, query values, raw bodies, upload contents, logcat, UI texts and workspace/executable paths. Existing path sanitization is reused for retained strings. Auth metadata accepts only boolean/null presence fields. Internal dynamic session/evidence IDs remain references, not credentials. Source artifacts and static report are untouched.

### Missing Evidence Handling

Optional missing/corrupt evidence yields unavailable/not_observed capability states and explicit evidence_status entries. Invalid source JSON/schema is not silently counted as available. Required session/exploration corruption or zero execution raises DynamicReportUnavailable and leaves canonical report generation unavailable; wiring isolates the failure from existing evidence/static results.

### Atomic Persistence

Validate first, write a unique temporary file, flush/fsync, then atomic replace at the run root. Failed replacement preserves the previous output and cleans the temporary file. File-backed generation reloads and validates the persisted report before returning success.

### Dynamic Artifact Registration

Uses actual existing fields: `artifacts.dynamic_analysis_report.available=true` and `relative_path="dynamic_analysis_report.json"`. The orchestrator checkpoints this availability before the separate completed-stage checkpoint. Checkpointer migration also persists newly discovered availability before upgrading the stage; checkpoint failure cannot produce a completed stage.

### Dynamic Stage Completion Rule

Completion requires the registered canonical root filename and a physically present, valid, scan-ID-consistent report. `save_scan_state` and normal `load_scan_state` validate the physical report for available dynamic artifacts. Pure structural validation remains usable without filesystem context; passing run_dir additionally validates physical integrity. A report file alone cannot override failed persistence/integrity checks during production completion.

### Old Guard Migration

Unconditional completed→partial coercion in ScanStateCheckpointer and `_update_scan_state_dynamic_stage` is now artifact-aware. Evidence-only execution still remains partial when no valid canonical report exists. Existing milestone tests now assert validated report-backed completion rather than unconditional non-completion. Matching/evidence tests remain intact.

### Recovery Semantics

Recovery loads structural state without trusting stale availability, validates the canonical dynamic report, reconciles its availability and completed stage, and persists repairs. Missing/corrupt reports clear availability and downgrade a previously completed dynamic stage to partial. Valid report recovery works even when state is missing/corrupt, including dynamic-only reconstruction. Overall terminal status semantics are retained, and Agent Analysis remains unavailable.

### Report Generation Stage

Remains partial because the Agent Report is absent. Static+dynamic report availability does not complete the full product reporting stage. Overall status retains its established pipeline meaning.

### Agent Boundary Verification

No Agent Analysis, LLM dependency/call, AI reasoning, attack selection, exploitation, request replay, fuzzing, AuthN/AuthZ tests or vulnerability generation was implemented. No agent report is created. A future task must explicitly warn the user before entering Agent Analysis; this task does not authorize that transition.

### Tests

`pytest tests/test_dynamic_analysis_report.py -q`: **80 passed**. Includes pure artifact generation, minimum viability, privacy, determinism, optional corruption, persistence failure, registration ordering, checkpoint failure, missing/corrupt canonical reports, recovery, read-only API dispatch and actual JavaScript stage-adapter execution without network access.

### Regressions

- Requested endpoint/correlation/traffic/runtime/exploration group: **261 passed, 18 subtests passed**.
- Requested state/integration/orchestrator/static-report group: **64 passed, 1 skipped**.
- Recovery/product-stage/exploration-wiring group: **69 passed**.
- Additional iOS orchestrator/static-context/report/dashboard-report group: **51 passed**.
- Existing web suite: **20 passed, 2 pre-existing failures**.

The web failures are `test_index_page_returns_200_and_contains_dashboard_elements` and `test_platform_selector_and_modular_url_html`. Both expect the old `Target URL (Direct APK or Google Play Store)` text, which is absent in the original HEAD dashboard as well. These unrelated stale dashboard assertions were not changed, and the UI was not redesigned to satisfy them. Loopback web tests required sandbox escalation; actual report generation sent no requests.

Across the final disjoint groups: **545 passed, 18 subtests passed, 1 skipped**, with those **2 known baseline failures**. `git diff --check` passed.

### Example dynamic_analysis_report.json

`examples/task_8_1/dynamic_analysis_report.json` is explicitly synthetic. It has completed report generation and partial coverage; 10 attempted steps, 4 screens, 3 traffic records (1 HTTP/2 HTTPS), one observed crash flag, 3 correlated API entries and 5 compact endpoint rows. None of those observations becomes a finding.

### Example scan_state

`examples/task_8_1/scan_state.json` illustrates completed static/dynamic stages, unavailable Agent Analysis, partial report_generation and root dynamic-report availability using the canonical field names. README labels it synthetic and states that source evidence/static report references are illustrative; source artifacts were not duplicated into the example directory.

### API Route

Read-only route follows the actual existing static-report architecture: `GET /reports/<run_id>/dynamic_analysis_report.json`. Valid canonical reports return 200; absent, corrupt or identity-mismatched reports return 404. Live status exposes validated canonical scan_state, and the existing dashboard stage adapter uses it to display Dynamic Analysis completion with the canonical artifact guard. No new report page or major dashboard redesign was added.

### Real Run Directory

No existing session/exploration evidence was found under demo_runs and no device/API execution was started. Therefore no real observation directory was fabricated. Production writes the canonical root report alongside scan_state/static report; source evidence remains under dynamic/. The delivered examples are synthetic and clearly labeled.

### Diff Summary

Added passive canonical report projection/validation/persistence, existing report facade, ordered production registration, artifact-aware completion/recovery, read-only route, minimal stage-state UI integration, synthetic tests and examples. Preserved the previously reviewed Task 7.1.1/7.2 work. No prohibited scanning or Agent Analysis capability was added.

Task 8.1 completed. Agent Analysis was not started.
