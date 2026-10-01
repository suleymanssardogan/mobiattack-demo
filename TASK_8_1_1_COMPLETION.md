# Task 8.1.1 — Dynamic Report Contract & Regression Cleanup

### Files Changed
- `src/web/request_helpers.py`: optional canonical JSON loader in shared report serving.
- `src/demo_web_server.py`: dynamic report route uses the same resolver/helper as static reports.
- `src/scan_state.py`: initial and recovered Agent Analysis wording.
- `src/templates/dashboard.html`: Agent Analysis card, adapter and reset wording.
- `tests/test_demo_web_server.py`: current dashboard copy and real HTTP report contracts.
- `tests/test_scan_state.py`: current initial Agent Analysis wording.
- `tests/test_dynamic_analysis_report.py`: shared response helper assertions and legacy recovery wording/boundaries.
- `TASK_8_1_1_COMPLETION.md`: this report. Earlier accepted local work was preserved.

### Web Test Failure Root Cause
Stale tests expected the old target label and four internal pipeline titles. The accepted dashboard uses Target Application and five product stages. Tests now assert that existing UI; no product layout was reverted.

### Product Copy Cleanup
Agent Analysis reads “Not available in this scan” in initial state, recovered state, card rendering, adapter and resets. Internal `not_available` vocabulary remains unchanged.

### Static Report Route
`GET /reports/<run_id>/static_analysis_report.json` remains unchanged, including its download behavior. A real HTTP regression test verifies successful retrieval.

### Dynamic Report Route
`GET /reports/<run_id>/dynamic_analysis_report.json` shares `serve_run_file` and `get_run_dir` with static reports. The existing canonical dynamic loader validates the document and requested scan ID before sending its parsed content; it does not reopen an unvalidated file for serving.

### Route Convention Decision
`/reports/<run_id>/<canonical_filename>.json` is the existing canonical report-serving pattern. No new `/api/runs/` route was added. Existing run ID/path containment checks are reused.

### Report Validation
Valid dynamic report returns 200; missing, malformed JSON and structurally invalid documents return 404. Canonical loader and validators remain the source of truth.

### Scan State Invariant
Dynamic completion still requires available=true plus a valid canonical root artifact. Checkpointer registration order and failed-checkpoint guards remain covered. Report Generation stays partial when a valid dynamic report exists without an Agent Report.

### Recovery Invariant
Valid files reconcile availability and completion. Missing/corrupt files clear availability and downgrade stale completion. Recovery also replaces legacy Agent Analysis copy, keeps its status unavailable and clears Agent Report availability.

### Agent Boundary Verification
No Agent Analysis, LLM calls, agent report, replay, attack selection, fuzzing, authorization tests, scoring or vulnerability generation was added or executed.

### Tests
- Web/report HTTP suite: 23 passed.
- Dynamic report suite after recovery assertion extension: 80 passed.
- Endpoint context, API correlation, traffic, runtime and exploration-loop regressions: 279 passed, 18 subtests passed.
- Report, dashboard, state, recovery, orchestrator and pipeline suites: 242 passed, 1 skipped.

Commands run:
```sh
pytest tests/test_demo_web_server.py -q --tb=short
pytest tests/test_dynamic_analysis_report.py tests/test_report_generator.py tests/test_static_analysis_report.py tests/test_split_dashboard_report.py tests/test_product_stage_progression.py tests/test_scan_state.py tests/test_scan_state_integration.py tests/test_scan_state_recovery.py tests/test_demo_orchestrator.py tests/test_ios_orchestrator_integration.py tests/test_dynamic_exploration_pipeline_wiring.py -q --tb=short
pytest tests/test_endpoint_context_builder.py tests/test_static_dynamic_api_correlation.py tests/test_dynamic_traffic_correlation.py tests/test_dynamic_traffic.py tests/test_dynamic_runtime_correlation.py tests/test_dynamic_exploration_loop.py -q --tb=short
pytest tests/test_dynamic_analysis_report.py -q
```
The web suite required permission to bind its local loopback server. HTTP tests exercised local read routes only.

### Regressions
Known web failures are fixed. Existing artifact guards and deterministic correlation behavior remain covered. `git diff --check` is clean.

### Final Relevant Test Status
544 passed, 18 subtests passed, 1 skipped, 0 failed across the three non-overlapping suite runs. The additional standalone dynamic report rerun (80 passed) overlaps the combined suite and is not double-counted. The existing optional real-device orchestrator smoke test was skipped because its required local APK/tool/device prerequisites were unavailable.

### Diff Summary
This task changes only report-serving reuse, Agent Analysis copy and regression coverage/documentation. It leaves accepted Task 8.1 report generation and validation semantics intact. Remote and current main are synchronized (0 ahead, 0 behind); local work is preserved. No commit or push was requested.

Task 8.1.1 completed. Agent Analysis was not started.
