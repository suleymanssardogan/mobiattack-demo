# Task 7.2 — Endpoint Context Builder V1

### Files Changed

- `src/dynamic/context/__init__.py`: public passive builder/model API.
- `src/dynamic/context/models.py`: EndpointContext, EndpointContextArtifact, deterministic IDs, atomic persistence and explicit load errors.
- `src/dynamic/context/endpoint_context_builder.py`: pure evidence aggregation.
- `src/demo_orchestrator.py`: isolated post-correlation production wiring.
- `tests/test_endpoint_context_builder.py`: synthetic builder and wiring tests.
- `tests/test_static_dynamic_api_correlation.py`: existing timeline assertion now identifies the correlation event alongside the new context event.
- `examples/task_7_2/endpoint_contexts.json` and `README.md`: clearly labeled synthetic example.
- This completion report.

Existing reviewed Task 7.1.1 changes remain preserved in the working tree. Remote `main` was fetched and equals local HEAD at `750d82ed63e59bf51c3c982beb27d118bff162ab`; no rebase was needed and no local changes were discarded.

### Context Builder Architecture

`build_endpoint_contexts(api_correlation, traffic_transactions, traffic_evidence=None, runtime_evidence=None)` returns an EndpointContextArtifact. It reuses canonical correlation/traffic/runtime model objects, and accepts canonical serialized transaction dictionaries. It has no ADB, proxy, network execution, LLM, or agent dependency. The orchestrator invokes it after saving `dynamic/api_correlation.json`, loads that artifact, and atomically saves `dynamic/endpoint_contexts.json`.

### Endpoint Identity

One context per canonical correlation entry. IDs hash normalized host, normalized path, static method when available (otherwise sorted observed methods), and canonical correlation ID into `ctx_<sha256[:16]>`. The correlation reference prevents distinct source candidates from accidentally merging. Query values, bodies, timestamps, and transaction order do not enter context identity. Explicit static templates retain canonical aggregation; numeric/UUID literals never acquire wildcard semantics.

### Static Context

Preserves candidate reference, match type, confidence, static method, source file, request line, framework, and candidate-ID origin/source-field provenance. Extraction evidence is represented by field names instead of arbitrary values. Correlation-side references remain distinguishable from IDs actually present in the source report.

### Dynamic Context

Carries canonical transaction IDs, observation count, observation times, observed methods/statuses, available transaction count, and missing transaction IDs. Runtime observation remains evidence from correlation even when a transaction body is unavailable. Scheme comes from linked requests; mixed or unavailable schemes remain null, with observed schemes listed separately. A static-only entry has unknown scheme because the correlation artifact does not retain static URL scheme.

### Request Context

Aggregates methods, lowercase header names, validated MIME types without parameters, query key names, body presence, body keys/types/shapes and available body byte sizes. It never embeds raw body or header values.

### Auth Context

Descriptive presence flags for Authorization, Bearer, Cookie, session cookie and API key headers. Existing canonical traffic redacts entire Authorization/Cookie values. Their presence remains true; Bearer/session subtype is null when redaction prevents determination. Concrete readable values can establish these subtypes, but never enter the output. These flags are not authentication or authorization verdicts.

### Body Shape Extraction

Scalar values become type names. JSON recursion stops at depth 3; objects retain at most 32 keys; arrays sample only their first element. Sensitive nested values become type names without traversing their contents. JSON text parsing is bounded to 1 MiB; form parsing retains at most 32 fields. Multipart uploads are not parsed because the current model does not expose structured file-part metadata. Binary bodies use presence/size metadata without hashes or contents.

### Response Context

Distinct statuses and MIME types, status-count mapping, header names, body presence/types/keys/shapes and available byte sizes. Counts reflect available linked responses and do not invent counts for missing transactions. Sensitive response values never persist.

### Action / Route Context

Uses canonical traffic action-to-transaction links. Compact action/source/target IDs are retained; canonical correlation route references are reused and deduplicated. No full UI tree or RouteGraph is loaded or copied. Repeated action IDs retain runtime aggregation through their existing evidence references.

### Runtime Context

Links by action ID and aggregates PID change, process death, activity change, fatal and crash observations. Unrelated/unavailable action evidence cannot contribute positive flags. `evidence_available` distinguishes absent evidence from a collection in which no positive flag was observed. No snapshots, log events or runtime diff payloads are embedded, and no causal security verdict is made.

### Visibility Context

Preserves correlation summary's HTTP visibility, HTTPS visibility and HTTPS reason, including partial/unavailable visibility.

### Evidence References

Preserves static candidate references, correlation IDs, transaction IDs, action IDs and linked runtime action IDs. Source artifact schemas are reused without duplicate source files or schema definitions.

### Privacy / Redaction

No request/response scalar values, query values, credentials, cookie values, upload contents, raw logs, hashes, or complete source artifacts are copied. Scanner filesystem paths in retained provenance/reference metadata use the existing path sanitizer. Tests cover sensitive keys, nested sensitive objects and arbitrary extraction evidence values.

### Static-Only Handling

Produces context with `observed=false` and the precise descriptive note: `Not observed in available runtime traffic.` It makes no endpoint availability verdict.

### Dynamic-Only Handling

Produces transaction/request/response context and available action/runtime links. `static` is empty and static candidate references are empty; no provenance is fabricated.

### Failure Isolation

Builder and persistence failures are logged and isolated. Source artifacts and existing scan state remain byte-for-byte unchanged. Atomic replacement cleans temporary files and preserves an existing output if replacement fails. Missing optional evidence is supported; malformed runtime evidence is logged and treated as unavailable. Timeline failures do not remove context output. Without a saved correlation artifact, wiring creates no context artifact.

### Product Integrity

Current stage semantics are untouched: dynamic_analysis and report_generation remain partial where already partial. No canonical Dynamic Analysis Report or Agent Report is created. No request replay, API security test selection or active testing was added.

### Agent Boundary Verification

No Agent Analysis, LLM calls, AI reasoning, orchestration agents, test selection agents, vulnerability verdicts or security recommendations were added. `agent_analysis` is not modified. Before a later task enters Agent Analysis, the user must be explicitly warned; this task does not authorize that transition.

### Tests

`pytest tests/test_endpoint_context_builder.py -q`: **72 passed**. Covers all requested areas plus redacted subtype uncertainty, literal endpoint separation, missing transaction references, mixed schemes, malformed runtime input, bounded forms, binary metadata, atomic replacement failure and timeline failure.

### Regressions

Requested correlation/dynamic group: **233 passed, 18 subtests passed**.

Static report/context, state/recovery/integration, Android/iOS orchestrator and report/dashboard suites: **135 passed, 1 skipped**.

Total: **440 passed, 18 subtests passed, 1 skipped**. `git diff --check` passed.

### Example EndpointContext

The synthetic example contains `POST https://api.example.com/login`, source candidate `cand_login`, transaction `tx_1`, action `act_login`, request keys `password`/`username`, response keys `token`/`user_id`, and descriptive runtime flags. No corresponding values persist. It is the first entry in `examples/task_7_2/endpoint_contexts.json`.

### Example endpoint_contexts.json

The complete synthetic artifact is `examples/task_7_2/endpoint_contexts.json` with schema version 1.0, session `session-123`, one runtime-observed context and no static-only/dynamic-only entries. Its README explicitly labels it synthetic. It is not evidence of a device observation.

### Real Run Directory

No existing real dynamic correlation/traffic/runtime artifact was found under `demo_runs`, and no device run was started for this synthetic-only task. Production wiring will write `demo_runs/<run_id>/dynamic/endpoint_contexts.json` after `api_correlation.json` exists. A real artifact was not fabricated; existing run directories were left unchanged.

### Diff Summary

Added the small context package, post-correlation isolated wiring, synthetic tests, example JSON and this report. The only Task 7.2 change to prior correlation tests accommodates the additional compact timeline event. Reviewed Task 7.1.1 matching and provenance changes are preserved.

Task 7.2 completed. Agent Analysis was not started.
