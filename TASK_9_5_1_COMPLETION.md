# Task 9.5.1 — Real Benchmark Dataset Preparation

### Files Changed
Added src/agent/evaluation/real_dataset.py, tests/test_real_benchmark_dataset.py,
benchmarks/agent_v1/real/{README.md,manifest.json}, examples/task_9_5_1/
(app_metadata.json, unreviewed_case.json, reviewed_case.json, review_template.json,
manifest.json, README.md), and this report. Existing production roles, shared
models, scorer, synthetic fixtures, runner and product code are unchanged.

### Real Dataset Architecture
Pure candidate builder, canonical sanitizer, strict parser, app-level export,
separate review application, aggregate validation and split-aware selection.
The importer does not scan applications or discover source folders.

### Synthetic vs Real Separation
Existing synthetic core remains at benchmarks/agent_v1/cases. Real imports have
their own real/manifest.json and app-specific directories. Examples are outside
both official selections and explicitly synthetic.

### App Metadata
Authorization classification, anonymous app alias, android platform, explicit
split/holdout, case_count, sanitized flag and aggregate review status.
No account/owner identity. Source classification is not proof of authorization.

### EndpointContext Import
Reuses canonical EndpointContext/EndpointContextArtifact. Accepts an explicit
endpoint_contexts.json path or typed artifact. Source file limit 2 MiB;
initial app endpoint limit 256. Source artifacts are never written.

### Sanitization
Allowlisted summaries only; no raw credentials, header values, bodies, logs,
filesystem paths or model outputs. Invalid presence becomes unknown; invalid
body-shape values become unknown. Unsafe exported fields fail validation.

### PII Minimization
Email/phone-like values are rejected or minimized; structural names remain.
Concrete numeric/UUID path identifiers become stable literal aliases. Sensitive
names/slugs must be supplied explicitly and inspected manually; no general DLP
claim. Password parameter names in type-only shapes are safe structural metadata.

### Alias Strategy
App-scoped host/resource digests, consistent across cases, distinct per host.
No exported reverse mapping. Explicit templates preserved; literal identifiers
never become templates. Python callers can preserve a safe public host explicitly.

### Case Schema
RealBenchmarkCase wraps canonical EndpointContext plus safe source, tags,
coverage, review and nullable gold; schema 1.0, real_pilot_v1.
Stable case ID hashes app_id + endpoint_context_id.
No competing endpoint or proposal schema.

### Human Review Workflow
Generated candidates are unreviewed, gold=null. Separate label templates and
save_review update only review/gold plus aggregate metadata/manifest.
Anonymous reviewer_1/reviewer_2 supported. Unreviewed/disputed/excluded/reviewed
states validated. Existing app exports cannot silently overwrite reviews.

### Gold Label Strategy
Existing scorer vocabulary reused. Gold is explicitly human-entered and
independent of Analyst/Planner results. Human-supported missed labels are
accepted even if the current system heuristic lacks a candidate.

### Multi-Label Semantics
Zero or multiple allowed/expected/forbidden hypotheses and expected/forbidden
tests. Expected hypotheses must be allowed; positive/negative contradictions
are rejected. Current endpoint-role enum remains singular.
Separate acceptable_test_ids is not added because current scoring has no clean
support for that vocabulary.

### Development Split
Explicit app-level development split; default loader returns reviewed
development cases only. No random reassignment.

### Holdout Split
holdout=true must agree with split=holdout. Explicit include_holdout=True is
required to include it. Supports 3–4 apps without hardcoding identities or
fabricating applications.

### Holdout Leakage Prevention
Split, tags, review notes and gold do not enter model_input. Administrative
validation can inspect holdout data; tuning with it is prohibited by workflow.
The importer cannot enforce what a human manually reads outside this boundary.

### Coverage Metadata
Preserves endpoint visibility, runtime observation, evidence availability,
missing transaction IDs and match type. Python import accepts bounded scan-level
traffic/exploration coverage. CLI does not invent unavailable scan coverage.

### Static-Only Handling
Production adapter says not observed in available runtime traffic; never unused.
Unknown auth remains unknown when runtime evidence is insufficient.

### Dynamic-Only Handling
Production adapter says no matching static candidate identified; never an
automatic static analyzer failure verdict.

### Dataset Versioning
Real family real_pilot_v1; overall agent_benchmark_v1 remains unchanged.
Manifest has deterministic dataset_fingerprint including app metadata, inputs,
review and gold, independent of generated_at. Freeze prompts/scoring/gold/splits
and fingerprint before comparison. A changed dataset needs an explicit version
update; this first parser accepts only real_pilot_v1.

### Manifest
App IDs/count, all review-status counts, development/holdout counts, category
counts, schema/benchmark/dataset versions, generated_at and snapshot fingerprint.
Checked against all declared app files. Actual manifest: 0 apps, 0 cases.

### Validation
Rejects duplicate cases/apps, absent app metadata, split/provenance/file identity
mismatch, invalid categories, unsupported gold IDs/roles/gaps, contradictions,
reviewed cases without gold/reviewer, unsafe fields and stale counts/fingerprint.
Resolved output paths cannot escape dataset root.

### Secret Safety Validation
Lightweight generic privacy guard plus real-specific raw payload/value names
and obvious personal values. Credential *names* are accepted only as type-only
shape metadata; raw values are never accepted there.

### Benchmark Leakage Prevention
model_input uses only canonical endpoint and coverage via the existing production
input builder. scoring_case requires reviewed status and supplies existing
BenchmarkCase structure. No gold/review/tags/split are passed to roles.
The existing synthetic runner is not modified to auto-ingest real cases;
future comparison wiring must explicitly select reviewed cases.

### Import Workflow
python -m src.agent.evaluation.real_dataset --endpoint-contexts <artifact>
--app-id app_001 --source-type owned_app --split development
--output benchmarks/agent_v1/real.
Optional --scan-reference and repeatable --sensitive-path-segment.
Each JSON is replaced atomically; no multi-file transaction is claimed.
Validation flags partial/interrupted dataset writes.

### Review Template
Separate case_id/review/gold object with empty structured label lists.
Application via apply_review/save_review cannot change input.

### README Workflow
Documents authorized pipeline → artifact → sanitized candidates → independent
human review → labels → validation → app holdout → frozen Task 9.6 comparison.
Includes exact CLI and Python review/selection commands.

### Provider Independence
No provider-specific fields or new client abstractions. Future local
Qwen/DeepSeek/compatible clients can reuse AgentModelClient; none implemented.

### Product Stage Boundary
No product files changed. agent_analysis remains not_available.
No agent_report.json.

### Focused Tests
Focused tests: PASSED.
pytest tests/test_real_benchmark_dataset.py -q:
34 passed. Covers conversion/immutability/provenance, splits/review/counts,
secrets/PII/type shapes, aliases/IDs, gold validation/leakage, coverage wording,
filesystem boundaries, atomic replacement failure and network/process guards.
CLI --help and git diff --check also verified.
No shared evaluation model/scorer changes, so no adjacent suites required.

### Full Regression Checkpoint Status
Full regression checkpoint: NOT RUN — Task 9.5 was the latest checkpoint.
No claim that this new diff has passed the entire repository suite.

### Example Unreviewed Case
examples/task_9_5_1/unreviewed_case.json: sanitized canonical input, source,
resource/object_access tags, unreviewed status and gold=null.
Synthetic format demonstration only.

### Example Reviewed Case
examples/task_9_5_1/reviewed_case.json: the same synthetic input with structured
object_authorization_candidate/OBJECT_AUTHORIZATION labels and anonymous
reviewer_1. Not actual human-reviewed application evidence.

### Example Manifest
examples/task_9_5_1/manifest.json shows one reviewed-format synthetic example;
real/manifest.json honestly contains zero applications and cases.

### Real Data Availability
No actual authorized EndpointContexts were supplied. Real data is not imported.
Infrastructure and synthetic examples are ready for manual authorized import.
No arbitrary local artifact discovery or historical processing performed.

### Diff Summary
Development-only importer, validator, human-review and holdout infrastructure,
focused tests, empty real-family manifest and explicitly synthetic examples.
No live benchmarks, model execution, tool calling, executor, request replay,
active API testing, findings, PoC or Agent Report.

Task 9.5.1 completed. Real benchmark dataset infrastructure is ready. Live model benchmarking, tool calling, executor, and active API testing were not started.
