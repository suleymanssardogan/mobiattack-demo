# Task 9.5.2 — Real Pilot Dataset Population

### Authorized Inputs Discovered
Initial workspace discovery: 1 distinct authorized training application APK,
0 usable canonical endpoint_contexts artifacts. Existing APK copies were not
counted as separate apps. The original Kotlin APK hash matched a previous run's
official OWASP download receipt. Additional official training inputs were
acquired through existing MobiAttack acquisition, yielding 3 analyzed apps.
Commercial APKs in prior workspaces were excluded because analysis authorization
could not be established. Synthetic examples/presets were not counted as real.

Authorization sources:
- https://mas.owasp.org/MASTG/apps/android/MASTG-APP-0012/
- https://github.com/OWASP/MASTG-Hacking-Playground/releases/tag/1.0
- https://github.com/dineshshetty/Android-InsecureBankv2

### Applications Selected
app_001: OWASP Kotlin Playground, intended development.
app_002: OWASP Java Playground, intended development.
app_003: InsecureBankv2, intended holdout.
Only app_001 supplied a nonempty EndpointContext and was imported.
These are actual training APKs, not duplicate copies or fabricated applications.

### Source Artifact Status
app_001: static completed, runtime launch succeeded, bounded exploration partial
(max_depth), traffic capture unavailable because proxy port 8080 was occupied;
canonical endpoint_contexts.json contains 1 static-only endpoint.
app_002: static completed, runtime failed INSTALL_FAILED_NO_MATCHING_ABIS,
0 static API candidates, canonical empty EndpointContext projection.
app_003: static completed, runtime failed INSTALL_FAILED_DEPRECATED_SDK_VERSION
(target SDK 22; emulator requires >=24), 0 static API candidates, canonical
empty EndpointContext projection. No APK patching or install-policy bypass.

Actual source runs are under demo_runs/task_9_5_2_app_001 through app_003.
APK hashes and source URLs are recorded in
examples/task_9_5_2/population_status.json; source artifacts remain ignored local
run material. Only safe summarized provenance enters tracked benchmark cases.

### Existing Scans Reused
No existing usable canonical real artifact was available. Reused the verified
local Kotlin APK rather than downloading it again; existing run receipt supplied
source/hash verification. Other old runs and synthetic demonstrations were not
relabelled.

### New Scans Required
Ran 3 existing acquisition/preprocessing/static/runtime pipelines sequentially.
Local Kotlin acquisition used a temporary loopback server serving only that APK;
remote training APKs came from their official project sources.
All canonical stages were reused. A progress callback used the existing static
report projector before correlation reads that artifact. On failed launches,
the existing correlation/EndpointContext projection was reused with the actual
ABORTED session to preserve available static evidence; it produced 0 cases.
No new scanner or architecture change was introduced.

### Application Split
Imported: app_001 development. Intended but unusable sources: app_002 development,
app_003 holdout. No zero-case app was imported to inflate application counts.
No application was split across development/holdout.

### EndpointContexts Imported
1 actual canonical endpoint, producing 1 stable real_app_001 case.
Source artifact SHA-256 was unchanged before/after import. No source artifact
was overwritten or supplemented with fake transactions.

### Sanitization Verification
Canonical safety validation passed for exported metadata/input.
No credential values, body payloads, logs, email/phone values or absolute local
paths were copied. Structural shape/name metadata only. Human-facing source
context is preserved; production model input correctly treats authentication
as unknown because the endpoint has no runtime-confirmed traffic.

### Alias Verification
Host is deterministically anonymized. Context/correlation IDs and source scan
alias remain traceable. No reverse mapping was exported. The source path is
literal and contains no private resource identifier. No new templates inferred.

### Candidate Selection
The single available static-only signup endpoint is retained as a coverage/
uncertainty candidate. No extra cases were fabricated to reach quotas.
The two applications with zero canonical endpoints contributed zero cases.

### Deduplication
Only one available selected endpoint; no semantic duplicate exists.
Repeated copies of the Kotlin APK were counted as one application.

### Human Review Status
1 unreviewed, 0 reviewed, 0 disputed, 0 excluded.
A separate blank review template is prepared under real/review_queue.
No anonymous human reviewer was impersonated. No Analyst or Planner was run
to generate gold. Independent human review is the next required input.

### Gold Label Summary
All actual gold remains null. Empty review-template lists are scaffolding,
not accepted labels. No vulnerability verdict or unsupported test ID assigned.

### Unknown / Ambiguous Handling
Missing runtime traffic does not imply authentication absent or endpoint unused.
The role adapter exposes auth flags as unknown. No missing expected behavior
was inferred. Future human review can mark disputed/excluded when necessary.

### Coverage Cases
1 static-only, HTTPS-visibility-limited case; source exploration max_depth,
traffic_available=false. Capture failure is recorded, never upgraded to success.
Existing proxy process was not stopped or reconfigured to force capture.

### No-Relevant-Test Cases
None human-labelled yet. gold=null must not be interpreted as expected_test_ids=[].
This category remains a dataset coverage gap.

### Development Cases
1 app / 1 unreviewed candidate; official scoring loader returns 0 cases.

### Holdout Cases
0 imported apps / 0 cases. Intended training holdout could not produce useful
API evidence. No duplicate development app was relabelled as holdout.

### Category Distribution
authentication: 1; static_only: 1; visibility_limited: 1.
Tags describe available evidence, not security judgments.

### Dataset Limitations
Very small and entirely static-only. No runtime-auth/session, resource/object,
query/body, dynamic-only or human-reviewed no-relevant-test diversity.
The 20–50 reviewed-case quality target is not met.
Missing inputs: at least one additional usable authorized development app,
one usable authorized holdout app, and independent human-reviewed structured
gold. Compatible runtime environments/working capture would improve evidence.

### Manifest
Canonical real manifest validated; 1 app, 1 case, 0 reviewed, 1 unreviewed,
1 development case, 0 holdout cases. No stale counts or duplicate IDs.
Empty source artifacts were not counted as populated benchmark applications.

### Dataset Fingerprint
2c6e98d16914337a932a364b0258c17a9aa210dc31a14312371e12b167a28695
This identifies the current unreviewed candidate snapshot, not a frozen ready
comparison set. Future reviewed gold/input/split changes require a changed
fingerprint and the documented dataset version/freeze procedure.

### Privacy Validation
PASSED on actual real cases, app metadata, manifest and safe production receipt.
Lightweight validation cannot replace human privacy inspection before review;
no comprehensive DLP guarantee is claimed.

### Gold Leakage Verification
PASSED for the actual development model_input: no gold, notes, reviewer identity,
expected/forbidden test IDs or split metadata. Actual gold is not generated.
Only the canonical production input adapter was invoked; no model call.

### Holdout Leakage Verification
Default loader excludes unreviewed input and returned zero scoring cases.
No actual holdout exists, so representative real holdout input verification
is NOT AVAILABLE. Existing focused suite verifies explicit holdout selection
and model-input leakage using clearly synthetic test fixtures.

### Code Changes
None for Task 9.5.2. Accepted Task 9.5.1 infrastructure remains unchanged.
No prompt, mapping, catalog, scorer or production-stage changes.
Temporary scripts only invoke existing canonical pipeline/projectors.

### Focused Tests
Focused real-dataset tests: PASSED.
pytest tests/test_real_benchmark_dataset.py -q: 34 passed.
No new test suite was created for population.

### Dataset Validation
Dataset validation: PASSED against the populated canonical directory.
Fingerprint/count/split/ID/privacy checks passed. The unreviewed candidate is
excluded from official scoring. git diff --check passed.

### Full Regression Checkpoint Status
Full regression checkpoint: NOT RUN.
Task 9.5 was the latest full checkpoint. No repository-wide clean claim.

### Readiness Gate
NOT_READY_FOR_LOCAL_MODEL_BENCHMARK.
Real input exists; manifest/fingerprint/privacy/development-input leakage pass.
>=2 usable development apps, >=1 usable holdout app, reviewed gold and real
holdout leakage verification are missing. Model benchmarking was not started.

### Real Dataset Summary
3 actual authorized training APKs analyzed; 1 nonempty canonical source artifact.
1 imported development application / 1 actual unreviewed case.
0 imported holdout applications; 0 human-reviewed gold cases.
The pilot remains partial and requires the documented external inputs.

### Diff Summary
Populated one actual real app directory/case and manifest, added a blank review
queue file, updated real README, added a safe population receipt and this report.
Existing Task 9.5.1 uncommitted work was preserved.
No synthetic data was copied into real, no model benchmark, Agent runtime,
Policy ALLOW execution, API attack/replay/fuzzing, PoC or agent_report.json.
No existing product state was modified; Agent analysis remains unavailable.
Task 9.6 was not started.

Task 9.5.2 completed. Real pilot dataset is NOT_READY_FOR_LOCAL_MODEL_BENCHMARK. Missing authorized inputs are documented. No synthetic data was presented as real.
