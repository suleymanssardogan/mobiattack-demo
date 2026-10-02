# Task 9.5.3 — Real pilot acquisition checkpoint

### Candidate Sources Investigated

Eight candidates were investigated: six official training-source candidates, followed by two ordinary Play Store apps after the user explicitly expanded acquisition scope. All source URLs, release/commit references and actual artifact hashes are recorded in [candidate_matrix.json](examples/task_9_5_3/candidate_matrix.json).

### Authorization Verification

AndroGoat, vuln-bank-mobile, Damn-Vulnerable-Bank, DodoVulnerableBank, Digitalbank and DVHMA were investigated through their official training repositories/releases. Wikipedia and AntennaPod are classified as explicitly_authorized_app for user-authorized local APK/static analysis and normal passive UI exploration. This records user authorization; it does not claim vendor authorization for backend security testing. No account login, credential collection or active security testing was performed.

### Emulator Environment

Existing emulator-5554: Android 16, API 36, arm64-v8a. No emulator downgrade, SDK override, ABI patch, installation-policy bypass or APK rebuild.

### Compatibility Gate Results

Five candidates passed actual installation, launch and usable UI prechecks: app_004, app_005, app_006, app_010 and app_011. Compatibility alone did not qualify them for dataset import. Three candidates were rejected before full analysis.

### Rejected Legacy Apps

app_007 had no official prebuilt APK and legacy source target SDK 23; no rebuild was attempted. app_008 official APK target SDK 19 and app_009 target SDK 23 were rejected before installation/full scans. Previous app_002 ABI failure and app_003 deprecated-SDK failure remain documented and were not retried.

### New Compatible Apps

app_004 AndroGoat v2.0.1 (target SDK 33), app_005 vuln-bank-mobile v1.3 (35), app_006 Damn-Vulnerable-Bank v1.1.0 (29), app_010 Wikipedia (37, split APK), app_011 AntennaPod (36, monolithic). Actual installed Wikipedia launch succeeded on API 36; its target SDK is not an assertion of minimum SDK.

### Acquisition Receipts

Official upstream releases/repository artifacts were acquired using existing acquisition APIs. Play Store artifacts were acquired from the installed official packages using the existing Play Store acquisition flow. Sanitized source and compatibility receipts are in the candidate matrix. APK bytes and raw lab artifacts remain ignored locally under artifacts/task_9_5_3 and demo_runs; no host paths or raw logs are included in the dataset.

### APK Hashes

Full SHA-256 hashes for every acquired APK are in the candidate matrix, including all three Wikipedia split components. app_007 has no APK hash because no APK was acquired. Hashes are measured artifact hashes, not inferred version identities.

### Existing Pipeline Runs

Canonical runs: task_9_5_3_app_004, app_005, app_006, app_010 and app_011. Wikipedia's initial runtime failure was retained; task_9_5_3_app_010_alias_fix reran the canonical pipeline after the parser fix and completed. The same APK components were used without modification. Static reports were projected from actual static-stage results before correlation; no endpoint facts were invented.

### Traffic Capture Status

Initial three training runs could not capture on occupied default port 8080. The user identified that listener as their website. A minimal optional capture-port parameter now lets canonical scans use 18080; 8080 remains the default. The website's original process remained listening throughout.

Wikipedia and AntennaPod capture started on 18080 and restored the prior device proxy. Both captured zero transactions. Available backend visibility is cleartext HTTP only; HTTPS content remains unavailable. No certificate/security bypass was introduced. Wikipedia stopped at the existing external-package boundary; AntennaPod stopped on UI observation timeout.

### EndpointContext Counts

All five new compatible applications emitted zero canonical EndpointContexts and zero static API candidates. Wikipedia's initial failed run is not counted as successful collection. Existing app_001 still contributes one static-only context/case from Task 9.5.2.

### API Benchmark Usefulness

All five new compatible applications are insufficient_evidence. Empty canonical artifacts cannot become benchmark cases. Zero observed contexts does not establish absence of APIs in the application.

### Applications Selected

No new app selected for import. Existing app_001 is preserved. The target of at least two usable development apps and one usable holdout app was not achieved.

### Development Split

Existing app_001: one unreviewed development case. No new split assigned to empty apps.

### Holdout Split

Zero holdout apps/cases. No rejected or zero-context app was designated holdout to satisfy a quota.

### Real Candidates Imported

Zero new cases. Existing real case count remains one. No synthetic replacement cases, gold labels, reviewed statuses or forced endpoint categories.

### Dataset Category Distribution

Existing manifest counts: authentication=1, static_only=1, visibility_limited=1. These are overlapping tags on one case, not three cases. Other categories remain unsupported by collected evidence.

### Sanitization Validation

Canonical real-dataset validation passed. Existing app_001 metadata and case SHA-256 hashes were verified unchanged against the start-of-task snapshot. Raw credentials, bodies, logs, account identities and filesystem paths were not added to the dataset or public acquisition matrix.

### Holdout Verification

Canonical loader check: default reviewed development selection=0; explicit include_holdout with reviewed_only=false returns the one existing unreviewed development case. Manifest holdout_case_count=0. Holdout isolation semantics were not changed.

### Manifest

benchmarks/agent_v1/real/manifest.json remains unchanged: app_count=1, case_count=1, unreviewed_case_count=1, reviewed_case_count=0, holdout_case_count=0.

### Dataset Fingerprint

Unchanged: 2c6e98d16914337a932a364b0258c17a9aa210dc31a14312371e12b167a28695.

### Candidate Matrix

examples/task_9_5_3/candidate_matrix.json records eight candidates, five compatible apps, zero newly usable apps, zero new imports, actual source provenance, hashes, SDK/ABI checks, failure reasons, original legacy exclusions and user-authorized Play Store scope.

### Code Changes

src/demo_orchestrator.py: optional validated traffic_proxy_port, forwarded to readiness, capture and timeline in both package layouts. Default behavior remains 8080.

src/manifest_parser.py: recognize declared enabled MAIN/LAUNCHER activity aliases and validate their target activity; activities retains actual activity declarations. This parses the existing APK manifest; it does not alter any APK manifest.

No extraction heuristics, model/provider, scoring, policy, executor or dataset contracts were changed.

### Focused Tests

PASSED: pytest tests/test_manifest_parser.py tests/test_real_benchmark_dataset.py -q — 55 passed.

PASSED: pytest tests/test_dynamic_exploration_pipeline_wiring.py -q — 46 passed.

The added tests cover capture-port forwarding and early validation, launcher-alias identity, disabled aliases and undeclared/missing targets. Directly adjacent suites were run because genuine pipeline fixes were required.

### Dataset Validation

PASSED: validate_real_dataset, original app_001 hash preservation, reviewed-loader exclusion and explicit unreviewed-loader count. git diff --check passed.

### Full Regression Checkpoint Status

NOT RUN — this task is not a full regression checkpoint. No claim that the entire repository is regression-clean.

### DATA_COLLECTION_READY

false / NOT_READY. Required development/holdout coverage and sufficient real endpoint evidence are missing.

### MODEL_BENCHMARK_READY

false. No reviewed gold labels exist. No LLM benchmark, model selection or gold review was started.

### Dataset Limitations

Modern installation compatibility is substantially better than the old failed candidates, but it did not yield meaningful canonical API evidence. HTTP capture produced no transactions in the Play Store runs; HTTPS visibility and bounded UI coverage limit conclusions. The initial training captures were blocked by 8080 occupancy. No application was fabricated into a successful dataset source.

Public agent_analysis remains not_available. No agent_report.json, replay, request mutation, fuzzing, authorization attack, PoC or vulnerability confirmation was introduced. Task 9.5.4 and Task 9.6 were not started.

### Diff Summary

Four tracked source/test files changed for two narrow pipeline fixes; candidate matrix, acquisition summary and this completion report added. Prior Task 9.5.1/9.5.2 local work and app_001 evidence preserved. Raw APKs/lab artifacts remain ignored. Changes remain local for review.

Task 9.5.3 completed. Real pilot data collection is NOT_READY. Compatibility and evidence limitations are documented. No legacy compatibility bypasses were introduced.
