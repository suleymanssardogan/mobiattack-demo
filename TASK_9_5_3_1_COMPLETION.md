# Task 9.5.3.1 — Static discovery diagnostic and regression checkpoint

### Files Changed

New: scripts/diagnose_static_api.py; tests/test_static_api_diagnostic.py; STATIC_API_DISCOVERY_DIAGNOSTIC.md; this report; examples/task_9_5_3_1 before/after inventories and canonical rerun summaries.

Changed: src/network_indicator_extractor.py — literal Smali String-field coverage only. Earlier accepted port/manifest source and test edits were preserved, not discarded.

### Apps Diagnosed

app_004 AndroGoat, app_005 vuln-bank-mobile, app_006 Damn-Vulnerable-Bank, app_010 Wikipedia and app_011 AntennaPod. Already-acquired local artifacts only; no new application, download or installation for diagnosis.

### Current Discovery Architecture

APKTool decoded artifacts → network indicators and Fuel call-context candidates → static context/report → canonical correlation → EndpointContext. Split components are independently analyzed and provenance preserved. JADX/native artifacts are diagnostic inputs only.

### Sources Currently Scanned

Production: supported UTF-8 decoded Smali/XML/JSON/text/web/config files. Candidate extraction: Smali only. No production Java/Kotlin, native, raw DEX or binary-bundle analysis. Exact supported extensions and pipeline callers were read, not inferred from filenames.

### Current Extraction Rules

Network regex/noise suppression, source-occurrence deduplication, deterministic ordering. Fuel method-local direct register flow and limited base joining; unsupported moves, field flow, invoke/range and non-Fuel frameworks. Indicator existence does not imply API semantics, execution or vulnerability.

### Raw Signal Inventory

Bounded development-only inventory: 2 MB/file, 128 MB/app; app-owned priority; raw and duplicate JADX resources excluded. Aggregate counts retained; maximum 512 representative safe observations exported per inventory. No raw lines, credentials, query values or host filesystem paths.

| App | Occurrences | Explicit-context triage |
|---|---:|---:|
| app_004 | 825 | 1 |
| app_005 | 258 | 3 |
| app_006 | 730 | 2 |
| app_010 | 6674 | 277 |
| app_011 | 1546 | 12 |

Occurrences include duplicated representations/localizations, not unique endpoints. Triage flags are diagnostic hints, not verified API labels.

### Per-App Coverage

Detailed tables and exact source-relative provenance: STATIC_API_DISCOVERY_DIAGNOSTIC.md and examples/task_9_5_3_1 inventories. Wikipedia includes 130 actual decoded runtime Retrofit HTTP declarations and 130 duplicate Java declarations. AntennaPod exposes search URL constants/formatting. Vuln-bank exposes DEBUG_ENDPOINT as a literal Smali field.

### Recognized Signals

Before→after inventory URL occurrences recognized by network indicator extraction: app_004 8→8; app_005 2→3; app_006 5→5; app_010 964→964; app_011 125→136. These counts are not API candidates.

### Missed Signals

Demonstrated field-line gap; Fuel-only candidate coverage misses Retrofit annotations and other client/formatting forms. Java sources are not pipeline inputs. Binary bundles and large/native-only behavior remain unsupported or unexamined. No encrypted or unavailable value was invented.

### Miss Categories

SOURCE_NOT_SCANNED, PATTERN_NOT_SUPPORTED and ANNOTATION_NOT_PARSED, plus NON_API_OR_UNCLASSIFIED observations. Recognition flags distinguish inspected source, extracted indicator and candidate emission. No unsupported claim that normalization deleted an endpoint.

### Non-API Noise

Namespaces, docs/licenses, public website links, media/resources, runtime input examples and library/dev-server configuration remain separate. The bank login hint is not a configured endpoint; Firebase metadata is not an HTTP route. No arbitrary domain or HTTP string is promoted.

### Runtime Cross-Check

Only existing runtime artifacts reused. Training capture was unavailable on occupied 8080; Wikipedia/AntennaPod captured zero transactions with HTTPS unavailable on 18080. Proxy restoration and bounded exploration stops are documented. Zero traffic is not negative proof of no API.

### Root Cause Classification

DISCOVERY_IMPLEMENTATION_GAP. Meaningful recoverable service declarations/network constants exist, but production candidate extraction supports Fuel only. No assertion that every app exposes a usable static API or that the inventory is exhaustive.

### Minimal Fixes Implemented

An exact Smali .field declaration of type java.lang.String with a literal initializer is now inspected by existing network indicator rules. File/line provenance remains exact. Non-String fields, expressions, schema URLs and unsupported dynamic flows remain excluded. No field-name endpoint heuristic or API-candidate schema change.

### Fixes Deferred

Retrofit method/path annotation parsing and structural base binding; explicit non-Fuel URL data flow; resource-to-network-use binding; binary/native decoding. No fragment concatenation, fuzzy matching, new model/provider or broad source expansion.

### Candidate Counts Before

All five apps: 0.

### Candidate Counts After

All five apps: 0. The fix improves indicator coverage only; it does not turn constants into API candidates.

### EndpointContext Counts Before

All five apps: 0.

### EndpointContext Counts After

All five apps: 0. Canonical static/correlation/context stages reran in separate task_9_5_3_1 directories from existing decoded inputs with original runtime evidence reused. Original runs preserved.

### Dataset Impact

No benchmark import, manual EndpointContext creation, gold label or reviewed status. Existing app_001 and manifest preserved. Fingerprint remains 2c6e98d16914337a932a364b0258c17a9aa210dc31a14312371e12b167a28695. DATA_COLLECTION_READY=false; MODEL_BENCHMARK_READY=false.

### Product Boundary

agent_analysis remains not_available. No Agent Report, live model, active API testing, request replay/mutation, tool-calling runtime, executor, finding, PoC or vulnerability confirmation. Website on 8080 remained running under the same original listener process. Default traffic_proxy_port remains 8080; optional port/launcher-alias regressions are included in full pytest coverage.

### Focused Tests

PASSED: pytest tests/test_static_api_diagnostic.py tests/test_network_indicator_extractor.py tests/test_api_candidate_extractor.py -q — 53 passed.

Covers classification, source/candidate comparison, miss reasons, privacy, determinism, bounded inventory and the actual missed field syntax. Neighboring namespace/local/non-String/expression noise remains outside network URLs; no candidate is manufactured.

### Full Regression Checkpoint

PASSED: pytest -q — 1535 passed, 2 skipped, 33 subtests passed, 0 failed / 0 errors (149.44 seconds).

The two established skips are integration tests requiring device 127.0.0.1:5555; the available device is emulator-5554. Skip reasons were separately confirmed.

Initial sandbox-restricted full attempt encountered localhost socket PermissionError failures/errors. It was rerun outside that restriction without code changes to suppress failures. Only the successful final checkpoint is claimed clean.

PASSED: python3 -m unittest discover -s tests -p 'test_*.py' — 935 tests, OK (skipped=2), 87.790 seconds.

### Known Coverage Limitations

Bounded inventory skips large/binary files and leaves ambiguous strings unclassified. Native printable strings do not establish networking use. Fuel-specific production extraction, unbound relative annotations, runtime construction and limited HTTPS visibility remain. Duplicate occurrences are not endpoint totals.

### Recommended Next Step

Review this diagnostic. A focused Retrofit declaration/base-binding implementation is the strongest next discovery improvement before further benchmark population. Task 9.5.4 and Task 9.6 were not started.

### Diff Summary

One narrow production indicator change, one development-only diagnostic tool, focused diagnostic/extraction tests and safe diagnostic/report artifacts. Previously accepted local work preserved. No acquisition expansion or benchmark contract changes; changes remain local for review.

Task 9.5.3.1 completed. Static API discovery gap was confirmed and minimally hardened. Full regression checkpoint completed.
