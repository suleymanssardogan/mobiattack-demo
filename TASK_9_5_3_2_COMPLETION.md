# Task 9.5.3.2 — Retrofit API Candidate Extraction V1

### Files Changed

Changed: src/api_candidate_extractor.py — integration of separate Retrofit helper and documentation; original Fuel extraction logic retained.

Added: src/retrofit_candidate_extractor.py; tests/test_retrofit_candidate_extractor.py; tests/fixtures/retrofit/SemanticSearchService.smali and receipt.json; examples/task_9_5_3_2 declaration inventories, before_after.json and wikipedia_base_binding_diagnostic.json; this report.

Earlier accepted uncommitted work was preserved. main matches the fetched origin/main commit; no remote update was pending.

### Retrofit Parser Architecture

Smali-only bounded declaration parser plus independent same-method builder-flow tracker. They join by exact service class descriptor, not filenames, neighboring strings or global URL guesses. Bound results use the existing canonical API candidate dictionary. Unbound declarations remain diagnostic records, outside canonical scan candidates and EndpointContexts.

### Supported Retrofit Forms

Abstract service-interface method annotations: GET, POST, PUT, PATCH, DELETE, HEAD and OPTIONS, with one supported HTTP annotation and a non-empty direct literal relative path.

Supported base chain: new Retrofit.Builder → its direct constructor → const-string base → baseUrl(String) on that receiver → build() result → create(Class) with same-method const-class service. Explicit move-result-object values are tracked. Referenced declarations may reside in another Smali file in the same decoded component.

### Unsupported Retrofit Forms

Generic HTTP annotation, empty/absent/nonliteral/escaped paths, absolute annotation URLs, default/concrete interface methods, annotation class metadata, field-based bases, HttpUrl overloads, builder customization chains, invoke/range, register moves, runtime construction, interprocedural flow, native/JADX production parsing and parameter extraction.

Bounds: 2 MB/file, 256 MB source bytes, 30,000 Smali files, 8,192 declaration records, 4,096 binding records and 10,000 candidates. Source/record limitations and unreadable files are recorded deterministically; no recursive semantic evaluation.

### Annotation Parsing

Only method-level runtime annotation usage in non-annotation service interfaces qualifies. Parameter annotation blocks are skipped, not converted into parameter evidence. Declaration collection completes at the method boundary; malformed/unterminated, duplicate HTTP and invalid value forms are not promoted.

A malformed file does not abort other files or Fuel extraction. No inference from Service/Api naming.

### Base URL Binding

Receiver identity, literal assignment, builder initialization, result type and exact create(Class) service identity must all be supported. Branch/label boundaries, unsupported calls and register overwrites invalidate tracked flow. Unknown calls that receive a tracked builder invalidate its base. No cross-method/global base state.

Base must be a safe HTTP(S) literal with valid host/port and trailing slash; userinfo, query, fragment and unsafe path forms are rejected. urljoin provides standard relative/root-relative path semantics. Explicit template text is preserved.

### False-Positive Controls

Unbound declarations, unrelated absolute URL fields, annotation definitions, unrelated annotations and unreferenced methods do not become canonical candidates. Service A's binding does not attach to service B. Generic fields remain network indicators. No fuzzy matching, dynamic-value evaluation or combinatorial fragment concatenation.

### Candidate Provenance

Existing framework/method/base_url/path/full_url/status/source_file/request_line/evidence fields are reused. Evidence records declaration method and service class, annotation/value positions, exact builder source/method/literal/call positions, and service-create source/method/class/call positions.

Query values are omitted even from raw-path evidence; query_values_removed records sanitization. The annotation's source/value line retains provenance to the original form. No credentials/headers/bodies are extracted. Candidate order is deterministic. No random source IDs were introduced; existing correlation-side ordinal reference conventions remain.

### Fuel Regression

Fuel's register-flow/signature/join logic is unchanged. Existing API extractor tests, static context/report tests and downstream correlation/context tests passed. Retrofit candidates are appended before the existing deterministic final sort; NetworkIndicator remains distinct from ApiCandidate.

### Wikipedia Real Regression

The exact local SemanticSearchService Smali artifact was copied as a focused fixture. Receipt records source-relative artifact, original base APK SHA-256 and fixture SHA-256. Real declaration: GET, api/search, annotation line 43, value line 44. The real unbound declaration is parsed without hardcoded package/path behavior.

Full existing Wikipedia decoded artifact: 127 valid relative-path declarations recovered, zero supported base bindings, zero canonical candidates; no source skipped under these bounds.

Exact missing binding form in ServiceFactory.smali:
- line 107: createRetrofit$default accepts the base string as a method argument.
- line 710: R8 directly constructs Retrofit, rather than the supported builder chain.
- line 735: constructor receives an OkHttp HttpUrl object.
- line 1105: fallback base comes from WikiSite.url().
- line 1126: Retrofit instance is returned across a method boundary.
- line 1134: create(Class) receives class parameter p3, not local const-class evidence.

This is unresolved interprocedural/inlined-constructor provenance, not absence of APIs. No unrelated URL was used as a substitute.

### AntennaPod Boundary

No generic constant-to-request tracing was added. Its existing URL constants remain network indicators; this V1 found no Retrofit declarations/bindings in its inspected artifacts.

### Candidate Counts Before

| App | Canonical API candidates |
|---|---:|
| app_004 | 0 |
| app_005 | 0 |
| app_006 | 0 |
| app_010 | 0 |
| app_011 | 0 |

### Candidate Counts After

All five remain 0 under conservative evidence rules. app_010 has 127 non-promoted declarations; the other four have zero qualifying Retrofit declarations. Source-bound exclusions: one oversized source each for app_004/app_005; none for the other apps. Before counts were read from original canonical static reports; after counts were measured by the updated production extractor.

### EndpointContext Counts Before

All five: 0, measured from existing canonical artifacts.

### EndpointContext Counts After

All five: 0. No real candidate list changed, so existing canonical EndpointContext artifacts remained authoritative and no correlation/context generation was repeated. The canonical generation path was verified with a structurally bound synthetic extraction fixture: it produces a static-only context marked “Not observed in available runtime traffic.”

No acquisition, installation, exploration, request execution or traffic collection was needed.

### Benchmark Dataset Impact

No import, split reassignment, holdout creation, gold label or agent-generated review. Existing one unreviewed app_001 case remains unchanged. Canonical dataset validation passed. Fingerprint remains 2c6e98d16914337a932a364b0258c17a9aa210dc31a14312371e12b167a28695. DATA_COLLECTION_READY=false; MODEL_BENCHMARK_READY=false.

### Product Boundary

agent_analysis remains not_available. No agent_report.json, provider/model evaluation, tool-calling runtime, executor, active API testing, replay, fuzzing, authorization changes, finding, Evidence Verifier or PoC. No service/process on 8080 was touched.

### Focused Tests

Retrofit suite covers seven HTTP methods, relative/root-relative joins, template preservation, malformed/empty/nonliteral/unrelated annotations, definitions, structural binding, unrelated hosts, multiple services, stale/escaped flow, determinism, provenance, privacy, failure isolation, real Wikipedia declaration and canonical static-only semantics.

Combined focused/adjacent run: 232 passed, 18 subtests passed, 0 failed.

### Adjacent Regression Tests

Executed: test_api_candidate_extractor.py, test_network_indicator_extractor.py, test_static_context_builder.py, test_split_static_context_builder.py, test_static_analysis_report.py, test_static_dynamic_api_correlation.py and test_endpoint_context_builder.py alongside the Retrofit suite. No canonical model change.

git diff --check passed. Existing dataset fingerprint, fixture provenance and diagnostic source-path hygiene verified.

### Full Regression Checkpoint Status

NOT RUN — this is a focused task. Task 9.5.3.1 remains the latest full checkpoint; no new entire-repository cleanliness claim.

### Known Limitations

V1 can emit canonical candidates for its demonstrated literal builder/create form, but the selected real Wikipedia APK uses an unsupported optimized/interprocedural form. Non-promoted declarations are discovery evidence only, not endpoints or benchmark cases. Unsupported/oversized source coverage is explicit. No partial candidate with guessed host is emitted.

### Decision Outcome

RETROFIT_PATHS_FOUND_BUT_BASE_UNRESOLVED.

### Recommended Next Step

Review V1 and the exact Wikipedia binding diagnostic. A separately authorized narrow investigation of optimized constructor/base/service provenance is required before supporting that form. Do not populate the benchmark from unbound paths. Task 9.5.4 and Task 9.6 were not started.

### Diff Summary

One existing extractor receives a small integration; framework parsing lives in a separate helper. Added focused tests, exact safe real declaration fixture and development-only receipts. No Fuel logic, API schema, networking engine, correlation semantics or dataset split was changed. Changes remain local for review.

Task 9.5.3.2 completed. Retrofit paths were recovered, but safe base URL binding remains unresolved.
