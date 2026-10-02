# Task 9.5.3.3 — Optimized Retrofit Base Binding V1

Decision: **NO_SAFE_OPTIMIZED_BINDING**. Narrow direct-flow support is implemented and validated with synthetic positive fixtures. The real Wikipedia chain still requires unsupported branch and object-state semantics. No real canonical candidate was manufactured.

### Files Changed

- src/retrofit_flow.py — new bounded direct-call provenance module.
- src/retrofit_candidate_extractor.py — optimized binding integration, legacy binding precedence, structured trace, safe hostname validation.
- tests/test_retrofit_flow.py — 17 focused cases including exact argument/return flow, isolation, ambiguity, bounds, privacy and canonical static-only context wiring.
- tests/fixtures/retrofit/OptimizedServiceFactory.smali and optimized_receipt.json — actual optimized Wikipedia methods, original line numbers, verified source/fixture hashes.
- examples/task_9_5_3_3/ — before/after counts, bounded unresolved diagnostics and performance for five apps, exact fixture compatibility evidence.
- TASK_9_5_3_3_COMPLETION.md — this report.

Accepted local work from earlier tasks was preserved. No additional orchestrator, dynamic runtime, Agent runtime, importer or product-state changes were made in this task.

### Optimized Retrofit Architecture

Existing Smali declaration extraction → component-local compact method index → per-callsite bounded direct evaluation → complete base/Retrofit/service binding → existing canonical safe join and ApiCandidate assembly. Diagnostics stay outside the candidate list. No general call-graph framework or symbolic execution engine was introduced.

### Interprocedural Scope

Seeds are actual Retrofit construction/use sites and exact service class constants. Only exact relevant callers and narrowly typed direct-return callees are retained, in four bounded indexing passes. Generic helper callees do not cause reverse expansion across unrelated callers. HttpUrl library implementation internals are not traversed for recognized parser semantics. Analysis remains decoded-component local.

### Supported Argument Flow

Exact owner/method descriptors and invocation modes map register words to callee parameter registers. Long/double parameters occupy two words. Forwarded values include a source invocation, argument word index and parameter register. Unsupported overwrites invalidate the register. Non-final virtual dispatch is rejected; only static, private/direct constructor or final virtual methods qualify.

### Supported Return Flow

Direct return-object → caller move-result-object → exact Retrofit.create receiver preserves the construction chain. Literal-return helpers are included only through relevant exact invocations. Direct local move-object is supported. Mutable builder/allocation objects cannot cross helper boundaries; unknown object escapes reject the chain.

### HttpUrl Provenance

A safe literal may enter HttpUrl.parse/get(String), or the explicit HttpUrl.Builder constructor/parse$okhttp(null, String)/build chain. Recognized descriptors and receiver types must match. The optimized Retrofit constructor accepts only a proven HttpUrl at its exact base argument position. Unknown HttpUrl, mutable property, formatted string or unrelated URL remains unresolved. No constructor internals are reconstructed.

### Service Class Provenance

const-class must name a service interface with actual supported Retrofit declarations. It may cross exact Class parameter slots, including a synthetic $default method. A create(Class) argument from an unknown Class or unrelated interface never binds a declaration.

### Callsite Isolation

Each root and nested invocation receives fresh argument/register state. Distinct callers sharing one factory remain base A/service A and base B/service B. No global helper value table exists. Identical complete chains are deduplicated deterministically.

### Ambiguity Handling

Any branch/label/switch/exception table, unsupported invoke form, recursion cycle, ambiguous dispatch or duplicate method descriptor rejects that chain. Diagnostic codes include CALLSITE_AMBIGUOUS, INTERPROCEDURAL_DEPTH_LIMIT, INTERPROCEDURAL_CYCLE, BASE_UNRESOLVED, SERVICE_UNRESOLVED and unsupported-flow reasons. No branch is selected by guesswork.

### Traversal Bounds

Depth ≤3; four indexing passes; ≤30,000 files, 2 MB/file and 256 MB source/component; ≤2,048 retained methods; ≤200,000 retained operations; ≤10,000 evaluations; ≤512 unresolved diagnostic records; ≤512 trace events. Existing declaration/binding/candidate caps remain. Diagnostic truncation is explicit. Limits reject incomplete provenance instead of promoting it.

### False-Positive Controls

Require an explicit safe base, correctly constructed Retrofit object, exact service identity and actual method/path declaration. No global URL pairing, package/name similarity, same-type inference, field graph, branch inference, reflection, runtime execution or generic OkHttp tracing. Base requires valid HTTP(S), valid host/port, no userinfo/query/fragment, safe path and trailing slash. Annotation templates retain existing semantics.

### Candidate Provenance

New candidates retain existing declaration evidence and add interprocedural_trace with component-relative source file, method, Smali line, construction/invocation, parameter mapping, return and create site. No raw body, secret literal, credential, token/cookie value, absolute local path or reasoning transcript is stored. base_url_call_line is null for optimized construction because there was no literal baseUrl setter; actual parser/constructor lines appear in the trace.

### Existing Retrofit V1 Regression

The old same-method literal Builder chain has precedence when rediscovered. Its candidate fields remain byte-for-byte equal with optimized flow enabled/disabled on the known fixture. compatibility.json records the equality and output hash. Existing Retrofit suite passed.

### Fuel Regression

Fuel parsing was not edited. Exact known Fuel fixture output with/without Retrofit integration is equal and recorded in compatibility.json. Existing API candidate tests passed, covering Fuel call-context behavior and framework isolation.

### Wikipedia Real Regression

Reused existing decoded app_010 artifact only. All 127 declarations remain; proven base bindings 0, proven service bindings 0, canonical API candidates 0. Actual createRetrofit$default and get methods appear in UNSUPPORTED_BRANCH_FLOW records. The exact real optimized factory/get fixture and original source hashes were verified programmatically. Supported linear versions are positive synthetic fixtures, not evidence of a real Wikipedia endpoint.

### Remaining Wikipedia Gaps

ServiceFactory.createRetrofit$default (source line 107) receives the base through p2 and contains branches/loops. HttpUrl.Builder.parse$okhttp appears near line 502; the optimized Retrofit constructor at line 735 receives that HttpUrl; Retrofit is returned. ServiceFactory.get (line 1084) selects/falls back to WikiSite.url() plus string concatenation around line 1105, calls the factory near line 1126 and create(Class) with p3 at line 1134. WikiSite.url() depends on instance fields. Resolving the actual effective base/service combination would require branch/default-argument selection and mutable object/property semantics. The stop rule applies; these were left unresolved.

### Other App Regression

Existing app_004, app_005, app_006 and app_011 decoded sources were re-extracted. All remain at 0 Retrofit declarations and 0 canonical candidates. The optimized analyzer is skipped when no service declaration exists. No unrelated base was attached. AntennaPod generic URL/string-format flows remain outside scope.

### Retrofit Declarations Before/After

| App | Declarations | Base bindings | Service bindings | API candidates | EndpointContexts |
|---|---:|---:|---:|---:|---:|
| app_004 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| app_005 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| app_006 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| app_010 | 127 → 127 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |
| app_011 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 | 0 → 0 |

All before counts come from accepted Task 9.5.3.2 measurements; after counts come from the current extractor and unchanged canonical context artifacts.

### Resolved Base Bindings Before/After

All five apps: 0 → 0. Complete binding and separately recorded partial base sites are both zero. A constructor signature's presence alone is not a resolved base.

### Resolved Service Bindings Before/After

All five apps: 0 → 0. The branchful real service factory is rejected before a safe concrete service invocation can be followed. A Class-typed formal parameter is not counted as a resolved service binding.

### Canonical Candidate Counts Before/After

All five apps: 0 → 0. Relative paths and partial structure remain diagnostic-only. No newly usable app was obtained.

### EndpointContext Counts Before/After

All five apps: 0 → 0. With no real candidate change, existing static reports/correlation/context artifacts were retained. No reinstall or exploration was performed. A positive optimized synthetic candidate was run through the canonical report → correlation → context wiring and remains static_only, observed=false, with “Not observed in available runtime traffic.”

### Benchmark Dataset Impact

No new canonical real context was available, so no import or split reassignment occurred. Dataset remains 1 app/1 unreviewed case, gold=null, development split, holdout count 0. Manifest fingerprint remains 2c6e98d16914337a932a364b0258c17a9aa210dc31a14312371e12b167a28695. No model outputs or human labels were added. Wikipedia is not recommended as a useful holdout case yet.

### Performance Bounds

Wikipedia base component: 11,393 accepted source files, 25 retained methods, 4,699 retained operations, 1,342,420 inspected invocation records across indexing passes, 28 evaluations, observed traversal depth 2 (hard limit 3), 13.0804 seconds optimized diagnostic analysis; 17.4066 seconds total declaration/binding extraction. Invocation count includes repeated pass inspection, not unique graph edges. No index/evaluation cap was reached and diagnostic truncation was false. DEXless splits retained component isolation. Other app total times: app_004 2.2267s, app_005 1.8345s, app_006 0.4819s, app_011 3.0453s. Timing is diagnostic metadata, never candidate identity.

### Product Boundary

Agent analysis remains not_available; no public Agent stage completion, agent_report.json, Agent runtime or model/provider change. Only static source files were read. No discovered URL was executed, no request/replay/fuzz/auth mutation or vulnerability validation was performed. The user's website on port 8080 was not touched.

### Focused Tests

PASSED: tests/test_retrofit_flow.py (17 cases) and existing Retrofit/API candidate tests. Coverage includes exact positional forwarding, optimized constructor, parser signatures, return/moves, synthetic names, wide slots, independent callers, duplicate descriptors, ambiguity, cycles/depth, overwrite/branches, privacy, unrelated inputs, malformed file isolation and optimized static-only context semantics.

### Adjacent Regression Tests

PASSED: 249 tests +18 subtests, 0 failures, 5.04 seconds. Command:

```bash
pytest tests/test_retrofit_flow.py tests/test_retrofit_candidate_extractor.py tests/test_api_candidate_extractor.py tests/test_network_indicator_extractor.py tests/test_static_context_builder.py tests/test_split_static_context_builder.py tests/test_static_analysis_report.py tests/test_static_dynamic_api_correlation.py tests/test_endpoint_context_builder.py -q
```

Exact compatibility fixture comparisons and real source receipt verification also passed. git diff --check passed.

### Full Regression Checkpoint Status

NOT RUN — this task is not a full regression checkpoint. Task 9.5.3.1 remains the latest full checkpoint. This report claims only the focused/adjacent results above, not whole-repository regression cleanliness.

### Known Limitations

No invoke/range support, branch merging, bitmask/default selection, generic field/property graph, heap alias engine, reflection/dynamic loading, encrypted/native values, arbitrary library reconstruction, cross-component base pairing or runtime confirmation. Unknown methods never produce trusted values. Four source inspection passes remain a measurable cost on large APKs despite the compact retained index. Real runtime coverage remains limited; unknown/absent evidence was not strengthened.

### Decision Outcome

**NO_SAFE_OPTIMIZED_BINDING** for the real Wikipedia artifact under bounded V1 rules. General direct-flow capability works on structurally complete positive fixtures, but it did not safely resolve more of this real chain into a base/service binding. Do not describe this as effective real API discovery or as partial resolved binding.

### Recommended Next Step

Review this bounded implementation and the real unresolved evidence. If the benchmark needs additional useful apps, separately authorize an application with a direct, provable Retrofit configuration. Supporting Wikipedia's mutable WikiSite/branch behavior needs an explicit later architecture decision; no expansion was started here. Task 9.5.4 and Task 9.6 were not started.

### Diff Summary

Two production modules changed/added; one focused suite, one exact optimized source fixture plus receipt, compatibility evidence and five-app count/diagnostic artifacts added. Existing Fuel/V1 candidate schema and ordering retained. No canonical real candidates, EndpointContexts, dataset cases or labels changed. Git main was fetched and verified equal to origin/main before implementation; existing uncommitted accepted work was preserved. No commit/push was made for this review task.

Task 9.5.3.3 completed. No safe optimized Retrofit binding was justified under bounded V1 rules.
