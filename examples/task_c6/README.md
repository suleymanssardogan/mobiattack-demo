# Ktor and bounded wrapper provenance V1

Focused extractor/static-context/non-regression suites: **263 passed, 0 failed**.
No full regression, download, runtime execution or HTTP request was performed.

Ktor supports exact HttpRequestBuilder URL/method flows into BuildersKt verbs/request
or HttpStatement construction. The String verb overload is accepted only with a
proven default empty block; unknown DSL/lambda overrides remain unresolved. URLBuilder
aliases are tied to one request allocation. No runtime dispatch is claimed.

The optional shared adapter expands only exact static/private/final helper calls,
copying parameters into isolated registers and propagating one direct object/String
return. It accepts explicitly initialized static-final String fields with no observed
writes, String.concat and bounded literal-only StringBuilder concatenation. Each
additional candidate includes original call/return/field/literal/source-line evidence.
No intermediate source or raw literal/query values are persisted.

Limits: helper depth 3; cycle detection; 30,000 files; 2 MB/file; 256 MB source bytes;
50,000 indexed methods; 2,048 root evaluations; 4,096 expanded lines; 512 trace/events
and diagnostics. Branches/exception tables, mutable fields, collection operations,
reflection, unknown returns/configuration, ambiguous callers/definitions and unknown
dispatch stop resolution. Incomplete indexes disable wrapper/field resolution to
avoid declaring a caller or field unique without complete evidence. Direct Ktor
analysis remains independent and reports its own coverage limitations.

Existing direct extractors are unchanged. The integrated path keeps their existing
rows/IDs and adds only new proven candidates. The adapter assists OkHttp, Volley,
HttpURLConnection and Ktor. Fuel and Retrofit retain their existing extraction paths;
Retrofit's existing bounded resolver was not rewritten. Static Context adapters
already preserve candidate dictionaries and discovery diagnostics.

| Existing decoded fixture | Canonical candidates | Direct behavior unchanged |
| --- | ---: | --- |
| AntennaPod | 0 | yes |
| VulnBank | 0 | yes |
| Wikipedia | 0 | yes |
| Damn Vulnerable Bank | 0 | yes |

Counts were not forced. In the first three fixtures, index/source limits prevent
wrapper resolution; these are explicit partial coverage. Remaining inspected flows
are branch-dependent or unsupported. Details are in `real_fixture_validation.json`.
The script compares unchanged direct framework rows with the integrated output.

Reproduce: `python -m examples.task_c6.validate_real_fixtures`.

Official Ktor 2.3.12 semantics/signature sources:
- https://github.com/ktorio/ktor/blob/2.3.12/ktor-client/ktor-client-core/common/src/io/ktor/client/request/builders.kt
- https://github.com/ktorio/ktor/blob/2.3.12/ktor-client/ktor-client-core/common/src/io/ktor/client/request/HttpRequest.kt

Remaining gaps: stateful coroutine/lambda DSL; ambiguous/dynamic/obfuscated wrappers;
large-index limits and branch/heap/collection flows. Dynamic and Agent were untouched.
