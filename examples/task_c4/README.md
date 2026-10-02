# OkHttp V1 validation

Focused extraction and static-context suites: **179 passed, 0 failed**.
No full regression, acquisition, app execution, or network requests were performed.

The extractor follows fresh Request.Builder allocations and aliases inside one
straight-line Smali method. It accepts literal String, HttpUrl.parse/get, Java URL,
and HttpUrl.resolve with a proven base and relative path. Constructor-default GET
and explicit method calls have distinct provenance. Building a request provides
a static candidate; `dispatch_observed=false` makes the boundary explicit.

Query values and header values are not emitted. Query keys, counts, and value
presence remain. Candidate IDs reuse the repository's canonical identity helper.
Unresolved requests and unsupported control/field/wrapper flows remain diagnostics
in single-APK and split Static Contexts. No cross-split inference is performed.

Limits: 30,000 files, 2 MB per file, 256 MB total, 4,096 lines per method, 10,000
candidates/diagnostics. Skipped sources are recorded as partial coverage.

Existing decoded real fixtures were checked twice for deterministic output and
their Retrofit rows compared with the unchanged Retrofit extractor:

| Fixture | OkHttp candidates | All canonical candidates |
| --- | ---: | ---: |
| AntennaPod | 0 | 0 |
| VulnBank | 0 | 0 |
| Wikipedia | 0 | 0 |
| OWASP MSTG Kotlin | 0 | 1 Fuel |

No fixture's unresolved flow was promoted to a full endpoint. The OWASP Fuel
`POST /signup` with base `http://127.0.0.1` remains intact. Exact unresolved reason
counts and source/size coverage limitations are in `real_fixture_validation.json`.

Remaining gaps: dynamic URL parameters/custom wrappers; branch/field/cross-method
binding; Kotlin HttpUrl companion/builders and invoke/range forms.

Reproduce with `python -m examples.task_c4.validate_real_fixtures` using the existing
decoded fixtures. This performs static artifact inspection only.
