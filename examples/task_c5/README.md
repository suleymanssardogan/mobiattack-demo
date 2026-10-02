# Volley + HttpURLConnection V1

Focused extraction/integration/non-regression suites: **231 passed, 0 failed**.
No full regression, app execution, or network request was performed.

Supported direct Volley classes: StringRequest, JsonObjectRequest, JsonArrayRequest.
Explicit method constants use the official Volley Request.Method mapping. Known
GET constructors are supported. Unknown/body-dependent method selection remains
unresolved. Constructor evidence alone creates a static candidate; queue/add refs
require the same proven request allocation and a proven queue allocation/factory.
No dispatch or runtime confirmation is claimed.

HTTP connection candidates require a locally allocated URL with a valid HTTP(S)
literal, exact openConnection result, HTTP type evidence, explicit setRequestMethod,
and connect/stream/response-code use. Platform-default method inference is disabled.
GET output-stream use and unsupported connection options are not silently promoted
or relabeled as POST. URL objects alone never create candidates.

Both mechanisms preserve exact source/component/method/line provenance, normalized
scheme/host/port/path and query key/shape metadata. Query and header values are not
emitted. Existing canonical ID/order and URI sanitization helpers are reused.
Diagnostics flow through existing single-APK/split Static Context adapters.

Analysis is straight-line and method-local; unsupported branches/exception handlers,
heap/field flows and custom wrappers stay unresolved. Bounded standard invoke/range
register lists are accepted for the six-register JSON constructors. Limits are
30,000 files, 2 MB/file, 256 MB total, 4,096 lines/method, 10,000 records. Skips are
explicit partial coverage.

Existing decoded fixtures:

| App | New Volley/HttpURLConnection candidates | All canonical candidates |
| --- | ---: | ---: |
| Damn Vulnerable Bank | 0 | 0 |
| Flashlight | 0 | 0 |
| AntennaPod | 0 | 0 |

Counts were not forced. Framework signal counts and unresolved reasons are in
`real_fixture_validation.json`. Each fixture was extracted twice for determinism;
existing OkHttp/Retrofit outputs were compared with their unchanged extractors.
Fuel's OWASP POST /signup baseline is covered by the focused regression suites.

Reproduce fixture checks: `python -m examples.task_c5.validate_real_fixtures`.

Official signature/constant references:
- https://github.com/google/volley/blob/master/core/src/main/java/com/android/volley/Request.java
- https://github.com/google/volley/blob/master/core/src/main/java/com/android/volley/toolbox/StringRequest.java
- https://github.com/google/volley/blob/master/core/src/main/java/com/android/volley/toolbox/JsonObjectRequest.java
- https://github.com/google/volley/blob/master/core/src/main/java/com/android/volley/toolbox/JsonArrayRequest.java
- https://developer.android.com/reference/java/net/HttpURLConnection

Remaining gaps: obfuscated/custom Volley wrappers; branch/exception/field and
cross-method binding; dynamic URLs and unsupported connection configuration flows.
Dynamic and Agent were not changed by this task.
