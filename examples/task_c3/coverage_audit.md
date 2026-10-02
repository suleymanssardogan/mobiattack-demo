# C3 Android networking coverage audit

Audit only. No production source changed, app executed, corpus downloaded, or endpoint guessed.
Measurements: `measurements.json`; reproduce with `PYTHONPATH=. python examples/task_c3/audit_frameworks.py`.
Counts cover available decoded base/monolithic artifacts; library presence, invocation instructions,
JNI methods and library loads are static signals, not observed requests or proof of first-party ownership.
Samples carry relative source/line references. Audit-only marker recognition is not production framework detection.

## Required coverage matrix

| Framework | Detection | Canonical Candidate | Provenance | Main Gap |
| --- | --- | --- | --- | --- |
| Fuel | PASS for named supported calls | YES, partial identity may remain unresolved | Receiver/register, literal/call lines | Five verbs; direct strings/local receiver state; unresolved resolution not explicit |
| Retrofit | PARTIAL | YES for independently bound service/base | Annotation, builder/create and bounded helper trace | Field/branch/DI flow, dynamic bases; 127 Wikipedia declarations unbound |
| OkHttp | PARTIAL: descriptors; HttpUrl binding helper | NO for standalone requests | Descriptor/call location only; helpers can support Retrofit provenance | Request builder to newCall/enqueue/execute receiver chain |
| Volley | PARTIAL: named descriptors/probe; obfuscated labels in DVB | NO | Library/log-string signal only in measured DVB | Constructor method enum + URL + RequestQueue.add chain; obfuscation |
| Ktor | FAIL in production; no recognized real-app descriptor | NO | Synthetic descriptor/URL location only | Coroutine/lambda URL and method builder state |
| HttpURLConnection | PARTIAL: descriptors in all six apps | NO | Static invocation location | URL/openConnection/receiver/method/connection-use chain |
| WebView | PARTIAL: descriptors/call sites | NO as backend API | String/call location, no canonical load binding | Navigation/local assets are not backend APIs by default |
| Native/JNI | PARTIAL: structure libraries and method/load signals | NO | Library/component presence, not networking provenance | Binary bodies/protocol/endpoint identity unresolved |
| Custom wrappers | PARTIAL for bounded direct Retrofit helpers | NO generic wrapper support | Up to depth-3 safe direct helper trace for Retrofit | Fields, branches, polymorphism/reflection; unknown identity |
| Raw sockets | PARTIAL: Socket/DatagramSocket/ServerSocket descriptors | NO | Call instruction location only | Host/port/lifecycle binding and protocol; HTTP method/path may not exist |

## Mechanism dimensions

Here method/base/path “current” means extraction by current production code. A literal URL indicator
is never credited as framework-specific extraction. “Possible V1” is a proposed bounded expansion,
not functionality implemented by this audit.

| Mechanism | Seen in real apps | Identification possible | Method current | Host/base current | Path current | Possible deterministic V1 | False-positive risk / blocker |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Fuel | YES | YES when named | YES: GET/POST/PUT/PATCH/DELETE | YES when proven | YES direct argument | Existing support | Medium if branches/state/order are overinterpreted; no general flow proof |
| Retrofit | YES | YES annotations/types | YES seven supported annotations | YES proven binding only | YES literal annotation/templates | Existing support | Medium: correct class/base ownership; unsupported branches/fields stay unresolved |
| OkHttp | YES | YES named types | NO standalone | HttpUrl helper for Retrofit only | NO standalone | YES direct Request.Builder literal chain | Medium: separate builders, dynamic URLs, bundled SDKs |
| Volley | Label signals YES; recognized types NO in measured apps | PARTIAL when obfuscated | NO | NO | NO | YES named standard request constructors + queue | Medium: custom Request subclasses, obfuscated classes, request enum |
| Ktor | NO recognized real-app types; synthetic probe only | YES if names survive | NO | NO | NO | PARTIAL simple literal request builders | High: inline code, suspend/lambda state, engine indirection |
| HttpURLConnection | YES, predominantly bundled-library calls | YES named platform API | NO | NO | NO | YES direct URL/openConnection + setRequestMethod + consumption | Medium: method default versus setDoOutput, casts, redirects, wrapper receivers |
| WebView | YES | YES platform API | NO API method | NO bound navigation extraction | NO bound navigation extraction | YES URL-load observations, not backend API promotion | High if assets/navigation/JavaScript strings are promoted to APIs |
| Raw sockets | YES in several apps | YES API descriptor; protocol NO | NO / non-HTTP | NO | NO / non-HTTP | PARTIAL direct socket address observations | High: protocol unknown; endpoint/path cannot be manufactured |
| Native/JNI | YES methods/loads/libraries; actual networking UNKNOWN | PARTIAL component identification only | NO | NO | NO | Presence/coverage signals only | High: audio/render/crypto libraries are not proof of networking |
| Custom wrappers | YES application-owned network call sites and helper fixtures | PARTIAL known call-chain only | PARTIAL Retrofit helper | PARTIAL Retrofit helper | PARTIAL Retrofit helper | Narrow final/static direct helpers only | High: obfuscation/dispatch/heap fields; no guessed wrapper identity |

## Real applications

| App | Signals | Canonical candidates | Unresolved / coverage | Assessment |
| --- | --- | --- | --- | --- |
| OWASP MSTG Kotlin | Fuel; platform HTTP; WebView; sockets | 1 Fuel POST /signup | One Retrofit file skipped; no declarations found | Valid provenance-backed Fuel candidate; other mechanisms incomplete |
| Wikipedia | Retrofit; OkHttp; platform HTTP; WebView; sockets; JNI/load signals | 0 | 127/127 declarations unbound; 23 branch-flow and 9 field-flow diagnostics | Conservative, incomplete; zero candidates is not absence of endpoints |
| Flashlight | Platform HTTP; WebView, mostly non-app-owned call sites | 0 | No supported declarations; those mechanisms have no extractor | Correct non-promotion; incomplete coverage; no first-party inference |
| AntennaPod | OkHttp with 428 app-owned invoke lines; platform HTTP; WebView; sockets; 4 native libraries | 0 | Standalone OkHttp unsupported | Incomplete coverage with strong application-owned call-site signals |
| VulnBank | OkHttp/library calls; platform HTTP; WebView; sockets; native/JNI signals | 0 | One Retrofit file skipped; no declarations | Incomplete; bundled/framework presence does not prove reachable app networking |
| Damn Vulnerable Bank | Obfuscated Volley labels; platform HTTP; WebView; native/JNI | 0 | Named Volley descriptors missing; no supported declarations | Incomplete; framework label signal is weaker than structural request provenance |

No confirmed wrong static endpoint binding was found in these measurements. The important product
representation gap is that `extract_api_candidates` returns only candidates and StaticContext does
not carry Retrofit declarations/unbound/skip diagnostics. Unresolved evidence must remain visible later.
The audit's descriptor scans may miss renamed/inlined code; “not recognized” is not app-wide absence.

## Canonical identity gap

Current candidate keys are method/base_url/path/full_url/framework/source_file/request_line/evidence/status.
Scheme, host and effective port are encoded in URLs, not explicit normalized candidate fields. Resolution
state is partly implicit in null base/full_url; `static_api_candidate` does not distinguish resolution.
Retrofit strips query values and records `query_values_removed`, but does not preserve query-key shape.
Fuel can retain literal query values in its path/full_url evidence. Future adapters should preserve
query keys/shape and redact values; no privacy fix or schema change was made during this audit.

## Next three implementations — engineering ranking, not measured market-share statistics

1. **OkHttp direct Request.Builder V1.** Highest anticipated ecosystem/coverage gain across independent
   clients and SDKs. Bind one builder's literal URL, explicit/default method with evidence, build result,
   and newCall/execute/enqueue receiver; reject reassignment/branch/ambiguous flow. Medium complexity/risk.
2. **Volley standard request V1.** Android-specific, compact constructors with method enum and URL;
   require the same request object's queue.add. Start with named standard StringRequest/JSON classes;
   leave obfuscated/custom subclasses unresolved. Medium expected gain, low-to-medium complexity/risk.
3. **HttpURLConnection direct V1.** Platform API covers clients not using a named third-party stack.
   Bind URL construction, openConnection result, method configuration and actual connection usage;
   do not infer GET when setDoOutput/custom mutations make it ambiguous. Medium gain/complexity/risk.

For all three: one shared normalization boundary, explicit resolved/partial/unresolved states, component
and call-line evidence, default-port normalization, query-key preservation, secret-value exclusion,
SDK ownership left unknown unless independently proven. Do not expand symbolic execution or fuzzy matching.
Ktor follows these bounded direct patterns; WebView should get navigation observations, not API assumptions.
Native/JNI and custom wrappers retain explicit coverage gaps until safe structural evidence exists.

Official sources informing the feasibility ranking (not prevalence percentages):
- https://github.com/square/okhttp/blob/master/README.md
- https://google.github.io/volley/simple
- https://developer.android.com/reference/java/net/HttpURLConnection
- https://ktor.io/docs/client-requests.html
