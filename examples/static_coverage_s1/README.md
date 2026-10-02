# S1 Static Coverage Audit

Status: PARTIAL. Audit only; no implementation fixes. Existing local APK artifacts were processed with the current static context builder and Retrofit diagnostics. Wikipedia components were analyzed separately; no inferred cross-split binding.

## APK measurements

| App | Package | Launcher | Permissions | Activities | DEX / multidex | Native libraries | Assets | Smali roots | Kotlin metadata |
|---|---|---|---:|---:|---|---:|---:|---|---|
| OWASP MSTG Kotlin | sg.vantagepoint.mstgkotlin | sg.vantagepoint.mstgkotlin.MainActivity | 1 | 5 | 1 / no | 0 | 1 | smali | present |
| Wikipedia | org.wikipedia | org.wikipedia.DefaultIcon (alias) | 19 | 78 | 2 / yes | 3 | 12 | smali, smali_classes2 | present |
| AntennaPod | de.danoeh.antennapod | de.danoeh.antennapod.activity.SplashActivity | 11 | 13 | 4 / yes | 4 | 17 | smali through smali_classes4 | present |

Wikipedia native libraries belong to the arm64 configuration split; its base APK has none. Configuration splits have no DEX or smali roots. Kotlin metadata is presence detection, not proof of application language. Structure inventories were checked against the APK ZIP contents.

Full permissions, activities, assets, libraries, hashes and component measurements: [OWASP](app_1.json), [Wikipedia](app_2.json), [AntennaPod](app_3.json).

| App | URLs | Domains | IPs | Path candidates | Local file URLs | Fuel APIs | Retrofit declarations | Retrofit bindings / APIs | Other APIs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| OWASP MSTG Kotlin | 1 | 2 | 0 | 5 | 2 | 1 | 0 | 0 / 0 | 0 |
| Wikipedia | 1938 | 42 | 0 | 347 | 0 | 0 | 127 | 0 / 0 | 0 |
| AntennaPod | 138 | 217 | 1 | 54 | 0 | 0 | 0 | 0 / 0 | 0 |

Indicator counts represent source occurrences, not unique endpoints. URLs alone do not become API candidates.

## Canonical candidate and provenance

OWASP: `POST`, base `http://127.0.0.1`, path `/signup`, full URL `http://127.0.0.1/signup`, framework Fuel. Source: `MSTG-Android-Kotlin.apk`, `smali/sg/vantagepoint/mstgkotlin/RegisterActivity$onCreate$2.smali`. Base literal/call: lines 97/99; path literal: 102; request call: 214. Each reference was checked in the existing source. Status is `static_api_candidate`; it is neither runtime confirmation nor a vulnerability.

Wikipedia and AntennaPod produced no canonical API candidates. Wikipedia's 127 Retrofit declarations remain unresolved rather than receiving guessed URLs; diagnostics include unsupported branch and field flow.

## Coverage matrix

| Capability | Status | Reliability boundary |
|---|---|---|
| Manifest | PARTIAL | Normal package, permissions, activities and launcher aliases work; SDK-specific permission declarations and inherited application enabled state are not handled. |
| Structure | PASS | APK inventories agree with original ZIPs; no native behavior analysis. |
| Network Indicators | PARTIAL | Supported text literals only; domain/path heuristics can be noisy; no encrypted/computed strings or IPv6 coverage. |
| Fuel API Discovery | PARTIAL | Direct method-local literals work; receiver-specific base binding and URI filtering are incomplete. |
| Retrofit Declarations | PARTIAL | Supported literal relative-path annotations are found; dynamic URLs and unsupported annotation forms are outside coverage. |
| Retrofit Base Binding | PARTIAL | Bounded direct builder/service patterns are supported; field and branch-dependent construction remains unresolved. |
| Other API Frameworks | FAIL | No canonical discovery for other mechanisms; URL indicators are not equivalent to APIs. |
| Provenance | PASS | The emitted real candidate has verified source and line references. |
| False-positive filtering | PARTIAL | Random URL strings are excluded, but a file URL passed directly to Fuel is still accepted as a candidate. |

## Audit probes and gaps

Small synthetic, network-free probes supplement the real APK measurements. A random URL alone and a local asset URL alone both produced zero candidates. However, passing `file:///android_asset/test.html` to Fuel GET produced a candidate with a file-URL path and no full URL: the required filtering boundary is incomplete.

A separate two-manager Fuel probe associated a POST on the first receiver with the second receiver's latest base URL. Thus source provenance is present but does not guarantee a sound receiver binding.

A manifest probe omitted `uses-permission-sdk-23` and selected a launcher under a disabled application. These are existing parser coverage gaps. Probe outputs are in [summary.json](summary.json). No fixes were applied.

## Validation and boundary

Focused manifest, structure, indicator, Fuel/API, Retrofit/flow, static context, split context and static diagnostic suites: **162 passed / 0 failed**. Full regression was not run. Existing suite success does not negate the gaps demonstrated by audit probes.

No Dynamic Analysis or Agent changes, API execution, request replay, model runs, findings, or gold labeling were performed. Existing local changes were preserved; the branch was verified aligned with the fetched upstream before the audit.
