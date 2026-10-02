# Static API Discovery Coverage Diagnostic — Task 9.5.3.1

Decision: **DISCOVERY_IMPLEMENTATION_GAP**. Zero API candidates was an extractor-coverage result, not evidence of zero APIs. Wikipedia service annotations and AntennaPod search URL constants demonstrate recoverable unsupported forms. Examples, websites and library metadata must not be promoted.

## Current Discovery Sources

Read implementations: src/network_indicator_extractor.py, src/api_candidate_extractor.py, src/static_context_builder.py and src/split_static_context_builder.py.

Monolithic Android context invokes both extractors on APKTool output. Split context invokes them independently per applicable decoded component, skips candidate extraction for DEX-less splits, and retains component provenance. APK structure inventories raw assets/native libraries but does not analyze their contents. JADX projections exist locally but are not passed to either Android extractor. Neither extractor reads raw DEX, native binaries or encrypted/binary bundles.

Network indicators scan supported UTF-8 Smali/XML/JSON/text/HTML/JS/properties/config/YAML extensions. Before this fix Smali inspection was restricted to lines containing const-string. Java, Kotlin and bundle extensions are outside the production extension set. Diagnostic native printable-string scanning is separate and never feeds production candidates.

## Current Extraction Rules

Network regexes find HTTP(S), local file URLs, IPv4, bare domains and route-like paths. XML namespaces, platform/package/method noise, local filesystem paths and known file extensions are suppressed. Trailing punctuation is trimmed. Results deduplicate by type + value + source file + line, retaining distinct source occurrences, and sort deterministically.

API candidates support Fuel GET/POST/PUT/DELETE/PATCH and FuelManager.setBasePath only. Method-local direct string register tracking is cleared at method boundaries and invalidated on recognized destination writes. Moves, fields, invoke/range, arbitrary concatenation and non-Fuel frameworks are unsupported. Method-local base/path joining is not global reconstruction. Candidates sort by source/line/method/path; the extractor does not semantically deduplicate separate calls.

Network indicators do not automatically become API candidates. Canonical report projection preserves this distinction. Downstream endpoint identity requires usable canonical URL evidence; no missing host is guessed.

## Per-App Signal Inventory

Already-present Task 9.5.3 artifacts only. Bounds: 2 MB/file and 128 MB/app, app-owned sources prioritized. Raw files and duplicate JADX resources are excluded; strict UTF-8/binary rejection applies. Small decoded native libraries get bounded printable-string inspection; larger libraries/binary bundles remain unexamined. Counts cover inspected files; at most 512 representative signals are exported, prioritizing explicit context. URL hosts/paths are hashed, query/fragment/userinfo dropped; raw source lines are never exported.

Counts are source occurrences, including Java/Smali duplicates and repeated resources, not unique endpoints. Explicit-context triage is a deterministic diagnostic selector requiring manual interpretation, not a production API classifier.

| App | Inventoried occurrences | Explicit-context triage | Recognized network occurrences before | API candidates |
|---|---:|---:|---:|---:|
| app_004 | 825 | 1 | 8 | 0 |
| app_005 | 258 | 3 | 2 | 0 |
| app_006 | 730 | 2 | 5 | 0 |
| app_010 | 6674 | 277 | 964 | 0 |
| app_011 | 1546 | 12 | 125 | 0 |

Machine-readable inventories with exact source-relative references: examples/task_9_5_3_1/*_before_inventory.json and *_after_inventory.json. File counts, skipped-file reasons and byte totals are included. This is not exhaustive APK coverage.

## Per-App Extractor Coverage

app_004: AndroGoat JADX TrafficActivity.java:184 constructs an OkHttp request for a public website. Its URL is an indicator, not evidence of an API endpoint. No supported Fuel call yields candidates.

app_005: decoded smali/com/vulnerablebankapp/Secrets.smali:7 declares DEBUG_ENDPOINT. JADX Secrets.java:5 is duplicate evidence. Before the fix, the Smali file was traversed but this field line skipped; Java was outside the production source set. React dev-server configuration is library/development plumbing, not automatically the application's API.

app_006: res/layout/activity_banklogin.xml:11 contains an API URL input hint/example, not the configured backend. res/values/strings.xml:71 contains firebase_database_url metadata, a configuration indicator rather than an HTTP endpoint declaration. Runtime configuration and obfuscated networking limit stronger static conclusions.

app_010: 130 decoded runtime Retrofit HTTP annotation occurrences in app-owned service interfaces, plus 130 corresponding JADX declarations. These are not library annotation class definitions. For example, processed/base/apktool_out/smali/org/wikipedia/search/SemanticSearchService.smali:43 declares GET with a literal value at line 44. Fuel-only extraction never parses this declaration. The 260 duplicated occurrences do not mean 260 unique endpoints. Relative paths are not joined to unrelated hosts.

app_011: decoded smali_classes2/de/danoeh/antennapod/net/discovery/FyydPodcastSearcher.smali:10 contains FYYD_API_URL; ItunesPodcastSearcher.smali:10 and PodcastIndexPodcastSearcher.smali:10 contain search URL constants. PodcastIndexPodcastSearcher.smali:175 has a const-string used by String.format. Literal URL evidence exists, but formatting/non-Fuel data flow is unsupported; request-dependent placeholders are not filled.

## Miss Categories

| App | SOURCE_NOT_SCANNED | PATTERN_NOT_SUPPORTED | ANNOTATION_NOT_PARSED | Non-API/unclassified |
|---|---:|---:|---:|---:|
| app_004 | 1 | 0 | 0 | 824 |
| app_005 | 2 | 1 | 0 | 255 |
| app_006 | 0 | 2 | 0 | 728 |
| app_010 | 136 | 11 | 130 | 6397 |
| app_011 | 7 | 5 | 0 | 1534 |

Before-fix triage counts, not counts of confirmed missed endpoints. SOURCE_NOT_SCANNED includes duplicate Java evidence. Recognition flags separately identify already-found indicators versus emitted candidates. No miss is attributed to normalization without evidence. Binary bundles and large libraries are recorded as unsupported/unexamined, without asserted endpoints.

## Non-API Noise

Namespaces, docs/licenses, public website navigation, media/resources and library/development URLs dominate. Known non-API forms are classified separately; ambiguous URL strings remain unclassified. Neither a URL nor an HTTP client call alone establishes API semantics or execution. The app_006 input placeholder is not a real endpoint.

## Static vs Available Runtime Hints

Existing training runs lacked capture because default 8080 was occupied. Wikipedia/AntennaPod captured zero transactions on 18080, restored the proxy and reported HTTPS unavailable (cleartext_http_only_backend). Wikipedia stopped at external-package boundary; AntennaPod at observation failure. No new traffic/replay was generated. Zero traffic does not refute static declarations.

## Root Causes

1. API extraction covers Fuel while local artifacts expose Retrofit and other networking forms.
2. Network extraction skipped literal Smali string fields.
3. JADX, binary bundles and native behavior are not production discovery inputs.
4. Resource configuration/example URLs are not automatically endpoints.
5. Limited HTTPS visibility and bounded exploration prevent runtime confirmation.

Overall DISCOVERY_IMPLEMENTATION_GAP is supported; meaningful API evidence in every app is not asserted.

## Recommended Minimal Fixes

Implemented only literal Smali string-field inspection. Exact declared String fields pass through existing indicator/noise rules with file/line provenance. Non-String fields, expressions and schema URLs remain excluded. Field names do not promote indicators into API candidates.

Recognized inventory URL occurrences before→after: app_004 8→8; app_005 2→3; app_006 5→5; app_010 964→964; app_011 125→136. Additional field indicators are not API candidate counts.

Canonical static/correlation/EndpointContext stages reran from existing artifacts in isolated task_9_5_3_1 directories, reusing original runtime evidence. No download/reinstall/exploration repeated. API candidates and EndpointContexts remain 0→0 for all five apps. No diagnostic signal was imported into the benchmark.

## Unsupported / Future Sources

A separate focused Retrofit annotation parser should preserve method/path provenance and require structural base binding before asserting full endpoint identity. Explicit client URL data flow is another supported next target. Resource URLs need network-use evidence. Do not globally concatenate fragments or promote every absolute URL.

Native analysis, Hermes/binary bundle decoding, encrypted values, broad JADX heuristics and cross-method symbolic execution are deferred. No provider/model benchmarking or active API testing.
