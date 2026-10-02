# Cross-framework canonicalization

Focused canonicalization, framework, Static Context, split, and Static report suites:
**321 passed, 0 failed**. No full regression was run.

The raw framework extractors retain their request-binding rules. The common adapter
normalizes their results after discovery and merges proven complete endpoint identities.

Resolved ID inputs: method, scheme, normalized host, effective port, normalized path,
query names and per-name multiplicity. Framework, source locations, APK component,
evidence count, query values/value-presence and input order do not control endpoint IDs.
HTTP/HTTPS and non-default ports remain separate. Framework aliases use the existing
labels Fuel, Retrofit, okhttp, volley, httpurlconnection and ktor.

Path normalization decodes unreserved percent escapes, uppercases remaining escapes
and encodes Unicode consistently. Encoded slashes/template delimiters remain literal.
Case, dot segments and repeated slashes are preserved rather than guessed equivalent.
IPv6 literals normalize to their compressed form. No fuzzy host/path matching is added.

One candidate exposes `frameworks`, `provenance` and `evidence_refs`. Existing singular
framework/source/evidence fields represent a deterministic primary source. Each origin
retains sanitized extractor identity, original source component, evidence and any
confidence/coverage metadata. `source_candidate_id` retains the previous generated
extractor-side reference ID; it is not an APK/manifest-provided field. New top-level
candidate IDs are endpoint references. Query values are removed throughout provenance.

Split sources are bound independently before merging, retaining source_apk on every
origin. Reapplying normalization is idempotent. Duplicate evidence is deduplicated.
Partial/unresolved identities retain source scope and never borrow another source's
missing authority, method or query metadata. Explicit unresolved states remain unresolved.

Retrofit's existing declaration parser now preserves query key/shape metadata before
removing values; no additional request patterns are supported. Unbound declarations
and existing discovery limitations remain in api_discovery through Static Context and
canonical Static report serialization. Zero canonical endpoints is not proof of no
networking. Older inputs with already-stripped query metadata remain explicitly unknown.

`canonical_example.json` contains one endpoint with all six framework provenance
records. This is synthetic metadata only; no requests were sent.

One old Static report sanitization test was updated to follow the accepted C2 rule:
cached findings lacking evidence are revalidated rather than blindly preserved. The
existing sanitizer is checked independently; finding behavior was not changed.

Dynamic and Agent were untouched. Remaining discovery/index limitations from C6,
unknown legacy query shape and conservative path equivalence remain explicit.
