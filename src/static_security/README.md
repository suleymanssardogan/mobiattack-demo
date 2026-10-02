# Static Security Control Catalog V1 (C8)

`control_catalog.json` is the machine-readable source of truth. `load_catalog()`
validates and returns an independent copy; no models, network calls, or execution
are used. Coverage is implementation coverage, not certification or a security
verdict. Unsupported controls are never assessed as passed; absent evidence is
unknown. Exact code-call evaluators for crypto, storage, WebView, auth bypass, and
privacy data flows are not introduced by this catalog.

The eight categories follow the official OWASP MASVS overview:
https://mas.owasp.org/MASVS/

The existing cleartext policy/proven HTTP-call mapping uses MASVS-NETWORK-1:
https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/

All other exact MASVS control refs and all MASWE/MASTG refs are intentionally empty.
Validation rejects unverified references, including syntactically plausible IDs.
Debuggable retains the existing MASVS-CODE category and severity guidance, without
claiming an exact control. Severity guidance is not a consequence of a mapping.

Evidence tiers are `fact`, `indicator`, `candidate`, `finding_eligible`. Only the
last tier can create a finding, and that label alone is insufficient: the gate
also requires a supported rule, matching catalog mapping, exact source/component,
observed value/pattern, and deterministic provenance reference. Existing static
policy/call checks determine eligibility before this gate; no user-supplied
indicator is silently upgraded. Explicit partial/unresolved API flows cannot
create HTTP-call findings. Endpoint discovery itself does not prove an endpoint
vulnerable; existing proven cleartext call findings concern transport configuration,
not signup/authentication behavior or runtime execution.

`provenance_refs` are evaluator-generated IDs for the persisted source/component/
value/reason/evidence-type tuple, not IDs claimed to exist in the original APK or
Static report. That tuple remains on the record for reference reproduction.
Merged framework evidence continues to live in canonical API candidate artifacts.
No raw secrets or PoC are introduced by these references.

The evaluator returns additive `control_catalog_version` and `control_coverage`
fields and catalog metadata on known evidence records. Canonical Static report
serialization preserves them in its existing vulnerabilities section. Coverage
assessment states are `unknown`, `requires_review`, `finding_present`, or
`not_evaluated`; none means secure. Legacy runtime handling is unchanged and is
outside this Static catalog. Dynamic and Agent files were not modified in C8.

Focused validation: 91 passed, 0 failed. No full regression run.
