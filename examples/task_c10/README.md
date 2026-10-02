# C10 — Static full checkpoint

All six existing local applications were re-analyzed twice through the current
Static builders and canonical report handoff. Wikipedia (3 APKs) and Flashlight
(5 APKs) were repeated with reversed split input order. No acquisition download,
app execution, or security attack was started by this checkpoint harness.
All 12 existing APK components passed the appropriate split-aware validator;
config splits are intentionally DEX-less and are not standalone APKs.

`checkpoint.json` records per-app packages, candidate/finding counts, network counts,
resolution/coverage diagnostics and deterministic SHA-256 fingerprints for the full
context/report/summary and separate manifest/structure/network/API/coverage blocks.
No lists were sorted by the comparison harness. Only timestamps/run IDs and repeat
output directories were normalized. All six repeats matched. OWASP /signup exact
call provenance was additionally checked against decoded source. Zero canonical
candidates in the other applications remains honest unresolved/bounded coverage.
Canonical Static reports and concise summaries are stored alongside this file.
Wikipedia and Flashlight report partial preprocessing coverage, preserving warnings.

Confirmed small regressions corrected:
- Static summary now includes existing C7 merged framework metadata for all six
  supported frameworks, and C8 partial/unsupported control coverage.
- Canonical report split metadata is ordered deterministically, including acquisition,
  preprocessing and merged APK component arrays. No analyzer behavior was changed.
- Development diagnostic inventory now follows the original URL in C7 provenance,
  rather than comparing an absolute source URL to its normalized relative path.
- One outdated static-to-dynamic contract test now checks the ID actually carried
  by the canonical Static report. Dynamic correlation code was not modified.

Final validation: 558 focused tests; 104 immediately affected tests; 6 real-app
integration checks; 6 deterministic repeat checks; 6 safe compact summary checks.
Full repository regression: 2576 passed, 0 failed, 3 skipped, 33 subtests passed.
The initial sandbox run could not bind localhost test-server ports and was stopped;
the final full run used approved local port access. No production code workaround
for that environment limitation was added. `verification.json` records final counts.

Remaining coverage limits: bounded/static networking cannot resolve every dynamic,
obfuscated/native/custom wrapper; crypto/storage/auth/privacy semantic controls remain
partial or unsupported; only locally available APK/splits and decoded evidence were
checked. None of these limitations implies absence of networking or app security.
No new framework, control, finding family, Dynamic behavior or Agent changes.
