# C9 — Static false-positive hardening

Focused synthetic adversarial probes and existing real static fixtures passed.
No scanner/framework support or security controls were added. Dynamic and Agent
files were not modified by this task; prior workspace changes were preserved.

Changes:
- Resource/comment/documentation/unused-literal contexts cannot promote HTTP calls.
- Explicit third-party provenance and direct networking-library-internal component
  namespaces remain context indicators. Host names and framework use do not prove
  ownership; otherwise ownership remains unknown. This is not an SDK fingerprint
  database, and unknown ownership does not suppress an otherwise proven call.
- Merged canonical framework provenance is evaluated per source rather than using
  only the canonical primary source. Explicit partial/unresolved candidates remain
  non-findings even when nested provenance claims resolution.
- Repeated equivalent HTTP issues within the same source component/endpoint merge;
  different source components/endpoints and distinct network configuration scopes
  remain separate. All supporting evidence/refs and affected call lines are retained.
- Global cleartext policy findings retain supporting HTTP call context without
  creating redundant call findings. Network-config call context is supplementary,
  not proof that a particular request belongs to a permitted domain scope.
- Stable additive finding_instance_id disambiguates issues while legacy control IDs
  remain available. Severity is unchanged by match count. C8 evidence gating and
  primary exact provenance refs remain intact; supporting refs are additive.
- Canonical Static reporting continues re-evaluating current evidence rather than
  trusting stale cached findings. Impact/remediation/evidence remain complete.

A loopback HTTP string is not a vulnerability. A structurally proven HTTP networking
call may still support the existing transport control, including the authorized
OWASP /signup fixture; that does not claim signup is vulnerable or runtime-confirmed.
An exact root binary reference remains a candidate, not proof of a root check.
Crypto/storage/auth/privacy call-flow evaluators remain unsupported as in C8.

Tests: 366 passed, 0 failed; focused evaluator/catalog/report and existing framework
extractor suites only. No full repository checkpoint; C10 is deferred.

Remaining limitations: explicit/minimal ownership metadata cannot identify every SDK;
static call evidence cannot prove runtime execution or sensitive-data transmission;
unsupported semantic/data-flow controls remain unknown rather than secure.
