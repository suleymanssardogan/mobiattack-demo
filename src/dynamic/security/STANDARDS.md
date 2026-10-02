# Dynamic Security standards traceability

Mapping version: `dynamic_security_standards_v1`. References reviewed on
2026-10-02. This is an offline, curated descriptive mapping, not an OWASP-defined
crosswalk, a compliance assessment, or evidence that an entire control was tested.

| Dynamic category | MASVS category | Control references | MASTG test / MASWE references |
| --- | --- | --- | --- |
| authentication_presence | MASVS-AUTH | MASVS-AUTH-1 | Empty |
| object_authorization | MASVS-AUTH | MASVS-AUTH-1 | Empty |
| function_authorization | MASVS-AUTH | MASVS-AUTH-1 | Empty |
| session_handling | MASVS-AUTH | MASVS-AUTH-1 | Empty |
| parameter_consistency | MASVS-CODE | Empty | Empty |
| input_validation | MASVS-CODE | Empty | Empty |

[MASVS-AUTH](https://mas.owasp.org/MASVS/07-MASVS-AUTH/) covers authentication and
authorization. [MASVS-AUTH-1](https://mas.owasp.org/MASVS/controls/MASVS-AUTH-1/)
explicitly discusses remote-endpoint enforcement. This supports a descriptive
association for auth, object/function access, and session-dependent access checks.
It does not establish complete protocol verification or authorize these tests.
The unnumbered [MASTG authentication architecture guide](https://mas.owasp.org/MASTG/0x04e-Testing-Authentication-and-Session-Management/)
also discusses server-side session/token checks and rejecting missing tokens.
That guide URL is not a `MASTG-TEST` identifier, so it is not put in test refs.

[MASVS-CODE](https://mas.owasp.org/MASVS/10-MASVS-CODE/) discusses untrusted data
entry and input validation. Parameter consistency and input validation receive
only this thematic category. [MASVS-CODE-4](https://mas.owasp.org/MASVS/controls/MASVS-CODE-4/)
addresses validation within the mobile app; our generic backend API categories do
not establish that app-side scope. The specific control array therefore stays
empty until a more precise supported mapping is established.

No exact numbered MASTG test or MASWE weakness mapping was established for these
abstract backend checks. For example,
[MASWE-0018](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0018/) concerns access to
app components and app-exposed local services, and
[MASWE-0020](https://mas.owasp.org/MASWE/MASVS-AUTH/MASWE-0020/) concerns local
app authentication. Neither is automatically assigned to a remote API baseline.
Session termination weaknesses are also not inferred from auth removal.

All specific refs remain empty where uncertain. Empty refs do not assert a clean
security state. References are validated against the curated per-category set,
not merely a matching identifier format. An official but unrelated ID is also
rejected. Extending the curated set requires verified provenance and scope.

New canonical report rows carry `standards`; older rows without this optional
metadata remain loadable. Metadata never changes execution results, risk,
validation outcomes, reason codes, evidence requirements, or `finding_created`.
