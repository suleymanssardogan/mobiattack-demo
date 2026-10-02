# Static evidence eligibility (C2)

Static strings are indicators. Exact root binary references and incomplete manifest
policies are candidates; neither implies a vulnerability. Exported components,
requested permissions and backup flags need usage/data context before promotion.

Findings currently require an explicit manifest/configuration policy or a canonical
network call with a concrete endpoint, method, relative source and call line.
A networking call does not prove runtime execution or sensitive data exposure.
An unresolved/denying network security policy prevents automatic call promotion.

Mappings are descriptive and do not claim compliance:

- Explicit cleartext policy / HTTP networking call: MASVS-NETWORK-1.
  https://mas.owasp.org/MASVS/controls/MASVS-NETWORK-1/
- Debuggable application: category MASVS-CODE only. An exact control/CWE is
  intentionally omitted rather than reusing an unrelated identifier.
  https://mas.owasp.org/MASVS/

Android policy precedence and defaults:
https://developer.android.com/guide/topics/manifest/application-element
https://developer.android.com/privacy-and-security/security-config

No raw string-based CWE claims, root-check bypass findings, permission misuse
claims, or production/internal-endpoint claims are inferred by this evaluator.
