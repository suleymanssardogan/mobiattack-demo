# Task 9.4 synthetic policy examples

Offline EndpointContext → Context Analyst → Test Planner → Policy Gate fixture.
No requests, tool calls, replay or execution. These are schema examples, not scan
evidence or production validation. Expected-behavior preconditions for the ALLOW
examples are explicitly vouched for by synthetic trusted resolver metadata; no
credential presence is treated as proof of authenticated behavior or ownership.

- allow.json: low INPUT_VALIDATION proposal satisfies supplied prerequisites.
- deny.json: canonical medium OBJECT_AUTHORIZATION is blocked by V1 policy.
- needs_evidence.json: SESSION_HANDLING has missing expected-session prerequisites.
- policy_evaluation.json: typed envelope and decision/count metadata.
- policy_trace.json: linked hypothesis/proposal/test/decision IDs and public-safe reasons.
- agent/policy_decisions.json: atomic internal persistence envelope.

ALLOW means eligible for future consideration, never execution or automatic
execution approval. No agent_report.json or public stage completion is created.
