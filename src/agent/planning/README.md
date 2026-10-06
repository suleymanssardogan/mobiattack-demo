# Goal + Utility V1

The flow is endpoint-scoped and bounded:

`PlanningGoal → Context Analyst → TestProposal[] → UtilityRanking → Policy Gate → existing Executor → existing Evidence Validator`

A goal expresses intent, never authority. Five closed goals are supported:
`review_security_coverage`, `assess_authentication`, `assess_object_authorization`,
`assess_function_authorization`, `assess_session_handling`. Each scopes candidates
to existing authentication/object/function/session primitives. Evidence prerequisites
still apply; this layer does not force a candidate when the existing Planner filters it.

The current Analyst and Planner receive sanitized goal metadata. The Planner still
emits canonical `TestProposal` records. Its candidates are revalidated against the
current endpoint/analyst snapshot before ranking. No new proposal schema is added.

## Deterministic priority

All factors are integers in 0..100. The versioned formula is:

`4 × relevance + 2 × evidence + coverage gain + information gain − 2 × risk − cost − 2 × duplicate penalty`

- Relevance: immutable goal-to-primitive mapping.
- Evidence: indexed, endpoint-linked references (50%), verified runtime baseline (25%),
  known sanitized auth flags (25%). Presence/absence are observations, not auth correctness.
- Coverage gain: fixed primitive-specific potential coverage prior; zero for duplicate work.
- Information gain: bounded prior reflecting unresolved auth/coverage context.
- Risk/cost: fixed catalog risk and relative primitive cost estimates, not measurements.
- Duplicates: explicit proposal IDs from this planning pass only; no persistent memory.

Confidence falls with missing evidence, missing prerequisites and coverage limitations.
Unknown states are not converted to absent/satisfied. Missing evidence can make a test
informative to consider, but NEVER eligible to execute. A high score is not a security
impact, finding, evidence, validation result or policy approval.

Sort descending by utility; break ties by canonical proposal ID. Policy receives a
priority-ordered view while original Planner records and policy serialization stay
canonical. Every decision is recomputed by the unchanged Gate. DENY/NEEDS_EVIDENCE
skip dispatch regardless of utility. Existing local-lab, execution binding, at-most-once,
risk and evidence-validator checks remain in force.

Goal/ranking traces are internal, safe metadata. Provider failures preserve the goal
and existing Static/Dynamic evidence. Invalid scorer input stops Agent processing.
No model migration, recursive supervisor, adaptive learning or execution retry is added.
