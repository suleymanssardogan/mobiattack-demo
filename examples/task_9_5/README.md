# Task 9.5 benchmark examples

Synthetic versioned dataset and offline clients only. Fixture timestamps are fixed
for reproducibility; latency/token/cost metadata are unknown, not guessed.

- benchmark_case.json: object-resource case with structured expectations.
- perfect_model_result.json: calibrated fixture matches all 25 cases; no winning
  production model is implied by a client that intentionally reads fixture gold.
- hallucinating_model_result.json: raw reference violations remain visible after
  production validation rejects responses. Analyst failure blocks downstream
  Planner; blocked runs are not silently scored as passing. Use Planner-only runs
  against the same gold Analyst baseline to compare Planner clients independently.

These are development metrics and task-recall/overreach proxies, not vulnerability
false-positive/false-negative measurements or product evidence. No provider, tools,
executor, active API tests, verifier, findings, PoC or Agent Report were introduced.
