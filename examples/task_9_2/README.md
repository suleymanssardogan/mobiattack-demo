# Task 9.2 synthetic examples

These examples use a synthetic EndpointContext and the offline test fake, not a
live provider or device scan. Source references illustrate canonical syntax; they
do not claim that corresponding source transactions exist in this example folder.

- `input.json`: bounded, sanitized single-endpoint input with presence/type metadata.
- `valid_result.json`: validated fake output wrapping the canonical observation,
  hypotheses and coverage gaps. This is not a finding or Agent Report.
- `rejected_model_output.json`: deliberately fabricated synthetic reference example.
  Production runtime does not persist rejected raw model output.
- `rejected_result.json`: actual deterministic invalid_output outcome, fixed error
  codes, two attempts, no fabricated analysis.
- `agent/context_analysis.json`: atomic internal persistence example, sorted by
  endpoint identity. No agent_report.json or product-stage update is created.
