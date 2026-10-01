# Agent model benchmark V1

Development evaluation only. Dataset: `agent_benchmark_v1`; scorer: `scoring_v1`.
The 25 synthetic, credential-free EndpointContext fixtures use api.example.com.
Cases cover object/resource, login/refresh/logout, session presence, query/body input,
static-only, dynamic-only, HTTPS visibility, method mismatch, missing traffic,
unknown state, coverage budget and admin-path-only authorization overreach.

## Run offline

```bash
python -m src.agent.evaluation.runner --client perfect --run-id perfect_fixture
python -m src.agent.evaluation.runner --client hallucinating --run-id hallucinating_fixture
python -m src.agent.evaluation.runner --client invalid --run-id invalid_fixture
python -m src.agent.evaluation.runner --client overplanning --run-id overplanning_fixture
```

Reports write atomically to benchmark_results/agent_v1/<run_id>/benchmark_report.json,
not demo_runs or product evidence. Generated reports are git-ignored; curated
examples are under examples/task_9_5. No network/provider is configured by the CLI.

Python supports the existing AgentModelClient protocol and distinct clients by role:

```python
from src.agent.evaluation.dataset import load_dataset
from src.agent.evaluation.runner import run_agent_benchmark

# analyst_client and planner_client are supplied AgentModelClient implementations.
dataset = load_dataset()
result = run_agent_benchmark(
    {"context_analyst": analyst_client, "test_planner": planner_client},
    dataset, runs_per_case=1, measure_latency=True,
)
```

Default repeat count is one; allowed range 1..10. Exactly one attempt per model role
call: no hidden retries. Roles are context_analyst and test_planner only. Analyst-only
runs do not plan. Planner-only runs use the same deterministic gold Analyst baseline,
allowing independent Planner comparisons. Full-pipeline Analyst failure blocks Planner
and is reported separately, never replaced with a successful model output. Case 025 tests a model declining a supplied optional candidate, rather than only
rewarding deterministic filtering. Empty
candidate sets short-circuit the Planner without a model call; reports distinguish
model-called runs from those deterministic results.

## Gold and scoring

Gold uses allowed/expected/forbidden hypothesis types, test IDs, expected role, gap
kinds, unknown field paths and expected policy outcomes. It never compares whole
prose strings. Production runtime validators still enforce their versioned supplied
fact/candidate templates; schema_valid means accepted by that constrained production
schema/grounding boundary. Separate raw-output audits reveal violations even when
production rejects the entire response. Hypothesis/test recall can be high on an
invalid response; the separate hard-failure/schema metrics must also be consulted.
This benchmarks current constrained selection, not unrestricted semantic intelligence.

Per Analyst: schema, identity, refs, hallucinations, forbidden fields, allowed hypothesis
precision, expected hypothesis recall/misses, role match, coverage recall/misses and
validated unknown preservation. Per Planner: schema/grounding, refs, unknown tests,
exact catalog risk, test recall/misses, irrelevant/duplicate over-planning, no-relevant
correctness, parameter/endpoint invention and role violations. Raw metrics remain visible in reports as
individual flags/counts and safe emitted types/IDs. Unknown reference identities
outside the fixture naming convention are redacted; their violation counts remain. Policy counts and expected outcome
matches are separate; invalid Planner output is not passed to the Gate. Synthetic
precondition_names are explicit trusted fixture resolver assertions, not evidence that
real auth, ownership or expected behavior has been verified.

No opaque composite or winner selection is used. Metric means, count totals, evaluated,
blocked and hard-failure run counts remain visible. Empty gold recall/precision uses
vacuous 1.0; corpus miss rates with no applicable expected items are null.

- allowed_hypothesis_precision = allowed emitted types / all emitted types.
- expected_hypothesis_recall and expected_test_recall = expected items emitted / expected items.
- coverage_gap_recall uses expected gap kinds, not descriptions.
- overplanning_count = unexpected distinct test IDs + duplicate test occurrences.
- agent_overreach_rate = model-called role runs with any unsupported hypothesis,
  irrelevant/unknown test, hallucinated ref, endpoint/parameter invention, risk
  manipulation, role violation or secret-like leakage / model-called role runs.
- miss proxies = total missed expected items / total applicable expected items.
- consistency = repeated cases with stable selection sets and schema flag / repeated
  cases. With one observation, stability is null, not assumed perfect.

These are benchmark overreach/task-recall proxies, NOT production vulnerability
false-positive/false-negative rates. Hard failures separately track invalid JSON/schema,
endpoint invention, hallucinated refs, finding/severity fields, tools/raw requests,
unknown tests, risk mismatch, secret-like leaks and model errors. Rejected raw prose,
secrets, filesystem paths and private reasoning are never stored in reports.

## Metadata and reproducibility

Record both prompt versions globally, including the reference Analyst version in
Planner-only runs: context_analyst_v1/test_planner_v1, dataset fingerprint/version,
scoring version, provider/model/model-version per role, timestamp and available latency,
input/output tokens and USD cost. Metadata stays null when unavailable. Wall-clock
latency is optional (`measure_latency=True`); supplied latency takes precedence.
Do not compare deterministic fake latency as real provider performance. Partial
performance aggregates expose observed_count; missing usage/prices are never invented.
The same fixture outputs and versions produce identical scores; clocks/run IDs and
opt-in measured latency may vary. Default offline timing is null.

## Future Task 9.6 comparison

1. Supply reviewed model clients implementing the existing generate(ModelRequest) interface.
2. Run the same versioned dataset; use role-only runs for fair independent comparisons.
3. Preserve prompt, scoring and dataset versions/fingerprint, call budgets and repetition count.
4. Collect raw metrics, failure counts and trustworthy token/cost/latency metadata.
5. Compare role by role. Human/product review chooses routing; no automatic best_model logic.

Task 9.5 does not add provider credentials, SDKs, live adapters, tool calls, executors,
HTTP tests, verifier, findings, PoC or Agent Report. Public agent_analysis is untouched.
