# Task 9.5 — Agent Model Evaluation Harness + Full Regression Checkpoint

### Files Changed

Added `src/agent/evaluation/{__init__,models,dataset,privacy,clients,scorers,runner,reporting}.py`, `benchmarks/agent_v1/manifest.json`, 25 versioned cases and README, `tests/test_agent_evaluation.py`, curated `examples/task_9_5/` and this report. Extended existing `src/agent/model_client.py` metadata with nullable model_version, latency_ms, input_tokens, output_tokens and cost_usd. Updated `.gitignore` for generated benchmark_results and appended a minimal model-selection section to SPEC.md.

Checkpoint-only maintenance: updated two obsolete expectations in `tests/test_dynamic_session_pipeline_wiring.py` to the already accepted Dynamic Report artifact/stage behavior, retaining the Agent stage boundary. No dynamic/static/orchestration implementation changes were made for Task 9.5.

Inspected main and existing dirty work, fetched origin and pulled main with fast-forward only; already current. All accepted local work was preserved. No commit or push.

### Evaluation Architecture

Versioned synthetic dataset → existing model interface → Context Analyst runtime/independent scorer → Test Planner runtime/independent scorer → deterministic Policy Gate → development BenchmarkRunResult/report. Raw responses are audited ephemerally before rejection erases violations. No production scan wiring.

A single client or a role-to-client mapping is supported. Analyst-only and Planner-only runs are supported; Planner-only uses the same deterministic gold Analyst baseline. Full-pipeline Analyst failure explicitly blocks Planner, rather than substituting a successful output. Valid Planner results alone reach the Policy Gate.

### Benchmark Dataset

25 synthetic, credential-free EndpointContext cases, loaded in stable order with duplicate/file-ID/endpoint-ID, schema, enum/gold consistency, source support, path, privacy and type-only shape checks. Fixture files are bounded to 32 KiB, dataset to 64 cases. Dataset fingerprint covers the canonical cases and expectations.

### Dataset Version

`agent_benchmark_v1`. The frozen fixture gold and dataset fingerprint make changes visible for future comparisons.

### Case Categories

Object/resource endpoints; login/refresh/logout; session presence; query/body input; static-only; dynamic-only; unavailable/partial HTTPS; method mismatch; missing traffic; unknown state; coverage budget; administrative-path-only overreach; no relevant tests. Case 025 explicitly tests a model declining a supplied optional candidate, so no-relevant correctness is not measured only through deterministic short-circuiting.

### Gold Expectation Strategy

Structured allowed/expected/forbidden hypothesis types, expected/forbidden test IDs, roles, coverage kinds, unknown field paths and policy outcomes. No whole-prose equality in gold scoring. Existing production validators still enforce their supplied versioned fact/candidate templates; schema_valid denotes acceptance by that current constrained boundary. This evaluates current bounded selection/grounding behavior, not unrestricted model intelligence.

### Context Analyst Metrics

schema_valid, endpoint_identity_valid, evidence_refs_valid, hallucinated_ref_count, forbidden_field_count, allowed_hypothesis_precision, expected_hypothesis_recall/miss counts, coverage_gap_recall/miss counts, role_violation_count, endpoint_role_valid, unknown_preservation and privacy failures. Validated tri-state facts preserve unknown; gold does not compare their prose.

### Test Planner Metrics

schema_valid, proposal_grounding_valid, hallucinated_ref_count, unknown_test_count, risk_integrity, expected_test_recall/misses, irrelevant_test_count, overplanning_count, no_relevant_test_correct, role_violation_count, invented endpoint/parameter counts and privacy failures. Raw invalid outputs remain observable through safe counts/enums, rather than appearing as successful empty plans.

### Policy Metrics

allow_count, deny_count, needs_evidence_count, policy_invalid_count and expected outcome matches/counts. Invalid Planner outputs skip policy; evaluated/not-evaluated case counts expose that distinction. Synthetic caller-verified prerequisite declarations are fixture assertions, not proof of real authenticated behavior or ownership. Perfect fixture outcomes: 24 ALLOW, 5 DENY, 10 NEEDS_EVIDENCE; all 39 expected policy outcomes match.

### Overreach / False-Positive Proxy

agent_overreach_rate is the fraction of model-called role runs with unsupported hypotheses, irrelevant/unknown tests, hallucinated refs, endpoint/parameter invention, risk manipulation, boundary violations or secret-like leakage. No-call deterministic results are explicitly separated. This is a benchmark overreach proxy, not production vulnerability false-positive rate.

### Miss / False-Negative Proxy

expected_hypothesis_miss_rate, expected_test_miss_rate and coverage_gap_miss_rate equal missed expected items / applicable expected items. They measure benchmark task recall, not vulnerability false-negative rate. No applicable denominator yields null; empty per-case gold recall/precision uses vacuous 1.0. Blocked roles are not silently assigned perfect or zero-miss scores.

### Hard Failure Rules

Invalid JSON/bounds or production schema, hallucinated endpoint/refs, finding/severity, tools/raw request construction, unknown test, risk mismatch, invented parameters, private-data/secret-like leakage and model errors. Failures are separate from precision/recall; even structurally useful raw output can fail grounding/boundary checks. Wrong nested field types are scored without crashing the harness.

### Scoring Version

`scoring_v1`. No opaque composite or automatic winner. Raw case flags/counts, metric means, count totals and hard-failure/evaluated/blocked counts remain visible. Formula definitions are in the benchmark README.

### Model Client Reuse

Reuses AgentModelClient.generate(ModelRequest) → ModelReply and existing production roles/prompts. An ephemeral capture decorator observes the same interface; no second provider abstraction. Optional metadata stays null if unavailable; numeric metadata rejects invalid/negative/nonfinite values. Supplied provider/model metadata is privacy-validated before report inclusion.

### Offline Fake Clients

PerfectFixtureClient, HallucinatingFixtureClient, InvalidSchemaFixtureClient and OverplanningFixtureClient calibrate scoring without internet or SDKs. PerfectFixtureClient intentionally reads gold and is not evidence for a real winning model. Tests use deterministic transformations for misses, forbidden fields, unknown tests, raw instructions, privacy leakage and malformed schemas.

### Benchmark Runner

`run_agent_benchmark(client_or_role_mapping, dataset, roles=..., runs_per_case=1, measure_latency=False)`. At most 10 repeats; exactly one attempt per model role call, no hidden retries. Optional measured latency and supplied usage/cost metadata are supported; missing usage/prices are never invented. Single-run consistency remains null.

Offline CLI: `python -m src.agent.evaluation.runner --client perfect --run-id task_9_5_perfect`. Other choices are hallucinating, invalid and overplanning; no provider options or credentials.

### Role-Separated Results

Independent Analyst and Planner score tables and per-role provider/model/version metadata support future distinct routing. Model-called and deterministic no-call runs are distinguished. Repeated-run consistency compares selection sets plus schema flags. Planner-only comparisons isolate Planner ability from Analyst failure; complete pipeline runs expose propagation failures.

### Benchmark Report Schema

BenchmarkRunResult includes schema/benchmark/scoring versions, both prompt versions (also in Planner-only runs), dataset fingerprint, run ID/timestamp, role summaries, policy metrics, aggregate proxies and case/iteration records. Case results contain status/pass/fail, raw metric flags/counts, safe emitted IDs/types, redacted hallucination details, role violations, hard failures, metadata and policy outcomes. No private reasoning or raw responses.

### Privacy

Only synthetic api.example.com fixtures; no production traffic, credential/header/cookie values, raw bodies/logs or host filesystem paths. Strict field/type-only shape checks reject raw values. Rejected outputs remain ephemeral. Unknown reference identities outside fixture naming conventions are redacted while counts remain. Private provider metadata is withheld and hard-failed. Reports are privacy-checked before atomic persistence.

### Reproducibility

Stable fixture ordering, dataset fingerprint, exact prompt/scorer versions, stable hypothesis/proposal/policy IDs and deterministic fake outputs produce stable scores. Fixed synthetic timestamps are used for curated examples; normal run timestamps/IDs and opt-in wall-clock measurements can vary. Token/cost/latency metadata are nullable; partial performance aggregates expose observed counts.

### SPEC Update

Minimal appended section: models are selected by versioned benchmark evidence rather than hardcoded assumptions; future role-specific routing is allowed. No architectural rewrite or production model choice.

### Full Regression Checkpoint

**PASSED — 0 failed.** Canonical full command: `pytest -q --tb=short -rs`.

Latest broad sweep: **1486 passed, 3 skipped, 33 subtests passed**. The three skips are established optional ADB-device integration tests in android_runtime_launcher, demo_orchestrator and html_probe_server; no connected device was available. The final evaluation-only privacy additions were verified afterward with all **33 evaluation tests passing**.

The initial sandbox run could not bind existing localhost fixture servers. The allowed-environment sweep verified those tests successfully. Two old session-wiring assertions were reconciled with accepted Task 8 Dynamic Report behavior; production implementation was preserved. No failing tests were removed/skipped to obtain the checkpoint.

### Tests

`pytest tests/test_agent_evaluation.py -q --tb=short`: **33 passed, 0 failed**. Covers deterministic/duplicate/malformed/private fixtures, perfect and bad clients, all major raw-output violations, gold misses and non-prose scoring, no-relevant behavior including actual model decline, coverage, all three policy outcomes, role separation/versions, nullable and supplied metadata, consistency, bounds, atomic report failure, untouched product artifacts/stage and no network/tools/executor.

Full checkpoint includes Context Analyst, Planner, Policy Gate/integration, Agent contracts, Endpoint Context, API correlation, Dynamic Report, static reporting, scan-state/recovery, orchestration and other repository suites. Historical localhost integration tests are test fixtures; the benchmark itself calls no network or active target API.

### Example Benchmark Case

`examples/task_9_5/benchmark_case.json`: /orders/{id}, synthetic resource identity/evidence, structured allowed/forbidden expectations, canonical medium OBJECT_AUTHORIZATION and passive AUTHENTICATION_PRESENCE expectations.

### Example Perfect Model Result

`examples/task_9_5/perfect_model_result.json`: both roles pass 25/25 cases, 50 scored role runs (46 actual model-called runs), zero overreach/hard failures/misses, all 39 expected policy outcomes match. Usage/cost/latency remain unknown, not inferred.

### Example Hallucinating Model Result

`examples/task_9_5/hallucinating_model_result.json`: 25 Analyst hallucinated-reference hard-failure runs and overreach rate 1.0. Planner is explicitly blocked on 25 cases, not scored as passing. Expected hypothesis recall may remain high because enum selection is separate from failed grounding; this illustrates why hard-failure metrics remain visible. Independent Planner-only calibration is supported and tested.

### Real Provider Boundary

No OpenAI/Gemini/Claude production integration, credentials, SDK or benchmark winner. Future Task 9.6 supplies reviewed clients through the same interface, preserves dataset/prompts/scorer, collects real usage/cost/latency and compares roles separately. Evidence Verifier is not evaluated.

### Product Stage Boundary

Development reports live at benchmark_results/agent_v1/<run_id>/benchmark_report.json, git-ignored and outside demo_runs. Atomic tempfile/fsync/replace preserves prior reports on write failure. No scan artifacts/state are written by the harness; agent_analysis stays not_available. No agent_report.json, tool calling, executor, replay, active API tests, verifier, confirmed finding or PoC.

### Diff Summary

Adds the versioned 25-case benchmark, bounded offline runner/scorers/clients, safe atomic reports, focused calibration tests and minimal model-selection documentation. Extends only the shared nullable metadata contract. Corrects two outdated regression assertions at the checkpoint, without introducing new product runtime behavior. No next milestone was implemented.

Task 9.5 completed. Agent model evaluation harness is ready. Live provider integration, tool calling, executor, and active API testing were not started.
