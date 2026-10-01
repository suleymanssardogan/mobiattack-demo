"""Offline-capable benchmark entry point using the existing AgentModelClient."""
from dataclasses import asdict
from datetime import datetime, timezone
from time import perf_counter
from collections.abc import Mapping
import statistics

from src.agent.model_client import AgentModelClient, ModelMetadata, ModelReply
from src.agent.models import ContractError, identifier, timestamp
from src.agent.context_analyst import analyze_endpoint_context, build_context_analyst_input
from src.agent.test_planner import plan_endpoint_tests, build_test_planner_input
from src.agent.policy import EvidenceRecord, PreconditionRecord, _REFERENCE_TYPES
from src.agent.policy_integration import evaluate_test_plan
from .models import BenchmarkRunResult, BenchmarkDataset, ROLES
from .dataset import load_dataset, parse_case
from .clients import PerfectFixtureClient
from .scorers import score_context_analyst, score_test_planner
from .privacy import validate_privacy


class _CaptureClient:
    """Ephemeral raw response for audit; never serialized into a benchmark report."""
    def __init__(self, client, measure_latency):
        self.client = client; self.measure_latency = measure_latency
        self.raw = None; self.metadata = None; self.privacy_failure = False; self.calls = 0; self.elapsed_ms = None

    def generate(self, request):
        self.calls += 1; started = perf_counter()
        try:
            reply = self.client.generate(request)
            self.raw = reply.data if isinstance(reply, ModelReply) else reply
            if isinstance(reply, ModelReply) and isinstance(reply.metadata, ModelMetadata):
                try:
                    metadata = asdict(ModelMetadata(**asdict(reply.metadata)))
                    validate_privacy(metadata)
                    self.metadata = metadata
                except (ContractError, TypeError): self.privacy_failure = True
            return reply
        finally:
            if self.measure_latency: self.elapsed_ms = round((perf_counter() - started) * 1000, 6)

    def measurements(self, now, role, prompt_version):
        data = self.metadata or {key: None for key in ("provider", "model", "model_version", "latency_ms", "input_tokens", "output_tokens", "cost_usd")}
        data = dict(data)
        if data["latency_ms"] is None: data["latency_ms"] = self.elapsed_ms
        return {**data, "role": role, "prompt_version": prompt_version, "timestamp": now, "model_calls": self.calls}


def _role_result(score, result, capture, now, role):
    metrics = score["metrics"]
    if capture.privacy_failure:
        metrics["secret_leak_count"] = metrics.get("secret_leak_count", 0) + 1
        score["hard_failures"] = sorted(set(score["hard_failures"]) | {"secret_leak"})
    flags = [metrics.get("schema_valid"), not score["hard_failures"]]
    for key in ("allowed_hypothesis_precision", "expected_hypothesis_recall", "coverage_gap_recall", "expected_test_recall"):
        if key in metrics: flags.append(metrics[key] == 1.0)
    for key in ("unsupported_hypothesis_count", "irrelevant_test_count", "overplanning_count"):
        if key in metrics: flags.append(metrics[key] == 0)
    if "endpoint_role_valid" in metrics: flags.append(metrics["endpoint_role_valid"])
    return {**score, "status": result.status, "passed": all(flags), "validation_errors": list(result.validation_errors),
            "metadata": capture.measurements(now, role, result.prompt_version)}


def _policy_signal(case, analyst, planner, source, now):
    index = {}
    for ref in source.evidence_universe:
        path, _, fragment = ref.partition("#"); key = fragment.partition("=")[0]
        kind = _REFERENCE_TYPES.get((path, key))
        if kind: index[ref] = EvidenceRecord(ref, case.endpoint_context.endpoint_context_id, kind[0])
    # Dataset-declared synthetic expected-behavior proofs are explicit resolver inputs.
    # The report/README must not present them as real scan or authentication proof.
    context_ref = source.evidence_refs["endpoint_context"][0]
    proof = {name: PreconditionRecord(name, case.endpoint_context.endpoint_context_id, (context_ref,))
             for name in case.precondition_names}
    evaluation = evaluate_test_plan(case.endpoint_context, analyst, planner, index, precondition_index=proof, created_at=now)
    expected = case.expected["expected_policy_outcomes"]
    actual = {d.test_id: d.decision for d in evaluation.decisions}
    return {"status": evaluation.status, "policy_version": evaluation.policy_version,
        "allow_count": evaluation.allow_count, "deny_count": evaluation.deny_count,
        "needs_evidence_count": evaluation.needs_evidence_count,
        "policy_invalid_count": sum(d.reason_code in {"SCHEMA_INVALID", "UNKNOWN_TEST", "UNKNOWN_ENDPOINT_CONTEXT", "UNKNOWN_HYPOTHESIS", "HALLUCINATED_EVIDENCE"} for d in evaluation.decisions),
        "expected_outcome_count": len(expected), "expected_outcome_match_count": sum(actual.get(t) == value for t, value in expected.items()),
        "decisions": [d.to_dict() for d in evaluation.decisions]}


def _role_summary(records, role):
    rows = [r["roles"][role] for r in records if role in r["roles"]]
    scored = [r for r in rows if r.get("metrics") is not None]
    means, totals = {}, {}
    keys = sorted({key for r in scored for key in r["metrics"]})
    for key in keys:
        values = [r["metrics"][key] for r in scored if r["metrics"].get(key) is not None]
        means[key] = round(statistics.mean(values), 6) if values else None
        if key.endswith("_count"): totals[key] = sum(values)
    models = sorted({(r["metadata"]["provider"], r["metadata"]["model"], r["metadata"]["model_version"])
                     for r in scored if r["metadata"]["provider"] is not None}, key=lambda values: tuple(v or "" for v in values))
    groups = {}
    for r in records:
        if role in r["roles"] and r["roles"][role].get("metrics") is not None:
            row = r["roles"][role]
            key = "emitted_hypothesis_types" if role == "context_analyst" else "emitted_test_ids"
            groups.setdefault(r["case_id"], []).append((tuple(row.get(key, [])), row["metrics"]["schema_valid"]))
    repeated = [values for values in groups.values() if len(values) > 1]
    performance = {}
    for key in ("latency_ms", "input_tokens", "output_tokens", "cost_usd"):
        values = [r["metadata"][key] for r in scored if r["metadata"][key] is not None]
        performance[key] = {"mean": round(statistics.mean(values), 6) if values else None,
                            "total": round(sum(values), 6) if values else None, "observed_count": len(values)}
    called = [r for r in scored if r["metadata"]["model_calls"]]
    return {"model_called_runs": len(called), "no_model_call_runs": len(scored) - len(called),
        "schema_valid_rate_for_called_runs": sum(r["metrics"]["schema_valid"] for r in called) / len(called) if called else None,
        "evaluated_runs": len(scored), "blocked_runs": len(rows) - len(scored),
        "passed_runs": sum(r["passed"] for r in scored), "hard_failure_runs": sum(bool(r["hard_failures"]) for r in scored),
        "models": [{"provider": p, "model": m, "model_version": v} for p, m, v in models],
        "metric_means": means, "metric_totals": totals, "performance": performance,
        "consistency": {"repeated_cases": len(repeated), "selection_and_schema_stability":
            sum(len(set(v)) == 1 for v in repeated) / len(repeated) if repeated else None}}


def run_agent_benchmark(model_client: AgentModelClient, dataset=None, *, roles=ROLES, runs_per_case=1,
                        run_id="offline_benchmark", created_at=None, measure_latency=False):
    """One attempt per role/case, no hidden retries. Clients may differ by role.

    Planner-only evaluation uses a deterministic gold Analyst fixture. In a full
    pipeline, failed Analyst output blocks downstream planning and is reported as
    blocked, never silently replaced with a passing Analyst output.
    """
    dataset = load_dataset() if dataset is None else dataset
    if not isinstance(dataset, BenchmarkDataset): raise ContractError("BenchmarkDataset required")
    if (not isinstance(roles, (tuple, list)) or not roles or any(not isinstance(role, str) for role in roles) or len(set(roles)) != len(roles)
            or any(role not in ROLES for role in roles)):
        raise ContractError("Unsupported benchmark roles")
    if type(runs_per_case) is not int or not 1 <= runs_per_case <= 10:
        raise ContractError("runs_per_case must be 1..10")
    if type(measure_latency) is not bool: raise ContractError("Invalid latency option")
    # Revalidate even manually assembled fixture objects at the harness boundary.
    dataset = BenchmarkDataset(dataset.version, tuple(parse_case(c.to_dict()) for c in dataset.cases))
    now = created_at or datetime.now(timezone.utc).isoformat()
    identifier(run_id, "run_id"); timestamp(now)
    reference_client = PerfectFixtureClient(dataset)
    clients = {role: model_client[role] if isinstance(model_client, Mapping) else model_client for role in roles}
    records = []
    for case in sorted(dataset.cases, key=lambda c: c.case_id):
        source = build_context_analyst_input(case.endpoint_context, coverage_metadata=case.coverage_metadata)
        for iteration in range(runs_per_case):
            row = {"case_id": case.case_id, "category": case.category, "iteration": iteration + 1, "roles": {}, "policy": None}
            capture = _CaptureClient(clients["context_analyst"] if "context_analyst" in roles else reference_client, measure_latency)
            analyst = analyze_endpoint_context(case.endpoint_context, capture, coverage_metadata=case.coverage_metadata, max_attempts=1, created_at=now)
            if "context_analyst" in roles:
                score = score_context_analyst(capture.raw, analyst, source, case.expected)
                row["roles"]["context_analyst"] = _role_result(score, analyst, capture, now, "context_analyst")
            if "test_planner" in roles:
                if analyst.status != "completed":
                    row["roles"]["test_planner"] = {"status": "blocked_upstream", "passed": None, "metrics": None, "hard_failures": [], "metadata": None}
                else:
                    planner_source = build_test_planner_input(case.endpoint_context, analyst)
                    capture = _CaptureClient(clients["test_planner"], measure_latency)
                    planner = plan_endpoint_tests(case.endpoint_context, analyst, capture, max_attempts=1, created_at=now)
                    raw = capture.raw if capture.calls else {"endpoint_context_id": planner.endpoint_context_id, "proposals": []}
                    score = score_test_planner(raw, planner, planner_source, case.expected)
                    row["roles"]["test_planner"] = _role_result(score, planner, capture, now, "test_planner")
                    if planner.status in {"completed", "no_relevant_tests"}:
                        row["policy"] = _policy_signal(case, analyst, planner, source, now)
            records.append(row)
    summaries = {role: _role_summary(records, role) for role in ROLES if role in roles}
    policies = [r["policy"] for r in records if r["policy"] is not None]
    policy = {key: sum(p[key] for p in policies) for key in ("allow_count", "deny_count", "needs_evidence_count", "policy_invalid_count", "expected_outcome_count", "expected_outcome_match_count")}
    policy["evaluated_cases"] = len(policies); policy["not_evaluated_cases"] = len(records) - len(policies)
    scored = [r for row in records for r in row["roles"].values() if r.get("metrics") is not None]
    called = [r for r in scored if r["metadata"]["model_calls"]]
    overreach = sum(any(r["metrics"].get(k, 0) for k in ("hallucinated_ref_count", "role_violation_count", "secret_leak_count", "unsupported_hypothesis_count", "irrelevant_test_count", "unknown_test_count", "unknown_parameter_count", "invented_endpoint_count"))
                    or "endpoint_identity_invalid" in r["hard_failures"] or "risk_mismatch" in r["hard_failures"] for r in called)
    aggregate = {"agent_overreach_rate": overreach / len(called) if called else None, "scored_role_runs": len(scored), "model_called_role_runs": len(called),
                 "hard_failure_runs": sum(bool(r["hard_failures"]) for r in scored)}
    for numerator, denominator, name in (("expected_hypothesis_miss_count", "expected_hypothesis_count", "expected_hypothesis_miss_rate"),
        ("expected_test_miss_count", "expected_test_count", "expected_test_miss_rate"),
        ("coverage_gap_miss_count", "expected_coverage_gap_count", "coverage_gap_miss_rate")):
        total = sum(r["metrics"].get(denominator, 0) for r in scored)
        aggregate[name] = sum(r["metrics"].get(numerator, 0) for r in scored) / total if total else None
    return BenchmarkRunResult(run_id, now, dataset.fingerprint, summaries, policy, aggregate, tuple(records), runs_per_case)


def main():
    import argparse
    from .clients import HallucinatingFixtureClient, InvalidSchemaFixtureClient, OverplanningFixtureClient
    from .reporting import write_benchmark_report
    parser = argparse.ArgumentParser(description="Offline Agent benchmark; no live provider")
    parser.add_argument("--client", choices=["perfect", "hallucinating", "invalid", "overplanning"], default="perfect")
    parser.add_argument("--run-id", default="offline_benchmark")
    parser.add_argument("--runs-per-case", type=int, default=1)
    args = parser.parse_args(); dataset = load_dataset()
    factories = {"perfect": PerfectFixtureClient, "hallucinating": HallucinatingFixtureClient,
                 "invalid": InvalidSchemaFixtureClient, "overplanning": OverplanningFixtureClient}
    result = run_agent_benchmark(factories[args.client](dataset), dataset, run_id=args.run_id, runs_per_case=args.runs_per_case)
    print(write_benchmark_report(result))


if __name__ == "__main__": main()
