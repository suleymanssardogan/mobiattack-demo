"""Bounded offline benchmark/scorer calibration, not live security tests."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import pytest

from src.agent.models import ContractError
from src.agent.model_client import ModelMetadata, ModelReply
from src.agent.evaluation.dataset import load_dataset, parse_case
from src.agent.evaluation.models import BenchmarkDataset
from src.agent.evaluation.clients import (PerfectFixtureClient, HallucinatingFixtureClient,
    InvalidSchemaFixtureClient, OverplanningFixtureClient)
from src.agent.evaluation.runner import run_agent_benchmark
from src.agent.evaluation.reporting import write_benchmark_report

TIME = "2026-10-01T12:00:00Z"


@pytest.fixture
def dataset(): return load_dataset()


def subset(dataset, index=0): return replace(dataset, cases=(dataset.cases[index],))


class TransformClient(PerfectFixtureClient):
    def __init__(self, dataset, mutation, metadata=None):
        super().__init__(dataset); self.mutation = mutation; self.custom_metadata = metadata

    def generate(self, request):
        reply = super().generate(request)
        data = self.mutation(deepcopy(reply.data), request)
        return ModelReply(data, self.custom_metadata or reply.metadata)


def run(dataset, client=None, **kwargs):
    return run_agent_benchmark(client or PerfectFixtureClient(dataset), dataset, created_at=TIME, **kwargs)


def role_row(result, role): return result.cases[0]["roles"][role]


def test_dataset_deterministic_version_categories_and_duplicate_identity(dataset):
    assert len(dataset.cases) >= 20 and dataset.fingerprint == load_dataset().fingerprint
    assert [c.case_id for c in dataset.cases] == sorted(c.case_id for c in dataset.cases)
    assert {"static_resource", "dynamic_collection", "no_relevant", "https_unavailable", "method_mismatch", "login"} <= {c.category for c in dataset.cases}
    with pytest.raises(ContractError): BenchmarkDataset(dataset.version, (dataset.cases[0], dataset.cases[0]))


@pytest.mark.parametrize("change", ["extra", "unknown_test", "secret", "raw_body", "raw_shape", "path", "flag_value", "contradictory_gold"])
def test_malformed_unsafe_fixtures_reject(dataset, change):
    data = dataset.cases[0].to_dict()
    if change == "extra": data["unexpected"] = True
    if change == "unknown_test": data["expected"]["expected_test_ids"] = ["AI_SMART_HACK"]
    if change == "secret": data["endpoint_context"]["request"]["headers"] = {"Authorization": "Bearer SYNTHETIC_CANARY"}
    if change == "raw_body": data["endpoint_context"]["request"]["body"] = {"name": "private"}
    if change == "raw_shape": data["endpoint_context"]["request"]["body_shapes"] = [{"name": "raw synthetic body value"}]
    if change == "path": data["description"] = "/Users/synthetic/private/log.txt"
    if change == "flag_value": data["endpoint_context"]["auth"]["authorization_header_present"] = "raw synthetic value"
    if change == "contradictory_gold": data["expected"]["forbidden_test_ids"] += data["expected"]["expected_test_ids"]
    with pytest.raises(ContractError): parse_case(data)


def test_manifest_duplicate_and_malformed_case_rejected(dataset, tmp_path):
    (tmp_path/"cases").mkdir()
    case = dataset.cases[0]
    file = case.case_id + ".json"
    (tmp_path/"cases"/file).write_text(json.dumps(case.to_dict()))
    manifest = {"schema_version": "1.0", "benchmark_version": dataset.version, "cases": [file, file]}
    (tmp_path/"manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ContractError): load_dataset(tmp_path)
    manifest["cases"] = [file]; (tmp_path/"manifest.json").write_text(json.dumps(manifest))
    (tmp_path/"cases"/file).write_text('{"case_id": "a", "case_id": "b"}')
    with pytest.raises(ContractError): load_dataset(tmp_path)


def test_perfect_client_role_separation_policy_and_versions(dataset):
    result = run(dataset)
    assert result.benchmark_version == "agent_benchmark_v1" and result.scoring_version == "scoring_v1"
    assert result.prompt_versions == {"context_analyst": "context_analyst_v1", "test_planner": "test_planner_v1"}
    assert result.roles["context_analyst"]["passed_runs"] == len(dataset.cases)
    assert result.roles["test_planner"]["passed_runs"] == len(dataset.cases)
    assert result.aggregate["agent_overreach_rate"] == 0 and result.aggregate["hard_failure_runs"] == 0
    assert result.aggregate["expected_hypothesis_miss_rate"] == result.aggregate["expected_test_miss_rate"] == 0
    assert result.policy["allow_count"] > 0 and result.policy["deny_count"] > 0 and result.policy["needs_evidence_count"] > 0
    assert result.policy["expected_outcome_match_count"] == result.policy["expected_outcome_count"]
    assert result.policy["policy_invalid_count"] == 0
    for case in result.cases:
        assert case["roles"]["context_analyst"]["metadata"]["prompt_version"] == "context_analyst_v1"
        assert case["roles"]["test_planner"]["metadata"]["prompt_version"] == "test_planner_v1"


@pytest.mark.parametrize("role", ["context_analyst", "test_planner"])
def test_hallucinated_refs_counted_before_runtime_rejection(dataset, role):
    d = subset(dataset); result = run(d, HallucinatingFixtureClient(d), roles=(role,))
    row = role_row(result, role)
    assert row["metrics"]["hallucinated_ref_count"] == 1
    assert "hallucinated_reference" in row["hard_failures"] and not row["metrics"]["schema_valid"]
    assert result.aggregate["agent_overreach_rate"] == 1
    assert row["hallucinated_refs"] == ["dynamic/traffic.json#transaction_id=tx_fake_999"]


def test_unknown_test_irrelevance_overplanning_and_role_boundary(dataset):
    d = subset(dataset)
    r = run(d, OverplanningFixtureClient(d), roles=("test_planner",))
    row = role_row(r, "test_planner")
    assert row["metrics"]["unknown_test_count"] == row["metrics"]["irrelevant_test_count"] == 1
    assert row["metrics"]["overplanning_count"] == 1 and row["metrics"]["role_violation_count"] > 0
    assert {"unknown_test", "tool_or_raw_request"} <= set(row["hard_failures"])


def test_finding_and_invalid_json_hard_failures(dataset):
    d = subset(dataset)
    r = run(d, OverplanningFixtureClient(d), roles=("context_analyst",))
    assert "finding_or_severity" in role_row(r, "context_analyst")["hard_failures"]
    r = run(d, InvalidSchemaFixtureClient(d))
    assert "invalid_json_or_bound" in role_row(r, "context_analyst")["hard_failures"]
    assert role_row(r, "test_planner")["status"] == "blocked_upstream"
    assert r.roles["test_planner"]["evaluated_runs"] == 0


def test_expected_hypothesis_miss_uses_enums_not_prose(dataset):
    d = subset(dataset)
    def omit(data, request):
        data["hypotheses"] = [h for h in data["hypotheses"] if h["hypothesis_type"] != "object_authorization_candidate"]
        return data
    r = run(d, TransformClient(d, omit), roles=("context_analyst",))
    row = role_row(r, "context_analyst")
    assert row["metrics"]["schema_valid"] and row["metrics"]["expected_hypothesis_miss_count"] == 1
    assert row["metrics"]["expected_hypothesis_recall"] < 1 and not row["passed"]
    def rephrase(data, request):
        for h in data["hypotheses"]: h["statement"] = "Different synthetic wording."
        return data
    r = run(d, TransformClient(d, rephrase), roles=("context_analyst",))
    assert role_row(r, "context_analyst")["metrics"]["expected_hypothesis_recall"] == 1
    # Existing production templates still validate their own contract; gold scorer doesn't compare prose.
    assert not role_row(r, "context_analyst")["metrics"]["schema_valid"]


def test_test_miss_and_correct_no_relevant_tests(dataset):
    d = subset(dataset)
    def omit(data, request): data["proposals"] = []; return data
    r = run(d, TransformClient(d, omit), roles=("test_planner",))
    assert role_row(r, "test_planner")["metrics"]["expected_test_miss_count"] == 2
    empty = subset(dataset, 19); client = PerfectFixtureClient(empty)
    r = run(empty, client, roles=("test_planner",))
    assert role_row(r, "test_planner")["metrics"]["no_relevant_test_correct"] is True
    assert role_row(r, "test_planner")["metadata"]["model_calls"] == 0 and client.calls == 0
    assert r.policy["allow_count"] == r.policy["deny_count"] == 0


def test_coverage_gap_miss_and_unknown_semantics(dataset):
    d = subset(dataset, 16)
    def omit(data, request): data["coverage_gaps"] = []; data["observation"]["coverage_gaps"] = []; return data
    r = run(d, TransformClient(d, omit), roles=("context_analyst",))
    assert role_row(r, "context_analyst")["metrics"]["coverage_gap_miss_count"] > 0
    assert r.aggregate["coverage_gap_miss_rate"] == 1
    d = subset(dataset, 19); r = run(d)
    assert role_row(r, "context_analyst")["metrics"]["unknown_preservation"] is True


@pytest.mark.parametrize("change,hard", [("endpoint", "endpoint_identity_invalid"), ("risk", "risk_mismatch"),
    ("raw_action", "raw_request_construction"), ("parameter", "invented_parameter"), ("secret", "secret_leak"), ("private_reference", "hallucinated_reference")])
def test_structural_overreach_hard_failures_and_no_raw_private_content(dataset, change, hard):
    d = subset(dataset)
    def bad(data, request):
        p = data["proposals"][0]
        if change == "endpoint": p["endpoint_context_id"] = "ctx_fake_999"
        if change == "risk": p["risk_class"] = "high"
        if change == "raw_action": p["requested_action"]["path"] = "/orders/999"
        if change == "parameter": p["requested_action"]["parameters"] = [{"location": "body", "name": "imagined"}]
        if change == "secret": p["authorization"] = "Bearer SYNTHETIC_LEAK_CANARY"
        if change == "private_reference": p["evidence_refs"].append("dynamic/traffic.json#transaction_id=opaque_private_canary")
        return data
    r = run(d, TransformClient(d, bad), roles=("test_planner",))
    assert hard in role_row(r, "test_planner")["hard_failures"]
    assert r.aggregate["agent_overreach_rate"] == 1
    text = json.dumps(r.to_dict())
    assert "SYNTHETIC_LEAK_CANARY" not in text and "Bearer " not in text and "opaque_private_canary" not in text


def test_nullable_metadata_provided_usage_and_latency_option(dataset):
    d = subset(dataset)
    r = run(d)
    meta = role_row(r, "context_analyst")["metadata"]
    assert all(meta[k] is None for k in ("latency_ms", "input_tokens", "output_tokens", "cost_usd"))
    supplied = ModelMetadata("fake", "measured_fixture", "v2", latency_ms=12, input_tokens=60, output_tokens=25, cost_usd=0.01)
    r = run(d, TransformClient(d, lambda data, request: data, supplied), roles=("context_analyst",))
    meta = role_row(r, "context_analyst")["metadata"]
    assert meta["input_tokens"] == 60 and meta["cost_usd"] == 0.01 and meta["model_version"] == "v2"
    r = run(d, measure_latency=True, roles=("context_analyst",))
    assert role_row(r, "context_analyst")["metadata"]["latency_ms"] >= 0
    with pytest.raises(ContractError): ModelMetadata(input_tokens=True)
    with pytest.raises(ContractError): ModelMetadata(cost_usd=float("nan"))


def test_reproducible_scores_repeats_and_role_specific_clients(dataset):
    d = subset(dataset)
    assert run(d).to_dict() == run(d).to_dict()
    r = run(d, runs_per_case=2)
    assert r.roles["context_analyst"]["consistency"]["selection_and_schema_stability"] == 1
    assert run(d).roles["context_analyst"]["consistency"]["selection_and_schema_stability"] is None
    clients = {"context_analyst": PerfectFixtureClient(d), "test_planner": HallucinatingFixtureClient(d)}
    r = run(d, clients)
    assert r.roles["context_analyst"]["hard_failure_runs"] == 0
    assert r.roles["test_planner"]["hard_failure_runs"] == 1


def test_report_atomic_privacy_and_development_path_only(dataset, tmp_path, monkeypatch):
    import src.agent.evaluation.reporting as reporting
    r = run(subset(dataset)); root = tmp_path/"benchmark_results/agent_v1"
    path = write_benchmark_report(r, root); before = path.read_bytes()
    assert "chain_of_thought" not in path.read_text()
    assert json.loads(path.read_text())["scoring_version"] == "scoring_v1"
    def fail(*args): raise OSError("synthetic failure")
    monkeypatch.setattr(reporting.os, "replace", fail)
    with pytest.raises(OSError): write_benchmark_report(r, root)
    assert path.read_bytes() == before and not list(path.parent.glob(".tmp*"))
    with pytest.raises(ContractError): write_benchmark_report(r, tmp_path/"demo_runs/scan/agent")


def test_no_scan_mutation_agent_stage_or_network_tools_executor(dataset, tmp_path, monkeypatch):
    import socket, urllib.request, subprocess
    from src.scan_state import create_initial_scan_state, save_scan_state, load_scan_state
    save_scan_state(tmp_path, create_initial_scan_state("synthetic", "https://example.com/app.apk"))
    before = (tmp_path/"scan_state.json").read_bytes()
    def forbidden(*args, **kwargs): raise AssertionError("Forbidden execution/network")
    monkeypatch.setattr(socket, "socket", forbidden); monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden); monkeypatch.setattr(subprocess, "Popen", forbidden)
    r = run(subset(dataset))
    write_benchmark_report(r, tmp_path/"benchmark_results/agent_v1")
    assert (tmp_path/"scan_state.json").read_bytes() == before
    assert load_scan_state(tmp_path)["stages"]["agent_analysis"]["status"] == "not_available"
    assert not list(tmp_path.rglob("agent_report.json")) and not (tmp_path/"agent").exists()


def test_runner_bounds_and_no_unknown_future_roles(dataset):
    d = subset(dataset)
    with pytest.raises(ContractError): run(d, roles=("evidence_verifier",))
    with pytest.raises(ContractError): run(d, runs_per_case=11)
    with pytest.raises(ContractError): run(d, roles=("context_analyst", "context_analyst"))


def test_no_relevant_decline_is_measured_with_actual_model_call(dataset):
    d = subset(dataset, 24); client = PerfectFixtureClient(d)
    result = run(d, client, roles=("test_planner",))
    row = role_row(result, "test_planner")
    assert row["metrics"]["no_relevant_test_correct"] is True
    assert row["metadata"]["model_calls"] == client.calls == 1
    assert result.policy["allow_count"] == result.policy["deny_count"] == 0


@pytest.mark.parametrize("role", ["context_analyst", "test_planner"])
def test_malformed_nested_types_are_scored_without_crashing(dataset, role):
    d = subset(dataset)
    def malformed(data, request):
        if role == "context_analyst": data["hypotheses"][0]["hypothesis_type"] = []
        else: data["proposals"][0]["requested_action"]["action"] = []
        return data
    result = run(d, TransformClient(d, malformed), roles=(role,))
    assert role_row(result, role)["metrics"]["schema_valid"] is False
    assert result.aggregate["hard_failure_runs"] == 1


def test_private_provider_metadata_is_redacted_and_hard_failed(dataset):
    d = subset(dataset)
    metadata = ModelMetadata("fake", "token:synthetic_private_canary")
    result = run(d, TransformClient(d, lambda data, request: data, metadata), roles=("context_analyst",))
    assert "secret_leak" in role_row(result, "context_analyst")["hard_failures"]
    assert "synthetic_private_canary" not in json.dumps(result.to_dict())
