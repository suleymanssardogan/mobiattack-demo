"""Focused offline real pilot boundaries. Every fixture here is synthetic."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import socket
import subprocess
import pytest

from src.agent.models import ContractError
from src.agent.evaluation.dataset import load_dataset
from src.agent.evaluation.real_dataset import (
    AppMetadata, build_real_benchmark_case, parse_real_case, build_manifest,
    export_real_app, load_real_cases, validate_real_dataset, review_template,
    apply_review, save_review, validate_real_safety, _atomic,
)
from src.dynamic.context.models import EndpointContextArtifact

NOW = "2026-10-01T12:00:00Z"

@pytest.fixture
def endpoint():
    e = deepcopy(load_dataset().cases[0].endpoint_context)
    e.host = "api.private-company.example"
    e.path = "/orders/123"
    return e

@pytest.fixture
def app():
    return AppMetadata("app_001", "owned_app")

@pytest.fixture
def root(tmp_path):
    return tmp_path / "benchmarks" / "agent_v1" / "real"

def reviewed(case, app):
    labels = review_template(case)
    labels["review"] = {"status": "reviewed", "reviewer_ids": ["reviewer_1"], "notes": ["Runtime-confirmed endpoint."]}
    labels["gold"]["expected_test_ids"] = ["SESSION_HANDLING"]
    labels["gold"]["allowed_hypothesis_types"] = ["session_behavior_candidate"]
    labels["gold"]["expected_hypothesis_types"] = ["session_behavior_candidate"]
    return apply_review(case, labels, app)

def test_import_canonical_immutable_stable_and_provenance(endpoint, app):
    before = deepcopy(endpoint.to_dict())
    first = build_real_benchmark_case(endpoint, app, scan_reference="scan_001", tags=["resource"])
    second = build_real_benchmark_case(endpoint, app, scan_reference="scan_001", tags=["resource"])
    assert first.to_dict() == second.to_dict()
    assert endpoint.to_dict() == before
    assert first.endpoint_context.evidence_refs == endpoint.evidence_refs
    assert first.source["scan_reference"] == "scan_001"
    assert first.review["status"] == "unreviewed" and first.gold is None
    assert first.tags == ("resource",)

def test_app_metadata_and_stable_split_required(endpoint):
    with pytest.raises(ContractError): build_real_benchmark_case(endpoint, {})
    for kwargs in ({"source_type": "third_party"}, {"split": "holdout"}, {"holdout": True}):
        data = {"app_id": "app_001", "source_type": "owned_app", **kwargs}
        with pytest.raises(ContractError): AppMetadata(**data)

@pytest.mark.parametrize("field,value", [
    ("authorization", "Bearer SYNTHETIC_ONLY"), ("bearer_token_value", "SYNTHETIC_ONLY"),
    ("cookie_value", "SYNTHETIC_ONLY"), ("password_value", "SYNTHETIC_ONLY"),
    ("refresh_token_value", "SYNTHETIC_ONLY"), ("api_key_value", "SYNTHETIC_ONLY"),
    ("raw_request_body", {"username": "alice@example.com"}), ("raw_response_body", {"phone": "+12345678901"}),
    ("filesystem_path", "/Users/example/private.log"), ("raw_logs", "personal log"),
])
def test_raw_values_removed_then_exported_values_rejected(endpoint, app, field, value):
    endpoint.request[field] = value
    endpoint.response[field] = value
    endpoint.auth[field] = value
    case = build_real_benchmark_case(endpoint, app)
    assert field not in case.endpoint_context.request
    assert field not in case.endpoint_context.response
    bad = case.to_dict(); bad["input"]["endpoint_context"]["request"][field] = value
    with pytest.raises(ContractError): parse_real_case(bad, app)

def test_pii_shapes_and_explicit_path_aliasing(endpoint, app):
    endpoint.path = "/users/alice@example.com/123"
    endpoint.request["body_keys"] = ["username", "phone"]
    endpoint.request["body_shapes"] = [{"username": "alice@example.com", "phone": "+12345678901"}]
    case = build_real_benchmark_case(endpoint, app)
    raw = json.dumps(case.to_dict())
    assert "alice@example.com" not in raw and "+12345678901" not in raw
    assert case.endpoint_context.request["body_keys"] == ["phone", "username"]
    assert case.endpoint_context.request["body_shapes"] == [{"phone": "unknown", "username": "unknown"}]
    assert "{" not in case.endpoint_context.path
    endpoint.path = "/users/alice"
    assert "alice" not in build_real_benchmark_case(endpoint, app, sensitive_path_segments=["alice"]).endpoint_context.path

def test_aliases_are_consistent_distinct_and_opt_out(endpoint, app):
    first = build_real_benchmark_case(endpoint, app)
    endpoint.endpoint_context_id = "ctx_other"
    second = build_real_benchmark_case(endpoint, app)
    assert first.endpoint_context.host == second.endpoint_context.host
    assert first.endpoint_context.path == second.endpoint_context.path
    endpoint.host = "admin.private-company.example"
    assert build_real_benchmark_case(endpoint, app).endpoint_context.host != first.endpoint_context.host
    assert build_real_benchmark_case(endpoint, app, alias_hosts=False).endpoint_context.host == endpoint.host

def test_filesystem_identity_rejected(endpoint, app):
    endpoint.path = "/Users/example/private"
    with pytest.raises(ContractError): build_real_benchmark_case(endpoint, app)

def test_review_required_independent_multilabel_gold(endpoint, app):
    case = build_real_benchmark_case(endpoint, app)
    with pytest.raises(ContractError): case.scoring_case()
    bad = case.to_dict(); bad["review"] = {"status": "reviewed", "reviewer_ids": ["reviewer_1"], "notes": []}
    with pytest.raises(ContractError): parse_real_case(bad, app)
    labeled = reviewed(case, app)
    # Human label lacks current path-derived heuristic support and is still valid.
    assert "session_behavior_candidate" not in case.model_input().hypothesis_catalog
    assert labeled.scoring_case().expected["expected_test_ids"] == ["SESSION_HANDLING"]
    labels = review_template(case); labels["review"] = {"status": "reviewed", "reviewer_ids": ["reviewer_1", "reviewer_2"], "notes": []}
    labels["gold"]["allowed_hypothesis_types"] = ["session_behavior_candidate", "input_validation_candidate"]
    labels["gold"]["expected_hypothesis_types"] = ["input_validation_candidate"]
    assert len(apply_review(case, labels, app).gold["allowed_hypothesis_types"]) == 2

@pytest.mark.parametrize("field,value", [
    ("expected_test_ids", ["AI_SMART_HACK"]), ("allowed_hypothesis_types", ["made_up"]),
    ("expected_endpoint_role", "vulnerable"), ("expected_coverage_gaps", ["invented_gap"]),
])
def test_unknown_gold_rejected(endpoint, app, field, value):
    labels = review_template(build_real_benchmark_case(endpoint, app))
    labels["review"] = {"status": "reviewed", "reviewer_ids": ["reviewer_1"], "notes": []}
    labels["gold"][field] = value
    with pytest.raises(ContractError): apply_review(build_real_benchmark_case(endpoint, app), labels, app)

def test_holdout_review_loader_manifest_and_source_file_unchanged(endpoint, app, root, tmp_path):
    source = tmp_path / "endpoint_contexts.json"
    source.write_text(json.dumps(EndpointContextArtifact(endpoints=[endpoint]).to_dict()))
    before = source.read_bytes()
    dev = export_real_app(source, app, root, generated_at=NOW)[0]
    holdout_app = AppMetadata("app_004", "authorized_training_app", "holdout", holdout=True)
    holdout = export_real_app(source, holdout_app, root, generated_at=NOW)[0]
    assert source.read_bytes() == before
    assert load_real_cases(root) == ()
    assert len(load_real_cases(root, reviewed_only=False)) == 1
    assert len(load_real_cases(root, reviewed_only=False, include_holdout=True)) == 2
    for case in (dev, holdout):
        labels = review_template(case); labels["review"] = {"status": "reviewed", "reviewer_ids": ["reviewer_1"], "notes": []}
        save_review(root, labels)
    assert len(load_real_cases(root)) == 1
    assert len(load_real_cases(root, include_holdout=True)) == 2
    manifest = validate_real_dataset(root)
    assert manifest["app_count"] == 2 and manifest["reviewed_case_count"] == 2
    assert manifest["development_case_count"] == manifest["holdout_case_count"] == 1
    labels = review_template(dev); labels["review"]["status"] = "excluded"
    save_review(root, labels)
    assert load_real_cases(root) == ()
    assert len(load_real_cases(root, reviewed_only=False)) == 0
    assert validate_real_dataset(root)["excluded_case_count"] == 1

@pytest.mark.parametrize("status", ["unreviewed", "disputed", "excluded"])
def test_only_reviewed_scoreable(endpoint, app, status):
    data = build_real_benchmark_case(endpoint, app).to_dict(); data["review"]["status"] = status
    with pytest.raises(ContractError): parse_real_case(data, app).scoring_case()

def test_duplicates_missing_metadata_and_manifest_counts(endpoint, app):
    case = build_real_benchmark_case(endpoint, app, tags=["resource", "static_only"])
    with pytest.raises(ContractError): build_manifest([replace(app, case_count=2)], [case, case])
    with pytest.raises(ContractError): build_manifest([], [case])
    manifest = build_manifest([replace(app, case_count=1)], [case], generated_at=NOW)
    assert manifest["category_counts"] == {"resource": 1, "static_only": 1}
    assert manifest["unreviewed_case_count"] == 1

@pytest.mark.parametrize("match,observed,phrase", [
    ("static_only", False, "not observed in available runtime traffic"),
    ("dynamic_only", True, "no matching static candidate"),
])
def test_coverage_and_honest_semantics(endpoint, app, match, observed, phrase):
    endpoint.static["match_type"] = match; endpoint.dynamic["observed"] = observed
    endpoint.visibility["https_visibility"] = "unavailable"
    case = build_real_benchmark_case(endpoint, app, coverage_metadata={"traffic_available": False, "stop_reason": "max_steps"}, tags=[match])
    model = case.model_input().to_dict()
    assert phrase in json.dumps(model["fact_catalog"])
    assert "unused" not in json.dumps(model)
    assert model["visibility"]["https_visibility"] == "unavailable"
    assert {g["kind"] for g in model["coverage"]["gaps"]} >= {"https_visibility_unavailable", "max_steps", "traffic_unavailable"}
    if match == "static_only": assert model["auth_context"]["authorization_header_present"] is None

def test_gold_review_and_holdout_metadata_never_in_model_input(endpoint, app):
    for metadata in (app, AppMetadata("app_004", "owned_app", "holdout", holdout=True)):
        case = reviewed(build_real_benchmark_case(endpoint, metadata), metadata)
        labels = case.to_dict()
        raw = json.dumps(case.model_input().to_dict())
        assert "gold" not in raw and "reviewer_1" not in raw and "holdout" not in raw and "expected_test_ids" not in raw
        labels["gold"]["forbidden_test_ids"] = ["OBJECT_AUTHORIZATION"]
        other = parse_real_case(labels, metadata)
        assert case.model_input().to_dict() == other.model_input().to_dict()

def test_export_boundary_no_overwrite_no_source_product_network_execution(endpoint, app, root, monkeypatch):
    def forbidden(*args, **kwargs): raise AssertionError("No network/process execution")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    source = EndpointContextArtifact(endpoints=[endpoint])
    before = deepcopy(source.to_dict())
    export_real_app(source, app, root, generated_at=NOW)
    with pytest.raises(ContractError): export_real_app(source, app, root)
    with pytest.raises(ContractError): export_real_app(source, app, root.parent / "demo_runs")
    assert source.to_dict() == before
    assert not list(root.rglob("agent_report.json"))
    assert not list(root.rglob("scan_state.json"))
    module = Path("src/agent/evaluation/real_dataset.py").read_text()
    assert "AgentModelClient" not in module and "run_agent_benchmark(" not in module

def test_tampered_manifest_split_unsafe_fields_and_atomic_failure(endpoint, app, root, monkeypatch):
    case = export_real_app(EndpointContextArtifact(endpoints=[endpoint]), app, root, generated_at=NOW)[0]
    manifest_path = root / "manifest.json"; manifest = json.loads(manifest_path.read_text())
    manifest["case_count"] = 99; manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ContractError): validate_real_dataset(root)
    data = case.to_dict(); data["source"].pop("split")
    with pytest.raises(ContractError): parse_real_case(data, app)
    with pytest.raises(ContractError): validate_real_safety({"raw_response_body": {}})
    path = root / "safe.json"; path.write_text('{"old":true}')
    original = path.read_bytes()
    def failed(*args): raise OSError("replacement failed")
    monkeypatch.setattr(Path, "replace", failed)
    with pytest.raises(OSError): _atomic(path, {"safe": True})
    assert path.read_bytes() == original

def test_credential_parameter_names_are_structural_not_values(endpoint, app):
    endpoint.request["body_keys"] = ["username", "password", "refresh_token"]
    endpoint.request["body_shapes"] = [{"username": "string", "password": "string", "refresh_token": "string"}]
    case = build_real_benchmark_case(endpoint, app)
    assert case.endpoint_context.request["body_shapes"][0]["password"] == "string"
    data = case.to_dict()
    data["input"]["endpoint_context"]["request"]["body_shapes"][0]["password"] = "personal_password"
    with pytest.raises(ContractError): parse_real_case(data, app)

def test_symlink_escape_rejected_without_writing(endpoint, app, root, tmp_path):
    root.mkdir(parents=True); outside = tmp_path / "elsewhere"; outside.mkdir()
    (root / "apps").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ContractError): export_real_app(EndpointContextArtifact(endpoints=[endpoint]), app, root)
    assert not list(outside.iterdir())

def test_invalid_fields_tags_and_contradictions(endpoint, app):
    case = build_real_benchmark_case(endpoint, app)
    for field, value in (("tags", ["invented"]), ("input", {"gold": {}})):
        data = case.to_dict(); data[field] = value
        with pytest.raises(ContractError): parse_real_case(data, app)
    labels = review_template(case)
    labels["gold"]["expected_test_ids"] = ["SESSION_HANDLING"]
    labels["gold"]["forbidden_test_ids"] = ["SESSION_HANDLING"]
    with pytest.raises(ContractError): apply_review(case, labels, app)

def test_snapshot_fingerprint_changes_with_labels_not_export_time(endpoint, app):
    case = build_real_benchmark_case(endpoint, app)
    metadata = replace(app, case_count=1)
    first = build_manifest([metadata], [case], generated_at=NOW)
    later = build_manifest([metadata], [case], generated_at="2026-10-02T12:00:00Z")
    assert first["dataset_fingerprint"] == later["dataset_fingerprint"]
    labeled = reviewed(case, app)
    second = build_manifest([replace(metadata, human_review_status="reviewed")], [labeled], generated_at=NOW)
    assert first["dataset_fingerprint"] != second["dataset_fingerprint"]
