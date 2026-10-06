"""Offline runtime/schema/retry/persistence tests; no live provider or active testing."""
import ast
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.agent.context_analyst import analyze_endpoint_context, analyze_endpoint_contexts
from src.agent.context_analyst.models import ContextAnalystResult, PROMPT_VERSION
from src.agent.context_analyst.persistence import load_context_analyses, save_context_analyses
from src.agent.context_analyst.prompts import INSTRUCTION, RETRY_CORRECTION
from src.agent.models import AgentObservation, ContractError, CoverageGap
from src.scan_state import create_initial_scan_state, save_scan_state, load_scan_state
from tests.context_analyst_fakes import FakeModelClient, TIME
from tests.test_context_analyst_input import endpoint


def run(endpoint, client=None, **kwargs):
    return analyze_endpoint_context(endpoint, client or FakeModelClient(), created_at=TIME, **kwargs)


def test_valid_observation_hypothesis_and_prompt_version(endpoint):
    client = FakeModelClient()
    result = run(endpoint, client)
    assert result.status == "completed" and isinstance(result.observation, AgentObservation)
    assert result.prompt_version == PROMPT_VERSION == "context_analyst_v1"
    assert result.endpoint_role == "resource_endpoint"
    object_hyp = next(h for h in result.hypotheses if h.hypothesis_type == "object_authorization_candidate")
    assert object_hyp.status == "hypothesis" and object_hyp.evidence_refs
    assert "ownership is unknown" in " ".join(result.observation.facts)
    assert result.model_metadata.provider == "fake"
    assert client.requests[0].output_schema["additionalProperties"] is False
    assert ContextAnalystResult.from_dict(result.to_dict()) == result


def test_coverage_gaps_preserved_and_linked(endpoint):
    endpoint.visibility["https_visibility"] = "unavailable"
    result = run(endpoint, coverage_metadata={"traffic_available": False, "stop_reason": "max_steps"})
    assert result.status == "completed"
    assert all(isinstance(g, CoverageGap) for g in result.coverage_gaps)
    assert {"https_visibility_unavailable", "traffic_unavailable", "max_steps"} <= {g.kind for g in result.coverage_gaps}
    assert set(result.observation.coverage_gaps) == {g.gap_id for g in result.coverage_gaps}


@pytest.mark.parametrize("field", ["severity", "finding", "is_vulnerable", "risk_score", "cvss", "confirmed_vulnerability",
    "exploit", "poc", "test_id", "requested_action", "allowed_mutations", "auto_execute", "test_plan",
    "tool_name", "tool_args", "tool_calls", "chain_of_thought", "unexpected"])
@pytest.mark.parametrize("location", ["root", "observation", "hypothesis"])
def test_unauthorized_fields_rejected_at_every_level(endpoint, field, location):
    def transform(data, request):
        target = data if location == "root" else data["observation"] if location == "observation" else data["hypotheses"][0]
        target[field] = "FORBIDDEN_SECRET"
        return data
    result = run(endpoint, FakeModelClient(transform))
    assert result.status == "invalid_output" and result.attempts == 2
    assert result.observation is None and not result.hypotheses
    assert "FORBIDDEN_SECRET" not in json.dumps(result.to_dict())


@pytest.mark.parametrize("mutation", ["missing_refs", "unknown_type", "fake_ref", "wrong_endpoint", "wrong_observation_endpoint",
    "wrong_hypothesis_endpoint", "wrong_state", "invalid_state", "false_fact", "unsafe_statement", "missing_precondition", "unsupported_role"])
def test_hallucinations_and_invalid_semantics_rejected(endpoint, mutation):
    def transform(data, request):
        h = data["hypotheses"][0]
        if mutation == "missing_refs": h["evidence_refs"] = []
        elif mutation == "unknown_type": h["hypothesis_type"] = "arbitrary_type"
        elif mutation == "fake_ref": h["evidence_refs"].append("dynamic/traffic.json#transaction_id=tx_fake_999")
        elif mutation == "wrong_endpoint": data["endpoint_context_id"] = "ctx_wrong"
        elif mutation == "wrong_observation_endpoint": data["observation"]["endpoint_context_id"] = "ctx_wrong"
        elif mutation == "wrong_hypothesis_endpoint": h["endpoint_context_id"] = "ctx_wrong"
        elif mutation == "wrong_state": h["status"] = "planned"
        elif mutation == "invalid_state": h["status"] = "confirmed"
        elif mutation == "false_fact": data["observation"]["facts"].append("HTTP 200 proves this endpoint is secure.")
        elif mutation == "unsafe_statement": h["statement"] = "The endpoint has BOLA. Run an attack."
        elif mutation == "missing_precondition": h["required_evidence"] = []
        elif mutation == "unsupported_role": data["endpoint_role"] = "collection_endpoint"
        return data
    result = run(endpoint, FakeModelClient(transform))
    assert result.status == "invalid_output" and not result.hypotheses
    assert result.attempts == 2


def test_missing_known_gap_and_unknown_semantics_cannot_be_erased(endpoint):
    endpoint.auth = {}
    def erase(data, request):
        data["coverage_gaps"] = []
        data["observation"]["coverage_gaps"] = []
        return data
    assert run(endpoint, FakeModelClient(erase)).status == "invalid_output"
    result = run(endpoint)
    assert result.status == "completed"
    assert any("cookie_present: unknown" in f for f in result.observation.facts)


def test_role_unknown_is_valid_and_not_forced(endpoint):
    def unknown(data, request):
        data["endpoint_role"] = "unknown"; data["hypotheses"] = []
        return data
    assert run(endpoint, FakeModelClient(unknown)).endpoint_role == "unknown"


def test_output_order_is_normalized_deterministically(endpoint):
    first = run(endpoint)
    def reorder(data, request):
        data["hypotheses"].reverse(); data["coverage_gaps"].reverse(); data["observation"]["facts"].reverse()
        data["observation"]["coverage_gaps"].reverse()
        for h in data["hypotheses"]: h["required_evidence"].reverse()
        return data
    assert run(endpoint, FakeModelClient(reorder)).to_dict() == first.to_dict()


def test_schema_invalid_retries_once_without_echoing_content(endpoint):
    def repair(data, request):
        if request.attempt == 1: return {"raw_reasoning": "REJECTED_SECRET"}
        return data
    client = FakeModelClient(repair)
    result = run(endpoint, client)
    assert result.status == "completed" and result.attempts == 2
    assert len(client.requests) == 2
    assert client.requests[1].correction == RETRY_CORRECTION
    assert "REJECTED_SECRET" not in str(client.requests[1])
    assert result.validation_errors == ("SCHEMA_INVALID",)


def test_invalid_output_at_most_two_attempts(endpoint):
    client = FakeModelClient(lambda data, request: "prose, not JSON")
    result = run(endpoint, client)
    assert result.status == "invalid_output" and len(client.requests) == 2
    client = FakeModelClient(lambda data, request: {})
    assert run(endpoint, client, max_attempts=1).attempts == 1
    assert len(client.requests) == 1
    with pytest.raises(ValueError): run(endpoint, max_attempts=3)


def test_model_error_and_invalid_input_do_not_fabricate_results(endpoint):
    client = FakeModelClient(error=RuntimeError("Authorization: MODEL_SECRET"))
    result = run(endpoint, client)
    assert result.status == "model_error" and result.attempts == 1
    assert result.observation is None and not result.hypotheses and not result.coverage_gaps
    assert "MODEL_SECRET" not in json.dumps(result.to_dict())
    client = FakeModelClient()
    endpoint.endpoint_context_id = ""
    result = run(endpoint, client)
    assert result.status == "input_invalid" and result.attempts == 0
    assert not client.requests


@pytest.mark.parametrize("invalid", [None, "raw endpoint", {}, {"endpoint_context_id": "ctx_1"}])
def test_noncanonical_input_fails_before_model_call(invalid):
    client = FakeModelClient()
    result = run(invalid, client)
    assert result.status == "input_invalid" and not client.requests


def test_model_request_is_detached_from_evidence(endpoint):
    before = deepcopy(endpoint)
    def mutate(data, request):
        request.input_data["endpoint"]["path"] = "/changed"
        request.input_data["auth_context"]["cookie_present"] = False
        return data
    assert run(endpoint, FakeModelClient(mutate)).status == "completed"
    assert endpoint == before


def test_model_json_output_is_supported_and_bounded(endpoint):
    assert run(endpoint, FakeModelClient(lambda data, request: json.dumps(data))).status == "completed"
    assert run(endpoint, FakeModelClient(lambda data, request: "X" * 32769)).status == "invalid_output"


def test_batch_is_bounded_sorted_and_isolates_failures(endpoint):
    other = replace(endpoint, endpoint_context_id="ctx_2", path="/users/2")
    def fail_one(data, request):
        return {} if request.input_data["endpoint_context_id"] == "ctx_2" else data
    result = analyze_endpoint_contexts([other, endpoint], FakeModelClient(fail_one), created_at=TIME)
    assert [r.endpoint_context_id for r in result] == ["ctx_1", "ctx_2"]
    assert [r.status for r in result] == ["completed", "invalid_output"]
    with pytest.raises(ContractError): analyze_endpoint_contexts([other, endpoint], FakeModelClient(), max_endpoints=1)
    with pytest.raises(ContractError): analyze_endpoint_contexts([endpoint, endpoint], FakeModelClient())


def test_atomic_persistence_sorted_merges_successes_preserves_stage(tmp_path, endpoint):
    state = create_initial_scan_state("run_test", "https://example.com/app.apk")
    save_scan_state(tmp_path, state)
    state_bytes = (tmp_path / "scan_state.json").read_bytes()
    first = run(endpoint)
    other = run(replace(endpoint, endpoint_context_id="ctx_2"))
    target = save_context_analyses(tmp_path, [other, first])
    assert target == tmp_path / "agent" / "context_analysis.json"
    assert [r.endpoint_context_id for r in load_context_analyses(tmp_path)] == ["ctx_1", "ctx_2"]
    previous = target.read_bytes()
    failure = run(replace(endpoint, endpoint_context_id="ctx_2"), FakeModelClient(lambda d, r: {}))
    save_context_analyses(tmp_path, [failure])
    assert target.read_bytes() == previous
    assert not list(target.parent.glob(".tmp*"))
    assert not (tmp_path / "agent_report.json").exists()
    assert (tmp_path / "scan_state.json").read_bytes() == state_bytes
    assert load_scan_state(tmp_path)["stages"]["agent_analysis"]["status"] == "not_available"
    assert load_scan_state(tmp_path)["artifacts"]["agent_report"]["available"] is False


def test_failed_atomic_replace_preserves_existing_artifact(tmp_path, endpoint):
    target = save_context_analyses(tmp_path, [run(endpoint)])
    previous = target.read_bytes()
    with patch("src.agent.context_analyst.persistence.os.replace", side_effect=OSError("disk unavailable")):
        with pytest.raises(OSError): save_context_analyses(tmp_path, [run(replace(endpoint, endpoint_context_id="ctx_2"))])
    assert target.read_bytes() == previous and not list(target.parent.glob(".tmp*"))


def test_corrupt_existing_artifact_not_silently_overwritten(tmp_path, endpoint):
    target = tmp_path / "agent" / "context_analysis.json"; target.parent.mkdir()
    target.write_text("{corrupt")
    with pytest.raises(ContractError): save_context_analyses(tmp_path, [run(endpoint)])
    assert target.read_text() == "{corrupt"


def test_failure_only_does_not_create_artifact(tmp_path, endpoint):
    failure = run(endpoint, FakeModelClient(lambda d, r: {}))
    assert save_context_analyses(tmp_path, [failure]) is None
    assert list(tmp_path.iterdir()) == []


def test_product_safe_trace_contains_ids_not_reasoning(endpoint):
    result = run(endpoint)
    assert result.trace["input_evidence_refs"]
    assert result.trace["observation_id"] == result.observation.observation_id
    assert result.trace["hypothesis_ids"] == [h.hypothesis_id for h in result.hypotheses]
    assert "chain_of_thought" not in result.trace and "reasoning" not in result.trace


def test_prompt_has_read_only_boundaries():
    for phrase in ("Only use supplied evidence", "Unknown facts remain unknown", "Do not create TestProposal",
        "Do not select security tests", "Do not recommend", "Do not infer vulnerability from status codes",
        "Do not infer authentication", "Do not infer authorization", "private chain-of-thought", "hypotheses, never findings"):
        assert phrase in INSTRUCTION
    assert PROMPT_VERSION in INSTRUCTION


def test_no_tools_policy_planner_or_network_execution(endpoint, monkeypatch):
    import socket
    import urllib.request
    def forbidden(*args, **kwargs): raise AssertionError("Forbidden execution")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    with patch("src.agent.policy.evaluate_proposal", side_effect=forbidden), patch("src.agent.models.TestProposal.__init__", side_effect=forbidden):
        assert run(endpoint).status == "completed"
    root = Path(__file__).resolve().parents[1] / "src" / "agent" / "context_analyst"
    forbidden_imports = {"openai", "anthropic", "google", "requests", "httpx", "urllib", "socket", "subprocess", "aiohttp"}
    for path in root.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import): assert not {a.name.split(".")[0] for a in node.names} & forbidden_imports
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in forbidden_imports
                assert node.module != "src.agent.policy"
    assert not list(root.glob("*executor*")) and not list(root.glob("*planner*"))


def test_duplicate_json_keys_and_oversized_structures_rejected(endpoint):
    client = FakeModelClient(lambda d, r: '{"schema_version":"1.0","schema_version":"1.0"}')
    result = run(endpoint, client)
    assert result.status == "invalid_output" and result.validation_errors == ("OUTPUT_DUPLICATE_KEY",) * 2
    result = run(endpoint, FakeModelClient(lambda d, r: {str(i): "value" for i in range(1000)}))
    assert result.status == "invalid_output" and result.validation_errors == ("OUTPUT_ITEMS_EXCEEDED",) * 2


def test_authentication_correctness_and_no_crash_claims_are_not_accepted(endpoint):
    def claim(data, request):
        data["observation"]["facts"][0] = "Authenticated securely; no crash exists."
        return data
    assert run(endpoint, FakeModelClient(claim)).status == "invalid_output"


def test_missing_fact_cannot_hide_method_mismatch(endpoint):
    endpoint.static["match_type"] = "method_mismatch"; endpoint.dynamic["observed_methods"] = ["POST"]
    endpoint.methods = ["GET", "POST"]
    def hide(data, request):
        data["observation"]["facts"] = [f for f in data["observation"]["facts"] if not f.startswith("Static method:")]
        return data
    assert run(endpoint, FakeModelClient(hide)).status == "invalid_output"


def test_model_attempt_cannot_extend_input_evidence_universe(endpoint):
    def inject(data, request):
        fake = "dynamic/traffic.json#transaction_id=tx_fake_999"
        request.input_data["evidence_refs"]["transactions"].append(fake)
        data["observation"]["evidence_refs"].append(fake)
        return data
    assert run(endpoint, FakeModelClient(inject)).status == "invalid_output"


def test_missing_initial_status_is_rejected(endpoint):
    def missing(data, request):
        data["hypotheses"][0].pop("status")
        return data
    assert run(endpoint, FakeModelClient(missing)).status == "invalid_output"


def semantic_output(data, request):
    for h in data['hypotheses']:
        for key in ('hypothesis_id', 'endpoint_context_id', 'status'):
            h.pop(key)
    return data


def test_runtime_owns_hypothesis_identity_state_and_does_not_mutate_reply(endpoint):
    from src.agent.context_analyst.validation import record_id
    captured={}
    def capture(data,request):
        semantic_output(data,request)
        captured['data']=data
        captured['before']=deepcopy(data)
        return data
    client=FakeModelClient(capture)
    result=run(endpoint,client)
    assert captured['data']==captured['before']
    assert result.status=='completed' and result.hypotheses
    schema=client.requests[0].output_schema
    assert set(schema['properties'])=={'schema_version','endpoint_context_id','endpoint_role','concerns'}
    assert set(schema['required'])==set(schema['properties'])
    for h in result.hypotheses:
        assert h.hypothesis_id==record_id('hyp',endpoint.endpoint_context_id+h.hypothesis_type)
        assert h.endpoint_context_id==endpoint.endpoint_context_id and h.status=='hypothesis'
    assert result.hypotheses==run(endpoint,FakeModelClient(semantic_output)).hypotheses


@pytest.mark.parametrize('mutation', ['statement','required','reference','endpoint','type','forbidden','duplicate'])
def test_runtime_identity_binding_never_repairs_semantic_errors(endpoint, mutation):
    def transform(data, request):
        semantic_output(data,request)
        h=data['hypotheses'][0]
        if mutation=='statement': h['statement']='Unsupported semantic claim'
        if mutation=='required': h['required_evidence']=[]
        if mutation=='reference': h['evidence_refs'].append('dynamic/traffic.json#transaction_id=tx_invented')
        if mutation=='endpoint': data['endpoint_context_id']='ctx_wrong'
        if mutation=='type': h['hypothesis_type']='invented_type'
        if mutation=='forbidden': h['finding']=True
        if mutation=='duplicate': data['hypotheses'].append(deepcopy(h))
        return data
    result=run(endpoint,FakeModelClient(transform))
    assert result.status=='invalid_output' and result.attempts==2 and not result.hypotheses


@pytest.mark.parametrize('field,value,code', [
    ('hypothesis_id','hyp_wrong','HYPOTHESIS_ID_INVALID'),
    ('status','planned','HYPOTHESIS_STATE_INVALID'),
    ('endpoint_context_id','ctx_other','ENDPOINT_MISMATCH')])
def test_explicit_legacy_identity_errors_are_distinguished_not_overwritten(endpoint,field,value,code):
    def transform(data,request):
        data['hypotheses'][0][field]=value
        return data
    result=run(endpoint,FakeModelClient(transform))
    assert result.status=='invalid_output' and code in result.validation_errors
