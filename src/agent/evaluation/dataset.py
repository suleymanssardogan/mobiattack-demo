"""Strict deterministic synthetic dataset loader; no scan evidence ingestion."""
from dataclasses import fields
import json
from pathlib import Path
import re
from src.agent.models import ContractError, CoverageGap, identifier, text
from src.agent.context_analyst.models import HYPOTHESIS_TYPES, ENDPOINT_ROLES
from src.agent.context_analyst.input_builder import build_context_analyst_input
from src.agent.context_analyst.validation import _unique_object
from src.agent.test_catalog import TEST_CATALOG
from src.dynamic.context.models import EndpointContext
from .models import BenchmarkCase, BenchmarkDataset, BENCHMARK_VERSION
from .privacy import validate_privacy

DEFAULT_DATASET = Path(__file__).resolve().parents[3] / "benchmarks/agent_v1"
EXPECTED_FIELDS = {"allowed_hypothesis_types", "expected_hypothesis_types", "forbidden_hypothesis_types",
    "expected_test_ids", "forbidden_test_ids", "expected_coverage_gaps", "expected_endpoint_role",
    "unknown_fields", "expected_policy_outcomes", "must_not_emit_finding"}


def _read(path):
    with path.open("rb") as handle: raw = handle.read(32769)
    if len(raw) > 32768: raise ContractError("Benchmark fixture exceeds bound")
    try: return json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, TypeError) as exc: raise ContractError("Invalid benchmark JSON") from exc


def parse_case(data):
    validate_privacy(data)
    expected_keys = {"case_id", "category", "description", "endpoint_context", "expected", "coverage_metadata", "precondition_names"}
    if not isinstance(data, dict) or set(data) != expected_keys:
        raise ContractError("Invalid benchmark case fields")
    for key in ("case_id", "category"): identifier(data[key], key)
    text(data["description"], "description")
    endpoint = data["endpoint_context"]
    if not isinstance(endpoint, dict) or set(endpoint) - {f.name for f in fields(EndpointContext)}:
        raise ContractError("Invalid benchmark EndpointContext")
    try: context = EndpointContext(**endpoint)
    except (ValueError, TypeError) as exc: raise ContractError("Invalid benchmark endpoint") from exc
    # The fixture boundary is an allowlist of sanitized fields, not merely a denylist.
    allowed = {
        "static": {"match_type", "confidence", "static_method", "static_candidate_id", "static_candidate_id_origin"},
        "dynamic": {"observed", "observed_methods", "available_transaction_count", "missing_transaction_ids"},
        "request": {"header_names", "query_keys", "body_keys", "body_present", "body_shapes"},
        "response": {"observed_status_codes", "content_types", "body_present", "body_shapes"},
        "auth": {"authorization_header_present", "bearer_token_present", "cookie_present", "session_cookie_present", "api_key_header_present"},
        "runtime_context": {"evidence_available", "activity_changes_observed"},
        "visibility": {"http_visibility", "https_visibility"},
        "evidence_refs": {"transaction_ids", "correlation_ids", "static_candidate_ids", "action_ids", "runtime_action_ids"}}
    for name, keys in allowed.items():
        value = getattr(context, name)
        if not isinstance(value, dict) or set(value) - keys: raise ContractError("Unsafe endpoint field")
    presence = list(context.auth.values()) + list(context.runtime_context.values()) + [context.dynamic.get("observed"), context.request.get("body_present"), context.response.get("body_present")]
    if any(value is not None and type(value) is not bool for value in presence):
        raise ContractError("Presence metadata must be boolean or unknown, never raw values")
    count = context.dynamic.get("available_transaction_count")
    if count is not None and (type(count) is not int or count < 0):
        raise ContractError("Invalid transaction count")
    if context.action_context or context.route_context:
        raise ContractError("Benchmark fixtures do not accept raw action/route records")
    if context.host != "api.example.com": raise ContractError("Synthetic benchmark host required")
    if not isinstance(data["coverage_metadata"], dict) or set(data["coverage_metadata"]) - {"traffic_available", "stop_reason", "input_action_skipped", "external_package_boundary", "system_ui_boundary"}:
        raise ContractError("Invalid benchmark coverage")
    def shape(value):
        if isinstance(value, dict): return all(isinstance(k, str) and shape(v) for k, v in value.items())
        if isinstance(value, list): return len(value) <= 1 and all(shape(v) for v in value)
        return value is None or isinstance(value, str) and value in {"string", "number", "integer", "boolean", "null", "unknown", "object", "array"}
    for message in (context.request, context.response):
        if not isinstance(message.get("body_shapes", []), list) or not all(shape(v) for v in message.get("body_shapes", [])):
            raise ContractError("Benchmark accepts type-only body shapes")
    source = build_context_analyst_input(context, coverage_metadata=data["coverage_metadata"])
    gold = data["expected"]
    if not isinstance(gold, dict) or set(gold) != EXPECTED_FIELDS: raise ContractError("Invalid gold expectation fields")
    domains = {"allowed_hypothesis_types": HYPOTHESIS_TYPES, "expected_hypothesis_types": HYPOTHESIS_TYPES,
               "forbidden_hypothesis_types": HYPOTHESIS_TYPES, "expected_test_ids": TEST_CATALOG,
               "forbidden_test_ids": TEST_CATALOG}
    for name, domain in domains.items():
        values = gold[name]
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values) or len(values) != len(set(values)) or any(v not in domain for v in values):
            raise ContractError("Invalid gold enum list")
    if (not set(gold["expected_hypothesis_types"]).issubset(gold["allowed_hypothesis_types"])
            or set(gold["allowed_hypothesis_types"]) & set(gold["forbidden_hypothesis_types"])
            or set(gold["expected_test_ids"]) & set(gold["forbidden_test_ids"])):
        raise ContractError("Contradictory gold expectations")
    if not set(gold["expected_hypothesis_types"]).issubset(source.hypothesis_catalog):
        raise ContractError("Gold hypotheses lack endpoint support")
    if gold["expected_endpoint_role"] not in source.supported_roles:
        raise ContractError("Gold role lacks endpoint support")
    if gold["expected_endpoint_role"] not in ENDPOINT_ROLES or gold["must_not_emit_finding"] is not True:
        raise ContractError("Invalid gold role/boundary")
    if not isinstance(gold["expected_coverage_gaps"], list) or not set(gold["expected_coverage_gaps"]).issubset({d["kind"] for d in source.coverage["gaps"]}):
        raise ContractError("Invalid expected coverage gaps")
    if not isinstance(gold["unknown_fields"], list): raise ContractError("Invalid expected unknown fields")
    for dotted in gold["unknown_fields"]:
        value = source.to_dict()
        for key in dotted.split("."):
            if not isinstance(value, dict) or key not in value: raise ContractError("Unknown gold field path")
            value = value[key]
        if value is not None: raise ContractError("Gold unknown field must actually be unknown")
    policy = gold["expected_policy_outcomes"]
    if (not isinstance(policy, dict) or any(t not in gold["expected_test_ids"] or d not in {"allow", "deny", "needs_evidence"} for t, d in policy.items())):
        raise ContractError("Invalid gold policy outcomes")
    names = data["precondition_names"]
    if not isinstance(names, list) or len(names) > 16 or any(not isinstance(v, str) for v in names) or len(set(names)) != len(names): raise ContractError("Invalid fixture preconditions")
    for name in names: text(name, "precondition name")
    return BenchmarkCase(data["case_id"], data["category"], data["description"], context, gold,
                         data["coverage_metadata"], tuple(sorted(names)))


def load_dataset(root=DEFAULT_DATASET):
    root = Path(root).resolve(); manifest = _read(root / "manifest.json")
    if (not isinstance(manifest, dict) or set(manifest) != {"schema_version", "benchmark_version", "cases"}
            or manifest["schema_version"] != "1.0" or manifest["benchmark_version"] != BENCHMARK_VERSION
            or not isinstance(manifest["cases"], list) or not 1 <= len(manifest["cases"]) <= 64):
        raise ContractError("Invalid benchmark manifest")
    names = manifest["cases"]
    if any(not isinstance(v, str) for v in names): raise ContractError("Invalid benchmark fixture name")
    if len(names) != len(set(names)): raise ContractError("Duplicate benchmark fixture")
    cases = []
    for name in sorted(names):
        if not isinstance(name, str) or not re.fullmatch(r"case_[0-9]{3}\.json", name): raise ContractError("Unsafe fixture filename")
        path = root / "cases" / name
        if not path.resolve().is_relative_to(root): raise ContractError("Fixture escapes dataset")
        case = parse_case(_read(path))
        if case.case_id != path.stem: raise ContractError("Case/file identity mismatch")
        cases.append(case)
    return BenchmarkDataset(BENCHMARK_VERSION, tuple(cases))
