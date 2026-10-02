"""Passive real pilot import and human review; no models, scanners or executors.

Canonical EndpointContext is reused. Generated candidates never contain gold.
"""
from __future__ import annotations
import argparse
from collections import Counter
from copy import deepcopy
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import tempfile

from src.agent.models import ContractError, identifier, timestamp
from src.agent.context_analyst.input_builder import build_context_analyst_input
from src.agent.context_analyst.models import ENDPOINT_ROLES, HYPOTHESIS_TYPES
from src.agent.test_catalog import TEST_CATALOG
from src.dynamic.context.models import EndpointContext, EndpointContextArtifact
from .dataset import EXPECTED_FIELDS, _read
from .models import BenchmarkCase, BENCHMARK_VERSION
from .privacy import validate_privacy

REAL_VERSION = "real_pilot_v1"
DEFAULT_REAL_ROOT = Path(__file__).resolve().parents[3] / "benchmarks/agent_v1/real"
SOURCE_TYPES = frozenset({"owned_app", "authorized_training_app", "authorized_open_source_app", "explicitly_authorized_app"})
REVIEW_STATUSES = frozenset({"unreviewed", "reviewed", "disputed", "excluded"})
TAGS = frozenset({"authentication", "session", "resource", "object_access", "input", "query", "body",
                  "static_only", "dynamic_only", "visibility_limited", "method_mismatch", "no_relevant_test", "unknown"})
EXTRA_UNSAFE = frozenset({"bearer_token_value", "password_value", "cookie_value", "refresh_token_value",
                         "api_key_value", "raw_request_body", "raw_response_body", "raw_request", "raw_response"})
_PII = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|(?<!\w)(?:\+?\d[\d ()-]{7,}\d)(?!\w)")
_REF_FIELDS = ("transaction_ids", "correlation_ids", "static_candidate_ids", "action_ids", "runtime_action_ids")
_SAFE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$-]{0,127}$")
_TYPES = frozenset({"string", "integer", "number", "boolean", "null", "unknown", "object", "array", "binary"})


def validate_real_safety(data):
    # Structural shape keys may be credential names; their values must be types.
    # The generic privacy validator otherwise mistakes a password *key* for a value.
    checked = deepcopy(data)
    def hide_shapes(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "body_shapes":
                    if not isinstance(child, list) or child != [_shape(v) for v in child]:
                        raise ContractError("Only type shapes allowed")
                    def shape_names(node):
                        if isinstance(node, dict):
                            for name, item in node.items():
                                validate_privacy(name)
                                if _PII.search(name): raise ContractError("Personal shape key")
                                shape_names(item)
                        elif isinstance(node, list):
                            for item in node: shape_names(item)
                    shape_names(child)
                    value[key] = []
                else: hide_shapes(child)
        elif isinstance(value, (list, tuple)):
            for child in value: hide_shapes(child)
    hide_shapes(checked)
    validate_privacy(checked)
    def visit(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() in EXTRA_UNSAFE: raise ContractError("Unsafe real benchmark field")
                visit(child)
        elif isinstance(value, (list, tuple)):
            for child in value: visit(child)
        elif isinstance(value, str) and _PII.search(value):
            raise ContractError("Personal value in real benchmark")
    visit(checked)


def _digest(value):
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _alias(app_id, value, kind):
    """App-scoped deterministic aliases; never export raw reverse mappings."""
    return f"{kind}_{_digest(app_id + ':' + kind + ':' + value)}"


@dataclass(frozen=True)
class AppMetadata:
    app_id: str
    source_type: str
    split: str = "development"
    platform: str = "android"
    holdout: bool = False
    case_count: int = 0
    sanitized: bool = True
    human_review_status: str = "unreviewed"

    def __post_init__(self):
        if not isinstance(self.app_id, str) or not re.fullmatch(r"app_[A-Za-z0-9_]{1,32}", self.app_id): raise ContractError("Invalid app ID")
        if not isinstance(self.source_type, str) or self.source_type not in SOURCE_TYPES or self.platform != "android": raise ContractError("Authorized app metadata required")
        if not isinstance(self.split, str) or self.split not in {"development", "holdout"} or type(self.holdout) is not bool or self.holdout != (self.split == "holdout"):
            raise ContractError("Explicit stable app split required")
        if type(self.case_count) is not int or self.case_count < 0 or self.sanitized is not True or not isinstance(self.human_review_status, str) or self.human_review_status not in REVIEW_STATUSES:
            raise ContractError("Invalid app metadata")

    def to_dict(self): return asdict(self)


def _names(values):
    if not isinstance(values, list) or len(values) > 256: raise ContractError("Invalid structural names")
    return sorted({v for v in values if isinstance(v, str) and _SAFE_NAME.fullmatch(v) and not _PII.search(v)})[:32]


def _shape(value, depth=0):
    if depth > 3: return "unknown"
    if isinstance(value, dict): return {k: _shape(value[k], depth + 1) for k in _names(list(value))}
    if isinstance(value, list): return [_shape(value[0], depth + 1)] if value else []
    return value if isinstance(value, str) and value in _TYPES else "unknown"


def sanitize_endpoint(context, app, *, alias_hosts=True, sensitive_path_segments=()):
    if not isinstance(context, EndpointContext) or not isinstance(app, AppMetadata): raise ContractError("Canonical context and app metadata required")
    if type(alias_hosts) is not bool: raise ContractError("Invalid alias option")
    identifier(context.endpoint_context_id, "endpoint_context_id")
    if not isinstance(context.path, str) or not context.path.startswith("/") or len(context.path) > 512: raise ContractError("Invalid source path")
    validate_privacy({"path": context.path})  # Filesystem paths are not endpoints.
    if ".." in context.path.split("/"): raise ContractError("Invalid source path")
    if not isinstance(context.host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", context.host): raise ContractError("Invalid source host")
    sensitive = set(sensitive_path_segments)
    if any(not isinstance(v, str) or not v or '/' in v for v in sensitive): raise ContractError("Invalid sensitive path segments")
    segments = []
    for part in context.path.split("?")[0].split("/"):
        personal = bool(_PII.search(part)) or bool(re.fullmatch(r"\d+|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", part))
        # Concrete resource aliases stay literal, never turn them into templates.
        segments.append(_alias(app.app_id, part, "resource") if part in sensitive or personal else part)
    path = '/'.join(segments)
    host = f"host-{_digest(app.app_id + ':' + context.host)}.{app.app_id.replace('_', '')}.local" if alias_hosts else context.host
    e = EndpointContext(context.endpoint_context_id, host, path, scheme=context.scheme if isinstance(context.scheme, str) and context.scheme in {"http", "https"} else None, methods=deepcopy(context.methods))
    def mapping(value): return value if isinstance(value, dict) else {}
    e.static = {k: deepcopy(v) for k, v in mapping(context.static).items() if k in {
        "match_type", "confidence", "static_method", "static_candidate_id", "static_candidate_id_origin", "static_candidate_id_source_field"}}
    e.dynamic = {k: deepcopy(v) for k, v in mapping(context.dynamic).items() if k in {
        "observed", "observed_methods", "available_transaction_count", "missing_transaction_ids"}}
    for name, keys in (("request", {"header_names", "query_keys", "body_keys", "body_present", "body_shapes", "body_types", "content_types"}),
                       ("response", {"header_names", "body_keys", "body_present", "body_shapes", "body_types", "content_types", "observed_status_codes"})):
        raw = mapping(getattr(context, name)); out = {}
        for key in keys:
            if key not in raw: continue
            if key in {"header_names", "query_keys", "body_keys"}: out[key] = _names(raw[key])
            elif key == "body_shapes":
                if not isinstance(raw[key], list) or len(raw[key]) > 32: raise ContractError("Invalid shapes")
                out[key] = [_shape(v) for v in raw[key]]
            elif key == "body_present": out[key] = raw[key] if type(raw[key]) is bool else None
            else: out[key] = deepcopy(raw[key])
        setattr(e, name, out)
    e.auth = {key: v if type(v) is bool else None for key, v in mapping(context.auth).items() if key in {
        "authorization_header_present", "bearer_token_present", "cookie_present", "session_cookie_present", "api_key_header_present"}}
    e.runtime_context = {k: v if type(v) is bool else None for k, v in mapping(context.runtime_context).items() if k in {
        "evidence_available", "pid_changed_observed", "process_death_observed", "activity_changes_observed", "fatal_observed", "crash_observed"}}
    e.visibility = {k: v if isinstance(v, str) and v in {"available", "partial", "unavailable", "unknown"} else "unknown"
                    for k, v in mapping(context.visibility).items() if k in {"http_visibility", "https_visibility"}}
    e.evidence_refs = {k: deepcopy(v) for k, v in mapping(context.evidence_refs).items() if k in _REF_FIELDS}
    validate_real_safety(e.to_dict())  # Unsafe provenance IDs fail closed.
    source = build_context_analyst_input(e)
    for name in ("request", "response"):
        selected = getattr(source, name + "_context")
        keys = set(getattr(e, name))
        setattr(e, name, {k: deepcopy(v) for k, v in selected.items() if k in keys})
    count = e.dynamic.get("available_transaction_count")
    if count is not None and (type(count) is not int or count < 0): raise ContractError("Invalid transaction count")
    for key in ("observed",):
        if key in e.dynamic and e.dynamic[key] is not None and type(e.dynamic[key]) is not bool: raise ContractError("Invalid presence metadata")
    for key, values in e.evidence_refs.items():
        if not isinstance(values, list) or len(values) > 64: raise ContractError("Invalid evidence references")
        for value in values: identifier(value, key)
        e.evidence_refs[key] = sorted(set(values))
    e.methods = source.endpoint["methods"]
    return e


def _coverage(metadata):
    metadata = {} if metadata is None else metadata
    if not isinstance(metadata, dict): raise ContractError("Invalid coverage")
    out = {k: v if type(v) is bool else None for k, v in metadata.items() if k in {
        "traffic_available", "input_action_skipped", "external_package_boundary", "system_ui_boundary"}}
    if "stop_reason" in metadata:
        out["stop_reason"] = metadata["stop_reason"] if isinstance(metadata["stop_reason"], str) and metadata["stop_reason"] in {"max_steps", "max_depth", "completed", "failed", "aborted"} else None
    return out


def _validate_gold(gold, endpoint, coverage):
    if not isinstance(gold, dict) or set(gold) != EXPECTED_FIELDS: raise ContractError("Reviewed case requires complete structured gold")
    domains = {"allowed_hypothesis_types": HYPOTHESIS_TYPES, "expected_hypothesis_types": HYPOTHESIS_TYPES,
               "forbidden_hypothesis_types": HYPOTHESIS_TYPES, "expected_test_ids": TEST_CATALOG, "forbidden_test_ids": TEST_CATALOG}
    for key, domain in domains.items():
        value = gold[key]
        if not isinstance(value, list) or any(not isinstance(v, str) or v not in domain for v in value) or len(value) != len(set(value)):
            raise ContractError("Unsupported or duplicate gold label")
    if (not set(gold["expected_hypothesis_types"]) <= set(gold["allowed_hypothesis_types"])
        or set(gold["allowed_hypothesis_types"]) & set(gold["forbidden_hypothesis_types"])
        or set(gold["expected_test_ids"]) & set(gold["forbidden_test_ids"])): raise ContractError("Contradictory gold")
    source = build_context_analyst_input(endpoint, coverage_metadata=coverage)
    if not isinstance(gold["expected_endpoint_role"], str) or gold["expected_endpoint_role"] not in ENDPOINT_ROLES: raise ContractError("Unknown role")
    # Human gold can disagree with system heuristics: missed labels remain scoreable.
    gaps = {"static_not_observed", "https_visibility_unavailable", "traffic_unavailable", "required_evidence_unavailable",
            "max_steps", "max_depth", "input_skipped", "external_package", "system_ui"}
    for key in ("expected_coverage_gaps", "unknown_fields"):
        value = gold[key]
        if not isinstance(value, list) or any(not isinstance(v, str) for v in value) or len(value) != len(set(value)): raise ContractError("Invalid gold list")
    if not set(gold["expected_coverage_gaps"]) <= gaps: raise ContractError("Unsupported coverage kind")
    for dotted in gold["unknown_fields"]:
        value = source.to_dict()
        for key in dotted.split('.'):
            if not isinstance(value, dict) or key not in value: raise ContractError("Unknown gold field")
            value = value[key]
        if value is not None: raise ContractError("Gold unknown must be unknown")
    policy = gold["expected_policy_outcomes"]
    if not isinstance(policy, dict) or any(k not in gold["expected_test_ids"] or v not in {"allow", "deny", "needs_evidence"} for k, v in policy.items()): raise ContractError("Invalid policy labels")
    if gold["must_not_emit_finding"] is not True: raise ContractError("Invalid finding boundary")
    validate_real_safety(gold)


@dataclass(frozen=True)
class RealBenchmarkCase:
    case_id: str
    source: dict
    endpoint_context: EndpointContext
    coverage_metadata: dict
    tags: tuple[str, ...]
    review: dict
    gold: dict | None = None
    schema_version: str = "1.0"

    def to_dict(self):
        return {"schema_version": self.schema_version, "case_id": self.case_id, "source": deepcopy(self.source),
                "input": {"endpoint_context": self.endpoint_context.to_dict(), "coverage_metadata": deepcopy(self.coverage_metadata)},
                "tags": list(self.tags), "review": deepcopy(self.review), "gold": deepcopy(self.gold)}

    def model_input(self):
        """Only canonical evidence enters the role adapter, never gold/review/tags."""
        return build_context_analyst_input(deepcopy(self.endpoint_context), coverage_metadata=deepcopy(self.coverage_metadata))

    def scoring_case(self):
        if self.review["status"] != "reviewed" or self.gold is None: raise ContractError("Only reviewed cases can be scored")
        return BenchmarkCase(self.case_id, self.tags[0] if self.tags else "unknown", "Human-reviewed real pilot case.",
                             deepcopy(self.endpoint_context), deepcopy(self.gold), deepcopy(self.coverage_metadata), ())


def build_real_benchmark_case(endpoint_context, source_metadata, *, scan_reference=None, coverage_metadata=None,
                              tags=(), alias_hosts=True, sensitive_path_segments=()):
    app = source_metadata
    if not isinstance(tags, (list, tuple)) or len(tags) > len(TAGS) or any(not isinstance(t, str) or t not in TAGS for t in tags):
        raise ContractError("Invalid case tags")
    if not isinstance(app, AppMetadata): raise ContractError("App metadata required")
    if scan_reference is not None: identifier(scan_reference, "scan_reference")
    context = sanitize_endpoint(endpoint_context, app, alias_hosts=alias_hosts, sensitive_path_segments=sensitive_path_segments)
    case_id = f"real_{app.app_id}_{_digest(app.app_id + ':' + context.endpoint_context_id)}"
    case = RealBenchmarkCase(case_id, {"dataset_type": "real", "dataset_version": REAL_VERSION, "app_id": app.app_id,
        "split": app.split, "endpoint_context_id": context.endpoint_context_id, "scan_reference": scan_reference},
        context, _coverage(coverage_metadata), tuple(sorted(set(tags))), {"status": "unreviewed", "reviewer_ids": [], "notes": []})
    return parse_real_case(case.to_dict(), app)


def parse_real_case(data, app):
    validate_real_safety(data)
    if not isinstance(app, AppMetadata) or not isinstance(data, dict) or set(data) != {"schema_version", "case_id", "source", "input", "tags", "review", "gold"} or data["schema_version"] != "1.0": raise ContractError("Invalid real case schema")
    source = data["source"]
    if not isinstance(source, dict) or set(source) != {"dataset_type", "dataset_version", "app_id", "split", "endpoint_context_id", "scan_reference"}: raise ContractError("Invalid provenance")
    if source["dataset_type"] != "real" or source["dataset_version"] != REAL_VERSION or source["app_id"] != app.app_id or source["split"] != app.split: raise ContractError("Case/app split mismatch")
    for key in ("endpoint_context_id", "scan_reference"):
        if source[key] is not None: identifier(source[key], key)
    inp = data["input"]
    if not isinstance(inp, dict) or set(inp) != {"endpoint_context", "coverage_metadata"}: raise ContractError("Invalid real input")
    raw = inp["endpoint_context"]
    if not isinstance(raw, dict) or set(raw) != {f.name for f in fields(EndpointContext)}: raise ContractError("Canonical EndpointContext required")
    endpoint = EndpointContext(**deepcopy(raw))
    # Reject files carrying anything the importer would drop or normalize.
    safe = sanitize_endpoint(endpoint, app, alias_hosts=False)
    if safe.to_dict() != endpoint.to_dict(): raise ContractError("Noncanonical sanitized input")
    if source["endpoint_context_id"] != endpoint.endpoint_context_id: raise ContractError("Endpoint provenance mismatch")
    expected_id = f"real_{app.app_id}_{_digest(app.app_id + ':' + endpoint.endpoint_context_id)}"
    if data["case_id"] != expected_id: raise ContractError("Invalid stable case ID")
    coverage = _coverage(inp["coverage_metadata"])
    if coverage != inp["coverage_metadata"]: raise ContractError("Unsafe coverage fields")
    tags = data["tags"]
    if not isinstance(tags, list) or any(not isinstance(t, str) or t not in TAGS for t in tags) or len(tags) != len(set(tags)): raise ContractError("Invalid category")
    review = data["review"]
    if not isinstance(review, dict) or set(review) != {"status", "reviewer_ids", "notes"} or not isinstance(review["status"], str) or review["status"] not in REVIEW_STATUSES: raise ContractError("Invalid review")
    if not isinstance(review["reviewer_ids"], list) or len(review["reviewer_ids"]) > 2 or any(v not in {"reviewer_1", "reviewer_2"} for v in review["reviewer_ids"]) or len(set(review["reviewer_ids"])) != len(review["reviewer_ids"]): raise ContractError("Anonymous reviewers required")
    if not isinstance(review["notes"], list) or len(review["notes"]) > 8 or any(not isinstance(v, str) or len(v) > 256 for v in review["notes"]): raise ContractError("Invalid review notes")
    if review["status"] == "reviewed" and not review["reviewer_ids"]: raise ContractError("Reviewed case requires human reviewer")
    if review["status"] == "reviewed" or data["gold"] is not None: _validate_gold(data["gold"], endpoint, coverage)
    return RealBenchmarkCase(data["case_id"], deepcopy(source), endpoint, coverage, tuple(sorted(tags)), deepcopy(review), deepcopy(data["gold"]))


def review_template(case):
    """Empty labels, never derived from Analyst/Planner answers."""
    return {"case_id": case.case_id, "review": {"status": "unreviewed", "reviewer_ids": [], "notes": []},
            "gold": {"allowed_hypothesis_types": [], "expected_hypothesis_types": [], "forbidden_hypothesis_types": [],
                     "expected_test_ids": [], "forbidden_test_ids": [], "expected_coverage_gaps": [],
                     "expected_endpoint_role": "unknown", "unknown_fields": [], "expected_policy_outcomes": {}, "must_not_emit_finding": True}}


def apply_review(case, labels, app):
    if not isinstance(labels, dict) or set(labels) != {"case_id", "review", "gold"} or labels["case_id"] != case.case_id: raise ContractError("Review identity mismatch")
    data = case.to_dict(); data.update(deepcopy(labels))
    return parse_real_case(data, app)


def build_manifest(apps, cases, *, generated_at=None):
    apps, cases = tuple(apps), tuple(cases)
    app_index = {app.app_id: app for app in apps}
    if len(app_index) != len(apps): raise ContractError("Duplicate app ID")
    ids = [case.case_id for case in cases]
    if len(ids) != len(set(ids)): raise ContractError("Duplicate case ID")
    for case in cases:
        if case.source["app_id"] not in app_index: raise ContractError("Missing app metadata")
        parse_real_case(case.to_dict(), app_index[case.source["app_id"]])
    for app in apps:
        app_cases = [c for c in cases if c.source["app_id"] == app.app_id]
        status = "reviewed" if app_cases and all(c.review["status"] == "reviewed" for c in app_cases) else "unreviewed"
        if app.case_count != len(app_cases) or app.human_review_status != status: raise ContractError("Stale app counts/review metadata")
    now = generated_at or datetime.now(timezone.utc).isoformat(); timestamp(now)
    counts = Counter(c.review["status"] for c in cases)
    snapshot = {"dataset_version": REAL_VERSION, "apps": [a.to_dict() for a in sorted(apps, key=lambda a: a.app_id)],
                "cases": [c.to_dict() for c in sorted(cases, key=lambda c: c.case_id)]}
    fingerprint = hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schema_version": "1.0", "benchmark_version": BENCHMARK_VERSION, "dataset_version": REAL_VERSION,
            "apps": sorted(app_index), "app_count": len(apps), "case_count": len(cases), "dataset_fingerprint": fingerprint,
            **{f"{status}_case_count": counts[status] for status in sorted(REVIEW_STATUSES)},
            "development_case_count": sum(c.source["split"] == "development" for c in cases),
            "holdout_case_count": sum(c.source["split"] == "holdout" for c in cases),
            "category_counts": dict(sorted(Counter(t for c in cases for t in c.tags).items())), "generated_at": now}


def _root(root):
    path = Path(root).resolve()
    if path.parts[-3:] != ("benchmarks", "agent_v1", "real") or "demo_runs" in path.parts: raise ContractError("Development real dataset directory required")
    return path


def _atomic(path, data):
    validate_real_safety(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as f:
            temporary = Path(f.name); json.dump(data, f, indent=2, sort_keys=True); f.write('\n'); f.flush()
        temporary.replace(path)
    finally:
        if temporary: temporary.unlink(missing_ok=True)


def _inside(root, path):
    if not path.resolve().is_relative_to(root): raise ContractError("Dataset path escapes root")
    return path


def _load_all(root):
    root = _root(root); manifest = _read(root / "manifest.json")
    validate_real_safety(manifest)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("apps"), list): raise ContractError("Invalid real manifest")
    apps, cases = [], []
    for app_id in manifest["apps"]:
        if not isinstance(app_id, str) or not re.fullmatch(r"app_[A-Za-z0-9_]{1,32}", app_id): raise ContractError("Unsafe app reference")
        directory = _inside(root, root / "apps" / app_id)
        metadata = _read(_inside(root, directory / "metadata.json")); validate_real_safety(metadata)
        try: app = AppMetadata(**metadata)
        except TypeError as exc: raise ContractError("Invalid app metadata") from exc
        if app.app_id != app_id: raise ContractError("App identity mismatch")
        apps.append(app)
        for path in sorted((directory / "cases").glob('*.json')):
            case = parse_real_case(_read(_inside(root, path)), app)
            if path.stem != case.case_id: raise ContractError("Case filename mismatch")
            cases.append(case)
    expected = build_manifest(apps, cases, generated_at=manifest.get("generated_at"))
    if manifest != expected: raise ContractError("Manifest mismatch")
    return tuple(apps), tuple(sorted(cases, key=lambda c: c.case_id)), manifest


def validate_real_dataset(root=DEFAULT_REAL_ROOT):
    return _load_all(root)[2]


def load_real_cases(root=DEFAULT_REAL_ROOT, *, include_holdout=False, reviewed_only=True):
    if type(include_holdout) is not bool or type(reviewed_only) is not bool: raise ContractError("Invalid selection option")
    _, cases, _ = _load_all(root)
    return tuple(c for c in cases if (include_holdout or c.source["split"] == "development")
                 and c.review["status"] != "excluded" and (not reviewed_only or c.review["status"] == "reviewed"))


def export_real_app(endpoint_contexts, app, root=DEFAULT_REAL_ROOT, *, scan_reference=None, coverage_metadata=None,
                    tags=(), sensitive_path_segments=(), generated_at=None):
    """Explicit artifact only; never scan folders, overwrite reviews or mutate source."""
    root = _root(root)
    if not isinstance(app, AppMetadata): raise ContractError("App metadata required")
    target = _inside(root, root / "apps" / app.app_id)
    if target.exists(): raise ContractError("App already exported; preserve existing human review")
    if not isinstance(endpoint_contexts, EndpointContextArtifact):
        if Path(endpoint_contexts).stat().st_size > 2_097_152: raise ContractError("Source artifact exceeds bound")
    artifact = endpoint_contexts if isinstance(endpoint_contexts, EndpointContextArtifact) else EndpointContextArtifact.load(endpoint_contexts)
    if len(artifact.endpoints) > 256: raise ContractError("Pilot app exceeds endpoint bound")
    cases = tuple(build_real_benchmark_case(e, app, scan_reference=scan_reference, coverage_metadata=coverage_metadata,
                  tags=tags, sensitive_path_segments=sensitive_path_segments) for e in artifact.endpoints)
    apps, existing = (), ()
    if (root / "manifest.json").exists(): apps, existing, _ = _load_all(root)
    saved_app = AppMetadata(app.app_id, app.source_type, app.split, holdout=app.holdout, case_count=len(cases))
    manifest = build_manifest((*apps, saved_app), (*existing, *cases), generated_at=generated_at)
    for case in cases: parse_real_case(case.to_dict(), saved_app)
    for case in cases: _atomic(_inside(root, target / "cases" / f"{case.case_id}.json"), case.to_dict())
    _atomic(_inside(root, target / "metadata.json"), saved_app.to_dict())
    _atomic(root / "manifest.json", manifest)
    return cases


def save_review(root, labels):
    """Apply a separate human label file; input remains immutable."""
    root = _root(root)
    apps, cases, _ = _load_all(root)
    matches = [c for c in cases if c.case_id == labels.get("case_id")]
    if len(matches) != 1: raise ContractError("Unknown review case")
    old = matches[0]; app = next(a for a in apps if a.app_id == old.source["app_id"])
    reviewed = apply_review(old, labels, app)
    updated_cases = tuple(reviewed if c.case_id == old.case_id else c for c in cases)
    updated_apps = []
    for original in apps:
        group = [c for c in updated_cases if c.source["app_id"] == original.app_id]
        metadata = original.to_dict()
        metadata["human_review_status"] = "reviewed" if group and all(c.review["status"] == "reviewed" for c in group) else "unreviewed"
        updated_apps.append(AppMetadata(**metadata))
    manifest = build_manifest(updated_apps, updated_cases)
    _atomic(_inside(root, root / "apps" / app.app_id / "cases" / f"{old.case_id}.json"), reviewed.to_dict())
    for metadata in updated_apps:
        _atomic(_inside(root, root / "apps" / metadata.app_id / "metadata.json"), metadata.to_dict())
    _atomic(root / "manifest.json", manifest)
    return reviewed


def main():
    parser = argparse.ArgumentParser(description="Export authorized canonical evidence; no scanning or model execution")
    parser.add_argument('--endpoint-contexts', required=True)
    parser.add_argument('--app-id', required=True)
    parser.add_argument('--source-type', choices=sorted(SOURCE_TYPES), required=True)
    parser.add_argument('--split', choices=['development', 'holdout'], required=True)
    parser.add_argument('--output', default=str(DEFAULT_REAL_ROOT))
    parser.add_argument('--scan-reference')
    parser.add_argument('--sensitive-path-segment', action='append', default=[])
    args = parser.parse_args()
    app = AppMetadata(args.app_id, args.source_type, args.split, holdout=args.split == 'holdout')
    export_real_app(args.endpoint_contexts, app, args.output, scan_reference=args.scan_reference,
                    sensitive_path_segments=args.sensitive_path_segment)


if __name__ == '__main__': main()
