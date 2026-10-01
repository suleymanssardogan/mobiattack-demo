"""Select one sanitized EndpointContext; never forward raw evidence dictionaries."""
from __future__ import annotations

import json
from pathlib import Path
import re

from src.agent.models import ContractError, identifier, reference
from src.dynamic.context.models import EndpointContext, EndpointContextArtifact
from .models import ContextAnalystInput

MAX_ITEMS = 32
MAX_SOURCE_ITEMS = 256
MAX_REFERENCES = 64
MAX_ARTIFACT_BYTES = 2_097_152
AUTH_FLAGS = ("authorization_header_present", "bearer_token_present", "cookie_present",
              "session_cookie_present", "api_key_header_present")
RUNTIME_FLAGS = ("pid_changed_observed", "process_death_observed", "activity_changes_observed",
                 "fatal_observed", "crash_observed")
METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"})
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$-]{0,127}$")
_PATH = re.compile(r"^/[A-Za-z0-9_./{}:<>%~-]*$")
_LOCAL_PATH = re.compile(r"^(?:/Users/|/private/var/|/opt/homebrew/|/var/folders/|[A-Za-z]:[\\/])")
_MEDIA = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")
_SHAPE_TYPES = frozenset({"null", "boolean", "number", "integer", "string", "object", "array", "binary", "unknown"})
_MATCH_TYPES = frozenset({"exact", "template", "host_path", "method_mismatch", "static_only", "dynamic_only"})


class InputInvalid(ContractError):
    """Only a fixed code crosses the runtime diagnostic boundary."""


class _Selector:
    def __init__(self):
        self.truncated = False

    def values(self, source, predicate, limit=MAX_ITEMS):
        if not isinstance(source, (list, tuple)):
            return []
        if len(source) > MAX_SOURCE_ITEMS:
            raise InputInvalid("SOURCE_COLLECTION_EXCEEDS_BOUND")
        values = sorted({v for v in source if isinstance(v, (str, int)) and not isinstance(v, bool) and predicate(v)})
        self.truncated |= len(values) > limit
        return values[:limit]

    def names(self, source):
        return self.values(source, lambda v: isinstance(v, str) and bool(_NAME.fullmatch(v)))

    def ids(self, source):
        def valid(v):
            try:
                identifier(v, "evidence_id")
                return True
            except ContractError:
                return False
        return self.values(source, valid)

    def shapes(self, source):
        if not isinstance(source, list):
            return []
        if len(source) > 32:
            raise InputInvalid("SOURCE_SHAPES_EXCEED_BOUND")
        selected = [_shape(v, self, budget=[256]) for v in source]
        unique = sorted({json.dumps(v, sort_keys=True) for v in selected})
        self.truncated |= len(unique) > 4
        return [json.loads(v) for v in unique[:4]]


def _dict(value):
    return value if isinstance(value, dict) else {}


def _tri(value):
    return value if type(value) is bool else None


def _shape(value, selector, depth=0, budget=None):
    budget = budget if budget is not None else [256]
    budget[0] -= 1
    if budget[0] < 0:
        selector.truncated = True
        return "unknown"
    if depth >= 3:
        selector.truncated |= isinstance(value, (dict, list))
        return "object" if isinstance(value, dict) else "array" if isinstance(value, list) else value if isinstance(value, str) and value in _SHAPE_TYPES else "unknown"
    if isinstance(value, dict):
        keys = selector.names(list(value))
        return {k: _shape(value[k], selector, depth + 1, budget) for k in keys}
    if isinstance(value, list):
        selector.truncated |= len(value) > 1
        return [_shape(value[0], selector, depth + 1, budget)] if value else []
    return value if isinstance(value, str) and value in _SHAPE_TYPES else "unknown"


def _media(selector, values):
    return selector.values(values, lambda v: isinstance(v, str) and len(v) <= 127 and bool(_MEDIA.fullmatch(v)))


def _message(source, selector):
    source = _dict(source)
    return {"header_names": selector.names(source.get("header_names")),
            "body_keys": selector.names(source.get("body_keys")),
            "body_present": _tri(source.get("body_present")),
            "body_shapes": selector.shapes(source.get("body_shapes")),
            "body_types": selector.values(source.get("body_types"), lambda v: v in _SHAPE_TYPES),
            "content_types": _media(selector, source.get("content_types"))}


def _resource_keys(path, request):
    from src.dynamic.correlation.api_correlator import is_template_param
    path_keys = [segment[1:-1] if segment.startswith(("{", "<")) else segment[1:]
                 for segment in path.split("/") if is_template_param(segment)]
    candidates = [("path", key) for key in path_keys]
    candidates += [("query", key) for key in request["query_keys"]]
    candidates += [("body", key) for key in request["body_keys"]]
    return sorted({f"{location}:{key}" for location, key in candidates
                   if _NAME.fullmatch(key) and (key.lower() == "id" or key.lower().endswith("_id") or key.endswith("Id"))})


def build_context_analyst_input(endpoint_context: EndpointContext, *, coverage_metadata=None,
                               available_evidence_refs=None) -> ContextAnalystInput:
    """Caller supplies canonical context and optional already-resolved evidence refs.

    No other endpoint, raw request/response or arbitrary metadata is passed through.
    References to missing transactions and correlation-side source-ID surrogates
    are excluded. Optional availability restriction can only narrow this universe.
    """
    if not isinstance(endpoint_context, EndpointContext):
        raise InputInvalid("INVALID_ENDPOINT_CONTEXT")
    e = endpoint_context
    try:
        identifier(e.endpoint_context_id, "endpoint_context_id")
    except ContractError as exc:
        raise InputInvalid("INVALID_ENDPOINT_ID") from exc
    if (not isinstance(e.host, str) or len(e.host) > 253
            or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.:-]*", e.host)
            or not isinstance(e.path, str) or len(e.path) > 512 or not _PATH.fullmatch(e.path)
            or _LOCAL_PATH.match(e.path) or ".." in e.path.split("/")):
        raise InputInvalid("INVALID_ENDPOINT_IDENTITY")
    selector = _Selector()
    methods = selector.values(e.methods, lambda v: v in METHODS)
    endpoint = {"host": e.host, "path": e.path, "methods": methods}
    static_source, dynamic_source = _dict(e.static), _dict(e.dynamic)
    match_type = static_source.get("match_type")
    static = {"match_type": match_type if isinstance(match_type, str) and match_type in _MATCH_TYPES else None,
              "confidence": static_source.get("confidence") if static_source.get("confidence") in ("high", "medium", "low") else None,
              "static_method": static_source.get("static_method") if static_source.get("static_method") in METHODS else None}
    for key in ("static_candidate_id", "static_candidate_id_source_field"):
        value = static_source.get(key)
        try:
            identifier(value, key)
        except ContractError:
            continue
        static[key] = value
    origin = static_source.get("static_candidate_id_origin")
    static["static_candidate_id_origin"] = origin if origin in ("source_report", "correlation_reference") else None
    source_file = static_source.get("source_file")
    if (isinstance(source_file, str) and len(source_file) <= 256 and not source_file.startswith("/")
            and re.fullmatch(r"[A-Za-z0-9_./$-]+", source_file) and ".." not in source_file.split("/")):
        static["source_file"] = source_file
    line = static_source.get("request_line")
    if type(line) is int and line >= 0:
        static["request_line"] = line
    framework = static_source.get("framework")
    if framework in ("Fuel", "Retrofit", "OkHttp", "Volley", "HttpURLConnection", "Ktor", "requests", "unknown"):
        static["framework"] = framework
    refs_source = _dict(e.evidence_refs)
    missing = set(selector.ids(dynamic_source.get("missing_transaction_ids")))
    tx_ids = [tid for tid in selector.ids(refs_source.get("transaction_ids")) if tid not in missing]
    observed = _tri(dynamic_source.get("observed"))
    if static["match_type"] == "static_only":
        if observed is True:
            raise InputInvalid("INCONSISTENT_RUNTIME_CONTEXT")
        observed = False
    if static["match_type"] == "dynamic_only":
        if observed is False:
            raise InputInvalid("INCONSISTENT_RUNTIME_CONTEXT")
        observed = True
    dynamic = {"runtime_confirmed": observed,
               "observed_methods": selector.values(dynamic_source.get("observed_methods"), lambda v: v in METHODS),
               "transaction_ids": tx_ids, "missing_transaction_ids": sorted(missing),
               "action_ids": selector.ids(refs_source.get("action_ids"))}
    request = _message(e.request, selector)
    request["query_keys"] = selector.names(_dict(e.request).get("query_keys"))
    request["resource_identifier_keys"] = _resource_keys(e.path, request)
    response = _message(e.response, selector)
    response["observed_status_codes"] = selector.values(_dict(e.response).get("observed_status_codes"),
                                                       lambda v: type(v) is int and 100 <= v <= 599)
    count = dynamic_source.get("available_transaction_count")
    auth_observable = observed is True and bool(tx_ids) and (type(count) is not int or count > 0)
    auth = {key: _tri(_dict(e.auth).get(key)) if auth_observable else None for key in AUTH_FLAGS}
    if not auth_observable and request["body_present"] is False:
        request["body_present"] = None
    if not response["observed_status_codes"] and not response["body_shapes"] and response["body_present"] is False:
        response["body_present"] = None
    runtime_source = _dict(e.runtime_context)
    runtime_available = _tri(runtime_source.get("evidence_available"))
    runtime = {"evidence_available": runtime_available}
    runtime.update({key: _tri(runtime_source.get(key)) if runtime_available is True else None for key in RUNTIME_FLAGS})
    visibility_source = _dict(e.visibility)
    visibility = {key: visibility_source.get(key) if visibility_source.get(key) in ("available", "partial", "unavailable", "unknown") else "unknown"
                  for key in ("http_visibility", "https_visibility")}
    action_context = []
    if any(isinstance(v, list) and len(v) > MAX_SOURCE_ITEMS for v in (e.action_context, e.route_context)):
        raise InputInvalid("SOURCE_COLLECTION_EXCEEDS_BOUND")
    for item in e.action_context if isinstance(e.action_context, list) else []:
        safe = {key: selector.ids([_dict(item).get(key)]) for key in ("action_id", "source_node_id", "target_node_id")}
        action_context.append({key: values[0] for key, values in safe.items() if values})
    route_context = []
    for item in e.route_context if isinstance(e.route_context, list) else []:
        safe = {key: selector.ids([_dict(item).get(key)]) for key in ("action_id", "source_node_id", "target_node_id")}
        route_context.append({key: values[0] for key, values in safe.items() if values})
    selector.truncated |= any(isinstance(v, list) and len(v) > 8 for v in (e.action_context, e.route_context))
    dynamic["action_context"] = sorted(action_context, key=lambda v: json.dumps(v, sort_keys=True))[:8]
    dynamic["route_context"] = sorted(route_context, key=lambda v: json.dumps(v, sort_keys=True))[:8]
    ctx_ref = f"dynamic/endpoint_contexts.json#endpoint_context_id={e.endpoint_context_id}"
    refs = {"endpoint_context": [ctx_ref], "transactions": [f"dynamic/traffic.json#transaction_id={tid}" for tid in tx_ids],
            "correlations": [f"dynamic/api_correlation.json#correlation_id={cid}" for cid in selector.ids(refs_source.get("correlation_ids"))],
            "traffic_actions": [f"dynamic/traffic_evidence.json#action_id={aid}" for aid in dynamic["action_ids"]],
            "runtime_actions": [f"dynamic/runtime_evidence.json#action_id={aid}" for aid in selector.ids(refs_source.get("runtime_action_ids"))]
            if runtime_available is True else [], "static_candidates": []}
    if origin == "source_report" and static.get("static_candidate_id") in selector.ids(refs_source.get("static_candidate_ids")):
        refs["static_candidates"] = [f"static_analysis_report.json#candidate_id={static['static_candidate_id']}"]
    if available_evidence_refs is not None:
        if not isinstance(available_evidence_refs, (list, tuple, set, frozenset)) or len(available_evidence_refs) > MAX_SOURCE_ITEMS:
            raise InputInvalid("INVALID_EVIDENCE_UNIVERSE")
        try:
            for ref in available_evidence_refs:
                reference(ref)
        except ContractError as exc:
            raise InputInvalid("INVALID_EVIDENCE_UNIVERSE") from exc
        available = set(available_evidence_refs)
        refs = {key: [ref for ref in values if ref in available] for key, values in refs.items()}
        if ctx_ref not in available:
            raise InputInvalid("MISSING_CONTEXT_EVIDENCE")
    # Keep context provenance first, then a stable bounded subset of other refs.
    universe = sorted({ref for values in refs.values() for ref in values} - {ctx_ref})
    selector.truncated |= len(universe) >= MAX_REFERENCES
    allowed = {ctx_ref, *universe[:MAX_REFERENCES - 1]}
    refs = {key: sorted(ref for ref in values if ref in allowed) for key, values in refs.items()}
    metadata = _dict(coverage_metadata)
    coverage = {key: _tri(metadata.get(key)) for key in ("traffic_available", "input_action_skipped", "external_package_boundary", "system_ui_boundary")}
    coverage["stop_reason"] = metadata.get("stop_reason") if metadata.get("stop_reason") in ("max_steps", "max_depth", "completed", "failed", "aborted") else None
    coverage["input_truncated"] = selector.truncated
    descriptors = []
    def gap(kind, description):
        descriptors.append({"kind": kind, "description": description, "evidence_refs": [ctx_ref]})
    if static["match_type"] == "static_only":
        gap("static_not_observed", "Static candidate was not observed in available runtime traffic.")
    if visibility["https_visibility"] in ("unavailable", "partial"):
        gap("https_visibility_unavailable", f"HTTPS visibility is {visibility['https_visibility']}; coverage is incomplete.")
    if coverage["traffic_available"] is False:
        gap("traffic_unavailable", "Traffic capture metadata is unavailable.")
    if missing:
        gap("required_evidence_unavailable", "Referenced traffic transactions are unavailable.")
    if runtime_available is not True:
        gap("required_evidence_unavailable", "Runtime evidence metadata is unavailable.")
    if not dynamic["action_ids"]:
        gap("required_evidence_unavailable", "Action-linked context is unavailable.")
    if all(value is None for value in auth.values()):
        gap("required_evidence_unavailable", "Authentication metadata is unknown in available evidence.")
    if coverage["stop_reason"] in ("max_steps", "max_depth"):
        gap(coverage["stop_reason"], f"Exploration stopped at {coverage['stop_reason']}; coverage is incomplete.")
    for key, kind in (("input_action_skipped", "input_skipped"), ("external_package_boundary", "external_package"), ("system_ui_boundary", "system_ui")):
        if coverage[key] is True:
            gap(kind, f"Coverage metadata records {kind}.")
    if selector.truncated:
        gap("required_evidence_unavailable", "Input summaries were bounded; omitted evidence is unavailable to this analysis.")
    coverage["gaps"] = sorted(descriptors, key=lambda v: (v["kind"], v["description"]))
    facts = []
    def fact(statement):
        facts.append({"statement": statement, "evidence_refs": [ctx_ref]})
    fact(f"Endpoint context identifies {e.host}{e.path} with methods: {', '.join(methods) or 'unknown'}.")
    if observed is True:
        fact("Runtime traffic confirmed this endpoint in the supplied context.")
    elif static["match_type"] == "static_only":
        fact("Endpoint candidate was identified statically but not observed in available runtime traffic.")
    if static["match_type"] == "dynamic_only":
        fact("Endpoint was observed at runtime but no matching static candidate was identified.")
    if static["static_method"]:
        fact(f"Static method: {static['static_method']}.")
    if dynamic["observed_methods"]:
        fact(f"Observed methods: {', '.join(dynamic['observed_methods'])}.")
    if static["match_type"] == "method_mismatch":
        fact("Method behavior differs between static and runtime evidence; neither method is resolved as correct.")
    if request["resource_identifier_keys"]:
        fact(f"Resource identifier names are present: {', '.join(request['resource_identifier_keys'][:8])}; ownership is unknown.")
    for key, value in auth.items():
        fact(f"Authentication metadata {key}: {'present' if value is True else 'not observed' if value is False else 'unknown'}; correctness is unknown.")
    if request["query_keys"]:
        fact(f"Observed query key names: {', '.join(request['query_keys'][:8])}.")
    if request["body_keys"]:
        fact(f"Observed request body key names: {', '.join(request['body_keys'][:8])}.")
    if response["observed_status_codes"]:
        fact(f"Observed response status codes: {', '.join(map(str, response['observed_status_codes']))}; status alone does not establish security.")
    for name, summary in (("Request", request), ("Response", response)):
        present = summary["body_present"]
        fact(f"{name} body presence metadata: {'observed' if present is True else 'not observed' if present is False else 'unknown'}.")
        if summary["body_shapes"]:
            fact(f"{name} body shape metadata is available with value types only.")
        if summary["content_types"]:
            fact(f"{name} content types: {', '.join(summary['content_types'][:8])}.")
    if static.get("static_candidate_id"):
        fact(f"Static candidate provenance is present; ID origin: {static['static_candidate_id_origin'] or 'unknown'}.")
    if dynamic["action_ids"]:
        fact("Action-linked IDs are available in the supplied context.")
    if runtime_available is True:
        for key in RUNTIME_FLAGS:
            if runtime[key] is not None:
                fact(f"Runtime metadata {key}: {'observed' if runtime[key] is True else 'not observed'}; causality is unknown.")
    else:
        fact("Runtime event evidence is unavailable; event absence is unknown.")
    fact(f"HTTPS visibility: {visibility['https_visibility']}.")
    roles = {"unknown"}
    segments = set(e.path.lower().split("/"))
    if request["resource_identifier_keys"]:
        roles.add("resource_endpoint")
    if segments & {"login", "signin", "authenticate", "auth", "logout"}:
        roles.add("authentication_endpoint")
    if segments & {"profile", "me"}:
        roles.add("profile_endpoint")
    if segments & {"upload", "uploads"} and request["body_present"] is True:
        roles.add("upload_endpoint")
    hypotheses = {}
    def candidate(kind, statement, required):
        hypotheses[kind] = {"statement": statement, "evidence_refs": [ctx_ref], "required_evidence": required}
    if request["resource_identifier_keys"]:
        candidate("object_authorization_candidate", "Object-level authorization behavior may require validation because the endpoint exposes a resource identifier.",
                  ["Observed resource behavior", "Authorized identity and ownership context"])
    if any(v is not None for v in auth.values()):
        candidate("authentication_behavior_candidate", "Authentication behavior may require later validation; presence metadata does not establish correctness.", ["Expected authentication behavior", "Comparable runtime observations"])
    if any(auth[key] is True for key in ("bearer_token_present", "cookie_present", "session_cookie_present")):
        candidate("session_behavior_candidate", "Session-dependent behavior may require validation because session-related metadata was observed.", ["Expected session behavior", "Comparable session observations"])
    if request["query_keys"] or request["body_keys"]:
        candidate("input_validation_candidate", "Input handling may require later validation because input key names were observed.", ["Expected input behavior", "Comparable input observations"])
        candidate("parameter_consistency_candidate", "Parameter behavior may require later validation because parameter names were observed.", ["Expected parameter behavior", "Comparable parameter observations"])
    elif static["match_type"] == "method_mismatch":
        candidate("parameter_consistency_candidate", "Method behavior differs between static and runtime evidence and may require later clarification.", ["Expected method behavior", "Comparable runtime observations"])
    if observed is True and segments & {"admin", "administrator"} and any(v is True for v in auth.values()):
        candidate("function_authorization_candidate", "Function-level authorization behavior may require validation because an administrative path and authentication metadata were observed.", ["Expected function permissions", "Authorized identity context"])
    if descriptors:
        candidate("coverage_limitation", "Available coverage limits endpoint context; additional evidence is required.", ["Evidence addressing recorded coverage gaps"])
    return ContextAnalystInput(e.endpoint_context_id, endpoint, static, dynamic, request, response, auth,
        runtime, visibility, coverage, refs, tuple(sorted(facts, key=lambda v: v["statement"])), hypotheses, tuple(sorted(roles)))


def load_context_analyst_input(run_dir: str | Path, endpoint_context_id: str, **kwargs) -> ContextAnalystInput:
    """Reuse the canonical artifact loader, selecting one endpoint for the model."""
    root = Path(run_dir).resolve()
    artifact = root / "dynamic" / "endpoint_contexts.json"
    if not artifact.resolve().is_relative_to(root) or artifact.stat().st_size > MAX_ARTIFACT_BYTES:
        raise InputInvalid("INVALID_CONTEXT_ARTIFACT")
    contexts = EndpointContextArtifact.load(artifact)
    matches = [e for e in contexts.endpoints if e.endpoint_context_id == endpoint_context_id]
    if len(matches) != 1:
        raise InputInvalid("UNKNOWN_OR_DUPLICATE_ENDPOINT")
    return build_context_analyst_input(matches[0], **kwargs)
