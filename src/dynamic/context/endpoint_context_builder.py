"""Pure deterministic aggregation of existing canonical evidence; no execution."""
from __future__ import annotations

from collections import Counter
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from src.dynamic.correlation.api_correlator import normalize_host, normalize_path, normalize_method, normalize_transport, match_paths
from src.dynamic.correlation.models import ApiCorrelationResult, sanitize_provenance_paths
from src.dynamic.traffic.models import TrafficTransaction, TrafficEvidenceArtifact
from src.dynamic.runtime.models import RuntimeEvidenceArtifact
from .models import EndpointContext, EndpointContextArtifact, generate_endpoint_context_id

MAX_SHAPE_DEPTH = 3
MAX_SHAPE_KEYS = 32
MAX_BODY_PARSE_BYTES = 1_048_576
SENSITIVE_KEYS = {"password", "passwd", "token", "access_token", "refresh_token", "secret",
                  "api_key", "authorization", "cookie", "session", "session_id"}
_MEDIA_TYPE = re.compile(r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$")


def _dict(value: Any) -> dict:
    return value.to_dict() if hasattr(value, "to_dict") else (value if isinstance(value, dict) else {})


def _name(value: Any) -> str:
    return sanitize_provenance_paths(str(value))[:128]


def _type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    return "string"


def body_shape(value: Any, depth: int = 0) -> Any:
    """Bound depth, object width and array sampling; retain no scalar values."""
    if depth >= MAX_SHAPE_DEPTH:
        return _type(value)
    if isinstance(value, dict):
        return {_name(key): (_type(value[key]) if str(key).lower() in SENSITIVE_KEYS
                             else body_shape(value[key], depth + 1))
                for key in sorted(value, key=str)[:MAX_SHAPE_KEYS]}
    if isinstance(value, list):
        return [body_shape(value[0], depth + 1)] if value else []
    return _type(value)


def _headers(message: dict) -> dict[str, str]:
    return {str(k).strip().lower(): str(v) for k, v in (message.get("headers") or {}).items()}


def _content_type(message: dict) -> str | None:
    raw = _headers(message).get("content-type") or (message.get("body_metadata") or {}).get("content_type", "")
    media = str(raw).split(";", 1)[0].strip().lower()
    return media if _MEDIA_TYPE.fullmatch(media) else None


def _body(message: dict) -> tuple[bool, str | None, Any, list[str]]:
    value = message.get("body")
    meta = message.get("body_metadata") or {}
    present = value is not None and value != "" and value != b""
    present = present or (isinstance(meta.get("size"), int) and meta["size"] > 0)
    ct = _content_type(message) or ""
    kind = "multipart" if ct.startswith("multipart/") else "form" if ct == "application/x-www-form-urlencoded" else "json" if "json" in ct else _type(value)
    if value is None and present and kind == "null":
        kind = "binary" if meta.get("binary") is True else "unknown"
    if kind == "multipart":
        # Existing traffic model does not expose structured file parts. Never parse uploads.
        return present, kind if present else None, None, []
    if isinstance(value, str) and len(value.encode("utf-8")) <= MAX_BODY_PARSE_BYTES:
        if kind == "json":
            try:
                value = json.loads(value)
            except (ValueError, RecursionError):
                value = None
        elif kind == "form":
            value = {key: "" for key, _ in parse_qsl(
                "&".join(value.split("&", MAX_SHAPE_KEYS)[:MAX_SHAPE_KEYS]), keep_blank_values=True)}
    if isinstance(value, (dict, list)) and kind not in ("json", "form"):
        kind = "json"
    keys = sorted({_name(key) for key in value})[:MAX_SHAPE_KEYS] if isinstance(value, dict) else []
    shape = body_shape(value) if value is not None else None
    return present, kind if present else None, shape, keys


def _message_context(messages: list[dict]) -> dict:
    shapes: dict[str, Any] = {}
    keys, types, content_types, header_names, sizes = set(), set(), set(), set(), set()
    present = False
    for message in messages:
        body_present, kind, shape, body_keys = _body(message)
        present |= body_present
        keys.update(body_keys)
        if kind:
            types.add(kind)
        if shape is not None:
            shapes[json.dumps(shape, sort_keys=True)] = shape
        ct = _content_type(message)
        if ct:
            content_types.add(ct)
        header_names.update(_name(k) for k in _headers(message))
        size = (message.get("body_metadata") or {}).get("size")
        if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
            sizes.add(size)
    return {"content_types": sorted(content_types), "header_names": sorted(header_names),
            "body_present": present, "body_types": sorted(types), "body_keys": sorted(keys),
            "body_shapes": [shapes[key] for key in sorted(shapes)], "body_sizes": sorted(sizes)}


def _auth(requests: list[dict], session_id=None) -> dict:
    from src.dynamic.traffic.auth_metadata import observe_auth, safe_auth_metadata
    observations = [safe_auth_metadata(r.get("auth_metadata"), session_id) or observe_auth(r.get("headers")) for r in requests]
    def presence(key):
        values = [o.get(key) for o in observations]
        return True if True in values else (None if not values or any(o['state']=='unknown' for o in observations) else False)
    types = sorted({o['token_type'] for o in observations if o.get('token_type')})
    cookie_names = sorted({c['name'] for o in observations for c in o['cookies']})
    bearer = True if 'bearer' in types else (None if not observations or 'unknown' in types else False)
    cookie_present = presence('cookie_header_present')
    session_cookie = any('session' in n.lower() or n.lower() in {'sid','jsessionid','phpsessid'} for n in cookie_names)
    return {'authorization_header_present':presence('authorization_header_present'),
            'bearer_token_present':bearer, 'cookie_present':cookie_present,
            'session_cookie_present':True if session_cookie else (None if cookie_present or not observations else False),
            'api_key_header_present':presence('api_key_header_present'), 'token_types':types,
            'cookie_names':cookie_names, 'credential_refs':sorted({ref for o in observations for ref in o['credential_refs']} |
                {c['credential_ref'] for o in observations for c in o['cookies'] if c.get('credential_ref')}),
            'request_auth_states':sorted({o['state'] for o in observations}) if observations else ['unknown'],
            'authenticated_state':'unknown'}


def _compact_route(route: dict) -> dict:
    return {key: _name(route[key]) if route[key] is not None else None
            for key in ("action_id", "source_node_id", "target_node_id") if key in route}


def build_endpoint_contexts(
    api_correlation: ApiCorrelationResult,
    traffic_transactions: list[TrafficTransaction] | list[dict],
    traffic_evidence: TrafficEvidenceArtifact | None = None,
    runtime_evidence: RuntimeEvidenceArtifact | None = None,
) -> EndpointContextArtifact:
    """Summarize each canonical correlation entry without modifying its inputs."""
    # Duplicate IDs are ambiguous; never choose an arbitrary last payload.
    tx_data = [_dict(tx) for tx in traffic_transactions]
    counts = Counter(tx.get("transaction_id") for tx in tx_data if isinstance(tx.get("transaction_id"), str))
    transactions = {tx["transaction_id"]: tx for tx in tx_data
                    if isinstance(tx.get("transaction_id"), str) and counts[tx["transaction_id"]] == 1}
    traffic_data, runtime_data = _dict(traffic_evidence), _dict(runtime_evidence)
    traffic_actions = traffic_data.get("actions", []) if traffic_data.get("session_id") == api_correlation.session_id else []
    runtime_actions = runtime_data.get("actions", []) if runtime_data.get("session_id") == api_correlation.session_id else []
    endpoints = []
    for entry in api_correlation.correlations:
        requested_ids = sorted(set(entry.transaction_ids))
        linked = []
        for tid in requested_ids:
            tx = transactions.get(tid)
            if not tx or tx.get("session_id") not in (None, "", api_correlation.session_id):
                continue
            req = tx.get("request")
            if not isinstance(req, dict) or not all(isinstance(req.get(k), str) and req[k] for k in ("host", "path", "method")):
                continue
            if any(req.get(key) is not None and not isinstance(req[key], dict) for key in ("headers", "body_metadata")):
                continue
            if tx.get("synthetic") or tx.get("internal") or req.get("synthetic") or req.get("internal"):
                continue
            authority = normalize_transport(req["host"], req.get("scheme"), req.get("port"))
            if not authority[1] or authority != (entry.host, entry.scheme, entry.port):
                continue
            if not match_paths(entry.path, req["path"])[0] or normalize_method(req["method"]) not in entry.observed_methods:
                continue
            resp = tx.get("response")
            if resp is not None and (not isinstance(resp, dict) or resp.get("synthetic") or resp.get("internal")
                    or not isinstance(resp.get("status_code"), int) or isinstance(resp.get("status_code"), bool)
                    or any(resp.get(key) is not None and not isinstance(resp[key], dict) for key in ("headers", "body_metadata"))):
                continue
            linked.append(tx)
        tx_ids = sorted(tx["transaction_id"] for tx in linked)
        requests = [tx["request"] for tx in linked]
        responses = [tx["response"] for tx in linked if tx.get("response")]
        actions = [action for action in traffic_actions if isinstance(action, dict)
                   and action.get("action_id") and action.get("source_node_id")
                   and action.get("session_id", api_correlation.session_id) == api_correlation.session_id
                   and action.get("correlation_status") in ("available", "partial")
                   and set(action.get("transaction_ids", [])) & set(tx_ids)
                   and any(route.get("action_id") == action["action_id"]
                           and route.get("source_node_id") == action["source_node_id"]
                           and route.get("target_node_id") == action.get("target_node_id")
                           for route in entry.route_context)]
        action_ids = sorted({a["action_id"] for a in actions})
        action_context = sorted([_compact_route(a) for a in actions], key=lambda a: json.dumps(a, sort_keys=True))
        routes = {json.dumps(route, sort_keys=True): route for route in action_context}
        runtime = [a for a in runtime_actions if isinstance(a, dict)
                   and a.get("correlation_status") in ("available", "partial")
                   and a.get("session_id", api_correlation.session_id) == api_correlation.session_id
                   and any(a.get("action_id") == route["action_id"]
                           and a.get("source_node_id") == route["source_node_id"]
                           and (a.get("target_node_id") is None or a.get("target_node_id") == route.get("target_node_id"))
                           for route in action_context)]
        usable_runtime = [a for a in runtime if a.get("correlation_status") != "unavailable"]
        flags = {out: any(a.get(source) is True for a in usable_runtime)
                 for out, source in (("pid_changed_observed", "pid_changed"), ("process_death_observed", "process_died"),
                                     ("activity_changes_observed", "activity_changed"), ("fatal_observed", "fatal_appeared"),
                                     ("crash_observed", "crash_appeared"))}
        flags["evidence_available"] = bool(usable_runtime)
        static = {}
        if entry.static_candidate_id is not None:
            static = {"static_candidate_id": entry.static_candidate_id, "match_type": entry.match_type,
                      "confidence": entry.confidence, "static_method": entry.static_method}
            for key in ("source_file", "request_line", "framework", "static_candidate_id_origin", "static_candidate_id_source_field"):
                if key in entry.provenance:
                    static[key] = sanitize_provenance_paths(entry.provenance[key])
            # Extraction evidence is summarized through field names; arbitrary values may be credentials.
            if isinstance(entry.provenance.get("evidence"), dict):
                static["extraction_provenance_keys"] = sorted(_name(k) for k in entry.provenance["evidence"])
        observed_methods = sorted({normalize_method(req["method"]) for req in requests})
        methods = sorted(set(observed_methods) | ({entry.static_method} if entry.static_method else set()))
        request = _message_context(requests)
        query_keys = set()
        for req in requests:
            query = req.get("query") or {}
            query_keys.update(query.keys() if isinstance(query, dict) else (k for k, _ in parse_qsl(str(query))))
            query_keys.update(k for k, _ in parse_qsl(urlsplit(req.get("path", "")).query))
        request.update(methods=sorted({normalize_method(r.get("method")) for r in requests if normalize_method(r.get("method"))}),
                       query_keys=sorted(_name(k) for k in query_keys))
        from src.dynamic.traffic.auth_metadata import safe_auth_metadata, observe_auth
        request['auth_observations'] = [{'transaction_id':tx['transaction_id'], 'metadata':safe_auth_metadata(tx['request'].get('auth_metadata'), api_correlation.session_id) or observe_auth(tx['request'].get('headers'))} for tx in linked]
        response = _message_context(responses)
        response['cookie_observations'] = [{'transaction_id':tx['transaction_id'], 'metadata':safe_auth_metadata(tx['response'].get('auth_metadata'), api_correlation.session_id) or observe_auth(tx['response'].get('headers'), response=True)} for tx in linked if tx.get('response')]
        counts = Counter(r["status_code"] for r in responses if isinstance(r.get("status_code"), int) and r["status_code"] > 0)
        response.update(observed_status_codes=sorted(counts),
                        status_code_counts={str(k): counts[k] for k in sorted(counts)})
        schemes = sorted({r.get("scheme", "").lower() for r in requests if r.get("scheme", "").lower() in {"http", "https"}})
        host, path = entry.host, normalize_path(entry.path)  # Authority is already canonical, including IPv6.
        dynamic = {"observed": bool(tx_ids), "transaction_ids": tx_ids, "observation_count": len(linked),
                   "available_transaction_count": len(linked), "missing_transaction_ids": sorted(set(requested_ids) - set(tx_ids)),
                   "first_observed_at": min((r.get("timestamp") for r in requests if r.get("timestamp")), default=None),
                   "last_observed_at": max((r.get("timestamp") for r in requests if r.get("timestamp")), default=None),
                   "observed_methods": observed_methods, "observed_status_codes": sorted(counts),
                   "schemes": schemes}
        if requested_ids and not linked:
            dynamic["note"] = "Dynamic evidence unavailable: referenced transaction payloads are missing or invalid."
        if entry.match_type == "static_only":
            dynamic["note"] = "Not observed in available runtime traffic."
        visibility = {key: getattr(api_correlation.summary, key)
                      for key in ("http_visibility", "https_visibility", "https_visibility_reason")}
        endpoints.append(EndpointContext(
            endpoint_context_id=generate_endpoint_context_id(
                host, path, entry.static_method if entry.static_candidate_id else (entry.observed_methods[0] if entry.observed_methods else None),
                scheme=entry.scheme, port=entry.port),
            host=host, path=path, scheme=entry.scheme, port=entry.port, methods=methods,
            static=static, dynamic=dynamic, request=request, response=response, auth=_auth(requests, api_correlation.session_id),
            action_context=action_context, route_context=[routes[key] for key in sorted(routes)],
            runtime_context=flags, visibility=visibility,
            evidence_refs={"static_candidate_ids": [entry.static_candidate_id] if entry.static_candidate_id else [],
                           "correlation_ids": [entry.correlation_id], "transaction_ids": tx_ids, "action_ids": action_ids,
                           "runtime_action_ids": sorted({a["action_id"] for a in runtime})}))
    return EndpointContextArtifact(session_id=api_correlation.session_id, endpoints=endpoints,
                                   summary={"endpoint_context_count": len(endpoints),
                                            "runtime_observed_count": sum(e.dynamic["observed"] for e in endpoints),
                                            "static_only_count": sum(c.match_type == "static_only" for c in api_correlation.correlations),
                                            "dynamic_only_count": sum(c.match_type == "dynamic_only" for c in api_correlation.correlations)})
