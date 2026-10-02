"""Pure and deterministic Static <-> Dynamic API Correlation engine (Week 2 — Day 7 Task 7.1)."""

from __future__ import annotations

from collections import Counter, defaultdict
import logging
import ipaddress
from pathlib import Path
import re
from typing import Any
import urllib.parse

from src.dynamic.correlation.models import (
    ApiCorrelationEntry,
    ApiCorrelationResult,
    ApiCorrelationSummary,
    MatchConfidence,
    MatchType,
    generate_deterministic_correlation_id,
    sanitize_provenance_paths,
)
from src.dynamic.traffic.models import TrafficTransaction

logger = logging.getLogger(__name__)

def _dict_session(value: Any) -> str | None:
    return value.get("session_id") if isinstance(value, dict) else None


def normalize_host(raw_host: str | None) -> str:
    """Safely normalizes host string without merging subdomains.
    
    Rules:
    - Lowercase
    - Strip whitespace and trailing dots
    - Remove default ports (:80, :443)
    - Preserve non-default ports if included in host string
    - Extract netloc if a full URL was accidentally passed
    """
    if not raw_host:
        return ""
    h = str(raw_host).strip()
    if "://" in h:
        parsed = urllib.parse.urlsplit(h)
        h = parsed.netloc or parsed.path.split("/")[0]
    elif "/" in h:
        h = h.split("/")[0]

    h = h.strip().lower().rstrip(".")
    if h.endswith(":80"):
        h = h[:-3]
    elif h.endswith(":443"):
        h = h[:-4]
    return h


def normalize_transport(raw_host: str, scheme: str | None, port: Any = None) -> tuple[str, str | None, int | None]:
    """Canonical authority, explicit protocol and effective port; no cross-protocol inference."""
    try:
        authority = raw_host
        try:
            if isinstance(ipaddress.ip_address(raw_host), ipaddress.IPv6Address):
                authority = "[" + raw_host + "]"
        except ValueError:
            pass
        parsed = urllib.parse.urlsplit(authority if "://" in authority else "//" + authority)
        protocol = (scheme or parsed.scheme or "").lower()
        if protocol not in {"http", "https"}:
            return normalize_host(raw_host), None, None
        if parsed.scheme and parsed.scheme.lower() != protocol:
            return normalize_host(raw_host), None, None
        embedded_port = parsed.port
        if port is not None and (isinstance(port, bool) or str(port) != str(int(port))):
            return normalize_host(raw_host), None, None
        explicit_port = int(port) if port is not None else embedded_port
        if embedded_port is not None and port is not None and embedded_port != explicit_port:
            return normalize_host(raw_host), None, None
        effective = explicit_port if explicit_port is not None else (443 if protocol == "https" else 80)
        if not 1 <= effective <= 65535 or not parsed.hostname or parsed.username or parsed.password:
            return normalize_host(raw_host), None, None
        return parsed.hostname.lower().rstrip("."), protocol, effective
    except (TypeError, ValueError):
        return normalize_host(raw_host), None, None


def normalize_path(raw_path: str | None) -> str:
    """Normalizes path for endpoint comparison.
    
    Rules:
    - Exclude query strings and fragments
    - Ensure leading slash
    - Collapse consecutive slashes
    - Strip trailing slash for paths longer than 1 character
    """
    if not raw_path:
        return "/"
    p = str(raw_path).strip()
    # Exclude query or fragment
    if "?" in p:
        p = p.split("?")[0]
    if "#" in p:
        p = p.split("#")[0]

    if not p.startswith("/"):
        p = "/" + p
    # Collapse duplicate slashes
    p = re.sub(r"/+", "/", p)
    # Strip trailing slash if not root
    if len(p) > 1 and p.endswith("/"):
        p = p.rstrip("/")
    return p


def normalize_method(raw_method: str | None) -> str | None:
    """Normalizes HTTP method to uppercase or None."""
    if not raw_method:
        return None
    m = str(raw_method).strip().upper()
    return m if m else None


def is_template_param(seg: str) -> bool:
    """Returns True if path segment is a recognized template placeholder: {id}, :id, <id>."""
    if not seg:
        return False
    if seg.startswith("{") and seg.endswith("}") and len(seg) > 2:
        return True
    if seg.startswith(":") and len(seg) > 1:
        return True
    if seg.startswith("<") and seg.endswith(">") and len(seg) > 2:
        return True
    return False


def match_paths(static_path: str, dynamic_path: str) -> tuple[bool, bool]:
    """Compares paths directionally: only explicit static placeholders are templates.

    A placeholder matches one non-empty concrete dynamic segment, never a slash.
    Numeric and UUID literals have no special matching semantics.
    
    Returns:
        (is_match, is_template):
        - (True, False): exact path match
        - (True, True): template/parameter path match
        - (False, False): no match
    """
    s_norm = normalize_path(static_path)
    d_norm = normalize_path(dynamic_path)

    if s_norm == d_norm:
        return True, False

    s_segs = [s for s in s_norm.strip("/").split("/") if s]
    d_segs = [d for d in d_norm.strip("/").split("/") if d]

    if len(s_segs) != len(d_segs):
        return False, False

    if not s_segs and not d_segs:
        return True, False

    matched_template = False
    for s, d in zip(s_segs, d_segs):
        if s == d:
            continue
        if is_template_param(s) and d and not is_template_param(d):
            matched_template = True
            continue
        return False, False

    return True, matched_template


def _extract_query_keys(query: Any) -> list[str]:
    """Extracts only query parameter keys (never values) for privacy."""
    if not query:
        return []
    keys: set[str] = set()
    if isinstance(query, dict):
        for k in query.keys():
            if k:
                keys.add(str(k))
    elif isinstance(query, str):
        for k, _ in urllib.parse.parse_qsl(query, keep_blank_values=True):
            if k:
                keys.add(str(k))
    return sorted(list(keys))


def _parse_static_candidate(cand: Any, index: int) -> dict[str, Any]:
    """Normalizes arbitrary static candidate structures into canonical form."""
    if isinstance(cand, str):
        cand = {"full_url": cand}
    elif not isinstance(cand, dict):
        cand = {}

    source_id_field = next(
        (key for key in ("id", "candidate_id", "endpoint_id") if cand.get(key)), None
    )
    # Keep the existing deterministic ordinal reference when the source has no ID.
    # This reference is generated by correlation, not added to the static report.
    cand_id = cand[source_id_field] if source_id_field else f"stat_cand_{index + 1}"

    full_url = cand.get("full_url") or cand.get("url")
    base_url = cand.get("base_url")
    path_val = cand.get("path")
    method_val = cand.get("method")

    scheme = ""
    host = ""
    path = ""

    if full_url:
        u_str = str(full_url).strip()
        parsed = urllib.parse.urlsplit(u_str if "://" in u_str else "//" + u_str)
        scheme = parsed.scheme
        host = parsed.netloc or cand.get("host", "")
        path = parsed.path or path_val or "/"
    elif base_url:
        b_str = str(base_url).strip()
        parsed = urllib.parse.urlsplit(b_str if "://" in b_str else "//" + b_str)
        scheme = parsed.scheme
        host = parsed.netloc or b_str
        if path_val:
            base_p = parsed.path.rstrip("/")
            rel_p = str(path_val).lstrip("/")
            path = f"{base_p}/{rel_p}" if base_p else f"/{rel_p}"
        else:
            path = parsed.path or "/"
    else:
        host = cand.get("host", "")
        path = path_val or "/"
        scheme = cand.get("scheme", "")

    norm_host, scheme, effective_port = normalize_transport(host, scheme, cand.get("port"))
    norm_path = normalize_path(path)
    norm_method = normalize_method(method_val)

    provenance: dict[str, Any] = {
        "static_candidate_id_origin": "source_report" if source_id_field else "correlation_reference",
        "static_candidate_id_source_field": source_id_field,
    }
    if "source_file" in cand and cand["source_file"]:
        provenance["source_file"] = sanitize_provenance_paths(str(cand["source_file"]))
    if "request_line" in cand and cand["request_line"]:
        provenance["request_line"] = cand["request_line"]
    if "framework" in cand and cand["framework"]:
        provenance["framework"] = cand["framework"]
    if "evidence" in cand and isinstance(cand["evidence"], dict):
        provenance["evidence"] = sanitize_provenance_paths(cand["evidence"])

    return {
        "candidate_id": cand_id,
        "host": norm_host,
        "path": norm_path,
        "method": norm_method,
        "scheme": scheme,
        "effective_port": effective_port,
        "provenance": provenance,
        "raw": cand,
    }


def _parse_dynamic_transaction(tx: Any, index: int) -> dict[str, Any]:
    """Normalizes arbitrary transaction object or dict into canonical matching format."""
    tx_id = getattr(tx, "transaction_id", None)
    if tx_id is None and isinstance(tx, dict):
        tx_id = tx.get("transaction_id")
    if not tx_id:
        tx_id = f"tx_{index + 1}"

    req = getattr(tx, "request", None)
    if req is None and isinstance(tx, dict):
        req = tx.get("request", {})

    host = getattr(req, "host", None) if req else None
    if host is None and isinstance(req, dict):
        host = req.get("host")

    path = getattr(req, "path", None) if req else None
    if path is None and isinstance(req, dict):
        path = req.get("path")

    method = getattr(req, "method", None) if req else None
    if method is None and isinstance(req, dict):
        method = req.get("method")

    query = getattr(req, "query", None) if req else None
    if query is None and isinstance(req, dict):
        query = req.get("query")

    timestamp = getattr(req, "timestamp", None) if req else None
    if timestamp is None and isinstance(req, dict):
        timestamp = req.get("timestamp")

    resp = getattr(tx, "response", None)
    if resp is None and isinstance(tx, dict):
        resp = tx.get("response")

    status_code = getattr(resp, "status_code", None) if resp else None
    if status_code is None and isinstance(resp, dict):
        status_code = resp.get("status_code", 0)
    status_code = int(status_code) if status_code is not None else 0

    scheme = getattr(req, "scheme", None) if req else None
    port = getattr(req, "port", None) if req else None
    if isinstance(req, dict):
        scheme, port = req.get("scheme"), req.get("port")
    norm_host, scheme, effective_port = normalize_transport(host or "", scheme, port)
    tx_session = getattr(tx, "session_id", None)
    if isinstance(tx, dict):
        tx_session = tx.get("session_id")

    return {
        "transaction_id": str(tx_id),
        "host": norm_host,
        "scheme": scheme,
        "effective_port": effective_port,
        "session_id": tx_session,
        "path": normalize_path(path or "/"),
        "method": normalize_method(method) or "GET",
        "query_keys": _extract_query_keys(query),
        "timestamp": str(timestamp) if timestamp else "",
        "status_code": status_code,
    }


def correlate_static_dynamic_apis(
    static_candidates: list[Any] | None,
    traffic_transactions: list[Any] | None,
    session_id: str = "",
    traffic_evidence: Any | None = None,
    http_visibility: str = "available",
    https_visibility: str = "unavailable",
    https_visibility_reason: str = "certificate_trust_unknown",
) -> ApiCorrelationResult:
    """Pure, deterministic correlation between static candidates and observed traffic transactions.
    
    Zero emulator/ADB/proxy dependency. Pure evidence-backed evaluation.
    """
    raw_static = static_candidates if isinstance(static_candidates, list) else []
    raw_traffic = traffic_transactions if isinstance(traffic_transactions, list) else []

    parsed_static = [_parse_static_candidate(c, i) for i, c in enumerate(raw_static)]
    parsed_traffic = []
    for index, raw_tx in enumerate(raw_traffic):
        data = raw_tx.to_dict() if hasattr(raw_tx, "to_dict") else raw_tx
        if not isinstance(data, dict) or not isinstance(data.get("transaction_id"), str) or not data["transaction_id"]:
            continue
        request = data.get("request")
        if (not isinstance(request, dict) or not all(isinstance(request.get(k), str) and request[k]
                for k in ("host", "path", "method")) or data.get("synthetic") or data.get("internal")
                or request.get("synthetic") or request.get("internal")):
            continue
        response = data.get("response")
        if response is not None and (not isinstance(response, dict) or response.get("synthetic") or response.get("internal")
                or not isinstance(response.get("status_code"), int) or isinstance(response.get("status_code"), bool)):
            continue
        if any(request.get(key) is not None and not isinstance(request[key], dict) for key in ("headers", "body_metadata")):
            continue
        try:
            tx = _parse_dynamic_transaction(raw_tx, index)
        except (ValueError, TypeError, AttributeError):
            continue
        if tx["scheme"] and (not tx["session_id"] or tx["session_id"] == session_id):
            parsed_traffic.append(tx)
    id_counts = Counter(tx["transaction_id"] for tx in parsed_traffic)
    parsed_traffic = [tx for tx in parsed_traffic if id_counts[tx["transaction_id"]] == 1]

    # Map transaction_id -> associated action_ids and route_context
    tx_to_actions: dict[str, list[str]] = defaultdict(list)
    tx_to_routes: dict[str, list[dict[str, Any]]] = defaultdict(list)

    if traffic_evidence and getattr(traffic_evidence, "session_id", _dict_session(traffic_evidence)) == session_id:
        actions_list = []
        if hasattr(traffic_evidence, "actions"):
            actions_list = traffic_evidence.actions
        elif isinstance(traffic_evidence, dict) and "actions" in traffic_evidence:
            actions_list = traffic_evidence.get("actions", [])

        for act in actions_list:
            data = act.to_dict() if hasattr(act, "to_dict") else act
            if (not isinstance(data, dict) or not data.get("action_id") or not data.get("source_node_id")
                    or data.get("session_id", session_id) != session_id
                    or data.get("correlation_status") not in ("available", "partial")
                    or not isinstance(data.get("transaction_ids"), list)):
                continue
            act_id = getattr(act, "action_id", None)
            if act_id is None and isinstance(act, dict):
                act_id = act.get("action_id", "")
            t_ids = getattr(act, "transaction_ids", None)
            if t_ids is None and isinstance(act, dict):
                t_ids = act.get("transaction_ids", [])
            src_node = getattr(act, "source_node_id", None)
            if src_node is None and isinstance(act, dict):
                src_node = act.get("source_node_id", "")
            tgt_node = getattr(act, "target_node_id", None)
            if tgt_node is None and isinstance(act, dict):
                tgt_node = act.get("target_node_id")

            route_item = {
                "action_id": act_id,
                "source_node_id": src_node,
                "target_node_id": tgt_node,
            }

            for tid in t_ids:
                if act_id and act_id not in tx_to_actions[tid]:
                    tx_to_actions[tid].append(act_id)
                if route_item not in tx_to_routes[tid]:
                    tx_to_routes[tid].append(route_item)

    # For each transaction, find best matching static candidate (if any)
    # Match score ranking:
    # 4: exact host + exact path + matching method
    # 3: exact host + template path + matching method
    # 2: exact host + exact path + static method unknown
    # 1: exact host + template path + static method unknown
    # 0: exact host + path match + method mismatch
    static_to_matched_txs: dict[int, list[tuple[dict[str, Any], str, str]]] = defaultdict(list)
    matched_tx_ids: set[str] = set()

    for tx in parsed_traffic:
        best_cand_idx: int | None = None
        best_score = -1
        best_match_type = ""
        best_conf = ""

        for idx, sc in enumerate(parsed_static):
            if (not sc["scheme"] or not tx["scheme"] or
                    (sc["scheme"], sc["host"], sc["effective_port"]) !=
                    (tx["scheme"], tx["host"], tx["effective_port"])):
                continue

            is_match, is_tmpl = match_paths(sc["path"], tx["path"])
            if not is_match:
                continue

            if sc["method"]:
                if sc["method"] == tx["method"]:
                    if is_tmpl:
                        score, m_type, conf = 3, MatchType.TEMPLATE.value, MatchConfidence.MEDIUM.value
                    else:
                        score, m_type, conf = 4, MatchType.EXACT.value, MatchConfidence.HIGH.value
                else:
                    score, m_type, conf = 0, MatchType.METHOD_MISMATCH.value, MatchConfidence.LOW.value
            else:
                if is_tmpl:
                    score, m_type, conf = 1, MatchType.TEMPLATE.value, MatchConfidence.MEDIUM.value
                else:
                    score, m_type, conf = 2, MatchType.HOST_PATH.value, MatchConfidence.MEDIUM.value

            if score > best_score:
                best_score = score
                best_cand_idx = idx
                best_match_type = m_type
                best_conf = conf

        if best_cand_idx is not None:
            static_to_matched_txs[best_cand_idx].append((tx, best_match_type, best_conf))
            matched_tx_ids.add(tx["transaction_id"])

    correlations: list[ApiCorrelationEntry] = []
    correlated_count = 0
    static_only_count = 0

    # Process all static candidates (either correlated or static_only)
    for idx, sc in enumerate(parsed_static):
        matched = static_to_matched_txs.get(idx, [])
        if matched:
            correlated_count += 1
            tx_list = [item[0] for item in matched]
            match_types = [item[1] for item in matched]
            confidences = [item[2] for item in matched]

            # Priority for overall match_type: exact > template > host_path > method_mismatch
            if MatchType.EXACT.value in match_types:
                entry_match_type = MatchType.EXACT.value
                entry_conf = MatchConfidence.HIGH.value
            elif MatchType.TEMPLATE.value in match_types:
                entry_match_type = MatchType.TEMPLATE.value
                entry_conf = MatchConfidence.MEDIUM.value
            elif MatchType.HOST_PATH.value in match_types:
                entry_match_type = MatchType.HOST_PATH.value
                entry_conf = MatchConfidence.MEDIUM.value
            else:
                entry_match_type = MatchType.METHOD_MISMATCH.value
                entry_conf = MatchConfidence.LOW.value

            tx_ids = sorted(list({t["transaction_id"] for t in tx_list}))
            obs_methods = sorted(list({t["method"] for t in tx_list}))
            obs_codes = sorted(list({t["status_code"] for t in tx_list if t["status_code"] > 0}))
            all_timestamps = [t["timestamp"] for t in tx_list if t["timestamp"]]
            first_obs = min(all_timestamps) if all_timestamps else None
            last_obs = max(all_timestamps) if all_timestamps else None

            action_ids: set[str] = set()
            route_ctx: list[dict[str, Any]] = []
            query_keys: set[str] = set()

            for t in tx_list:
                tid = t["transaction_id"]
                action_ids.update(tx_to_actions.get(tid, []))
                for r in tx_to_routes.get(tid, []):
                    if r not in route_ctx:
                        route_ctx.append(r)
                query_keys.update(t["query_keys"])

            corr_id = generate_deterministic_correlation_id(
                static_candidate_id=sc["candidate_id"],
                host=sc["host"],
                path=sc["path"],
                match_type=entry_match_type,
                method=sc["method"],
                scheme=sc["scheme"], port=sc["effective_port"],
            )

            correlations.append(
                ApiCorrelationEntry(
                    correlation_id=corr_id,
                    match_type=entry_match_type,
                    confidence=entry_conf,
                    host=sc["host"],
                    path=sc["path"],
                    scheme=sc["scheme"], port=sc["effective_port"],
                    static_candidate_id=sc["candidate_id"],
                    transaction_ids=tx_ids,
                    static_method=sc["method"],
                    observed_methods=obs_methods,
                    observed_status_codes=obs_codes,
                    first_observed_at=first_obs,
                    last_observed_at=last_obs,
                    observation_count=len(tx_list),
                    observed_action_ids=sorted(list(action_ids)),
                    observed_query_keys=sorted(list(query_keys)),
                    route_context=route_ctx,
                    provenance=sc["provenance"],
                    notes=None,
                )
            )
        else:
            static_only_count += 1
            corr_id = generate_deterministic_correlation_id(
                static_candidate_id=sc["candidate_id"],
                host=sc["host"],
                path=sc["path"],
                match_type=MatchType.STATIC_ONLY.value,
                method=sc["method"],
                scheme=sc["scheme"], port=sc["effective_port"],
            )

            note = "not observed in available runtime traffic"
            if https_visibility != "available" and sc.get("scheme") == "https":
                note = f"not observed in available runtime traffic (HTTPS interception: {https_visibility})"

            correlations.append(
                ApiCorrelationEntry(
                    correlation_id=corr_id,
                    match_type=MatchType.STATIC_ONLY.value,
                    confidence=MatchConfidence.LOW.value,
                    host=sc["host"],
                    path=sc["path"],
                    scheme=sc["scheme"], port=sc["effective_port"],
                    static_candidate_id=sc["candidate_id"],
                    transaction_ids=[],
                    static_method=sc["method"],
                    observed_methods=[],
                    observed_status_codes=[],
                    first_observed_at=None,
                    last_observed_at=None,
                    observation_count=0,
                    observed_action_ids=[],
                    observed_query_keys=[],
                    route_context=[],
                    provenance=sc["provenance"],
                    notes=note,
                )
            )

    # Process unmatched dynamic transactions (group by host + path) -> dynamic_only
    dynamic_only_groups: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for tx in parsed_traffic:
        if tx["transaction_id"] not in matched_tx_ids:
            dynamic_only_groups[(tx["scheme"], tx["host"], tx["effective_port"], tx["path"], tx["method"])].append(tx)

    dynamic_only_count = len(dynamic_only_groups)
    for (d_scheme, d_host, d_port, d_path, d_method), tx_group in sorted(dynamic_only_groups.items(), key=lambda item: str(item[0])):
        tx_ids = sorted(list({t["transaction_id"] for t in tx_group}))
        obs_methods = sorted(list({t["method"] for t in tx_group}))
        obs_codes = sorted(list({t["status_code"] for t in tx_group if t["status_code"] > 0}))
        all_timestamps = [t["timestamp"] for t in tx_group if t["timestamp"]]
        first_obs = min(all_timestamps) if all_timestamps else None
        last_obs = max(all_timestamps) if all_timestamps else None

        action_ids: set[str] = set()
        route_ctx: list[dict[str, Any]] = []
        query_keys: set[str] = set()

        for t in tx_group:
            tid = t["transaction_id"]
            action_ids.update(tx_to_actions.get(tid, []))
            for r in tx_to_routes.get(tid, []):
                if r not in route_ctx:
                    route_ctx.append(r)
            query_keys.update(t["query_keys"])

        first_method = obs_methods[0] if obs_methods else "GET"
        corr_id = generate_deterministic_correlation_id(
            static_candidate_id=None,
            host=d_host,
            path=d_path,
            match_type=MatchType.DYNAMIC_ONLY.value,
            method=first_method,
            scheme=d_scheme, port=d_port,
        )

        correlations.append(
            ApiCorrelationEntry(
                correlation_id=corr_id,
                match_type=MatchType.DYNAMIC_ONLY.value,
                confidence=MatchConfidence.LOW.value,
                host=d_host,
                path=d_path,
                scheme=d_scheme, port=d_port,
                static_candidate_id=None,
                transaction_ids=tx_ids,
                static_method=None,
                observed_methods=obs_methods,
                observed_status_codes=obs_codes,
                first_observed_at=first_obs,
                last_observed_at=last_obs,
                observation_count=len(tx_group),
                observed_action_ids=sorted(list(action_ids)),
                observed_query_keys=sorted(list(query_keys)),
                route_context=route_ctx,
                provenance={},
                notes="observed in runtime traffic; not identified in static analysis candidates",
            )
        )

    # Visibility notes
    visibility_note = None
    if https_visibility != "available":
        visibility_note = (
            f"HTTPS traffic visibility was {https_visibility} ({https_visibility_reason}). "
            "Unobserved static HTTPS candidates were not observable in runtime traffic."
        )

    summary = ApiCorrelationSummary(
        static_candidate_count=len(parsed_static),
        dynamic_endpoint_count=correlated_count + dynamic_only_count,
        correlated_count=correlated_count,
        static_only_count=static_only_count,
        dynamic_only_count=dynamic_only_count,
        http_visibility=http_visibility,
        https_visibility=https_visibility,
        https_visibility_reason=https_visibility_reason,
        visibility_note=visibility_note,
        notes=[],
    )

    return ApiCorrelationResult(
        schema_version="1.0",
        session_id=session_id,
        summary=summary,
        correlations=correlations,
    )
