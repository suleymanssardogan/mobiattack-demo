"""Artifacts responsibilities for the demo pipeline."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable
import logging

logger = logging.getLogger(__name__)


def _wire_endpoint_contexts(
    root_path: Path,
    transactions: list[Any] | None = None,
    traffic_evidence: Any | None = None,
    timeline_recorder: Any | None = None,
) -> Any:
    """Task 7.2: build passive context only after canonical correlation exists."""
    try:
        import json
        from src.dynamic.context import build_endpoint_contexts
        from src.dynamic.correlation.models import ApiCorrelationResult
        from src.dynamic.runtime.models import RuntimeEvidenceArtifact
        from src.dynamic.traffic.models import TrafficEvidenceArtifact

        dynamic_dir = root_path / "dynamic"
        corr_file = dynamic_dir / "api_correlation.json"
        if not corr_file.is_file():
            return None
        correlation = ApiCorrelationResult.load(corr_file)
        if transactions is None:
            traffic_file = dynamic_dir / "traffic.json"
            transactions = json.loads(traffic_file.read_text()).get("transactions", []) if traffic_file.is_file() else []
        if traffic_evidence is None and (dynamic_dir / "traffic_evidence.json").is_file():
            traffic_evidence = TrafficEvidenceArtifact.load_or_create(dynamic_dir / "traffic_evidence.json", correlation.session_id)
        runtime_file = dynamic_dir / "runtime_evidence.json"
        runtime_evidence = None
        if runtime_file.is_file():
            try:
                runtime_evidence = RuntimeEvidenceArtifact.from_dict(json.loads(runtime_file.read_text()))
            except Exception as exc:
                logger.warning("Could not read runtime evidence for endpoint contexts: %s", exc)
        result = build_endpoint_contexts(correlation, transactions, traffic_evidence, runtime_evidence)
        result.save_atomic(dynamic_dir / "endpoint_contexts.json")
        if timeline_recorder and hasattr(timeline_recorder, "_record_system_event"):
            try:
                timeline_recorder._record_system_event("ENDPOINT_CONTEXTS_BUILT", dict(result.summary))
            except Exception as exc:
                logger.warning("Could not record ENDPOINT_CONTEXTS_BUILT: %s", exc)
        return result
    except Exception as exc:
        logger.error("Endpoint context builder failed (isolated): %s", exc, exc_info=True)
        return None


def _wire_api_correlation(
    root_path: Path,
    session_id: str,
    timeline_recorder: Any | None = None,
    traffic_service: Any | None = None,
    *,
    _wire_endpoint_contexts: Callable,
) -> Any:
    """Task 7.1: Correlates static API candidates with captured dynamic traffic transactions.

    Persists dynamic/api_correlation.json atomically.
    Failure-isolated: prior evidence is never modified or erased.
    """
    try:
        import json
        from src.dynamic.correlation import correlate_static_dynamic_apis
        from src.dynamic.traffic.models import TrafficEvidenceArtifact

        dynamic_dir = root_path / "dynamic"
        corr_file = dynamic_dir / "api_correlation.json"

        # 1. Load static candidates from static_analysis_report.json if available
        static_report_path = root_path / "static_analysis_report.json"
        static_candidates: list[Any] = []
        if static_report_path.is_file():
            try:
                with open(static_report_path, "r", encoding="utf-8") as f:
                    static_data = json.load(f)
                static_candidates = static_data.get("api_candidates", [])
            except Exception as exc:
                logger.warning("Could not read static candidates for correlation: %s", exc)

        # 2. Collect dynamic transactions and visibility context
        transactions: list[Any] = []
        http_vis = "available"
        https_vis = "unavailable"
        https_reason = "certificate_trust_unknown"

        traffic_file = dynamic_dir / "traffic.json"
        if traffic_service and getattr(traffic_service, "captured_transactions", None):
            transactions = list(traffic_service.captured_transactions)
            visibility = traffic_service.get_visibility_metadata()
            http_vis = visibility.get('http_visibility', 'unknown')
            https_vis = visibility.get('https_visibility', 'unknown')
            https_reason = visibility.get('https_reason', 'no_https_transaction_available_to_verify')
        elif traffic_file.is_file():
            try:
                with open(traffic_file, "r", encoding="utf-8") as f:
                    traffic_data = json.load(f)
                transactions = traffic_data.get("transactions", [])
                http_vis = traffic_data.get("http_visibility", "available")
                https_vis = traffic_data.get("https_visibility", "unavailable")
                https_reason = traffic_data.get("https_visibility_reason", "certificate_trust_unknown")
            except Exception as exc:
                logger.warning("Could not read traffic.json for correlation: %s", exc)

        # 3. Load traffic_evidence.json if available
        traffic_evidence_file = dynamic_dir / "traffic_evidence.json"
        traffic_evidence = None
        if traffic_evidence_file.is_file():
            try:
                traffic_evidence = TrafficEvidenceArtifact.load_or_create(traffic_evidence_file, session_id=session_id)
            except Exception as exc:
                logger.warning("Could not read traffic_evidence.json for correlation: %s", exc)

        # 4. Perform correlation
        corr_result = correlate_static_dynamic_apis(
            static_candidates=static_candidates,
            traffic_transactions=transactions,
            session_id=session_id,
            traffic_evidence=traffic_evidence,
            http_visibility=http_vis,
            https_visibility=https_vis,
            https_visibility_reason=https_reason,
        )

        # 5. Atomically persist api_correlation.json
        corr_result.save_atomic(corr_file)

        # 6. Record compact timeline event if timeline_recorder available
        if timeline_recorder and hasattr(timeline_recorder, "_record_system_event"):
            try:
                timeline_recorder._record_system_event(
                    "API_CORRELATION_COMPLETED",
                    {
                        "static_candidates": corr_result.summary.static_candidate_count,
                        "dynamic_endpoints": corr_result.summary.dynamic_endpoint_count,
                        "correlated_count": corr_result.summary.correlated_count,
                        "static_only": corr_result.summary.static_only_count,
                        "dynamic_only": corr_result.summary.dynamic_only_count,
                    },
                )
            except Exception as exc:
                logger.warning("Could not record API_CORRELATION_COMPLETED event: %s", exc)

        _wire_endpoint_contexts(root_path, transactions, traffic_evidence, timeline_recorder)

        return corr_result
    except Exception as exc:
        logger.error("Static <-> Dynamic API correlation failed (isolated): %s", exc, exc_info=True)
        return None
