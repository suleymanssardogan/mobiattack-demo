"""Correlation engine linking HTTP transactions with dynamic flows and markers."""

from __future__ import annotations

from datetime import datetime
import logging
from typing import Any

from src.dynamic.session.models import DynamicSession, EventType
from src.dynamic.traffic.models import TrafficTransaction

logger = logging.getLogger(__name__)

MARKER_CORRELATION_WINDOW_MS = 5000.0


def parse_iso_timestamp(ts: str) -> datetime | None:
    """Parses ISO-8601 UTC timestamp safely."""
    if not ts:
        return None
    try:
        # Handle 'Z' or '+00:00'
        clean = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except Exception:
        return None


class TrafficCorrelator:
    """Correlates HTTP transactions to active TargetFlows and proximate timeline markers."""

    def __init__(
        self,
        session: DynamicSession | None = None,
        in_scope_domains: list[str] | None = None,
        marker_window_ms: float = MARKER_CORRELATION_WINDOW_MS,
    ) -> None:
        self.session = session
        self.in_scope_domains = [d.lower() for d in (in_scope_domains or [])]
        self.marker_window_ms = marker_window_ms

    def correlate(self, transaction: TrafficTransaction) -> TrafficTransaction:
        """Enriches transaction with flow_id, nearest markers, scope, and attribution."""
        req_ts_dt = parse_iso_timestamp(transaction.request.timestamp)

        # 1. Determine Scope
        req_host = (transaction.request.host or "").lower()
        if self.in_scope_domains:
            if any(dom in req_host or req_host == dom for dom in self.in_scope_domains):
                transaction.scope = "IN_SCOPE"
            else:
                transaction.scope = "OUT_OF_SCOPE"
        else:
            transaction.scope = "UNKNOWN"

        # 2. Target App Attribution (Honest modeling as per requirements)
        pkg = self.session.package_name if self.session else "unknown"
        transaction.attribution = {
            "package_name": pkg,
            "confidence": "UNKNOWN",
            "method": "session_time_window",
            "note": "Attribution is probabilistic based on session observation window; system services may traverse device proxy.",
        }

        if not self.session or not req_ts_dt:
            return transaction

        # 3. Flow Correlation (Deterministic Policy: Most recently started ACTIVE flow, or window match)
        matched_flow_id: str | None = None
        overlapping_matches: list[str] = []

        for flow in self.session.flows:
            f_start = parse_iso_timestamp(flow.started_at)
            f_end = parse_iso_timestamp(flow.ended_at) if flow.ended_at else None

            if not f_start:
                continue

            # Check if request timestamp falls within flow window
            if f_start <= req_ts_dt:
                if f_end is None or req_ts_dt <= f_end:
                    overlapping_matches.append(flow.flow_id)

        if len(overlapping_matches) == 1:
            matched_flow_id = overlapping_matches[0]
        elif len(overlapping_matches) > 1:
            # Deterministic policy: select the flow that started latest (closest to event)
            matched_flow_id = overlapping_matches[-1]
            transaction.correlation["overlap_warning"] = (
                f"Multiple flows overlapped at {transaction.request.timestamp}. "
                f"Attributed to most recently started flow {matched_flow_id}."
            )

        transaction.flow_id = matched_flow_id
        transaction.session_id = self.session.session_id

        # 4. Marker Correlation (Find nearest marker before and after within window)
        nearest_before: dict[str, Any] | None = None
        nearest_after: dict[str, Any] | None = None
        min_delta_before_ms: float = float("inf")
        min_delta_after_ms: float = float("inf")

        for event in self.session.timeline:
            ev_type = event.type.value if hasattr(event.type, "value") else str(event.type)
            if ev_type != EventType.MARKER.value:
                continue

            ev_ts_dt = parse_iso_timestamp(event.timestamp)
            if not ev_ts_dt:
                continue

            delta_ms = (req_ts_dt - ev_ts_dt).total_seconds() * 1000.0

            # Marker occurred BEFORE or AT request time
            if 0.0 <= delta_ms <= self.marker_window_ms:
                if delta_ms < min_delta_before_ms:
                    min_delta_before_ms = delta_ms
                    nearest_before = {
                        "name": event.name,
                        "delta_ms": round(delta_ms, 1),
                        "event_id": event.event_id,
                    }
            # Marker occurred AFTER request time
            elif -self.marker_window_ms <= delta_ms < 0.0:
                abs_delta = abs(delta_ms)
                if abs_delta < min_delta_after_ms:
                    min_delta_after_ms = abs_delta
                    nearest_after = {
                        "name": event.name,
                        "delta_ms": round(abs_delta, 1),
                        "event_id": event.event_id,
                    }

        if nearest_before:
            transaction.correlation["nearest_marker_before"] = nearest_before
        if nearest_after:
            transaction.correlation["nearest_marker_after"] = nearest_after

        return transaction
