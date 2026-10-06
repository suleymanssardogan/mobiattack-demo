"""Atomic persistence and serialization for RouteGraph (Week 1 — Day 5 Task 5.1).

Stores route graph to:
    demo_runs/<run_id>/dynamic/route_graph.json
via safe, atomic write-then-rename semantics.
"""

from __future__ import annotations

from src.persistence import write_json_atomic

import json
import logging
from pathlib import Path
from typing import Any

from src.dynamic.route.graph import RouteGraph

logger = logging.getLogger(__name__)

ROUTE_GRAPH_FILENAME: str = "route_graph.json"


class RouteGraphError(Exception):
    """Base exception for RouteGraph persistence and operations."""
    pass


class RouteGraphCorruptionError(RouteGraphError):
    """Raised when route_graph.json exists on disk but is unparseable or corrupted."""
    pass


class RouteGraphStorage:
    """Handles thread-safe, atomic JSON disk operations for RouteGraph."""

    def __init__(self, base_dir: str | Path | None = None) -> None:
        self.base_dir = Path(base_dir).resolve() if base_dir else None

    def resolve_path(self, file_path: str | Path | None = None, run_id: str | None = None) -> Path:
        """Resolves target path for route_graph.json."""
        if file_path:
            return Path(file_path).resolve()

        if self.base_dir:
            # If base_dir already ends with 'dynamic', write directly inside
            if self.base_dir.name == "dynamic":
                return self.base_dir / ROUTE_GRAPH_FILENAME
            return self.base_dir / "dynamic" / ROUTE_GRAPH_FILENAME

        if run_id:
            return Path("demo_runs") / run_id / "dynamic" / ROUTE_GRAPH_FILENAME

        raise ValueError("Must provide file_path, base_dir, or run_id to resolve route graph path.")

    def save_graph(
        self,
        graph: RouteGraph,
        file_path: str | Path | None = None,
        run_id: str | None = None,
    ) -> Path:
        """Atomically persists route graph to JSON on disk."""
        target_path = self.resolve_path(file_path=file_path, run_id=run_id or graph.run_id)
        target_dir = target_path.parent
        target_dir.mkdir(parents=True, exist_ok=True)

        data = graph.to_dict()

        try:
            write_json_atomic(target_path, data)
            return target_path
        except Exception as exc:
            logger.error(f"Failed to persist route graph to '{target_path}': {exc}")
            raise RouteGraphError(f"Failed to persist route graph to '{target_path}': {exc}") from exc

    def load_graph(self, file_path: str | Path | None = None, run_id: str | None = None) -> RouteGraph:
        """Loads and validates a RouteGraph from JSON on disk."""
        target_path = self.resolve_path(file_path=file_path, run_id=run_id)

        if not target_path.is_file():
            raise FileNotFoundError(f"Route graph file not found at '{target_path}'")

        try:
            content = target_path.read_text(encoding="utf-8")
        except Exception as exc:
            raise RouteGraphCorruptionError(f"Cannot read route graph at '{target_path}': {exc}") from exc

        if not content.strip():
            raise RouteGraphCorruptionError(f"Route graph file is empty at '{target_path}'")

        try:
            data = json.loads(content)
        except Exception as exc:
            raise RouteGraphCorruptionError(f"Invalid JSON syntax in route graph at '{target_path}': {exc}") from exc

        if not isinstance(data, dict):
            raise RouteGraphCorruptionError(f"Route graph root must be a JSON object, got {type(data).__name__}")

        if "schema_version" not in data or "nodes" not in data:
            raise RouteGraphCorruptionError(f"Route graph missing required schema fields at '{target_path}'")

        try:
            return RouteGraph.from_dict(data)
        except Exception as exc:
            raise RouteGraphCorruptionError(f"Failed to instantiate RouteGraph from '{target_path}': {exc}") from exc
