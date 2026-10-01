"""Route Graph implementation for tracking UI screen states and transitions (Week 1 — Day 5 Task 5.1).

Maintains an in-memory graph of:
- Screen states as RouteNodes (deduplicated by screen_identity)
- Potential interactions as DiscoveredActions
- Observed screen transitions as RouteEdges
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import uuid
from typing import Any

from src.dynamic.route.models import (
    DiscoveredAction,
    RouteEdge,
    RouteNode,
    compute_action_id,
    compute_edge_id,
    compute_node_id,
    utc_now_iso,
)
from src.dynamic.ui.models import ActionCandidate, ScreenObservation

SCHEMA_VERSION: str = "1.0"


class RouteGraph:
    """Deterministic graph container of observed screens and recorded transitions."""

    def __init__(
        self,
        graph_id: str | None = None,
        run_id: str | None = None,
        session_id: str | None = None,
        created_at: str | None = None,
        updated_at: str | None = None,
        root_node_id: str | None = None,
        current_node_id: str | None = None,
    ) -> None:
        now = created_at or utc_now_iso()
        if graph_id:
            self.graph_id = str(graph_id).strip()
        elif run_id:
            digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:12]
            self.graph_id = f"graph_{digest}"
        else:
            self.graph_id = f"graph_{uuid.uuid4().hex[:12]}"

        self.schema_version = SCHEMA_VERSION
        self.run_id = str(run_id).strip() if run_id else None
        self.session_id = str(session_id).strip() if session_id else None
        self.created_at = now
        self.updated_at = updated_at or now
        self.root_node_id = root_node_id
        self.current_node_id = current_node_id

        self.nodes: dict[str, RouteNode] = {}
        self.edges: dict[str, RouteEdge] = {}
        self._identity_to_node_id: dict[str, str] = {}

    @property
    def node_count(self) -> int:
        """Returns total number of unique observed screen nodes."""
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        """Returns total number of unique recorded transitions."""
        return len(self.edges)

    @property
    def discovered_action_count(self) -> int:
        """Returns total number of discovered actions across all nodes."""
        return sum(len(node.actions) for node in self.nodes.values())

    def get_node(self, node_id: str) -> RouteNode | None:
        """Retrieves a node by its route_node_id."""
        return self.nodes.get(node_id)

    def get_node_by_identity(self, screen_identity: str) -> RouteNode | None:
        """Retrieves a node by its screen_identity."""
        node_id = self._identity_to_node_id.get(screen_identity)
        if node_id:
            return self.nodes.get(node_id)
        return None

    def get_edge(self, edge_id: str) -> RouteEdge | None:
        """Retrieves an edge by its edge_id."""
        return self.edges.get(edge_id)

    def observe_screen(
        self,
        observation: ScreenObservation,
        timestamp: str | None = None,
    ) -> RouteNode:
        """Observes a screen state, adding a new RouteNode or deduplicating an existing one.

        Side-effect-free: does not execute any taps, inputs, or navigation actions.
        """
        ts = timestamp or observation.timestamp or utc_now_iso()
        screen_id = observation.screen_identity

        if screen_id in self._identity_to_node_id:
            # Re-observed screen: reuse existing node and merge newly discovered elements
            node_id = self._identity_to_node_id[screen_id]
            node = self.nodes[node_id]
            node.merge_observation(observation, timestamp=ts)
            self.current_node_id = node.route_node_id
            self.updated_at = ts
            return node

        # New screen state
        node = RouteNode.from_observation(observation, timestamp=ts)
        self.nodes[node.route_node_id] = node
        self._identity_to_node_id[screen_id] = node.route_node_id

        # First observed screen becomes root node
        if self.root_node_id is None:
            self.root_node_id = node.route_node_id

        self.current_node_id = node.route_node_id
        self.updated_at = ts
        return node

    def record_transition(
        self,
        source_node: RouteNode | str,
        action: DiscoveredAction | ActionCandidate | str,
        target_observation: ScreenObservation,
        timestamp: str | None = None,
        success: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> RouteEdge:
        """Records an observed transition from source_node via action to target_observation.

        - If target_observation was already observed, target node is deduplicated.
        - If the exact transition (source -> action -> target) was already observed,
          observation_count is incremented instead of creating a duplicate edge.
        - Supports self-loops where source and target screen states are identical.
        """
        ts = timestamp or utc_now_iso()

        # Resolve source node ID
        if isinstance(source_node, RouteNode):
            src_node_id = source_node.route_node_id
        elif isinstance(source_node, str):
            if source_node in self.nodes:
                src_node_id = source_node
            elif source_node in self._identity_to_node_id:
                src_node_id = self._identity_to_node_id[source_node]
            else:
                src_node_id = source_node
        else:
            raise TypeError(f"Invalid source_node type: {type(source_node)}")

        # Ensure target observation is registered in the graph
        target_node = self.observe_screen(target_observation, timestamp=ts)
        target_node_id = target_node.route_node_id

        # Resolve action ID and action type
        if isinstance(action, DiscoveredAction):
            act_id = action.action_id
            act_type = action.action_type
        elif isinstance(action, ActionCandidate):
            # Compute action ID relative to source screen identity
            src_node = self.nodes.get(src_node_id)
            src_screen_id = src_node.screen_identity if src_node else ""
            act_id = compute_action_id(src_screen_id, action.node_id, action.action_type)
            act_type = action.action_type
        elif isinstance(action, str):
            act_id = action
            act_type = "click"
        else:
            raise TypeError(f"Invalid action type: {type(action)}")

        edge_id = compute_edge_id(src_node_id, act_id, target_node_id)

        if edge_id in self.edges:
            existing_edge = self.edges[edge_id]
            existing_edge.observation_count += 1
            if metadata:
                existing_edge.metadata.update(metadata)
            self.updated_at = ts
            return existing_edge

        new_edge = RouteEdge(
            edge_id=edge_id,
            source_node_id=src_node_id,
            target_node_id=target_node_id,
            action_id=act_id,
            action_type=act_type,
            created_at=ts,
            observation_count=1,
            success=success,
            metadata=metadata or {},
        )
        self.edges[edge_id] = new_edge
        self.updated_at = ts
        return new_edge

    def to_dict(self) -> dict[str, Any]:
        """Serializes route graph to standardized dictionary."""
        return {
            "schema_version": self.schema_version,
            "graph_id": self.graph_id,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "root_node_id": self.root_node_id,
            "current_node_id": self.current_node_id,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "discovered_action_count": self.discovered_action_count,
            "nodes": [node.to_dict() for node in sorted(self.nodes.values(), key=lambda n: n.route_node_id)],
            "edges": [edge.to_dict() for edge in sorted(self.edges.values(), key=lambda e: e.edge_id)],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RouteGraph:
        """Deserializes route graph from standardized dictionary."""
        graph = cls(
            graph_id=data.get("graph_id"),
            run_id=data.get("run_id"),
            session_id=data.get("session_id"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            root_node_id=data.get("root_node_id"),
            current_node_id=data.get("current_node_id"),
        )
        graph.schema_version = data.get("schema_version", SCHEMA_VERSION)

        nodes_list = data.get("nodes", [])
        for node_data in nodes_list:
            node = RouteNode.from_dict(node_data)
            graph.nodes[node.route_node_id] = node
            graph._identity_to_node_id[node.screen_identity] = node.route_node_id

        edges_list = data.get("edges", [])
        for edge_data in edges_list:
            edge = RouteEdge.from_dict(edge_data)
            graph.edges[edge.edge_id] = edge

        return graph
