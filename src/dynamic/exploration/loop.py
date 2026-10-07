"""Bounded Exploration Loop V1 implementation (Week 1 — Day 5 Task 5.3).

Executes autonomous UI exploration bounded by max_steps, max_depth, and deadline:
1. Observes current screen and registers RouteNode in RouteGraph.
2. Selects the next safe, unattempted click action deterministically.
3. Updates action lifecycle: DISCOVERED -> ATTEMPTED.
4. Executes tap via ActionExecutor.
5. Updates action lifecycle: ATTEMPTED -> SUCCEEDED / FAILED.
6. On success: waits for UI stabilization, re-observes screen, and records transition edge.
7. Persists route_graph.json atomically after each mutation.
8. Records compact, sanitized timeline evidence.
9. Halts on max_steps, max_depth, deadline, external package, or exhausted actions.
"""

from __future__ import annotations

from src.persistence import write_json_atomic
from src.dynamic.deadline import bounded_operation, current_deadline
from src.dynamic.action.completion import wait_for_completion
from src.dynamic.exploration.frontier import build_frontier, exploration_summary

import logging
from pathlib import Path
import time
from typing import Any, Callable

from src.dynamic.action.executor import ActionExecutor
from src.dynamic.action.models import ActionExecutionStatus
from src.dynamic.exploration.models import (
    ExplorationLimits,
    ExplorationResult,
    ExplorationStatus,
    StopReason,
    is_allowed_system_dialog,
    is_safe_clickable_action,
    navigation_skip_reason,
    sanitize_value,
    utc_now_iso,
)
from src.dynamic.route.graph import RouteGraph
from src.dynamic.route.models import ActionStatus, DiscoveredAction, RouteNode
from src.dynamic.route.storage import RouteGraphStorage
from src.dynamic.runtime.models import (
    CorrelationStatus,
    RuntimeActionEvidence,
    RuntimeEvidenceArtifact,
    create_action_runtime_evidence,
)
from src.dynamic.runtime.observer import AndroidRuntimeObserver
from src.dynamic.traffic.models import (
    ActionTrafficEvidence,
    TrafficEvidenceArtifact,
    create_action_traffic_evidence,
)
from src.dynamic.ui.models import ScreenObservation

logger = logging.getLogger(__name__)


def select_next_action(node: RouteNode) -> DiscoveredAction | None:
    """Selects the next unattempted, safe click action sorted deterministically by action_id."""
    candidates = [
        act for act in node.actions.values()
        if is_safe_clickable_action(act, context=node)
    ]
    if not candidates:
        return None

    # Deterministic sorting
    candidates.sort(key=lambda a: a.action_id)
    return candidates[0]


def select_frontier_navigation(graph, current, max_hops):
    """Shortest proven safe route to pending work; no inferred transitions or retries."""
    from collections import deque
    queue = deque([(current.route_node_id, [])])
    visited = {current.route_node_id}
    while queue:
        node_id, path = queue.popleft()
        node = graph.get_node(node_id)
        if path and select_next_action(node) is not None:
            return path[0]
        if len(path) >= max_hops:
            continue
        edges = sorted((e for e in graph.edges.values() if e.source_node_id == node_id and e.success),
                       key=lambda e: (e.action_id, e.target_node_id))
        for edge in edges:
            action = node.actions.get(edge.action_id)
            target = graph.get_node(edge.target_node_id)
            targets = {e.target_node_id for e in edges if e.action_id == edge.action_id}
            if (action is None or action.status != 'succeeded' or navigation_skip_reason(action) is not None
                    or len(targets) != 1 or target is None or not target.is_target_package
                    or edge.target_node_id in visited):
                continue
            visited.add(edge.target_node_id)
            queue.append((edge.target_node_id, path + [action]))
    return None


def _emit_timeline_event(
    recorder: Any | None,
    name: str,
    metadata: dict[str, Any],
) -> None:
    """Emits a compact timeline event if a recorder is configured."""
    if recorder is None:
        return
    try:
        clean_meta = sanitize_value(metadata)
        if hasattr(recorder, "_record_system_event"):
            recorder._record_system_event(name, metadata=clean_meta)
        elif hasattr(recorder, "_record_user_action"):
            recorder._record_user_action(name, metadata=clean_meta)
        elif hasattr(recorder, "append"):
            from src.dynamic.session.models import EventType, TimelineEvent
            recorder.append(
                TimelineEvent(
                    type=EventType.SYSTEM_EVENT,
                    name=name,
                    timestamp=utc_now_iso(),
                    metadata=clean_meta,
                )
            )
        elif callable(recorder):
            recorder(name, clean_meta)
    except Exception as exc:
        logger.warning("Failed to emit timeline event '%s': %s", name, exc)


@bounded_operation(60.0, limits_field="deadline_seconds")
def run_exploration(
    observer: Callable[[], ScreenObservation],
    executor: ActionExecutor,
    route_graph: RouteGraph,
    graph_storage: RouteGraphStorage | None = None,
    timeline_recorder: Any | None = None,
    limits: ExplorationLimits | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    initial_observation: ScreenObservation | None = None,
    runtime_observer: AndroidRuntimeObserver | None = None,
    target_package: str = "",
    runtime_evidence_file: Path | str | None = None,
    traffic_service: Any | None = None,
    traffic_evidence_file: Path | str | None = None,
    auth_wait_seconds: float = 20.0,
    auth_cancelled: Callable[[], bool] = lambda: False,
    auth_status_callback: Callable[[dict], None] | None = None,
    no_navigation_postcondition: Callable[[ScreenObservation], bool] | None = None,
) -> ExplorationResult:
    """Executes a bounded dynamic UI exploration session over the target application."""
    from src.dynamic.session.auth_intervention import auth_wall, safe_observation, wait_for_user_auth
    raw_observer = observer
    observer = lambda: safe_observation(raw_observer())
    cfg = limits or ExplorationLimits()
    start_monotonic = clock()
    started_at = utc_now_iso()

    steps_attempted = 0
    actions_succeeded = 0
    actions_failed = 0
    screens_observed = 0
    transitions_recorded = 0
    node_depths: dict[str, int] = {}

    evidence_path: Path | None = None
    if runtime_evidence_file:
        evidence_path = Path(runtime_evidence_file)
    elif graph_storage and hasattr(graph_storage, "base_dir"):
        evidence_path = Path(graph_storage.base_dir) / "runtime_evidence.json"

    evidence_artifact: RuntimeEvidenceArtifact | None = None
    if evidence_path:
        evidence_artifact = RuntimeEvidenceArtifact.load_or_create(
            evidence_path,
            session_id=route_graph.session_id,
        )

    traffic_path: Path | None = None
    if traffic_evidence_file:
        traffic_path = Path(traffic_evidence_file)
    elif graph_storage and hasattr(graph_storage, "base_dir"):
        traffic_path = Path(graph_storage.base_dir) / "traffic_evidence.json"

    traffic_artifact: TrafficEvidenceArtifact | None = None
    if traffic_path:
        traffic_artifact = TrafficEvidenceArtifact.load_or_create(
            traffic_path,
            session_id=route_graph.session_id,
        )

    def _persist_graph() -> None:
        if graph_storage:
            try:
                graph_storage.save_graph(route_graph)
                # Atomic frontier snapshots follow the same session/graph mutation boundaries.
                frontier_path = graph_storage.resolve_path(run_id=route_graph.run_id).parent / 'exploration_frontier.json'
                write_json_atomic(str(frontier_path), {
                    'session_id': route_graph.session_id, 'graph_id': route_graph.graph_id,
                    **build_frontier(route_graph, allow_system_dialogs=cfg.allow_system_dialogs)})
            except Exception as exc:
                logger.warning("Failed to persist route graph: %s", exc)

    _emit_timeline_event(
        timeline_recorder,
        "EXPLORATION_STARTED",
        {
            "max_steps": cfg.max_steps,
            "base_step_budget": cfg.base_budget,
            "hard_step_ceiling": cfg.hard_ceiling,
            "max_depth": cfg.max_depth,
            "deadline_seconds": cfg.deadline_seconds,
            "graph_id": route_graph.graph_id,
        },
    )

    # 1. Initial Screen Observation
    if initial_observation is not None:
        initial_obs = safe_observation(initial_observation)
    else:
        try:
            initial_obs = observer()
            if not initial_obs:
                raise ValueError("UI observer returned empty observation.")
        except Exception as exc:
            duration = clock() - start_monotonic
            err_msg = f"Initial screen observation failed: {exc}"
            logger.error(err_msg)
            _emit_timeline_event(timeline_recorder, "EXPLORATION_FAILED", {"error": err_msg})
            return ExplorationResult(
                status=ExplorationStatus.PARTIAL.value,
                stop_reason=StopReason.OBSERVATION_FAILED.value,
                started_at=started_at,
                completed_at=utc_now_iso(),
                duration_seconds=duration,
                error=err_msg,
                metadata={"frontier": build_frontier(route_graph, observation_available=False)},
            )

    # Register initial screen in RouteGraph
    current_node = route_graph.observe_screen(initial_obs)
    screens_observed += 1
    node_depths[current_node.route_node_id] = 0

    _emit_timeline_event(
        timeline_recorder,
        "SCREEN_OBSERVED",
        {
            "step": 0,
            "node_id": current_node.route_node_id,
            "screen_identity": current_node.screen_identity,
            "activity": current_node.activity,
            "clickable_count": current_node.clickable_count,
            "input_count": current_node.input_count,
        },
    )
    _persist_graph()

    stop_reason: str = StopReason.COMPLETED.value
    loop_error: str | None = None
    skipped_actions = {}
    visited_states = set()
    stagnation_count = 0
    progress_steps = []
    navigation_steps = []
    current_observation = initial_obs
    auth_interventions = []

    try:
        # 2. Main Bounded Exploration Loop
        while True:
            # Check deadline
            if current_deadline().remaining() <= 0 or (clock() - start_monotonic) >= cfg.deadline_seconds:
                stop_reason = StopReason.DEADLINE.value
                break

            if auth_wall(current_observation):
                path = (graph_storage.resolve_path(run_id=route_graph.run_id).parent / 'auth_intervention.json') if graph_storage else None
                def publish_auth(evidence):
                    _emit_timeline_event(timeline_recorder, evidence['state'], evidence)
                    if auth_status_callback:auth_status_callback(evidence)
                try:
                    resumed, auth_evidence = wait_for_user_auth(current_observation, observer, runtime_observer,
                        session_id=route_graph.session_id, package_name=target_package or current_observation.foreground_package,
                        traffic_service=traffic_service, timeout_seconds=auth_wait_seconds, cancelled=auth_cancelled,
                        publish=publish_auth, evidence_path=path, clock=clock, sleeper=sleeper)
                except Exception:
                    resumed=None
                    auth_evidence={'state':'AUTH_NOT_COMPLETED','session_id':route_graph.session_id,
                        'message':'Authentication required for deeper runtime coverage.'}
                auth_interventions.append(auth_evidence)
                if resumed is None:
                    stop_reason = StopReason.AUTH_NOT_COMPLETED.value
                    break
                previous_depth = node_depths.get(current_node.route_node_id, 0)
                previous_route = current_node.route_node_id
                current_observation = resumed
                current_node = route_graph.observe_screen(resumed)
                current_node.metadata['auth_intervention'] = {'evidence_ref':'dynamic/auth_intervention.json',
                    'pre_auth_route_id':previous_route,'session_id':route_graph.session_id}
                screens_observed += 1
                node_depths.setdefault(current_node.route_node_id, previous_depth + 1)
                _persist_graph()
                continue

            # Check max steps
            if steps_attempted >= cfg.hard_ceiling:
                stop_reason = (StopReason.HARD_STEP_CEILING.value if cfg.hard_ceiling > cfg.base_budget
                               else StopReason.MAX_STEPS.value)
                break

            # Check exploration boundary:
            # 1. Target application -> continue exploration.
            # 2. Allowed system dialog (e.g. permission controllers) -> continue if allowed.
            # 3. Blocked system UI (e.g. Settings, SystemUI, Package Installer) -> stop with SYSTEM_UI_BOUNDARY.
            # 4. External third-party apps -> stop with EXTERNAL_PACKAGE.
            if not current_node.is_target_package:
                if is_allowed_system_dialog(current_node):
                    if not cfg.allow_system_dialogs:
                        stop_reason = StopReason.SYSTEM_UI_BOUNDARY.value
                        break
                elif current_node.is_dialog_or_system:
                    stop_reason = StopReason.SYSTEM_UI_BOUNDARY.value
                    break
                elif cfg.stop_on_external_package:
                    stop_reason = StopReason.EXTERNAL_PACKAGE.value
                    break

            # Check depth boundary
            curr_depth = node_depths.get(current_node.route_node_id, 0)
            if curr_depth >= cfg.max_depth:
                stop_reason = StopReason.MAX_DEPTH.value
                break

            revisited = current_node.screen_identity in visited_states
            visited_states.add(current_node.screen_identity)
            for candidate in current_node.actions.values():
                reason = navigation_skip_reason(candidate)
                if candidate.status == ActionStatus.DISCOVERED.value and reason and candidate.action_id not in skipped_actions:
                    skipped_actions[candidate.action_id] = {"action_id": candidate.action_id,
                        "route_id": current_node.route_node_id, "reason_code": reason}
                    _emit_timeline_event(timeline_recorder, "ACTION_SKIPPED", skipped_actions[candidate.action_id])
            # Stagnation remains explicit even when return navigation has no remaining hop budget.
            if (cfg.hard_ceiling > cfg.base_budget and steps_attempted >= cfg.base_budget
                    and stagnation_count >= cfg.stagnation_actions
                    and build_frontier(route_graph, allow_system_dialogs=cfg.allow_system_dialogs)['safe_actions_remaining'] > 0):
                stop_reason = StopReason.FRONTIER_STAGNATED.value
                break
            # Select next safe unattempted action
            action = select_next_action(current_node)
            frontier_navigation = False
            if action is None and cfg.hard_ceiling > cfg.base_budget:
                action = select_frontier_navigation(route_graph, current_node, cfg.stagnation_actions - stagnation_count)
                frontier_navigation = action is not None
            if action is None:
                pending = any(select_next_action(n) for n in route_graph.nodes.values())
                unsafe = any(navigation_skip_reason(a) for a in current_node.actions.values()
                             if a.status == ActionStatus.DISCOVERED.value)
                stop_reason = (StopReason.REPEATED_STATE.value if revisited and pending else
                               StopReason.UNSAFE_ACTION_BOUNDARY.value if unsafe else StopReason.NO_ACTIONS.value)
                break

            # Adaptive continuation is fail-closed and uses fresh runtime evidence.
            if cfg.hard_ceiling > cfg.base_budget and steps_attempted >= cfg.base_budget:
                if not progress_steps or stagnation_count >= cfg.stagnation_actions:
                    stop_reason = StopReason.FRONTIER_STAGNATED.value
                    break
                remaining = min(current_deadline().remaining(), cfg.deadline_seconds - (clock() - start_monotonic))
                if remaining < cfg.minimum_extension_seconds:
                    stop_reason = StopReason.DEADLINE.value
                    break
                try:
                    runtime = runtime_observer.observe(target_package) if runtime_observer else None
                except Exception:
                    runtime = None
                if runtime is None or not runtime.process_running or runtime.crash_detected or runtime.fatal_detected:
                    stop_reason = StopReason.RUNTIME_UNAVAILABLE.value
                    break
                if min(current_deadline().remaining(), cfg.deadline_seconds - (clock() - start_monotonic)) < cfg.minimum_extension_seconds:
                    stop_reason = StopReason.DEADLINE.value
                    break

            known_states = {n.screen_identity for n in route_graph.nodes.values()}
            known_safe_actions = {a.action_id for n in route_graph.nodes.values()
                                  for a in n.actions.values() if navigation_skip_reason(a) is None}

            # Bind dispatch geometry to this fresh hierarchy, including proven return navigation.
            fresh = RouteNode.from_observation(current_observation).actions.get(action.action_id)
            if fresh is None or navigation_skip_reason(fresh) is not None:
                stop_reason = StopReason.OBSERVATION_FAILED.value
                break
            action.bounds = fresh.bounds
            action.center = fresh.center

            # Mark action as ATTEMPTED
            steps_attempted += 1
            if frontier_navigation:
                navigation_steps.append(steps_attempted)
            action.status = ActionStatus.ATTEMPTED.value
            _persist_graph()

            _emit_timeline_event(
                timeline_recorder,
                "ACTION_SELECTED",
                {
                    "step": steps_attempted,
                    "frontier_navigation": frontier_navigation,
                    "action_id": action.action_id,
                    "source_node_id": current_node.route_node_id,
                    "source_screen_identity": current_node.screen_identity,
                    "action_type": action.action_type,
                    "center": list(action.center),
                    "resource_id": action.resource_id,
                },
            )

            # Traffic BEFORE marker
            traffic_marker: int | None = None
            if traffic_service:
                try:
                    traffic_marker = traffic_service.get_current_marker()
                except Exception as exc:
                    logger.warning("Traffic get_current_marker failed: %s", exc)
                    traffic_marker = None

            # Runtime BEFORE Snapshot
            before_runtime: Any | None = None
            if runtime_observer:
                try:
                    before_runtime = runtime_observer.observe(target_package)
                except Exception as exc:
                    logger.warning("Runtime observer BEFORE snapshot failed: %s", exc)
                    before_runtime = None

            # Execute action
            exec_res = executor.click(action, timeline_recorder=timeline_recorder)

            completion = wait_for_completion(observer, current_node, runtime_observer=runtime_observer,
                before_runtime=before_runtime, target_package=target_package,
                no_navigation=no_navigation_postcondition, clock=clock, sleeper=sleeper)
            _emit_timeline_event(timeline_recorder, "ACTION_POSTCONDITION", {
                "action_id": action.action_id, "condition": completion.condition,
                "dispatch_status": exec_res.status, "confirmed": completion.confirmed,
                "causation_claimed": False})
            action.status = ActionStatus.SUCCEEDED.value if completion.confirmed else ActionStatus.FAILED.value
            if completion.confirmed:
                actions_succeeded += 1
            else:
                actions_failed += 1
            _persist_graph()

            # Runtime AFTER Snapshot
            after_runtime: Any | None = completion.runtime
            if runtime_observer and after_runtime is None:
                try:
                    since_ts = before_runtime.timestamp if before_runtime else None
                    after_runtime = runtime_observer.observe(target_package, since_timestamp=since_ts)
                except Exception as exc:
                    logger.warning("Runtime observer AFTER snapshot failed: %s", exc)
                    after_runtime = None

            # Traffic AFTER transactions
            new_txs: list[Any] = []
            traffic_status: str | None = None if traffic_service else CorrelationStatus.UNAVAILABLE.value
            vis_meta = traffic_service.get_visibility_metadata() if (traffic_service and hasattr(traffic_service, "get_visibility_metadata")) else {}
            if isinstance(vis_meta, dict):
                hv = vis_meta.get("http_visibility")
                http_vis = str(hv) if isinstance(hv, str) else "available"
                hsv = vis_meta.get("https_visibility")
                https_vis = str(hsv) if isinstance(hsv, str) else "unavailable"
                hr = vis_meta.get("https_reason")
                https_reason = str(hr) if isinstance(hr, str) else ""
            else:
                http_vis = "available" if traffic_service else "unavailable"
                https_vis = "unavailable"
                https_reason = ""

            if traffic_service and traffic_marker is not None:
                try:
                    new_txs = (traffic_service.wait_transactions_since(traffic_marker) if callable(getattr(traffic_service, 'wait_transactions_since', None))
                               else traffic_service.get_transactions_since(traffic_marker))
                    wait_meta = getattr(traffic_service, 'last_traffic_wait', {})
                    if isinstance(wait_meta, dict):
                        _emit_timeline_event(timeline_recorder, 'TRAFFIC_WAIT_COMPLETED', wait_meta)
                except Exception as exc:
                    logger.warning("Traffic get_transactions_since failed: %s", exc)
                    traffic_status = CorrelationStatus.PARTIAL.value

            # Post-action screen observation
            post_obs: ScreenObservation | None = None
            try:
                post_obs = completion.observation
            except Exception as exc:
                logger.warning("Post-action UI observation failed: %s", exc)
                post_obs = None

            if post_obs is None or not completion.confirmed:
                # UI observation failed, but runtime AFTER may still exist
                if runtime_observer and (before_runtime or after_runtime):
                    evidence = create_action_runtime_evidence(
                        action_id=action.action_id,
                        source_node_id=current_node.route_node_id,
                        target_node_id=None,
                        source_screen_identity=current_node.screen_identity,
                        target_screen_identity=None,
                        before=before_runtime,
                        after=after_runtime,
                    )
                    if not completion.confirmed:
                        evidence.correlation_status = CorrelationStatus.PARTIAL.value
                    if evidence_artifact and evidence_path:
                        evidence_artifact.record_action_evidence(evidence, evidence_path)

                    _emit_timeline_event(
                        timeline_recorder,
                        "ACTION_RUNTIME_CORRELATED",
                        {
                            "step": steps_attempted,
                            "action_id": action.action_id,
                            "source_node_id": current_node.route_node_id,
                            "target_node_id": None,
                            "correlation_status": evidence.correlation_status,
                            "pid_changed": evidence.pid_changed,
                            "process_died": evidence.process_died,
                            "foreground_changed": evidence.foreground_changed,
                            "activity_changed": evidence.activity_changed,
                            "fatal_appeared": evidence.fatal_appeared,
                            "crash_appeared": evidence.crash_appeared,
                            "new_log_event_count": evidence.new_log_event_count,
                        },
                    )

                # UI observation failed, but traffic may still exist
                if traffic_service:
                    t_evidence = create_action_traffic_evidence(
                        action_id=action.action_id,
                        source_node_id=current_node.route_node_id,
                        target_node_id=None,
                        transactions=new_txs,
                        correlation_status=traffic_status,
                        http_visibility=http_vis,
                        https_visibility=https_vis,
                        https_visibility_reason=https_reason,
                    )
                    if traffic_artifact and traffic_path:
                        traffic_artifact.record_action_evidence(t_evidence, traffic_path)

                    edge_vis = (
                        "unavailable"
                        if t_evidence.correlation_status == CorrelationStatus.UNAVAILABLE.value
                        else ("available" if t_evidence.http_visibility == "available" and t_evidence.https_visibility == "available" else "partial")
                    )
                    _emit_timeline_event(
                        timeline_recorder,
                        "ACTION_TRAFFIC_CORRELATED",
                        {
                            "step": steps_attempted,
                            "action_id": action.action_id,
                            "source_node_id": current_node.route_node_id,
                            "target_node_id": None,
                            "correlation_status": t_evidence.correlation_status,
                            "transaction_count": t_evidence.transaction_count,
                            "transaction_ids": t_evidence.transaction_ids,
                            "methods": t_evidence.methods,
                            "hosts": t_evidence.hosts,
                            "visibility": edge_vis,
                            "correlation_note": t_evidence.correlation_note,
                        },
                    )

                _emit_timeline_event(
                    timeline_recorder,
                    "POST_ACTION_OBSERVATION_FAILED",
                    {
                        "step": steps_attempted,
                        "action_id": action.action_id,
                        "source_node_id": current_node.route_node_id,
                    },
                )
                stop_reason = StopReason.OBSERVATION_FAILED.value
                break

            screens_observed += 1
            _emit_timeline_event(
                timeline_recorder,
                "SCREEN_OBSERVED",
                {
                    "step": steps_attempted,
                    "screen_identity": post_obs.screen_identity,
                    "activity": post_obs.foreground_activity,
                    "clickable_count": post_obs.clickable_count,
                    "input_count": post_obs.input_count,
                },
            )

            # Correlate runtime diff and prepare edge metadata
            edge_metadata: dict[str, Any] = {}
            evidence: RuntimeActionEvidence | None = None
            if runtime_observer:
                evidence = create_action_runtime_evidence(
                    action_id=action.action_id,
                    source_node_id=current_node.route_node_id,
                    source_screen_identity=current_node.screen_identity,
                    target_screen_identity=post_obs.screen_identity,
                    before=before_runtime,
                    after=after_runtime,
                )
                edge_metadata["runtime"] = {
                    "pid_changed": evidence.pid_changed,
                    "process_died": evidence.process_died,
                    "activity_changed": evidence.activity_changed,
                    "fatal_appeared": evidence.fatal_appeared,
                    "crash_appeared": evidence.crash_appeared,
                    "new_log_event_count": evidence.new_log_event_count,
                }

            t_evidence: ActionTrafficEvidence | None = None
            if traffic_service:
                t_evidence = create_action_traffic_evidence(
                    action_id=action.action_id,
                    source_node_id=current_node.route_node_id,
                    target_node_id=None,
                    transactions=new_txs,
                    correlation_status=traffic_status,
                    http_visibility=http_vis,
                    https_visibility=https_vis,
                    https_visibility_reason=https_reason,
                )
                edge_vis = (
                    "unavailable"
                    if t_evidence.correlation_status == CorrelationStatus.UNAVAILABLE.value
                    else ("available" if t_evidence.http_visibility == "available" and t_evidence.https_visibility == "available" else "partial")
                )
                edge_metadata["traffic"] = {
                    "transaction_count": t_evidence.transaction_count,
                    "transaction_ids": t_evidence.transaction_ids,
                    "visibility": edge_vis,
                }

            # Record transition edge in RouteGraph
            edge = route_graph.record_transition(
                source_node=current_node,
                action=action,
                target_observation=post_obs,
                metadata=edge_metadata,
            )
            transitions_recorded += 1

            if evidence:
                evidence.target_node_id = edge.target_node_id
                if evidence_artifact and evidence_path:
                    evidence_artifact.record_action_evidence(evidence, evidence_path)

                _emit_timeline_event(
                    timeline_recorder,
                    "ACTION_RUNTIME_CORRELATED",
                    {
                        "step": steps_attempted,
                        "action_id": action.action_id,
                        "source_node_id": current_node.route_node_id,
                        "target_node_id": edge.target_node_id,
                        "correlation_status": evidence.correlation_status,
                        "pid_changed": evidence.pid_changed,
                        "process_died": evidence.process_died,
                        "foreground_changed": evidence.foreground_changed,
                        "activity_changed": evidence.activity_changed,
                        "fatal_appeared": evidence.fatal_appeared,
                        "crash_appeared": evidence.crash_appeared,
                        "new_log_event_count": evidence.new_log_event_count,
                    },
                )

            if t_evidence:
                t_evidence.target_node_id = edge.target_node_id
                if traffic_artifact and traffic_path:
                    traffic_artifact.record_action_evidence(t_evidence, traffic_path)

                edge_vis = (
                    "unavailable"
                    if t_evidence.correlation_status == CorrelationStatus.UNAVAILABLE.value
                    else ("available" if t_evidence.http_visibility == "available" and t_evidence.https_visibility == "available" else "partial")
                )
                _emit_timeline_event(
                    timeline_recorder,
                    "ACTION_TRAFFIC_CORRELATED",
                    {
                        "step": steps_attempted,
                        "action_id": action.action_id,
                        "source_node_id": current_node.route_node_id,
                        "target_node_id": edge.target_node_id,
                        "correlation_status": t_evidence.correlation_status,
                        "transaction_count": t_evidence.transaction_count,
                        "transaction_ids": t_evidence.transaction_ids,
                        "methods": t_evidence.methods,
                        "hosts": t_evidence.hosts,
                        "visibility": edge_vis,
                        "correlation_note": t_evidence.correlation_note,
                    },
                )

            is_self_loop = (edge.source_node_id == edge.target_node_id)
            _emit_timeline_event(
                timeline_recorder,
                "ROUTE_TRANSITION_RECORDED",
                {
                    "step": steps_attempted,
                    "edge_id": edge.edge_id,
                    "source_node_id": edge.source_node_id,
                    "target_node_id": edge.target_node_id,
                    "is_self_loop": is_self_loop,
                    "observation_count": edge.observation_count,
                },
            )

            new_safe_actions = {a.action_id for n in route_graph.nodes.values()
                                for a in n.actions.values() if navigation_skip_reason(a) is None} - known_safe_actions
            progressed = (not frontier_navigation and completion.confirmed and (post_obs.screen_identity not in known_states or bool(new_safe_actions)))
            stagnation_count = 0 if progressed else stagnation_count + 1
            if progressed:
                progress_steps.append(steps_attempted)

            # Check for confirmed process death or crash
            if evidence and (evidence.process_died or evidence.crash_appeared):
                logger.info("Process death / crash detected post-action; terminating exploration safely.")
                stop_reason = StopReason.OBSERVATION_FAILED.value
                _persist_graph()
                break

            if not completion.confirmed:
                stop_reason = StopReason.OBSERVATION_FAILED.value
                _persist_graph()
                break

            # Update current node and track depth
            current_node = route_graph.get_node(edge.target_node_id) or current_node
            current_observation = post_obs
            target_depth = curr_depth if is_self_loop else curr_depth + 1
            if current_node.route_node_id not in node_depths:
                node_depths[current_node.route_node_id] = target_depth
            else:
                node_depths[current_node.route_node_id] = min(
                    node_depths[current_node.route_node_id],
                    target_depth,
                )

            _persist_graph()


    except Exception as exc:
        loop_error = str(exc)
        logger.error("Exploration loop crashed: %s", exc, exc_info=True)
        stop_reason = StopReason.EXECUTOR_FAILED.value
        _persist_graph()

    # Determine overall status using canonical vocabulary (completed, partial, failed)
    duration = clock() - start_monotonic
    completed_at = utc_now_iso()

    has_meaningful_evidence = (
        actions_succeeded > 0
        or transitions_recorded > 0
        or (screens_observed > 0 and stop_reason not in (StopReason.EXECUTOR_FAILED.value, StopReason.OBSERVATION_FAILED.value))
    )

    frontier = build_frontier(route_graph,
        observation_available=stop_reason not in {StopReason.OBSERVATION_FAILED.value, StopReason.EXECUTOR_FAILED.value, StopReason.RUNTIME_UNAVAILABLE.value},
        allow_system_dialogs=cfg.allow_system_dialogs)
    if loop_error:
        overall_status = (
            ExplorationStatus.PARTIAL.value
            if (actions_succeeded > 0 or transitions_recorded > 0)
            else ExplorationStatus.FAILED.value
        )
    elif stop_reason in (StopReason.COMPLETED.value, StopReason.NO_ACTIONS.value, StopReason.UNSAFE_ACTION_BOUNDARY.value) and frontier["safe_frontier_exhausted"] and not frontier["safe_actions_failed"]:
        overall_status = ExplorationStatus.COMPLETED.value
    elif stop_reason in (
        StopReason.NO_ACTIONS.value,
        StopReason.UNSAFE_ACTION_BOUNDARY.value,
        StopReason.REPEATED_STATE.value,
        StopReason.MAX_STEPS.value,
        StopReason.MAX_DEPTH.value,
        StopReason.DEADLINE.value,
        StopReason.EXTERNAL_PACKAGE.value,
        StopReason.SYSTEM_UI_BOUNDARY.value,
    ):
        overall_status = (
            ExplorationStatus.PARTIAL.value
            if has_meaningful_evidence
            else ExplorationStatus.FAILED.value
        )
    elif has_meaningful_evidence:
        overall_status = ExplorationStatus.PARTIAL.value
    else:
        overall_status = ExplorationStatus.FAILED.value

    result = ExplorationResult(
        status=overall_status,
        stop_reason=stop_reason,
        steps_attempted=steps_attempted,
        actions_succeeded=actions_succeeded,
        actions_failed=actions_failed,
        screens_observed=screens_observed,
        transitions_recorded=transitions_recorded,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=duration,
        root_node_id=route_graph.root_node_id,
        current_node_id=current_node.route_node_id if current_node else None,
        error=loop_error,
        metadata={
            "auth_interventions": auth_interventions,
            "frontier": frontier,
            "exploration_summary": exploration_summary(overall_status, stop_reason, frontier, {
                "base_step_budget": cfg.base_budget, "hard_step_ceiling": cfg.hard_ceiling,
                "actions_attempted": steps_attempted, "adaptive_extension_used": steps_attempted > cfg.base_budget}),
            "budget": {"base_step_budget": cfg.base_budget, "hard_step_ceiling": cfg.hard_ceiling,
                       "actions_attempted": steps_attempted, "adaptive_extension_used": steps_attempted > cfg.base_budget,
                       "extension_actions": max(0, steps_attempted - cfg.base_budget),
                       "stagnation_actions": cfg.stagnation_actions, "progress_steps": progress_steps,
                       "frontier_navigation_steps": navigation_steps},
            "safe_frontier_exhausted": frontier["safe_frontier_exhausted"],
            "skipped_actions": sorted(skipped_actions.values(), key=lambda item: item["action_id"]),
            "max_steps": cfg.max_steps,
            "base_step_budget": cfg.base_budget,
            "hard_step_ceiling": cfg.hard_ceiling,
            "max_depth": cfg.max_depth,
            "nodes_in_graph": route_graph.node_count,
            "edges_in_graph": route_graph.edge_count,
        },
    )

    _emit_timeline_event(
        timeline_recorder,
        "EXPLORATION_COMPLETED",
        {
            "status": overall_status,
            "stop_reason": stop_reason,
            "steps_attempted": steps_attempted,
            "actions_succeeded": actions_succeeded,
            "actions_failed": actions_failed,
            "screens_observed": screens_observed,
            "transitions_recorded": transitions_recorded,
            "duration_seconds": round(duration, 3),
        },
    )
    _persist_graph()
    if graph_storage:
        try:
            path = graph_storage.resolve_path(run_id=route_graph.run_id).parent / 'exploration_frontier.json'
            write_json_atomic(str(path), {'session_id': route_graph.session_id,
                'graph_id': route_graph.graph_id, **frontier})
        except Exception as exc:
            logger.warning('Frontier persistence failed: %s', exc)

    return result
