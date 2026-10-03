"""Deterministic accounting for the discovered, navigation-only frontier."""
from .models import navigation_skip_reason, is_allowed_exploration_surface


def build_frontier(graph, *, observation_available=True, allow_system_dialogs=True):
    states = []
    for node in sorted(graph.nodes.values(), key=lambda n: n.route_node_id):
        reachable = is_allowed_exploration_surface(node) and (allow_system_dialogs or not node.is_dialog_or_system)
        safe = [a for a in node.actions.values() if navigation_skip_reason(a) is None]
        remaining = sorted(a.action_id for a in safe if a.status == 'discovered' and reachable)
        states.append({
            'route_id': node.route_node_id, 'screen_identity': node.screen_identity,
            'safe_actions_discovered': len(safe),
            'safe_actions_attempted': sum(a.status in {'attempted', 'succeeded', 'failed'} for a in safe),
            'safe_actions_completed': sum(a.status == 'succeeded' for a in safe),
            'safe_actions_failed': sum(a.status == 'failed' for a in safe),
            'safe_actions_blocked_skipped': sum(a.status in {'blocked', 'skipped'} or
                (not reachable and a.status == 'discovered') for a in safe),
            'unsafe_skipped': sum(navigation_skip_reason(a) is not None for a in node.actions.values()),
            'safe_actions_remaining': len(remaining), 'remaining_action_ids': remaining,
        })
    counts = {key: sum(s[key] for s in states) for key in (
        'safe_actions_discovered', 'safe_actions_attempted', 'safe_actions_completed',
        'safe_actions_failed', 'safe_actions_blocked_skipped', 'unsafe_skipped', 'safe_actions_remaining')}
    return {'schema_version': '1.0', 'scope': 'discovered_reachable_safe_ui_only',
            'observation_available': observation_available,
            'safe_frontier_exhausted': observation_available and counts['safe_actions_remaining'] == 0,
            **counts, 'states': states}


def exploration_summary(status, stop_reason, frontier, budget=None):
    """Use only typed counts and known reasons, never model/free-form report prose."""
    if not isinstance(frontier, dict):
        return {'stop_kind': {'auth_intervention_not_completed':'AUTH_NOT_COMPLETED','hard_step_ceiling':'HARD_STEP_CEILING','frontier_stagnated':'FRONTIER_STAGNATED','max_steps':'MAX_STEPS','max_depth':'MAX_DEPTH','deadline':'DEADLINE','repeated_state':'REPEATED_STATE','observation_failed':'OBSERVATION_UNAVAILABLE','runtime_unavailable':'RUNTIME_UNAVAILABLE','unsafe_action_boundary':'UNSAFE_BOUNDARY'}.get(stop_reason,'UNKNOWN'), 'safe_actions_remaining': None,
                'safe_frontier_exhausted': None, 'unsafe_skipped': None,
                'note': 'Safe frontier accounting is unavailable.'}
    def count(key):
        value = frontier.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
    remaining, skipped = count('safe_actions_remaining'), count('unsafe_skipped')
    exhausted = (frontier.get('observation_available') is True and remaining == 0
                 and frontier.get('safe_frontier_exhausted') is True)
    kinds = {'auth_intervention_not_completed': 'AUTH_NOT_COMPLETED', 'hard_step_ceiling': 'HARD_STEP_CEILING', 'frontier_stagnated': 'FRONTIER_STAGNATED', 'max_steps': 'MAX_STEPS', 'max_depth': 'MAX_DEPTH', 'deadline': 'DEADLINE',
             'repeated_state': 'REPEATED_STATE', 'observation_failed': 'OBSERVATION_UNAVAILABLE',
             'runtime_unavailable': 'RUNTIME_UNAVAILABLE', 'unsafe_action_boundary': 'UNSAFE_BOUNDARY',
             'external_package': 'UNSAFE_BOUNDARY', 'system_ui_boundary': 'UNSAFE_BOUNDARY'}
    kind = kinds.get(stop_reason, 'NO_SAFE_ACTIONS' if count('safe_actions_discovered') == 0 else 'FRONTIER_EXHAUSTED' if exhausted else 'NO_SAFE_ACTIONS')
    if stop_reason in {'max_steps', 'max_depth', 'deadline', 'hard_step_ceiling'}:
        limit = {'hard_step_ceiling': 'hard safety ceiling', 'max_steps': 'step budget', 'max_depth': 'depth budget', 'deadline': 'operation deadline'}[stop_reason]
        amount = str(remaining) if remaining is not None else 'unknown'
        note = f'Exploration partial — {limit} reached with {amount} safe actions remaining.'
    elif status == 'completed' and exhausted:
        note = (f'Safe reachable exploration frontier exhausted; {skipped} actions were skipped due to side-effect or input risk.'
                if skipped else 'Safe reachable exploration frontier exhausted.')
    else:
        note = 'Exploration partial — '+kind.lower().replace('_', ' ')+f'; {remaining if remaining is not None else "unknown"} safe actions remaining.'
    budget_fields = {}
    if isinstance(budget, dict):
        for key in ('base_step_budget', 'hard_step_ceiling', 'actions_attempted'):
            value = budget.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                budget_fields[key] = value
        if isinstance(budget.get('adaptive_extension_used'), bool):
            budget_fields['adaptive_extension_used'] = budget['adaptive_extension_used']
        if {'base_step_budget', 'hard_step_ceiling', 'actions_attempted', 'adaptive_extension_used'} <= budget_fields.keys():
            extension = 'yes' if budget_fields['adaptive_extension_used'] else 'no'
            note += (f" Budget {budget_fields['base_step_budget']}; {budget_fields['actions_attempted']} actions explored; "
                     f"bounded extension {extension}; safety ceiling {budget_fields['hard_step_ceiling']}.")
    return {**budget_fields, 'stop_kind': kind, 'safe_actions_remaining': remaining,
            'safe_frontier_exhausted': exhausted, 'unsafe_skipped': skipped, 'note': note,
            'scope': 'discovered_reachable_safe_ui_only'}
