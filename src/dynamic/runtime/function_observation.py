"""Function-observation evidence contract for an opt-in feasibility spike.

No instrumentation is installed, attached, or invoked here. Only explicit
method-entry evidence may populate the contract; UI/activity/log heuristics
cannot become method invocation evidence. Not wired into production scans.
"""
from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import re

MAX_ARGUMENTS = 16
MAX_INVOCATION_COUNT = 1000
MAX_WINDOW_SECONDS = 30
_ID = re.compile(r'[A-Za-z0-9_.:-]{1,160}')
_CLASS = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*){1,30}')
_METHOD = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]{0,127}')
_TYPES = {'unknown', 'null', 'void', 'boolean', 'number', 'string', 'array', 'object', 'binary'}
_MECHANISMS = {'jdwp_method_entry', 'app_emitted_method_event'}


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('Invalid evidence timestamp')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('Invalid evidence timestamp') from None
    if parsed.tzinfo is None:
        raise ValueError('Timestamp requires timezone')
    return parsed


def _safe_metadata(data):
    """Strict descriptors only; arbitrary values/keys never enter evidence."""
    if not isinstance(data, dict) or set(data) - {'type', 'presence', 'length', 'item_count'}:
        raise ValueError('Only safe type/presence/shape metadata is accepted')
    if data.get('type') not in _TYPES or data.get('presence') not in {'present', 'absent', 'unknown'}:
        raise ValueError('Invalid metadata descriptor')
    for key in ('length', 'item_count'):
        if key in data and (type(data[key]) is not int or not 0 <= data[key] <= 1_000_000):
            raise ValueError('Invalid bounded size metadata')
    return dict(data)


@dataclass(frozen=True)
class FunctionTarget:
    class_name: str
    method_name: str

    def __post_init__(self):
        if not _CLASS.fullmatch(self.class_name) or not _METHOD.fullmatch(self.method_name):
            raise ValueError('Invalid function target')


@dataclass(frozen=True)
class InvocationWindow:
    session_id: str
    route_id: str
    action_id: str
    started_at: str
    ended_at: str

    def __post_init__(self):
        if not all(isinstance(v, str) and _ID.fullmatch(v) for v in
                   (self.session_id, self.route_id, self.action_id)):
            raise ValueError('Missing or invalid provenance')
        duration = (_timestamp(self.ended_at) - _timestamp(self.started_at)).total_seconds()
        if not 0 <= duration <= MAX_WINDOW_SECONDS:
            raise ValueError('Invalid or unbounded observation window')


def build_invocation_observation(target, window, *, source_kind, mechanism, source_evidence_ref,
                                class_name, method_name, session_id, route_id, action_id,
                                timestamp, invocation_count, argument_metadata, return_metadata=None):
    """Validate a future adapter's explicit evidence, never infer execution.

    Caller must verify source evidence exists. This helper validates the local
    target/chain/bounds only; no production adapter is supplied by the spike.
    """
    if source_kind != 'method_entry' or mechanism not in _MECHANISMS:
        raise ValueError('Explicit method-entry evidence required')
    if (class_name, method_name) != (target.class_name, target.method_name):
        raise ValueError('Target mismatch')
    if (session_id, route_id, action_id) != (window.session_id, window.route_id, window.action_id):
        raise ValueError('Invocation evidence chain mismatch')
    if not isinstance(source_evidence_ref, str) or not _ID.fullmatch(source_evidence_ref):
        raise ValueError('Missing source evidence reference')
    if not _timestamp(window.started_at) <= _timestamp(timestamp) <= _timestamp(window.ended_at):
        raise ValueError('Invocation outside observation window')
    if type(invocation_count) is not int or not 1 <= invocation_count <= MAX_INVOCATION_COUNT:
        raise ValueError('Invalid bounded invocation count')
    if not isinstance(argument_metadata, list) or len(argument_metadata) > MAX_ARGUMENTS:
        raise ValueError('Argument metadata limit exceeded')
    arguments = [_safe_metadata(item) for item in argument_metadata]
    returns = _safe_metadata(return_metadata) if return_metadata is not None else None
    identity = '|'.join([class_name, method_name, session_id, route_id, action_id, timestamp, source_evidence_ref])
    return {'evidence_ref': 'invocation_' + hashlib.sha256(identity.encode()).hexdigest()[:24],
            'class_name': class_name, 'method_name': method_name, 'timestamp': timestamp,
            'session_id': session_id, 'route_id': route_id, 'action_id': action_id,
            'invocation_count': invocation_count, 'argument_metadata': arguments, 'return_metadata': returns,
            'mechanism': mechanism, 'source_evidence_ref': source_evidence_ref,
            'linkage': 'observed_in_action_window', 'caused_by_action': 'unknown',
            'semantics': 'runtime_observation_only'}


def unavailable_observation(target, window):
    """Honest result when no non-invasive method evidence adapter is available."""
    return {'status': 'unavailable', 'target': asdict(target), 'window': asdict(window),
            'observations': [], 'coverage_gaps': ['method_entry_observation_backend_unavailable',
                'debugger_method_events_or_explicit_app_events_required',
                'no_observed_invocation_does_not_mean_method_never_executed'],
            'instrumentation_enabled': False, 'semantics': 'runtime_observation_only'}
