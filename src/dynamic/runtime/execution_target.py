"""Small execution-target contract; no physical/cloud execution adapters."""
from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import re
from pathlib import Path

from src.dynamic.session.storage import SessionStorage
from src.dynamic.deadline import bounded_operation


class TargetType(str, Enum):
    EMULATOR = 'EMULATOR'
    PHYSICAL_DEVICE = 'PHYSICAL_DEVICE'
    CLOUD_DEVICE = 'CLOUD_DEVICE'
    UNKNOWN = 'UNKNOWN'


CAPABILITIES = ('app_install', 'app_launch', 'foreground_observation', 'pid_observation',
                'ui_automation', 'proxy_configuration', 'traffic_capture',
                'filesystem_observation', 'debugger_available', 'host_reachability',
                'http_capture', 'https_capture')
STATES = {'available', 'unavailable', 'unknown'}


@dataclass
class Capability:
    state: str = 'unknown'
    reason: str = 'NOT_OBSERVED'
    source: str = 'execution_target'

    def __post_init__(self):
        if self.state not in STATES or not re.fullmatch(r'[A-Z_]+', self.reason):
            raise ValueError('Invalid capability state/reason')
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', self.source):
            raise ValueError('Invalid capability provenance')


@dataclass
class ExecutionTarget:
    target_id: str
    target_type: TargetType = TargetType.UNKNOWN
    adb_serial: str | None = None
    platform: str = 'android'
    abis: list[str] = field(default_factory=list)
    api_level: int | None = None
    capabilities: dict[str, Capability] = field(default_factory=lambda: {k: Capability() for k in CAPABILITIES})
    availability: str = 'unknown'
    source: str = 'adb_selection'
    proxy_context: dict = field(default_factory=dict)

    def __post_init__(self):
        self.target_type = TargetType(self.target_type)
        if self.proxy_context:
            if (set(self.proxy_context) != {'host', 'source'} or not isinstance(self.proxy_context['host'], str)
                or not re.fullmatch(r'[A-Za-z0-9_.:-]+', self.proxy_context['host'])
                or self.proxy_context['source'] != 'emulator_adapter_configuration'):
                raise ValueError('Invalid proxy context')
        if not re.fullmatch(r'target_[a-f0-9]{16}', self.target_id) or self.platform != 'android':
            raise ValueError('Invalid execution target identity')
        if self.adb_serial is not None and not re.fullmatch(r'[A-Za-z0-9_.:-]+', self.adb_serial):
            raise ValueError('Invalid ADB transport identity')
        if self.availability not in STATES or set(self.capabilities) != set(CAPABILITIES):
            raise ValueError('Invalid target availability/capabilities')
        if any(not isinstance(v, Capability) for v in self.capabilities.values()):
            raise ValueError('Invalid capability contract')
        if any(not re.fullmatch(r'[A-Za-z0-9_-]+', abi) for abi in self.abis):
            raise ValueError('Invalid target ABI')
        if self.api_level is not None and (isinstance(self.api_level, bool) or not isinstance(self.api_level, int) or self.api_level <= 0):
            raise ValueError('Invalid API level')
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', self.source):
            raise ValueError('Invalid target provenance')

    @classmethod
    def selected(cls, serial, target_type=TargetType.UNKNOWN, **kwargs):
        identity = hashlib.sha256(f'android:{serial or "unselected"}'.encode()).hexdigest()[:16]
        return cls('target_' + identity, target_type, serial, **kwargs)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        value = dict(value)
        value['capabilities'] = {k: Capability(**v) for k, v in value['capabilities'].items()}
        return cls(**value)

    def require_capability(self, name):
        if name not in self.capabilities or self.capabilities[name].state == 'unavailable':
            raise ValueError('TARGET_CAPABILITY_UNAVAILABLE')

    def require_transport(self, selected_serial=None):
        if self.target_type in {TargetType.PHYSICAL_DEVICE, TargetType.CLOUD_DEVICE}:
            raise ValueError('TARGET_ADAPTER_UNAVAILABLE')
        if not self.adb_serial or self.availability != 'available':
            raise ValueError('TARGET_UNAVAILABLE')
        if selected_serial and selected_serial != self.adb_serial:
            raise ValueError('TARGET_IDENTITY_MISMATCH')
        return self.adb_serial


def select_transport(entries, selected_serial=None):
    """Never silently pick the first of multiple attached transports."""
    if selected_serial:
        matches = [(s, state) for s, state in entries if s == selected_serial]
        if len(matches) != 1:
            raise ValueError('DEVICE_NOT_FOUND')
        serial, state = matches[0]
    else:
        if not entries:
            raise ValueError('DEVICE_NOT_FOUND')
        if len(entries) != 1:
            raise ValueError('MULTIPLE_DEVICES')
        serial, state = entries[0]
    if state != 'device':
        raise ValueError({'offline': 'DEVICE_OFFLINE', 'unauthorized': 'DEVICE_UNAUTHORIZED'}.get(state, 'DEVICE_NOT_FOUND'))
    ExecutionTarget.selected(serial)  # validate transport before any targeted operation
    return serial


class EmulatorTargetAdapter:
    """Describe observed transport capabilities, without installing or modifying a target."""
    @bounded_operation(2.0)
    def describe(self, serial, query, runtime=None):
        target = ExecutionTarget.selected(serial, availability='available')
        for prop, key in [('ro.kernel.qemu', 'emulator'), ('ro.product.cpu.abilist', 'abis'), ('ro.build.version.sdk', 'api')]:
            try:
                code, value, _ = query(['shell', 'getprop', prop], serial=serial)
                if code != 0:
                    continue
                value = value.strip()
                if key == 'emulator' and value == '1':
                    target.target_type = TargetType.EMULATOR
                elif key == 'abis':
                    target.abis = sorted({x for x in value.split(',') if re.fullmatch(r'[A-Za-z0-9_-]+', x)})
                elif key == 'api' and value.isdigit() and int(value) > 0:
                    target.api_level = int(value)
            except Exception:
                continue  # failed observation never becomes positive capability evidence
        if target.target_type == TargetType.EMULATOR:
            target.proxy_context = {'host': '10.0.2.2', 'source': 'emulator_adapter_configuration'}
        if runtime:
            for key, observed in [('pid_observation', bool(runtime.get('pid'))),
                                  ('foreground_observation', bool(runtime.get('foreground_verified')))]:
                if observed:
                    target.capabilities[key] = Capability('available', 'OBSERVED', 'runtime_launcher')
            if runtime.get('pid'):
                target.capabilities['app_launch'] = Capability('available', 'OBSERVED', 'runtime_launcher')
        return target


def save_target(root, target):
    target = ExecutionTarget.from_dict(target.to_dict())
    path = Path(root) / 'dynamic' / 'execution_target.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    SessionStorage._atomic_write_json(str(path), target.to_dict())


def load_target(root):
    import json
    path = Path(root) / 'dynamic' / 'execution_target.json'
    return ExecutionTarget.from_dict(json.loads(path.read_text())) if path.is_file() else None


def resolve_run_transport(root, *serials):
    """Run-scoped selection wins; conflicting preflight/session identities are rejected."""
    target = load_target(root)
    known = {s for s in serials if s}
    if target:
        known.add(target.require_transport())
    if len(known) != 1:
        reason = 'TARGET_IDENTITY_MISMATCH' if known else 'TARGET_UNAVAILABLE'
        from src.dynamic.runtime.availability import availability, save_availability
        record = availability('RUNTIME_OBSERVATION_UNAVAILABLE', backend_reason=reason,
            target_serial=target.adb_serial if target else None, evidence={'source': 'execution_target'})
        if target:
            record['execution_target_id'] = target.target_id
        save_availability(root, record)
        raise ValueError(reason)
    return next(iter(known))


@bounded_operation(8.0)
def verify_run_target(root, query):
    """Recheck selected transport; disappearance never selects a replacement."""
    target = load_target(root)
    if not target:
        return
    serial = target.require_transport()
    code, output, _ = query(['devices'])
    entries = [tuple(line.split()[:2]) for line in output.splitlines()[1:] if len(line.split()) >= 2]
    try:
        if code != 0:
            raise ValueError('TARGET_OBSERVATION_UNAVAILABLE')
        select_transport(entries, serial)
    except ValueError:
        target.availability = 'unavailable'
        save_target(root, target)
        from src.dynamic.runtime.availability import availability, save_availability
        record = availability('RUNTIME_OBSERVATION_UNAVAILABLE', target_serial=serial,
            backend_reason='TARGET_UNAVAILABLE', evidence={'source': 'adb_selection'})
        record['execution_target_id'] = target.target_id
        save_availability(root, record)
        raise ValueError('TARGET_UNAVAILABLE') from None


def record_capabilities(root, observations, source):
    target = load_target(root)
    if not target:
        return
    for key, state in observations.items():
        if key not in CAPABILITIES or state not in STATES:
            raise ValueError('Invalid observed capability')
        target.capabilities[key] = Capability(state, 'OBSERVED' if state != 'unknown' else 'NOT_VERIFIED', source)
    save_target(root, target)


def environment_summary(target):
    return {'label': 'Current execution environment', 'target_type': target.target_type.value,
            'availability': target.availability,
            'capabilities': {k: v.state for k, v in sorted(target.capabilities.items())}}
