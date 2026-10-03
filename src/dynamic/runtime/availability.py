"""Evidence-only execution availability, independent of target device type."""
from enum import Enum
import re
from pathlib import Path
from src.dynamic.session.storage import SessionStorage


class RuntimeReason(str, Enum):
    SUPPORTED = 'SUPPORTED'
    INSTALL_FAILED = 'INSTALL_FAILED'
    INSTALL_INCOMPATIBLE = 'INSTALL_INCOMPATIBLE'
    ABI_UNSUPPORTED = 'ABI_UNSUPPORTED'
    LAUNCHER_UNRESOLVED = 'LAUNCHER_UNRESOLVED'
    APP_LAUNCH_FAILED = 'APP_LAUNCH_FAILED'
    PROCESS_EXITED = 'PROCESS_EXITED'
    APP_CRASHED = 'APP_CRASHED'
    EMULATOR_UNSUPPORTED = 'EMULATOR_UNSUPPORTED'
    DEVICE_FEATURE_UNAVAILABLE = 'DEVICE_FEATURE_UNAVAILABLE'
    INTEGRITY_ENVIRONMENT_REJECTED = 'INTEGRITY_ENVIRONMENT_REJECTED'
    RUNTIME_OBSERVATION_UNAVAILABLE = 'RUNTIME_OBSERVATION_UNAVAILABLE'
    UNKNOWN = 'UNKNOWN'


MESSAGES = {
    'SUPPORTED': 'Application process observed on the current execution target.',
    'INSTALL_FAILED': 'Application installation failed.',
    'INSTALL_INCOMPATIBLE': 'Package manager reported installation incompatibility.',
    'ABI_UNSUPPORTED': 'Package manager reported incompatible native ABI.',
    'LAUNCHER_UNRESOLVED': 'No declared enabled launcher could be resolved.',
    'APP_LAUNCH_FAILED': 'Application launch could not be verified.',
    'PROCESS_EXITED': 'Application process exited during startup.',
    'APP_CRASHED': 'Application crashed during startup.',
    'EMULATOR_UNSUPPORTED': 'Application explicitly rejected the emulator.',
    'DEVICE_FEATURE_UNAVAILABLE': 'Required device feature is unavailable.',
    'INTEGRITY_ENVIRONMENT_REJECTED': 'Application explicitly rejected the execution environment.',
    'RUNTIME_OBSERVATION_UNAVAILABLE': 'Runtime observation is unavailable.',
    'UNKNOWN': 'Runtime availability could not be determined.',
}


def install_reason(output):
    """Only exact package-manager failure tokens qualify; never infer from libraries."""
    match = re.search(r'\b(INSTALL_FAILED_[A-Z_]+)\b', output)
    code = match.group(1) if match else 'INSTALL_FAILED'
    reason = ('ABI_UNSUPPORTED' if code == 'INSTALL_FAILED_NO_MATCHING_ABIS' else
              'INSTALL_INCOMPATIBLE' if code in {'INSTALL_FAILED_OLDER_SDK', 'INSTALL_FAILED_MISSING_FEATURE',
                  'INSTALL_FAILED_CPU_ABI_INCOMPATIBLE'} else 'INSTALL_FAILED')
    if code == 'INSTALL_FAILED_CPU_ABI_INCOMPATIBLE':
        reason = 'ABI_UNSUPPORTED'
    return reason, code


def availability(reason, *, backend_reason=None, evidence=None, status='unavailable', package_name=None, target_serial=None):
    reason = RuntimeReason(reason).value
    return {'schema_version': '1.0', 'status': status, 'reason_code': reason,
            'backend_reason_code': backend_reason or reason, 'message': MESSAGES[reason],
            'package_name': package_name, 'target_serial': target_serial,
            'evidence': dict(evidence or {}), 'evidence_refs': ['dynamic/runtime_availability.json'],
            'coverage': 'observed' if status == 'available' else status}


def validate_availability(value):
    if not isinstance(value, dict) or value.get('schema_version') != '1.0':
        raise ValueError('Invalid runtime availability schema')
    expected = {'schema_version', 'status', 'reason_code', 'backend_reason_code', 'message', 'evidence', 'evidence_refs', 'coverage', 'package_name', 'target_serial'}
    if set(value) - {'execution_target_id'} != expected:
        raise ValueError('Unexpected availability fields')
    for key, pattern in [('package_name', r'[A-Za-z_][A-Za-z0-9_.]*'), ('target_serial', r'[A-Za-z0-9_.:-]+')]:
        if value.get(key) is not None and (not isinstance(value[key], str) or not re.fullmatch(pattern, value[key])):
            raise ValueError('Unsafe execution identity')
    if 'execution_target_id' in value and not re.fullmatch(r'target_[a-f0-9]{16}', value['execution_target_id']):
        raise ValueError('Invalid execution target reference')
    reason = RuntimeReason(value.get('reason_code')).value
    if value.get('message') != MESSAGES[reason] or value.get('status') not in {'available', 'partial', 'unavailable'}:
        raise ValueError('Invalid runtime availability state')
    if value.get('coverage') != ('observed' if value['status'] == 'available' else value['status']):
        raise ValueError('Invalid runtime coverage')
    if not re.fullmatch(r'[A-Z_]+', value.get('backend_reason_code', '')):
        raise ValueError('Invalid backend reason')
    evidence = value.get('evidence')
    if not isinstance(evidence, dict) or not evidence:
        raise ValueError('Missing availability evidence')
    allowed = {'source', 'exception_type', 'returncode', 'install_succeeded', 'launch_succeeded',
               'process_appeared', 'process_survived', 'foreground_verified', 'pid', 'app_abis', 'device_abis'}
    if set(evidence) - allowed:
        raise ValueError('Unsafe availability evidence')
    for key, item in evidence.items():
        if key in {'source', 'exception_type'}:
            if not isinstance(item, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*', item):
                raise ValueError('Unsafe evidence source')
        elif key in {'app_abis', 'device_abis'}:
            if not isinstance(item, list) or any(not isinstance(x, str) or not re.fullmatch(r'[a-zA-Z0-9_-]+', x) for x in item):
                raise ValueError('Invalid ABI metadata')
        elif key in {'returncode', 'pid'}:
            if item is not None and (isinstance(item, bool) or not isinstance(item, int)):
                raise ValueError('Invalid evidence number')
        elif not isinstance(item, bool):
            raise ValueError('Invalid evidence flag')
    if value.get('evidence_refs') != ['dynamic/runtime_availability.json']:
        raise ValueError('Invalid availability evidence refs')
    if value['status'] != 'unavailable' and (not evidence.get('process_survived') or not evidence.get('pid')):
        raise ValueError('Supported execution requires process evidence')
    if (reason == 'SUPPORTED') == (value['status'] == 'unavailable'):
        raise ValueError('Contradictory availability')


def save_availability(root, value):
    validate_availability(value)
    path = Path(root) / 'dynamic' / 'runtime_availability.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    SessionStorage._atomic_write_json(str(path), value)
    return path
