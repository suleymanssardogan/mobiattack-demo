"""Runtime responsibilities for the demo pipeline."""
from __future__ import annotations

from typing import Callable
import logging


from src.android_runtime_launcher import AndroidDeviceUnavailableError
from src.dynamic.preflight.models import PreflightStatus

logger = logging.getLogger(__name__)


def _runtime_with_availability(
    root_path,
    package_name,
    launcher_activity,
    *,
    progress_callback = None,
    launch_android_app: Callable,
    _ensure_preflight_persisted_from_meta: Callable,
    _persist_preflight_fallback: Callable,
    _emit_progress: Callable,
    _wire_dynamic_analysis_report: Callable,
    _update_scan_state_dynamic_stage: Callable,
    **kwargs,
):
    """Runtime limitations are isolated; Static and result assembly always continue."""
    from src.dynamic.runtime.availability import availability, save_availability, RuntimeReason
    from src.android_runtime_launcher import AndroidRuntimeError
    try:
        if not isinstance(launcher_activity, str) or not launcher_activity.strip() or launcher_activity.endswith('.unknown'):
            raise AndroidRuntimeError('No declared enabled launcher.', 'LAUNCHER_UNRESOLVED',
                                      evidence={'source': 'launcher_resolution'})
        metadata = launch_android_app(package_name=package_name.strip(), launcher_activity=launcher_activity.strip(), **kwargs)
        runtime = metadata.get('runtime', {})
        pid = runtime.get('pid')
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 or runtime.get('process_survived') is False:
            raise AndroidRuntimeError('Runtime process could not be verified.', 'RUNTIME_OBSERVATION_UNAVAILABLE',
                                      evidence={'source': 'runtime_observation', 'process_survived': False})
        foreground = bool(runtime.get('foreground_verified'))
        record = availability('SUPPORTED', package_name=package_name, target_serial=metadata.get('adb', {}).get('serial') or kwargs.get('adb_serial'), status='available' if foreground else 'partial', evidence={
            'source': 'runtime_launcher', 'pid': pid, 'process_appeared': True, 'process_survived': True,
            'foreground_verified': foreground})
        from src.dynamic.runtime.execution_target import ExecutionTarget, save_target
        if metadata.get('execution_target'):
            selected = ExecutionTarget.from_dict(metadata['execution_target'])
            if selected.adb_serial != record['target_serial']:
                raise ValueError('TARGET_IDENTITY_MISMATCH')
            save_target(root_path, selected)
            record['execution_target_id'] = selected.target_id
        save_availability(root_path, record)
        metadata['runtime_availability'] = record
        _ensure_preflight_persisted_from_meta(root_path, package_name, launcher_activity, metadata, kwargs.get('adb_serial'))
        _emit_progress(progress_callback, 'runtime', 'success', record['message'], metadata)
        return metadata
    except Exception as exc:
        reason = getattr(exc, 'reason_code', 'UNKNOWN')
        if isinstance(exc, AndroidDeviceUnavailableError):
            reason = 'RUNTIME_OBSERVATION_UNAVAILABLE'
        if reason not in {item.value for item in RuntimeReason}:
            reason = 'UNKNOWN'
        backend_reason = getattr(exc, 'backend_reason_code', reason)
        if isinstance(exc, AndroidDeviceUnavailableError):
            backend_reason = {'adb_not_found': 'ADB_NOT_FOUND', 'unauthorized': 'DEVICE_UNAUTHORIZED',
                'offline': 'DEVICE_OFFLINE', 'multiple_devices': 'MULTIPLE_DEVICES'}.get(getattr(exc, 'reason', ''), 'DEVICE_NOT_FOUND')
        record = availability(reason, package_name=package_name, target_serial=kwargs.get('adb_serial'), backend_reason=backend_reason,
            evidence=getattr(exc, 'evidence', None) or {'source': 'runtime_boundary', 'exception_type': type(exc).__name__})
        from src.dynamic.runtime.execution_target import load_target
        selected = load_target(root_path)
        if selected:
            record['target_serial'] = selected.adb_serial
            record['execution_target_id'] = selected.target_id
        save_availability(root_path, record)
        _persist_preflight_fallback(root_path, package_name, launcher_activity, PreflightStatus.FAIL,
            record['message'], record['reason_code'], adb_serial=kwargs.get('adb_serial'))
        _emit_progress(progress_callback, 'runtime', 'skipped', record['message'], {'runtime_availability': record})
        _wire_dynamic_analysis_report(root_path)
        _update_scan_state_dynamic_stage(root_path, 'not_available', record['message'])
        return {'status': 'unavailable', 'runtime_availability': record, 'runtime': {'pid': None, 'process_running': False}}
