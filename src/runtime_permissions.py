"""Normal Android runtime grants with bounded commands and metadata-only recording."""
import re
import subprocess
import time


def _inventory(text):
    permissions = {}
    runtime = False
    for line in text.splitlines():
        if 'runtime permissions:' in line:
            runtime = True
            continue
        if runtime:
            match = re.match(r'\s+(android\.permission\.[A-Z0-9_]+): granted=(true|false)', line)
            if match:
                permissions[match[1]] = match[2] == 'true'
            elif line.strip():
                runtime = False
    return permissions


def grant_runtime_permissions(adb_bin, serial, package_name, timeout_seconds=10):
    result = {'package_name': package_name, 'granted': [], 'already_granted': [],
              'unavailable': [], 'coverage': 'available'}
    deadline = time.monotonic() + 30
    def command(*args):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired('runtime permission observation', 30)
        return subprocess.run([adb_bin, '-s', serial, 'shell', *args], capture_output=True,
                              text=True, timeout=min(timeout_seconds, remaining))
    try:
        before = command('dumpsys', 'package', package_name)
        if before.returncode or 'runtime permissions:' not in before.stdout:
            raise ValueError('Permission inventory unavailable')
        inventory = _inventory(before.stdout)
        result['already_granted'] = sorted(name for name, granted in inventory.items() if granted)
        names = sorted(name for name, granted in inventory.items() if not granted)
        for name in names[:64]:
            try:
                command('pm', 'grant', package_name, name)
            except (OSError, subprocess.TimeoutExpired):
                break
        after = command('dumpsys', 'package', package_name)
        if after.returncode:
            raise ValueError('Permission verification unavailable')
        verified = _inventory(after.stdout)
        result['granted'] = [name for name in names[:64] if verified.get(name) is True]
        result['unavailable'] = [name for name in names if name not in result['granted']]
        if result['unavailable']:
            result['coverage'] = 'partial'
    except (OSError, subprocess.TimeoutExpired, ValueError):
        result['coverage'] = 'unavailable'
    return result

def save_permission_observation(run_dir, result):
    """Atomic metadata artifact; never stores command output or file contents."""
    import json
    import os
    import tempfile
    from pathlib import Path

    directory = Path(run_dir) / 'dynamic'
    directory.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=directory, prefix='.permissions_', suffix='.json')
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
        os.replace(name, directory / 'runtime_permissions.json')
    finally:
        Path(name).unlink(missing_ok=True)
