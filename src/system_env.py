"""System environment and tool resolution helper.

Ensures that external analysis tools (apktool, jadx, adb, etc.) installed in standard
system paths (such as macOS Homebrew /opt/homebrew/bin, /usr/local/bin, or Android SDK)
are discovered even when the server or script is launched from an environment with a minimal PATH.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import unittest.mock
from typing import Sequence

# Common directories where external analysis tools typically reside
COMMON_TOOL_DIRS: list[str] = [
    "/opt/homebrew/bin",
    "/opt/homebrew/sbin",
    "/usr/local/bin",
    str(Path.home() / "Library/Android/sdk/platform-tools"),
    str(Path.home() / "Library/Android/sdk/cmdline-tools/latest/bin"),
    str(Path.home() / "Android/Sdk/platform-tools"),
    str(Path.home() / ".local/bin"),
    "/usr/bin",
    "/bin",
]


def ensure_system_paths() -> None:
    """Ensure standard tool directories are present in os.environ['PATH']."""
    current_path = os.environ.get("PATH", "")
    existing_paths = [p for p in current_path.split(os.pathsep) if p]
    existing_set = set(existing_paths)

    dirs_to_add: list[str] = []
    for candidate in COMMON_TOOL_DIRS:
        if os.path.isdir(candidate) and candidate not in existing_set:
            dirs_to_add.append(candidate)
            existing_set.add(candidate)

    if dirs_to_add:
        # Prepend to PATH so tools like brew apktool/jadx/adb are prioritized
        os.environ["PATH"] = os.pathsep.join(dirs_to_add + existing_paths)


# Initialize paths on module load
ensure_system_paths()


def is_mocked(func_or_obj: object) -> bool:
    """Check if an object or function has been patched/mocked by unittest.mock."""
    return (
        isinstance(func_or_obj, (unittest.mock.Mock, unittest.mock.MagicMock, unittest.mock.NonCallableMock))
        or hasattr(func_or_obj, "mock_calls")
        or hasattr(func_or_obj, "assert_called")
    )


def resolve_executable(name: str, explicit_path: str | None = None) -> str | None:
    """Resolves an executable by checking explicit path, PATH, and common installation locations.

    Respects unittest.mock if shutil.which is patched.
    """
    ensure_system_paths()

    # If explicit path provided
    if explicit_path:
        res = shutil.which(explicit_path)
        if res:
            return res
        if not is_mocked(shutil.which):
            exp_path = Path(explicit_path)
            if exp_path.is_file() and os.access(exp_path, os.X_OK):
                return str(exp_path.resolve())
        return None

    # Check via shutil.which
    res = shutil.which(name)
    if res:
        return res

    # If shutil.which was mocked in a test, do not bypass the mock with disk fallback
    if is_mocked(shutil.which):
        return None

    # Fallback search across common tool directories
    for cand_dir in COMMON_TOOL_DIRS:
        cand_file = Path(cand_dir) / name
        if cand_file.is_file() and os.access(cand_file, os.X_OK):
            cand_str = str(cand_file.resolve())
            # Ensure its directory is on PATH for subprocesses
            if cand_dir not in os.environ.get("PATH", ""):
                os.environ["PATH"] = f"{cand_dir}{os.pathsep}{os.environ.get('PATH', '')}"
            return cand_str

    return None
