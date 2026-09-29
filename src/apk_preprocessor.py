"""APK Preprocessor Module for MobiAttack-v1.

Automates extraction and decompilation of Android APK packages for downstream
static analysis tasks:
- Extracts raw APK contents into <workspace>/raw_apk/ with Zip Slip and zip-bomb defenses.
- Decodes resources and disassembles Smali into <workspace>/apktool_out/ via apktool.
- Decompiles Dalvik bytecode to Java sources into <workspace>/jadx_out/ via jadx.
- Enforces strict execution safety, timeout controls, artifact validation,
  and atomic rollback on failure.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

# Strict Smali root directory pattern (matching Task 02 conventions)
SMALI_ROOT_PATTERN = re.compile(r"^smali(_classes\d+)?$")

# Unix file mode mask for symbolic links (S_IFLNK is 0o120000 in stat.h)
S_IFLNK = 0o120000

# Defaults
DEFAULT_TIMEOUT_SECONDS: float = 300.0
DEFAULT_MAX_UNCOMPRESSED_BYTES: int = 2 * 1024 * 1024 * 1024  # 2 GB


class ApkPreprocessingError(ValueError):
    """Raised when APK preprocessing, tool invocation, or artifact validation fails."""
    pass


def sanitize_workspace_name(name: str, fallback: str = "unnamed_apk") -> str:
    """Sanitizes an APK filename or stem into a safe single-directory component."""
    if not name:
        return fallback

    # Strip .apk suffix if present
    base = re.sub(r"\.apk$", "", name, flags=re.IGNORECASE)

    # Strip null bytes and control chars
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", str(base))

    # Normalize slashes and take basename
    cleaned = cleaned.replace("\\", "/").split("/")[-1].strip()

    # Strip leading dots and traversal artifacts
    cleaned = re.sub(r"^\.+", "", cleaned).strip()

    # Replace invalid directory characters
    cleaned = re.sub(r'[<>:"/\\|?*]', "_", cleaned).strip()

    if not cleaned:
        return fallback

    return cleaned


def extract_raw_apk_safely(
    apk_path: Path,
    dest_dir: Path,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
) -> int:
    """Safely extracts APK archive into dest_dir.

    Enforces:
    - Early check of total ZipInfo.file_size against max_uncompressed_bytes.
    - Rejection of path traversal (Zip Slip) and absolute paths.
    - Rejection of Unix symbolic link entries.
    - Continuous tracking of extracted bytes during write.

    Returns:
        Total count of extracted files.
    """
    if not zipfile.is_zipfile(apk_path):
        raise ApkPreprocessingError(f"APK file is not a valid ZIP archive: '{apk_path}'")

    dest_resolved = dest_dir.resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(apk_path, "r") as zf:
        infolist = zf.infolist()

        # 1. Early aggregate size check
        total_declared_size = sum(info.file_size for info in infolist)
        if total_declared_size > max_uncompressed_bytes:
            raise ApkPreprocessingError(
                f"Total uncompressed ZIP size ({total_declared_size} bytes) exceeds "
                f"maximum limit of {max_uncompressed_bytes} bytes."
            )

        extracted_file_count = 0
        total_extracted_bytes = 0

        for info in infolist:
            filename = info.filename

            # Check 2: Reject absolute paths and null bytes
            if "\x00" in filename or filename.startswith("/") or filename.startswith("\\"):
                raise ApkPreprocessingError(
                    f"Unsafe absolute or null-byte member in APK archive: '{filename}'"
                )

            # Check 3: Detect symbolic link entries
            # Upper 16 bits of external_attr contain Unix file mode
            unix_mode = info.external_attr >> 16
            if unix_mode and (unix_mode & S_IFLNK) == S_IFLNK:
                raise ApkPreprocessingError(
                    f"Symbolic link member rejected in APK archive: '{filename}'"
                )

            target_path = (dest_dir / filename).resolve()

            # Check 4: Zip Slip path containment check
            try:
                target_path.relative_to(dest_resolved)
            except ValueError:
                raise ApkPreprocessingError(
                    f"Zip Slip path traversal attempt detected in member: '{filename}'"
                )

            # If directory, create it safely
            if info.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            # Ensure parent directories exist
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # Check 5: Stream member and enforce byte ceiling
            chunk_size = 65536
            with zf.open(info, "r") as src, open(target_path, "wb") as dst:
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    total_extracted_bytes += len(chunk)
                    if total_extracted_bytes > max_uncompressed_bytes:
                        raise ApkPreprocessingError(
                            f"Extracted bytes exceeded maximum limit of {max_uncompressed_bytes} bytes."
                        )
                    dst.write(chunk)

            extracted_file_count += 1

    return extracted_file_count


def validate_apktool_output(apktool_dir: Path) -> bool:
    """Validates that apktool produced expected artifacts.

    Must contain:
    - AndroidManifest.xml
    - At least one valid Smali root (smali, smali_classes2, ...)
    """
    manifest_path = apktool_dir / "AndroidManifest.xml"
    if not manifest_path.is_file():
        return False

    has_smali_root = any(
        entry.is_dir() and SMALI_ROOT_PATTERN.match(entry.name)
        for entry in apktool_dir.iterdir()
    )
    return has_smali_root


def validate_jadx_output(jadx_dir: Path) -> bool:
    """Validates that jadx produced non-empty decompiled source files.

    Checks that jadx_dir/sources exists and contains at least one actual file.
    """
    sources_dir = jadx_dir / "sources"
    if not sources_dir.is_dir():
        return False

    for item in sources_dir.rglob("*"):
        if item.is_file():
            return True

    return False


def preprocess_apk(
    apk_path: str | Path,
    output_root: str | Path,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
    apktool_executable: str | None = None,
    jadx_executable: str | None = None,
) -> dict:
    """Preprocesses an APK by extracting raw files, decoding with apktool, and decompiling with jadx.

    Args:
        apk_path: Path to the target Android APK file.
        output_root: Base directory where the APK workspace will be created.
        timeout_seconds: Subprocess timeout in seconds for each external tool.
        max_uncompressed_bytes: Maximum allowed uncompressed byte size for raw extraction.
        apktool_executable: Optional custom path/name for apktool binary.
        jadx_executable: Optional custom path/name for jadx binary.

    Returns:
        Deterministic preprocessing metadata dictionary.

    Raises:
        ApkPreprocessingError: On invalid input, missing executables, collisions,
                               tool execution failures, timeouts, or validation failures.
    """
    apk_file = Path(apk_path)
    if not apk_file.exists():
        raise ApkPreprocessingError(f"APK file not found: '{apk_path}'")
    if not apk_file.is_file():
        raise ApkPreprocessingError(f"APK path is not a file: '{apk_path}'")

    # Detect external executables
    apktool_bin = shutil.which(apktool_executable or "apktool")
    if not apktool_bin:
        raise ApkPreprocessingError(
            f"Required executable 'apktool' not found on system PATH. "
            f"(Specified: '{apktool_executable or 'apktool'}')"
        )

    jadx_bin = shutil.which(jadx_executable or "jadx")
    if not jadx_bin:
        raise ApkPreprocessingError(
            f"Required executable 'jadx' not found on system PATH. "
            f"(Specified: '{jadx_executable or 'jadx'}')"
        )

    out_root = Path(output_root)
    out_root.mkdir(parents=True, exist_ok=True)

    # Determine safe workspace name
    safe_name = sanitize_workspace_name(apk_file.name)
    workspace_dir = out_root / safe_name

    # Collision defense: do not overwrite existing workspace
    if workspace_dir.exists():
        raise ApkPreprocessingError(
            f"Workspace directory already exists: '{workspace_dir}'. "
            f"Silently overwriting or auto-deleting is prohibited."
        )

    # Track workspace creation for atomic rollback on failure
    created_workspace: Path | None = None

    try:
        workspace_dir.mkdir(parents=True, exist_ok=False)
        created_workspace = workspace_dir

        raw_apk_dir = workspace_dir / "raw_apk"
        apktool_dir = workspace_dir / "apktool_out"
        jadx_dir = workspace_dir / "jadx_out"

        # 1. Safely extract raw APK
        file_count = extract_raw_apk_safely(
            apk_file,
            raw_apk_dir,
            max_uncompressed_bytes=max_uncompressed_bytes,
        )

        # 2. Run apktool
        apktool_cmd = [apktool_bin, "d", str(apk_file), "-o", str(apktool_dir)]
        try:
            res_apktool = subprocess.run(
                apktool_cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as err:
            raise ApkPreprocessingError(
                f"apktool timed out after {timeout_seconds} seconds."
            ) from err
        except OSError as err:
            raise ApkPreprocessingError(f"Failed to invoke apktool: {err}") from err

        if res_apktool.returncode != 0:
            err_msg = (res_apktool.stderr or res_apktool.stdout or "").strip()
            raise ApkPreprocessingError(
                f"apktool failed with exit code {res_apktool.returncode}: {err_msg[:300]}"
            )

        if not validate_apktool_output(apktool_dir):
            raise ApkPreprocessingError(
                "apktool completed with code 0 but failed artifact validation: "
                "missing AndroidManifest.xml or valid Smali root."
            )

        # 3. Run JADX
        jadx_cmd = [jadx_bin, "-d", str(jadx_dir), str(apk_file)]
        try:
            res_jadx = subprocess.run(
                jadx_cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as err:
            raise ApkPreprocessingError(
                f"jadx timed out after {timeout_seconds} seconds."
            ) from err
        except OSError as err:
            raise ApkPreprocessingError(f"Failed to invoke jadx: {err}") from err

        # Evaluate JADX status
        if res_jadx.returncode == 0:
            if not validate_jadx_output(jadx_dir):
                raise ApkPreprocessingError(
                    "jadx completed with code 0 but failed artifact validation: "
                    "missing or empty sources directory."
                )
            jadx_status = "success"
        elif res_jadx.returncode == 3:
            if not validate_jadx_output(jadx_dir):
                raise ApkPreprocessingError(
                    "jadx exited with returncode 3 (warnings) but failed artifact validation: "
                    "missing or empty sources directory."
                )
            jadx_status = "success_with_warnings"
        else:
            err_msg = (res_jadx.stderr or res_jadx.stdout or "").strip()
            raise ApkPreprocessingError(
                f"jadx failed with fatal exit code {res_jadx.returncode}: {err_msg[:300]}"
            )

        # Format clean relative paths
        def _fmt_path(p: Path) -> str:
            try:
                return p.relative_to(Path.cwd()).as_posix()
            except ValueError:
                return p.as_posix()

        metadata = {
            "apk_path": _fmt_path(apk_file),
            "workspace": _fmt_path(workspace_dir),
            "raw_apk": {
                "success": True,
                "output_dir": _fmt_path(raw_apk_dir),
                "file_count": file_count,
            },
            "apktool": {
                "status": "success",
                "executable": apktool_bin,
                "output_dir": _fmt_path(apktool_dir),
                "returncode": res_apktool.returncode,
            },
            "jadx": {
                "status": jadx_status,
                "executable": jadx_bin,
                "output_dir": _fmt_path(jadx_dir),
                "returncode": res_jadx.returncode,
            },
        }

        # Successful completion; disarm rollback
        created_workspace = None
        return metadata

    finally:
        # Atomic rollback: remove created workspace if preprocessing did not succeed
        if created_workspace is not None and created_workspace.exists():
            try:
                shutil.rmtree(created_workspace)
            except OSError:
                pass


# Expose split preprocessing capability for V2
def preprocess_package_set(*args, **kwargs):
    from src.split_preprocessor import preprocess_package_set as _preprocess_pkg
    return _preprocess_pkg(*args, **kwargs)
