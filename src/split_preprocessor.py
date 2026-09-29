"""Isolated Per-Split APK Preprocessing Module for MobiAttack V2 (Task 14 Phase B).

Performs collision-proof decomposition of every APK component in a package set:
  1. Creates an isolated preprocessing workspace per component under processed/<stem>/
  2. Safely extracts raw APK contents (with Zip Slip / traversal protection)
  3. Runs Apktool where structurally applicable, capturing warnings/errors without dropping components
  4. Runs JADX strictly when DEX bytecode exists (skips DEX-less config splits cleanly)
  5. Enforces failure semantics: Base APK failure aborts; optional split failure records warnings
  6. Updates package_set.json deterministically with per-component preprocessing metadata.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

from src.apk_preprocessor import (
    DEFAULT_MAX_UNCOMPRESSED_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    SMALI_ROOT_PATTERN,
    ApkPreprocessingError,
    extract_raw_apk_safely,
    sanitize_workspace_name,
    validate_apktool_output,
    validate_jadx_output,
)


def validate_split_apktool_output(apktool_dir: Path, role: str | None = None, has_dex: bool = True) -> bool:
    """Validates apktool output artifacts according to the component's role.

    - For 'base' or DEX-bearing components: requires AndroidManifest.xml and at least one Smali root.
    - For DEX-less config/resource splits: requires AndroidManifest.xml, res/ directory, or apktool.yml.
    """
    manifest_path = apktool_dir / "AndroidManifest.xml"
    yml_path = apktool_dir / "apktool.yml"
    res_path = apktool_dir / "res"

    if role == "base" or has_dex:
        return validate_apktool_output(apktool_dir)

    # Config / resource split: Smali is not expected
    if manifest_path.is_file() or yml_path.is_file() or res_path.is_dir():
        return True

    return False


def preprocess_package_set(
    package_set_input: str | Path | dict,
    processed_root: str | Path | None = None,
    apktool_executable: str | None = None,
    jadx_executable: str | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
) -> dict:
    """Preprocesses all components within a package set in isolated sub-workspaces.

    Args:
        package_set_input: Dictionary model, or path to package_set.json, or workspace directory.
        processed_root: Optional target directory for processed splits (defaults to workspace/processed).
        apktool_executable: Optional custom path/name for apktool binary.
        jadx_executable: Optional custom path/name for jadx binary.
        timeout_seconds: Subprocess timeout ceiling per tool invocation.
        max_uncompressed_bytes: Safety ceiling for raw zip archive decompression.

    Returns:
        Structured Phase B result summary.

    Raises:
        ApkPreprocessingError: If base APK fails preprocessing or required tools are missing.
    """
    # 1. Resolve package_set data and paths
    pkg_set_file: Path | None = None
    if isinstance(package_set_input, dict):
        package_set = package_set_input
    else:
        p = Path(package_set_input).resolve()
        if p.is_file() and p.name == "package_set.json":
            pkg_set_file = p
            with open(p, "r", encoding="utf-8") as f:
                package_set = json.load(f)
        elif (p / "package_set" / "package_set.json").is_file():
            pkg_set_file = p / "package_set" / "package_set.json"
            with open(pkg_set_file, "r", encoding="utf-8") as f:
                package_set = json.load(f)
        elif (p / "package_set.json").is_file():
            pkg_set_file = p / "package_set.json"
            with open(pkg_set_file, "r", encoding="utf-8") as f:
                package_set = json.load(f)
        else:
            raise ApkPreprocessingError(f"Cannot resolve package_set.json from input: '{package_set_input}'")

    # 2. Determine processed_root directory
    if processed_root is not None:
        processed_dir = Path(processed_root).resolve()
    elif pkg_set_file is not None:
        # workspace/package_set/package_set.json -> workspace/processed
        workspace_base = pkg_set_file.parent.parent
        processed_dir = workspace_base / "processed"
    else:
        processed_dir = Path.cwd() / "processed"

    processed_dir.mkdir(parents=True, exist_ok=True)

    # 3. Resolve executables
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

    components = package_set.get("components", [])
    if not components:
        raise ApkPreprocessingError("Package set does not contain any components to preprocess.")

    package_name = package_set.get("package_name", "unknown_package")
    package_layout = package_set.get("package_layout", "split")
    all_warnings: list[str] = []
    processed_summaries: list[dict] = []

    # 4. Iterate over components
    for comp in components:
        fname = comp.get("filename", "")
        role = comp.get("role", "unknown")
        local_path_str = comp.get("local_path", "")
        local_apk = Path(local_path_str).resolve()
        has_dex = comp.get("has_dex", False)

        if not local_apk.is_file():
            err_msg = f"Component APK file missing from local path: '{local_apk}'"
            if role == "base":
                raise ApkPreprocessingError(f"Base APK preprocessing failed: {err_msg}")
            all_warnings.append(err_msg)
            comp["preprocessing"] = {
                "raw_extract_status": "failed",
                "apktool_status": "failed",
                "jadx_status": "failed",
                "warnings": [err_msg],
                "workspace": None,
                "raw_apk_dir": None,
                "apktool_dir": None,
                "jadx_dir": None,
            }
            continue

        comp_folder_name = sanitize_workspace_name(Path(fname).stem)
        comp_workspace = processed_dir / comp_folder_name
        comp_workspace.mkdir(parents=True, exist_ok=True)

        raw_apk_dir = comp_workspace / "raw_apk"
        apktool_dir = comp_workspace / "apktool_out"
        jadx_dir = comp_workspace / "jadx_out"
        comp_warnings: list[str] = []

        # --- A. Safe Raw Extraction ---
        try:
            extract_raw_apk_safely(
                local_apk,
                raw_apk_dir,
                max_uncompressed_bytes=max_uncompressed_bytes,
            )
            raw_extract_status = "success"
        except Exception as exc:
            raw_extract_status = "failed"
            msg = f"Raw extraction failed for '{fname}': {exc}"
            comp_warnings.append(msg)
            all_warnings.append(msg)

        # --- B. Apktool Execution ---
        try:
            res_apktool = subprocess.run(
                [apktool_bin, "d", str(local_apk), "-o", str(apktool_dir)],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
            if res_apktool.returncode == 0:
                is_valid_apktool = validate_split_apktool_output(apktool_dir, role=role, has_dex=has_dex)
                if is_valid_apktool:
                    stderr_text = res_apktool.stderr or ""
                    if "W:" in stderr_text or "warning" in stderr_text.lower():
                        apktool_status = "success_with_warnings"
                        w_msg = f"Apktool decode warning in '{fname}': {stderr_text.strip()[:200]}"
                        comp_warnings.append(w_msg)
                        all_warnings.append(w_msg)
                    else:
                        apktool_status = "success"
                else:
                    apktool_status = "failed"
                    msg = f"Apktool output for '{fname}' missing expected artifacts (manifest, smali, or resources)"
                    comp_warnings.append(msg)
                    all_warnings.append(msg)
            else:
                apktool_status = "failed"
                err_text = (res_apktool.stderr or res_apktool.stdout or "").strip()[:200]
                msg = f"Apktool failed for '{fname}' with code {res_apktool.returncode}: {err_text}"
                comp_warnings.append(msg)
                all_warnings.append(msg)
        except subprocess.TimeoutExpired:
            apktool_status = "failed"
            msg = f"Apktool timed out after {timeout_seconds}s for '{fname}'"
            comp_warnings.append(msg)
            all_warnings.append(msg)
        except OSError as err:
            apktool_status = "failed"
            msg = f"Failed to invoke apktool for '{fname}': {err}"
            comp_warnings.append(msg)
            all_warnings.append(msg)

        # --- C. JADX Execution (Strictly only when has_dex is True) ---
        jadx_dir_str: str | None = None
        if not has_dex:
            jadx_status = "skipped_no_dex"
            jadx_dir_str = None
        else:
            jadx_dir_str = str(jadx_dir)
            try:
                res_jadx = subprocess.run(
                    [jadx_bin, "-d", str(jadx_dir), str(local_apk)],
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                )
                if res_jadx.returncode == 0:
                    if validate_jadx_output(jadx_dir):
                        jadx_status = "success"
                    else:
                        jadx_status = "failed"
                        msg = f"JADX completed with code 0 for '{fname}' but sources directory is missing or empty"
                        comp_warnings.append(msg)
                        all_warnings.append(msg)
                elif res_jadx.returncode == 3:
                    if validate_jadx_output(jadx_dir):
                        jadx_status = "success_with_warnings"
                        w_msg = f"JADX exited with warnings (code 3) for '{fname}'"
                        comp_warnings.append(w_msg)
                        all_warnings.append(w_msg)
                    else:
                        jadx_status = "failed"
                        msg = f"JADX exited with code 3 for '{fname}' but sources directory is missing or empty"
                        comp_warnings.append(msg)
                        all_warnings.append(msg)
                else:
                    jadx_status = "failed"
                    err_text = (res_jadx.stderr or res_jadx.stdout or "").strip()[:200]
                    msg = f"JADX failed for '{fname}' with code {res_jadx.returncode}: {err_text}"
                    comp_warnings.append(msg)
                    all_warnings.append(msg)
            except subprocess.TimeoutExpired:
                jadx_status = "failed"
                msg = f"JADX timed out after {timeout_seconds}s for '{fname}'"
                comp_warnings.append(msg)
                all_warnings.append(msg)
            except OSError as err:
                jadx_status = "failed"
                msg = f"Failed to invoke jadx for '{fname}': {err}"
                comp_warnings.append(msg)
                all_warnings.append(msg)

        # --- D. Failure Handling Semantics ---
        if role == "base":
            if raw_extract_status == "failed" or apktool_status == "failed" or jadx_status == "failed":
                raise ApkPreprocessingError(
                    f"Base APK preprocessing failed for '{fname}': {'; '.join(comp_warnings)}"
                )

        # Record per-component metadata
        comp_preprocessing = {
            "raw_extract_status": raw_extract_status,
            "apktool_status": apktool_status,
            "jadx_status": jadx_status,
            "warnings": comp_warnings,
            "workspace": str(comp_workspace),
            "raw_apk_dir": str(raw_apk_dir),
            "apktool_dir": str(apktool_dir) if apktool_status != "failed" else None,
            "jadx_dir": jadx_dir_str if jadx_status in ("success", "success_with_warnings") else None,
        }
        comp["preprocessing"] = comp_preprocessing

        processed_summaries.append({
            "filename": fname,
            "role": role,
            "raw_extract_status": raw_extract_status,
            "apktool_status": apktool_status,
            "jadx_status": jadx_status,
            "warnings": comp_warnings,
            "workspace": str(comp_workspace),
            "raw_apk_dir": str(raw_apk_dir),
            "apktool_dir": str(apktool_dir) if apktool_status != "failed" else None,
            "jadx_dir": jadx_dir_str if jadx_status in ("success", "success_with_warnings") else None,
        })

    # 5. Update package_set.json on disk if file was loaded from disk
    if pkg_set_file is not None and pkg_set_file.is_file():
        with open(pkg_set_file, "w", encoding="utf-8") as f:
            json.dump(package_set, f, indent=2)

    return {
        "package_name": package_name,
        "package_layout": package_layout,
        "component_count": len(components),
        "status": "success" if not all_warnings else "success_with_warnings",
        "warnings": all_warnings,
        "components": processed_summaries,
        "package_set_path": str(pkg_set_file) if pkg_set_file else None,
        "processed_root": str(processed_dir),
    }
