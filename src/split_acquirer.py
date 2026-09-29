"""Split APK Acquisition & Package-Set Inventory Module for MobiAttack V2 (Task 14 Phase A).

Provides safe multi-APK pulling from Android devices, independent structural validation,
conservative role classification (base, config_abi, config_locale, config_density, feature, unknown),
deterministic SHA-256 calculation, and package_set.json generation.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import zipfile

from src.apk_acquirer import STRICT_DEX_PATTERN, _dex_sort_key


# Known ABI naming conventions (filename suffix and lib/ folder names)
KNOWN_ABIS = {
    "arm64_v8a", "arm64-v8a",
    "armeabi_v7a", "armeabi-v7a",
    "armeabi",
    "x86",
    "x86_64",
    "mips",
    "mips64",
}

# Known density screen configurations
KNOWN_DENSITIES = {
    "ldpi",
    "mdpi",
    "tvdpi",
    "hdpi",
    "xhdpi",
    "xxhdpi",
    "xxxhdpi",
    "anydpi",
    "nodpi",
}

# Standard 2-3 letter ISO language regex, optional script/region (e.g. en, tr, es, pt_BR, zh_CN, b+es+419)
LOCALE_PATTERN = re.compile(r"^([a-z]{2,3}(_[a-zA-Z0-9]+)?|b\+[a-z]{2,3}(\+[a-zA-Z0-9]+)*)$")


def classify_split_component(
    filename: str,
    zip_entries: list[str] | None = None,
) -> str:
    """Classifies an APK component conservatively based on filename and archive contents.

    Supported roles:
      - 'base': Master application APK.
      - 'config_abi': Architecture-specific native library split.
      - 'config_locale': Language/locale resource split.
      - 'config_density': Screen DPI graphical resource split.
      - 'feature': Dynamic feature module split.
      - 'unknown': Split could not be categorized with sufficient evidence.

    Returns:
        One of ('base', 'config_abi', 'config_locale', 'config_density', 'feature', 'unknown').
    """
    clean_name = Path(filename).name.lower()

    # 1. Base APK detection
    if clean_name == "base.apk" or clean_name.startswith("base_"):
        return "base"

    # 2. Config Split Pattern: split_config.<config_name>.apk
    config_match = re.match(r"^split_config\.([a-zA-Z0-9_+]+)\.apk$", clean_name)
    if config_match:
        cfg = config_match.group(1).lower()

        # ABI check
        if cfg in KNOWN_ABIS:
            return "config_abi"
        if zip_entries and any(e.startswith("lib/") for e in zip_entries):
            return "config_abi"

        # Density check
        if cfg in KNOWN_DENSITIES:
            return "config_density"
        if zip_entries and any(e.startswith(f"res/drawable-{cfg}") or e.startswith(f"res/mipmap-{cfg}") for e in zip_entries):
            return "config_density"

        # Locale check
        if LOCALE_PATTERN.match(cfg):
            return "config_locale"
        if zip_entries and any(e.startswith(f"res/values-{cfg}") for e in zip_entries):
            return "config_locale"

        # If it matches split_config but doesn't match ABI/density/locale, return unknown
        return "unknown"

    # 3. Dynamic Feature Split Pattern: split_<feature>.apk (excluding config splits)
    feature_match = re.match(r"^split_([a-zA-Z0-9_-]+)\.apk$", clean_name)
    if feature_match:
        feature_name = feature_match.group(1)
        if not feature_name.startswith("config."):
            # If zip entries provided, check if it contains code or manifest
            if zip_entries is None or any(STRICT_DEX_PATTERN.match(e) for e in zip_entries) or "AndroidManifest.xml" in zip_entries:
                return "feature"

    # 4. Content-based classification fallback if filename is non-standard
    if zip_entries:
        has_dex = any(STRICT_DEX_PATTERN.match(e) for e in zip_entries)
        has_native = any(e.startswith("lib/") for e in zip_entries)
        has_res = any(e.startswith("res/") for e in zip_entries)

        if has_native and not has_dex:
            return "config_abi"
        if has_res and not has_dex and not has_native:
            # Check if density or locale
            if any("drawable-" in e for e in zip_entries):
                return "config_density"
            if any("values-" in e for e in zip_entries):
                return "config_locale"

    # 5. Default conservative fallback
    return "unknown"


def validate_split_apk(
    file_path: str | Path,
    role: str | None = None,
) -> dict:
    """Structurally validates an individual APK within a package set.

    Checks:
      1. Is a valid, readable ZIP archive.
      2. Contains root-level 'AndroidManifest.xml'.
      3. Discovers DEX files conforming to Android conventions (classes*.dex).
      4. Validates that base packages contain DEX bytecode; config splits may be DEX-less.

    Returns deterministic validation facts dictionary.
    """
    path = Path(file_path)
    if not path.is_file():
        return {
            "is_valid_zip": False,
            "has_android_manifest": False,
            "has_dex": False,
            "dex_count": 0,
            "dex_files": [],
            "is_valid": False,
            "error": f"File does not exist: {path}",
        }

    if not zipfile.is_zipfile(path):
        return {
            "is_valid_zip": False,
            "has_android_manifest": False,
            "has_dex": False,
            "dex_count": 0,
            "dex_files": [],
            "is_valid": False,
            "error": "File is not a valid ZIP archive",
        }

    try:
        with zipfile.ZipFile(path, "r") as zf:
            namelist = zf.namelist()
            has_manifest = "AndroidManifest.xml" in namelist
            dex_files = [n for n in namelist if STRICT_DEX_PATTERN.match(n)]
            dex_files.sort(key=_dex_sort_key)
            dex_count = len(dex_files)
            has_dex = dex_count > 0

            # Structural validity rules:
            # - Must be a valid zip (already checked)
            # - Must contain AndroidManifest.xml
            # - Base APK must have classes.dex; config splits may be DEX-less
            if not has_manifest:
                return {
                    "is_valid_zip": True,
                    "has_android_manifest": False,
                    "has_dex": has_dex,
                    "dex_count": dex_count,
                    "dex_files": dex_files,
                    "is_valid": False,
                    "error": "Missing root AndroidManifest.xml in archive",
                }

            if role == "base" and not has_dex:
                return {
                    "is_valid_zip": True,
                    "has_android_manifest": True,
                    "has_dex": False,
                    "dex_count": 0,
                    "dex_files": [],
                    "is_valid": False,
                    "error": "Base APK does not contain any valid DEX bytecode (classes*.dex)",
                }

            return {
                "is_valid_zip": True,
                "has_android_manifest": True,
                "has_dex": has_dex,
                "dex_count": dex_count,
                "dex_files": dex_files,
                "is_valid": True,
                "error": None,
            }
    except (zipfile.BadZipFile, OSError) as exc:
        return {
            "is_valid_zip": False,
            "has_android_manifest": False,
            "has_dex": False,
            "dex_count": 0,
            "dex_files": [],
            "is_valid": False,
            "error": f"Corrupt archive or decompression error: {exc}",
        }


def compute_file_sha256(file_path: Path) -> str:
    """Computes SHA-256 digest in buffered 64KB blocks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_package_set_model(
    package_name: str,
    components: list[dict],
    package_layout: str = "split",
) -> dict:
    """Constructs the canonical package-set dictionary model."""
    return {
        "package_name": package_name,
        "package_layout": package_layout,
        "split_count": len(components),
        "components": components,
    }


def write_package_set_json(
    package_set_dir: Path,
    package_set_data: dict,
) -> Path:
    """Writes package_set.json deterministically to package_set workspace."""
    package_set_dir.mkdir(parents=True, exist_ok=True)
    json_path = package_set_dir / "package_set.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(package_set_data, f, indent=2)
    return json_path


def acquire_split_package_set(
    package_name: str,
    output_dir: Path | str,
    serial: str,
    adb_bin: str | None = None,
    timeout_seconds: float = 60.0,
    remote_paths: list[str] | None = None,
) -> dict:
    """Pulls all installed split APKs for a package, validates them, and writes package_set.json.

    Args:
        package_name: Android package identifier.
        output_dir: Root workspace directory for the package set.
        serial: Connected ADB device serial.
        adb_bin: Optional explicit path to adb binary.
        timeout_seconds: Timeout per adb command.
        remote_paths: Optional pre-queried remote paths. If None, queries device directly.

    Returns:
        Deterministic acquisition result dictionary containing full package-set metadata.

    Raises:
        PlayStoreAcquisitionError: On pull failure or structural validation failure.
    """
    from src.play_store_acquirer import (
        PlayStoreAcquisitionError,
        pull_device_apk,
        query_package_paths,
        resolve_adb_executable,
    )

    resolved_adb = resolve_adb_executable(adb_bin)
    out_dir = Path(output_dir).resolve()
    package_set_dir = out_dir / "package_set"
    apks_dir = package_set_dir / "apks"
    apks_dir.mkdir(parents=True, exist_ok=True)

    if remote_paths is None:
        remote_paths = query_package_paths(
            adb_bin=resolved_adb,
            serial=serial,
            package_name=package_name,
            timeout_seconds=min(timeout_seconds, 30.0),
        )

    if not remote_paths:
        raise PlayStoreAcquisitionError(
            "Package is not installed on the connected Android device.",
            package_name=package_name,
            installed_on_device=False,
            package_layout="none",
        )

    used_filenames: set[str] = set()
    components: list[dict] = []

    for remote_path in remote_paths:
        base_name = Path(remote_path).name
        candidate_name = base_name
        counter = 1
        while candidate_name in used_filenames:
            stem = Path(base_name).stem
            ext = Path(base_name).suffix
            candidate_name = f"{stem}_{counter}{ext}"
            counter += 1
        used_filenames.add(candidate_name)

        local_apk_path = apks_dir / candidate_name
        if local_apk_path.exists():
            try:
                local_apk_path.unlink()
            except OSError:
                pass

        pull_device_apk(
            adb_bin=resolved_adb,
            serial=serial,
            remote_path=remote_path,
            local_path=local_apk_path,
            timeout_seconds=timeout_seconds,
        )

        # Inspect archive entries for classification
        zip_entries: list[str] | None = None
        if zipfile.is_zipfile(local_apk_path):
            try:
                with zipfile.ZipFile(local_apk_path, "r") as zf:
                    zip_entries = zf.namelist()
            except Exception:
                zip_entries = None

        role = classify_split_component(filename=candidate_name, zip_entries=zip_entries)
        validation = validate_split_apk(local_apk_path, role=role)

        if not validation["is_valid"]:
            err_msg = validation.get("error") or "Unknown validation error"
            raise PlayStoreAcquisitionError(
                f"Pulled APK component '{candidate_name}' failed structural validation: {err_msg}",
                package_name=package_name,
                installed_on_device=True,
                package_layout="split" if len(remote_paths) > 1 else "monolithic",
            )

        sha256_hash = compute_file_sha256(local_apk_path)
        size_bytes = local_apk_path.stat().st_size

        component_info = {
            "filename": candidate_name,
            "role": role,
            "device_path": remote_path,
            "local_path": str(local_apk_path),
            "size_bytes": size_bytes,
            "sha256": sha256_hash,
            "is_valid_zip": validation["is_valid_zip"],
            "has_android_manifest": validation["has_android_manifest"],
            "has_dex": validation["has_dex"],
            "dex_count": validation["dex_count"],
            "dex_files": validation["dex_files"],
            "is_valid": validation["is_valid"],
        }
        components.append(component_info)

    layout = "monolithic" if len(components) == 1 else "split"
    package_set_data = build_package_set_model(
        package_name=package_name,
        components=components,
        package_layout=layout,
    )

    json_path = write_package_set_json(package_set_dir, package_set_data)

    return {
        "input_url": f"https://play.google.com/store/apps/details?id={package_name}",
        "platform": "android",
        "source_type": "play_store",
        "package_name": package_name,
        "installed_on_device": True,
        "package_layout": layout,
        "split_count": len(components),
        "package_set_path": str(json_path),
        "package_set": package_set_data,
        "components": components,
        "remote_paths": remote_paths,
    }
