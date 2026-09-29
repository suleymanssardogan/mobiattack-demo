"""Deterministic iOS Application Structure Extractor for MobiAttack V2.

Collects factual file and directory inventory from unpacked iOS application bundles:
  - Info.plist presence
  - Main executable presence
  - Embedded Frameworks (.framework bundles, .dylib libraries)
  - App Extensions (.appex bundles in PlugIns/)
  - Resource files (plists, JSON, asset catalogs, localizations)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def extract_ios_structure(
    app_bundle_dir: str | Path,
    executable_name: str | None = None,
    relative_bundle_path: str = "Payload/App.app",
) -> dict[str, Any]:
    """Collects factual structure inventory from an extracted iOS app bundle.

    Args:
        app_bundle_dir: Path to the extracted .app directory on disk.
        executable_name: Executable filename declared in Info.plist (CFBundleExecutable).
        relative_bundle_path: Relative bundle path (e.g. 'Payload/Example.app').

    Returns:
        Structured dictionary matching normalized iOS structure schema.
    """
    bundle_path = Path(app_bundle_dir).resolve()
    if not bundle_path.is_dir():
        raise NotADirectoryError(f"Application bundle directory not found: '{app_bundle_dir}'")

    rel_root = relative_bundle_path.rstrip("/\\")

    # 1. Info.plist & Main Executable Check
    has_info_plist = (bundle_path / "Info.plist").is_file()

    has_executable = False
    executable_rel: str | None = None
    if executable_name:
        exe_path = bundle_path / executable_name
        has_executable = exe_path.is_file()
        if has_executable:
            executable_rel = f"{rel_root}/{executable_name}"

    # 2. Embedded Frameworks Inventory (Frameworks/)
    frameworks: list[dict[str, str]] = []
    frameworks_dir = bundle_path / "Frameworks"
    if frameworks_dir.is_dir():
        for entry in sorted(frameworks_dir.iterdir()):
            if entry.name.endswith(".framework") and entry.is_dir():
                frameworks.append({
                    "name": entry.name,
                    "relative_path": f"{rel_root}/Frameworks/{entry.name}",
                    "type": "framework_bundle",
                })
            elif entry.name.endswith(".dylib") and entry.is_file():
                frameworks.append({
                    "name": entry.name,
                    "relative_path": f"{rel_root}/Frameworks/{entry.name}",
                    "type": "dynamic_library",
                })

    # 3. App Extensions Inventory (PlugIns/)
    extensions: list[dict[str, str]] = []
    plugins_dir = bundle_path / "PlugIns"
    if plugins_dir.is_dir():
        for entry in sorted(plugins_dir.iterdir()):
            if entry.name.endswith(".appex") and entry.is_dir():
                extensions.append({
                    "name": entry.name,
                    "relative_path": f"{rel_root}/PlugIns/{entry.name}",
                    "type": "app_extension",
                })

    # 4. Resource Categorization
    plist_files: list[str] = []
    json_files: list[str] = []
    asset_catalogs: list[str] = []
    localization_dirs: list[str] = []
    storyboards: list[str] = []
    total_files_count = 0

    for root, dirs, files in os.walk(bundle_path):
        rel_to_bundle = Path(root).relative_to(bundle_path)

        # Detect localization directories
        for d in dirs:
            if d.endswith(".lproj"):
                localization_dirs.append(str(rel_to_bundle / d) if str(rel_to_bundle) != "." else d)
            elif d.endswith(".xcassets"):
                asset_catalogs.append(str(rel_to_bundle / d) if str(rel_to_bundle) != "." else d)

        for f in files:
            total_files_count += 1
            f_rel = str(rel_to_bundle / f) if str(rel_to_bundle) != "." else f

            if f.endswith(".plist") and f != "Info.plist":
                plist_files.append(f_rel)
            elif f.endswith(".json"):
                json_files.append(f_rel)
            elif f == "Assets.car":
                asset_catalogs.append(f_rel)
            elif f.endswith(".storyboardc") or f.endswith(".nib"):
                storyboards.append(f_rel)

    return {
        "app_bundle_path": rel_root,
        "has_info_plist": has_info_plist,
        "executable_name": executable_name,
        "has_executable": has_executable,
        "executable_path": executable_rel,
        "frameworks": frameworks,
        "framework_count": len(frameworks),
        "extensions": extensions,
        "extension_count": len(extensions),
        "resources": {
            "total_files_count": total_files_count,
            "plist_files": sorted(plist_files)[:100],  # Bounded for dashboard payloads
            "plist_count": len(plist_files),
            "json_files": sorted(json_files)[:100],
            "json_count": len(json_files),
            "asset_catalogs": sorted(asset_catalogs),
            "localization_dirs": sorted(localization_dirs),
            "storyboard_count": len(storyboards),
        },
    }
