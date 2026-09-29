"""Deterministic Static Context Builder.

Aggregates deterministic facts from Task 01 (Manifest), Task 02 (APK Structure),
Task 03 (Network Indicators), and Task 04 (Static API Candidates) into a unified,
evidence-preserving application context.

Rules:
- No new analysis or endpoint inference.
- No AI or runtime assumptions.
- Calls Task 04 with apktool_root so that all source paths are canonically relative
  to apktool_root without guessing or auto-prefixing.
- Preserves all evidence lines, registers, values, and static_api_candidate status exactly.
"""

from pathlib import Path

from src.manifest_parser import parse_manifest
from src.apk_structure_extractor import extract_apk_structure
from src.network_indicator_extractor import extract_network_indicators
from src.api_candidate_extractor import extract_api_candidates


def build_static_context(
    manifest_path: str | Path,
    raw_apk_root: str | Path,
    apktool_root: str | Path,
) -> dict:
    """Build unified static analysis context from underlying deterministic components.

    Args:
        manifest_path: Path to readable AndroidManifest.xml (from Apktool).
        raw_apk_root: Path to unpacked raw APK directory.
        apktool_root: Path to decoded Apktool root directory.

    Returns:
        dict matching the schema:
            {
                "app": {
                    "package_name": "...",
                    "launcher_activity": "..."
                },
                "permissions": [...],
                "activities": [...],
                "structure": {
                    "dex_files": [...],
                    "dex_count": int,
                    "is_multidex": bool,
                    "native_libraries": [...],
                    "has_native_code": bool,
                    "assets": [...],
                    "smali_roots": [...],
                    "has_kotlin_metadata": bool
                },
                "network_indicators": {
                    "network_urls": [...],
                    "domains": [...],
                    "ip_addresses": [...],
                    "path_candidates": [...],
                    "local_file_urls": [...]
                },
                "api_candidates": [...]
            }

    Raises:
        FileNotFoundError: If manifest_path, raw_apk_root, or apktool_root does not exist.
        NotADirectoryError: If raw_apk_root or apktool_root is not a directory.
    """
    manifest_p = Path(manifest_path)
    if not manifest_p.exists():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")
    if not manifest_p.is_file():
        raise FileNotFoundError(f"Manifest path is not a regular file: {manifest_path}")

    raw_p = Path(raw_apk_root)
    if not raw_p.exists():
        raise FileNotFoundError(f"Raw APK directory not found: {raw_apk_root}")
    if not raw_p.is_dir():
        raise NotADirectoryError(f"Raw APK path is not a directory: {raw_apk_root}")

    apktool_p = Path(apktool_root)
    if not apktool_p.exists():
        raise FileNotFoundError(f"Apktool directory not found: {apktool_root}")
    if not apktool_p.is_dir():
        raise NotADirectoryError(f"Apktool path is not a directory: {apktool_root}")

    # 1. Task 01: Manifest facts
    manifest_data = parse_manifest(manifest_p)

    # 2. Task 02: APK structure facts
    structure_data = extract_apk_structure(raw_p, apktool_p)

    # 3. Task 03: Textual network indicators (source paths relative to apktool_root)
    network_indicators = extract_network_indicators(apktool_p)

    # 4. Task 04: Static API candidates
    # Called directly with apktool_root so Smali source paths are canonically relative to apktool_root
    api_data = extract_api_candidates(apktool_p)

    return {
        "app": {
            "package_name": manifest_data["package_name"],
            "launcher_activity": manifest_data["launcher_activity"],
        },
        "permissions": manifest_data["permissions"],
        "activities": manifest_data["activities"],
        "structure": structure_data,
        "network_indicators": network_indicators,
        "api_candidates": api_data["api_candidates"],
    }


# Expose split static context builder for V2
def build_split_static_context(*args, **kwargs):
    from src.split_static_context_builder import build_split_static_context as _builder
    return _builder(*args, **kwargs)
