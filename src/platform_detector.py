"""Deterministic Platform and Archive Structure Detector for MobiAttack V2.

Identifies mobile application package platforms (.apk vs .ipa) based on content
and archive structure rather than trusting file extensions alone.
"""

from __future__ import annotations

from pathlib import Path
import re
import zipfile

# Strict Android DEX pattern: classes.dex, classes2.dex, classes3.dex...
STRICT_DEX_PATTERN = re.compile(r"^classes([2-9]\d*)?\.dex$")


def detect_platform(file_path: str | Path) -> dict:
    """Deterministically identifies the mobile OS platform of a package archive.

    Inspects container format and required internal structural anchors:
      - Android (.apk): Valid ZIP containing root-level AndroidManifest.xml and
                        at least one classes*.dex.
      - iOS (.ipa): Valid ZIP containing Payload/ directory and at least one
                    Payload/<app_name>.app/ bundle.

    Args:
        file_path: Path to the target package file.

    Returns:
        Structured detection dictionary:
            platform: 'android' | 'ios' | 'unknown'
            valid: bool
            detected_by: list[str] (e.g. ['zip_container', 'payload_directory', 'app_bundle'])
            reason: str (if invalid or unrecognized)
            app_bundle: str (if iOS valid)
            has_info_plist: bool (if iOS valid)
            dex_count: int (if Android valid)
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        return {
            "platform": "unknown",
            "valid": False,
            "detected_by": [],
            "reason": f"Target file does not exist or is not a regular file: '{file_path}'",
        }

    if not zipfile.is_zipfile(path):
        return {
            "platform": "unknown",
            "valid": False,
            "detected_by": [],
            "reason": "File is not a valid ZIP archive.",
        }

    try:
        with zipfile.ZipFile(path, "r") as zf:
            namelist = [name.replace("\\", "/") for name in zf.namelist()]
    except Exception as exc:
        return {
            "platform": "unknown",
            "valid": False,
            "detected_by": ["zip_container"],
            "reason": f"Failed to read ZIP archive table of contents: {exc}",
        }

    # 1. Android Structural Verification
    has_android_manifest = "AndroidManifest.xml" in namelist
    dex_files = [name for name in namelist if STRICT_DEX_PATTERN.match(name)]
    if has_android_manifest and len(dex_files) > 0:
        return {
            "platform": "android",
            "valid": True,
            "detected_by": ["zip_container", "android_manifest", "dex_files"],
            "dex_count": len(dex_files),
        }

    # 2. iOS Structural Verification
    # Expected layout: Payload/<AppName>.app/
    payload_entries = [name for name in namelist if name.startswith("Payload/")]
    has_payload_dir = any(name == "Payload/" or name.startswith("Payload/") for name in namelist)

    if has_payload_dir or payload_entries:
        detected_by = ["zip_container", "payload_directory"]

        # Discover top-level .app bundles directly inside Payload/
        # e.g. "Payload/Foo.app/" or "Payload/Foo.app/Info.plist" -> "Payload/Foo.app"
        app_bundles: set[str] = set()
        for name in payload_entries:
            parts = name.split("/")
            if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
                app_bundles.add(f"Payload/{parts[1]}")

        sorted_bundles = sorted(app_bundles)

        if not sorted_bundles:
            return {
                "platform": "ios",
                "valid": False,
                "detected_by": detected_by,
                "reason": "missing_app_bundle: Archive contains Payload/ directory but no Payload/*.app bundle.",
            }

        if len(sorted_bundles) > 1:
            return {
                "platform": "ios",
                "valid": False,
                "detected_by": detected_by + ["multiple_app_bundles"],
                "reason": "ambiguous_multiple_app_bundles: Multiple application bundles found directly in Payload/.",
                "app_bundles": sorted_bundles,
            }

        primary_bundle = sorted_bundles[0]
        detected_by.append("app_bundle")

        info_plist_path = f"{primary_bundle}/Info.plist"
        has_info_plist = info_plist_path in namelist
        if has_info_plist:
            detected_by.append("info_plist")

        return {
            "platform": "ios",
            "valid": True,
            "detected_by": detected_by,
            "app_bundle": primary_bundle,
            "has_info_plist": has_info_plist,
        }

    # If file has .ipa extension but lacks Payload/
    if path.suffix.lower() == ".ipa":
        return {
            "platform": "ios",
            "valid": False,
            "detected_by": ["zip_container"],
            "reason": "invalid_ipa_structure: File has .ipa extension but lacks required Payload/ directory.",
        }

    # If file has .apk extension but lacks AndroidManifest or DEX
    if path.suffix.lower() == ".apk":
        reasons = []
        if not has_android_manifest:
            reasons.append("missing AndroidManifest.xml")
        if len(dex_files) == 0:
            reasons.append("missing classes*.dex")
        return {
            "platform": "android",
            "valid": False,
            "detected_by": ["zip_container"],
            "reason": f"invalid_apk_structure: {', '.join(reasons)}",
        }

    return {
        "platform": "unknown",
        "valid": False,
        "detected_by": ["zip_container"],
        "reason": "unrecognized_archive_structure: Archive does not match Android (.apk) or iOS (.ipa) signatures.",
    }
