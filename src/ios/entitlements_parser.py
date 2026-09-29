"""Conservative Entitlements Parser for MobiAttack V2.

Extracts application entitlements from embedded provisioning profiles (embedded.mobileprovision)
or code signatures without assuming or inferring vulnerabilities.
"""

from __future__ import annotations

from pathlib import Path
import plistlib
import re
import shutil
import subprocess
from typing import Any


def _extract_plist_from_mobileprovision(data: bytes) -> dict[str, Any] | None:
    """Extracts and parses the embedded XML plist from a .mobileprovision binary."""
    start_idx = data.find(b"<?xml")
    if start_idx == -1:
        return None
    end_tag = b"</plist>"
    end_idx = data.find(end_tag, start_idx)
    if end_idx == -1:
        return None

    xml_bytes = data[start_idx : end_idx + len(end_tag)]
    try:
        parsed = plistlib.loads(xml_bytes)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def extract_entitlements(
    app_bundle_dir: str | Path,
    relative_bundle_path: str = "Payload/App.app",
    use_system_tools: bool = True,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Conservatively extracts application entitlements from an iOS application bundle.

    Sources inspected in order:
      1. embedded.mobileprovision (parsed directly via standard library).
      2. macOS codesign utility (if available and mobileprovision not present).

    Strict rules:
      - Does not infer vulnerabilities from entitlements.
      - Returns explicit status: 'extracted', 'not_found', 'unsupported', or 'tool_failed'.

    Args:
        app_bundle_dir: Filesystem path to the extracted .app directory.
        relative_bundle_path: Relative path for evidence provenance.
        use_system_tools: Whether to allow invoking macOS codesign tool.
        timeout_seconds: Subprocess timeout ceiling.

    Returns:
        Structured entitlements dictionary.
    """
    bundle_path = Path(app_bundle_dir).resolve()
    if not bundle_path.is_dir():
        return {
            "status": "not_found",
            "items": {},
            "item_count": 0,
            "source": None,
            "extraction_method": "none",
            "error": f"App bundle not found: '{app_bundle_dir}'",
        }

    rel_root = relative_bundle_path.rstrip("/\\")
    sources: dict[str, dict[str, Any]] = {}
    records: list[dict[str, Any]] = []

    # Source 1: embedded.mobileprovision
    prov_file = bundle_path / "embedded.mobileprovision"
    prov_ents: dict[str, Any] | None = None
    if prov_file.is_file():
        try:
            prov_bytes = prov_file.read_bytes()
            prov_plist = _extract_plist_from_mobileprovision(prov_bytes)
            if prov_plist and "Entitlements" in prov_plist and isinstance(prov_plist["Entitlements"], dict):
                prov_ents = prov_plist["Entitlements"]
                sources["embedded_mobileprovision"] = {
                    "source_type": "embedded_mobileprovision",
                    "status": "extracted",
                    "items": prov_ents,
                    "item_count": len(prov_ents),
                    "source_file": f"{rel_root}/embedded.mobileprovision",
                    "extraction_method": "embedded_mobileprovision_plist",
                    "note": "Provisioning profile capabilities represent developer/device authorization limits; they are not automatically equivalent to effective runtime behavior.",
                }
                for k, v in prov_ents.items():
                    records.append({
                        "key": k,
                        "value": v,
                        "source_type": "embedded_mobileprovision",
                        "source_file": f"{rel_root}/embedded.mobileprovision",
                        "extraction_method": "embedded_mobileprovision_plist",
                    })
            else:
                sources["embedded_mobileprovision"] = {
                    "source_type": "embedded_mobileprovision",
                    "status": "parse_failed",
                    "source_file": f"{rel_root}/embedded.mobileprovision",
                    "extraction_method": "embedded_mobileprovision_plist",
                    "error": "Malformed or missing Entitlements dictionary in embedded.mobileprovision",
                }
        except Exception as exc:
            sources["embedded_mobileprovision"] = {
                "source_type": "embedded_mobileprovision",
                "status": "parse_failed",
                "source_file": f"{rel_root}/embedded.mobileprovision",
                "extraction_method": "embedded_mobileprovision_plist",
                "error": str(exc),
            }
    else:
        sources["embedded_mobileprovision"] = {
            "source_type": "embedded_mobileprovision",
            "status": "not_found",
            "source_file": None,
            "extraction_method": "embedded_mobileprovision_plist",
            "reason": "file_not_present",
        }

    # Source 2: macOS codesign utility
    codesign_ents: dict[str, Any] | None = None
    if use_system_tools and shutil.which("codesign"):
        try:
            cmd = ["codesign", "-d", "--entitlements", ":-", str(bundle_path)]
            proc = subprocess.run(
                cmd,
                shell=False,
                timeout=timeout_seconds,
                capture_output=True,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                try:
                    parsed = plistlib.loads(proc.stdout)
                    if isinstance(parsed, dict) and parsed:
                        codesign_ents = parsed
                        sources["codesign_entitlements"] = {
                            "source_type": "codesign_entitlements",
                            "status": "extracted",
                            "items": codesign_ents,
                            "item_count": len(codesign_ents),
                            "source_file": f"{rel_root}/_CodeSignature",
                            "extraction_method": "codesign_cli",
                            "note": "Embedded signature entitlements extracted from Mach-O code signature metadata.",
                        }
                        for k, v in codesign_ents.items():
                            records.append({
                                "key": k,
                                "value": v,
                                "source_type": "codesign_entitlements",
                                "source_file": f"{rel_root}/_CodeSignature",
                                "extraction_method": "codesign_cli",
                            })
                except Exception as exc:
                    sources["codesign_entitlements"] = {
                        "source_type": "codesign_entitlements",
                        "status": "parse_failed",
                        "source_file": f"{rel_root}/_CodeSignature",
                        "extraction_method": "codesign_cli",
                        "error": str(exc),
                    }
            elif proc.returncode != 0 and "no signature" in proc.stderr.decode("utf-8", errors="replace").lower():
                sources["codesign_entitlements"] = {
                    "source_type": "codesign_entitlements",
                    "status": "not_found",
                    "source_file": None,
                    "extraction_method": "codesign_cli",
                    "reason": "unsigned_bundle",
                }
            elif proc.returncode != 0:
                sources["codesign_entitlements"] = {
                    "source_type": "codesign_entitlements",
                    "status": "tool_failed",
                    "source_file": None,
                    "extraction_method": "codesign_cli",
                    "error": proc.stderr.decode("utf-8", errors="replace").strip(),
                }
        except subprocess.TimeoutExpired:
            sources["codesign_entitlements"] = {
                "source_type": "codesign_entitlements",
                "status": "tool_failed",
                "source_file": None,
                "extraction_method": "codesign_cli",
                "error": "timeout",
            }
        except Exception as exc:
            sources["codesign_entitlements"] = {
                "source_type": "codesign_entitlements",
                "status": "tool_failed",
                "source_file": None,
                "extraction_method": "codesign_cli",
                "error": str(exc),
            }
    elif use_system_tools:
        sources["codesign_entitlements"] = {
            "source_type": "codesign_entitlements",
            "status": "unsupported",
            "source_file": None,
            "extraction_method": "codesign_cli",
            "reason": "tool_not_found_on_host",
        }
    else:
        sources["codesign_entitlements"] = {
            "source_type": "codesign_entitlements",
            "status": "unsupported",
            "source_file": None,
            "extraction_method": "codesign_cli",
            "reason": "system_tools_disabled",
        }

    # Determine primary extracted entitlement set preserving provenance
    if prov_ents is not None:
        primary_source_type = "embedded_mobileprovision"
        primary_items = prov_ents
        primary_source = f"{rel_root}/embedded.mobileprovision"
        primary_method = "embedded_mobileprovision_plist"
        status = "extracted"
    elif codesign_ents is not None:
        primary_source_type = "codesign_entitlements"
        primary_items = codesign_ents
        primary_source = f"{rel_root}/_CodeSignature"
        primary_method = "codesign_cli"
        status = "extracted"
    else:
        primary_source_type = None
        primary_items = {}
        primary_source = None
        primary_method = "none"
        if not use_system_tools:
            status = "not_found"
        elif sources.get("codesign_entitlements", {}).get("status") == "tool_failed":
            status = "tool_failed"
        else:
            status = "not_found"

    return {
        "status": status,
        "source_type": primary_source_type,
        "items": primary_items,
        "entitlements": primary_items,
        "item_count": len(primary_items),
        "source": primary_source,
        "extraction_method": primary_method,
        "sources": sources,
        "records": records,
        "runtime_note": "Provisioning profile entitlements represent developer/provisioning capability limits and are not automatically equivalent to effective runtime behavior.",
    }
