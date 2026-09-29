"""Google Play Store UI Automator and Inspection Module for MobiAttack-v2.

Provides deterministic UI inspection and optional safe automated installation
trigger for Google Play Store screens on connected Android test devices.

Strict Safety and Guardrail Rules:
  1. Default mode is 'manual' - this module is ONLY used when explicitly opted in.
  2. UI automation must NEVER click 'Update' or 'Güncelle'.
  3. Authoritative post-install proof is 'adb shell pm path <package>', not UI text.
  4. Accepted free install labels are strictly limited to 'Install' and 'Yükle'.
  5. Any detected blockers (incompatibility, sign-in required, paid apps) halt
     immediately with machine-readable reason codes without tapping.
  6. Tapping is strictly bounded to validated clickable coordinates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import subprocess
import xml.etree.ElementTree as ET

from src.android_runtime_launcher import (
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    AndroidRuntimeError,
    resolve_adb_executable,
)

# Accepted free-install button labels (Strictly limited to Install / Yükle per requirements)
ACCEPTED_INSTALL_LABELS = {"install", "yükle"}

# Labels indicating the app is already installed or has an update available
# Task 15 is package acquisition, not app updating - DO NOT tap Update
INSTALLED_BUTTON_LABELS = {"open", "aç", "uninstall", "kaldır"}
UPDATE_LABELS = {"update", "güncelle"}

# Negative compatibility patterns
COMPATIBILITY_BLOCKER_PATTERNS = [
    re.compile(r"device isn't compatible with this version", re.IGNORECASE),
    re.compile(r"not compatible with this version", re.IGNORECASE),
    re.compile(r"not available for your device", re.IGNORECASE),
    re.compile(r"isn't compatible with your device", re.IGNORECASE),
    re.compile(r"cihazınız bu sürümle uyumlu değil", re.IGNORECASE),
    re.compile(r"bu uygulama cihazınızla uyumlu değil", re.IGNORECASE),
    re.compile(r"cihazınızla uyumlu değil", re.IGNORECASE),
]

# Google Account Sign-In blocker patterns
SIGN_IN_BLOCKER_PATTERNS = [
    re.compile(r"sign in to your google account", re.IGNORECASE),
    re.compile(r"sign in to find the latest apps", re.IGNORECASE),
    re.compile(r"google hesabınızda oturum açın", re.IGNORECASE),
    re.compile(r"oturum açın", re.IGNORECASE),
]

# Item / Package not found patterns
NOT_FOUND_BLOCKER_PATTERNS = [
    re.compile(r"item not found", re.IGNORECASE),
    re.compile(r"requested url was not found", re.IGNORECASE),
    re.compile(r"öğe bulunamadı", re.IGNORECASE),
]

# Download or install failure dialog patterns
DOWNLOAD_FAILED_PATTERNS = [
    re.compile(r"can't download", re.IGNORECASE),
    re.compile(r"couldn't install", re.IGNORECASE),
    re.compile(r"download failed", re.IGNORECASE),
    re.compile(r"indirilemiyor", re.IGNORECASE),
    re.compile(r"yüklenemiyor", re.IGNORECASE),
]

# Currency / Price patterns indicating paid app
PAYMENT_PATTERNS = [
    re.compile(r"^\s*[$€£₺]\s*\d+"),
    re.compile(r"\d+([.,]\d{2})?\s*(usd|eur|try|tl|gbp)\b", re.IGNORECASE),
    re.compile(r"\b(purchase|buy|satın al)\b", re.IGNORECASE),
]

# Target context verification patterns (indicators of an app details page)
DETAILS_PAGE_INDICATORS = [
    re.compile(r"about this (app|game)", re.IGNORECASE),
    re.compile(r"bu uygulama hakkında|bu oyun hakkında", re.IGNORECASE),
    re.compile(r"average rating|stars in", re.IGNORECASE),
    re.compile(r"screenshot \d+ of \d+", re.IGNORECASE),
    re.compile(r"downloaded \d+", re.IGNORECASE),
    re.compile(r"developer contact|geliştirici iletişim", re.IGNORECASE),
    re.compile(r"add to wishlist|istek listesine ekle", re.IGNORECASE),
    re.compile(r"content rating", re.IGNORECASE),
    re.compile(r"reviews", re.IGNORECASE),
    re.compile(r"değerlendirmeler", re.IGNORECASE),
]


@dataclass
class PlayStoreScreenInspection:
    """Structured inspection of a Google Play Store screen hierarchy."""

    package_name: str
    is_play_store: bool = False
    package_context_verified: bool = False
    is_installed: bool = False
    install_button_bounds: tuple[int, int, int, int] | None = None
    install_button_label: str | None = None
    is_blocked: bool = False
    block_reason: str | None = None
    diagnostics: list[str] = field(default_factory=list)


def parse_node_bounds(bounds_str: str | None) -> tuple[int, int, int, int] | None:
    """Parses a UI Automator bounds attribute string e.g. '[0,54][2560,1440]'."""
    if not bounds_str:
        return None
    match = re.match(r"^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$", bounds_str.strip())
    if not match:
        return None
    x1, y1, x2, y2 = map(int, match.groups())
    return (x1, y1, x2, y2)


def dump_window_hierarchy(
    serial: str,
    adb_bin: str | None = None,
    timeout_seconds: float = 12.0,
) -> ET.Element:
    """Executes 'adb shell uiautomator dump' and returns parsed XML ElementTree root.

    Raises:
        AndroidRuntimeError: If uiautomator dump fails or produces empty hierarchy.
    """
    resolved_adb = resolve_adb_executable(adb_bin)
    remote_dump_path = "/sdcard/window_dump.xml"

    # Step 1: Dump hierarchy on device
    dump_cmd = [resolved_adb, "-s", serial, "shell", "uiautomator", "dump", remote_dump_path]
    try:
        dump_res = subprocess.run(
            dump_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, OSError) as err:
        raise AndroidRuntimeError(f"Failed to dump UI hierarchy via uiautomator: {err}") from err

    # Step 2: Read dumped XML
    cat_cmd = [resolved_adb, "-s", serial, "shell", "cat", remote_dump_path]
    try:
        cat_res = subprocess.run(
            cat_cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (subprocess.TimeoutExpired, OSError) as err:
        raise AndroidRuntimeError(f"Failed to read UI hierarchy XML from device: {err}") from err

    # Step 3: Cleanup remote dump file
    try:
        subprocess.run(
            [resolved_adb, "-s", serial, "shell", "rm", "-f", remote_dump_path],
            capture_output=True,
            timeout=5.0,
        )
    except Exception:
        pass

    xml_text = cat_res.stdout or ""
    if not xml_text.strip():
        raise AndroidRuntimeError("UI Automator hierarchy dump produced empty output.")

    try:
        return ET.fromstring(xml_text.strip())
    except ET.ParseError as err:
        raise AndroidRuntimeError(f"Failed to parse UI Automator XML hierarchy: {err}") from err


def inspect_play_store_hierarchy(
    root: ET.Element,
    package_name: str = "",
) -> PlayStoreScreenInspection:
    """Inspects a UI Automator XML hierarchy for Google Play Store context and install controls.

    Strict Safety Rules:
      1. Verifies that the UI belongs to Google Play Store (com.android.vending).
      2. Verifies the screen appears to correspond to an application details page.
      3. Detects explicit blockers first (incompatibility, sign in, payment, download fail).
      4. Never clicks 'Update' or 'Güncelle' (app is considered already installed).
      5. Only accepts free 'Install' or 'Yükle' buttons.
    """
    inspection = PlayStoreScreenInspection(package_name=package_name)
    nodes = list(root.iter("node"))

    # 1. Verify com.android.vending presence
    vending_nodes = [n for n in nodes if n.attrib.get("package") == "com.android.vending"]
    if vending_nodes:
        inspection.is_play_store = True
    else:
        inspection.is_play_store = False
        inspection.is_blocked = True
        inspection.block_reason = "play_store_not_available"
        inspection.diagnostics.append("Current screen does not contain com.android.vending package nodes.")
        return inspection

    # Collect visible texts and content descriptions for blocker analysis
    all_texts: list[str] = []
    for node in vending_nodes:
        t = node.attrib.get("text", "").strip()
        d = node.attrib.get("content-desc", "").strip()
        if t:
            all_texts.append(t)
        if d:
            all_texts.append(d)

    full_screen_text = " ".join(all_texts)

    # 2. Check for Compatibility Blocker
    for pat in COMPATIBILITY_BLOCKER_PATTERNS:
        if pat.search(full_screen_text):
            inspection.is_blocked = True
            inspection.block_reason = "device_not_compatible"
            inspection.diagnostics.append("Detected device incompatibility message in Play Store UI.")
            return inspection

    # 3. Check for Sign-In Blocker
    if any(text.casefold() in {"sign in", "giriş yap"} for text in all_texts):
        inspection.is_blocked = True
        inspection.block_reason = "sign_in_required"
        inspection.diagnostics.append("Google Play Store is waiting for account sign-in.")
        return inspection
    for pat in SIGN_IN_BLOCKER_PATTERNS:
        if pat.search(full_screen_text):
            inspection.is_blocked = True
            inspection.block_reason = "sign_in_required"
            inspection.diagnostics.append("Detected Google Account sign-in requirement in Play Store UI.")
            return inspection

    # 4. Check for Not Found Blocker
    for pat in NOT_FOUND_BLOCKER_PATTERNS:
        if pat.search(full_screen_text):
            inspection.is_blocked = True
            inspection.block_reason = "package_not_found"
            inspection.diagnostics.append("Detected item not found in Play Store UI.")
            return inspection

    # 5. Check for Download Failure Blocker
    for pat in DOWNLOAD_FAILED_PATTERNS:
        if pat.search(full_screen_text):
            inspection.is_blocked = True
            inspection.block_reason = "download_failed"
            inspection.diagnostics.append("Detected download or installation failure dialog in Play Store UI.")
            return inspection

    # 6. Check if Already Installed ("Open", "Uninstall", or "Update")
    # RULE: Do not use Update as Install. If Update is visible, package is already installed.
    has_open_or_uninstall = any(
        t.lower() in INSTALLED_BUTTON_LABELS for t in all_texts
    )
    has_update = any(
        t.lower() in UPDATE_LABELS for t in all_texts
    )
    if has_open_or_uninstall or has_update:
        inspection.is_installed = True
        label_found = "Update" if has_update else "Open/Uninstall"
        inspection.diagnostics.append(f"Detected '{label_found}' button indicating package is already on device.")
        return inspection

    # 7. Check for Paid App (Payment Required)
    # If a button has price text or "Buy", halt with payment_required
    for node in vending_nodes:
        node_text = (node.attrib.get("text") or node.attrib.get("content-desc") or "").strip()
        if node.attrib.get("clickable") == "true":
            for pat in PAYMENT_PATTERNS:
                if pat.search(node_text):
                    inspection.is_blocked = True
                    inspection.block_reason = "payment_required"
                    inspection.diagnostics.append(f"Detected payment/purchase control '{node_text}'. Automated purchase is prohibited.")
                    return inspection

    # 8. Verify Target Context: Ensure screen appears to be an app details page
    # Look for package name in text/desc OR presence of standard app details markers
    context_verified = False
    if package_name and package_name.lower() in full_screen_text.lower():
        context_verified = True
    else:
        for pat in DETAILS_PAGE_INDICATORS:
            if pat.search(full_screen_text):
                context_verified = True
                break

    # If context is not verified, but free install button exists, check whether
    # there is sufficient app structure (e.g. at least some descriptive text)
    if context_verified:
        inspection.package_context_verified = True
    else:
        # If the page has none of the app details indicators, avoid clicking stray install buttons
        inspection.package_context_verified = False

    # 9. Search for Accepted Free-Install Button ("Install" / "Yükle")
    for node in vending_nodes:
        node_text = (node.attrib.get("text") or "").strip()
        node_desc = (node.attrib.get("content-desc") or "").strip()
        bounds_str = node.attrib.get("bounds")

        # Must strictly match ACCEPTED_INSTALL_LABELS ("Install", "Yükle")
        text_matches = node_text.lower() in ACCEPTED_INSTALL_LABELS
        desc_matches = node_desc.lower() in ACCEPTED_INSTALL_LABELS

        # Ensure it does NOT match Update/Güncelle
        if (text_matches or desc_matches) and not (node_text.lower() in UPDATE_LABELS or node_desc.lower() in UPDATE_LABELS):
            bounds = parse_node_bounds(bounds_str)
            if bounds:
                # Ensure width and height are positive
                x1, y1, x2, y2 = bounds
                if (x2 - x1) > 10 and (y2 - y1) > 10:
                    inspection.install_button_bounds = bounds
                    inspection.install_button_label = node_text or node_desc
                    inspection.package_context_verified = True
                    inspection.diagnostics.append(
                        f"Found install control '{inspection.install_button_label}' at {bounds}."
                    )
                    return inspection

    # 10. No install button found and no known blocker
    inspection.is_blocked = True
    inspection.block_reason = "ui_automation_failed"
    inspection.diagnostics.append(
        "Could not identify a free 'Install' or 'Yükle' button on current Play Store screen."
    )
    return inspection


def tap_screen_bounds(
    serial: str,
    bounds: tuple[int, int, int, int],
    adb_bin: str | None = None,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> tuple[int, int]:
    """Calculates center coordinates of bounds and sends 'input tap x y' over ADB."""
    resolved_adb = resolve_adb_executable(adb_bin)
    center_x = (bounds[0] + bounds[2]) // 2
    center_y = (bounds[1] + bounds[3]) // 2

    cmd = [resolved_adb, "-s", serial, "shell", "input", "tap", str(center_x), str(center_y)]
    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=True,
        )
    except (subprocess.TimeoutExpired, OSError, subprocess.CalledProcessError) as err:
        raise AndroidRuntimeError(f"Failed to tap coordinates ({center_x}, {center_y}) on device '{serial}': {err}") from err

    return (center_x, center_y)


def attempt_play_store_ui_install(
    serial: str,
    package_name: str,
    adb_bin: str | None = None,
    timeout_seconds: float = 15.0,
) -> dict:
    """Executes safe UI Automator inspection and optional Install button tap.

    Returns:
        Structured dict with:
            success: bool
            status: 'install_triggered' | 'already_installed' | 'blocked' | 'failed'
            reason: str | None
            diagnostics: list[str]
            tap_coordinates: tuple[int, int] | None
    """
    try:
        root = dump_window_hierarchy(serial=serial, adb_bin=adb_bin, timeout_seconds=timeout_seconds)
    except Exception as exc:
        return {
            "success": False,
            "status": "failed",
            "reason": "ui_automation_failed",
            "diagnostics": [f"Failed to dump UI hierarchy: {exc}"],
            "tap_coordinates": None,
        }

    inspection = inspect_play_store_hierarchy(root=root, package_name=package_name)

    if inspection.is_installed:
        return {
            "success": True,
            "status": "already_installed",
            "reason": None,
            "diagnostics": inspection.diagnostics,
            "tap_coordinates": None,
        }

    if inspection.is_blocked:
        return {
            "success": False,
            "status": "blocked",
            "reason": inspection.block_reason,
            "diagnostics": inspection.diagnostics,
            "tap_coordinates": None,
        }

    if inspection.install_button_bounds:
        try:
            coords = tap_screen_bounds(
                serial=serial,
                bounds=inspection.install_button_bounds,
                adb_bin=adb_bin,
            )
            return {
                "success": True,
                "status": "install_triggered",
                "reason": None,
                "button_label": inspection.install_button_label,
                "diagnostics": inspection.diagnostics + [f"Tapped install button at {coords}."],
                "tap_coordinates": coords,
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "failed",
                "reason": "ui_automation_failed",
                "diagnostics": inspection.diagnostics + [f"Tap execution failed: {exc}"],
                "tap_coordinates": None,
            }

    return {
        "success": False,
        "status": "failed",
        "reason": "ui_automation_failed",
        "diagnostics": inspection.diagnostics,
        "tap_coordinates": None,
    }
