"""Generic Android UI Observation and Screen State Fingerprinting (Week 1 — Day 4 Task 4.2).

Provides deterministic, side-effect-free screen observation:
- Parses UI Automator XML hierarchy without clicking or modifying state
- Discovers clickable elements and input fields
- Calculates precise bounds and center coordinates
- Computes deterministic, structural screen_identity fingerprints (resilient to dynamic texts)
- Sanitizes sensitive password fields
- Distinguishes target app from system/dialog screens
- Executes bounded observation stabilization loop for sluggish UI transitions
"""

from __future__ import annotations
from src.dynamic.deadline import bounded_operation, current_deadline

import hashlib
import logging
import re
import time
from typing import Any, Callable
import xml.etree.ElementTree as ET

from src.android_runtime_launcher import (
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    AndroidRuntimeError,
    get_current_activity,
    resolve_adb_executable,
)
from src.dynamic.ui.models import ActionCandidate, ScreenObservation, UiNode
from src.play_store_ui_automator import dump_window_hierarchy, parse_node_bounds

logger = logging.getLogger(__name__)

DEFAULT_UI_OBSERVE_MAX_ATTEMPTS: int = 4
DEFAULT_UI_OBSERVE_POLL_INTERVAL: float = 0.4
DEFAULT_UI_OBSERVE_DEADLINE_SECONDS: float = 4.0

KNOWN_INPUT_CLASSES = {
    "android.widget.EditText",
    "android.widget.AutoCompleteTextView",
    "android.widget.MultiAutoCompleteTextView",
    "com.google.android.material.textfield.TextInputEditText",
    "androidx.appcompat.widget.AppCompatEditText",
}

SYSTEM_PACKAGE_PREFIXES = (
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
    "com.android.packageinstaller",
    "com.google.android.packageinstaller",
    "com.android.systemui",
    "com.google.android.gms",
    "android",
)


class UIObservationError(AndroidRuntimeError):
    """Raised when screen observation cannot be completed within bounded retries."""
    pass


def compute_node_id(
    class_name: str,
    resource_id: str,
    bounds: tuple[int, int, int, int],
    clickable: bool,
    editable: bool,
    structural_key: str = "",
) -> str:
    """Computes a deterministic 12-character hex ID for an interactive UI node."""
    raw = f"{class_name}:{resource_id}:{structural_key}:{1 if clickable else 0}:{1 if editable else 0}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def compute_screen_identity(
    package_name: str,
    activity_name: str,
    nodes: list[UiNode],
) -> str:
    """Computes a deterministic 16-character structural fingerprint for the screen.

    Strict Resilience Rules:
    - Dynamic text (clocks, balances, usernames, counters) is excluded.
    - Captures structural elements: class, resource-id, interactive flags,
      accessibility labels for controls, hierarchy positions and checked/selected state.
    - Compose nodes lacking resource-ids are distinguished by structural descriptors.
    """
    descriptors: list[str] = []
    for node in nodes:
        # Geometry remains tap evidence, not visited-state identity.
        desc_label = node.content_desc.strip() if (node.clickable or node.editable) else ""
        control_label = re.sub(r"\d+", "#", node.text) if node.clickable and not node.editable and not node.password else ""
        descriptor = (
            f"{node.node_id}|{node.class_name}|{node.resource_id}|{desc_label}|"
            f"{int(node.clickable)}|{int(node.editable)}|{int(node.enabled)}|"
            f"{int(node.checkable)}|{int(node.checked)}|{int(node.selected)}|{int(node.visible)}|{control_label}"
        )
        descriptors.append(descriptor)

    # Deterministic alphabetical ordering
    descriptors.sort()

    payload = f"{package_name}/{activity_name}\n" + "\n".join(descriptors)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def extract_ui_node(node_elem: ET.Element, structural_key: str = "") -> UiNode | None:
    """Extracts and normalizes a UiNode from an XML ElementTree node."""
    attrib = node_elem.attrib
    class_name = (attrib.get("class") or "").strip()
    resource_id = (attrib.get("resource-id") or "").strip()
    raw_text = (attrib.get("text") or "").strip()
    content_desc = (attrib.get("content-desc") or "").strip()
    package = (attrib.get("package") or "").strip()

    clickable = attrib.get("clickable", "false").lower() == "true"
    enabled = attrib.get("enabled", "true").lower() == "true"
    focusable = attrib.get("focusable", "false").lower() == "true"
    focused = attrib.get("focused", "false").lower() == "true"
    scrollable = attrib.get("scrollable", "false").lower() == "true"
    checkable = attrib.get("checkable", "false").lower() == "true"
    checked = attrib.get("checked", "false").lower() == "true"

    # Input / Editable detection
    is_password = attrib.get("password", "false").lower() == "true"
    is_editable = (
        class_name in KNOWN_INPUT_CLASSES
        or class_name.endswith(".EditText")
        or "EditText" in class_name
        or attrib.get("editable", "false").lower() == "true"
    )

    # Privacy: password text masking
    if is_password or (is_editable and any(p in resource_id.lower() for p in ("password", "passwd", "pin_code"))):
        is_password = True
        safe_text = "[PROTECTED]" if raw_text else ""
    else:
        safe_text = raw_text

    # Bounds parsing
    bounds_tuple = parse_node_bounds(attrib.get("bounds"))
    if not bounds_tuple:
        bounds_tuple = (0, 0, 0, 0)

    x1, y1, x2, y2 = bounds_tuple
    width = max(0, x2 - x1)
    height = max(0, y2 - y1)
    center_x = (x1 + x2) // 2
    center_y = (y1 + y2) // 2

    node_id = compute_node_id(
        class_name=class_name,
        resource_id=resource_id,
        bounds=bounds_tuple,
        clickable=clickable,
        editable=is_editable,
        structural_key=structural_key,
    )

    return UiNode(
        node_id=node_id,
        class_name=class_name,
        package=package,
        resource_id=resource_id,
        text=safe_text,
        content_desc=content_desc,
        clickable=clickable,
        enabled=enabled,
        focusable=focusable,
        focused=focused,
        editable=is_editable,
        password=is_password,
        scrollable=scrollable,
        checkable=checkable,
        checked=checked,
        selected=attrib.get("selected", "false").lower() == "true",
        visible=attrib.get("visible-to-user", "true").lower() != "false" and width > 0 and height > 0,
        bounds=bounds_tuple,
        center_x=center_x,
        center_y=center_y,
        width=width,
        height=height,
    )


def parse_ui_hierarchy(
    root: ET.Element,
    foreground_package: str,
    foreground_activity: str,
    target_package: str = "",
    observation_attempts: int = 1,
) -> ScreenObservation:
    """Parses a UI Automator XML root element into a complete ScreenObservation."""
    nodes: list[UiNode] = []
    action_candidates: list[ActionCandidate] = []
    clickable_count = 0
    input_count = 0
    diagnostics: list[str] = []

    # Preserve hierarchy position for repeated/no-id controls; never use tap coordinates as identity.
    paths = {}
    def index_tree(elem, path="root"):
        paths[id(elem)] = path
        for i, child in enumerate(elem):
            index_tree(child, f"{path}/{i}")
    index_tree(root)
    from src.dynamic.ui.navigation import navigation_roles
    roles = navigation_roles(root, paths)
    # Traverse all nodes safely
    for elem in root.iter("node"):
        try:
            node = extract_ui_node(elem, structural_key=paths[id(elem)])
            if not node:
                continue

            nodes.append(node)

            if node.editable:
                input_count += 1

            if node.clickable:
                clickable_count += 1
                # Action candidate rules: must be enabled and have positive visible bounds
                if node.enabled and node.visible:
                    action_type = "input" if node.editable else "toggle" if node.checkable else "click"
                    # A clickable row often owns its non-clickable label. Do not promote the child
                    # to a second action, or inherit editable/password values.
                    label = node.text
                    if not node.editable and not node.password:
                        labels = [label] if label else []
                        for child in elem.iter("node"):
                            if child is elem or child.get("clickable") == "true":
                                continue
                            parsed = extract_ui_node(child)
                            if parsed and not parsed.editable and not parsed.password and parsed.enabled and parsed.visible:
                                value = parsed.text or parsed.content_desc
                                if value:
                                    labels.append(value)
                        label = " ".join(dict.fromkeys(labels))[:200]
                        node.text = label
                    candidate = ActionCandidate(
                        node_id=node.node_id,
                        resource_id=node.resource_id,
                        class_name=node.class_name,
                        text=label,
                        content_desc=node.content_desc,
                        bounds=node.bounds,
                        center_x=node.center_x,
                        center_y=node.center_y,
                        action_type=action_type,
                        navigation_evidence=roles.get(id(elem), {}),
                    )
                    action_candidates.append(candidate)
        except Exception as exc:
            diagnostics.append(f"Failed to parse node element: {exc}")

    if any(e.get("actions") or e.get("accessibility-actions") for e in root.iter("node")):
        diagnostics.append("Accessibility-only actions are not supported by the UIAutomator click backend.")
    # Derive package from XML root if dumpsys did not provide one
    if not foreground_package and nodes:
        for n in nodes:
            if n.package:
                foreground_package = n.package
                break

    is_target_pkg = bool(target_package and foreground_package == target_package)
    is_dialog = any(foreground_package.startswith(prefix) for prefix in SYSTEM_PACKAGE_PREFIXES)

    screen_identity = compute_screen_identity(
        package_name=foreground_package,
        activity_name=foreground_activity,
        nodes=nodes,
    )

    return ScreenObservation(
        screen_identity=screen_identity,
        foreground_package=foreground_package,
        foreground_activity=foreground_activity,
        target_package=target_package,
        is_target_package=is_target_pkg,
        is_dialog_or_system=is_dialog,
        nodes=nodes,
        clickable_count=clickable_count,
        input_count=input_count,
        action_candidates=action_candidates,
        observation_attempts=observation_attempts,
        diagnostics=diagnostics,
    )


@bounded_operation(4.0, field="deadline_seconds")
def observe_screen(
    serial: str,
    adb_bin: str | None = None,
    target_package: str = "",
    max_attempts: int = DEFAULT_UI_OBSERVE_MAX_ATTEMPTS,
    poll_interval: float = DEFAULT_UI_OBSERVE_POLL_INTERVAL,
    deadline_seconds: float = DEFAULT_UI_OBSERVE_DEADLINE_SECONDS,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> ScreenObservation:
    """Observes the current screen hierarchy on the target device via a bounded stabilization loop.

    - Side-effect-free observation only (no tap, no input, no navigation)
    - Retries transient empty/stale dumps
    - Accurately captures permission dialogs and system UI states without crashing
    """
    start_time = clock()
    attempt = 0
    last_error: Exception | None = None
    last_observation: ScreenObservation | None = None

    while attempt < max_attempts and (clock() - start_time) < deadline_seconds:
        attempt += 1

        # 1. Query foreground package and activity
        activity_info = get_current_activity(
            adb_serial=serial,
            adb_executable=adb_bin,
            timeout_seconds=min(DEFAULT_COMMAND_TIMEOUT_SECONDS, 8.0),
        )
        if current_deadline().remaining() <= 0:
            raise UIObservationError('UI observation deadline exhausted')
        fg_pkg = activity_info.get("observed_package") or ""
        fg_act = activity_info.get("observed_activity") or ""

        # 2. Dump XML hierarchy
        try:
            root = dump_window_hierarchy(
                serial=serial,
                adb_bin=adb_bin,
                timeout_seconds=min(DEFAULT_COMMAND_TIMEOUT_SECONDS, 10.0),
            )
            if current_deadline().remaining() <= 0:
                raise UIObservationError('UI observation deadline exhausted')
            obs = parse_ui_hierarchy(
                root=root,
                foreground_package=fg_pkg,
                foreground_activity=fg_act,
                target_package=target_package,
                observation_attempts=attempt,
            )
            last_observation = obs

            # If target package was requested and we are on target package, observation is optimal!
            if not target_package or obs.foreground_package == target_package:
                return obs

            # If on a known system dialog (permission, package installer), return immediately
            if obs.is_dialog_or_system:
                return obs

        except Exception as exc:
            last_error = exc

        # Sleep before next polling attempt if deadline permits
        elapsed = clock() - start_time
        remaining = deadline_seconds - elapsed
        if attempt < max_attempts and remaining > 0:
            wait_time = min(poll_interval, remaining, current_deadline().remaining())
            if wait_time > 0:
                sleeper(wait_time)

    # If we obtained at least one valid ScreenObservation, return it
    if last_observation is not None and current_deadline().remaining() > 0:
        last_observation.observation_attempts = attempt
        return last_observation

    # Hierarchy was never dumped successfully
    raise UIObservationError(
        f"Failed to observe screen on device '{serial}' after {attempt} attempts: {last_error}"
    ) from last_error
