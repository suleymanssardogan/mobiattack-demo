"""Android Manifest Extractor.

Extracts deterministic facts from a readable AndroidManifest.xml decoded by Apktool:
- package_name
- permissions
- activities
- launcher_activity

Launcher aliases are returned as launchable components; activities retains actual activity declarations.
"""

from pathlib import Path
import xml.etree.ElementTree as ET

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ATTR_NAME = f"{{{ANDROID_NS}}}name"
ACTION_MAIN = "android.intent.action.MAIN"
CATEGORY_LAUNCHER = "android.intent.category.LAUNCHER"


def normalize_activity_name(name: str, package_name: str) -> str:
    """Normalize activity name to its fully-qualified representation.

    Rules:
    - Case 1: Starts with '.' (e.g. '.MainActivity') -> package_name + name
    - Case 2: No dot in name (e.g. 'MainActivity') -> package_name + '.' + name
    - Case 3: Fully qualified (contains dot, does not start with '.') -> keep as-is
    """
    if not name:
        return ""

    if name.startswith("."):
        return f"{package_name}{name}"
    elif "." not in name:
        return f"{package_name}.{name}"
    else:
        return name


def _is_launcher_filter(intent_filter: ET.Element) -> bool:
    """Return True if an intent-filter contains both MAIN action and LAUNCHER category."""
    has_main = False
    has_launcher = False

    for child in intent_filter:
        tag = child.tag
        # Handle tags with or without namespace
        if tag.endswith("action") or tag == "action":
            if child.attrib.get(ATTR_NAME) == ACTION_MAIN:
                has_main = True
        elif tag.endswith("category") or tag == "category":
            if child.attrib.get(ATTR_NAME) == CATEGORY_LAUNCHER:
                has_launcher = True

        if has_main and has_launcher:
            return True

    return False


def parse_manifest(manifest_path: str | Path) -> dict:
    """Parse a readable AndroidManifest.xml and extract key deterministic metadata.

    Args:
        manifest_path: Path to the AndroidManifest.xml file.

    Returns:
        dict with keys:
            - package_name (str)
            - permissions (list[str])
            - activities (list[str])
            - launcher_activity (str | None)

    Raises:
        FileNotFoundError: If the manifest file does not exist.
        ValueError: If the XML is malformed or missing the root manifest tag.
    """
    path = Path(manifest_path)
    if not path.is_file():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

    try:
        tree = ET.parse(path)
    except ET.ParseError as err:
        raise ValueError(f"Failed to parse XML from {manifest_path}: {err}") from err

    root = tree.getroot()
    # Ensure root is a manifest tag (with or without namespace)
    if not (root.tag.endswith("manifest") or root.tag == "manifest"):
        raise ValueError(f"Root element must be <manifest>, found <{root.tag}>")

    package_name = root.attrib.get("package", "").strip()

    # Extract uses-permission elements
    permissions: list[str] = []
    for elem in root:
        tag = elem.tag
        if tag.endswith("uses-permission") or tag == "uses-permission":
            perm_name = elem.attrib.get(ATTR_NAME)
            if perm_name and perm_name not in permissions:
                permissions.append(perm_name)

    # Locate application node
    application_node = None
    for elem in root:
        tag = elem.tag
        if tag.endswith("application") or tag == "application":
            application_node = elem
            break

    activities: list[str] = []
    launcher_activity: str | None = None

    if application_node is not None:
        for elem in application_node:
            tag = elem.tag
            is_alias = tag.rsplit("}", 1)[-1] == "activity-alias"
            if not (tag.endswith("activity") or is_alias):
                continue

            raw_name = elem.attrib.get(ATTR_NAME)
            if not raw_name:
                # Skip activities without android:name attribute
                continue

            norm_name = normalize_activity_name(raw_name.strip(), package_name)
            if not is_alias and norm_name not in activities:
                activities.append(norm_name)

            if elem.attrib.get(f"{{{ANDROID_NS}}}enabled") == "false":
                continue
            if is_alias:
                target = normalize_activity_name(
                    elem.attrib.get(f"{{{ANDROID_NS}}}targetActivity", "").strip(), package_name
                )
                declared_targets = {
                    normalize_activity_name(node.attrib.get(ATTR_NAME, "").strip(), package_name)
                    for node in application_node
                    if node.tag.rsplit("}", 1)[-1] == "activity"
                    and node.attrib.get(f"{{{ANDROID_NS}}}enabled") != "false"
                }
                if not target or target not in declared_targets:
                    continue

            # Detect launcher activity if not already identified
            if launcher_activity is None:
                for child in elem:
                    child_tag = child.tag
                    if child_tag.endswith("intent-filter") or child_tag == "intent-filter":
                        if _is_launcher_filter(child):
                            launcher_activity = norm_name
                            break

    return {
        "package_name": package_name,
        "permissions": permissions,
        "activities": activities,
        "launcher_activity": launcher_activity,
    }
