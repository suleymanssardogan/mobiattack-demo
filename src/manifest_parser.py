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
        if tag.rsplit("}", 1)[-1] == "uses-permission" or tag.rsplit("}", 1)[-1].startswith("uses-permission-sdk-"):
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
    launchers = []
    launcher_target = None

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

            if application_node.attrib.get(f"{{{ANDROID_NS}}}enabled", "true").lower() != "true":
                continue
            if elem.attrib.get(f"{{{ANDROID_NS}}}enabled", "true").lower() != "true":
                continue
            if is_alias:
                target = normalize_activity_name(
                    elem.attrib.get(f"{{{ANDROID_NS}}}targetActivity", "").strip(), package_name
                )
                declared_targets = {
                    normalize_activity_name(node.attrib.get(ATTR_NAME, "").strip(), package_name)
                    for node in application_node
                    if node.tag.rsplit("}", 1)[-1] == "activity"
                    and node.attrib.get(f"{{{ANDROID_NS}}}enabled", "true").lower() == "true"
                }
                if not target or target not in declared_targets:
                    continue

            # Detect launcher activity if not already identified
            if launcher_activity is None:
                for child in elem:
                    child_tag = child.tag
                    if child_tag.endswith("intent-filter") or child_tag == "intent-filter":
                        if _is_launcher_filter(child):
                            from src.android_identity import launch_component, AndroidIdentityError
                            try:
                                launch_component(package_name, norm_name)
                                launchers.append((norm_name, target if is_alias else None))
                            except AndroidIdentityError:
                                pass
                            break

    if launchers:
        launcher_activity, launcher_target = sorted(launchers, key=lambda candidate: candidate[0])[0]
    return {
        **_security_facts(root, application_node, package_name, path),
        "package_name": package_name,
        "permissions": sorted(permissions),
        "activities": activities,
        "launcher_activity": launcher_activity,
        "launcher_target_activity": launcher_target,
        "launcher_status": "resolved" if launcher_activity else "LAUNCHER_UNRESOLVED",
        "version_code": root.attrib.get(f"{{{ANDROID_NS}}}versionCode"),
    }


def _bool(value):
    return True if value == 'true' else False if value == 'false' else None


def _sdk(value):
    return int(value) if isinstance(value, str) and value.isdigit() else None


def _security_facts(root, app, package, path):
    """Explicit facts and platform defaults are separate; resource booleans stay unknown."""
    ns = '{' + ANDROID_NS + '}'
    sdk = root.find('uses-sdk')
    minimum = _sdk(sdk.get(ns + 'minSdkVersion')) if sdk is not None else None
    target = _sdk(sdk.get(ns + 'targetSdkVersion')) if sdk is not None else None
    sdk_evidence = {}
    if minimum is not None:
        sdk_evidence['min_sdk'] = 'AndroidManifest.xml: uses-sdk.android:minSdkVersion'
    if target is not None:
        sdk_evidence['target_sdk'] = 'AndroidManifest.xml: uses-sdk.android:targetSdkVersion'
    # Apktool moves uses-sdk values into sdkInfo. Read only this bounded,
    # numeric two-level block; unresolved resource/codename values remain unknown.
    metadata = path.parent / 'apktool.yml'
    import re
    try:
        if metadata.stat().st_size <= 262144:
            in_sdk = False
            for line in metadata.read_text().splitlines():
                if line == 'sdkInfo:':
                    in_sdk = True
                    continue
                if in_sdk and line and not line.startswith(' '):
                    break
                match = re.fullmatch(r"  (minSdkVersion|targetSdkVersion):\s*['\"]?(\d+)['\"]?\s*", line) if in_sdk else None
                if match:
                    key = 'min_sdk' if match[1] == 'minSdkVersion' else 'target_sdk'
                    manifest_attribute = sdk.get(ns + match[1]) if sdk is not None else None
                    if manifest_attribute is None and key not in sdk_evidence:
                        if key == 'min_sdk':
                            minimum = int(match[2])
                        else:
                            target = int(match[2])
                        sdk_evidence[key] = 'apktool.yml: sdkInfo.' + match[1]
    except (OSError, UnicodeError):
        pass
    facts = {'min_sdk': minimum, 'target_sdk': target, 'sdk_evidence': sdk_evidence,
             'application': {}, 'components': [], 'permission_declarations': []}
    for node in root:
        tag = node.tag.rsplit('}', 1)[-1]
        if tag == 'uses-permission' or tag.startswith('uses-permission-sdk-'):
            facts['permission_declarations'].append({'name': node.get(ns + 'name'), 'tag': tag,
                'max_sdk': _sdk(node.get(ns + 'maxSdkVersion')),
                'uses_permission_flags': node.get(ns + 'usesPermissionFlags'), 'source': 'AndroidManifest.xml'})
    facts['permission_declarations'].sort(key=lambda row: (row['name'] or '', row['tag'], row['max_sdk'] or 0))
    if app is None:
        return facts
    attrs = {'debuggable': 'debuggable', 'allow_backup': 'allowBackup',
             'uses_cleartext_traffic': 'usesCleartextTraffic', 'enabled': 'enabled'}
    facts['application'] = {key: _bool(app.get(ns + attribute)) for key, attribute in attrs.items()}
    facts['application']['observed_attributes'] = {attribute: app.get(ns + attribute) for attribute in attrs.values()}
    facts['application']['network_security_config'] = app.get(ns + 'networkSecurityConfig')
    facts['application']['enabled_effective'] = True if app.get(ns + 'enabled') is None else _bool(app.get(ns + 'enabled'))
    facts['network_security_policy'] = {'status': 'not_declared', 'cleartext_permissions': []}
    reference = facts['application']['network_security_config']
    if reference:
        policy = facts['network_security_policy']
        policy['status'] = 'unresolved'
        import re
        if re.fullmatch(r'@xml/[a-zA-Z0-9_]+', reference):
            resource = path.parent / 'res/xml' / (reference[5:] + '.xml')
            try:
                config = ET.parse(resource).getroot()
                if config.tag != 'network-security-config':
                    raise ValueError('Invalid network security configuration')
                policy['status'] = 'resolved'
                for node in config.iter():
                    value = _bool(node.get('cleartextTrafficPermitted'))
                    if value is not None and node.tag in {'base-config', 'domain-config'}:
                        policy['cleartext_permissions'].append({'value': value,
                            'source': 'res/xml/' + resource.name, 'component': node.tag,
                            'domains': sorted((d.text or '').strip() for d in node.findall('domain'))})
            except (OSError, ET.ParseError, ValueError):
                pass
    for node in app:
        kind = node.tag.rsplit('}', 1)[-1]
        if kind not in {'activity', 'activity-alias', 'service', 'receiver', 'provider'}:
            continue
        filters = []
        for intent in node.findall('intent-filter'):
            filters.append({'actions': sorted(n.get(ns + 'name', '') for n in intent.findall('action')),
                'categories': sorted(n.get(ns + 'name', '') for n in intent.findall('category')),
                'data': sorted([dict(sorted(n.attrib.items())) for n in intent.findall('data')], key=str)})
        filters.sort(key=str)
        exported = _bool(node.get(ns + 'exported'))
        if node.get(ns + 'exported') is None:
            effective = (target <= 16 if target is not None else None) if kind == 'provider' else (None if filters and (target is None or target >= 31) else bool(filters))
            exported_source = 'platform_default' if effective is not None else 'unknown'
        else:
            effective = exported
            exported_source = 'explicit' if exported is not None else 'unknown'
        component_enabled = True if node.get(ns + 'enabled') is None else _bool(node.get(ns + 'enabled'))
        app_enabled = facts['application']['enabled_effective']
        enabled = False if False in (app_enabled, component_enabled) else True if app_enabled is True and component_enabled is True else None
        facts['components'].append({'type': kind, 'name': normalize_activity_name(node.get(ns + 'name', ''), package),
            'exported': exported, 'exported_effective': effective, 'exported_source': exported_source,
            'enabled': _bool(node.get(ns + 'enabled')), 'enabled_effective': enabled,
            'permission': node.get(ns + 'permission', app.get(ns + 'permission')),
            'read_permission': node.get(ns + 'readPermission'), 'write_permission': node.get(ns + 'writePermission'),
            'target_activity': normalize_activity_name(node.get(ns + 'targetActivity', ''), package) or None,
            'intent_filters': filters, 'source': 'AndroidManifest.xml'})
    facts['components'].sort(key=lambda row: (row['type'], row['name'], str(row)))
    for plural, kind in [('services', 'service'), ('receivers', 'receiver'), ('providers', 'provider')]:
        facts[plural] = [row for row in facts['components'] if row['type'] == kind]
    return facts
