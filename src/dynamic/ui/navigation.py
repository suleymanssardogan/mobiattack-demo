"""Narrow navigation roles derived from Android widget hierarchy, never app identity."""
def navigation_roles(root, paths):
    roles = {}
    def item_shape(elem):
        if elem.get('class') != 'android.widget.FrameLayout':
            return False
        children = {n.get('resource-id', '').split('/')[-1] for n in elem.iter('node') if n is not elem}
        return {'navigation_bar_item_icon_container', 'navigation_bar_item_labels_group'} <= children
    for container in root.iter('node'):
        items = [e for e in container if item_shape(e)]
        if len(items) >= 2 and any(e.get('selected') == 'true' for e in items):
            for item in items:
                roles[id(item)] = {'role': 'navigation_item', 'source': 'material_navigation_hierarchy',
                    'container_path': paths[id(container)], 'control_path': paths[id(item)]}
        if container.get('class') == 'android.widget.TabWidget':
            for item in container:
                roles[id(item)] = {'role': 'navigation_item', 'source': 'android_tab_widget',
                    'container_path': paths[id(container)], 'control_path': paths[id(item)]}
    return roles
