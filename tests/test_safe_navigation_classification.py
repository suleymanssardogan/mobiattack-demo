import xml.etree.ElementTree as ET
import pytest
from src.dynamic.ui.observer import parse_ui_hierarchy
from src.dynamic.route.models import DiscoveredAction
from src.dynamic.route.graph import RouteGraph
from src.dynamic.exploration.models import navigation_classification,navigation_skip_reason


def xml(labels=('Home','Queue'), selected=True, shape=True):
    items=[]
    for i,label in enumerate(labels):
        children='<node resource-id="any:id/navigation_bar_item_icon_container"/><node resource-id="any:id/navigation_bar_item_labels_group"/>' if shape else ''
        items.append(f'<node class="android.widget.FrameLayout" clickable="true" enabled="true" selected="{str(selected and i==0).lower()}" text="{label}" bounds="[0,0][100,100]">{children}</node>')
    return '<hierarchy><node class="android.view.ViewGroup">'+''.join(items)+'</node></hierarchy>'


def actions(value):
    obs=parse_ui_hierarchy(ET.fromstring(value),'any','any.Main','any')
    return list(RouteGraph().observe_screen(obs).actions.values())


def test_material_peer_structure_allows_navigation_with_provenance():
    for a in actions(xml()):
        assert navigation_classification(a)=='SAFE_NAVIGATION'
        assert navigation_skip_reason(a) is None
        assert a.navigation_evidence['container_path']
        assert DiscoveredAction.from_dict(a.to_dict()).navigation_evidence==a.navigation_evidence


@pytest.mark.parametrize('label',['Search','More options','Queue'])
def test_label_alone_not_safe(label):
    assert navigation_classification(actions(xml((label,),shape=False))[0])=='AMBIGUOUS'
    assert navigation_skip_reason(actions(xml((label,),shape=False))[0])=='UNCERTAIN_SIDE_EFFECTS'


@pytest.mark.parametrize('label',['Subscribe','Delete account','Login','Send message','Purchase','Confirm','Update account'])
def test_structure_does_not_override_side_effect_boundaries(label):
    a=actions(xml(('Home',label)))[1]
    assert navigation_classification(a) in {'SIDE_EFFECTING','DESTRUCTIVE','CREDENTIAL/AUTH'}
    assert navigation_skip_reason(a) is not None


@pytest.mark.parametrize('selected,shape',[(False,True),(True,False)])
def test_incomplete_structure_is_ambiguous(selected,shape):
    assert all(navigation_classification(a)=='AMBIGUOUS' for a in actions(xml(selected=selected,shape=shape)))


def test_parent_class_without_standard_item_shape_is_insufficient():
    assert all(not a.navigation_evidence for a in actions(xml(shape=False)))


def test_disabled_invisible_navigation_not_discovered():
    value=xml().replace('enabled="true"','enabled="false"')
    assert actions(value)==[]


def test_tab_widget_structural_role_and_id_order_independent_of_package():
    value='<hierarchy><node class="android.widget.TabWidget"><node class="android.widget.TextView" clickable="true" text="First" bounds="[0,0][100,100]"/></node></hierarchy>'
    a=actions(value)[0]
    assert navigation_classification(a)=='SAFE_NAVIGATION'
    assert a.navigation_evidence['source']=='android_tab_widget'
