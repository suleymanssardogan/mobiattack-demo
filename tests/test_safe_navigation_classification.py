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


@pytest.mark.parametrize('label',['Shuffle','More options','Queue'])
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


@pytest.mark.parametrize('exit_label', [
    'Close app', 'Exit app', 'Quit app', 'Close application',
    'Exit application', 'Terminate app', 'Force close',
])
def test_terminal_exit_actions_rejected(exit_label):
    from src.dynamic.exploration.models import is_terminal_exit_action, is_safe_clickable_action
    # Even on a disclosure screen, exit actions must be rejected as SIDE_EFFECT_BOUNDARY
    xml_str = f'<hierarchy><node class="android.widget.ScrollView"><node class="android.widget.TextView" text="Privacy Disclosure"/><node class="android.widget.Button" clickable="true" enabled="true" text="{exit_label}" bounds="[0,0][100,100]"/></node></hierarchy>'
    acts = actions(xml_str)
    a = acts[0]
    assert is_terminal_exit_action(a) is True
    assert navigation_skip_reason(a) == 'SIDE_EFFECT_BOUNDARY'
    assert navigation_classification(a) == 'SIDE_EFFECTING'
    assert is_safe_clickable_action(a) is False


@pytest.mark.parametrize('ack_label', [
    'I understand', 'Got it', 'Understood', 'I agree', 'Agree', 'Dismiss notice', 'Accept',
])
def test_disclosure_acknowledgment_progression(ack_label):
    from src.dynamic.exploration.models import is_safe_clickable_action
    xml_str = f'<hierarchy><node class="android.widget.ScrollView"><node class="android.widget.TextView" text="Accessibility Service Disclosure"/><node class="android.widget.TextView" text="This notice is required before autofill can be offered."/><node class="android.widget.Button" clickable="true" enabled="true" text="{ack_label}" bounds="[0,0][100,100]"/></node></hierarchy>'
    acts = actions(xml_str)
    a = acts[0]
    assert navigation_skip_reason(a) is None
    assert is_safe_clickable_action(a) is True


def test_generic_continue_requires_context():
    from src.dynamic.exploration.models import is_safe_clickable_action
    # On a generic screen without disclosure indicators, Continue and I understand are UNCERTAIN_SIDE_EFFECTS
    xml_generic = '<hierarchy><node class="android.widget.LinearLayout"><node class="android.widget.Button" clickable="true" enabled="true" text="Continue" bounds="[0,0][100,100]"/><node class="android.widget.Button" clickable="true" enabled="true" text="I understand" bounds="[0,100][100,200]"/></node></hierarchy>'
    acts = actions(xml_generic)
    for a in acts:
        assert navigation_skip_reason(a) == 'UNCERTAIN_SIDE_EFFECTS'
        assert is_safe_clickable_action(a) is False

    # On a confirmed disclosure screen, Continue is safely permitted
    xml_disclosure = '<hierarchy><node class="android.widget.ScrollView"><node class="android.widget.TextView" text="Terms and Privacy Notice"/><node class="android.widget.Button" clickable="true" enabled="true" text="Continue" bounds="[0,0][100,100]"/></node></hierarchy>'
    acts_disc = actions(xml_disclosure)
    assert navigation_skip_reason(acts_disc[0]) is None
    assert is_safe_clickable_action(acts_disc[0]) is True

    # On a screen with credential inputs (password field), Continue is blocked
    xml_login = '<hierarchy><node class="android.widget.LinearLayout"><node class="android.widget.EditText" password="true" editable="true" bounds="[0,0][100,50]"/><node class="android.widget.Button" clickable="true" enabled="true" text="Continue" bounds="[0,50][100,100]"/></node></hierarchy>'
    acts_login = actions(xml_login)
    assert navigation_skip_reason(acts_login[0]) is not None
    assert is_safe_clickable_action(acts_login[0]) is False


def test_auth_wall_false_positive_prevention():
    from src.dynamic.session.auth_intervention import auth_wall
    # Informational disclosure mentioning login/credentials in body text without password field
    xml_disclosure = '<hierarchy><node class="android.widget.ScrollView"><node class="android.widget.TextView" text="Accessibility Service Disclosure"/><node class="android.widget.TextView" text="Detect login fields and credentials for autofill."/><node class="android.widget.Button" clickable="true" enabled="true" text="I understand" bounds="[0,0][100,100]"/><node class="android.widget.Button" clickable="true" enabled="true" text="Close app" bounds="[0,100][100,200]"/></node></hierarchy>'
    obs_disc = parse_ui_hierarchy(ET.fromstring(xml_disclosure), 'com.target.app', 'com.target.app.MainActivity', 'com.target.app')
    assert auth_wall(obs_disc) is False

    # Real auth wall with password input and login action
    xml_real_auth = '<hierarchy><node class="android.widget.LinearLayout" package="com.target.app"><node class="android.widget.EditText" package="com.target.app" password="true" editable="true" bounds="[0,0][100,50]"/><node class="android.widget.Button" package="com.target.app" clickable="true" enabled="true" text="Log In" bounds="[0,50][100,100]"/></node></hierarchy>'
    obs_auth = parse_ui_hierarchy(ET.fromstring(xml_real_auth), 'com.target.app', 'com.target.app.MainActivity', 'com.target.app')
    assert auth_wall(obs_auth) is True


def test_foreground_preservation_bitwarden_screen_simulation():
    from src.dynamic.exploration.loop import select_next_action
    # Bitwarden initial disclosure screen with both "I understand" and "Close app"
    xml_bitwarden = (
        '<hierarchy><node class="android.widget.ScrollView">'
        '<node class="android.widget.TextView" text="Accessibility Service Disclosure"/>'
        '<node class="android.widget.TextView" text="This notice is required before Bitwarden can offer accessibility-based autofill."/>'
        '<node class="android.widget.Button" clickable="true" enabled="true" text="I understand" bounds="[42,1163][1038,1289]"/>'
        '<node class="android.widget.Button" clickable="true" enabled="true" text="Close app" bounds="[42,1321][1038,1447]"/>'
        '</node></hierarchy>'
    )
    obs = parse_ui_hierarchy(ET.fromstring(xml_bitwarden), 'com.x8bit.bitwarden', 'com.x8bit.bitwarden.MainActivity', 'com.x8bit.bitwarden')
    node = RouteGraph().observe_screen(obs)

    # "Close app" must be skipped
    close_action = [a for a in node.actions.values() if a.text == "Close app"][0]
    assert navigation_skip_reason(close_action) == "SIDE_EFFECT_BOUNDARY"

    # "I understand" must be safe
    understand_action = [a for a in node.actions.values() if a.text == "I understand"][0]
    assert navigation_skip_reason(understand_action) is None

    # select_next_action MUST select "I understand" and NEVER "Close app"
    chosen = select_next_action(node)
    assert chosen is not None
    assert chosen.text == "I understand"


def test_bitwarden_gateway_login_navigation():
    from src.dynamic.exploration.loop import select_next_action
    xml_gateway = (
        '<hierarchy><node class="android.widget.FrameLayout" package="com.x8bit.bitwarden">'
        '<node class="android.widget.TextView" text="Security, prioritized"/>'
        '<node class="android.view.View" resource-id="ChooseAccountCreationButton" clickable="true" enabled="true" text="Create account" bounds="[42,2025][1038,2151]"/>'
        '<node class="android.view.View" resource-id="ChooseLoginButton" clickable="true" enabled="true" text="Log in" bounds="[42,2172][1038,2298]"/>'
        '</node></hierarchy>'
    )
    obs = parse_ui_hierarchy(ET.fromstring(xml_gateway), 'com.x8bit.bitwarden', 'com.x8bit.bitwarden.MainActivity', 'com.x8bit.bitwarden')
    node = RouteGraph().observe_screen(obs)

    create_act = [a for a in node.actions.values() if a.text == "Create account"][0]
    assert navigation_skip_reason(create_act, context=node) == "SIDE_EFFECT_BOUNDARY"

    login_act = [a for a in node.actions.values() if a.text == "Log in"][0]
    assert navigation_skip_reason(login_act, context=node) is None

    chosen = select_next_action(node)
    assert chosen is not None
    assert chosen.text == "Log in"


def test_bitwarden_login_screen_auth_wall_and_no_submission():
    from src.dynamic.exploration.loop import select_next_action
    from src.dynamic.session.auth_intervention import auth_wall
    xml_login = (
        '<hierarchy><node class="android.widget.FrameLayout" package="com.x8bit.bitwarden">'
        '<node class="android.widget.TextView" text="Log in to Bitwarden"/>'
        '<node class="android.widget.EditText" resource-id="EmailAddressEntry" editable="true" enabled="true" bounds="[42,500][1038,600]"/>'
        '<node class="android.widget.TextView" text="Email address"/>'
        '<node class="android.view.View" clickable="true" enabled="true" text="Continue" bounds="[42,700][1038,800]"/>'
        '<node class="android.view.View" clickable="true" enabled="true" text="Create an account" bounds="[42,900][1038,1000]"/>'
        '</node></hierarchy>'
    )
    obs = parse_ui_hierarchy(ET.fromstring(xml_login), 'com.x8bit.bitwarden', 'com.x8bit.bitwarden.MainActivity', 'com.x8bit.bitwarden')
    assert auth_wall(obs) is True

    node = RouteGraph().observe_screen(obs)
    continue_act = [a for a in node.actions.values() if a.text == "Continue"][0]
    assert navigation_skip_reason(continue_act, context=node) is not None

    chosen = select_next_action(node)
    assert chosen is None


@pytest.mark.parametrize('label,res_id', [
    ('Kategoriler', 'com.example:id/nav_categories'),
    ('Categories', 'com.example:id/category_tab'),
    ('Anasayfa', 'com.example:id/home'),
    ('Home', 'com.example:id/nav_home'),
    ('Ürün, kategori veya marka ara', 'com.example:id/search_box'),
    ('Search', 'com.example:id/search_edit_text'),
    ('Outlet Ürünler', 'com.example:id/campaign_outlet'),
    ('Kampanyalar', 'com.example:id/promotions'),
    ('Fırsatlar', 'com.example:id/deals'),
    ('Keşfet', 'com.example:id/explore'),
    ('Yardım', 'com.example:id/help_center'),
    ('Ürün Detayı', 'com.example:id/product_detail'),
    ('İncele', 'com.example:id/item_card'),
])
def test_read_only_catalog_navigation_allowed(label, res_id):
    from src.dynamic.exploration.models import is_read_only_catalog_navigation
    xml_str = f'<hierarchy><node class="android.widget.FrameLayout"><node class="android.view.View" clickable="true" enabled="true" text="{label}" resource-id="{res_id}" bounds="[0,0][100,100]"/></node></hierarchy>'
    acts = actions(xml_str)
    a = acts[0]
    assert is_read_only_catalog_navigation(a) is True
    assert navigation_skip_reason(a) is None


@pytest.mark.parametrize('label,res_id', [
    ('Sepetim', 'com.example:id/cart_button'),
    ('Sepete Ekle', 'com.example:id/btn_add_to_cart'),
    ('Add to Cart', 'com.example:id/add_to_cart'),
    ('Sepetten Çıkar', 'com.example:id/btn_remove_cart'),
    ('Favorilerim', 'com.example:id/wishlist'),
    ('Favorilere Ekle', 'com.example:id/add_wishlist'),
    ('Add to Wishlist', 'com.example:id/favorite_btn'),
    ('Hesabım', 'com.example:id/my_account'),
    ('My Account', 'com.example:id/profile_tab'),
    ('Profili Düzenle', 'com.example:id/edit_profile'),
    ('Ödeme Yap', 'com.example:id/btn_checkout'),
    ('Satın Al', 'com.example:id/btn_buy_now'),
    ('Checkout', 'com.example:id/checkout'),
    ('Adres Ekle', 'com.example:id/add_address'),
    ('Kupon Kullan', 'com.example:id/apply_coupon'),
    ('İndirim Kodu', 'com.example:id/coupon_code'),
    ('Üye Ol', 'com.example:id/sign_up'),
    ('Giriş Yap', 'com.example:id/login'),
    ('Hesabı Sil', 'com.example:id/delete_account'),
])
def test_mutation_boundaries_strictly_preserved(label, res_id):
    from src.dynamic.exploration.models import is_mutation_action
    xml_str = f'<hierarchy><node class="android.widget.FrameLayout"><node class="android.view.View" clickable="true" enabled="true" text="{label}" resource-id="{res_id}" bounds="[0,0][100,100]"/></node></hierarchy>'
    acts = actions(xml_str)
    a = acts[0]
    assert is_mutation_action(a) is True
    assert navigation_skip_reason(a) in {'SIDE_EFFECT_BOUNDARY', 'CREDENTIAL/AUTH', 'DESTRUCTIVE'}


def test_form_context_blocks_catalog_navigation():
    # If the screen contains password fields or editable credential inputs, navigation is blocked
    xml_str = (
        '<hierarchy><node class="android.widget.LinearLayout">'
        '<node class="android.widget.EditText" password="true" editable="true" bounds="[0,0][100,50]"/>'
        '<node class="android.view.View" clickable="true" enabled="true" text="Kategoriler" bounds="[0,50][100,100]"/>'
        '</node></hierarchy>'
    )
    obs = parse_ui_hierarchy(ET.fromstring(xml_str), 'com.example.app', 'com.example.app.MainActivity', 'com.example.app')
    node = RouteGraph().observe_screen(obs)
    cat_act = list(node.actions.values())[0]
    assert navigation_skip_reason(cat_act, context=node) is not None

