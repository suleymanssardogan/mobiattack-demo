"""Data models and configurations for Bounded Dynamic Exploration (Week 1 — Day 5 Task 5.3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any

from src.dynamic.route.models import ActionStatus, DiscoveredAction

_HOST_PATH_RE = re.compile(r"/(?:Users|home)/[^/\s]+/[^\s'\"]*")
_OPT_PATH_RE = re.compile(r"/opt/homebrew/[^\s'\"]*")
_TMP_PATH_RE = re.compile(r"/(?:tmp|private/tmp|var/folders)/[^\s'\"]*")


def utc_now_iso() -> str:
    """Returns current UTC timestamp in strict ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def sanitize_str(val: str | None) -> str | None:
    """Sanitizes host filesystem paths from a string."""
    if val is None:
        return None
    cleaned = _HOST_PATH_RE.sub("<host_path>", val)
    cleaned = _OPT_PATH_RE.sub("<host_path>", cleaned)
    cleaned = _TMP_PATH_RE.sub("<host_path>", cleaned)
    return cleaned


def sanitize_value(val: Any) -> Any:
    """Recursively sanitizes values for metadata output."""
    if isinstance(val, dict):
        return {k: sanitize_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize_value(item) for item in val]
    elif isinstance(val, str):
        return sanitize_str(val)
    return val


DESTRUCTIVE_KEYWORDS: set[str] = {
    "delete",
    "remove account",
    "uninstall",
    "purchase",
    "buy",
    "pay",
    "confirm payment",
    "sil",
    "hesabı sil",
    "kaldır",
    "satın al",
    "öde",
}


TERMINAL_EXIT_PATTERNS: tuple[str, ...] = (
    "close app",
    "exit app",
    "quit app",
    "close application",
    "exit application",
    "quit application",
    "terminate app",
    "terminate application",
    "force close",
    "leave app",
)

DISCLOSURE_KEYWORDS_RE = re.compile(
    r"\b(disclosure|notice|disclaimer|accessibility|privacy|terms|policy|agreement|license|welcome|about|overview|instructions|guidelines|tutorial|warning|info|information)\b",
    re.I,
)
PAYMENT_KEYWORDS_RE = re.compile(
    r"\b(credit\s*card|cvv|security\s*code|billing|purchase|buy\s*now|checkout|pricing|\$|€|£|₺)\b",
    re.I,
)
DESTRUCTIVE_SCREEN_RE = re.compile(
    r"\b(delete\s*account|remove\s*account|uninstall|wipe\s*data|factory\s*reset|clear\s*all)\b",
    re.I,
)
CREDENTIAL_PROMPT_RE = re.compile(
    r"\b(master\s*password|enter\s*(?:your\s*)?password|create\s*(?:your\s*)?account|sign\s*in\s*to|log\s*in\s*to)\b",
    re.I,
)

DISCLOSURE_PROGRESSION_PATTERNS = re.compile(
    r"\b(i\s*understand|got\s*it|understood|i\s*agree|agree|dismiss\s*notice|accept|continue|next)\b",
    re.I,
)


def is_terminal_exit_action(action: DiscoveredAction) -> bool:
    """Detects explicit application exit/termination actions."""
    label = " ".join((action.text or "", action.content_desc or "", action.resource_id or "")).lower()
    return any(pat in label for pat in TERMINAL_EXIT_PATTERNS)


def classify_screen_context(obs: Any) -> dict[str, Any]:
    """Extracts contextual safety indicators from a screen observation."""
    nodes = getattr(obs, "nodes", []) or []
    has_password = any(getattr(n, "password", False) and getattr(n, "visible", True) for n in nodes)
    has_editable = any(getattr(n, "editable", False) and getattr(n, "visible", True) for n in nodes)
    texts = [
        (getattr(n, "text", "") or getattr(n, "content_desc", "") or "").strip().lower()
        for n in nodes
        if (getattr(n, "text", "") or getattr(n, "content_desc", ""))
        and (getattr(n, "visible", True) or not getattr(n, "bounds", None) or n.bounds == (0, 0, 0, 0))
    ]
    combined_text = " ".join(texts)

    has_payment = bool(PAYMENT_KEYWORDS_RE.search(combined_text))
    has_destructive = bool(DESTRUCTIVE_SCREEN_RE.search(combined_text))
    has_credential_prompt = bool(CREDENTIAL_PROMPT_RE.search(combined_text)) and has_editable

    is_disclosure = (
        not has_password
        and not has_payment
        and not has_destructive
        and not has_credential_prompt
        and bool(DISCLOSURE_KEYWORDS_RE.search(combined_text))
    )
    return {
        "is_disclosure_context": is_disclosure,
        "has_password": has_password,
        "has_editable": has_editable,
        "has_payment": has_payment,
        "has_destructive": has_destructive,
        "has_credential_prompt": has_credential_prompt,
        "screen_text": combined_text[:500],
    }


def is_informational_disclosure_context(context: Any = None, action: DiscoveredAction | None = None) -> bool:
    """Verifies whether the screen context is clearly non-credential, non-payment, non-destructive informational/disclosure UI."""
    if context is None and action is not None:
        context = getattr(action, "_screen_context", None) or getattr(action, "navigation_evidence", {}).get("screen_context")
    if context is None:
        return False
    if isinstance(context, dict):
        if context.get("is_disclosure_context") is not None:
            return bool(context.get("is_disclosure_context"))
        if context.get("has_password") or context.get("has_payment") or context.get("has_destructive") or context.get("has_credential_prompt"):
            return False
        if context.get("screen_text"):
            text = str(context["screen_text"]).lower()
            return bool(DISCLOSURE_KEYWORDS_RE.search(text))
    meta = getattr(context, "metadata", None)
    if isinstance(meta, dict) and "screen_context" in meta:
        return bool(meta["screen_context"].get("is_disclosure_context"))
    nodes = getattr(context, "nodes", None)
    if isinstance(nodes, list):
        has_password = any(getattr(n, "password", False) and getattr(n, "visible", True) for n in nodes)
        if has_password:
            return False
        texts = [
            (getattr(n, "text", "") or getattr(n, "content_desc", "") or "").strip().lower()
            for n in nodes
            if (getattr(n, "text", "") or getattr(n, "content_desc", ""))
            and (getattr(n, "visible", True) or not getattr(n, "bounds", None) or getattr(n, "bounds", None) == (0, 0, 0, 0))
        ]
        combined = " ".join(texts)
        if PAYMENT_KEYWORDS_RE.search(combined) or DESTRUCTIVE_SCREEN_RE.search(combined):
            return False
        has_editable = any(getattr(n, "editable", False) and getattr(n, "visible", True) for n in nodes)
        if has_editable and CREDENTIAL_PROMPT_RE.search(combined):
            return False
        return bool(DISCLOSURE_KEYWORDS_RE.search(combined))
    return False


def is_disclosure_acknowledgment(action: DiscoveredAction, context: Any = None) -> bool:
    """Checks whether the action is a harmless acknowledgment on a verified disclosure screen."""
    if not is_informational_disclosure_context(context, action=action):
        return False
    label = " ".join((action.text or "", action.content_desc or "", action.resource_id or "")).lower()
    return bool(DISCLOSURE_PROGRESSION_PATTERNS.search(label))


def is_login_navigation(action: DiscoveredAction, context: Any = None) -> bool:
    """Detects safe login navigation from a gateway screen without credential inputs.

    Navigating TO a login screen is safe exploration; submitting credentials is not.
    """
    if action.action_type != "click":
        return False
    if structural_navigation(action):
        return False
    text_desc = " ".join((action.text or "", action.content_desc or "")).strip().lower()
    res_id = (action.resource_id or "").strip().lower()
    # Must explicitly match login navigation gateway label
    is_login_gateway = bool(re.search(r"^(log[ -]?in|sign[ -]?in)$", text_desc)) or "chooselogin" in res_id
    if not is_login_gateway:
        return False
    # Explicit account creation or registration is excluded per policy
    if re.search(r"\b(create|register|sign.?up|new\s+account)\b", text_desc):
        return False
    if is_destructive_action(action):
        return False

    # Extract screen context indicators
    ctx = context
    if ctx is None and action is not None:
        ctx = getattr(action, "_screen_context", None)
    if ctx is None:
        return False

    if isinstance(ctx, dict):
        has_editable = ctx.get("has_editable", False)
        has_password = ctx.get("has_password", False)
        has_credential_prompt = ctx.get("has_credential_prompt", False)
    else:
        meta = getattr(ctx, "metadata", None)
        if isinstance(meta, dict) and "screen_context" in meta:
            sc = meta["screen_context"]
            has_editable = sc.get("has_editable", False)
            has_password = sc.get("has_password", False)
            has_credential_prompt = sc.get("has_credential_prompt", False)
        else:
            nodes = getattr(ctx, "nodes", None)
            if isinstance(nodes, list):
                has_password = any(getattr(n, "password", False) and getattr(n, "visible", True) for n in nodes)
                has_editable = any(getattr(n, "editable", False) and getattr(n, "visible", True) for n in nodes)
                has_credential_prompt = False
            else:
                input_count = getattr(ctx, "input_count", 0)
                has_password = False
                has_editable = input_count > 0
                has_credential_prompt = False

    # If the screen already has editable fields or password inputs, this is a form submission, not navigation!
    if has_editable or has_password or has_credential_prompt:
        return False

    return True


MUTATION_ACTION_RE = re.compile(
    r"\b("
    r"add\s*to\s*(?:cart|basket|bag|wishlist|favorites?)|"
    r"remove\s*from\s*(?:cart|basket|bag|wishlist|favorites?)|"
    r"clear\s*cart|empty\s*cart|cart|basket|trolley|"
    r"sepete\s*ekle|sepetten\s*(?:çıkar|cikar|sil)|sepeti\s*(?:boşalt|bosalt)|sepetim?|sepetiniz|"
    r"wishlist|favorites?|favourite|favourites?|bookmark|save\s*for\s*later|"
    r"favorilere?\s*ekle|favorilerden\s*(?:çıkar|cikar|sil)|favoril?e?r?i?m?|"
    r"checkout|buy(?:\s*now)?|place\s*order|purchase|pay|payment|complete\s*order|"
    r"satın\s*al|satin\s*al|hemen\s*al|sipariş(?:\s*ver)?|siparis(?:\s*ver)?|siparişi\s*tamamla|ödeme(?:\s*yap)?|odeme(?:\s*yap)?|öde|ode|"
    r"my\s*account|my\s*profile|edit\s*profile|hesabım|hesabim|profilim|"
    r"address(?:es)?|add\s*address|edit\s*address|delete\s*address|adres(?:ler|lerim)?|adres\s*ekle|"
    r"coupon|voucher|redeem|apply\s*coupon|promo\s*code|kupon(?:\s*kullan)?|hediye\s*(?:çeki|ceki)|"
    r"submit|sign\s*in|sign\s*up|login|register|logout|sign\s*out|create\s*account|new\s*account|"
    r"giriş\s*yap|giris\s*yap|üye\s*ol|uye\s*ol|kaydol|hesap\s*oluştur|çıkış\s*yap|"
    r"password|credential|şifre|sifre|parola"
    r")\b",
    re.IGNORECASE,
)

MUTATION_RES_ID_RE = re.compile(
    r"(cart|basket|sepet|wishlist|favorite|favori|checkout|purchase|payment|satin_al|odeme|"
    r"account|profile|address|hesabim|adres|coupon|voucher|redeem|kupon|"
    r"submit|login|register|logout|signin|signup|password|credential)",
    re.IGNORECASE,
)

READONLY_CATALOG_RE = re.compile(
    r"\b("
    r"categor(?:y|ies)|departments?|kategoril?e?r?|reyon|bölüm|bolum|"
    r"search|arama?|ürün\s*ara|urun\s*ara|marka\s*ara|katalogda\s*ara|"
    r"products?|items?|catalog(?:ue)?|ürünl?e?r?|urunl?e?r?|katalog|detayl?a?r?|incele|görüntüle|goruntule|"
    r"campaigns?|featured|deals?|offers?|outlet|banners?|slides?|sliders?|carousel|promotions?|"
    r"kampanyal?a?r?|fırsatl?a?r?|firsatl?a?r?|indirimler?|vitrin|duyuru|"
    r"home(?:page)?|browse|explore|discover|shop|store|feed|anasayfa|ana\s*sayfa|keşfet|kesfet|gözat|gozat|mağaza|magaza|"
    r"help|support|faq|yardım|yardim|destek|sss|hakkında|hakkinda|bilgi"
    r")\b",
    re.IGNORECASE,
)

READONLY_RES_ID_RE = re.compile(
    r"(category|kategori|department|search|arama|product|item_card|catalog|listing|urun|"
    r"banner|slide|slider|carousel|promo|campaign|kampanya|deal|firsat|outlet|"
    r"tab_home|nav_home|home|browse|explore|discover|anasayfa|kesfet|"
    r"help|support|yardim|destek)",
    re.IGNORECASE,
)


def is_mutation_action(action: DiscoveredAction) -> bool:
    """Detects state-mutating actions (cart, wishlist, checkout, account, addresses, coupons, credentials)."""
    text = (action.text or "").strip().lower()
    desc = (action.content_desc or "").strip().lower()
    res_id = (action.resource_id or "").strip().lower()
    combined = f"{text} {desc} {res_id}".strip()
    if not combined:
        return False
    if MUTATION_ACTION_RE.search(combined):
        return True
    if res_id and MUTATION_RES_ID_RE.search(res_id):
        return True
    return False


def is_form_or_transaction_screen(context: Any) -> bool:
    """Checks if the screen context indicates an active form, checkout, or credential prompt state."""
    if context is None:
        return False
    ctx = context
    if isinstance(ctx, dict):
        if ctx.get("has_password") or ctx.get("has_credential_prompt"):
            return True
        if ctx.get("has_editable") and ctx.get("editable_count", 0) > 1:
            return True
    else:
        meta = getattr(ctx, "metadata", None)
        if isinstance(meta, dict) and "screen_context" in meta:
            sc = meta["screen_context"]
            if sc.get("has_password") or sc.get("has_credential_prompt"):
                return True
            if sc.get("has_editable") and sc.get("editable_count", 0) > 1:
                return True
        else:
            nodes = getattr(ctx, "nodes", None)
            if isinstance(nodes, list):
                if any(getattr(n, "password", False) and getattr(n, "visible", True) for n in nodes):
                    return True
                editable_nodes = [n for n in nodes if getattr(n, "editable", False) and getattr(n, "visible", True)]
                if len(editable_nodes) > 1:
                    return True
    return False


def is_read_only_catalog_navigation(action: DiscoveredAction, context: Any = None) -> bool:
    """Detects low-risk read-only catalog browsing, category navigation, search entry, and public showcase tabs.

    Strictly excludes mutations (cart, favorites, checkout, account, credentials).
    """
    if is_form_or_transaction_screen(context):
        return False
    if is_mutation_action(action) or is_destructive_action(action) or is_terminal_exit_action(action):
        return False
    text = (action.text or "").strip().lower()
    desc = (action.content_desc or "").strip().lower()
    res_id = (action.resource_id or "").strip().lower()
    combined = f"{text} {desc} {res_id}".strip()
    if not combined:
        return False
    if READONLY_CATALOG_RE.search(combined):
        return True
    if res_id and READONLY_RES_ID_RE.search(res_id):
        return True
    return False


def is_destructive_action(action: DiscoveredAction) -> bool:
    """Detects potentially destructive actions based on a conservative label denylist."""
    text = (action.text or "").lower()
    desc = (action.content_desc or "").lower()
    res_id = (action.resource_id or "").lower()
    combined = f"{text} {desc} {res_id}"
    return any(kw in combined for kw in DESTRUCTIVE_KEYWORDS)


def navigation_skip_reason(action: DiscoveredAction, context: Any = None) -> str | None:
    """Conservative navigation-only policy; unknown side effects never auto-dispatch."""
    if action.action_type != "click":
        return "NON_NAVIGATION_INPUT"
    if is_terminal_exit_action(action):
        return "SIDE_EFFECT_BOUNDARY"
    if is_login_navigation(action, context=context):
        return None
    # Checkable controls may modify persistent state even when their caption looks informational.
    if any(term in action.class_name.lower() for term in ("switch", "checkbox", "toggle")):
        return "SIDE_EFFECT_BOUNDARY"
    if is_destructive_action(action) or is_mutation_action(action):
        return "SIDE_EFFECT_BOUNDARY"
    label = " ".join((action.text or "", action.content_desc or "", action.resource_id or "")).lower()
    if re.search(
        r"submit|sign.?in|sign.?up|login|register|logout|send|message|save|update|confirm|"
        r"create.?account|new.?account|\bsubscribe\b|credential|password|permission_allow|while using|allow access|enable|disable", label
    ):
        return "SIDE_EFFECT_BOUNDARY"
    if structural_navigation(action):
        return None
    if re.search(r"\b(menu|navigation|drawer|tab|back|cancel|close|dismiss|help|about|instructions|information|details)\b", label):
        return None
    if re.search(r"\b(open|show|view)\s+(an?\s+)?(informational|screen|dialog|list|settings)\b", label):
        return None
    if re.search(r"\bimplementation\b", label):
        return None  # informational implementation sections, not test/submit buttons
    if is_disclosure_acknowledgment(action, context=context):
        return None
    if is_read_only_catalog_navigation(action, context=context):
        return None
    return "UNCERTAIN_SIDE_EFFECTS"


def structural_navigation(action):
    evidence = getattr(action, 'navigation_evidence', {})
    return (isinstance(evidence, dict) and evidence.get('role') == 'navigation_item'
            and evidence.get('source') in {'material_navigation_hierarchy', 'android_tab_widget'}
            and evidence.get('control_path', '').startswith(evidence.get('container_path', '') + '/')
            and bool(evidence.get('container_path')))


def navigation_classification(action, context: Any = None):
    """Classification for evidence-based roles; existing informational policy is unchanged."""
    label = ' '.join((action.text or '', action.content_desc or '', action.resource_id or '')).lower()
    if is_destructive_action(action):
        return 'DESTRUCTIVE'
    if is_terminal_exit_action(action):
        return 'SIDE_EFFECTING'
    if re.search(r'login|register|sign.?in|sign.?up|credential|password', label):
        return 'CREDENTIAL/AUTH'
    reason = navigation_skip_reason(action, context=context)
    if reason in {'SIDE_EFFECT_BOUNDARY', 'NON_NAVIGATION_INPUT', 'TERMINAL_BOUNDARY'}:
        return 'SIDE_EFFECTING'
    if structural_navigation(action) and reason is None:
        return 'SAFE_NAVIGATION'
    return 'AMBIGUOUS'


def is_safe_clickable_action(action: DiscoveredAction, context: Any = None) -> bool:
    return action.status == ActionStatus.DISCOVERED.value and navigation_skip_reason(action, context=context) is None


ALLOWED_PERMISSION_PACKAGES: frozenset[str] = frozenset({
    "com.android.permissioncontroller",
    "com.google.android.permissioncontroller",
})


def is_allowed_system_dialog(target: Any) -> bool:
    """Checks whether an observation, route node, or package name represents an explicitly allowed system dialog.

    Allowed dialogs currently include standard Android runtime permission controllers.
    """
    if isinstance(target, str):
        pkg = target.strip().lower()
        return pkg in ALLOWED_PERMISSION_PACKAGES

    if not getattr(target, "is_dialog_or_system", False):
        return False

    pkg = (
        getattr(target, "foreground_package", None)
        or getattr(target, "package_name", None)
        or ""
    ).strip().lower()
    return pkg in ALLOWED_PERMISSION_PACKAGES


def is_allowed_exploration_surface(target: Any) -> bool:
    """Checks whether autonomous safe click exploration is allowed on the observed screen.

    Returns True for:
    - Target application (is_target_package == True)
    - Explicitly allowed system dialogs (e.g. runtime permission controllers)

    Returns False for:
    - Generic SystemUI, Android Settings, Package Installer
    - External/unrelated third-party applications
    """
    if getattr(target, "is_target_package", False):
        return True
    return is_allowed_system_dialog(target)


class ExplorationStatus(str, Enum):
    """Overall outcome of the exploration loop run."""
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class StopReason(str, Enum):
    """Specific condition that terminated the exploration loop."""
    COMPLETED = "completed"
    NO_ACTIONS = "no_actions"
    UNSAFE_ACTION_BOUNDARY = "unsafe_action_boundary"
    REPEATED_STATE = "repeated_state"
    MAX_STEPS = "max_steps"
    AUTH_NOT_COMPLETED = "auth_intervention_not_completed"
    HARD_STEP_CEILING = "hard_step_ceiling"
    FRONTIER_STAGNATED = "frontier_stagnated"
    RUNTIME_UNAVAILABLE = "runtime_unavailable"
    MAX_DEPTH = "max_depth"
    DEADLINE = "deadline"
    EXTERNAL_PACKAGE = "external_package"
    SYSTEM_UI_BOUNDARY = "system_ui_boundary"
    OBSERVATION_FAILED = "observation_failed"
    EXECUTOR_FAILED = "executor_failed"


@dataclass
class ExplorationLimits:
    """Configurable boundaries for autonomous exploration."""

    max_steps: int = 10
    max_depth: int = 3
    deadline_seconds: float = 60.0
    action_settle_delay: float = 0.2
    allow_system_dialogs: bool = True
    stop_on_external_package: bool = True
    base_step_budget: int | None = None
    hard_step_ceiling: int | None = None
    stagnation_actions: int = 3
    minimum_extension_seconds: float = 1.0

    def __post_init__(self):
        base = self.max_steps if self.base_step_budget is None else self.base_step_budget
        ceiling = base if self.hard_step_ceiling is None else self.hard_step_ceiling
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 1
               for v in (base, ceiling, self.stagnation_actions)) or ceiling < base:
            raise ValueError("Budgets must be positive integers with hard ceiling >= base")
        import math
        if not math.isfinite(self.minimum_extension_seconds) or self.minimum_extension_seconds <= 0:
            raise ValueError("Extension requires a finite positive remaining deadline")

    @property
    def base_budget(self):
        return self.max_steps if self.base_step_budget is None else self.base_step_budget

    @property
    def hard_ceiling(self):
        return self.base_budget if self.hard_step_ceiling is None else self.hard_step_ceiling



@dataclass
class ExplorationResult:
    """Comprehensive summary of a bounded exploration run."""

    status: str
    stop_reason: str
    steps_attempted: int = 0
    actions_succeeded: int = 0
    actions_failed: int = 0
    screens_observed: int = 0
    transitions_recorded: int = 0
    started_at: str = field(default_factory=utc_now_iso)
    completed_at: str = field(default_factory=utc_now_iso)
    duration_seconds: float = 0.0
    root_node_id: str | None = None
    current_node_id: str | None = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serializes exploration result to user-safe dictionary."""
        return {
            "schema_version": "1.0",
            "status": self.status,
            "stop_reason": self.stop_reason,
            "steps_attempted": self.steps_attempted,
            "actions_succeeded": self.actions_succeeded,
            "actions_failed": self.actions_failed,
            "screens_observed": self.screens_observed,
            "transitions_recorded": self.transitions_recorded,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "root_node_id": self.root_node_id,
            "current_node_id": self.current_node_id,
            "error": sanitize_str(self.error),
            "metadata": sanitize_value(self.metadata),
        }
