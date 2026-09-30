"""Dashboard HTML template loader.

Loads the dashboard template from the external HTML file at
``src/templates/dashboard.html``, keeping the 3,400+ line template
out of the Python source.
"""

from __future__ import annotations

from pathlib import Path

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_CACHED_HTML: str | None = None


def load_dashboard_html() -> str:
    """Returns the dashboard HTML page content, caching on first read."""
    global _CACHED_HTML
    if _CACHED_HTML is None:
        template_path = _TEMPLATE_DIR / "dashboard.html"
        _CACHED_HTML = template_path.read_text(encoding="utf-8")
    return _CACHED_HTML
