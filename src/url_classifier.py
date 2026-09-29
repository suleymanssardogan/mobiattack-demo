"""Deterministic URL Classifier and Platform Routing Module for MobiAttack-v1.

Analyzes user-provided target URLs and selects appropriate acquisition strategies
without making outbound network requests or downloading content during classification.
"""

from __future__ import annotations

import re
import urllib.parse

# Android package name regex: components separated by dots, each starting with a letter
ANDROID_PACKAGE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)+$")


def classify_input_url(url: str, platform: str = "android") -> dict:
    """Classifies an input URL and determines the target acquisition strategy.

    Args:
        url: User-provided URL string.
        platform: Target OS platform ('android' or 'ios'). Defaults to 'android'.

    Returns:
        dict containing:
            platform: 'android' | 'ios'
            type: 'direct_apk' | 'play_store' | 'unsupported' | 'not_implemented'
            normalized_url: str (if valid)
            package_name: str | None
            reason: str (if unsupported or not implemented)
    """
    clean_platform = (platform or "android").strip().lower()
    raw_url = (url or "").strip()

    # 1. iOS Platform Handling
    if clean_platform == "ios":
        parsed = None
        if raw_url.startswith(("http://", "https://", "file://")):
            try:
                parsed = urllib.parse.urlparse(raw_url)
            except Exception:
                pass
        url_path = parsed.path if parsed else raw_url
        unquoted_path = urllib.parse.unquote(url_path).strip()
        if unquoted_path.lower().endswith(".ipa"):
            return {
                "platform": "ios",
                "type": "direct_ipa",
                "normalized_url": raw_url,
                "package_name": None,
            }
        try:
            if Path(raw_url).is_file() and raw_url.lower().endswith(".ipa"):
                return {
                    "platform": "ios",
                    "type": "direct_ipa",
                    "normalized_url": raw_url,
                    "package_name": None,
                }
        except Exception:
            pass

        return {
            "platform": "ios",
            "type": "not_implemented",
            "normalized_url": raw_url,
            "package_name": None,
            "message": "iOS analysis is not implemented in V1.",
        }

    # 2. Android Platform Handling
    if not raw_url.startswith(("http://", "https://")):
        return {
            "platform": "android",
            "type": "unsupported",
            "normalized_url": raw_url,
            "package_name": None,
            "reason": "URL must begin with http:// or https://",
        }

    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception:
        return {
            "platform": "android",
            "type": "unsupported",
            "normalized_url": raw_url,
            "package_name": None,
            "reason": "Malformed URL format.",
        }

    host = (parsed.hostname or "").lower()
    path = parsed.path or ""

    # Strategy A: Google Play Store URL
    # Matches play.google.com/store/apps/details?id=<package_name>
    if host == "play.google.com" or host.endswith(".play.google.com"):
        if path.rstrip("/").startswith("/store/apps/details"):
            query_params = urllib.parse.parse_qs(parsed.query)
            package_ids = query_params.get("id")
            if package_ids and package_ids[0].strip():
                package_name = package_ids[0].strip()
                if ANDROID_PACKAGE_RE.match(package_name):
                    return {
                        "platform": "android",
                        "type": "play_store",
                        "normalized_url": raw_url,
                        "package_name": package_name,
                    }
                else:
                    return {
                        "platform": "android",
                        "type": "unsupported",
                        "normalized_url": raw_url,
                        "package_name": None,
                        "reason": f"Malformed Play Store package identifier: '{package_name}'.",
                    }
            else:
                return {
                    "platform": "android",
                    "type": "unsupported",
                    "normalized_url": raw_url,
                    "package_name": None,
                    "reason": "Google Play Store URL missing required 'id' parameter.",
                }

    # Strategy B: Direct APK URL
    # Checks if the URL path ends with .apk (case-insensitive)
    unquoted_path = urllib.parse.unquote(path).strip()
    if unquoted_path.lower().endswith(".apk"):
        return {
            "platform": "android",
            "type": "direct_apk",
            "normalized_url": raw_url,
            "package_name": None,
        }

    # Strategy C: Unsupported URL
    return {
        "platform": "android",
        "type": "unsupported",
        "normalized_url": raw_url,
        "package_name": None,
        "reason": "Unsupported Android URL. Provide a direct APK URL or a Google Play Store application URL.",
    }
