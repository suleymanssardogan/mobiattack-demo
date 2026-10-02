"""Static String / Network Indicator Extractor.

Extracts deterministic string-level facts from readable/textual files in decoded APKs:
- network_urls: HTTP/HTTPS URLs (excluding XML schema namespaces)
- domains: Bare domain candidates (heuristic detection with noise suppression)
- ip_addresses: Standalone IPv4 addresses
- path_candidates: Potential API/network route path candidates
- local_file_urls: Local file URLs (e.g. file:///android_asset/...)

Semantic Notes:
    1. Finding an indicator at a source location proves strictly that:
       "The string exists at this source location."
       It does NOT prove active network execution, API status, or WebView security posture.
    2. Local file URLs (e.g. file:///android_asset/unsafe_content.html) inside an Activity
       prove only the presence of that string constant; security evaluation belongs to
       subsequent analysis stages.
    3. Bare-domain detection is heuristic and may produce false positives or false negatives.
"""

from pathlib import Path
import re
from src.ios.ios_network_indicator_extractor import is_valid_domain

# Supported textual extensions to scan
SUPPORTED_EXTENSIONS = {
    ".smali",
    ".xml",
    ".json",
    ".txt",
    ".html",
    ".js",
    ".properties",
    ".conf",
    ".ini",
    ".yaml",
    ".yml",
}

# Explicitly excluded binary / metadata extensions
EXCLUDED_EXTENSIONS = {
    ".dex",
    ".arsc",
    ".so",
    ".kotlin_module",
    ".kotlin_builtins",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".jar",
    ".zip",
    ".apk",
    ".rsa",
    ".sf",
    ".mf",
}

# Common file extensions used to reject file names matching domain pattern (e.g. layout.xml, icon.png)
COMMON_FILE_EXTENSIONS = {
    "xml", "png", "jpg", "jpeg", "gif", "webp", "smali", "json", "txt", "html",
    "js", "css", "so", "dex", "arsc", "java", "kt", "class", "mf", "sf", "rsa",
    "properties", "yml", "yaml", "ini", "conf", "svg", "ttf", "otf", "mp3", "wav",
    "apk", "bin", "aar",
}

# Standard programming / platform package prefixes to reject from bare domain detection
PACKAGE_PREFIXES_TO_IGNORE = (
    "android.",
    "androidx.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "dalvik.",
    "com.android.",
    "org.xml.",
    "org.w3c.",
    "org.json.",
    "org.apache.",
)

# Programming variable/scope prefixes that produce noise (e.g. this.add, super.onCreate, window.alert)
CODE_PREFIXES_TO_IGNORE = (
    "this.",
    "super.",
    "window.",
    "self.",
    "root.",
    "owner.",
    "sb.",
    "options.",
    "option.",
    "nativepattern.",
    "regex.",
    "resources.",
    "document.",
    "view.",
    "vnd.",
    "pair.",
    "password.",
    "u2026",
    "r.string.",
)

# Common programming method/property suffixes that look like TLDs (e.g. obj.toString, map.first)
CODE_SUFFIXES_TO_IGNORE = {
    "tostring", "toint", "tochar", "tolong", "tofloat", "todouble", "first", "second",
    "add", "subtract", "multiply", "divide", "negate", "and", "or", "not", "xor",
    "remainder", "matcher", "pattern", "split", "cancel", "getchildat", "value",
    "text", "context", "configuration", "displaymetrics", "oncreate", "onstart",
    "onresume", "onpause", "onstop", "ondestroy", "onattach", "ondetach", "sortwith",
    "compile", "create", "show", "exit", "getenv", "separator", "next", "quote",
    "unmodifiable", "extras",
}

# XML schema namespace prefixes to exclude from network_urls
SCHEMA_PREFIXES_TO_IGNORE = (
    "http://schemas.android.com/",
    "https://schemas.android.com/",
    "http://www.w3.org/",
    "https://www.w3.org/",
    "http://schemas.microsoft.com/",
)

# Excluded local path prefixes for path_candidate filtering
LOCAL_PATH_PREFIXES_TO_IGNORE = (
    "/android_asset/",
    "/res/",
    "/drawable",
    "/layout",
    "/mipmap",
    "/assets/",
    "/data/",
    "/system/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/META-INF/",
    "/shared_prefs/",
    "/schemas.",
)

# Regex definitions
LOCAL_FILE_URL_RE = re.compile(r'\bfile:///[^\s"\'<>]+')
NETWORK_URL_RE = re.compile(r'\bhttps?://[a-zA-Z0-9][-a-zA-Z0-9.]*(?::[0-9]+)?(?:/[^\s"\'<>]*)?')
IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b')
PATH_CANDIDATE_RE = re.compile(r'(?<![a-zA-Z0-9_<:/])/(?:[a-zA-Z0-9_.-]+/?)+')
SMALI_STRING_FIELD_RE = re.compile(r'^\s*\.field\s+[^=\n]+:Ljava/lang/String;\s*=\s*"([^"\\]*(?:\\.[^"\\]*)*)"\s*$')


def _clean_trailing_punctuation(val: str) -> str:
    """Trim trailing quotes, semicolons, commas, or parentheses from extracted strings."""
    return val.rstrip("\"'`,;:)>]} ")


def extract_network_indicators(analysis_root: str | Path) -> dict:
    """Scan textual files under analysis_root and extract network-related indicators.

    Args:
        analysis_root: Root directory to scan (e.g. apk_lab/apktool_out).

    Returns:
        dict with keys:
            - network_urls: list[dict]
            - domains: list[dict]
            - ip_addresses: list[dict]
            - path_candidates: list[dict]
            - local_file_urls: list[dict]

    Raises:
        FileNotFoundError: If analysis_root does not exist.
        NotADirectoryError: If analysis_root is not a directory.
    """
    root_path = Path(analysis_root)
    if not root_path.exists():
        raise FileNotFoundError(f"Analysis root directory not found: {analysis_root}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Analysis root is not a directory: {analysis_root}")

    network_urls: list[dict] = []
    domains: list[dict] = []
    ip_addresses: list[dict] = []
    path_candidates: list[dict] = []
    local_file_urls: list[dict] = []

    seen_keys: set[tuple[str, str, str, int]] = set()

    # Sorting makes both the evidence order and the JSON report reproducible across
    # filesystems. Process files as streams because decoded packages can contain
    # large generated JavaScript and resource files.
    for file_path in sorted(root_path.rglob("*"), key=lambda path: path.as_posix()):
        if not file_path.is_file():
            continue

        ext = file_path.suffix.lower()
        if ext in EXCLUDED_EXTENSIONS or ext not in SUPPORTED_EXTENSIONS:
            continue

        rel_source_path = file_path.relative_to(root_path).as_posix()

        # Strict UTF-8 decoding; safely skip non-decodable files without modifying evidence
        try:
            file_handle = file_path.open("r", encoding="utf-8")
            # Text decoding errors can arise only while iterating. Validate once so
            # a malformed resource is skipped atomically instead of aborting the
            # whole package analysis, then seek back for streaming extraction.
            while file_handle.read(64 * 1024):
                pass
            file_handle.seek(0)
        except (UnicodeDecodeError, OSError):
            try:
                file_handle.close()
            except UnboundLocalError:
                pass
            continue

        with file_handle:
            for line_num, raw_line in enumerate(file_handle, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                if ext == ".smali" and "const-string" not in line:
                    field = SMALI_STRING_FIELD_RE.match(line)
                    if not field:
                        continue
                    # A declared literal is an indicator only; field names do not
                    # establish API semantics. Retain the original source line.
                    line = field.group(1)

                line_network_urls: list[str] = []
                line_local_urls: list[str] = []
                all_urls_on_line: list[str] = []

                # 1. Local File URLs (file:///)
                for m in LOCAL_FILE_URL_RE.finditer(line):
                    cleaned = _clean_trailing_punctuation(m.group(0))
                    if cleaned:
                        line_local_urls.append(cleaned)
                        all_urls_on_line.append(cleaned)
                        key = ("local_file_url", cleaned, rel_source_path, line_num)
                        if key not in seen_keys:
                            seen_keys.add(key)
                            local_file_urls.append({
                                "type": "local_file_url",
                                "value": cleaned,
                                "source_file": rel_source_path,
                                "line_number": line_num,
                            })

                # 2. Network URLs (http:// or https://)
                for m in NETWORK_URL_RE.finditer(line):
                    cleaned = _clean_trailing_punctuation(m.group(0))
                    if not cleaned:
                        continue
                    all_urls_on_line.append(cleaned)
                    if any(cleaned.startswith(prefix) for prefix in SCHEMA_PREFIXES_TO_IGNORE):
                        continue
                    line_network_urls.append(cleaned)
                    key = ("network_url", cleaned, rel_source_path, line_num)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        network_urls.append({
                            "type": "network_url", "value": cleaned,
                            "source_file": rel_source_path, "line_number": line_num,
                        })

                # 3. IPv4 Addresses
                for m in IPV4_RE.finditer(line):
                    ip_val = m.group(0)
                    if any(ip_val in url for url in all_urls_on_line):
                        continue
                    key = ("ip_address", ip_val, rel_source_path, line_num)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        ip_addresses.append({
                            "type": "ip_address", "value": ip_val,
                            "source_file": rel_source_path, "line_number": line_num,
                        })

                # 4. Bare Domains (heuristic with noise suppression)
                for m in DOMAIN_RE.finditer(line):
                    dom_val = _clean_trailing_punctuation(m.group(0))
                    dom_lower = dom_val.lower()
                    if not is_valid_domain(dom_val):
                        continue
                    if dom_lower.startswith(("com.", "org.", "net.")):
                        continue
                    if any(ch.isupper() for label in dom_val.split(".") for ch in label[1:]):
                        continue
                    if m.start() > 0 and (line[m.start() - 1].isalnum() or line[m.start() - 1] in "._"):
                        continue
                    if m.end() < len(line) and (line[m.end()].isalnum() or line[m.end()] in "._"):
                        continue

                    # Suppress if already part of any URL on this line
                    if any(dom_val in url for url in all_urls_on_line):
                        continue

                    tld = dom_lower.split(".")[-1]
                    if tld in COMMON_FILE_EXTENSIONS:
                        continue

                    if any(dom_lower.startswith(p) for p in CODE_PREFIXES_TO_IGNORE):
                        continue

                    if tld in CODE_SUFFIXES_TO_IGNORE:
                        continue

                    raw_tld = dom_val.split(".")[-1]
                    if raw_tld.istitle():
                        continue
                    if any(c.isupper() for c in raw_tld[1:]):
                        continue

                    if any(dom_lower.startswith(pkg) for pkg in PACKAGE_PREFIXES_TO_IGNORE):
                        continue

                    if dom_val.endswith(";") or "/" in dom_val:
                        continue

                    key = ("domain", dom_val, rel_source_path, line_num)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        domains.append({
                            "type": "domain", "value": dom_val,
                            "source_file": rel_source_path, "line_number": line_num,
                        })

                # 5. Path Candidates
                for m in PATH_CANDIDATE_RE.finditer(line):
                    path_val = _clean_trailing_punctuation(m.group(0))
                    if len(path_val) < 2 or not path_val.startswith("/"):
                        continue

                    content_after_slash = path_val.lstrip("/")
                    if len(content_after_slash) < 2 or not any(c.isalnum() for c in content_after_slash):
                        continue

                    if any(path_val in url for url in all_urls_on_line):
                        continue

                    if "//" in path_val or ":/" in path_val:
                        continue

                    if any(path_val.startswith(p) for p in LOCAL_PATH_PREFIXES_TO_IGNORE):
                        continue

                    path_lower = path_val.lower()
                    if path_lower.startswith(("/files/", "/databases", "/phenotype/")) or path_lower == "/cmdline":
                        continue
                    ext_candidate = path_lower.split(".")[-1] if "." in path_lower else ""
                    if ext_candidate in COMMON_FILE_EXTENSIONS | {"db", "pb", "bak", "db-shm", "db-wal"}:
                        continue

                    if path_val.endswith(";"):
                        continue

                    key = ("path_candidate", path_val, rel_source_path, line_num)
                    if key not in seen_keys:
                        seen_keys.add(key)
                        path_candidates.append({
                            "type": "path_candidate", "value": path_val,
                            "source_file": rel_source_path, "line_number": line_num,
                        })

    # Sort each list deterministically by (value, source_file, line_number)
    def sort_key(item: dict) -> tuple:
        return (item["value"], item["source_file"], item["line_number"])

    return {
        "network_urls": sorted(network_urls, key=sort_key),
        "domains": sorted(domains, key=sort_key),
        "ip_addresses": sorted(ip_addresses, key=sort_key),
        "path_candidates": sorted(path_candidates, key=sort_key),
        "local_file_urls": sorted(local_file_urls, key=sort_key),
    }
