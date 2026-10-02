"""Call-Context-Aware Static API Candidate Extractor.

Performs local call-context and direct register-flow analysis on Smali files to identify
static API candidates used in Fuel networking calls.

Supported Framework:
- Fuel (GET, POST, PUT, DELETE, PATCH)
- Retrofit method annotations with independently verified literal builder/service binding.

Supported Signatures & Parameter Mapping:
1. FuelKt extension functions:
   - Pattern: Lcom/github/kittinunf/fuel/FuelKt;->(get|post|put|delete|patch)($default)?(
   - Path argument: index 0 in invoke register list {path_reg, ...}
2. Fuel$Companion methods:
   - Pattern: Lcom/github/kittinunf/fuel/Fuel$Companion;->(get|post|put|delete|patch)($default)?(
   - Path argument: index 1 in invoke register list {companion_reg, path_reg, ...}
3. Fuel class direct methods:
   - Pattern: Lcom/github/kittinunf/fuel/Fuel;->(get|post|put|delete|patch)($default)?(
   - Path argument: index 0 in invoke register list {path_reg, ...}
4. FuelManager instance methods:
   - Pattern: Lcom/github/kittinunf/fuel/core/FuelManager;->(get|post|put|delete|patch)($default)?(
   - Path argument: index 1 in invoke register list {manager_reg, path_reg, ...}
5. FuelManager.setBasePath:
   - Pattern: Lcom/github/kittinunf/fuel/core/FuelManager;->setBasePath(Ljava/lang/String;)V
   - Base URL argument: index 1 in invoke register list {manager_reg, url_reg}

Limitations & V1 Constraints:
- Method-local analysis only: Register state and base URLs are cleared at method boundaries (.method / .end method).
- Conservative invalidation: Any instruction writing to a tracked register with non-string data invalidates that register.
- Complex flows (move-object, field storage, StringBuilder concatenation) are not propagated in V1.
- invoke/range syntax is not supported in V1.
- Base evidence is receiver-local, except explicitly observed FuelManager singleton context.
- Unsupported control-flow boundaries discard base bindings; URI schemes must be HTTP(S).
"""

from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urlsplit

# Match const-string instructions: const-string vX, "..." or const-string/jumbo vX, "..."
CONST_STRING_RE = re.compile(r'^\s*const-string(?:/jumbo)?\s+([vp]\d+),\s*"([^"\\]*(?:\\.[^"\\]*)*)"')

# Match method boundaries
METHOD_START_RE = re.compile(r'^\s*\.method\b')
METHOD_END_RE = re.compile(r'^\s*\.end\s+method\b')

# Match Smali invoke instructions (excluding /range)
INVOKE_RE = re.compile(r'^\s*invoke-(?:virtual|static|direct|interface|super)\s+\{([^}]*)\},\s*([^->]+)->([^(]+)\(([^)]*)\)(.+)')

# Regex to detect instructions that write to a destination register (dest, ...)
# Captures destination register as group 1
DEST_WRITE_RE = re.compile(
    r'^\s*(?:'
    r'move|move-result|move-result-object|move-result-wide|'
    r'move-object|move-object/from16|move-object/16|'
    r'move/from16|move/16|move-wide|'
    r'const|const/4|const/16|const/high16|const-wide|const-wide/16|const-wide/32|const-wide/high16|'
    r'const-class|'
    r'new-instance|new-array|filled-new-array|'
    r'check-cast|'
    r'sget|sget-object|sget-boolean|sget-byte|sget-char|sget-short|sget-wide|'
    r'iget|iget-object|iget-boolean|iget-byte|iget-char|iget-short|iget-wide|'
    r'aget|aget-object|aget-boolean|aget-byte|aget-char|aget-short|aget-wide|'
    r'instance-of|array-length|'
    r'neg-int|not-int|neg-long|not-long|neg-float|neg-double|'
    r'int-to-long|int-to-float|int-to-double|long-to-int|long-to-float|long-to-double|'
    r'float-to-int|float-to-long|float-to-double|double-to-int|double-to-long|double-to-float|'
    r'int-to-byte|int-to-char|int-to-short|'
    r'add-int|sub-int|mul-int|div-int|rem-int|and-int|or-int|xor-int|shl-int|shr-int|ushr-int|'
    r'add-int/2addr|sub-int/2addr|mul-int/2addr|div-int/2addr|rem-int/2addr|and-int/2addr|or-int/2addr|xor-int/2addr|'
    r'add-int/lit8|rsub-int/lit8|mul-int/lit8|div-int/lit8|rem-int/lit8|and-int/lit8|or-int/lit8|xor-int/lit8|'
    r'add-int/lit16|rsub-int|mul-int/lit16|div-int/lit16|rem-int/lit16|and-int/lit16|or-int/lit16|xor-int/lit16'
    r')\s+([vp]\d+)\b'
)

# Supported Fuel HTTP methods
FUEL_HTTP_METHODS = {"get", "post", "put", "delete", "patch"}


@dataclass
class TrackedString:
    value: str
    line_number: int


@dataclass
class BaseUrlEvidence:
    value: str
    register: str
    line_number: int
    call_line_number: int


def _parse_register_list(raw_regs: str) -> list[str]:
    """Parse comma-separated Smali register string into a list of register names."""
    if not raw_regs.strip():
        return []
    return [r.strip() for r in raw_regs.split(",") if r.strip()]


def _http_url(value: str, *, base: bool = False) -> bool:
    """Accept only unambiguous network URLs; never reinterpret another scheme."""
    if not value or re.search(r"[\s\\]", value):
        return False
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme.lower() in {"http", "https"}
            and value.lower().startswith(parsed.scheme.lower() + "://")
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and parsed.port != 0
            and not parsed.fragment
            and (not base or not parsed.query)
        )
    except ValueError:
        return False


def _relative_path(value: str) -> bool:
    if not value or value.startswith("//") or re.search(r"[\s\\]", value):
        return False
    try:
        parsed = urlsplit(value)
        return not parsed.scheme and not parsed.netloc and bool(parsed.path) and not parsed.fragment
    except ValueError:
        return False


def _combine_url(base_url: str | None, path: str) -> str | None:
    if _http_url(path):
        return path
    if not base_url or not _http_url(base_url, base=True) or not _relative_path(path):
        return None
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def extract_api_candidates(analysis_root: str | Path) -> dict:
    """Extract Fuel calls and structurally bound Retrofit declarations from Smali.

    Args:
        analysis_root: Root directory to scan (e.g. apk_lab/apktool_out).

    Returns:
        dict with structure:
            {
                "api_candidates": [
                    {
                        "framework": "Fuel",
                        "method": "...",
                        "base_url": "...",
                        "path": "...",
                        "full_url": "...",
                        "status": "static_api_candidate",
                        "source_file": "...",
                        "request_line": int,
                        "evidence": {
                            "path_value": "...",
                            "path_register": "...",
                            "path_line": int,
                            "request_call_line": int,
                            "base_url_value": "...",
                            "base_url_register": "...",
                            "base_url_line": int,
                            "base_url_call_line": int
                        }
                    }
                ]
            }

    Raises:
        FileNotFoundError: If analysis_root does not exist.
        NotADirectoryError: If analysis_root is not a directory.
    """
    root_path = Path(analysis_root)
    if not root_path.exists():
        raise FileNotFoundError(f"Analysis root directory not found: {analysis_root}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Analysis root is not a directory: {analysis_root}")

    api_candidates: list[dict] = []

    for file_path in root_path.rglob("*.smali"):
        if not file_path.is_file():
            continue

        rel_source_path = file_path.relative_to(root_path).as_posix()

        try:
            with file_path.open("r", encoding="utf-8") as f:
                lines = f.readlines()
        except (UnicodeDecodeError, OSError):
            continue

        in_method = False
        registers: dict[str, TrackedString] = {}
        receiver_bases: dict[str, BaseUrlEvidence] = {}
        singleton_receivers: set[str] = set()
        singleton_base: BaseUrlEvidence | None = None
        pending_singleton = False

        for line_num, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # 1. Method boundary handling
            if METHOD_START_RE.match(line):
                in_method = True
                registers.clear()
                receiver_bases.clear()
                singleton_receivers.clear()
                singleton_base = None
                pending_singleton = False
                continue

            if METHOD_END_RE.match(line):
                in_method = False
                registers.clear()
                receiver_bases.clear()
                singleton_receivers.clear()
                singleton_base = None
                pending_singleton = False
                continue

            if not in_method:
                continue

            # Do not carry base identity through unsupported control-flow joins.
            if line.startswith(":") or re.match(r"(?:goto|packed-switch|sparse-switch)\b", line):
                receiver_bases.clear()
                singleton_receivers.clear()
                singleton_base = None
                pending_singleton = False

            # The only shared Fuel context accepted is an explicit getInstance result.
            singleton_result = pending_singleton and line.startswith("move-result-object ")
            if not line.startswith("."):
                pending_singleton = False

            # 2. Track direct const-string assignments
            m_const = CONST_STRING_RE.match(line)
            if m_const:
                reg, val = m_const.group(1), m_const.group(2)
                receiver_bases.pop(reg, None)
                singleton_receivers.discard(reg)
                registers[reg] = TrackedString(value=val, line_number=line_num)
                continue

            # An unsupported object alias can later mutate the same manager.
            # Revoke its original binding rather than infer an alias relationship.
            alias = re.match(r"move-object(?:/from16|/16)?\s+([vp]\d+),\s*([vp]\d+)", line)
            if alias:
                source = alias.group(2)
                receiver_bases.pop(source, None)
                if source in singleton_receivers:
                    singleton_base = None
                singleton_receivers.discard(source)

            # 3. Invalidate registers overwritten by unsupported instructions
            m_dest = DEST_WRITE_RE.match(line)
            if m_dest:
                dest_reg = m_dest.group(1)
                # Overwritten with non-string/unknown data -> discard stale tracked value
                registers.pop(dest_reg, None)
                receiver_bases.pop(dest_reg, None)
                singleton_receivers.discard(dest_reg)
                if singleton_result:
                    singleton_receivers.add(dest_reg)

            # 4. Check invokes
            m_inv = INVOKE_RE.match(line)
            if not m_inv:
                continue

            raw_regs, target_class, method_name = m_inv.group(1), m_inv.group(2).strip(), m_inv.group(3).strip()
            reg_list = _parse_register_list(raw_regs)

            if (
                target_class == "Lcom/github/kittinunf/fuel/core/FuelManager$Companion;"
                and method_name == "getInstance"
                and m_inv.group(4) == ""
                and m_inv.group(5) == "Lcom/github/kittinunf/fuel/core/FuelManager;"
                and len(reg_list) == 1
            ):
                pending_singleton = True
                continue

            # Bind only to this receiver. Unknown/invalid setters revoke old evidence.
            if target_class == "Lcom/github/kittinunf/fuel/core/FuelManager;" and method_name == "setBasePath":
                if reg_list:
                    receiver = reg_list[0]
                    receiver_bases.pop(receiver, None)
                    if receiver in singleton_receivers:
                        singleton_base = None
                    tracked_url = registers.get(reg_list[1]) if len(reg_list) == 2 else None
                    if (
                        tracked_url and _http_url(tracked_url.value, base=True)
                        and m_inv.group(4) == "Ljava/lang/String;" and m_inv.group(5) == "V"
                    ):
                        base = BaseUrlEvidence(
                            value=tracked_url.value,
                            register=reg_list[1],
                            line_number=tracked_url.line_number,
                            call_line_number=line_num,
                        )
                        receiver_bases[receiver] = base
                        if receiver in singleton_receivers:
                            singleton_base = base
                continue

            # 4B. Fuel HTTP method call detection
            # Check for get, post, put, delete, patch (including $default variants)
            clean_method_name = method_name.split("$")[0].lower()
            if clean_method_name not in FUEL_HTTP_METHODS:
                continue

            http_method = clean_method_name.upper()

            # Determine path argument index based on signature
            path_arg_index: int | None = None

            if target_class == "Lcom/github/kittinunf/fuel/FuelKt;":
                # Static extension: invoke-static {path_reg, ...}, FuelKt->method(...)
                path_arg_index = 0
            elif target_class == "Lcom/github/kittinunf/fuel/Fuel$Companion;":
                # Companion method: invoke-static {companion_reg, path_reg, ...}, Fuel$Companion->method(...)
                # or invoke-virtual {companion_reg, path_reg, ...}
                path_arg_index = 1
            elif target_class == "Lcom/github/kittinunf/fuel/Fuel;":
                # Static method: invoke-static {path_reg, ...}, Fuel->method(...)
                path_arg_index = 0
            elif target_class == "Lcom/github/kittinunf/fuel/core/FuelManager;":
                # Instance method: invoke-virtual {manager_reg, path_reg, ...}, FuelManager->method(...)
                path_arg_index = 1

            if path_arg_index is None or len(reg_list) <= path_arg_index:
                # Unsupported signature pattern or insufficient arguments -> skip safely
                continue

            path_reg = reg_list[path_arg_index]
            if path_reg not in registers:
                # Target path register does not hold a tracked direct string literal -> skip
                continue

            tracked_path = registers[path_reg]
            path_val = tracked_path.value

            if not (_http_url(path_val) or _relative_path(path_val)):
                continue

            base = None
            if not _http_url(path_val):
                if target_class == "Lcom/github/kittinunf/fuel/core/FuelManager;":
                    receiver = reg_list[0]
                    base = singleton_base if receiver in singleton_receivers else receiver_bases.get(receiver)
                else:
                    base = singleton_base
            base_url_val = base.value if base else None
            full_url_val = _combine_url(base_url_val, path_val)

            evidence_dict = {
                "path_value": path_val,
                "path_register": path_reg,
                "path_line": tracked_path.line_number,
                "request_call_line": line_num,
                "base_url_value": base_url_val,
                "base_url_register": base.register if base else None,
                "base_url_line": base.line_number if base else None,
                "base_url_call_line": base.call_line_number if base else None,
            }

            api_candidates.append({
                "framework": "Fuel",
                "method": http_method,
                "base_url": base_url_val,
                "path": path_val,
                "full_url": full_url_val,
                "status": "static_api_candidate",
                "source_file": rel_source_path,
                "request_line": line_num,
                "evidence": evidence_dict,
            })

    def sort_key(item: dict) -> tuple:
        return (item["source_file"], item["request_line"], item["method"], item["path"])

    from src.retrofit_candidate_extractor import extract_retrofit
    api_candidates.extend(extract_retrofit(root_path)["api_candidates"])

    return {
        "api_candidates": sorted(api_candidates, key=sort_key),
    }
