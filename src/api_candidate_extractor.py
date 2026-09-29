"""Call-Context-Aware Static API Candidate Extractor.

Performs local call-context and direct register-flow analysis on Smali files to identify
static API candidates used in Fuel networking calls.

Supported Framework:
- Fuel (GET, POST, PUT, DELETE, PATCH)

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
"""

from dataclasses import dataclass
from pathlib import Path
import re

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


def _combine_url(base_url: str | None, path: str) -> str | None:
    """Deterministically join base URL and path avoiding double slashes."""
    if not path:
        return None
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if not base_url:
        return None
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def extract_api_candidates(analysis_root: str | Path) -> dict:
    """Scan Smali files under analysis_root and extract Fuel static API candidates.

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
        latest_base_url: BaseUrlEvidence | None = None

        for line_num, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # 1. Method boundary handling
            if METHOD_START_RE.match(line):
                in_method = True
                registers.clear()
                latest_base_url = None
                continue

            if METHOD_END_RE.match(line):
                in_method = False
                registers.clear()
                latest_base_url = None
                continue

            if not in_method:
                continue

            # 2. Track direct const-string assignments
            m_const = CONST_STRING_RE.match(line)
            if m_const:
                reg, val = m_const.group(1), m_const.group(2)
                registers[reg] = TrackedString(value=val, line_number=line_num)
                continue

            # 3. Invalidate registers overwritten by unsupported instructions
            m_dest = DEST_WRITE_RE.match(line)
            if m_dest:
                dest_reg = m_dest.group(1)
                # Overwritten with non-string/unknown data -> discard stale tracked value
                registers.pop(dest_reg, None)

            # 4. Check invokes
            m_inv = INVOKE_RE.match(line)
            if not m_inv:
                continue

            raw_regs, target_class, method_name = m_inv.group(1), m_inv.group(2).strip(), m_inv.group(3).strip()
            reg_list = _parse_register_list(raw_regs)

            # 4A. FuelManager.setBasePath detection
            # Signature: Lcom/github/kittinunf/fuel/core/FuelManager;->setBasePath(Ljava/lang/String;)V
            # Register index 0: FuelManager instance, Register index 1: Base URL string
            if target_class == "Lcom/github/kittinunf/fuel/core/FuelManager;" and method_name == "setBasePath":
                if len(reg_list) >= 2:
                    url_reg = reg_list[1]
                    if url_reg in registers:
                        tracked_url = registers[url_reg]
                        latest_base_url = BaseUrlEvidence(
                            value=tracked_url.value,
                            register=url_reg,
                            line_number=tracked_url.line_number,
                            call_line_number=line_num,
                        )
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

            # Combine URL if local base URL exists
            base_url_val = latest_base_url.value if latest_base_url else None
            full_url_val = _combine_url(base_url_val, path_val)

            evidence_dict = {
                "path_value": path_val,
                "path_register": path_reg,
                "path_line": tracked_path.line_number,
                "request_call_line": line_num,
                "base_url_value": base_url_val,
                "base_url_register": latest_base_url.register if latest_base_url else None,
                "base_url_line": latest_base_url.line_number if latest_base_url else None,
                "base_url_call_line": latest_base_url.call_line_number if latest_base_url else None,
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

    return {
        "api_candidates": sorted(api_candidates, key=sort_key),
    }
