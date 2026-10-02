"""Bounded Smali-only Retrofit declarations and same-method literal builder binding.

Optional bounded direct-call provenance; no field tracing, parameter extraction or global host pairing.
Unbound declarations remain diagnostic records, never canonical candidates.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urljoin, urlsplit, urlunsplit

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 256_000_000
MAX_FILES = 30_000
MAX_DECLARATIONS = 8192
MAX_BINDINGS = 4096
MAX_CANDIDATES = 10_000
ANNOTATION = re.compile(r"^\.annotation runtime Lretrofit2/http/(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS);$")
VALUE = re.compile(r'^value\s*=\s*"([^"\\]*)"$')
STRING = re.compile(r'^const-string(?:/jumbo)?\s+([vp]\d+),\s*"([^"\\]*)"$')
CLASS = re.compile(r'^const-class\s+([vp]\d+),\s*(L[^;\s]+;)$')
NEW = re.compile(r'^new-instance\s+([vp]\d+),\s*Lretrofit2/Retrofit\$Builder;$')
RESULT = re.compile(r'^move-result-object\s+([vp]\d+)$')
INVOKE = re.compile(r'^invoke-(?:virtual|direct|static|interface)\s+\{([^}]*)\},\s*(L[^;]+;)->(\S+)$')
REGISTER = re.compile(r'^[vp]\d+$')
DEST = re.compile(r'^[a-z][\w/-]*\s+([vp]\d+)(?:,|$)')
SENSITIVE_PATH = re.compile(r'/(?:token|password|secret|api[-_]?key|authorization)/[^/{]+', re.I)


def _safe_path(value: str) -> str | None:
    if not value or value.startswith(("//", "http:", "https:")):
        return None
    if any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value or "@" in value or "%" in value:
        return None
    parsed = urlsplit(value)
    path = parsed.path
    if parsed.scheme or parsed.netloc or not path or parsed.fragment:
        return None
    if any(part in (".", "..") for part in path.split("/")) or SENSITIVE_PATH.search(path):
        return None
    if not re.fullmatch(r'[A-Za-z0-9_./{}~-]+', path):
        return None
    # Only complete identifier placeholders; never broaden template semantics.
    without_templates = re.sub(r'\{[A-Za-z_][A-Za-z0-9_]*\}', '', path)
    if "{" in without_templates or "}" in without_templates:
        return None
    return path  # query values never retained, including in raw-path evidence


def _safe_base(value: str) -> str | None:
    try:
        if any(c.isspace() or ord(c) < 32 for c in value):
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            return None
        if "?" in value or "#" in value or not parsed.path.endswith("/") or parsed.port == 0:
            return None
        if not re.fullmatch(r'[A-Za-z0-9.-]+', parsed.hostname):
            return None
        host = parsed.hostname.rstrip(".")
        if len(host) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in host.split(".")):
            return None
        if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', host):
            from ipaddress import IPv4Address
            IPv4Address(host)
        if not re.fullmatch(r'[A-Za-z0-9_./~-]*', parsed.path) or any(p in (".", "..") for p in parsed.path.split("/")):
            return None
        if SENSITIVE_PATH.search(parsed.path):
            return None
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    except ValueError:
        return None


@dataclass
class Builder:
    base: dict | None = None
    initialized: bool = False


@dataclass(frozen=True)
class Client:
    base: dict | None


def _bindings(lines: list[tuple[int, str]], source: str, symbol: str) -> list[dict]:
    """Track only a straight-line builder/baseUrl/build/create chain."""
    registers: dict[str, object] = {}
    pending: object | None = None
    found = []
    for number, line in lines:
        if line.startswith(("#", ".line", ".local", ".end local", ".restart local")) or not line:
            continue
        if line.startswith((":","if-", "goto", "packed-switch", "sparse-switch", ".catch", "return", "throw")):
            registers.clear(); pending = None
            continue
        result = RESULT.fullmatch(line)
        if result:
            registers.pop(result[1], None)
            if pending is not None:
                registers[result[1]] = pending
            pending = None
            continue
        pending = None
        literal = STRING.fullmatch(line)
        clazz = CLASS.fullmatch(line)
        new = NEW.fullmatch(line)
        if literal:
            registers[literal[1]] = ("string", literal[2], number)
            continue
        if clazz:
            registers[clazz[1]] = ("class", clazz[2], number)
            continue
        if new:
            registers[new[1]] = Builder()
            continue
        call = INVOKE.fullmatch(line)
        if call:
            regs = [r.strip() for r in call[1].split(",") if r.strip()]
            if not regs or not all(REGISTER.fullmatch(r) for r in regs):
                registers.clear()
                continue
            receiver = registers.get(regs[0])
            owner, signature = call[2], call[3]
            if owner == "Lretrofit2/Retrofit$Builder;" and isinstance(receiver, Builder):
                if signature == "<init>()V" and len(regs) == 1 and line.startswith("invoke-direct "):
                    receiver.base = None
                    receiver.initialized = True
                elif signature == "baseUrl(Ljava/lang/String;)Lretrofit2/Retrofit$Builder;" and len(regs) == 2 and line.startswith("invoke-virtual ") and receiver.initialized:
                    literal_base = registers.get(regs[1])
                    receiver.base = None
                    if isinstance(literal_base, tuple) and literal_base[0] == "string":
                        base = _safe_base(literal_base[1])
                        if base:
                            receiver.base = dict(value=base, source_file=source, source_method=symbol,
                                                 literal_line=literal_base[2], call_line=number)
                    pending = receiver
                elif signature == "build()Lretrofit2/Retrofit;" and len(regs) == 1 and line.startswith("invoke-virtual ") and receiver.initialized:
                    pending = Client(dict(receiver.base) if receiver.base else None)
                else:
                    receiver.base = None
            elif owner == "Lretrofit2/Retrofit;" and signature == "create(Ljava/lang/Class;)Ljava/lang/Object;" and len(regs) == 2 and line.startswith("invoke-virtual "):
                service = registers.get(regs[1])
                if isinstance(receiver, Client) and receiver.base and isinstance(service, tuple) and service[0] == "class":
                    found.append(dict(service=service[1], base=receiver.base, create_line=number,
                                      class_line=service[2], source_file=source, source_method=symbol))
            else:
                # Unknown calls may escape/mutate tracked objects; don't infer purity.
                for reg in regs:
                    obj = registers.pop(reg, None)
                    if isinstance(obj, Builder):
                        obj.base = None
            continue
        if line.startswith("invoke-"):
            registers.clear()  # unsupported range/custom calls
            continue
        write = DEST.match(line)
        if write:
            registers.pop(write[1], None)
    return found


def _parse_file(text: str, source: str) -> tuple[list[dict], list[dict]]:
    declarations, bindings = [], []
    service = None
    annotation_class = False
    service_interface = False
    method = None
    method_is_abstract = False
    method_lines: list[tuple[int, str]] = []
    annotation = None
    method_declarations = []
    http_annotations = 0
    parameter = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith(".class "):
            service = line.split()[-1]
            annotation_class = "annotation" in line.split()
            service_interface = "interface" in line.split() and bool(re.fullmatch(r"L[^;\s]+;", service))
        if line.startswith(".method "):
            # Reset malformed previous method/annotation rather than carrying state.
            method = line.split()[-1]
            method_is_abstract = "abstract" in line.split()
            method_lines = []
            method_declarations = []
            http_annotations = 0
            annotation = None
            parameter = False
            continue
        if line == ".end method":
            if method and not annotation_class:
                bindings.extend(_bindings(method_lines, source, method))
                if len(method_declarations) == 1 and http_annotations == 1 and annotation is None:
                    declarations.extend(method_declarations)
            method = None; annotation = None
            continue
        if not method or annotation_class or not service:
            continue
        method_lines.append((number, line))
        if line.startswith(".param "):
            parameter = True
        elif line == ".end param":
            parameter = False
        match = ANNOTATION.fullmatch(line)
        if not parameter and (match or line == '.annotation runtime Lretrofit2/http/HTTP;'):
            http_annotations += 1
        if match and not parameter and annotation is None:
            annotation = dict(method=match[1], annotation_line=number, values=[], invalid=False)
        elif line.startswith(".annotation"):
            if annotation:
                annotation["invalid"] = True
        elif annotation and line == ".end annotation":
            if len(annotation["values"]) == 1 and not annotation["invalid"]:
                value_line, value = annotation["values"][0]
                path = _safe_path(value)
                if path and service_interface and method_is_abstract:
                    from src.api_candidate_canonicalizer import literal_query_metadata
                    method_declarations.append(dict(service=service, source_file=source, source_method=method,
                        method=annotation["method"], path=path, annotation_line=annotation["annotation_line"],
                        path_line=value_line, query_values_removed="?" in value, **literal_query_metadata(value)))
            annotation = None
        elif annotation and line:
            value = VALUE.fullmatch(line)
            if value:
                annotation["values"].append((number, value[1]))
            elif not line.startswith("#"):
                annotation["invalid"] = True
    return declarations, bindings


def extract_retrofit(analysis_root: str | Path) -> dict:
    """Return canonical bound candidates plus non-promoted discovery diagnostics."""
    root = Path(analysis_root)
    if not root.is_dir():
        raise FileNotFoundError(f"Analysis directory not found: {root}")
    declarations, bindings, skipped = [], [], []
    used = 0
    for index, path in enumerate(sorted(root.rglob("*.smali"))):
        source = path.relative_to(root).as_posix()
        if index >= MAX_FILES:
            skipped.append(dict(source_file=source, reason="source_limit"))
            break
        try:
            size = path.stat().st_size
            if path.is_symlink() or size > MAX_FILE_BYTES or used + size > MAX_TOTAL_BYTES:
                skipped.append(dict(source_file=source, reason="size_or_source_boundary"))
                continue
            used += size
            text = path.read_text(encoding="utf-8")
            if "\x00" in text:
                raise ValueError("binary text")
            parsed, linked = _parse_file(text, source)
            if len(declarations) + len(parsed) > MAX_DECLARATIONS or len(bindings) + len(linked) > MAX_BINDINGS:
                skipped.append(dict(source_file=source, reason="record_limit"))
                continue
            declarations.extend(parsed); bindings.extend(linked)
        except (UnicodeDecodeError, OSError, ValueError):
            skipped.append(dict(source_file=source, reason="unreadable_or_malformed"))
    from src.retrofit_flow import optimized_bindings
    flow = optimized_bindings(root, {d["service"] for d in declarations}) if declarations else {
        "bindings": [], "unresolved": [], "performance": {"files_scanned": 0, "methods_indexed": 0,
        "call_edges_inspected": 0, "max_traversal_depth": 0, "elapsed_seconds": 0.0}}
    # Keep V1 candidates byte-for-byte stable when the same binding is rediscovered.
    seen_bindings = {(b["service"], b["base"]["value"], b["source_file"], b["source_method"], b["create_line"]) for b in bindings}
    for binding in flow["bindings"]:
        key = (binding["service"], binding["base"]["value"], binding["source_file"], binding["source_method"], binding["create_line"])
        if key not in seen_bindings and len(bindings) < MAX_BINDINGS:
            bindings.append(binding)
            seen_bindings.add(key)
    by_service: dict[str, list[dict]] = {}
    for binding in bindings:
        by_service.setdefault(binding["service"], []).append(binding)
    candidates = []
    for declaration in declarations:
        for binding in by_service.get(declaration["service"], []):
            if len(candidates) >= MAX_CANDIDATES:
                break
            base = binding["base"]
            full = urljoin(base["value"], declaration["path"])
            if not _safe_base(base["value"]) or urlsplit(full).netloc != urlsplit(base["value"]).netloc:
                continue
            candidates.append(dict(framework="Retrofit", method=declaration["method"], base_url=base["value"],
                query_keys=declaration["query_keys"], query_shape=declaration["query_shape"], query_shape_known=declaration["query_shape_known"],
                path=declaration["path"], full_url=full, status="static_api_candidate",
                source_file=declaration["source_file"], request_line=declaration["annotation_line"],
                evidence=dict(path_value=declaration["path"], path_line=declaration["path_line"],
                    source_method=declaration["source_method"], service_class=declaration["service"],
                    annotation_line=declaration["annotation_line"], query_values_removed=declaration["query_values_removed"],
                    base_url_value=base["value"], base_url_source_file=base["source_file"],
                    base_url_source_method=base["source_method"], base_url_line=base["literal_line"],
                    base_url_call_line=base["call_line"], service_create_source_file=binding["source_file"],
                    service_create_source_method=binding["source_method"], service_create_line=binding["create_line"],
                    service_class_line=binding["class_line"])))
            if binding.get("trace"):
                candidates[-1]["evidence"]["interprocedural_trace"] = binding["trace"]
    candidates.sort(key=lambda c:(c["source_file"], c["request_line"], c["method"], c["path"],
                                   c["base_url"], c["evidence"]["service_create_source_file"], c["evidence"]["service_create_line"]))
    return dict(api_candidates=candidates, declarations=declarations, bindings=bindings,
                unbound_declaration_count=sum(d["service"] not in by_service for d in declarations), skipped=skipped,
                unresolved_flow=flow["unresolved"], flow_performance=flow["performance"])
