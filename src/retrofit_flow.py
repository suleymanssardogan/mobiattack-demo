"""Bounded direct Retrofit provenance; no heap, field, branch or general taint engine."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from time import perf_counter

MAX_DEPTH = 3
MAX_METHODS = 2048
MAX_OPERATIONS = 200_000
MAX_EVALUATIONS = 10_000
MAX_DIAGNOSTICS = 512
MAX_TRACE = 512
NETWORK_TYPES = {
    "Lretrofit2/Retrofit;", "Lretrofit2/Retrofit$Builder;",
    "Lokhttp3/HttpUrl;", "Lokhttp3/HttpUrl$Builder;",
}
CALL = re.compile(r'^invoke-(static|virtual|direct|interface|super)\s+\{([^}]*)\},\s*(L[^;]+;)->(\S+)$')
MOVE = re.compile(r'^move-object(?:/from16|/16)?\s+([vp]\d+),\s*([vp]\d+)$')
NEW = re.compile(r'^new-instance\s+([vp]\d+),\s*(L[^;]+;)$')
ZERO = re.compile(r'^const(?:/4|/16)?\s+([vp]\d+),\s*0x0$')
PARAMETER = re.compile(r'\[*L[^;]+;|\[*[ZBCSIFJD]')


@dataclass
class Method:
    key: str
    source: str
    symbol: str
    static: bool
    final: bool
    direct: bool
    operations: list
    types: list[str]


@dataclass
class Value:
    kind: str
    data: object
    trace: list


def _event(method: Method, line: int, kind: str, **extra) -> dict:
    return dict(source_file=method.source, source_method=method.symbol, line=line, kind=kind, **extra)


def _types(symbol: str) -> list[str] | None:
    match = re.fullmatch(r'[^()\s]+\(([^)]*)\)(?:\[*L[^;]+;|\[*[VZBCSIFJD])', symbol)
    if not match:
        return None
    types = PARAMETER.findall(match[1])
    return types if "".join(types) == match[1] else None


def _methods(text: str, source: str, safe_base, string_re, class_re, result_re, dest_re):
    owner = None
    class_final = False
    current = None
    annotation_depth = 0
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith(".class "):
            owner = line.split()[-1]
            class_final = "final" in line.split()
        if line.startswith(".method "):
            flags = line.split()
            symbol = flags[-1]
            types = _types(symbol)
            current = Method(owner + "->" + symbol, source, symbol, "static" in flags,
                             "final" in flags or class_final, "private" in flags or symbol.startswith("<init>"),
                             [], types) if owner and types is not None else None
            annotation_depth = 0
            continue
        if line == ".end method":
            if current:
                yield current
            current = None
            continue
        if not current:
            continue
        if line.startswith(".annotation"):
            annotation_depth += 1
        elif line == ".end annotation":
            annotation_depth = max(0, annotation_depth - 1)
        if annotation_depth or line.startswith((".", "#")) or not line:
            # Exception tables imply unsupported exceptional flow.
            if line.startswith(".catch"):
                current.operations.append((line_no, "branch"))
            continue
        if line.startswith((":", "if-", "goto", "packed-switch", "sparse-switch", "throw")):
            op = ("branch",)
        elif (match := string_re.fullmatch(line)):
            op = ("string", match[1], safe_base(match[2]))  # discard non-URL/secret literals at indexing
        elif (match := class_re.fullmatch(line)):
            op = ("class", match[1], match[2])
        elif (match := MOVE.fullmatch(line)):
            op = ("move", match[1], match[2])
        elif (match := result_re.fullmatch(line)):
            op = ("result", match[1])
        elif (match := NEW.fullmatch(line)):
            op = ("new", match[1], match[2])
        elif (match := ZERO.fullmatch(line)):
            op = ("zero", match[1])
        elif (match := CALL.fullmatch(line)):
            registers = [r.strip() for r in match[2].split(",") if r.strip()]
            if not all(re.fullmatch(r'[vp]\d+', r) for r in registers):
                op = ("unsupported_call",)
            else:
                op = ("call", match[1], match[3] + "->" + match[4], registers)
        elif line.startswith("invoke-"):
            op = ("unsupported_call",)
        elif line.startswith("return-object "):
            op = ("return", line.split()[-1])
        elif line.startswith("return"):
            op = ("return_none",)
        elif (match := dest_re.match(line)):
            category = "field_store" if line.startswith(("iput", "sput")) else "field" if line.startswith(("iget", "sget")) else "unknown"
            op = ("write", match[1], category)
        else:
            # Unsupported instructions cannot preserve a pending call result.
            op = ("other",)
        current.operations.append((line_no, *op))


def optimized_bindings(root: Path, service_descriptors: set[str], *, max_depth=MAX_DEPTH) -> dict:
    from src.retrofit_candidate_extractor import (
        MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_FILES, _safe_base, STRING, CLASS, RESULT, DEST,
    )
    started = perf_counter()
    max_depth = max(0, min(max_depth, MAX_DEPTH))
    paths = []
    used = 0
    for path in sorted(root.rglob("*.smali")):
        if len(paths) >= MAX_FILES:
            break
        try:
            size = path.stat().st_size
            if path.is_symlink() or size > MAX_FILE_BYTES or used + size > MAX_TOTAL_BYTES:
                continue
            used += size
            paths.append(path)
        except OSError:
            continue
    methods, duplicates, network_methods = {}, set(), set()
    stats = dict(files_scanned=len(paths), methods_indexed=0, call_edges_inspected=0,
                 max_traversal_depth=0, evaluations=0, indexing_passes=0, diagnostics_truncated=False)
    diagnostics = []
    seen_diagnostics = set()

    def diagnostic(reason, method=None, line=0, **extra):
        item = dict(reason=reason, **extra)
        if method:
            item.update(_event(method, line, "unresolved"))
        identity = repr(item)
        if len(diagnostics) < MAX_DIAGNOSTICS and identity not in seen_diagnostics:
            diagnostics.append(item); seen_diagnostics.add(identity)
        elif identity not in seen_diagnostics:
            stats["diagnostics_truncated"] = True

    # Seed actual Retrofit construction/create sites and service constants.
    # URL-return helpers enter only through a selected caller's exact target.
    # This avoids indexing unrelated URL literals or HttpUrl implementation internals.
    operations = 0
    for pass_no in range(max_depth + 1):
        stats["indexing_passes"] += 1
        targets = set(network_methods)
        callees = set()
        for method in methods.values():
            if not any(item[1] in ("branch", "unsupported_call") for item in method.operations):
                callees.update(op[3] for op in method.operations if op[1] == "call"
                               and op[3].split("->")[0] not in NETWORK_TYPES
                               and op[3].split(")")[-1] in ("Ljava/lang/String;", "Ljava/lang/Class;", "Ljava/lang/Object;", "Lokhttp3/HttpUrl;", "Lretrofit2/Retrofit;"))
        seen_in_pass = set()
        for path in paths:
            try:
                text = path.read_text(encoding="utf-8")
                if "\x00" in text:
                    continue
                for method in _methods(text, path.relative_to(root).as_posix(), _safe_base, STRING, CLASS, RESULT, DEST):
                    if method.key in methods:
                        if methods[method.key].source != method.source or method.key in seen_in_pass:
                            duplicates.add(method.key)
                        seen_in_pass.add(method.key)
                        continue
                    relevant = method.key in callees
                    network_relevant = False
                    for op in method.operations:
                        if op[1] == "call":
                            stats["call_edges_inspected"] += 1
                            network_relevant |= op[3].split("->")[0] in ("Lretrofit2/Retrofit;", "Lretrofit2/Retrofit$Builder;") or op[3] in targets
                        elif op[1] == "new":
                            network_relevant |= op[3] in ("Lretrofit2/Retrofit;", "Lretrofit2/Retrofit$Builder;")
                        elif op[1] == "class":
                            network_relevant |= op[3] in service_descriptors
                    if relevant or network_relevant:
                        if len(methods) >= MAX_METHODS or operations + len(method.operations) > MAX_OPERATIONS:
                            diagnostic("INDEX_LIMIT")
                            continue
                        methods[method.key] = method
                        if network_relevant:
                            network_methods.add(method.key)
                        seen_in_pass.add(method.key)
                        operations += len(method.operations)
            except (OSError, UnicodeDecodeError, ValueError):
                continue
    stats["methods_indexed"] = len(methods)
    stats["operations_retained"] = operations

    def forward(value, event):
        if value is None or value.kind not in ("string", "class", "httpurl", "retrofit", "instance", "zero"):
            return None
        return Value(value.kind, value.data, value.trace + [event])

    def evaluate(method, actuals, depth, stack):
        stats["evaluations"] += 1
        stats["max_traversal_depth"] = max(stats["max_traversal_depth"], min(depth, max_depth))
        if stats["evaluations"] > MAX_EVALUATIONS:
            diagnostic("EVALUATION_LIMIT", method)
            return None, [], False
        if depth > max_depth:
            diagnostic("INTERPROCEDURAL_DEPTH_LIMIT", method)
            return None, [], False
        if method.key in stack:
            diagnostic("INTERPROCEDURAL_CYCLE", method)
            return None, [], False
        if method.key in duplicates:
            diagnostic("CALLSITE_AMBIGUOUS", method)
            return None, [], False
        if any(op[1] in ("branch", "unsupported_call") for op in method.operations):
            diagnostic("UNSUPPORTED_BRANCH_FLOW" if any(op[1] == "branch" for op in method.operations) else "UNSUPPORTED_CALL_FLOW", method)
            return None, [], False
        expected = sum(2 if t in ("J", "D") else 1 for t in method.types) + (not method.static)
        if actuals is not None and len(actuals) != expected:
            diagnostic("ARGUMENT_MAPPING_UNRESOLVED", method)
            return None, [], False
        registers = {}
        if actuals is not None:
            cursor = 0
            if not method.static:
                registers["p0"] = actuals[0]
                cursor = 1
            kinds = {"Ljava/lang/String;": "string", "Ljava/lang/Class;": "class",
                     "Lokhttp3/HttpUrl;": "httpurl", "Lretrofit2/Retrofit;": "retrofit"}
            for typ in method.types:
                width = 2 if typ in ("J", "D") else 1
                value = actuals[cursor]
                registers[f"p{cursor}"] = value if value and kinds.get(typ) == value.kind else None
                if width == 2:
                    registers[f"p{cursor + 1}"] = None
                cursor += width
        pending = None
        found = []
        for op in method.operations:
            if any(value and len(value.trace) >= MAX_TRACE for value in registers.values()):
                diagnostic("TRACE_LIMIT", method, op[0])
                return None, [], False
            line, kind, *args = op
            event = _event(method, line, kind)
            if kind == "result":
                if pending and pending.kind in ("builder", "http_builder"):
                    pending.trace.append(event)
                    registers[args[0]] = pending
                else:
                    registers[args[0]] = forward(pending, event)
                pending = None
                continue
            pending = None
            if kind == "string":
                registers[args[0]] = Value("string", args[1], [event]) if args[1] else None
            elif kind == "class":
                registers[args[0]] = Value("class", args[1], [event])
            elif kind == "move":
                value = registers.get(args[1])
                # Direct local object identity only, no field/heap alias traversal.
                if value and value.kind in ("builder", "http_builder", "allocation"):
                    value.trace.append(event)
                registers[args[0]] = value if value and value.kind in ("builder", "http_builder", "allocation") else forward(value, event)
            elif kind == "zero":
                registers[args[0]] = Value("zero", None, [event])
            elif kind == "new":
                owner = args[1]
                typ = {"Lretrofit2/Retrofit;": "allocation", "Lretrofit2/Retrofit$Builder;": "builder",
                       "Lokhttp3/HttpUrl$Builder;": "http_builder"}.get(owner, "instance")
                registers[args[0]] = Value(typ, dict(owner=owner, initialized=False, base=None), [event])
            elif kind == "write":
                previous = registers.get(args[0])
                if args[1] == "field_store" and previous and previous.kind in ("builder", "http_builder", "allocation", "retrofit"):
                    diagnostic("UNSUPPORTED_OBJECT_ESCAPE", method, line)
                    return None, [], False
                registers[args[0]] = None
                if args[1] in ("field", "field_store"):
                    diagnostic("UNSUPPORTED_FIELD_FLOW", method, line)
            elif kind == "return":
                return forward(registers.get(args[0]), _event(method, line, "return")), found, True
            elif kind == "return_none":
                return None, found, True
            elif kind == "call":
                mode, target, names = args
                event = _event(method, line, "call", callee=target)
                owner, signature = target.split("->", 1)
                values = [registers.get(name) for name in names]
                receiver = values[0] if values else None
                if owner in ("Lretrofit2/Retrofit$Builder;", "Lokhttp3/HttpUrl$Builder;") and receiver and receiver.kind in ("builder", "http_builder") and receiver.data["owner"] == owner:
                    if mode == "direct" and (signature == "<init>()V" and len(values) == 1 or owner == "Lokhttp3/HttpUrl$Builder;" and signature == "<init>(B)V" and len(values) == 2 and values[1] and values[1].kind == "zero"):
                        receiver.data["initialized"] = True
                        receiver.trace.append(event)
                    elif receiver.data["initialized"] and mode == "virtual" and signature == "baseUrl(Ljava/lang/String;)Lretrofit2/Retrofit$Builder;" and owner == "Lretrofit2/Retrofit$Builder;" and len(values) == 2:
                        receiver.data["base"] = values[1] if values[1] and values[1].kind == "string" else None
                        receiver.trace.append(event); pending = receiver
                    elif receiver.data["initialized"] and mode == "virtual" and signature == "parse$okhttp(Lokhttp3/HttpUrl;Ljava/lang/String;)V" and owner == "Lokhttp3/HttpUrl$Builder;" and len(values) == 3 and values[1] and values[1].kind == "zero":
                        receiver.data["base"] = values[2] if values[2] and values[2].kind == "string" else None
                        receiver.trace.append(event)
                    elif receiver.data["initialized"] and mode == "virtual" and len(values) == 1 and (owner, signature) in (("Lretrofit2/Retrofit$Builder;", "build()Lretrofit2/Retrofit;"), ("Lokhttp3/HttpUrl$Builder;", "build()Lokhttp3/HttpUrl;")):
                        base = receiver.data["base"]
                        if base:
                            pending = Value("retrofit" if receiver.kind == "builder" else "httpurl", base,
                                            base.trace + receiver.trace + [event])
                        else:
                            diagnostic("BASE_UNRESOLVED", method, line)
                    else:
                        receiver.data["base"] = None
                        diagnostic("UNSUPPORTED_HTTPURL_FLOW" if receiver.kind == "http_builder" else "BASE_UNRESOLVED", method, line)
                elif owner == "Lokhttp3/HttpUrl;" and mode == "static" and signature in ("parse(Ljava/lang/String;)Lokhttp3/HttpUrl;", "get(Ljava/lang/String;)Lokhttp3/HttpUrl;") and len(values) == 1:
                    base = values[0]
                    if base and base.kind == "string":
                        pending = Value("httpurl", base, base.trace + [event])
                    else:
                        diagnostic("UNSUPPORTED_HTTPURL_FLOW", method, line)
                elif owner == "Lretrofit2/Retrofit;" and mode == "direct" and signature == "<init>(Lokhttp3/OkHttpClient;Lokhttp3/HttpUrl;Ljava/util/List;Ljava/util/List;)V" and len(values) == 5 and receiver and receiver.kind == "allocation":
                    base = values[2]
                    if base and base.kind == "httpurl":
                        receiver.kind = "retrofit"
                        receiver.data = base.data
                        receiver.trace = base.trace + receiver.trace + [event]
                    else:
                        diagnostic("BASE_UNRESOLVED", method, line)
                elif owner == "Lretrofit2/Retrofit;" and mode == "virtual" and signature == "create(Ljava/lang/Class;)Ljava/lang/Object;" and len(values) == 2:
                    service = values[1]
                    known_service = service is not None and service.kind == "class" and service.data in service_descriptors
                    known_base = receiver is not None and receiver.kind == "retrofit" and receiver.data is not None
                    if known_service and known_base:
                        base = receiver.data
                        origin = base.trace[0]
                        chain = receiver.trace + service.trace + [event]
                        if len(chain) > MAX_TRACE:
                            diagnostic("TRACE_LIMIT", method, line)
                            return None, [], False
                        found.append(dict(service=service.data,
                            base=dict(value=base.data, source_file=origin["source_file"], source_method=origin["source_method"],
                                      literal_line=origin["line"], call_line=None),
                            source_file=method.source, source_method=method.symbol, create_line=line,
                            class_line=service.trace[0]["line"], trace=chain))
                    else:
                        diagnostic("BASE_UNRESOLVED" if known_service else "SERVICE_UNRESOLVED", method, line,
                                   service_resolved=known_service, base_resolved=known_base,
                                   service_class=service.data if known_service else None)
                elif target in methods:
                    callee = methods[target]
                    allowed = (mode == "static" and callee.static or mode == "direct" and not callee.static and callee.direct
                               or mode == "virtual" and not callee.static and callee.final)
                    if not allowed:
                        diagnostic("CALLSITE_AMBIGUOUS", method, line)
                        return None, [], False
                    if any(value and value.kind in ("builder", "http_builder", "allocation") for value in values):
                        diagnostic("UNSUPPORTED_OBJECT_FLOW", method, line)
                        return None, [], False
                    actuals = [forward(value, _event(method, line, "argument", callee=target,
                               argument_word_index=i, parameter_register=f"p{i}")) for i, value in enumerate(values)]
                    pending, nested, ok = evaluate(callee, actuals, depth + 1, stack + (method.key,))
                    if not ok:
                        return None, [], False
                    found.extend(nested)
                else:
                    # Unknown calls never produce trusted results; escaped object identity invalidates.
                    escaped = False
                    for value in values:
                        if value and value.kind in ("builder", "http_builder", "allocation", "retrofit"):
                            escaped = True
                            value.data = None
                            for register, known in list(registers.items()):
                                if known is value:
                                    registers[register] = None
                    if escaped:
                        diagnostic("UNSUPPORTED_OBJECT_ESCAPE", method, line)
                        return None, [], False
        return None, found, True

    bindings = []
    for method in sorted(methods.values(), key=lambda m: m.key):
        _, found, _ = evaluate(method, None, 0, ())
        bindings.extend(found)
    # Same exact declaration/call chain is emitted once, never globally merged by type.
    unique = {}
    for binding in bindings:
        key = repr(binding)
        unique.setdefault(key, binding)
    stats["elapsed_seconds"] = round(perf_counter() - started, 4)
    return dict(bindings=list(unique.values()), unresolved=diagnostics, performance=stats)
