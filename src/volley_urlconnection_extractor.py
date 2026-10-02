"""Bounded direct Volley construction and explicit-method HTTP connection flows.

No branch/heap/wrapper interpretation. Construction/use evidence is static only;
queue linkage is attached only to a locally proven queue and request allocation.
"""
from dataclasses import dataclass
from pathlib import Path
import re

from src.okhttp_candidate_extractor import CALL, STRING, MOVE, NEW, RESULT, Literal, _identity
from src.android_identity import canonical_candidates

URL = 'Ljava/net/URL;'
HTTP = {'Ljava/net/HttpURLConnection;', 'Ljavax/net/ssl/HttpsURLConnection;'}
CONNECTION = 'Ljava/net/URLConnection;'
REQUEST = 'Lcom/android/volley/Request;'
QUEUE = 'Lcom/android/volley/RequestQueue;'
LISTENERS = 'Lcom/android/volley/Response$Listener;Lcom/android/volley/Response$ErrorListener;'
VOLLEY = {f'Lcom/android/volley/toolbox/{name};': body for name, body in
          [('StringRequest', None), ('JsonObjectRequest', 'Lorg/json/JSONObject;'), ('JsonArrayRequest', 'Lorg/json/JSONArray;')]}
METHODS = dict(enumerate(['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'PATCH']))
MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES = 30000, 2_000_000, 256_000_000
MAX_METHOD_LINES, MAX_RECORDS = 4096, 10000
INTEGER = re.compile(r'^const(?:/4|/16)?\s+([vp]\d+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))$')
ENUM = re.compile(r'^sget\s+([vp]\d+),\s*Lcom/android/volley/Request\$Method;->(GET|POST|PUT|DELETE|HEAD|OPTIONS|TRACE|PATCH):I$')


@dataclass
class Integer:
    value: int
    line: int


@dataclass
class Ref:
    kind: str
    allocation: int
    initialized: bool = False
    valid: bool = True
    url: Literal | None = None
    method: Literal | None = None
    origin: int | None = None
    init_line: int | None = None
    method_call_line: int | None = None
    http_line: int | None = None
    row: dict | None = None


def _method(lines, source, component, symbol):
    rows, gaps = [], []
    signals = {'volley': any('Lcom/android/volley/' in s for _, s in lines),
               'httpurlconnection': any(URL in s or any(t in s for t in HTTP) for _, s in lines)}
    def gap(framework, reason, line):
        if len(gaps) < MAX_RECORDS:
            gaps.append(dict(framework=framework, source_file=source, source_component=component,
                             source_method=symbol, line=line, reason=reason, resolution_state='unresolved'))
    if not any(signals.values()):
        return rows, gaps
    if not component or not re.fullmatch(r'L[^;\s]+;', component):
        for framework, present in signals.items():
            if present: gap(framework, 'SOURCE_COMPONENT_UNRESOLVED', 0)
        return rows, gaps
    if len(lines) > MAX_METHOD_LINES or any(s.startswith(':') or re.match(r'(if-|goto|packed-switch|sparse-switch|\.catch)', s) for _, s in lines):
        for framework, present in signals.items():
            if present: gap(framework, 'UNSUPPORTED_CONTROL_FLOW', lines[0][0])
        return rows, gaps
    registers, pending = {}, None
    def invalidate(values, reason, number):
        for ref in values:
            if isinstance(ref, Ref):
                ref.valid = False
                if ref.kind in VOLLEY or ref.kind == QUEUE:
                    gap('volley', reason, number)
                elif ref.kind in {URL, CONNECTION}:
                    gap('httpurlconnection', reason, number)
    def emit(framework, ref, number, evidence):
        identity = _identity(ref.url.value) if ref.url else None
        if not identity or not ref.method:
            gap(framework, 'REQUEST_URL_OR_METHOD_UNRESOLVED', number)
            return None
        row = dict(identity, method=ref.method.value, framework=framework,
                   source_file=source, source_component=component, request_line=number,
                   status='static_api_candidate', resolution_state='resolved',
                   evidence=dict(source_method=symbol, allocation_line=ref.allocation,
                                 url_literal_line=ref.url.line, method_line=ref.method.line,
                                 query_values_removed=bool(identity['query_keys']), **evidence))
        rows.append(row)
        return row
    for number, line in lines:
        if not line or line.startswith(('#', '.')):
            continue
        match = RESULT.fullmatch(line)
        if match:
            registers.pop(match[1], None)
            if pending is not None: registers[match[1]] = pending
            pending = None
            continue
        pending = None
        if line.startswith(('return', 'throw')): break
        match = STRING.fullmatch(line)
        if match:
            registers[match[1]] = Literal(match[2], number)
            continue
        match = INTEGER.fullmatch(line)
        if match:
            registers[match[1]] = Integer(int(match[2], 0) if 'x' in match[2] else int(match[2]), number)
            continue
        match = ENUM.fullmatch(line)
        if match:
            registers[match[1]] = Integer(next(k for k, v in METHODS.items() if v == match[2]), number)
            continue
        match = MOVE.fullmatch(line) or re.fullmatch(r'move(?:/from16|/16)?\s+([vp]\d+),\s*([vp]\d+)', line)
        if match:
            value = registers.get(match[2])
            registers.pop(match[1], None)
            if value is not None: registers[match[1]] = value
            continue
        match = NEW.fullmatch(line)
        if match:
            registers.pop(match[1], None)
            if match[2] in {*VOLLEY, QUEUE, URL}:
                registers[match[1]] = Ref(match[2], number)
            continue
        match = re.fullmatch(r'check-cast\s+([vp]\d+),\s*(L[^;]+;)', line)
        if match:
            ref = registers.get(match[1])
            if isinstance(ref, Ref) and ref.kind == CONNECTION and match[2] in HTTP:
                ref.http_line = number
            elif isinstance(ref, Ref):
                ref.valid = False
            continue
        match = CALL.fullmatch(line)
        ranged = re.fullmatch(r'invoke-(virtual|direct|static|interface)/range\s+\{([vp])(\d+)\s+\.\.\s+([vp])(\d+)\},\s*(L[^;]+;)->(\S+)', line)
        if ranged and ranged[2] == ranged[4] and 0 <= int(ranged[5])-int(ranged[3]) <= 8:
            mode, owner, signature = ranged[1], ranged[6], ranged[7]
            regs = [ranged[2]+str(i) for i in range(int(ranged[3]), int(ranged[5])+1)]
        elif match:
            mode, register_text, owner, signature = match.groups()
            regs = [r.strip() for r in register_text.split(',') if r.strip()]
        else:
            regs = None
        if regs is not None:
            if not all(re.fullmatch(r'[vp]\d+', r) for r in regs):
                invalidate(registers.values(), 'UNSUPPORTED_INVOKE_FORM', number)
                continue
            receiver = registers.get(regs[0]) if regs else None
            args = [registers.get(r) for r in regs[1:]]
            if mode == 'direct' and owner in VOLLEY and isinstance(receiver, Ref) and receiver.kind == owner and receiver.valid and not receiver.initialized:
                body = VOLLEY[owner]
                explicit = '<init>(ILjava/lang/String;' + (body or '') + LISTENERS + ')V'
                default = '<init>(Ljava/lang/String;' + LISTENERS + ')V'
                method, url = None, None
                method_origin = 'explicit_method_constant'
                if signature == explicit and len(args) == (5 if body else 4):
                    code = args[0]
                    if isinstance(code, Integer) and code.value in METHODS:
                        method = Literal(METHODS[code.value], code.line)
                    url = args[1] if isinstance(args[1], Literal) else None
                elif signature == default and len(args) == 3:
                    method, method_origin = Literal('GET', number), 'constructor_default_GET'
                    url = args[0] if isinstance(args[0], Literal) else None
                elif owner.endswith('/JsonObjectRequest;') and signature == '<init>(Ljava/lang/String;Lorg/json/JSONObject;' + LISTENERS + ')V' and len(args) == 4:
                    # Only known null is supported; an unknown body cannot choose GET/POST.
                    if isinstance(args[1], Integer) and args[1].value == 0:
                        method, method_origin = Literal('GET', number), 'constructor_null_body_GET'
                    url = args[0] if isinstance(args[0], Literal) else None
                receiver.initialized, receiver.url, receiver.method = True, url, method
                receiver.row = emit('volley', receiver, number, dict(constructor_line=number,
                    request_class=owner, method_origin=method_origin, queue_add_refs=[], dispatch_observed=False))
                continue
            if isinstance(receiver, Ref) and receiver.kind == QUEUE and owner == QUEUE:
                queue_constructors = {'<init>(Lcom/android/volley/Cache;Lcom/android/volley/Network;)V', '<init>(Lcom/android/volley/Cache;Lcom/android/volley/Network;I)V', '<init>(Lcom/android/volley/Cache;Lcom/android/volley/Network;ILcom/android/volley/ResponseDelivery;)V'}
                if mode == 'direct' and signature in queue_constructors and not receiver.initialized:
                    receiver.initialized = True
                    receiver.init_line = number
                    continue
                if mode == 'virtual' and signature == 'add(' + REQUEST + ')' + REQUEST and len(args) == 1:
                    request = args[0]
                    if receiver.valid and receiver.initialized and isinstance(request, Ref) and request.valid and request.row:
                        request.row['evidence']['queue_add_refs'].append(dict(queue_origin_line=receiver.allocation, queue_init_line=receiver.init_line, add_line=number))
                        pending = request
                    else: gap('volley', 'QUEUE_REQUEST_BINDING_UNRESOLVED', number)
                    continue
            if mode == 'static' and owner == 'Lcom/android/volley/toolbox/Volley;' and signature == 'newRequestQueue(Landroid/content/Context;)' + QUEUE and len(regs) == 1:
                pending = Ref(QUEUE, number, initialized=True, init_line=number)
                continue
            if mode == 'direct' and owner == URL and isinstance(receiver, Ref) and receiver.kind == URL and not receiver.initialized and signature == '<init>(Ljava/lang/String;)V' and len(args) == 1:
                receiver.initialized = True
                receiver.init_line = number
                receiver.url = args[0] if isinstance(args[0], Literal) and _identity(args[0].value) else None
                continue
            if mode == 'virtual' and owner == URL and signature == 'openConnection()' + CONNECTION and len(regs) == 1 and isinstance(receiver, Ref) and receiver.kind == URL:
                if receiver.valid and receiver.initialized and receiver.url:
                    pending = Ref(CONNECTION, receiver.allocation, initialized=True, url=receiver.url, origin=number, init_line=receiver.init_line)
                else: gap('httpurlconnection', 'URL_BINDING_UNRESOLVED', number)
                continue
            if mode == 'virtual' and owner in HTTP | {CONNECTION} and isinstance(receiver, Ref) and receiver.kind == CONNECTION:
                if owner in HTTP: receiver.http_line = receiver.http_line or number
                if not receiver.valid:
                    gap('httpurlconnection', 'CONNECTION_IDENTITY_UNRESOLVED', number)
                    continue
                if owner in HTTP and signature == 'setRequestMethod(Ljava/lang/String;)V' and len(args) == 1:
                    receiver.method = args[0] if isinstance(args[0], Literal) and args[0].value in set(METHODS.values()) - {'TRACE'} else None
                    receiver.method_call_line = number
                    continue
                triggers = {'connect()V', 'getInputStream()Ljava/io/InputStream;', 'getOutputStream()Ljava/io/OutputStream;', 'getResponseCode()I'}
                if signature in triggers and len(regs) == 1:
                    if receiver.http_line and receiver.method and not (signature.startswith('getOutputStream') and receiver.method.value == 'GET'):
                        emit('httpurlconnection', receiver, number, dict(open_connection_line=receiver.origin,
                             url_constructor_line=receiver.init_line, method_call_line=receiver.method_call_line,
                             http_type_line=receiver.http_line, use_line=number, use_kind=signature.split('(')[0],
                             method_origin='explicit_setRequestMethod', dispatch_observed=False))
                    else:
                        gap('httpurlconnection', 'HTTP_TYPE_OR_METHOD_UNRESOLVED', number)
                        if signature.startswith('getOutputStream'):
                            receiver.valid = False
                    continue
                if signature in {'setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V', 'addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V'} and len(args) == 2:
                    continue
                if signature == 'disconnect()V' and len(regs) == 1:
                    receiver.valid = False
                    continue
                # setDoOutput and unknown options may change effective request semantics.
                receiver.valid = False
                gap('httpurlconnection', 'UNSUPPORTED_CONNECTION_OPERATION', number)
                continue
            if owner in HTTP or owner == CONNECTION:
                gap('httpurlconnection', 'CONNECTION_IDENTITY_UNRESOLVED', number)
            elif owner in VOLLEY or owner == QUEUE:
                gap('volley', 'REQUEST_OR_QUEUE_IDENTITY_UNRESOLVED', number)
            invalidate([registers.get(r) for r in regs], 'ESCAPED_TO_UNSUPPORTED_CALL', number)
            continue
        if line.startswith(('invoke-', 'iput', 'sput', 'aput', 'monitor-')):
            invalidate(registers.values(), 'UNSUPPORTED_FIELD_OR_INVOKE_FLOW', number)
            continue
        match = re.match(r'^[a-z][\w/-]*\s+([vp]\d+)(?:,|$)', line)
        if match: registers.pop(match[1], None)
    return rows, gaps


def extract_volley_urlconnection(analysis_root):
    root = Path(analysis_root)
    if not root.is_dir(): raise FileNotFoundError('Analysis root unavailable')
    rows, gaps, skipped, used = [], [], [], 0
    for index, path in enumerate(sorted(root.rglob('*.smali'))):
        source = path.relative_to(root).as_posix()
        if index >= MAX_FILES or len(rows) >= MAX_RECORDS:
            skipped.append(dict(source_file=source, reason='scan_limit'))
            break
        try:
            size = path.stat().st_size
            if path.is_symlink() or size > MAX_FILE_BYTES or used + size > MAX_TOTAL_BYTES:
                skipped.append(dict(source_file=source, reason='source_or_size_boundary'))
                continue
            used += size
            text = path.read_text(encoding='utf-8')
            if '\x00' in text: raise ValueError('Binary smali')
        except (OSError, ValueError, UnicodeError):
            skipped.append(dict(source_file=source, reason='unreadable_source'))
            continue
        if 'Lcom/android/volley/' not in text and URL not in text and not any(t in text for t in HTTP): continue
        component, symbol, body = None, None, []
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if line.startswith('.class '): component = line.split()[-1]
            if line.startswith('.method '): symbol, body = line.split()[-1], []
            elif line == '.end method' and symbol:
                found, unresolved = _method(body, source, component, symbol)
                if len(rows) + len(found) > MAX_RECORDS or len(gaps) + len(unresolved) > MAX_RECORDS:
                    skipped.append(dict(source_file=source, reason='record_limit'))
                rows.extend(found[:MAX_RECORDS-len(rows)])
                gaps.extend(unresolved[:MAX_RECORDS-len(gaps)])
                symbol, body = None, []
            elif symbol is not None: body.append((number, line))
    diagnostics = {framework: dict(unresolved=[g for g in gaps if g['framework'] == framework],
                    coverage=dict(skipped=skipped, partial=bool(skipped or any(g['framework'] == framework for g in gaps))))
                   for framework in ('volley', 'httpurlconnection')}
    return dict(api_candidates=canonical_candidates(rows), discovery_diagnostics=diagnostics)
