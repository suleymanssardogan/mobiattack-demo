"""OkHttp V1: bounded straight-line, same-method request construction evidence.

No heap/field/branch interpretation or arbitrary wrapper execution. A built request
is a static candidate, never proof of dispatch, runtime use or a vulnerability.
"""
from dataclasses import dataclass, field
from pathlib import Path
import re
import ipaddress
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit, unquote

BUILDER = 'Lokhttp3/Request$Builder;'
HTTP_URL = 'Lokhttp3/HttpUrl;'
JAVA_URL = 'Ljava/net/URL;'
METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}
MAX_FILES = 30000
MAX_FILE_BYTES = 2_000_000
MAX_TOTAL_BYTES = 256_000_000
MAX_METHOD_LINES = 4096
MAX_RECORDS = 10000
CALL = re.compile(r'^invoke-(virtual|direct|static|interface)\s+\{([^}]*)\},\s*(L[^;]+;)->(\S+)$')
STRING = re.compile(r'^const-string(?:/jumbo)?\s+([vp]\d+),\s*"([^"\\]*)"$')
MOVE = re.compile(r'^move-object(?:/from16|/16)?\s+([vp]\d+),\s*([vp]\d+)$')
NEW = re.compile(r'^new-instance\s+([vp]\d+),\s*(L[^;]+;)$')
RESULT = re.compile(r'^move-result-object\s+([vp]\d+)$')


@dataclass
class Literal:
    value: str
    line: int


@dataclass
class Url:
    value: str | None = None
    trace: list = field(default_factory=list)


@dataclass
class Builder:
    allocation: int
    initialized: bool = False
    valid: bool = True
    url: Url | None = None
    method: str | None = None
    method_line: int | None = None
    init_line: int | None = None


def _identity(value):
    try:
        if any(c.isspace() or ord(c) < 32 for c in value) or '\\' in value:
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
            return None
        port = parsed.port if parsed.port is not None else {'http': 80, 'https': 443}[parsed.scheme]
        if not 1 <= port <= 65535:
            return None
        host = parsed.hostname.lower()
        if ':' in host:
            ipaddress.IPv6Address(host)
        elif not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host) or any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-') for label in host.split('.')):
            return None
        if any(unquote(segment) in {'.', '..'} for segment in parsed.path.split('/')):
            return None
        # No malformed host/path normalization guesses or raw secret path segments.
        if re.search(r'/(?:token|password|secret|api[-_]?key|authorization)/[^/{]+', parsed.path, re.I):
            return None
        if len(parsed.query) > 8192:
            return None
        query = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=128)
        if any(not key or len(key) > 128 or any(ord(c) < 32 for c in key) for key, _ in query):
            return None
        keys = sorted({key for key, _ in query})
        shape = {key: {'count': sum(k == key for k, _ in query), 'value_present': any(bool(v) for k, v in query if k == key)} for key in keys}
        authority = '[' + host + ']' if ':' in host else host
        if port != {'http': 80, 'https': 443}[parsed.scheme]:
            authority += ':' + str(port)
        path = parsed.path or '/'
        return {'scheme': parsed.scheme, 'host': host, 'port': port, 'path': path,
                'base_url': urlunsplit((parsed.scheme, authority, '/', '', '')).rstrip('/'),
                'full_url': urlunsplit((parsed.scheme, authority, path, '', '')),
                'query_keys': keys, 'query_shape': shape}
    except (ValueError, TypeError):
        return None


def _method(lines, source, component, symbol):
    candidates, unresolved = [], []
    def gap(reason, line):
        if len(unresolved) < MAX_RECORDS:
            unresolved.append({'source_file': source, 'source_component': component, 'source_method': symbol,
                               'line': line, 'reason': reason, 'resolution_state': 'unresolved'})
    if not any(BUILDER in line for _, line in lines):
        return [], []
    if not component or not re.fullmatch(r'L[^;\s]+;', component):
        gap('SOURCE_COMPONENT_UNRESOLVED', lines[0][0] if lines else 0)
        return [], unresolved
    # Any control flow / exception edges in this method make local attribution unsupported.
    if len(lines) > MAX_METHOD_LINES or any(line.startswith(':') or re.match(r'(if-|goto|packed-switch|sparse-switch|\.catch)', line) for _, line in lines):
        gap('UNSUPPORTED_CONTROL_FLOW', lines[0][0] if lines else 0)
        return candidates, unresolved
    registers, pending = {}, None
    for number, line in lines:
        if not line or line.startswith(('#', '.')):
            continue
        match = RESULT.fullmatch(line)
        if match:
            registers.pop(match[1], None)
            if pending is not None:
                registers[match[1]] = pending
            pending = None
            continue
        pending = None
        if line.startswith(('return', 'throw')):
            break
        match = STRING.fullmatch(line)
        if match:
            registers[match[1]] = Literal(match[2], number)
            continue
        match = MOVE.fullmatch(line)
        if match:
            value = registers.get(match[2])
            registers.pop(match[1], None)
            if value is not None:
                registers[match[1]] = value
            continue
        match = NEW.fullmatch(line)
        if match:
            registers.pop(match[1], None)
            if match[2] == BUILDER:
                registers[match[1]] = Builder(number)
            elif match[2] == JAVA_URL:
                registers[match[1]] = Url()
            continue
        match = CALL.fullmatch(line)
        if match:
            mode, register_text, owner, signature = match.groups()
            regs = [r.strip() for r in register_text.split(',') if r.strip()]
            if not all(re.fullmatch(r'[vp]\d+', r) for r in regs):
                continue
            receiver = registers.get(regs[0]) if regs else None
            args = [registers.get(r) for r in regs[1:]]
            if owner == BUILDER and isinstance(receiver, Builder):
                if mode == 'direct' and signature == '<init>()V' and len(regs) == 1 and not receiver.initialized:
                    receiver.initialized = True
                    receiver.method, receiver.method_line, receiver.init_line = 'GET', number, number
                    continue
                if mode != 'virtual' or not receiver.initialized or not receiver.valid:
                    receiver.valid = False
                    gap('BUILDER_IDENTITY_UNRESOLVED', number)
                    continue
                if signature in {'url(Ljava/lang/String;)' + BUILDER, 'url(' + HTTP_URL + ')' + BUILDER, 'url(' + JAVA_URL + ')' + BUILDER} and len(args) == 1:
                    value = args[0]
                    if isinstance(value, Literal) and signature.startswith('url(Ljava/lang/String;)'):
                        receiver.url = Url(value.value, [{'line': value.line, 'kind': 'url_literal'}, {'line': number, 'kind': 'builder_url'}]) if _identity(value.value) else None
                    elif isinstance(value, Url) and value.value and not signature.startswith('url(Ljava/lang/String;)'):
                        receiver.url = Url(value.value, value.trace + [{'line': number, 'kind': 'builder_url'}])
                    else:
                        receiver.url = None
                    pending = receiver
                    continue
                simple = {'get()': 'GET', 'head()': 'HEAD', 'delete()': 'DELETE', 'delete(Lokhttp3/RequestBody;)': 'DELETE',
                          'post(Lokhttp3/RequestBody;)': 'POST', 'put(Lokhttp3/RequestBody;)': 'PUT', 'patch(Lokhttp3/RequestBody;)': 'PATCH'}
                key = signature.removesuffix(BUILDER)
                if signature.endswith(BUILDER) and key in simple and len(regs) == (1 if key.endswith('()') else 2):
                    receiver.method, receiver.method_line = simple[key], number
                    pending = receiver
                    continue
                if signature == 'method(Ljava/lang/String;Lokhttp3/RequestBody;)' + BUILDER and len(args) == 2:
                    receiver.method = args[0].value if isinstance(args[0], Literal) and args[0].value in METHODS else None
                    receiver.method_line = number
                    pending = receiver
                    continue
                if signature == 'build()Lokhttp3/Request;' and len(regs) == 1:
                    identity = _identity(receiver.url.value) if receiver.url else None
                    if identity and receiver.method:
                        evidence = {'source_method': symbol, 'builder_allocation_line': receiver.allocation,
                                    'builder_init_line': receiver.init_line, 'method_line': receiver.method_line,
                                    'method_origin': 'constructor_default_GET' if receiver.method_line == receiver.init_line else 'explicit_method_call',
                                    'request_call_line': number, 'url_trace': receiver.url.trace,
                                    'query_values_removed': bool(identity['query_keys']), 'dispatch_observed': False}
                        candidates.append(dict(identity, method=receiver.method, framework='okhttp', source_file=source,
                            source_component=component, request_line=number, evidence=evidence,
                            status='static_api_candidate', resolution_state='resolved'))
                    else:
                        gap('REQUEST_URL_OR_METHOD_UNRESOLVED', number)
                    continue
                # Explicitly allowed metadata calls cannot change URL or method.
                if signature in {'header(Ljava/lang/String;Ljava/lang/String;)' + BUILDER, 'addHeader(Ljava/lang/String;Ljava/lang/String;)' + BUILDER, 'removeHeader(Ljava/lang/String;)' + BUILDER} and len(args) == (1 if signature.startswith('removeHeader') else 2):
                    pending = receiver
                    continue
                receiver.valid = False
                gap('UNSUPPORTED_BUILDER_OPERATION', number)
                continue
            if owner == HTTP_URL and mode == 'static' and signature in {'parse(Ljava/lang/String;)' + HTTP_URL, 'get(Ljava/lang/String;)' + HTTP_URL} and len(regs) == 1:
                value = registers.get(regs[0])
                if isinstance(value, Literal) and _identity(value.value):
                    pending = Url(value.value, [{'line': value.line, 'kind': 'url_literal'}, {'line': number, 'kind': 'http_url_parse'}])
                continue
            if owner == JAVA_URL and mode == 'direct' and signature == '<init>(Ljava/lang/String;)V' and isinstance(receiver, Url) and len(args) == 1:
                value = args[0]
                if isinstance(value, Literal) and _identity(value.value):
                    receiver.value = value.value
                    receiver.trace = [{'line': value.line, 'kind': 'url_literal'}, {'line': number, 'kind': 'java_url_init'}]
                continue
            if owner == HTTP_URL and mode == 'virtual' and signature == 'resolve(Ljava/lang/String;)' + HTTP_URL and isinstance(receiver, Url) and len(args) == 1 and isinstance(args[0], Literal):
                relative = args[0]
                try:
                    parsed = urlsplit(relative.value)
                except ValueError:
                    continue
                if receiver.value and relative.value and not parsed.scheme and not parsed.netloc and not parsed.fragment and not relative.value.startswith('//') and not any(p in {'.', '..'} for p in parsed.path.split('/')):
                    joined = urljoin(receiver.value, relative.value)
                    if _identity(joined) and urlsplit(joined).netloc == urlsplit(receiver.value).netloc:
                        pending = Url(joined, receiver.trace + [{'line': relative.line, 'kind': 'relative_path_literal'}, {'line': number, 'kind': 'http_url_resolve'}])
                continue
            # A builder escaping through unknown code can be mutated through an alias.
            for reg in regs:
                value = registers.get(reg)
                if isinstance(value, Builder):
                    value.valid = False
                    gap('BUILDER_ESCAPED_TO_UNSUPPORTED_CALL', number)
            continue
        if line.startswith('invoke-'):
            # Unsupported invoke/range cannot safely preserve any mutable receiver.
            for value in registers.values():
                if isinstance(value, Builder):
                    value.valid = False
            gap('UNSUPPORTED_INVOKE_FORM', number)
            continue
        match = re.match(r'^[a-z][\w/-]*\s+([vp]\d+)(?:,|$)', line)
        if match and not line.startswith(('iput', 'sput', 'aput', 'monitor-')):
            registers.pop(match[1], None)
        if line.startswith(('iput', 'sput', 'aput', 'monitor-')):
            for value in registers.values():
                if isinstance(value, Builder):
                    value.valid = False
            gap('UNSUPPORTED_FIELD_OR_ARRAY_FLOW', number)
    return candidates, unresolved


def extract_okhttp(analysis_root):
    root = Path(analysis_root)
    if not root.is_dir():
        raise FileNotFoundError('OkHttp analysis root unavailable')
    candidates, unresolved, skipped = [], [], []
    used = 0
    files = sorted(root.rglob('*.smali'))
    for index, path in enumerate(files):
        source = path.relative_to(root).as_posix()
        if index >= MAX_FILES or len(candidates) >= MAX_RECORDS:
            skipped.append({'source_file': source, 'reason': 'scan_limit'})
            break
        try:
            size = path.stat().st_size
            if path.is_symlink() or size > MAX_FILE_BYTES or used + size > MAX_TOTAL_BYTES:
                skipped.append({'source_file': source, 'reason': 'source_or_size_boundary'})
                continue
            used += size
            text = path.read_text(encoding='utf-8')
            if '\x00' in text:
                raise ValueError('Binary smali')
        except (OSError, UnicodeError, ValueError):
            skipped.append({'source_file': source, 'reason': 'unreadable_source'})
            continue
        if BUILDER not in text:
            continue
        component, symbol, body = None, None, []
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if line.startswith('.class '):
                component = line.split()[-1]
            if line.startswith('.method '):
                symbol, body = line.split()[-1], []
            elif line == '.end method' and symbol:
                found, gaps = _method(body, source, component, symbol)
                candidates.extend(found[:MAX_RECORDS-len(candidates)])
                unresolved.extend(gaps[:MAX_RECORDS-len(unresolved)])
                symbol, body = None, []
            elif symbol is not None:
                body.append((number, line))
    from src.android_identity import canonical_candidates
    return {'api_candidates': canonical_candidates(candidates), 'unresolved': unresolved,
            'coverage': {'skipped': skipped, 'partial': bool(skipped or unresolved)}}
