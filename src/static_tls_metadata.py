"""Bounded TLS configuration evidence; never runtime enforcement or findings."""
from __future__ import annotations

import base64
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

NS = '{http://schemas.android.com/apk/res/android}'
PIN_BUILDER = 'Lokhttp3/CertificatePinner$Builder;'
PINNER = 'Lokhttp3/CertificatePinner;'
CLIENT_BUILDER = 'Lokhttp3/OkHttpClient$Builder;'
MAX_FILES = 30000
MAX_BYTES = 2_000_000
MAX_TOTAL = 256_000_000
MAX_RECORDS = 10000
CALL = re.compile(r'^invoke-(?:virtual|direct|static|interface)\s+\{([^}]*)\},\s*(L[^;]+;)->(\S+)$')


def _valid_pin(value, algorithm=None):
    if algorithm is None:
        algorithm, sep, value = value.partition('/')
        if not sep:
            return False
    sizes = {'SHA-256': 32, 'SHA-1': 20, 'sha256': 32, 'sha1': 20}
    try:
        return algorithm in sizes and len(base64.b64decode(value, validate=True)) == sizes[algorithm]
    except (ValueError, TypeError):
        return False


def _host(value):
    return bool(re.fullmatch(r'(?:\*\*?\.)?[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', value)) and all(
        label and len(label) <= 63 and not label.startswith('-') and not label.endswith('-')
        for label in value.removeprefix('**.').removeprefix('*.').split('.'))


def _record(kind, classification, source, locator, **details):
    row = {'kind': kind, 'classification': classification, 'source_file': source,
           'locator': locator, 'runtime_enforcement': 'not_established',
           'finding_created': False, **details}
    identity = json.dumps({k: v for k, v in row.items() if k not in {'assessed_on', 'expired'}}, sort_keys=True, separators=(',', ':'))
    row['evidence_id'] = 'tls_' + hashlib.sha256(identity.encode()).hexdigest()[:20]
    return row


def _nsc(root, manifest, as_of, gaps):
    rows = []
    try:
        app = ET.parse(manifest).getroot().find('application')
        ref = app.get(NS + 'networkSecurityConfig') if app is not None else None
        if not ref:
            return rows
        if not re.fullmatch(r'@xml/[A-Za-z0-9_]+', ref):
            gaps.append('NETWORK_CONFIG_REFERENCE_UNRESOLVED'); return rows
        path = root / 'res/xml' / (ref[5:] + '.xml')
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or path.stat().st_size > MAX_BYTES:
            gaps.append('NETWORK_CONFIG_SOURCE_BOUNDARY'); return rows
        cfg = ET.parse(path).getroot()
        if cfg.tag != 'network-security-config':
            raise ValueError('Invalid NSC')
    except (OSError, ET.ParseError, ValueError):
        gaps.append('NETWORK_CONFIG_UNAVAILABLE'); return rows
    source = path.relative_to(root).as_posix()
    manifest_source = Path(manifest).name
    def walk(node, locator, inherited_domains=(), debug=False, depth=0):
        if depth > 16 or len(rows) >= MAX_RECORDS:
            gaps.append('NETWORK_CONFIG_LIMIT'); return
        debug = debug or node.tag == 'debug-overrides'
        domains = tuple(sorted((n.text or '').strip() for n in node.findall('domain'))) or inherited_domains
        common = {'domains': list(domains), 'debug_only': debug,
                  'manifest_ref': {'source_file': manifest_source, 'attribute': 'android:networkSecurityConfig', 'value': ref},
                  'debuggable': app.get(NS + 'debuggable') == 'true'}
        if node.tag == 'pin-set':
            pins = [{'digest': p.get('digest'), 'hash': (p.text or '').strip(),
                     'valid': p.get('digest') == 'SHA-256' and _valid_pin((p.text or '').strip(), p.get('digest'))} for p in node.findall('pin')]
            expiration = node.get('expiration'); expiry = None; valid_expiry = True
            if expiration:
                try: expiry = date.fromisoformat(expiration)
                except ValueError: valid_expiry = False
            valid = bool(pins) and all(p['valid'] for p in pins) and valid_expiry and bool(domains) and all(_host(d) and '*' not in d for d in domains)
            rows.append(_record('network_security_pin_set', 'PROVEN_STATIC_PINNING_CONFIG' if valid else 'POSSIBLE_PINNING',
                                source, locator, **common, pins=pins, expiration=expiration,
                                expiration_valid=valid_expiry, expired=(expiry < as_of if expiry else None),
                                assessed_on=as_of.isoformat(), configuration_valid=valid,
                                scope_include_subdomains=scope_flags.get(domains, {})))
        if node.tag == 'certificates':
            rows.append(_record('trust_anchor', 'TLS_CUSTOMIZATION', source, locator, **common,
                                certificate_source=node.get('src'), override_pins=node.get('overridePins', 'true' if debug else 'false')))
        if node.tag == 'debug-overrides':
            rows.append(_record('debug_overrides', 'TLS_CUSTOMIZATION', source, locator, **common))
        for index, child in enumerate(node):
            walk(child, f'{locator}/{child.tag}[{index + 1}]', domains, debug, depth+1)
    scope_flags = {}
    for node in cfg.iter('domain-config'):
        ds = tuple(sorted((d.text or '').strip() for d in node.findall('domain')))
        scope_flags[ds] = {(d.text or '').strip(): d.get('includeSubdomains') == 'true' for d in node.findall('domain')}
    walk(cfg, '/network-security-config')
    return rows


def _smali_method(lines, source, component, symbol):
    """Resolve only straight-line literal pins, with receiver/array identity isolation."""
    rows = []
    relevant = any((call := CALL.match(line)) and ((call[2] == PIN_BUILDER and call[3].startswith('add(')) or (call[2] == CLIENT_BUILDER and call[3].startswith('certificatePinner('))) for _, line in lines)
    unsafe = len(lines) > 4096 or any(re.match(r'^(?:if-|goto|packed-switch|sparse-switch|:|\.catch)', line) for _, line in lines)
    registers, pending = {}, None
    for number, line in lines:
        call = CALL.match(line)
        if call:
            args = [a.strip() for a in call[1].split(',') if a.strip()]
            owner, method = call[2], call[3]
            if owner == 'Ljavax/net/ssl/SSLContext;' and method.startswith('init('):
                rows.append(_record('ssl_context_init', 'TLS_CUSTOMIZATION', source, f'line:{number}', source_component=component, source_method=symbol))
            if method.startswith(('setHostnameVerifier(', 'hostnameVerifier(', 'sslSocketFactory(')) and owner in {'Ljavax/net/ssl/HttpsURLConnection;', CLIENT_BUILDER}:
                rows.append(_record('tls_customization_call', 'TLS_CUSTOMIZATION', source, f'line:{number}', source_component=component, source_method=symbol, call=owner+'->'+method))
        if unsafe:
            continue
        if not line or line.startswith('.'):
            continue
        match = re.fullmatch(r'const-string(?:/jumbo)? ([vp]\d+), "([^"\\]*)"', line)
        if match:
            registers[match[1]] = match[2]; pending = None; continue
        match = re.fullmatch(r'const(?:/4|/16)? ([vp]\d+), (-?(?:0x[0-9a-fA-F]+|[0-9]+))', line)
        if match:
            registers[match[1]] = int(match[2], 16 if '0x' in match[2] else 10); pending = None; continue
        match = re.fullmatch(r'new-array ([vp]\d+), ([vp]\d+), \[Ljava/lang/String;', line)
        if match:
            length = registers.get(match[2])
            registers[match[1]] = [None] * length if isinstance(length, int) and 0 <= length <= 128 else None
            pending = None; continue
        match = re.fullmatch(r'aput-object ([vp]\d+), ([vp]\d+), ([vp]\d+)', line)
        if match:
            value, array, index = [registers.get(match[i]) for i in (1, 2, 3)]
            if isinstance(array, list) and isinstance(index, int) and 0 <= index < len(array):
                array[index] = value if isinstance(value, str) else None
            else:
                registers[match[2]] = None
            pending = None; continue
        match = re.fullmatch(r'new-instance ([vp]\d+), (L[^;]+;)', line)
        if match:
            value = {'type': match[2], 'initialized': False, 'pins': [], 'lines': [number]}
            registers[match[1]] = value
            pending = None; continue
        match = re.fullmatch(r'move-object(?:/from16|/16)? ([vp]\d+), ([vp]\d+)', line)
        if match:
            registers[match[1]] = registers.get(match[2]); pending = None; continue
        match = re.fullmatch(r'move-result-object ([vp]\d+)', line)
        if match:
            registers[match[1]] = pending; pending = None; continue
        match = re.fullmatch(r'filled-new-array \{([^}]*)\}, \[Ljava/lang/String;', line)
        if match:
            values = [registers.get(r.strip()) for r in match[1].split(',')]
            pending = values if all(isinstance(v, str) for v in values) else None; continue
        if call:
            args = [a.strip() for a in call[1].split(',') if a.strip()]
            values = [registers.get(a) for a in args]
            receiver = values[0] if values else None
            owner, method = call[2], call[3]; pending = None
            if owner in {PIN_BUILDER, CLIENT_BUILDER} and method == '<init>()V' and isinstance(receiver, dict) and receiver['type'] == owner:
                receiver['initialized'] = True
            elif owner == PIN_BUILDER and method == 'add(Ljava/lang/String;[Ljava/lang/String;)Lokhttp3/CertificatePinner$Builder;' and isinstance(receiver, dict) and receiver['type'] == owner and receiver['initialized'] and not receiver.get('invalid'):
                if len(values) == 3 and isinstance(values[1], str) and _host(values[1]) and isinstance(values[2], list) and values[2] and all(isinstance(p, str) and _valid_pin(p) for p in values[2]):
                    receiver['pins'].append({'host': values[1].lower(), 'hashes': sorted(set(values[2]))}); receiver['lines'].append(number)
                else: receiver['invalid'] = True
                pending = receiver
            elif owner == PIN_BUILDER and method == 'build()Lokhttp3/CertificatePinner;' and isinstance(receiver, dict) and receiver['type'] == owner and receiver['initialized'] and not receiver.get('invalid'):
                pending = {'type': PINNER, 'pins': list(receiver['pins']), 'lines': receiver['lines'] + [number]}
            elif owner == CLIENT_BUILDER and method == 'certificatePinner(Lokhttp3/CertificatePinner;)Lokhttp3/OkHttpClient$Builder;' and len(values) == 2 and isinstance(receiver, dict) and receiver['type'] == owner and receiver['initialized'] and not receiver.get('invalid') and isinstance(values[1], dict) and values[1]['type'] == PINNER and not values[1].get('invalid') and values[1]['pins']:
                receiver['bound'] = values[1]; pending = receiver
            elif owner == CLIENT_BUILDER and method == 'build()Lokhttp3/OkHttpClient;' and isinstance(receiver, dict) and receiver['type'] == owner and receiver.get('bound') and not receiver.get('invalid'):
                bound = receiver['bound']
                rows.append(_record('okhttp_pin_binding', 'PROVEN_STATIC_PINNING_CONFIG', source, f'line:{number}', source_component=component, source_method=symbol, bindings=bound['pins'], evidence_lines=sorted(set(bound['lines']+[number]))))
            else:
                # Unknown calls can mutate any passed object: fail closed for alias receivers.
                for value in values:
                    if isinstance(value, dict): value['invalid'] = True; value.pop('bound', None)
                    elif isinstance(value, list): value.clear()
            continue
        # Unhandled writes must never retain old register values.
        match = re.match(r'\S+\s+([vp]\d+)(?:,|$)', line)
        if match: registers.pop(match[1], None)
        pending = None
    if relevant and not any(r['classification'] == 'PROVEN_STATIC_PINNING_CONFIG' for r in rows):
        rows.append(_record('unresolved_pinner_flow', 'POSSIBLE_PINNING', source, f'method:{symbol}', source_component=component, source_method=symbol, reason='CONTROL_FLOW_OR_BINDING_UNRESOLVED'))
    return rows


def extract_static_tls_metadata(analysis_root, manifest_path=None, *, as_of=None):
    root = Path(analysis_root)
    if not root.is_dir(): raise FileNotFoundError('TLS analysis root unavailable')
    as_of = as_of or date.today()
    gaps = []; rows = _nsc(root, Path(manifest_path or root/'AndroidManifest.xml'), as_of, gaps)
    total = 0
    paths = sorted(p for p in root.rglob('*') if p.suffix.lower() in {'.smali', '.cer', '.crt', '.pem', '.der', '.pub', '.key'})
    for index, path in enumerate(paths):
        if index >= MAX_FILES or len(rows) >= MAX_RECORDS:
            gaps.append('SCAN_LIMIT'); break
        try:
            size = path.stat().st_size
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or size > MAX_BYTES or total+size > MAX_TOTAL:
                gaps.append('SOURCE_BOUNDARY'); continue
            total += size; source = path.relative_to(root).as_posix()
            if path.suffix.lower() == '.smali':
                text = path.read_text(); component = None; symbol = None; body = []; implementations = set()
                if not any(s in text for s in ('CertificatePinner', 'javax/net/ssl/')): continue
                for number, raw in enumerate(text.splitlines(), 1):
                    line = raw.strip()
                    if line.startswith('.class '): component = line.split()[-1]
                    elif line.startswith('.method '): symbol = line.split()[-1]; body = []
                    elif line == '.end method' and symbol:
                        rows.extend(_smali_method(body, source, component, symbol))
                        if any(line and not line.startswith(('.', ':', '#')) for _, line in body):
                            implementations.add(symbol.split('(')[0])
                        symbol = None
                    elif symbol: body.append((number, line))
                for interface, method in [('X509TrustManager', 'checkServerTrusted('), ('HostnameVerifier', 'verify(')]:
                    if f'.implements Ljavax/net/ssl/{interface};' in text and method.split('(')[0] in implementations:
                        rows.append(_record('custom_tls_implementation', 'TLS_CUSTOMIZATION', source, f'interface:{interface}', source_component=component, interface=interface))
            else:
                # Parse public material only; never serialize certificate contents/private keys.
                data = path.read_bytes()
                if b'PRIVATE KEY' in data: gaps.append('PRIVATE_KEY_MATERIAL_EXCLUDED'); continue
                try:
                    from cryptography import x509
                    from cryptography.exceptions import UnsupportedAlgorithm
                    from cryptography.hazmat.primitives import hashes, serialization
                    try: cert = x509.load_pem_x509_certificate(data) if b'BEGIN CERTIFICATE' in data else x509.load_der_x509_certificate(data)
                    except ValueError:
                        key = serialization.load_pem_public_key(data) if b'BEGIN PUBLIC KEY' in data or b'BEGIN RSA PUBLIC KEY' in data else serialization.load_der_public_key(data)
                        public = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                        rows.append(_record('bundled_public_key', 'TLS_CUSTOMIZATION', source, 'public-key', fingerprint_sha256=hashlib.sha256(public).hexdigest(), supporting_evidence_only=True)); continue
                    public = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                    rows.append(_record('bundled_certificate', 'TLS_CUSTOMIZATION', source, 'certificate', fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(), public_key_sha256=hashlib.sha256(public).hexdigest(), supporting_evidence_only=True))
                except ImportError: gaps.append('CERTIFICATE_PARSER_UNAVAILABLE')
                except (ValueError, TypeError, UnsupportedAlgorithm): gaps.append('CERTIFICATE_MATERIAL_UNRESOLVED')
        except (OSError, UnicodeError): gaps.append('UNREADABLE_SOURCE')
    if len(rows) > MAX_RECORDS: gaps.append('RECORD_LIMIT')
    rows = sorted({r['evidence_id']: r for r in rows}.values(), key=lambda r: (r['source_file'], r['locator'], r['evidence_id']))[:MAX_RECORDS]
    return {'schema_version': '1.0', 'evidence': rows, 'coverage': {'status': 'partial', 'limitations': sorted(set(gaps + ['Static configuration does not establish runtime TLS enforcement.', 'Indirect, obfuscated, native and branch-dependent pin bindings remain unresolved.']))}}
