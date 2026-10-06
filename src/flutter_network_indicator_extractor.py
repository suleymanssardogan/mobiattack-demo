"""Bounded Flutter string inventory. String presence is never request-use evidence."""
from dataclasses import dataclass
import os
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from src.network_indicator_extractor import (DOMAIN_RE, COMMON_FILE_EXTENSIONS,
    CODE_SUFFIXES_TO_IGNORE, PACKAGE_PREFIXES_TO_IGNORE, CODE_PREFIXES_TO_IGNORE,
    SCHEMA_PREFIXES_TO_IGNORE, _clean_trailing_punctuation)
from src.ios.ios_network_indicator_extractor import is_valid_domain
from src.static_inventory import indicator_context

COVERAGE_NOTE = ('Flutter network strings are indicators only; Dart request-use, HTTP methods, '
                 'dynamic URL construction and compressed/UTF-16 strings are not resolved.')
FLUTTER_URL_RE = re.compile(r'\bhttps?://[^\s"\'<>]+')
TEXT_EXTENSIONS = {'.json', '.txt', '.xml', '.yaml', '.yml', '.ini', '.conf', '.properties', '.html', '.js', '.md', '.csv'}
SECRET_ASSIGNMENT = re.compile(r'(?i)(?:^\s*(?:export\s+)?|[,\{]\s*)["\']?(?:password|passwd|secret|token|access_token|refresh_token|api_key|authorization|cookie|jwt)["\']?\s*[:=]')

@dataclass(frozen=True)
class FlutterInventoryLimits:
    max_files: int = 256
    max_entries: int = 4096
    max_text_bytes: int = 1024 * 1024
    max_native_bytes: int = 32 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_strings: int = 100000
    max_string_bytes: int = 8192
    max_indicators: int = 2000
    max_occurrences: int = 8000

    def __post_init__(self):
        if any(isinstance(v, bool) or not isinstance(v, int) or v <= 0 for v in vars(self).values()):
            raise ValueError('Flutter inventory limits must be positive integers')


def is_flutter_asset(path):
    return path.as_posix().startswith('assets/flutter_assets/')


def is_safe_asset(path):
    return is_flutter_asset(path) and (path.name == '.env' or path.suffix.lower() in TEXT_EXTENSIONS)


def _safe_url(value):
    try:
        parsed = urlsplit(_clean_trailing_punctuation(value))
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
            return None
        host = parsed.hostname.lower()
        # URL credentials and fragments are discarded; every query value is redacted.
        port = parsed.port
        authority = host + (f':{port}' if port else '')
        keys = sorted({k for k, _ in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=128)})
        if any(not re.fullmatch(r'[A-Za-z0-9_.\[\]-]{1,128}', key) for key in keys):
            return None
        query = urlencode([(key, '[REDACTED]') for key in keys])
        return urlunsplit((parsed.scheme, authority, parsed.path or '/', query, '')), keys
    except ValueError:
        return None


def extract_flutter_network_indicators(analysis_root, *, limits=None):
    root = Path(analysis_root)
    if not root.is_dir():
        raise NotADirectoryError(str(root))
    limits = limits or FlutterInventoryLimits()
    reasons = set(); files = []; visited = 0; detected = False
    # Restrict traversal to Flutter assets and native library directories; never follow symlinks.
    for folder in (root/'assets/flutter_assets', root/'lib'):
        if reasons & {'ENTRY_LIMIT', 'FILE_LIMIT'}: break
        if not folder.is_dir() or folder.is_symlink() or not folder.resolve().is_relative_to(root.resolve()):
            continue
        if folder.name == 'flutter_assets': detected = True
        for current, dirs, names in os.walk(folder, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not (Path(current)/d).is_symlink())
            visited += len(dirs) + len(names)
            if visited > limits.max_entries:
                reasons.add('ENTRY_LIMIT'); break
            for name in sorted(names):
                path = Path(current)/name
                if path.is_symlink(): continue
                relative = path.relative_to(root)
                if name == 'libflutter.so': detected = True
                if is_safe_asset(relative) or (relative.parts[0] == 'lib' and name == 'libapp.so'):
                    if len(files) >= limits.max_files:
                        reasons.add('FILE_LIMIT'); break
                    files.append(path)
            if 'FILE_LIMIT' in reasons: break
    if not detected:
        files = []  # A libapp.so filename alone does not prove Flutter embedding.
    records = {}; total_bytes = 0; strings_seen = 0; scanned = 0; occurrences = 0
    for path in sorted(files):
        relative = path.relative_to(root).as_posix(); binary = path.name == 'libapp.so'
        try:
            size = path.stat().st_size
            if size > (limits.max_native_bytes if binary else limits.max_text_bytes):
                reasons.add('FILE_SIZE_LIMIT'); continue
            if total_bytes + size > limits.max_total_bytes:
                reasons.add('TOTAL_BYTE_LIMIT'); break
            with path.open('rb') as stream:
                data = stream.read(size + 1)
            if len(data) != size:
                reasons.add('FILE_CHANGED'); continue
            total_bytes += size
            if binary:
                if not data.startswith(b'\x7fELF'):
                    reasons.add('INVALID_ELF'); continue
                chunks = ((m.group(), m.start(), None) for m in re.finditer(rb'[\x20-\x7e]{4,}', data))
            else:
                data.decode('utf-8', errors='strict')
                def lines():
                    offset = 0
                    for number, line in enumerate(data.splitlines(keepends=True), 1):
                        yield line, offset, number
                        offset += len(line)
                chunks = lines()
            scanned += 1
            for chunk, offset, line_number in chunks:
                strings_seen += 1
                if strings_seen > limits.max_strings:
                    reasons.add('STRING_LIMIT'); break
                if len(chunk) > limits.max_string_bytes:
                    reasons.add('STRING_SIZE_LIMIT'); continue
                text = chunk.decode('ascii' if binary else 'utf-8')
                if path.name == '.env':
                    assignment = re.match(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=', text)
                    if not assignment or not re.search(r'(?:URL|URI|HOST|DOMAIN|ENDPOINT)', assignment[1], re.I):
                        continue
                    if re.search(r'(?:TOKEN|SECRET|PASSWORD|KEY|COOKIE|AUTHORIZATION)', assignment[1], re.I):
                        continue
                if SECRET_ASSIGNMENT.search(text): continue
                matches = list(FLUTTER_URL_RE.finditer(text)); items = []
                for match in matches:
                    if match.end() < len(text) and text[match.end()] in ':@': continue
                    if any(match.group().startswith(p) for p in SCHEMA_PREFIXES_TO_IGNORE): continue
                    safe = _safe_url(match.group())
                    if safe: items.append(('network_url', safe[0], safe[1], match.start()))
                for match in DOMAIN_RE.finditer(text):
                    domain = match.group().lower()
                    if any(a.start() <= match.start() < a.end() for a in matches): continue
                    if not is_valid_domain(domain) or domain.split('.')[-1] in COMMON_FILE_EXTENSIONS | CODE_SUFFIXES_TO_IGNORE: continue
                    if domain.startswith(PACKAGE_PREFIXES_TO_IGNORE + CODE_PREFIXES_TO_IGNORE + ('io.flutter.', 'package.', 'dart.')): continue
                    if match.start() and text[match.start()-1] in '._abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789': continue
                    if match.end() < len(text) and text[match.end()] in '._abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789': continue
                    items.append(('domain', domain, [], match.start()))
                for kind, value, keys, position in items:
                    if occurrences >= limits.max_occurrences:
                        reasons.add('OCCURRENCE_LIMIT'); break
                    occurrences += 1
                    identity = (kind, value, relative)
                    if identity not in records:
                        if len(records) >= limits.max_indicators:
                            reasons.add('INDICATOR_LIMIT'); break
                        records[identity] = {'type':kind, 'value':value, 'source_file':relative,
                            'line_number':line_number, 'byte_offset':offset+len(text[:position].encode('ascii' if binary else 'utf-8')),
                            'byte_offsets':[], 'query_keys':keys, 'framework':'flutter',
                            'extraction_method':'native_ascii_strings' if binary else 'flutter_text_asset',
                            'inventory_context':indicator_context(value, relative), 'backend_confirmed':False,
                            'evidence_kind':'static_string_indicator'}
                    row = records[identity]
                    row['byte_offsets'].append(offset+len(text[:position].encode('ascii' if binary else 'utf-8')))
                if reasons & {'INDICATOR_LIMIT','OCCURRENCE_LIMIT'}: break
            if reasons & {'STRING_LIMIT','INDICATOR_LIMIT','OCCURRENCE_LIMIT'}: break
        except (OSError, UnicodeDecodeError):
            reasons.add('UNREADABLE_OR_NON_UTF8')
    for row in records.values(): row['byte_offsets'] = sorted(set(row['byte_offsets']))
    rows = sorted(records.values(), key=lambda r:(r['type'],r['value'],r['source_file']))
    return {'network_urls':[r for r in rows if r['type']=='network_url'],
            'domains':[r for r in rows if r['type']=='domain'],
            'coverage':{'detected':detected or bool(files), 'files_scanned':scanned,
                        'bytes_scanned':total_bytes, 'indicator_count':len(rows),
                        'status':'partial', 'limit_reasons':sorted(reasons), 'note':COVERAGE_NOTE}}
