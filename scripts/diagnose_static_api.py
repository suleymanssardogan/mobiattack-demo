"""Development-only bounded inventory; never creates production candidates or requests."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from src.api_candidate_extractor import extract_api_candidates
from src.network_indicator_extractor import extract_network_indicators, SUPPORTED_EXTENSIONS

URL = re.compile(r'https?://[^\s"\'<>\\]+')
DECLARATION = re.compile(r'(?:@(?:GET|POST|PUT|PATCH|DELETE)\("[^"\n]+"\)|\.annotation\s+runtime\s+Lretrofit2/http/(?:GET|POST|PUT|PATCH|DELETE);)')
CLIENT = re.compile(r'(?:Lretrofit2/Retrofit\$Builder;->baseUrl|Lokhttp3/Request\$Builder;->url|\.baseUrl\(|\.url\(|\.openConnection\(|->openConnection\()')
TEXT_EXTENSIONS = SUPPORTED_EXTENSIONS | {'.java', '.kt', '.bundle'}


def safe_url(value: str) -> str:
    """Drop credentials/query/fragment and anonymize hosts and paths, including secrets."""
    from hashlib import sha256
    try:
        url = urlsplit(value.rstrip('),;]}'))
        if url.scheme not in ('http', 'https') or not url.hostname:
            return '<redacted_url>'
        host = 'host_' + sha256(url.hostname.encode()).hexdigest()[:12] + '.invalid'
        # No raw path is exported: even a readable segment may contain a credential.
        path = '/path_' + sha256(url.path.encode()).hexdigest()[:12] if url.path else ''
        return url.scheme + '://' + host + path
    except ValueError:
        return '<redacted_url>'


def classify(value: str, line: str, source_kind: str) -> tuple[str, bool]:
    lowered = line.lower()
    if source_kind == 'native_library':
        return 'native_network_string', False
    if any(word in value.lower() for word in ('schemas.android', 'www.w3.org', 'privacy', 'license', 'github.com', 'youtrack.', '.png', '.jpg', '.svg')):
        return 'non_api_url', False
    if re.search(r'(?:api|endpoint|base_?url|server_?url)', lowered):
        return ('base_url' if 'baseurl' in lowered or 'base_url' in lowered else 'absolute_url'), True
    if CLIENT.search(line):
        return 'network_client_configuration', True
    if source_kind == 'resource':
        return 'resource_url', False
    if source_kind == 'manifest':
        return 'manifest_network_reference', False
    if source_kind == 'asset':
        return 'asset_configuration', False
    return 'unknown_network_indicator', False


def compare(*, source_scanned: bool, indicator_found: bool, candidate_found: bool,
            meaningful: bool, kind: str) -> str:
    if candidate_found:
        return 'RECOGNIZED_CANDIDATE'
    if not meaningful:
        return 'NON_API_OR_UNCLASSIFIED'
    if not source_scanned:
        return 'SOURCE_NOT_SCANNED'
    if kind == 'endpoint_annotation':
        return 'ANNOTATION_NOT_PARSED'
    if not indicator_found:
        return 'PATTERN_NOT_SUPPORTED'
    return 'PATTERN_NOT_SUPPORTED'


def inventory(app_id: str, workspace: Path, *, max_file_bytes: int = 2_000_000,
              max_total_bytes: int = 128_000_000) -> dict:
    """Exact occurrence comparison within a bounded inventory, not exhaustive APK truth."""
    roots = sorted(workspace.rglob('apktool_out'))
    found_indicators, found_candidates = set(), set()
    for root in roots:
        component = root.relative_to(workspace).as_posix()
        for items in extract_network_indicators(root).values():
            for item in items:
                found_indicators.add((component + '/' + item['source_file'], item['line_number'], item['value']))
        for item in extract_api_candidates(root)['api_candidates']:
            found_candidates.add((component + '/' + item['source_file'], item['evidence']['path_line'], item['path']))
    signals, inspected, skipped = [], Counter(), Counter()
    used = 0
    # Prefer canonical decoded files, then JADX; avoid raw/JADX duplicate resources.
    from src.manifest_parser import parse_manifest
    packages = []
    for root in roots:
        manifest = root / 'AndroidManifest.xml'
        if manifest.exists():
            package = parse_manifest(manifest)['package_name']
            if package:
                packages.append(package.replace('.', '/'))
    def priority(path):
        relative = path.relative_to(workspace).as_posix()
        owned = any('/' + package + '/' in relative for package in packages)
        return (0 if owned else 1, 0 if 'apktool_out' in path.parts else 1, relative)
    files = sorted((p for p in workspace.rglob('*') if p.is_file()), key=priority)
    for path in files:
        rel = path.relative_to(workspace).as_posix()
        if 'raw_apk' in path.parts or ('jadx_out' in path.parts and 'resources' in path.parts):
            continue
        native = path.suffix == '.so'
        if path.suffix.lower() not in TEXT_EXTENSIONS and not native:
            skipped['unsupported_extension'] += 1
            continue
        size = path.stat().st_size
        if size > max_file_bytes or used + size > max_total_bytes:
            skipped['size_budget'] += 1
            continue
        data = path.read_bytes(); used += size
        if native:
            text = '\n'.join(m.decode('ascii') for m in re.findall(rb'[\x20-\x7e]{8,}', data))
            kind = 'native_library'
        else:
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                skipped['binary_or_invalid_utf8'] += 1
                continue
            if '\x00' in text:
                skipped['binary_or_invalid_utf8'] += 1
                continue
            kind = ('jadx_source' if 'jadx_out' in path.parts else 'manifest' if path.name == 'AndroidManifest.xml'
                    else 'smali' if path.suffix == '.smali' else 'asset' if 'assets' in path.parts else 'resource')
        inspected[kind] += 1
        source_scanned = 'apktool_out' in path.parts and path.suffix.lower() in SUPPORTED_EXTENSIONS and not native
        for number, line in enumerate(text.splitlines(), 1):
            for match in URL.finditer(line):
                value = match.group().rstrip('),;]}')
                category, meaningful = classify(value, line, kind)
                indicator = (rel, number, value) in found_indicators
                candidate = (rel, number, value) in found_candidates
                signals.append(dict(signal_type=category, source_kind=kind, safe_value=safe_url(value),
                    source_ref=rel, line_number=None if native else number, source_scanned=source_scanned,
                    recognized_by_indicator_extractor=indicator, recognized_by_current_extractor=candidate,
                    api_relevance='explicit_static_context' if meaningful else 'unclassified_or_non_api',
                    reason=compare(source_scanned=source_scanned, indicator_found=indicator,
                                   candidate_found=candidate, meaningful=meaningful, kind=category)))
            for match in DECLARATION.finditer(line):
                signals.append(dict(signal_type='endpoint_annotation', source_kind=kind, safe_value='<endpoint_declaration>',
                    source_ref=rel,line_number=number,source_scanned=source_scanned,
                    recognized_by_indicator_extractor=False,recognized_by_current_extractor=False,
                    api_relevance='explicit_static_context',reason=compare(source_scanned=source_scanned,
                    indicator_found=False,candidate_found=False,meaningful=True,kind='endpoint_annotation')))
    signals.sort(key=lambda s:(s['source_ref'],s['line_number'] or 0,s['signal_type'],s['safe_value']))
    exported = sorted(signals, key=lambda s: (s['api_relevance'] != 'explicit_static_context', s['source_ref'], s['line_number'] or 0, s['signal_type'], s['safe_value']))[:512]
    return dict(app_id=app_id, scanned_sources=dict(sorted(inspected.items())), skipped_files=dict(sorted(skipped.items())),
        bytes_inspected=used, bounds=dict(max_file_bytes=max_file_bytes,max_total_bytes=max_total_bytes),
        inventory_occurrence_count=len(signals), meaningful_occurrence_count=sum(s['api_relevance']=='explicit_static_context' for s in signals),
        indicator_occurrence_count=sum(s['recognized_by_indicator_extractor'] for s in signals),
        candidate_count=len(found_candidates), categories=dict(sorted(Counter(s['signal_type'] for s in signals).items())),
        coverage=dict(sorted(Counter(s['reason'] for s in signals).items())),
        exported_signal_count=len(exported), signals_truncated=len(exported)<len(signals),signals=exported)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True);parser.add_argument('--app-id',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=inventory(args.app_id,args.workspace)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')

if __name__=='__main__':
    main()
