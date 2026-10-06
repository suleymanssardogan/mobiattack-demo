"""Provenance-based inventory classification; does not discover endpoints."""
import re
from pathlib import PurePosixPath
from urllib.parse import urlsplit


def is_configuration_identifier(value, source_file, line):
    if not re.fullmatch(r'config\.[a-zA-Z0-9_]+', value):
        return False
    source = str(source_file).replace('\\', '/')
    if source.endswith('.xml'):
        return bool(re.search(r'\bsplit\s*=\s*[\"\']'+re.escape(value)+r'[\"\']', line))
    if source.endswith(('apktool.yml', 'apktool.yaml')):
        return bool(re.search(r'\b(?:apkFileName|split)\s*:\s*(?:split_)?'+re.escape(value)+r'(?:\.apk)?\b', line))
    return False


def indicator_context(value, source_file=''):
    try:
        parsed=urlsplit(value if '://' in value else '//'+value)
        host=(parsed.hostname or '').lower();path=parsed.path.lower()
    except ValueError:
        return 'unconfirmed_network_indicator'
    name=PurePosixPath(str(source_file).lower()).name
    if name.startswith(('license','notice','readme')):
        return 'documentation_or_license'
    if host in {'developer.android.com','docs.flutter.dev','api.flutter.dev','flutter.dev','dart.dev'}:
        return 'framework_documentation'
    if host=='pub.dev':
        return 'framework_package_repository'
    if host=='github.com' and ('/issues/' in path or '/flutter/' in path):
        return 'framework_repository_or_issue_tracker'
    if value=='io.flutter.network' and str(source_file).endswith('.smali'):
        return 'framework_metadata'
    return 'unconfirmed_network_indicator'


def runtime_technologies(structure):
    """Embedding files prove technology presence, not backend or networking usage."""
    evidence=[]
    for component in [structure, *(structure.get('components') or [])]:
        for path in component.get('assets') or []:
            if path.startswith('assets/flutter_assets/'):
                evidence.append({'source_file':path,'source_apk':component.get('source_apk')})
        for path in component.get('native_libraries') or []:
            if PurePosixPath(path).name=='libflutter.so':
                evidence.append({'source_file':path,'source_apk':component.get('source_apk')})
    evidence=sorted({(r['source_file'],r['source_apk'] or '') for r in evidence})
    return [{'name':'Flutter','status':'detected','evidence':[{'source_file':p,**({'source_apk':a} if a else {})} for p,a in evidence]}] if evidence else []


FLUTTER_COVERAGE = 'Flutter/Dart request-use is not resolved; extracted network strings are indicators, not API endpoints.'
