"""Bounded WebView call evidence, isolated from findings and runtime claims."""
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit, parse_qsl
import xml.etree.ElementTree as ET

WEB = 'Landroid/webkit/WebView;'
SETTINGS = 'Landroid/webkit/WebSettings;'
CLIENT = 'Landroid/webkit/WebViewClient;'
CHROME = 'Landroid/webkit/WebChromeClient;'
SSL = 'Landroid/webkit/SslErrorHandler;'
FLAGS = {'setJavaScriptEnabled', 'setAllowFileAccess', 'setAllowContentAccess',
         'setAllowFileAccessFromFileURLs', 'setAllowUniversalAccessFromFileURLs', 'setMixedContentMode'}
CALL = re.compile(r'^invoke-(virtual|direct|static|interface)\s+\{([^}]*)\},\s*(L[^;]+;)->(\S+)$')
MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_ROWS = 30000, 2_000_000, 256_000_000, 10000


@dataclass
class Ref:
    type: str
    identity: str
    source_line: int
    web: object = None
    valid: bool = True
    initialized: bool = False


@dataclass
class Unit:
    source: str
    component: str
    parent: str
    methods: list = field(default_factory=list)


def _record(unit, method, line, kind, tier='configuration_metadata', web=None, **data):
    row = {'kind': kind, 'evidence_tier': tier, 'source_file': unit.source,
           'source_component': unit.component, 'source_method': method, 'line_number': line,
           'webview_instance_id': web.identity if isinstance(web, Ref) and web.valid else None,
           'runtime_confirmed': False, 'finding_created': False, **data}
    row['evidence_id'] = 'webview_' + hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()[:20]
    return row


def _types(signature):
    return re.findall(r'\[*L[^;]+;|\[*[ZBCSIJFD]', signature.split('(', 1)[1].split(')', 1)[0])


def _parameters(unit, symbol, static):
    regs = {}; index = 0 if static else 1
    if not static: regs['p0'] = Ref(unit.component, f'{unit.source}:{symbol}:this', 0)
    for typ in _types(symbol):
        regs[f'p{index}'] = Ref(typ, f'{unit.source}:{symbol}:p{index}', 0)
        index += 2 if typ in {'J', 'D'} else 1
    return regs


def _url(value):
    if not isinstance(value, str): return {'resolution_state': 'unresolved'}
    try:
        u = urlsplit(value)
        # No arbitrary literal bodies, JS payloads, userinfo, query values or fragments.
        kind = ('local_asset' if value.startswith('file:///android_asset/') else
                'local_file' if u.scheme == 'file' else 'network' if u.scheme in {'http', 'https'} else 'other_scheme')
        return {'resolution_state': 'literal', 'scheme': u.scheme or None, 'host': u.hostname,
                'url_kind': kind, 'query_keys': sorted({k for k, _ in parse_qsl(u.query, max_num_fields=128)})}
    except ValueError: return {'resolution_state': 'unresolved'}


def _analyze(unit, symbol, static, body, subtype, app_components, ssl_behaviors):
    rows = []; regs = _parameters(unit, symbol, static); pending = None
    if len(body) > 4096:
        return [_record(unit, symbol, body[0][0], 'unsupported_method', reason='METHOD_LIMIT')]
    callback = symbol == 'onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V' and subtype(unit.component, CLIENT) and not static
    straight = not any(re.match(r'^(if-|goto|:|packed-switch|sparse-switch|\.catch)', line) for _, line in body)
    callback_calls = [line for _, line in body if line.startswith('invoke-')]
    straight = straight and all((call := CALL.match(line)) and (call[3] == SSL or (call[3] == 'Lkotlin/jvm/internal/Intrinsics;' and call[4].startswith('check'))) for line in callback_calls)
    expected_handler = f'{unit.source}:{symbol}:p2'
    terminated = False
    for number, line in body:
        if line.startswith(('return-', 'throw ')):
            terminated = True; pending = None; continue
        if re.match(r'^(if-|goto|:|packed-switch|sparse-switch|\.catch)', line):
            regs = _parameters(unit, symbol, static); pending = None
            if line.startswith(':'): terminated = False
            continue
        if terminated: continue
        if not line or line.startswith(('.', '#')): continue
        m = re.fullmatch(r'move-result-object ([vp]\d+)', line)
        if m: regs[m[1]] = pending; pending = None; continue
        pending = None
        m = re.fullmatch(r'const(?:/4|/16)? ([vp]\d+), (-?(?:0x[\da-fA-F]+|\d+))', line)
        if m: regs[m[1]] = int(m[2], 16 if '0x' in m[2] else 10); continue
        m = re.fullmatch(r'const-string(?:/jumbo)? ([vp]\d+), "([^"\\]*)"', line)
        if m: regs[m[1]] = m[2]; continue
        m = re.fullmatch(r'move-object(?:/from16|/16)? ([vp]\d+), ([vp]\d+)', line)
        if m: regs[m[1]] = regs.get(m[2]); continue
        m = re.fullmatch(r'new-instance ([vp]\d+), (L[^;]+;)', line)
        if m:
            regs[m[1]] = Ref(m[2], f'{unit.source}:{symbol}:allocation:{number}', number)
            if subtype(m[2], WEB): rows.append(_record(unit, symbol, number, 'webview_allocation', web=regs[m[1]]))
            continue
        m = re.fullmatch(r'check-cast ([vp]\d+), (L[^;]+;)', line)
        if m:
            old = regs.get(m[1]); identity = old.identity if isinstance(old, Ref) else f'{unit.source}:{symbol}:cast:{number}'
            regs[m[1]] = Ref(m[2], identity, number); continue
        call = CALL.match(line)
        if call:
            args = [a.strip() for a in call[2].split(',') if a.strip()]
            values = [regs.get(a) for a in args]; receiver = values[0] if values else None
            owner, sig = call[3], call[4]; name = sig.split('(')[0]
            web = receiver if isinstance(receiver, Ref) and receiver.valid and subtype(receiver.type, WEB) else None
            settings = receiver if isinstance(receiver, Ref) and receiver.valid and receiver.type == SETTINGS else None
            if name == 'getSettings' and sig == 'getSettings()Landroid/webkit/WebSettings;' and subtype(owner, WEB):
                pending = Ref(SETTINGS, f'{unit.source}:{symbol}:settings:{number}', number, web=web)
                rows.append(_record(unit, symbol, number, 'webview_settings', web=web, receiver_resolved=web is not None))
            elif owner == SETTINGS and name in FLAGS:
                value = values[1] if len(values) == 2 and isinstance(values[1], int) else None
                if name != 'setMixedContentMode' and value not in {0, 1}: value = None
                if name == 'setMixedContentMode' and value not in {0, 1, 2}: value = None
                risky = (name in {'setAllowUniversalAccessFromFileURLs','setAllowFileAccessFromFileURLs'} and value == 1) or (name == 'setMixedContentMode' and value == 0)
                rows.append(_record(unit, symbol, number, 'webview_setting', 'risky_indicator' if risky else 'configuration_metadata', web=settings.web if settings else None,
                                    setting=name, value=value, settings_source_line=settings.source_line if settings else None))
            elif subtype(owner, WEB) and name in {'loadUrl','addJavascriptInterface','setWebViewClient','setWebChromeClient'}:
                kind = {'loadUrl':'url_loading','addJavascriptInterface':'javascript_interface','setWebViewClient':'webview_client','setWebChromeClient':'webchrome_client'}[name]
                details = {}
                if name == 'loadUrl': details = _url(values[1] if len(values) >= 2 else None)
                elif name == 'addJavascriptInterface':
                    details = {'interface_type': values[1].type if len(values)>1 and isinstance(values[1], Ref) else None,
                               'interface_name_resolved': len(values)>2 and isinstance(values[2],str)}
                else:
                    target = values[1] if len(values)>1 and isinstance(values[1], Ref) and values[1].valid and values[1].initialized else None
                    details = {'client_type': target.type if target else None, 'client_source_line': target.source_line if target else None}
                    behavior = ssl_behaviors.get(target.type) if target and name == 'setWebViewClient' else None
                    if behavior:
                        app_linked = unit.component in app_components and web is not None and target.source_line>0
                        tier = 'finding_eligible_evidence' if behavior['unconditional_proceed'] and app_linked else 'risky_indicator' if behavior['proceed'] else 'configuration_metadata'
                        rows.append(_record(unit, symbol, number, 'linked_ssl_error_behavior', tier, web=web,
                                            client_type=target.type, app_linked=app_linked, callback_evidence_refs=behavior['refs'],
                                            behavior='proceed' if behavior['proceed'] else 'cancel', eligibility_reason='LINKED_UNCONDITIONAL_SSL_ERROR_PROCEED' if tier=='finding_eligible_evidence' else 'CALLBACK_CONTEXT_ONLY'))
                rows.append(_record(unit, symbol, number, kind, web=web, **details))
            elif callback and owner == SSL and name in {'proceed','cancel'}:
                handler_match = isinstance(receiver,Ref) and receiver.identity==expected_handler and receiver.valid
                rows.append(_record(unit, symbol, number, 'ssl_error_callback', 'risky_indicator' if name=='proceed' else 'configuration_metadata', web=regs.get('p1'),
                                    behavior=name, handler_parameter_linked=handler_match, unconditional=straight and handler_match))
            elif name == '<init>':
                # A constructor does not prove security semantics, but preserves allocation identity.
                if isinstance(receiver, Ref): receiver.initialized = True
            else:
                # Calls cannot replace a Dalvik register's object reference. Preserve
                # identity only; no effective settings/client state is inferred across
                # unknown calls. Register writes/results and block boundaries reset it.
                if sig.endswith(')Landroid/view/View;'):
                    pending=Ref('Landroid/view/View;',f'{unit.source}:{symbol}:view-return:{number}',number)
            continue
        # Unsupported register writes never reuse stale evidence.
        m = re.match(r'\S+\s+([vp]\d+)(?:,|$)', line)
        if m: regs.pop(m[1], None)
    return rows


def extract_webview_metadata(analysis_root, manifest_path=None):
    root=Path(analysis_root)
    if not root.is_dir(): raise FileNotFoundError('WebView analysis root unavailable')
    units=[]; gaps=[]; used=0
    for index,path in enumerate(sorted(root.rglob('*.smali'))):
        if index>=MAX_FILES: gaps.append('FILE_LIMIT');break
        try:
            size=path.stat().st_size
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or size>MAX_FILE_BYTES or used+size>MAX_TOTAL_BYTES:
                gaps.append('SOURCE_BOUNDARY');continue
            used+=size;text=path.read_text(); component=None; parent=None; methods=[]; current=None
            for number,raw in enumerate(text.splitlines(),1):
                line=raw.strip()
                if line.startswith('.class '): component=line.split()[-1]
                elif line.startswith('.super '): parent=line.split()[-1]
                elif line.startswith('.method '): current=(line.split()[-1], 'static' in line.split(), [])
                elif line=='.end method' and current: methods.append(current);current=None
                elif current: current[2].append((number,line))
            if component: units.append(Unit(path.relative_to(root).as_posix(),component,parent,methods))
        except (OSError,UnicodeError):gaps.append('UNREADABLE_SOURCE')
    # Duplicate class identities cannot establish linkage.
    counts={}
    for u in units:counts[u.component]=counts.get(u.component,0)+1
    parents={u.component:u.parent for u in units if counts[u.component]==1}
    def subtype(component,target):
        seen=set()
        for _ in range(4):
            if component==target:return True
            if component in seen:return False
            seen.add(component);component=parents.get(component)
        return False
    app_components=set()
    try:
        manifest=ET.parse(manifest_path or root/'AndroidManifest.xml').getroot();package=manifest.get('package','')
        app=manifest.find('application')
        for node in app if app is not None else []:
            if node.tag not in {'activity','application','service','receiver'}:continue
            name=node.get('{http://schemas.android.com/apk/res/android}name','')
            if name.startswith('.'):name=package+name
            elif '.' not in name:name=package+'.'+name
            app_components.add('L'+name.replace('.','/')+';')
    except (OSError,ET.ParseError):gaps.append('APP_LINKAGE_UNAVAILABLE')
    web_types={WEB} | {component for component in parents if subtype(component,WEB)}
    rows=[];behaviors={}
    for u in units:
        if counts[u.component]!=1: gaps.append('DUPLICATE_COMPONENT');continue
        for symbol,static,body in u.methods:
            if symbol.startswith('onReceivedSslError('):
                found=_analyze(u,symbol,static,body,subtype,app_components,{})
                callbacks=[r for r in found if r['kind']=='ssl_error_callback']
                if callbacks:
                    behaviors[u.component]={'proceed':any(r['behavior']=='proceed' for r in callbacks),
                        'unconditional_proceed':len(callbacks)==1 and callbacks[0]['behavior']=='proceed' and callbacks[0]['unconditional'],
                        'refs':[r['evidence_id'] for r in callbacks]}
    for u in units:
        if counts[u.component]!=1:continue
        for symbol,static,body in u.methods:
            if not any('android/webkit/' in line or any(owner in line for owner in web_types) for _,line in body):continue
            rows.extend(_analyze(u,symbol,static,body,subtype,app_components,behaviors))
            if len(rows)>=MAX_ROWS:gaps.append('RECORD_LIMIT');break
        if len(rows)>=MAX_ROWS:break
    rows=sorted({r['evidence_id']:r for r in rows}.values(),key=lambda r:(r['source_file'],r['line_number'],r['evidence_id']))[:MAX_ROWS]
    available={r['evidence_id'] for r in rows}
    for row in rows:
        if row.get('callback_evidence_refs') and not set(row['callback_evidence_refs'])<=available:
            row['evidence_tier']='risky_indicator';row['eligibility_reason']='CALLBACK_EVIDENCE_UNAVAILABLE'
    return {'schema_version':'1.0','detected':bool(rows),'evidence':rows,
            'coverage':{'status':'partial','limitations':sorted(set(gaps+['Static WebView evidence does not prove runtime execution or exploitability.','Cross-method fields, branches and indirect URL sources are unresolved; no broad taint analysis.']))}}
