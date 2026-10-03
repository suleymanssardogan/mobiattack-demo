"""Read-only, bounded presentation of canonical reports. No analysis or writes."""
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
from src.static_inventory import indicator_context, runtime_technologies, FLUTTER_COVERAGE

from src.dynamic.report.models import load_dynamic_analysis_report, DynamicReportError
from src.dynamic.security.standards import standards_for_category, validate_standards_metadata

KEY_PERMISSIONS = ('INTERNET','ACCESS_NETWORK_STATE','CAMERA','RECORD_AUDIO','ACCESS_FINE_LOCATION',
                  'ACCESS_COARSE_LOCATION','READ_CONTACTS','READ_SMS','SEND_SMS','READ_PHONE_STATE',
                  'MANAGE_EXTERNAL_STORAGE','READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE')


def _text(value, default='Unknown', *, complete=False):
    if not isinstance(value,str) or not value.strip(): return default
    if re.search(r'(?i)bearer\s|(?:token|password|secret|cookie|authorization|api[_-]?key)\s*[:=]|eyJ[\w-]+\.|(?:/Users/|/home/|/private/|/tmp/|[A-Za-z]:\\)',value): return default
    return value.strip() if complete else value.strip()[:160]


def _count(value):
    return value if isinstance(value,int) and not isinstance(value,bool) and value>=0 else None


def _length(value):
    return len(value) if isinstance(value,list) else None


def _endpoint(row, contexts):
    context=contexts.get(row.get('endpoint_context_id'),{})
    host=_text(context.get('host') or row.get('host'))
    if '@' in host or '://' in host:host='Unknown'
    if ':' in host and not host.startswith('['):host='['+host+']'
    path=context.get('path') or row.get('path') or '/'
    path=path.split('?',1)[0].split('#',1)[0] if isinstance(path,str) else '/'
    path=_text(path,'/')
    methods=context.get('methods') or row.get('observed_methods') or ([row['static_method']] if row.get('static_method') else [])
    method=next((m for m in methods if m in {'GET','POST','HEAD','OPTIONS','PUT','PATCH','DELETE'}),'')
    port=context.get('port')
    scheme=context.get('scheme')
    default_port={'http':80,'https':443}.get(scheme)
    if isinstance(port,int) and port!=default_port:host+=f':{port}'
    origin=(scheme+'://' if scheme in {'http','https'} else '')+host
    return ' '.join(x for x in (method,origin+path) if x)


def _evidence_available(row, index):
    refs=row.get('evidence_refs') or []
    required={row.get('endpoint_context_id'),row.get('session_id'),row.get('execution_result_ref'),
              *(row.get('baseline_evidence_refs') or {}).values(),*(row.get('variant_evidence_refs') or {}).values()}
    return bool(required and None not in required and len(required)>=7 and required.issubset(refs)
        and all(ref in index and index[ref].get('endpoint_context_id')==row.get('endpoint_context_id')
                and index[ref].get('session_id')==row.get('session_id') for ref in required))


def build_report_summary(static_report=None,dynamic_report=None,*,contexts=None,available_executions=None):
    static=static_report or {};dynamic=dynamic_report or {};contexts=contexts or {}
    app=static.get('application') or {};candidates=static.get('api_candidates');net=static.get('network_indicators') or {}
    permissions=static.get('permissions') or []
    names={p if isinstance(p,str) else p.get('name','') for p in permissions if isinstance(p,(str,dict))}
    key_permissions=[name for name in KEY_PERMISSIONS if 'android.permission.'+name in names][:8]
    hosts=set()
    for value in net.get('network_urls') or []:
        url=value if isinstance(value,str) else (value.get('value') or value.get('url') or '') if isinstance(value,dict) else ''
        if indicator_context(url, value.get("source_file", "") if isinstance(value, dict) else "") != "unconfirmed_network_indicator":
            continue
        try:
            parsed=urlsplit(url)
            if parsed.scheme in {'http','https'} and parsed.hostname and parsed.username is None:
                hosts.add(_text(parsed.hostname))
        except ValueError:pass
    static_limits=[]
    if not static:static_limits.append('Static report is unavailable.')
    elif static.get('status') in {'partial','failed'}:static_limits.append('Static coverage is '+static['status']+'.')
    if static.get('limitations'):static_limits.append('Additional static coverage limits are recorded in the full evidence.')
    if any('call-context' in str(value).lower() or 'heuristic' in str(value).lower() for value in static.get('limitations',[])):
        static_limits.append('API discovery covers supported code patterns; it is not a complete endpoint inventory.')
    if any('split' in str(value).lower() for value in static.get('limitations',[])):
        static_limits.append('Only available application splits were analyzed.')
    if static.get('preprocessing',{}).get('jadx',{}).get('status') in {'success_with_warnings','failed'}:
        static_limits.append('Some code could not be fully decoded.')
    static_limits.append('Static API candidates are not runtime confirmation.')
    control_coverage = (static.get('vulnerabilities') or {}).get('control_coverage') or []
    limited_categories = sorted({r.get('masvs_category') for r in control_coverage
        if isinstance(r, dict) and r.get('coverage_state') in {'partial', 'unsupported'}
        and r.get('masvs_category') in {'MASVS-STORAGE', 'MASVS-CRYPTO', 'MASVS-AUTH', 'MASVS-NETWORK',
            'MASVS-PLATFORM', 'MASVS-CODE', 'MASVS-RESILIENCE', 'MASVS-PRIVACY'}})
    if limited_categories:
        static_limits.append('Static control coverage is partial or unavailable for: ' + ', '.join(limited_categories) + '.')
    if static.get('api_discovery'):
        static_limits.append('API discovery is bounded; unresolved networking is not absence of networking.')
    technologies = runtime_technologies(static.get("structure") or {})
    if technologies:
        static_limits.append(FLUTTER_COVERAGE)
    static_summary={'app':_text(app.get('app_name') or app.get('label') or app.get('filename')),
        'package':_text(app.get('package_name')),'status':static.get('status') if static.get('status') in {'completed','partial','failed'} else 'unavailable',
        'key_permissions':key_permissions,'api_candidates_count':_length(candidates),
        'frameworks_detected':sorted({framework for c in candidates or [] if isinstance(c,dict)
            for framework in (c.get('frameworks') if isinstance(c.get('frameworks'), list) else [c.get('framework')])
            if framework in {'Fuel','Retrofit','okhttp','volley','httpurlconnection','ktor'}}),
        'runtime_technologies': [r['name'] for r in technologies],
        'network_indicators':{'urls':_length(net.get('network_urls')),'domains':_length(net.get('domains')),'ips':_length(net.get('ip_addresses')),
                              'paths':_length(net.get('path_candidates')),'local_file_urls':_length(net.get('local_file_urls')),'hosts':sorted(hosts)[:5]},
        'coverage_limitations':static_limits}
    security=dynamic.get('security_results') or {};rows=security.get('results') or []
    endpoint_rows={r['endpoint_context_id']:r for r in dynamic.get('endpoint_contexts',[])}
    security_rows=[]
    for row in rows:
        metadata=row.get('standards') or standards_for_category(row['test_category'])
        validate_standards_metadata(metadata,row['test_category'])
        mapping=[metadata['masvs_category'],*metadata['masvs_control_refs'],*metadata['mastg_test_refs'],*metadata['maswe_refs']]
        available=_evidence_available(row,security.get('evidence_index',{}))
        if available_executions is not None:available=available and row.get('execution_result_ref') in available_executions
        security_rows.append({'endpoint':_endpoint(endpoint_rows.get(row['endpoint_context_id'],{}),contexts),
            'test_category':row['test_category'],'outcome':row['validation_outcome'],
            'reason_code':', '.join(row['reason_codes']),'standard_mapping':', '.join(mapping),
            'evidence_available':'YES' if available else 'NO',
            **({'result_message':row['result_message'],'tested_relationship':row['tested_relationship']} if row['test_category'] in {'object_authorization','function_authorization','session_handling'} else {})})
    coverage=dynamic.get('coverage') or {};preflight=dynamic.get('preflight') or {};exploration=dynamic.get('exploration') or {}
    count=_count(dynamic.get('endpoint_context_summary',{}).get('runtime_observed_count'))
    dynamic_limits=[]
    if not dynamic:dynamic_limits.append('Dynamic report is unavailable.')
    if dynamic.get('analysis_coverage')=='partial':dynamic_limits.append('Dynamic coverage is partial.')
    for name,label in [('http_visibility','HTTP visibility'),('https_visibility','HTTPS visibility'),('runtime_observation','Runtime observation'),('ui_exploration','Exploration')]:
        state=coverage.get(name,'unavailable')
        if state!='available':dynamic_limits.append(label+' is '+state+'.')
    http_reason = _text((dynamic.get('traffic') or {}).get('http_visibility_reason'), '')
    if coverage.get('http_visibility') != 'available' and http_reason:
        dynamic_limits.append('HTTP capture reason: '+http_reason+'.')
    if count==0:dynamic_limits.append('No endpoints were observed in available traffic; this does not establish absence of network activity.')
    if not rows:dynamic_limits.append('No security validation results are available; security was not established.')
    elif security.get('coverage')!='available':dynamic_limits.append('Security validation coverage is partial or unavailable.')
    if any(r['evidence_available']=='NO' for r in security_rows):dynamic_limits.append('Some linked security evidence is unavailable.')
    if any('HISTORICAL_BASELINE' in r.get('limitations',[]) for r in rows):dynamic_limits.append('Security comparisons use a previously observed baseline.')
    dynamic_summary={'status':dynamic.get('analysis_coverage') if dynamic else 'unavailable',
        'launch_status':'Observed' if preflight.get('launch_success') is True else 'Failed' if preflight.get('launch_success') is False else 'Unknown',
        'runtime_status':coverage.get('runtime_observation','unavailable'),
        'routes_explored':_count(dynamic.get('routes',{}).get('node_count')),
        'exploration_note':_text(exploration.get('note'), 'Safe frontier accounting is unavailable.', complete=True),
        'exploration_stop_reason':_text(exploration.get('stop_kind') or exploration.get('stop_reason')),
        'safe_actions_remaining':exploration.get('safe_actions_remaining') if isinstance(exploration.get('safe_actions_remaining'), int) else None,
        'actions_attempted':_count(exploration.get('steps_attempted')),'actions_succeeded':_count(exploration.get('actions_succeeded')),
        'traffic_visibility':{name:coverage.get(name,'unavailable') for name in ('http_visibility','https_visibility')},
        'observed_endpoints':count,'security_tests_executed':sum(r['execution_status']=='completed' for r in rows),
        'validation_outcomes':{key:sum(r['validation_outcome']==key for r in rows) for key in ('validated','rejected','inconclusive','blocked')},
        'coverage_limitations':dynamic_limits}
    findings = []
    for row in (static.get('vulnerabilities') or {}).get('findings', []):
        if not isinstance(row, dict):
            continue
        findings.append({'title': _text(row.get('title')), 'severity': _text(row.get('severity')),
            'component': ', '.join(_text(value) for value in (row.get('affected_items') or [])[:3]),
            'standards': ', '.join(_text(row.get(key), '') for key in ('masvs_id', 'cwe_id') if row.get(key)),
            'impact': _text(row.get('impact') or row.get('description'), complete=True), 'evidence': _text(row.get('evidence'), 'Not available', complete=True),
            'remediation': _text(row.get('remediation'), 'Not available', complete=True)})
    return {'static_security_report': {'status': static_summary['status'], 'findings': findings,
                'coverage_limitations': static_limits},
            'dynamic_security_report': {'runtime_status': dynamic_summary['runtime_status'],
                'results': [dict(row, finding_created=False, outcome=('inconclusive' if row['outcome'] == 'validated' and row['evidence_available'] == 'NO' else row['outcome'])) for row in security_rows],
                'coverage_limitations': dynamic_limits}, 'summary_version':'1.0' ,'static_summary':static_summary,'dynamic_summary':dynamic_summary,
            'security_validation_summary':security_rows,
            'security_note':'Validated auth enforcement is expected security behavior, not a vulnerability finding.'}


def load_report_summary(run_dir, *, static_run_id=None):
    """Only reads canonical sources. Missing/corrupt sources remain explicit."""
    run_dir=Path(run_dir);static=None;dynamic=None;contexts={};available=set()
    try:
        from src.static_security.report_freshness import load_current_static_report
        static=load_current_static_report(run_dir, static_run_id or run_dir.name)
    except (ValueError,OSError):pass
    try:dynamic=load_dynamic_analysis_report(run_dir,run_dir.name)
    except DynamicReportError:pass
    if dynamic:
        try:
            source=json.loads((run_dir/'dynamic/endpoint_contexts.json').read_text())
            if source.get('session_id')==dynamic['session']['session_id']:
                contexts={c['endpoint_context_id']:c for c in source['endpoints']}
            from src.dynamic.security.reporting import build_security_section
            security_source=json.loads((run_dir/'dynamic/security_results.json').read_text())
            verified=build_security_section(security_source,dynamic['session']['session_id'],list(contexts.values()))
            reported={r['execution_result_ref']:r for r in dynamic.get('security_results',{}).get('results',[])}
            for row in verified['results']:
                old=reported.get(row['execution_result_ref'])
                if old and row['validation_outcome']==old['validation_outcome'] and _evidence_available(row,verified['evidence_index']):available.add(row['execution_result_ref'])
        except (ValueError,OSError,KeyError,TypeError,AttributeError):pass
    result=build_report_summary(static,dynamic,contexts=contexts,available_executions=available)
    if dynamic and dynamic.get('execution_environment'):
        result['dynamic_summary']['execution_environment'] = dynamic['execution_environment']
    if dynamic:
        # Compare only previously validated, ownership-checked canonical records.
        try:
            for record in security_source['records']:
                execution = record.get('execution', {})
                execution_ref = record.get('evidence', {}).get('execution_ref')
                if execution_ref not in available:
                    continue
                evidence = record.get('evidence', {})
                baseline = (evidence.get('baseline', {}).get('response') or {}).get('status_code')
                variant = (evidence.get('variant', {}).get('response') or {}).get('status_code')
                if _count(baseline) is not None and _count(variant) is not None:
                    rows = dynamic.get('security_results', {}).get('results', [])
                    for index, row in enumerate(rows):
                        if row.get('execution_result_ref') == execution_ref:
                            result['dynamic_security_report']['results'][index]['comparison'] = f'{baseline} / {variant}'
        except (UnboundLocalError, KeyError, TypeError, AttributeError):
            pass
    try:
        permissions = json.loads((run_dir / 'dynamic/runtime_permissions.json').read_text())
        if permissions.get('coverage') in {'partial', 'unavailable'}:
            result['dynamic_summary']['coverage_limitations'].append('Some runtime permissions could not be granted or verified.')
    except (ValueError, OSError, AttributeError):
        pass
    if dynamic and dynamic.get('runtime_availability'):
        availability = dynamic['runtime_availability']
        result['dynamic_summary']['runtime_status'] = availability['status']
        result['dynamic_summary']['runtime_reason'] = availability['reason_code']
        if availability['status'] != 'available':
            limits = ['Runtime analysis unavailable on the current execution environment.' if availability['status'] == 'unavailable'
                      else 'Runtime analysis coverage is partial.', availability['message']]
            if availability['status'] == 'partial' and not availability['evidence'].get('foreground_verified'):
                limits.append('Foreground activity could not be confirmed.')
            result['dynamic_summary']['coverage_limitations'].extend(limits)
            result['dynamic_security_report']['coverage_limitations'].extend(limits)
    result['canonical_artifacts']={'static':static is not None,'dynamic':dynamic is not None}
    return result
