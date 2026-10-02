"""Endpoint canonicalization only: no discovery or cross-endpoint inference.

Resolved identity excludes framework/source and query values. Partial/unresolved
identities retain their source scope so unknown hosts cannot be merged by guessing.
Original extractor facts are kept as separate sanitized provenance records.
"""
from copy import deepcopy
import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, quote

UNRESERVED=set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~')
METHODS={'GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','TRACE','CONNECT'}
FRAMEWORKS={name.lower():name for name in ('Fuel','Retrofit','okhttp','volley','httpurlconnection','ktor')}
IDENTITY_FIELDS=('method','scheme','host','port','path')


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)


def _id(prefix,value):
    return prefix+hashlib.sha256(_json(value).encode()).hexdigest()[:24]


def _sanitize(value):
    if isinstance(value,dict):return {k:_sanitize(v) for k,v in value.items()}
    if isinstance(value,list):return [_sanitize(v) for v in value]
    if isinstance(value,str) and (value.startswith('/') or re.match(r'^https?://',value,re.I)):
        return value.split('?',1)[0].split('#',1)[0]
    return value


def _path(value):
    if not isinstance(value,str) or not value or any(ord(c)<32 or c.isspace() for c in value):return None
    if '\\' in value or re.search(r'%(?![0-9a-fA-F]{2})',value):return None
    # Decode only unreserved characters. Encoded slash/template delimiters stay literal.
    value=re.sub(r'%([0-9a-fA-F]{2})',lambda m:chr(int(m[1],16)) if chr(int(m[1],16)) in UNRESERVED else '%'+m[1].upper(),value)
    return quote(value,safe="/:@!$&'()*+,;=-._~{}<>%")


def _url(value):
    try:
        if not isinstance(value,str) or any(c.isspace() or ord(c)<32 for c in value) or '\\' in value:return None
        parsed=urlsplit(value)
        scheme=parsed.scheme.lower()
        if scheme not in {'http','https'} or not parsed.hostname or parsed.username is not None or parsed.password is not None:return None
        host=parsed.hostname.lower()
        if ':' in host:
            import ipaddress
            host=ipaddress.IPv6Address(host).compressed
        elif not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',host) or any(not part or part.startswith('-') or part.endswith('-') or len(part)>63 for part in host.split('.')):
            return None
        port=parsed.port if parsed.port is not None else (80 if scheme=='http' else 443)
        if not 1<=port<=65535:return None
        path=_path(parsed.path or '/')
        if path is None:return None
        authority='['+host+']' if ':' in host else host
        if port!=(80 if scheme=='http' else 443):authority+=':'+str(port)
        return dict(scheme=scheme,host=host,port=port,path=path,
                    base_url=scheme+'://'+authority,
                    full_url=urlunsplit((scheme,authority,path,'','')),query=parsed.query)
    except (ValueError,TypeError):return None


def _query(row,raw_query):
    keys=row.get('query_keys') or []
    shape=row.get('query_shape') or {}
    if not isinstance(keys,list) or not isinstance(shape,dict):raise ValueError('QUERY_SHAPE_INVALID')
    if raw_query:
        parsed=parse_qsl(raw_query,keep_blank_values=True,max_num_fields=128)
        keys=sorted({k for k,v in parsed})
        shape={k:dict(count=sum(key==k for key,v in parsed),value_present=any(bool(v) for key,v in parsed if key==k)) for k in keys}
    keys=sorted(set(keys)|set(shape))
    result={}
    for key in keys:
        if not isinstance(key,str) or not key or len(key)>128 or any(ord(c)<32 for c in key):raise ValueError('QUERY_KEY_INVALID')
        metadata=shape.get(key,{})
        if not isinstance(metadata,dict):raise ValueError('QUERY_SHAPE_INVALID')
        count=metadata.get('count',1)
        if type(count) is not int or not 1<=count<=128:raise ValueError('QUERY_SHAPE_INVALID')
        result[key]={'count':count,'value_present':metadata.get('value_present') if type(metadata.get('value_present')) is bool else None}
    if len(keys)>128:raise ValueError('QUERY_SHAPE_INVALID')
    return keys,result


def literal_query_metadata(value):
    """Metadata from a proven URL/declaration literal; never returns query values."""
    try:
        keys,shape=_query({},value.partition('?')[2].split('#',1)[0])
        return dict(query_keys=keys,query_shape=shape,query_shape_known=True)
    except (ValueError,TypeError):
        return dict(query_keys=[],query_shape={},query_shape_known=False)


def _source(candidate):
    row=_sanitize(deepcopy(candidate))
    for key in ('candidate_id','provenance','frameworks','evidence_refs','evidence_ref'):
        row.pop(key,None)
    row.setdefault('extractor_identity',_sanitize({key:candidate.get(key) for key in ('method','base_url','path','full_url')}))
    framework=row.get('framework')
    if isinstance(framework,str):row['framework']=FRAMEWORKS.get(framework.lower(),framework)
    if candidate.get('source_candidate_id'):
        row['source_candidate_id']=candidate['source_candidate_id']
    elif candidate.get('candidate_id'):
        row['source_candidate_id']=candidate['candidate_id']
    raw_url=candidate.get('full_url')
    raw_path=candidate.get('path')
    # Absolute request literals have priority over a manager base not used by that call.
    if not raw_url and isinstance(raw_path,str) and re.match(r'^https?://',raw_path,re.I):raw_url=raw_path
    if not raw_url and candidate.get('scheme') and candidate.get('host') and isinstance(raw_path,str) and raw_path.startswith('/'):
        host=candidate['host'];host='['+host+']' if ':' in host and not host.startswith('[') else host
        port=candidate.get('port')
        raw_url=str(candidate['scheme'])+'://'+host+(':'+str(port) if port is not None else '')+raw_path
    url=_url(raw_url) if raw_url else None
    reason=None
    method=candidate.get('method')
    row['method']=method.strip().upper() if isinstance(method,str) and method.strip() else None
    raw_query=''
    if url:
        # Contradictory explicit authority metadata is not silently repaired.
        for key in ('scheme','host','port'):
            supplied=candidate.get(key)
            normalized=str(supplied).lower() if key!='port' else supplied
            if key=='host' and supplied is not None and ':' in str(supplied):
                try:
                    import ipaddress
                    normalized=ipaddress.IPv6Address(str(supplied)).compressed
                except ValueError:pass
            if supplied is not None and normalized!=url[key]:reason='AUTHORITY_CONFLICT'
        raw_query=url.pop('query')
        row.update(url)
    else:
        row.update(scheme=None,host=None,port=None,base_url=None,full_url=None)
        try:relative=isinstance(raw_path,str) and not urlsplit(raw_path).scheme
        except ValueError:relative=False
        if relative:
            path,_,raw_query=raw_path.partition('?')
            row['path']=_path(path.split('#',1)[0])
        else:row['path']=None
        if raw_url:reason='URL_UNRESOLVED_OR_INVALID'
    try:row['query_keys'],row['query_shape']=_query(candidate,raw_query)
    except (ValueError,TypeError):
        row['query_keys'],row['query_shape']=[],{}
        reason='QUERY_METADATA_INVALID'
    row['query_shape_known']=candidate.get('query_shape_known',not ((candidate.get('evidence') or {}).get('query_values_removed') and not raw_query and 'query_keys' not in candidate))
    original=candidate.get('resolution_state')
    if reason or not row['path'] or original=='unresolved':state='unresolved'
    elif original=='partial' or not url or row['method'] not in METHODS or not row['query_shape_known']:state='partial'
    else:state='resolved'
    row['resolution_state']=state
    if reason:
        row['normalization_reason']=reason
        row.update(scheme=None,host=None,port=None,base_url=None,full_url=None)
    row.setdefault('source_component',(row.get('evidence') or {}).get('service_class'))
    row.setdefault('status','static_api_candidate')
    return row


def canonicalize_api_candidates(candidates):
    sources=[]
    for candidate in candidates or []:
        if not isinstance(candidate,dict):continue
        provenance=candidate.get('provenance')
        if isinstance(provenance,list) and provenance:
            for origin in provenance:
                if isinstance(origin,dict):sources.append(_source(origin))
        else:sources.append(_source(candidate))
    groups={}
    for source in sources:
        identity={key:source.get(key) for key in IDENTITY_FIELDS}
        identity['query_shape']={k:{'count':v['count']} for k,v in source['query_shape'].items()}
        if not source['query_shape_known']:identity['query_shape_known']=False
        if source['resolution_state']!='resolved':
            identity['resolution_state']=source['resolution_state']
            identity['source_scope']={k:source.get(k) for k in ('framework','source_apk','source_file','source_component','request_line')}
        key=_json(identity)
        groups.setdefault(key,(identity,{}))[1][_json(source)]=source
    result=[]
    for key,(identity,records) in sorted(groups.items()):
        origins=sorted(records.values(),key=lambda r:(str(r.get('framework') or ''),str(r.get('source_apk') or ''),str(r.get('source_file') or ''),r.get('request_line') or 0,_json(r)))
        primary=deepcopy(origins[0])
        primary.pop('source_candidate_id',None)
        primary['candidate_id']=_id('static_',identity)
        primary['frameworks']=sorted({r['framework'] for r in origins if r.get('framework')})
        primary['provenance']=[dict(r,evidence_ref=_id('static_evidence_',r)) for r in origins]
        primary['evidence_refs']=[r['evidence_ref'] for r in primary['provenance']]
        for query_key,metadata in primary['query_shape'].items():
            values=[r['query_shape'][query_key]['value_present'] for r in origins]
            metadata['value_present']=True if True in values else (False if all(v is False for v in values) else None)
        result.append(primary)
    return result


def bind_source_apk(candidate,filename):
    row=deepcopy(candidate)
    row['source_apk']=filename
    for origin in row.get('provenance',[]):origin['source_apk']=filename
    return row
