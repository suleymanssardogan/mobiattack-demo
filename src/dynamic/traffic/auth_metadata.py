"""Value-free capture auth observations; credential references are keyed and session scoped."""
import hashlib
import hmac
import re
import secrets
from http.cookies import SimpleCookie

_PROCESS_KEY = secrets.token_bytes(32)  # Memory only; never persisted or logged.
_NAMES = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
_TYPES = {'bearer', 'basic', 'digest', 'other', 'unknown'}


def credential_ref(value, session_id):
    if not session_id or not value or value == '[REDACTED]':
        return None
    digest = hmac.new(_PROCESS_KEY, (session_id+'\0'+value).encode(), hashlib.sha256).hexdigest()
    return 'credential_' + digest


def observe_auth(headers, session_id=None, *, response=False):
    if not isinstance(headers, dict):
        headers = {}
        complete = False
    else:
        complete = True
    normalized = {str(k).strip().lower(): v for k,v in headers.items()}
    normalized = {k: (v if isinstance(v,list) and k=='set-cookie' else str(v)) for k,v in normalized.items()}
    authorization = normalized.get('authorization')
    cookie = normalized.get('set-cookie' if response else 'cookie')
    token_type = None
    refs = []
    if authorization is not None:
        scheme = authorization.split(None,1)[0].lower() if authorization.strip() else ''
        token_type = scheme if scheme in {'bearer','basic','digest'} else ('unknown' if authorization=='[REDACTED]' or not scheme else 'other')
        ref = credential_ref(authorization,session_id)
        if ref: refs.append(ref)
    cookies = []
    cookie_values = cookie if isinstance(cookie,list) else [cookie]
    for cookie_value in cookie_values[:100]:
        if not cookie_value or cookie_value == '[REDACTED]': continue
        jar = SimpleCookie()
        try: jar.load(str(cookie_value))
        except Exception: jar = SimpleCookie()
        for name,morsel in sorted(jar.items()):
            if not _NAMES.fullmatch(name): continue
            item = {'name':name}
            if response:
                # Attribute values such as Domain/Path may contain secrets; retain presence only.
                item.update(secure=bool(morsel['secure']), httponly=bool(morsel['httponly']),
                            samesite=morsel['samesite'].lower() if morsel['samesite'].lower() in {'strict','lax','none'} else None,
                            domain_present=bool(morsel['domain']), path_present=bool(morsel['path']),
                            expires_present=bool(morsel['expires']), max_age_present=bool(morsel['max-age']))
            ref = credential_ref('cookie:'+name+'='+morsel.value, session_id)
            if ref: item['credential_ref']=ref
            cookies.append(item)
    extra = any(k in normalized for k in ('x-api-key','x-auth-token','x-access-token','api-key','apikey'))
    present = authorization is not None or (cookie is not None and not response) or extra
    return {'schema_version':'1.0', 'state':'present' if present else ('absent' if complete else 'unknown'),
            'authorization_header_present':authorization is not None if complete else None, 'token_type':token_type,
            'cookie_header_present':cookie is not None and not response,
            'set_cookie_header_present':cookie is not None and response,
            'cookies':cookies, 'api_key_header_present':extra if complete else None, 'credential_refs':sorted(set(refs)),
            'session_id':session_id, 'authenticated_state':'unknown'}


def safe_auth_metadata(value, session_id=None):
    """Project an exact safe schema; arbitrary provider metadata never crosses persistence."""
    if not isinstance(value, dict): return None
    state = value.get('state')
    if state not in {'present','absent','unknown'}: return None
    scoped = isinstance(session_id,str) and value.get('session_id') == session_id
    valid_ref = lambda ref: isinstance(ref,str) and re.fullmatch(r'credential_[0-9a-f]{64}',ref) is not None
    result = {'schema_version':'1.0','state':state,'authenticated_state':'unknown',
              'session_id':session_id if scoped else None,
              'token_type':value.get('token_type') if value.get('token_type') in _TYPES else None,
              'credential_refs':sorted({r for r in (value.get('credential_refs') if isinstance(value.get('credential_refs'),list) else []) if scoped and valid_ref(r)}),
              'cookies':[]}
    for key in ('authorization_header_present','cookie_header_present','set_cookie_header_present','api_key_header_present'):
        result[key] = value.get(key) if type(value.get(key)) is bool else None
    for cookie in (value.get('cookies') if isinstance(value.get('cookies'),list) else [])[:100]:
        if not isinstance(cookie,dict) or not isinstance(cookie.get('name'),str) or not _NAMES.fullmatch(cookie['name']): continue
        item={'name':cookie['name']}
        for key in ('secure','httponly','domain_present','path_present','expires_present','max_age_present'):
            if type(cookie.get(key)) is bool:item[key]=cookie[key]
        if 'samesite' in cookie and cookie.get('samesite') in {'strict','lax','none',None}:item['samesite']=cookie.get('samesite')
        if scoped and valid_ref(cookie.get('credential_ref')):item['credential_ref']=cookie['credential_ref']
        result['cookies'].append(item)
    return result


def observe_payload_credentials(metadata, query, body, content_type, session_id):
    """Identify named credential signals before redaction; never retain their values."""
    import json
    from urllib.parse import parse_qs
    material = {'token','access_token','refresh_token','api_key','apikey','password','passwd','credential','session','session_id','sid','jwt','auth','authorization'}
    if isinstance(body,(str,bytes)) and len(body) <= 1048576:
        try:
            body = json.loads(body) if 'json' in (content_type or '') else parse_qs(body.decode() if isinstance(body,bytes) else body) if 'x-www-form-urlencoded' in (content_type or '') else None
        except (ValueError,UnicodeError): body=None
    found=[]
    def visit(value,depth=0):
        if depth>6:return
        if isinstance(value,dict):
            for key,item in list(value.items())[:100]:
                name=re.sub(r'([a-z])([A-Z])',r'\1_\2',str(key)).lower().replace('-','_')
                if name in material:
                    found.append(item)
                else:visit(item,depth+1)
        elif isinstance(value,list):
            for item in value[:100]:visit(item,depth+1)
    for payload in (query,body):visit(payload)
    if found:
        metadata['state']='present'
        metadata['credential_refs']=sorted(set(metadata['credential_refs']) | {ref for value in found for ref in [credential_ref(json.dumps(value,sort_keys=True),session_id)] if ref})
    return metadata
