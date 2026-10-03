"""Local-only authentication baseline fixture; no security executor integration.

Credentials are public fixed training fixtures. Tokens live only in memory.
The browser performs one login and one authenticated read when the user taps
its button. It never sends a missing-auth variant or retries.
"""
import hmac
import ipaddress
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import uuid

TRAINING_ACCOUNT = 'local_lab_user'
TRAINING_PASSWORD = 'local_lab_password'
MAX_BODY_BYTES = 4096


class TrainingAuthLab:
    def __init__(self, run_id):
        uuid.UUID(run_id)
        self.run_id = run_id
        self._tokens = set()
        self.receipts = []

    def login(self, data):
        if not isinstance(data, dict) or set(data) != {'auth_user', 'password'}:
            return 400, {'error': 'invalid_shape'}
        if data['auth_user'] != TRAINING_ACCOUNT or data['password'] != TRAINING_PASSWORD:
            return 401, {'error': 'invalid_training_credentials'}
        if self._tokens:  # One acquisition flow per lab instance, no retry/chaining.
            return 409, {'error': 'baseline_already_issued'}
        token = secrets.token_urlsafe(32)
        self._tokens.add(token)
        return 200, {'access_token': token, 'token_type': 'Bearer'}

    def profile(self, authorization):
        valid = isinstance(authorization, str) and authorization.startswith('Bearer ') and any(
            hmac.compare_digest(authorization[7:].encode(), token.encode()) for token in self._tokens)
        if not valid:
            return 401, {'error': 'authentication_required'}
        return 200, {'authenticated': True, 'purpose': 'read_only_training_profile',
                     'profile': {'display_name': 'Training User'}}

    def receipt(self, trace_id, method, path, status, auth_present, auth_valid):
        if len(self.receipts) >= 32:
            raise ValueError('Lab receipt bound exceeded')
        self.receipts.append({'trace_id': trace_id, 'run_id': self.run_id,
                              'method': method, 'path': path, 'status': status,
                              'auth_present': auth_present, 'auth_valid': auth_valid,
                              'source': 'local_training_backend_actual_response'})

    def page(self):
        credentials = json.dumps({'auth_user': TRAINING_ACCOUNT, 'password': TRAINING_PASSWORD})
        run_id = json.dumps(self.run_id)
        return '''<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Auth Baseline Lab</title></head><body>
<h1>Local Auth Baseline Lab</h1><p>One login, then one authenticated read. No security test.</p>
<button style="font-size:24px;padding:20px" id="start">Login and load profile</button>
<p id="result">Ready</p><script>
const button=document.getElementById('start'); button.onclick=async()=>{
 button.disabled=true; const result=document.getElementById('result');
 try {
 const login=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json','X-Lab-Run-ID':RUN_ID},body:JSON.stringify(CREDENTIALS)});
 if(!login.ok)throw new Error('Login failed');
 const session=await login.json();
 const profile=await fetch('/profile',{headers:{'Authorization':'Bearer '+session.access_token,'X-Lab-Run-ID':RUN_ID}});
 const data=await profile.json();
 result.textContent=profile.ok&&data.authenticated===true?'Authenticated profile loaded':'Profile failed';
 }catch(e){result.textContent='Lab transport or login failed';}
};</script></body></html>'''.replace('RUN_ID', run_id).replace('CREDENTIALS', credentials).encode()



class TrainingObjectLab(TrainingAuthLab):
    """Two fixed principals/resources; credentials and sessions remain memory-only."""
    def __init__(self, run_id):
        super().__init__(run_id)
        self._principal_sessions = {}
        self.owners = {'1001': 'user_A', '2002': 'user_B'}
        self._issued = set()

    def login(self, data):
        accounts = {'user_A': 'training_A_password', 'user_B': 'training_B_password'}
        if not isinstance(data, dict) or set(data) != {'auth_user', 'password'}:
            return 400, {'error': 'invalid_shape'}
        alias = data['auth_user']
        if alias not in accounts or data['password'] != accounts[alias]:
            return 401, {'error': 'invalid_training_credentials'}
        if alias in self._issued:
            return 409, {'error': 'baseline_already_issued'}
        token = secrets.token_urlsafe(32)
        self._principal_sessions[token] = (alias, 'principal_session_' + uuid.uuid4().hex)
        self._issued.add(alias)
        return 200, {'access_token': token, 'token_type': 'Bearer'}

    def principal(self, authorization):
        if isinstance(authorization, str) and authorization.startswith('Bearer '):
            for token, identity in self._principal_sessions.items():
                if hmac.compare_digest(authorization[7:].encode(), token.encode()):
                    return identity
        return None, None

    def order(self, authorization, resource):
        alias, _ = self.principal(authorization)
        if alias is None:
            return 401, {'error': 'authentication_required'}
        if resource not in self.owners:
            return 404, {'error': 'unknown_training_resource'}
        if self.owners[resource] != alias:
            return 403, {'error': 'object_access_denied', 'resource_id': resource}
        return 200, {'resource_id': resource, 'owner_alias': alias, 'purpose': 'protected_training_order'}

    def ownership(self, host, port):
        import hashlib
        ref = 'ownership_' + hashlib.sha256(self.run_id.encode()).hexdigest()[:20]
        return {'evidence_ref': ref, 'session_id': self.run_id, 'source': 'controlled_local_lab_configuration',
                'host': host, 'port': port, 'principals': ['user_A', 'user_B'], 'resources': dict(self.owners)}

class TrainingSessionLab(TrainingObjectLab):
    """One credential generation, explicit revocation, no refresh/re-authentication."""
    def __init__(self, run_id):
        super().__init__(run_id)
        self.sessions = {}
        import threading
        self.validation_claimed = False
        self.validation_lock = threading.Lock()

    def login(self, data):
        from datetime import datetime, timedelta, timezone
        if not isinstance(data,dict) or data.get('auth_user')!='user_A':
            return 401, {'error':'invalid_training_credentials'}
        status,body=super().login(data)
        if status==200:
            _,ref=self.principal('Bearer '+body['access_token'])
            self.sessions[ref]={'credential_ref':ref,'generation':1,'active':True,'version':1,
                'reason':'login','expires_at':(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat()}
        return status,body

    def profile(self, authorization):
        from datetime import datetime, timezone
        alias,ref=self.principal(authorization)
        if alias!='user_A' or ref not in self.sessions:
            return 401, {'error':'authentication_required'}
        state=self.sessions[ref]
        if datetime.fromisoformat(state['expires_at'])<=datetime.now(timezone.utc):
            return 401, {'error':'session_expired'}
        if not state['active']:
            return 401, {'error':'session_invalidated'}
        return 200, {'authenticated':True,'purpose':'read_only_training_profile','profile':{'display_name':'Training User A'}}

    def logout(self, authorization, data):
        alias,ref=self.principal(authorization)
        if alias!='user_A' or ref not in self.sessions or data!={}:
            return 401, {'error':'authentication_required'}
        state=self.sessions[ref]
        if not state['active']:
            return 409, {'error':'already_invalidated'}
        self.sessions[ref]={**state,'active':False,'version':state['version']+1,'reason':'logout'}
        return 200, {'logout':'completed'}

    def lifecycle(self, host, port):
        import hashlib
        refs=[ref for alias,ref in self._principal_sessions.values() if alias=='user_A']
        return {'evidence_ref':'lifecycle_'+hashlib.sha256(self.run_id.encode()).hexdigest()[:20],
            'session_id':self.run_id,'source':'controlled_local_lab_configuration','host':host,'port':port,
            'principal_alias':'user_A','credential_ref':refs[0] if len(refs)==1 else None,'generation':1,
            'protected':{'method':'GET','path':'/profile'},'logout':{'method':'POST','path':'/logout'}}

    def record_session_state(self, trace, authorization, before=None):
        alias,ref=self.principal(authorization)
        state=dict(self.sessions.get(ref,{}))
        self.receipts[-1].update({'principal_alias':alias,'credential_ref':ref,'generation':state.get('generation'),
            'state_before':{'evidence_ref':'state_'+trace+'_before','session_id':self.run_id,'trace_id':trace,**(before if before is not None else state)},
            'state_after':{'evidence_ref':'state_'+trace+'_after','session_id':self.run_id,'trace_id':trace,**state}})


class TrainingFunctionLab(TrainingObjectLab):
    """A disposable administrative toggle with explicit roles, never real accounts."""
    def __init__(self, run_id):
        super().__init__(run_id)
        self.roles = {'user_A':'user', 'user_B':'admin'}
        self.state = {'enabled':False, 'revision':0}

    def reset(self):
        self.state = {'enabled':False, 'revision':0}

    def privileges(self, host, port):
        import hashlib
        identities = {alias:{'role':self.roles[alias], 'credential_ref':credential}
                      for alias,credential in self._principal_sessions.values()}
        return {'evidence_ref':'privilege_' + hashlib.sha256(self.run_id.encode()).hexdigest()[:20],
                'session_id':self.run_id, 'source':'controlled_local_lab_configuration',
                'host':host, 'port':port, 'principals':identities,
                'function':{'method':'POST', 'path':'/lab/admin/toggle', 'required_role':'admin',
                            'disposable':True, 'body':{'enabled':True}}}

    def toggle(self, authorization, data):
        alias,_ = self.principal(authorization)
        if alias is None:
            return 401, {'error':'authentication_required'}
        if self.roles.get(alias) != 'admin':
            return 403, {'error':'function_access_denied', 'function':'training_toggle'}
        if data != {'enabled':True}:
            return 400, {'error':'invalid_training_operation'}
        self.state = {'enabled':True, 'revision':self.state['revision']+1}
        return 200, {'function':'training_toggle', 'applied':True, **self.state}


def make_server(bind_host, port, lab):
    address = ipaddress.ip_address(bind_host)
    if not (address.is_private or address.is_loopback) or address.is_unspecified:
        raise ValueError('Explicit local/private bind address required')

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(3)

        def log_message(self, *args):
            pass  # No headers, credentials, tokens, or request bodies in logs.

        def _reply(self, status, value, trace=None, html=False):
            body = value if html else json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            if trace:
                self.send_header('X-Lab-Trace-ID', trace)
            self.end_headers()
            self.wfile.write(body)

        def _permitted(self):
            # Other LAN clients cannot use this fixture even when bound to a LAN
            # interface. Emulator traffic arrives through the host-local proxy.
            return self.client_address[0] in {'127.0.0.1', bind_host}

        def do_GET(self):
            if not self._permitted():
                return self._reply(403, {'error': 'host_proxy_only'})
            path = urlsplit(self.path).path
            if path == '/':
                return self._reply(200, lab.page(), html=True)
            if type(lab) is TrainingObjectLab and path in {'/orders/1001', '/orders/2002'}:
                if self.headers.get('X-Lab-Run-ID') != lab.run_id:
                    return self._reply(403, {'error': 'run_ownership_mismatch'})
                authorization = self.headers.get('Authorization')
                resource = path.rsplit('/', 1)[1]
                status, body = lab.order(authorization, resource)
                alias, credential_ref = lab.principal(authorization)
                trace = 'lab_' + uuid.uuid4().hex
                lab.receipt(trace, 'GET', path, status, bool(authorization), alias is not None)
                import hashlib
                lab.receipts[-1].update({'principal_alias': alias, 'credential_ref': credential_ref,
                    'resource_id': resource, 'owner_alias': lab.owners[resource],
                    'response_sha256': hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest(),
                    'response_resource_id': body.get('resource_id'), 'response_owner_alias': body.get('owner_alias')})
                return self._reply(status, body, trace)
            if path != '/profile':
                return self._reply(404, {'error': 'unknown_lab_path'})
            if self.headers.get('X-Lab-Run-ID') != lab.run_id:
                return self._reply(403, {'error': 'run_ownership_mismatch'})
            authorization = self.headers.get('Authorization')
            status, body = lab.profile(authorization)
            trace = 'lab_' + uuid.uuid4().hex
            lab.receipt(trace, 'GET', path, status, bool(authorization), status == 200)
            if type(lab) is TrainingSessionLab:
                import hashlib
                lab.record_session_state(trace,authorization)
                lab.receipts[-1]['response_sha256']=hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest()
            self._reply(status, body, trace)

        def do_POST(self):
            if not self._permitted():
                return self._reply(403, {'error': 'host_proxy_only'})
            path = urlsplit(self.path).path
            function = type(lab) is TrainingFunctionLab and path == '/lab/admin/toggle'
            logout = type(lab) is TrainingSessionLab and path == '/logout'
            if path != '/login' and not function and not logout:
                return self._reply(404, {'error': 'unknown_lab_path'})
            if self.headers.get('X-Lab-Run-ID') != lab.run_id:
                return self._reply(403, {'error': 'run_ownership_mismatch'})
            try:
                size = int(self.headers.get('Content-Length', 0))
                if not 0 < size <= MAX_BODY_BYTES:
                    return self._reply(413, {'error': 'bounded_body_required'})
                data = json.loads(self.rfile.read(size))
            except (ValueError, TimeoutError):
                return self._reply(400, {'error': 'invalid_body'})
            if logout:
                import hashlib
                authorization=self.headers.get('Authorization')
                _,ref=lab.principal(authorization)
                before=dict(lab.sessions.get(ref,{}))
                status,body=lab.logout(authorization,data)
                trace='lab_'+uuid.uuid4().hex
                lab.receipt(trace,'POST',path,status,bool(authorization),ref is not None)
                lab.record_session_state(trace,authorization,before)
                lab.receipts[-1]['response_sha256']=hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest()
                return self._reply(status,body,trace)
            if function:
                import hashlib
                before = dict(lab.state)
                authorization = self.headers.get('Authorization')
                alias,credential = lab.principal(authorization)
                status,body = lab.toggle(authorization,data)
                trace = 'lab_' + uuid.uuid4().hex
                lab.receipt(trace,'POST',path,status,bool(authorization),alias is not None)
                lab.receipts[-1].update({'principal_alias':alias,'role':lab.roles.get(alias),
                    'credential_ref':credential, 'response_sha256':hashlib.sha256(json.dumps(body,sort_keys=True).encode()).hexdigest(),
                    'state_before':{'evidence_ref':'state_'+trace+'_before','session_id':lab.run_id,'trace_id':trace,**before},
                    'state_after':{'evidence_ref':'state_'+trace+'_after','session_id':lab.run_id,'trace_id':trace,**lab.state}})
                return self._reply(status,body,trace)
            status, body = lab.login(data)
            trace = 'lab_' + uuid.uuid4().hex
            lab.receipt(trace, 'POST', '/login', status, False, False)
            self._reply(status, body, trace)

    server = ThreadingHTTPServer((bind_host, port), Handler)
    server.training_lab = lab
    return server


def validate_baseline_artifacts(traffic, contexts, session, receipts, *, host, port):
    """Verify real local backend receipts against sanitized captured transactions."""
    run_id = session['session_id']
    if traffic.get('session_id') != run_id or contexts.session_id != run_id:
        raise ValueError('Session ownership mismatch')
    transactions = traffic.get('transactions', [])
    matches = {}
    for path, method in [('/login', 'POST'), ('/profile', 'GET')]:
        selected = [t for t in transactions if t.get('request', {}).get('path') == path and
                    t.get('request', {}).get('method') == method]
        if len(selected) != 1:
            raise ValueError('Exactly one observed login and profile required')
        tx = selected[0]
        req, resp = tx['request'], tx.get('response')
        if any(item.get('synthetic') or item.get('internal') for item in (tx, req, resp or {})):
            raise ValueError('Synthetic/internal traffic cannot be baseline evidence')
        if (req.get('scheme'), req.get('host'), req.get('port')) != ('http', host, port):
            raise ValueError('Lab endpoint authority mismatch')
        if tx.get('session_id') != run_id or not resp or resp.get('status_code') != 200:
            raise ValueError('Real successful baseline response missing')
        if req.get('headers', {}).get('x-lab-run-id') != run_id:
            raise ValueError('Request run ownership mismatch')
        trace = resp.get('headers', {}).get('x-lab-trace-id')
        records = [r for r in receipts if r['trace_id'] == trace and r['run_id'] == run_id and
                   r['path'] == path and r['method'] == method and r['status'] == 200]
        if len(records) != 1 or records[0].get('source') != 'local_training_backend_actual_response':
            raise ValueError('Response not backed by actual local server receipt')
        if path == '/profile' and (not records[0]['auth_present'] or not records[0]['auth_valid'] or
                                  req.get('headers', {}).get('authorization') != '[REDACTED]'):
            raise ValueError('Observed authenticated baseline missing')
        if path == '/login':
            if req.get('body') != {'auth_user': '[REDACTED]', 'password': '[REDACTED]'} or resp.get('body', {}).get('access_token') != '[REDACTED]':
                raise ValueError('Credentials/token not safely redacted')
        elif resp.get('body', {}).get('authenticated') is not True or resp.get('body', {}).get('purpose') != 'read_only_training_profile':
            raise ValueError('Authenticated response shape/purpose not supported')
        matches[path] = tx
    protected = matches['/profile']
    endpoints = [e for e in contexts.endpoints if e.path == '/profile' and
                 protected['transaction_id'] in e.evidence_refs.get('transaction_ids', [])]
    if len(endpoints) != 1 or not endpoints[0].dynamic.get('observed') or not endpoints[0].auth.get('authorization_header_present'):
        raise ValueError('Canonical authenticated EndpointContext missing')
    endpoint = endpoints[0]
    if (endpoint.scheme, endpoint.host, endpoint.port) != ('http', host, port) or endpoint.methods != ['GET']:
        raise ValueError('Canonical endpoint identity mismatch')
    return {'session_id': run_id, 'endpoint_context_id': endpoints[0].endpoint_context_id,
            'login_transaction_ref': matches['/login']['transaction_id'],
            'login_request_ref': matches['/login']['request']['request_id'],
            'protected_transaction_ref': protected['transaction_id'],
            'protected_request_ref': protected['request']['request_id'],
            'login_response_ref': matches['/login']['response']['headers']['x-lab-trace-id'],
            'protected_response_ref': protected['response']['headers']['x-lab-trace-id'],
            'authorization_presence': True, 'eligible_baseline': True,
            'source': 'controlled_local_lab_real_capture', 'security_test_executed': False}
