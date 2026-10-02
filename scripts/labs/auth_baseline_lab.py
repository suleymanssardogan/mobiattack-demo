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
            if path != '/profile':
                return self._reply(404, {'error': 'unknown_lab_path'})
            if self.headers.get('X-Lab-Run-ID') != lab.run_id:
                return self._reply(403, {'error': 'run_ownership_mismatch'})
            authorization = self.headers.get('Authorization')
            status, body = lab.profile(authorization)
            trace = 'lab_' + uuid.uuid4().hex
            lab.receipt(trace, 'GET', path, status, bool(authorization), status == 200)
            self._reply(status, body, trace)

        def do_POST(self):
            if not self._permitted():
                return self._reply(403, {'error': 'host_proxy_only'})
            if urlsplit(self.path).path != '/login':
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
            status, body = lab.login(data)
            trace = 'lab_' + uuid.uuid4().hex
            lab.receipt(trace, 'POST', '/login', status, False, False)
            self._reply(status, body, trace)

    return ThreadingHTTPServer((bind_host, port), Handler)


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
