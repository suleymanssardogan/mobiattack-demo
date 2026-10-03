# Controlled authenticated baseline lab

Test infrastructure only. This standard-library HTTP fixture serves a fixed
public training account, `POST /login`, and read-only `GET /profile`. The latter
requires an issued bearer token. Tokens exist only in memory, and a lab instance
permits one successful login. No MobiAttack security executor is invoked.

Run from the repository root with the host's private IPv4 address:

```sh
python -m scripts.labs.acquire_auth_baseline --bind <host-private-IP> --out <new-artifact-directory>
```

Requires an existing authorized emulator and Chrome. Backend port is 18081;
existing NativeProxyCaptureBackend uses 18080. The backend accepts host/proxy
connections only. The Android browser loads a local training page, and the
existing UI executor clicks its single login/profile button. Servers stop and
the prior device proxy is restored after acquisition.

Fixtures are defined in `auth_baseline_lab.py`. Login uses `auth_user` and
`password`, both covered by the existing sanitizer. Credentials and returned
token values are never written to scan artifacts. The browser uses no token
storage or retries. Only normal login and authenticated read requests are sent.

Artifacts contain canonical traffic, action evidence, correlations and endpoint
contexts, plus safe lab receipt and baseline-reference metadata. Response trace
references are actual upstream header values, resolved through captured responses
and `lab_receipts.json`; they are not invented canonical response-ID fields.
Session run headers and server trace receipts bind the lab evidence. Generic
proxy attribution remains a time-window observation, not a causal guarantee.

READY means a baseline is available for a later auth-presence test. It is not a
validation result, execution approval, finding or PoC. No missing-auth variant
is sent. Server authorization behavior is checked with focused unit tests.

D21 object authorization lab is separate from the Android auth-baseline flow.
`python -m scripts.labs.execute_object_authorization --out <new-directory>` binds
an ephemeral loopback HTTP server, authenticates training principal A, observes
its successful `/orders/1001` baseline, and sends exactly one `/orders/2002`
variant with unchanged authentication. Resource ownership is recorded from the
fixed lab configuration (A owns 1001, B owns 2002). A real 403 plus the matching
lab denial representation confirms enforcement; status alone is insufficient.
Both principals' authenticated own-resource reads are covered by focused tests.

Tokens remain in memory. Persisted receipts use opaque credential references;
artifacts contain sanitized requests/responses, ownership evidence, execution,
validation, canonical Dynamic report and compact summary. Android UI/runtime
coverage stays unavailable in this host-only smoke. Reports never create a
finding. `finalize_report(path)` regenerates the report offline without sending
another variant. This backend cannot dispatch to a public target, arbitrary
resource, or generic request transport.

D22 uses `python -m scripts.labs.execute_function_authorization --out <new-directory>`.
It creates normal principal A and admin principal B on a fresh loopback server.
The only function is `POST /lab/admin/toggle` with `{"enabled": true}`; its
state is disposable and reset on shutdown. The real B baseline changes revision
0 to 1. One A variant preserves method/path/body and all non-auth headers.
Matching denial plus unchanged state confirms enforcement. A failure result
requires a real A response representing the privileged effect plus bound
pre/post revision evidence. HTTP 200 or an admin-looking path proves neither.
Role/credential aliases, privilege configuration and state refs are sanitized;
raw credentials remain in memory. No finding or public-target execution exists.

D23 uses `python -m scripts.labs.execute_session_invalidation --out <new-directory>`.
A fresh loopback lab issues exactly one generation of A's training credential.
Real `GET /profile` access must succeed before `POST /logout`; logout must
produce a bound server registry transition from active/version 1 to revoked/
version 2. Only then does the existing executor send one identical old-credential
profile request. No refresh/login is performed by the executor. Credentials
remain memory-only; opaque per-credential UUID refs and generation aliases prove
identity across baseline/logout/variant receipts. Expiry is checked independently
so expiration cannot be mislabeled as logout enforcement. A matching real 401
and invalidated-session response confirms enforcement. Proven old-credential
protected access is a failure result, never an automatic finding; generic 200
remains inconclusive. Canonical artifacts retain logout and state refs, while
host-only UI/runtime coverage remains unavailable. No public-target transport,
token mutation, guessing or replay retries are provided.
