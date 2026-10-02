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
