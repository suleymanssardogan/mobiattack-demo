# D16 — Dynamic wait/timeout audit

Read-only source audit plus seven synthetic probes. No emulator/network activity,
real sleep, runtime refactor, hooks, report semantics, Static or Agent changes.
The current branch was clean and synchronized with origin/main before the audit.
`wait_inventory.json` gives every classified executable site, source line, expression,
necessity, problem, preferred condition and deadline role, plus source fingerprints.
`audit_waits.py` reproduces the inventory without executing the Dynamic pipeline.

## Counting

Unique executable source sites, exclusive primary classification. Delegated timeout
calls and their implementation sites are separately counted; these are not 71
independent timeout policies. Signatures/default declarations/comments are excluded.
UI observation and the shared dump_window_hierarchy helper are included because
Dynamic uses them. Play Store acquisition waits, security executor, Static and Agent
are outside this audit. Session/route/correlation code has no hidden sleep loops;
the traffic correlator's 5000ms marker window is explicitly temporal attribution,
not a wait and not proof of causality.

| Classification | Sites |
|---|---:|
| FIXED_SLEEP | 2 |
| STATE_WAIT | 6 |
| POLLING_LOOP | 4 |
| SAFETY_DEADLINE | 71 |
| RETRY_BACKOFF | 2 |
| UNKNOWN | 7 |

RETRY_BACKOFF identifies the bounded action retry loop and the attempt-triggered
single relaunch: neither currently implements a timed backoff. UNKNOWN explicitly
covers unbounded/inherited I/O, cleanup and the non-wait correlation window.

## Transition table

| Area | Current behavior | Problem | Preferred state/event |
|---|---|---|---|
| Install completion | Synchronous ADB exit + Success; package inspection; legacy skip-install branch | Timeout is command bound; ALREADY_EXISTS/skip is not version proof | Keep ADB completion, verify intended package/version; install deadline only ceiling |
| App launch | am start -W, then PID/crash/foreground checks | Attempt 2 can trigger relaunch regardless of proven recoverable condition | Confirm launch result and readiness/recoverable state; retain one-relaunch limit |
| Foreground verification | Poll window/activity state; honest presence-only fallback | Outer 8s deadline does not bound several independent 8s ADB calls | Fresh foreground state; remaining deadline propagated to each query |
| Process/PID appearance | Current preflight re-queries PID, legacy caches first PID | Legacy can retain a PID after process death; command failure conflates unavailable/missing observation | Refresh PID and observation availability; detect actual exit/crash |
| Activity transition | Observe target package/system dialog after action | Same target package or valid XML does not prove the action finished; stale hierarchy may be accepted | Fresh action-relative hierarchy/activity condition, including legitimate no-navigation actions |
| UI action completion | ADB returncode 0 → succeeded, then 0.2s settle sleep | Input dispatch is not semantic completion; retry after timeout can duplicate tap/text | State postcondition first; no blind retry for ambiguous non-idempotent input |
| Traffic availability | Backend event/liveness + visibility metadata; proxy put command result | Emulator host reachability assumed; proxy write is not readback verification | Ready/exit event, proxy readback; preserve HTTPS verification from real capture |
| Transaction arrival | Callback storage, marker then one get_transactions_since read before UI observation | Delayed responses can miss the action snapshot; empty does not imply no network | Bounded event/watermark or drain condition with explicit late/in-flight/unknown coverage |
| Exploration completion | No actions, max steps/depth, boundary and 60s deadline | Deadline checked only between whole action/runtime/UI steps | Keep state/coverage stop reasons; propagate remaining budget inside steps |
| Proxy/backend readiness | Native bind/thread start; mitm sleep 0.6s then real ready Event.wait(5s) | Extra startup delay; native lacks ready acknowledgement; readers start after sleep | Start readers immediately; ready/error/exit condition; deadline only ceiling |
| Shutdown/cleanup | TERM wait(4s), kill then unbounded wait(); bounded reader joins; native shutdown then join | communicate()/kill wait()/shutdown and client body I/O can block; join timeout does not prove evidence drained | Bounded process exit/drain/shutdown acknowledgement; record partial cleanup rather than assume completion |

Native server serve_forever uses the standard inherited 0.5s polling default, not
an app readiness sleep. Upstream HTTP uses a 3s socket timeout: this is necessary
but does not bound total response duration (slow/trickling data), incoming client
body reads or writes. Stop paths do not have a single total cleanup budget.
CA inspection has a 3s OpenSSL timeout and delegated ADB bounds; scanning matching
certificate files is count-bounded, without a total elapsed-time deadline.
Runtime observer PID helpers inherit an 8s ADB bound independently of its configured
5s observation timeout. Exploration's 60s deadline can be exceeded by a single
nested action/runtime/UI step. These bounds should remain, capped by one monotonic
remaining budget instead of being treated as readiness evidence.

## Existing correct behavior

- Preflight returns immediately on PID + foreground or crash/death; presence-only
  fallback does not claim foreground. The 0.5s sleeper paces checks, not assumed readiness.
- UI observation returns on target package/known dialog and retries unavailable dumps
  with 0.4s pacing; it is state-driven, although action-specific freshness is missing.
- Mitmproxy requires a real addon-ready event and live process, and consumes transaction/
  TLS-failure events. The initial 0.6s sleep alone never approves readiness or HTTPS.
- Exploration stops on explicit state/budget limits and preserves partial/unavailable
  evidence. Action/traffic correlation remains observational, not causal.
- Install/tool subprocess timeouts, socket bounds and graceful cleanup deadlines
  are necessary safety controls; they must not all be removed.

## Probes and D17 priorities

Seven tests passed, zero failed (`tests/test_dynamic_wait_audit.py` only): inventory
coverage/repeatability; exact fixed-sleep sites; immediate runtime-ready return;
24s nested runtime work despite an 8s outer deadline; 33s UI return despite a 4s
outer deadline; timeout-triggered duplicate input dispatch; unbounded cleanup sites
and one-shot pre-UI traffic read. Fake clocks, fake runners and mocks were used;
no real commands, transport or sleep. Current problematic behavior is documented,
not accepted as a future implementation contract.

D17 priorities:
1. One monotonic operation deadline, remaining-budget propagation and cancellable
   nested observations/actions/cleanup; retain command and socket safety bounds.
2. Replace settle sleep with fresh action-specific UI state; coordinate bounded
   transaction events/drain/watermarks and preserve late/unknown coverage.
3. Retry ambiguous UI dispatch only after checking postcondition; use backend
   ready/exit/drained acknowledgements with bounded cleanup, without invasive hooks.

No fixes were implemented in D16.
