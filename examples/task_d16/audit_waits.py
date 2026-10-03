"""Read-only AST inventory of executable Dynamic wait sites, never run the pipeline."""
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
AREAS=('preflight','session','route','action','exploration','runtime','traffic','correlation','ui')
CLASSES={'SAFETY_DEADLINE','STATE_WAIT','RETRY_BACKOFF','FIXED_SLEEP','POLLING_LOOP','UNKNOWN'}


def inventory():
    files=sorted({p for area in AREAS for p in (ROOT/'src/dynamic'/area).rglob('*.py')} |
                 {ROOT/'src/android_runtime_launcher.py',ROOT/'src/android_runtime_inspector.py',ROOT/'src/play_store_ui_automator.py'})
    records=[]
    def add(path,node,kind,necessary,problem,preferred,boundary):
        records.append(dict(file=str(path.relative_to(ROOT)),line=node.lineno,classification=kind,
            expression=ast.unparse(node),necessary=necessary,problem=problem,
            preferred_state_event=preferred,deadline_role=boundary))
    for path in files:
        tree=ast.parse(path.read_text())
        for node in ast.walk(tree):
            # Only the shared UI dump helper is a Dynamic dependency; Play Store
            # acquisition/install waits are outside D16, not silently counted here.
            if path.name=='play_store_ui_automator.py' and not (121<=getattr(node,'lineno',0)<178):continue
            if isinstance(node,ast.Call):
                name=ast.unparse(node.func)
                keys={k.arg for k in node.keywords}
                if name in {'time.sleep','sleeper'}:
                    fixed=path.name=='mitmproxy_backend.py' or 'action_settle_delay' in ast.unparse(node)
                    add(path,node,'FIXED_SLEEP' if fixed else 'STATE_WAIT',not fixed,
                        'Elapsed time is not readiness.' if fixed else 'Poll pacing; nested commands can exceed outer remaining time.',
                        'Backend ready/exit event.' if path.name=='mitmproxy_backend.py' else 'PID/foreground/crash or fresh action-specific UI condition.',
                        'control_logic' if fixed else 'poll_pacing')
                elif name.endswith('._bridge_ready.wait'):
                    add(path,node,'STATE_WAIT',True,'Ready event is checked, but startup sleep precedes readers.',
                        'Keep ready event and process-exit detection; propagate remaining budget.','safety_ceiling')
                elif name in {'subprocess.run','self._runner','run_adb_cmd','http.client.HTTPConnection'} or name.endswith('.settimeout') or (
                    keys & {'timeout','timeout_seconds'} and name not in {'self.stop'}):
                    add(path,node,'SAFETY_DEADLINE',True,'Per-command/socket bound; not a total operation deadline.',
                        'Command exit/real response/thread exit; cap each wait by remaining parent budget.','safety_boundary')
                elif name.endswith(('.communicate','.wait','.shutdown')) or name in {'self.rfile.read','upstream_resp.read','self.wfile.write'}:
                    add(path,node,'UNKNOWN',True,'Potential blocking I/O/cleanup without a local total deadline.',
                        'EOF/drain or verified shutdown with bounded cancellation/join.','missing_or_inherited_bound')
                elif name=='threading.Thread' and any(k.arg=='target' and 'serve_forever' in ast.unparse(k.value) for k in node.keywords):
                    add(path,node,'POLLING_LOOP',True,'HTTPServer inherited serve_forever poll_interval defaults to 0.5s; no explicit ready acknowledgement.',
                        'Verified listen/serve-ready state; shutdown event acknowledgement.','inherited_poll_pacing')
            elif isinstance(node,ast.While):
                condition=ast.unparse(node.test)
                if 'max_attempts' in condition and path.name=='executor.py':
                    add(path,node,'RETRY_BACKOFF',True,'Immediate retry on timeout/error, without backoff or checking whether input was applied.',
                        'Check action postcondition before retrying non-idempotent UI input.','attempt_cap_not_total_deadline')
                elif 'clock()' in condition or 'time.monotonic()' in condition:
                    add(path,node,'POLLING_LOOP',True,'Predicate is state-driven but checked only between blocking commands.',
                        'Refresh PID/foreground/fresh hierarchy, cap nested calls by remaining monotonic deadline.','safety_ceiling_plus_attempt_cap')
            elif isinstance(node,ast.If):
                condition=ast.unparse(node.test)
                if 'cfg.deadline_seconds' in condition:
                    add(path,node,'SAFETY_DEADLINE',True,'Exploration deadline only checked between complete steps.',
                        'Keep max steps/depth/exhaustion and interruptible remaining-budget checks inside step.','safety_boundary')
                elif 'attempt >= 2' in condition and 'relaunch_fn' in condition:
                    add(path,node,'RETRY_BACKOFF',False,'Relaunch is triggered by attempt count rather than a confirmed recoverable launch state.',
                        'Verified launch failure/recoverable state; preserve single-relaunch cap.','control_logic')
            elif isinstance(node,ast.For) and any(s in ast.unparse(node.iter) for s in ('self.process.stdout','self.process.stderr')):
                add(path,node,'STATE_WAIT',True,'Blocking stream iteration until event/EOF; bounded joins do not prove drain completed.',
                    'Keep event-driven stream consumption; acknowledge EOF/drained before artifact finalization.','event_stream_with_cleanup_bound')
            elif isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='MARKER_CORRELATION_WINDOW_MS' for t in node.targets):
                add(path,node,'UNKNOWN',True,'5000ms attribution window is temporal correlation policy, not an execution wait or causal proof.',
                    'Preserve observation timestamps and explicit non-causal attribution; not a readiness timeout.','correlation_window_not_wait')
    records.sort(key=lambda r:(r['file'],r['line'],r['classification']))
    return {'counting_rule':'Unique executable source sites (including delegated timeout sites), not elapsed seconds or runtime invocation counts. Defaults/docstrings/pass-through signatures excluded; classification is exclusive per site.',
        'scope':'Dynamic focus areas plus UI observer, live legacy launcher/inspector, and shared dump_window_hierarchy only. Security executor/Static/Agent/acquisition waits excluded.',
        'source_fingerprints':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
        'counts':dict(sorted(Counter(r['classification'] for r in records).items())),
        'occurrences':records}

if __name__=='__main__':
    result=inventory()
    Path(__file__).with_name('wait_inventory.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result['counts'],sort_keys=True))
