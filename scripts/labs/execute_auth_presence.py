"""One local D10.3 variant using the existing, validated D10.2 evidence.

Restarting the fixture does not reauthenticate or replay the baseline. The
comparison explicitly records its historical nature. Existing files are untouched.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import threading
import uuid

from scripts.labs.auth_baseline_lab import TrainingAuthLab, make_server, validate_baseline_artifacts, TRAINING_ACCOUNT, TRAINING_PASSWORD
from src.dynamic.context.models import EndpointContextArtifact
from src.dynamic.security.authentication_presence import LocalLabAuthenticationPresence
from src.dynamic.security.contracts import DynamicTestRequest, DynamicValidationResult, EvidenceReference, validate_result
from src.dynamic.security.executor import DeterministicSecurityExecutor
from src.dynamic.runtime.models import utc_now_iso
from src.dynamic.traffic.normalizer import sanitize_transaction_data


def atomic_json(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp.' + uuid.uuid4().hex)
    try:
        temporary.write_text(json.dumps(data, indent=2, sort_keys=True)+'\n')
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def load_baseline(directory):
    directory = Path(directory)
    read = lambda name: json.loads((directory/name).read_text())
    manifest = read('baseline.json')
    traffic = read('dynamic/traffic.json')
    contexts = EndpointContextArtifact.load(directory/'dynamic/endpoint_contexts.json')
    session = read('dynamic/session.json')
    receipts = read('lab_receipts.json')
    if not manifest.get('eligible_baseline') or manifest.get('lab_http_port') != 18081:
        raise ValueError('Existing eligible local lab baseline required')
    matching = [c for c in contexts.endpoints if c.endpoint_context_id == manifest['endpoint_context_id']]
    if len(matching) != 1:
        raise ValueError('Canonical context missing or duplicated')
    context = matching[0]
    verified = validate_baseline_artifacts(traffic, contexts, session, receipts, host=context.host, port=18081)
    if any(manifest.get(key) != value for key, value in verified.items()):
        raise ValueError('Baseline manifest disagrees with canonical evidence')
    tool = read('lab_acquisition_result.json')
    if (tool.get('evidence_ref'), tool.get('session_id'), tool.get('endpoint_context_id'), tool.get('source'), tool.get('status')) != (manifest['tool_result_ref'], session['session_id'], context.endpoint_context_id, 'live_android_ui_local_backend_capture', 'completed'):
        raise ValueError('Baseline tool ownership mismatch')
    matches = [t for t in traffic['transactions'] if t['transaction_id'] == manifest['protected_transaction_ref']]
    if len(matches) != 1:
        raise ValueError('Baseline transaction missing or duplicated')
    return manifest, context, matches[0], session


def execute(baseline_dir='examples/auth_lab_d10_2', out='examples/auth_presence_d10_3'):
    manifest, context, baseline, session = load_baseline(baseline_dir)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)  # A completed run is never overwritten/replayed.
    session_id = session['session_id']
    registry = {}
    for ref, kind in [(manifest['protected_request_ref'], 'request'), (manifest['protected_response_ref'], 'response'),
                      (context.endpoint_context_id, 'context'), (session_id, 'runtime'), (manifest['tool_result_ref'], 'tool')]:
        registry[ref] = EvidenceReference(ref, context.endpoint_context_id, kind, session_id)
    request = DynamicTestRequest(
        test_id='AUTHENTICATION_PRESENCE', endpoint_context_id=context.endpoint_context_id,
        test_category='authentication_presence', purpose='Check expected authentication enforcement in the local training fixture',
        required_evidence_refs=tuple(registry), requested_action='validate_authentication_presence', risk_class='low', session_id=session_id)
    lab = TrainingAuthLab(session_id)  # No token regenerated, login or baseline replay.
    server = make_server(context.host, 18081, lab)
    backend = LocalLabAuthenticationPresence(server=server, receipts=lab.receipts, baseline=baseline, context=context, session_id=session_id)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        execution = DeterministicSecurityExecutor(auth_backend=backend).execute(request, context, registry, session_id=session_id)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)
    if execution.execution_status == 'completed':
        validation = backend.validate(request, execution)
        registry = backend.evidence
        transaction = sanitize_transaction_data(backend.transaction.to_dict())
    else:
        validation = DynamicValidationResult(
            test_id=request.test_id, endpoint_context_id=context.endpoint_context_id, session_id=session_id,
            outcome='inconclusive', evidence_refs=tuple(registry), criterion='insufficient_evidence',
            coverage='unavailable', created_at=utc_now_iso())
        transaction = None
        validate_result(request, execution, validation, registry)
    artifacts = {
        'test_request.json': request.to_dict(), 'execution_result.json': {'evidence_ref': backend.execution_ref, **execution.to_dict()},
        'validation_result.json': validation.to_dict(), 'comparison.json': backend.comparison,
        'variant_transaction.json': transaction, 'baseline_transaction.json': sanitize_transaction_data(baseline),
        'endpoint_context.json': context.to_dict(), 'session_evidence.json': session,
        'lab_receipts.json': lab.receipts, 'evidence_registry.json': {k:asdict(v) for k,v in registry.items()},
        'provenance.json': {'baseline_artifact': 'examples/auth_lab_d10_2/dynamic/traffic.json',
            'baseline_acquisition_ref': manifest['tool_result_ref'], 'session_mode': 'historical_baseline_continuation',
            'fixture_restarted': True, 'fresh_authenticated_baseline_sent': False,
            'fixture_sha256': hashlib.sha256(Path('scripts/labs/auth_baseline_lab.py').read_bytes()).hexdigest(),
            'execution_source': 'bound_local_http_server_and_deterministic_executor', 'finding_generated': False},
    }
    serialized = json.dumps(artifacts)
    if TRAINING_ACCOUNT in serialized or TRAINING_PASSWORD in serialized or lab._tokens:
        raise ValueError('Unexpected credential persistence or fresh login')
    if len(lab.receipts) > 1 or (transaction is not None and len(lab.receipts) != 1):
        raise ValueError('More than one variant response observed')
    for name, data in artifacts.items():
        atomic_json(out/name, data)
    report = {'status': 'PASS' if execution.execution_status == 'completed' and validation.outcome == 'validated' else 'PARTIAL',
              'baseline_status': baseline['response']['status_code'], 'variant_status': transaction['response']['status_code'] if transaction else None,
              'controlled_variant_sent': backend.used, 'real_response_observed': transaction is not None,
              'outcome': validation.outcome, 'secret_persisted': False, 'finding_generated': False,
              'evidence_complete': transaction is not None, 'execution_status': execution.execution_status}
    atomic_json(out/'summary.json', report)
    print(json.dumps(report))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--baseline', default='examples/auth_lab_d10_2')
    parser.add_argument('--out', default='examples/auth_presence_d10_3')
    args = parser.parse_args()
    execute(args.baseline, args.out)
