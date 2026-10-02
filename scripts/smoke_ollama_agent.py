"""One existing synthetic context, real local inference, deterministic policy only.

Run with PYTHONPATH=. python scripts/smoke_ollama_agent.py.
Configuration uses MOBIATTACK_OLLAMA_{BASE_URL,MODEL,TIMEOUT}. No download/fallback.
"""
import json
from pathlib import Path
from datetime import datetime, timezone

from src.agent.ollama_model_client import OllamaModelClient, OllamaClientError
from src.agent.context_analyst import analyze_endpoint_context
from src.agent.context_analyst.input_builder import build_context_analyst_input
from src.agent.test_planner import plan_endpoint_tests
from src.agent.policy import EvidenceRecord, _REFERENCE_TYPES
from src.agent.policy_integration import evaluate_test_plan
from src.dynamic.context.models import EndpointContext


def main(*, output_path=None):
    root = Path(__file__).resolve().parents[1]
    output = (root / output_path).resolve() if output_path else root / 'examples/task_9_6/smoke_result.json'
    if not output.is_relative_to(root / 'examples'):
        raise ValueError('Smoke output must remain in workspace examples')
    result = dict(status='BLOCKED', model=None, ollama_version=None, local_available=False,
                  context_analyst='NOT_RUN', test_planner='NOT_RUN', policy_gate='NOT_RUN',
                  hypotheses_count=0, proposals_count=0, allow_count=0, deny_count=0, needs_evidence_count=0,
                  synthetic_case='case_001', model_calls=0, policy_model_calls=0,
                  no_executor=True, no_active_api_testing=True, no_finding=True, no_poc=True)
    try:
        client = OllamaModelClient.from_env()
        result['model'] = client.model
        def get(path):
            with client._opener.open(client.base_url+path, timeout=5) as response:
                return json.loads(response.read(262145))
        result['ollama_version'] = get('/api/version')['version']
        names = {m['name'] for m in get('/api/tags')['models']}
        if client.model not in names:
            raise OllamaClientError('MODEL_UNAVAILABLE')
        result['local_available'] = True
        transport = client
        class ObservedClient:
            def generate(self, request):
                try:
                    return transport.generate(request)
                except OllamaClientError as exc:
                    result['client_error'] = exc.code
                    raise
        client = ObservedClient()
        raw = json.loads((root/'benchmarks/agent_v1/cases/case_001.json').read_text())
        endpoint = EndpointContext(**raw['endpoint_context'])
        source = build_context_analyst_input(endpoint, coverage_metadata=raw['coverage_metadata'])
        # Only the trusted synthetic fixture's refs enter the evidence resolver;
        # never obtain evidence or prerequisite satisfaction from LLM output.
        index = {}
        for ref in source.evidence_universe:
            path, _, fragment = ref.partition('#')
            typ = _REFERENCE_TYPES.get((path, fragment.partition('=')[0]))
            if typ: index[ref] = EvidenceRecord(ref, endpoint.endpoint_context_id, typ[0])
        now = datetime.now(timezone.utc).isoformat()
        print('Context Analyst: real local Qwen inference started', flush=True)
        analyst = analyze_endpoint_context(endpoint, client, coverage_metadata=raw['coverage_metadata'], created_at=now)
        result.update(context_analyst='PASS' if analyst.status=='completed' else 'FAIL',
                      analyst_status=analyst.status, analyst_attempts=analyst.attempts,
                      hypotheses_count=len(analyst.hypotheses), analyst_errors=list(analyst.validation_errors),
                      analyst_metadata=analyst.to_dict()['model_metadata'], model_calls=analyst.attempts)
        if analyst.status != 'completed':
            return finish(output, result)
        print('Test Planner: validated Analyst result → real local Qwen', flush=True)
        planner = plan_endpoint_tests(endpoint, analyst, client, coverage_metadata=raw['coverage_metadata'], created_at=now)
        result.update(test_planner='PASS' if planner.status in {'completed','no_relevant_tests'} and planner.attempts else 'FAIL',
                      planner_status=planner.status, planner_attempts=planner.attempts,
                      proposals_count=len(planner.proposals), planner_errors=list(planner.validation_errors),
                      planner_metadata=planner.to_dict()['model_metadata'], model_calls=analyst.attempts+planner.attempts)
        if result['test_planner'] != 'PASS':
            return finish(output, result)
        policy = evaluate_test_plan(endpoint, analyst, planner, index, created_at=now)
        again = evaluate_test_plan(endpoint, analyst, planner, index, created_at=now)
        deterministic = policy == again
        result.update(policy_gate='PASS' if deterministic and policy.status in {'evaluated','no_proposals'} else 'FAIL',
                      policy_version=policy.policy_version, policy_status=policy.status,
                      allow_count=policy.allow_count, deny_count=policy.deny_count,
                      needs_evidence_count=policy.needs_evidence_count, policy_deterministic=deterministic)
        if result['policy_gate'] == 'PASS': result['status'] = 'PASS'
    except OllamaClientError as exc:
        result['error'] = exc.code
    except Exception:
        result['error'] = 'LOCAL_SMOKE_ERROR'
    return finish(output, result)


def finish(path, result):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    temp.replace(path)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['status']=='PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
