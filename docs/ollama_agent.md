# Local Ollama AgentModelClient

Use `OllamaModelClient` from `src.agent.ollama_model_client` with the existing
`analyze_endpoint_context` and `plan_endpoint_tests` functions. Policy integration
remains an explicit deterministic call after validation. Nothing executes proposals.

Defaults: `http://127.0.0.1:11434`, `qwen2.5:7b`, 120 seconds. The selected existing
7B Q4_K_M model is appropriate for this machine's 24 GB memory; no model was downloaded.

Constructor keyword arguments: `base_url`, `model`, `timeout` (1–300 seconds).
`OllamaModelClient.from_env()` reads `MOBIATTACK_OLLAMA_BASE_URL`,
`MOBIATTACK_OLLAMA_MODEL`, and `MOBIATTACK_OLLAMA_TIMEOUT`.
Only loopback hosts are accepted. HTTP proxies and redirects are disabled.
The adapter posts the existing prompt/input/schema to `/api/chat`, disables streaming
and thinking, and sends no tools or credentials. It retains only content and canonical
metadata. Large string length constraints are omitted only from the Ollama grammar
(the current runner cannot compile those repetitions); the unchanged canonical schema
remains in the prompt and runtime validators enforce all original length bounds.
Provider envelopes are bounded; existing runtimes validate output and own
bounded retries. No raw response or thinking transcript is logged/persisted.

Run the single existing synthetic fixture smoke with:

```bash
PYTHONPATH=. python scripts/smoke_ollama_agent.py
```

The smoke uses case_001, sends no expected labels, performs no scoring, and writes
only safe status/count/metadata fields to `examples/task_9_6/smoke_result.json`.
Missing Ollama/model or invalid output returns BLOCKED; no fake fallback or download.
No executor, network security tests, findings, PoC, public stage completion or Agent Report.

Protocol: [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs).
