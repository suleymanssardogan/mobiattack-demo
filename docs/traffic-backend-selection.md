# Dynamic capture backend selection

The demo, web demo, and capture service default to `https`, which selects
`MitmproxyCaptureBackend`. Missing mitmproxy is a capability failure, never an
automatic switch to HTTP-only capture.

Use `--traffic-mode native_http` for explicit cleartext-only capture, or
`traffic_mode="native_http"` in the demo API. Invalid modes are rejected before
acquisition. `dynamic/traffic_backend.json` records the selected mode and backend;
`dynamic/traffic.json` and the canonical Dynamic report preserve backend identity
including capture startup failures.

For a provisioned environment outside PATH, set `MITMPROXY_PATH` (or
`MITMDUMP_PATH`) to its existing executable. Set `MITMPROXY_CA_DIR` to its existing
CA directory when needed. For example, from the repository root:

```sh
MITMPROXY_PATH="$PWD/workspaces/tools/mitmproxy/venv/bin/mitmdump" \
MITMPROXY_CA_DIR="$PWD/workspaces/tools/mitmproxy/ca" \
python scripts/run_web_demo.py --port 18083 --traffic-proxy-port 18080 --traffic-mode https
```

Restart an already-running demo to load the changed wiring/configuration.
Backend readiness is not proof of app HTTPS visibility. Existing app-scoped
trust/pinning classifications and real transaction requirements remain in force.
No CA is installed by backend selection.
