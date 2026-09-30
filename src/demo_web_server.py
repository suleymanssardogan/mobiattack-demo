"""Local Web Demo Dashboard Server for MobiAttack-v1.

Provides an interactive browser interface to execute, monitor, visualize,
and inspect detailed analysis results and generated reports without external
CDN dependencies or security verdicts.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import json
from pathlib import Path
import re
import threading
import time
import urllib.parse
import uuid

from src.constants import PRESENTATION_ADB_SERIAL, make_ios_vuln_not_evaluated
from src.demo_orchestrator import DemoOrchestrationError, run_demo
from src.html_probe_server import (
    ProbeServer,
    configure_adb_reverse,
    remove_adb_reverse,
    trigger_device_browser,
)
from src.report_generator import build_report_dict, generate_reports
from src.url_classifier import classify_input_url
from src.play_store_acquirer import open_play_store_on_device
from src.vulnerability_evaluator import evaluate_vulnerabilities
from src.web.template_loader import load_dashboard_html
from src.web.request_helpers import (
    ensure_vulnerabilities,
    parse_json_body,
    send_json,
    send_file,
    serve_run_file,
)


# Backward-compatible alias — legacy code may import HTML_PAGE directly.
# The actual template now lives in src/templates/dashboard.html.
class _LazyHTML:
    """Descriptor that defers template loading until first access."""
    def __repr__(self) -> str:
        return load_dashboard_html()
    def __contains__(self, item: str) -> bool:
        return item in load_dashboard_html()
    def __str__(self) -> str:
        return load_dashboard_html()
    def encode(self, encoding: str = "utf-8") -> bytes:
        return load_dashboard_html().encode(encoding)

HTML_PAGE = _LazyHTML()


# ---------------------------------------------------------------------------
# Request Handler
# ---------------------------------------------------------------------------

class _DemoRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Demo Web Server."""

    def log_message(self, format: str, *args) -> None:
        pass

    def _send_json(self, status_code: int, data: dict) -> None:
        send_json(self, status_code, data)

    @property
    def web_server(self) -> DemoWebServer:
        server_obj = getattr(self, "server", None)
        if server_obj and hasattr(server_obj, "web_server"):
            return server_obj.web_server
        if hasattr(_DemoRequestHandler, "_global_web_server"):
            return _DemoRequestHandler._global_web_server
        import os
        global_srv = DemoWebServer(runs_root=os.environ.get("DEMO_RUNS_DIR", "demo_runs"))
        _DemoRequestHandler._global_web_server = global_srv
        return global_srv

    # ── GET Routes ─────────────────────────────────────────────────

    def do_GET(self) -> None:
        # Path traversal guard
        if ".." in self.path:
            self._send_json(400, {"status": "error", "message": "Invalid path traversal attempt."})
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        server: DemoWebServer = self.web_server

        if path == "" or path == "/index.html":
            self._serve_dashboard()
            return

        # GET /samples/<filename>
        sample_match = re.match(r"^/samples/([a-zA-Z0-9_\-\.]+\.apk)$", path)
        if sample_match:
            self._serve_sample_apk(sample_match.group(1))
            return

        # GET /api/runs/recent
        if path == "/api/runs/recent":
            self._handle_recent_runs(server)
            return

        # GET /api/status/<run_id>
        status_run_id = self._extract_status_run_id(path)
        if status_run_id:
            status_data = server.get_run_status(status_run_id)
            if status_data is None:
                self._send_json(404, {"status": "error", "message": f"Run '{status_run_id}' not found."})
            else:
                self._send_json(200, status_data)
            return

        # GET /api/vulnerabilities/<run_id>
        vuln_api_match = re.match(r"^/api/vulnerabilities/([a-zA-Z0-9_\-]+)$", path)
        if vuln_api_match:
            self._handle_vulnerabilities(vuln_api_match.group(1), server)
            return

        # GET /api/report/<run_id>
        report_api_match = re.match(r"^/api/report/([a-zA-Z0-9_\-]+)$", path)
        if report_api_match:
            self._handle_report_api(report_api_match.group(1), server)
            return

        # GET /reports/<run_id>/report.html
        report_html_match = re.match(r"^/reports/([a-zA-Z0-9_\-]+)/report\.html$", path)
        if report_html_match:
            serve_run_file(
                self, report_html_match.group(1), "report.html",
                "text/html; charset=utf-8", server.get_run_dir,
                label="HTML report",
            )
            return

        # GET /reports/<run_id>/report.json
        report_json_match = re.match(r"^/reports/([a-zA-Z0-9_\-]+)/report\.json$", path)
        if report_json_match:
            rid = report_json_match.group(1)
            serve_run_file(
                self, rid, "report.json",
                "application/json; charset=utf-8", server.get_run_dir,
                disposition_filename=f"report_{rid}.json",
                label="JSON report",
            )
            return

        # GET /reports/<run_id>/baseline_report.json
        baseline_json_match = re.match(r"^/reports/([a-zA-Z0-9_\-]+)/baseline_report\.json$", path)
        if baseline_json_match:
            rid = baseline_json_match.group(1)
            serve_run_file(
                self, rid, "baseline_report.json",
                "application/json; charset=utf-8", server.get_run_dir,
                disposition_filename=f"baseline_report_{rid}.json",
                label="Baseline report",
            )
            return

        self._send_json(404, {"status": "error", "message": "Not Found"})

    # ── POST Routes ────────────────────────────────────────────────

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        server: DemoWebServer = self.web_server

        if path == "/api/classify":
            self._handle_classify()
            return

        if path in ("/api/stop", "/api/cancel"):
            res = server.stop_active_run()
            self._send_json(200, res)
            return

        if path == "/api/open_store":
            self._handle_open_store()
            return

        if path == "/api/run":
            self._handle_run(server)
            return

        if path == "/api/probe":
            self._handle_probe(server)
            return

        self._send_json(404, {"status": "error", "message": "Not Found"})

    # ── Route Implementations ──────────────────────────────────────

    def _serve_dashboard(self) -> None:
        """Serves the main dashboard HTML page."""
        try:
            body = load_dashboard_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _serve_sample_apk(self, apk_filename: str) -> None:
        """Serves a sample APK file from the project root."""
        apk_path = Path(__file__).resolve().parent.parent / apk_filename
        if not apk_path.is_file():
            apk_path = Path(apk_filename).resolve()
        if apk_path.is_file():
            try:
                send_file(self, apk_path, "application/vnd.android.package-archive")
                return
            except Exception as e:
                self._send_json(500, {"status": "error", "message": str(e)})
                return
        self._send_json(404, {"status": "error", "message": f"Sample APK '{apk_filename}' not found."})

    def _extract_status_run_id(self, path: str) -> str | None:
        """Extracts run_id from status endpoint path or query params."""
        status_match = re.match(r"^/api/status/([a-zA-Z0-9_\-]+)$", path)
        if status_match:
            return status_match.group(1)
        if path.startswith("/api/status"):
            query_parts = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            return (query_parts.get("run_id") or [None])[0]
        return None

    def _handle_recent_runs(self, server: DemoWebServer) -> None:
        """Handles GET /api/runs/recent — returns the latest run ID."""
        latest_id = None
        if server._runs:
            latest_id = list(server._runs.keys())[-1]
        else:
            try:
                candidates = []
                if server.runs_root.exists():
                    candidates.extend([d for d in server.runs_root.iterdir() if d.is_dir() and d.name.startswith("run_") and (d / "report.json").exists()])
                repo_runs = (Path(__file__).resolve().parent.parent / "demo_runs").resolve()
                if repo_runs.exists() and repo_runs != server.runs_root.resolve():
                    candidates.extend([d for d in repo_runs.iterdir() if d.is_dir() and d.name.startswith("run_") and (d / "report.json").exists()])
                run_dirs = sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)
                if run_dirs:
                    latest_id = run_dirs[0].name
            except Exception:
                pass
        self._send_json(200, {"status": "ok", "latest_run_id": latest_id})

    def _handle_vulnerabilities(self, run_id: str, server: DemoWebServer) -> None:
        """Handles GET /api/vulnerabilities/<run_id>."""
        status_data = server.get_run_status(run_id)
        if not status_data:
            target_dir = (server.runs_root / run_id).resolve()
            # Try cached findings first, then regenerate from report
            for filename, loader in [
                ("security_findings.json", lambda f: json.load(f)),
                ("report.json", lambda f: evaluate_vulnerabilities(json.load(f))),
            ]:
                fpath = target_dir / filename
                if fpath.exists():
                    try:
                        with open(fpath, "r", encoding="utf-8") as fp:
                            self._send_json(200, loader(fp))
                        return
                    except Exception:
                        pass
            self._send_json(404, {"status": "error", "message": f"Run '{run_id}' not found."})
            return

        res = status_data.get("result") or {}
        vulns = res.get("vulnerabilities") or evaluate_vulnerabilities(res)
        self._send_json(200, vulns)

    def _handle_report_api(self, run_id: str, server: DemoWebServer) -> None:
        """Handles GET /api/report/<run_id> — returns report.json as JSON API."""
        target_dir = server.get_run_dir(run_id)
        if not target_dir:
            self._send_json(404, {"status": "error", "message": f"Report for run '{run_id}' not found."})
            return
        report_file = target_dir / "report.json"
        if not report_file.exists():
            self._send_json(404, {"status": "error", "message": f"Report for run '{run_id}' not found."})
            return
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                report_data = json.load(f)
            self._send_json(200, report_data)
        except Exception as e:
            self._send_json(500, {"status": "error", "message": str(e)})

    def _handle_classify(self) -> None:
        """Handles POST /api/classify — URL classification."""
        try:
            payload = parse_json_body(self)
        except ValueError:
            self._send_json(400, {"status": "error", "message": "Invalid JSON payload."})
            return

        url = payload.get("url", "")
        platform = payload.get("platform", "android")
        classification = classify_input_url(url=url, platform=platform)
        self._send_json(200, classification)

    def _handle_open_store(self) -> None:
        """Handles POST /api/open_store — opens Play Store on device."""
        try:
            payload = parse_json_body(self)
        except ValueError:
            payload = {}

        adb_serial = PRESENTATION_ADB_SERIAL
        url = payload.get("url")
        package_name = payload.get("package_name")
        try:
            res = open_play_store_on_device(serial=adb_serial, package_name=package_name, play_store_url=url)
            self._send_json(200, res)
        except Exception as err:
            self._send_json(500, {"status": "error", "message": str(err)})

    def _handle_run(self, server: DemoWebServer) -> None:
        """Handles POST /api/run — starts a new analysis run."""
        try:
            payload = parse_json_body(self)
        except ValueError:
            self._send_json(400, {"status": "error", "message": "Invalid JSON payload."})
            return

        url = payload.get("url", "")
        if not isinstance(url, str) or not (url.strip().startswith(("http://", "https://", "file://")) or (url.strip().startswith("/") and url.strip().endswith(".ipa"))):
            self._send_json(400, {"status": "error", "message": "A valid http:// or https:// URL is required."})
            return

        platform = payload.get("platform", "android")
        classification = classify_input_url(url=url.strip(), platform=platform)
        if classification.get("type") in ("not_implemented", "unsupported"):
            reason = classification.get("message") or classification.get("reason") or "Unsupported URL or platform."
            self._send_json(400, {
                "status": "error",
                "error": reason,
                "message": reason,
            })
            return

        adb_serial = PRESENTATION_ADB_SERIAL
        reinstall = bool(payload.get("reinstall", True))
        grant_permissions = bool(payload.get("grant_permissions", False))
        install_mode = str(payload.get("install_mode", "manual")).strip().lower()
        if install_mode not in ("manual", "ui_automation"):
            install_mode = "manual"

        try:
            run_id = server.start_run(
                url=url.strip(),
                platform=platform,
                adb_serial=adb_serial,
                reinstall=reinstall,
                grant_permissions=grant_permissions,
                install_mode=install_mode,
            )
            self._send_json(200, {"status": "ok", "run_id": run_id})
        except ValueError as err:
            self._send_json(409, {"status": "error", "message": str(err)})

    def _handle_probe(self, server: DemoWebServer) -> None:
        """Handles POST /api/probe — connectivity probe."""
        try:
            parse_json_body(self)
        except ValueError:
            pass

        adb_serial = PRESENTATION_ADB_SERIAL
        probe_res = server.execute_connectivity_probe(adb_serial=adb_serial)
        self._send_json(200 if probe_res.get("hit") else 500, probe_res)


# ---------------------------------------------------------------------------
# Web Server
# ---------------------------------------------------------------------------

class DemoWebServer:
    """Local Web Server managing live dashboard UI, reporting, and background orchestrations."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080, runs_root: str | Path = "demo_runs") -> None:
        self.host = host
        self._requested_port = port
        self.port: int = port
        self.base_url: str = ""
        self.runs_root = Path(runs_root).resolve()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._runs: dict[str, dict] = {}
        self._active_run_id: str | None = None
        self._last_probe: dict | None = None
        self._running = False

    def start(self) -> None:
        """Starts the local web server on a background daemon thread."""
        if self._running:
            return

        self._server = ThreadingHTTPServer((self.host, self._requested_port), _DemoRequestHandler)
        self._server.web_server = self  # type: ignore
        self.port = self._server.server_port
        self.base_url = f"http://{self.host}:{self.port}"

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._running = True

    def stop(self) -> None:
        """Shuts down web server and releases port."""
        if not self._running or self._server is None:
            return

        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

        self._server = None
        self._running = False

    def start_run(
        self,
        url: str,
        platform: str = "android",
        adb_serial: str | None = None,
        reinstall: bool = True,
        grant_permissions: bool = False,
        install_mode: str = "manual",
    ) -> str:
        """Schedules a new demo run on a background thread. Only one active run permitted."""
        with self._lock:
            if self._active_run_id is not None:
                raise ValueError("Demo already running. Please wait for the current run to complete.")

            run_id = f"run_{int(time.time())}_{uuid.uuid4().hex[:6]}"
            is_ios = str(platform).lower() == "ios"
            self._active_run_id = run_id
            self._runs[run_id] = {
                "run_id": run_id,
                "platform": platform,
                "overall_status": "running",
                "current_stage": "acquisition",
                "stages": {
                    "acquisition": {"state": "running", "message": "Starting IPA acquisition..." if is_ios else "Starting APK acquisition...", "data": None},
                    "preprocessing": {"state": "pending", "message": "Waiting...", "data": None},
                    "static_analysis": {"state": "pending", "message": "Waiting...", "data": None},
                    "runtime": {"state": "skipped" if is_ios else "pending", "message": "iOS runtime analysis is not implemented." if is_ios else "Waiting...", "data": None},
                },
                "error": None,
                "result": None,
            }

        worker = threading.Thread(
            target=self._run_worker,
            args=(run_id, url, platform, adb_serial, reinstall, grant_permissions, install_mode),
            daemon=True,
        )
        worker.start()
        return run_id

    def _run_worker(
        self,
        run_id: str,
        url: str,
        platform: str,
        adb_serial: str | None,
        reinstall: bool,
        grant_permissions: bool,
        install_mode: str = "manual",
    ) -> None:
        run_dir = self.runs_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        def callback(stage: str, state: str, message: str, data: dict | None = None) -> None:
            with self._lock:
                run = self._runs.get(run_id)
                if not run:
                    return

                if stage == "demo" and state == "completed":
                    run["overall_status"] = "completed"
                    if data and "vulnerabilities" not in data:
                        if data.get("platform") == "ios" or str(platform).lower() == "ios":
                            data["vulnerabilities"] = make_ios_vuln_not_evaluated()
                        else:
                            data["vulnerabilities"] = evaluate_vulnerabilities(data)
                    run["result"] = data
                    self._active_run_id = None
                elif state == "failed":
                    run["overall_status"] = "failed"
                    run["current_stage"] = stage
                    if stage in run["stages"]:
                        run["stages"][stage]["state"] = "failed"
                        run["stages"][stage]["message"] = message
                    run["error"] = message
                    self._active_run_id = None
                else:
                    run["current_stage"] = stage
                    if stage in run["stages"]:
                        run["stages"][stage]["state"] = state
                        run["stages"][stage]["message"] = message
                        if data is not None:
                            run["stages"][stage]["data"] = data

        try:
            res = run_demo(
                url=url,
                output_root=run_dir,
                platform=platform,
                adb_serial=adb_serial,
                reinstall=reinstall,
                grant_permissions=grant_permissions,
                progress_callback=callback,
                install_mode=install_mode,
            )
            # Evaluate vulnerabilities
            ensure_vulnerabilities(res)
            try:
                with open(run_dir / "security_findings.json", "w", encoding="utf-8") as vf:
                    json.dump(res["vulnerabilities"], vf, indent=2)
            except Exception:
                pass

            # Generate deterministic reports
            probe_data = None
            with self._lock:
                probe_data = self._last_probe

            generate_reports(
                run_dir=run_dir,
                run_id=run_id,
                pipeline_result=res,
                connectivity_probe=probe_data,
            )
            with self._lock:
                run = self._runs.get(run_id)
                if run:
                    run["report"] = {
                        "json_url": f"/reports/{run_id}/report.json",
                        "html_url": f"/reports/{run_id}/report.html",
                        "baseline_json_url": f"/reports/{run_id}/baseline_report.json",
                        "api_url": f"/api/report/{run_id}",
                    }
        except Exception as exc:
            self._handle_run_failure(run_id, url, platform, adb_serial, reinstall, grant_permissions, run_dir, exc)

    def _handle_run_failure(
        self,
        run_id: str,
        url: str,
        platform: str,
        adb_serial: str | None,
        reinstall: bool,
        grant_permissions: bool,
        run_dir: Path,
        exc: Exception,
    ) -> None:
        """Handles pipeline execution failure — updates state and generates partial report."""
        with self._lock:
            run = self._runs.get(run_id)
            if run and run["overall_status"] != "completed":
                run["overall_status"] = "failed"
                run["error"] = str(exc)
                stage = getattr(exc, "stage", run.get("current_stage", "unknown"))
                if stage in run["stages"]:
                    run["stages"][stage]["state"] = "failed"
                    run["stages"][stage]["message"] = str(exc)
                self._active_run_id = None

                # Generate partial report on failure
                partial_result = {
                    "input": {
                        "url": url,
                        "platform": platform,
                        "adb_serial": adb_serial,
                        "reinstall": reinstall,
                        "grant_permissions": grant_permissions,
                    },
                    "acquisition": run["stages"].get("acquisition", {}).get("data"),
                    "preprocessing": run["stages"].get("preprocessing", {}).get("data"),
                    "static_analysis": run["stages"].get("static_analysis", {}).get("data"),
                    "runtime": run["stages"].get("runtime", {}).get("data"),
                    "demo_status": "failed",
                }
                ensure_vulnerabilities(partial_result)
                try:
                    generate_reports(
                        run_dir=run_dir,
                        run_id=run_id,
                        pipeline_result=partial_result,
                        error=str(exc),
                        current_stage=stage,
                    )
                    run["report"] = {
                        "json_url": f"/reports/{run_id}/report.json",
                        "html_url": f"/reports/{run_id}/report.html",
                        "api_url": f"/api/report/{run_id}",
                    }
                except Exception:
                    pass

    def stop_active_run(self) -> dict:
        """Stops the current active demo run and clears the lock."""
        with self._lock:
            active_id = self._active_run_id
            if active_id and active_id in self._runs:
                run = self._runs[active_id]
                run["overall_status"] = "failed"
                run["error"] = "Execution stopped by user."
                curr = run.get("current_stage")
                if curr and curr in run.get("stages", {}):
                    run["stages"][curr]["state"] = "failed"
                    run["stages"][curr]["message"] = "Stopped by user."
            self._active_run_id = None
            return {"status": "ok", "message": "Demo run stopped.", "stopped_run_id": active_id}

    def get_run_dir(self, run_id: str) -> Path | None:
        """Finds run directory, checking runs_root first and falling back to repository bundled runs."""
        if not run_id or not re.match(r"^[a-zA-Z0-9_\-]+$", run_id):
            return None
        candidate = (self.runs_root / run_id).resolve()
        if candidate.is_relative_to(self.runs_root.resolve()) and candidate.is_dir():
            return candidate
        bundled = (Path(__file__).resolve().parent.parent / "demo_runs" / run_id).resolve()
        repo_runs_root = (Path(__file__).resolve().parent.parent / "demo_runs").resolve()
        if bundled.is_relative_to(repo_runs_root) and bundled.is_dir():
            return bundled
        return None

    def get_run_status(self, run_id: str) -> dict | None:
        with self._lock:
            run = self._runs.get(run_id)
            if not run:
                return self._load_status_from_disk(run_id)
            return self._build_status_response(run)

    def _load_status_from_disk(self, run_id: str) -> dict | None:
        """Loads run status from persisted report.json on disk."""
        run_dir = self.get_run_dir(run_id)
        if not run_dir:
            return None

        report_file = run_dir / "report.json"
        if not report_file.exists():
            return None

        try:
            with open(report_file, "r", encoding="utf-8") as f:
                rep_data = json.load(f)

            # Load or compute vulnerabilities
            vuln_file = run_dir / "security_findings.json"
            if vuln_file.exists():
                with open(vuln_file, "r", encoding="utf-8") as vf:
                    rep_data["vulnerabilities"] = json.load(vf)
            else:
                ensure_vulnerabilities(rep_data)

            runtime_data = rep_data.get("runtime")
            is_ios = str(rep_data.get("platform") or rep_data.get("input", {}).get("platform") or "").lower() == "ios"
            runtime_not_implemented = isinstance(runtime_data, dict) and runtime_data.get("status") == "not_implemented"
            runtime_state = "skipped" if is_ios or runtime_not_implemented else "success"
            runtime_message = (
                "iOS runtime analysis is not implemented."
                if runtime_state == "skipped"
                else "Runtime completed."
            )
            return {
                "run_id": run_id,
                "overall_status": "completed",
                "current_stage": "completed",
                "result": rep_data,
                "report": {
                    "json_url": f"/reports/{run_id}/report.json",
                    "html_url": f"/reports/{run_id}/report.html",
                    "api_url": f"/api/report/{run_id}",
                },
                "stages": {
                    "acquisition": {"state": "success", "message": "Acquisition completed.", "data": rep_data.get("acquisition")},
                    "preprocessing": {"state": "success", "message": "Preprocessing completed.", "data": rep_data.get("preprocessing")},
                    "static_analysis": {"state": "success", "message": "Static analysis completed.", "data": rep_data.get("static_analysis")},
                    "runtime": {"state": runtime_state, "message": runtime_message, "data": runtime_data},
                },
            }
        except Exception:
            return None

    def _build_status_response(self, run: dict) -> dict:
        """Builds a status response dict from an in-memory run record."""
        status_copy = {
            "run_id": run.get("run_id"),
            "url": run.get("url"),
            "platform": run.get("platform"),
            "overall_status": run.get("overall_status"),
            "current_stage": run.get("current_stage"),
            "error": run.get("error"),
            "report": run.get("report"),
            "stages": {},
        }
        if run.get("result"):
            res_dict = dict(run["result"])
            ensure_vulnerabilities(res_dict)
            status_copy["result"] = res_dict

        for st_name, st_info in run.get("stages", {}).items():
            st_data = st_info.get("data")
            light_data = self._lighten_stage_data(st_name, st_data)
            status_copy["stages"][st_name] = {
                "state": st_info.get("state"),
                "message": st_info.get("message"),
                "data": light_data,
            }
        return status_copy

    @staticmethod
    def _lighten_stage_data(stage_name: str, data: dict | None) -> dict | None:
        """Strips heavy payload fields from stage data for status responses."""
        if stage_name != "static_analysis" or not isinstance(data, dict):
            return data

        light_data = dict(data)
        api_cands = data.get("api_candidates", [])
        light_data["api_candidates_count"] = len(api_cands) if isinstance(api_cands, (list, tuple)) else 0
        light_data["api_candidates"] = []

        net = data.get("network_indicators")
        if isinstance(net, dict):
            light_net = dict(net)
            path_cands = net.get("path_candidates", [])
            light_net["path_candidates_count"] = len(path_cands) if isinstance(path_cands, (list, tuple)) else 0
            light_net["path_candidates"] = []
            light_data["network_indicators"] = light_net

        return light_data

    def execute_connectivity_probe(self, adb_serial: str = PRESENTATION_ADB_SERIAL, timeout: float = 12.0) -> dict:
        """Executes a standalone Task 10 emulator connectivity check."""
        probe_server = ProbeServer(host="127.0.0.1", port=0)
        reverse_configured = False
        port = None
        run_id = f"probe_{int(time.time())}"

        try:
            probe_server.start()
            port = probe_server.port
            configure_adb_reverse(adb_serial=adb_serial, device_port=port, host_port=port)
            reverse_configured = True

            probe_url = probe_server.get_probe_url(run_id)
            trigger_device_browser(adb_serial=adb_serial, url=probe_url)

            start_t = time.monotonic()
            res_dict = None
            while (time.monotonic() - start_t) < timeout:
                st = probe_server.get_status(run_id)
                if st.get("hit") is True:
                    res_dict = {
                        "serial": adb_serial,
                        "probe_url": probe_url,
                        "hit": True,
                        "hit_count": st.get("hit_count", 1),
                        "connectivity_probe": "verified",
                        "disclaimer": "Emulator connectivity only — not target app navigation.",
                    }
                    break
                time.sleep(0.4)

            if res_dict is None:
                res_dict = {
                    "serial": adb_serial,
                    "probe_url": probe_url,
                    "hit": False,
                    "hit_count": 0,
                    "connectivity_probe": "unverified",
                    "message": "Timed out waiting for emulator browser probe request.",
                    "disclaimer": "Emulator connectivity only — not target app navigation.",
                }

            with self._lock:
                self._last_probe = res_dict
            return res_dict

        except Exception as exc:
            err_dict = {
                "serial": adb_serial,
                "hit": False,
                "hit_count": 0,
                "connectivity_probe": "failed",
                "message": str(exc),
                "disclaimer": "Emulator connectivity only — not target app navigation.",
            }
            with self._lock:
                self._last_probe = err_dict
            return err_dict
        finally:
            if reverse_configured and port is not None:
                remove_adb_reverse(adb_serial=adb_serial, device_port=port)
            probe_server.stop()
