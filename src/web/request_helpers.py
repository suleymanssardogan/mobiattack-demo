"""Reusable HTTP request/response helpers for the Demo Web Server.

Eliminates DRY violations in _DemoRequestHandler by providing shared
utilities for JSON body parsing, file serving, and response writing.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any


def parse_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    """Reads and parses a JSON body from an HTTP request.

    Returns an empty dict on missing or invalid payloads.  Raises
    ``ValueError`` with a user-facing message when the body is present
    but syntactically invalid.
    """
    length = int(handler.headers.get("Content-Length", 0))
    raw_body = handler.rfile.read(length) if length > 0 else b"{}"
    try:
        return json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid JSON payload.") from exc


def send_json(handler: BaseHTTPRequestHandler, status_code: int, data: dict) -> None:
    """Sends a JSON response with standard headers.

    Silently absorbs broken-pipe errors that occur when clients
    disconnect before the response is fully written.
    """
    try:
        body = json.dumps(data, indent=2).encode("utf-8")
        handler.send_response(status_code)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(body)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass


def send_file(
    handler: BaseHTTPRequestHandler,
    file_path: Path,
    content_type: str,
    *,
    disposition_filename: str | None = None,
) -> None:
    """Serves a file from disk with the given content type.

    Optionally adds a ``Content-Disposition`` header for downloadable
    attachments when *disposition_filename* is provided.
    """
    try:
        content = file_path.read_bytes()
        handler.send_response(200)
        handler.send_header("Content-Type", content_type)
        if disposition_filename:
            handler.send_header(
                "Content-Disposition",
                f'attachment; filename="{disposition_filename}"',
            )
        handler.send_header("Content-Length", str(len(content)))
        handler.send_header("Connection", "close")
        handler.end_headers()
        handler.wfile.write(content)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass


def serve_run_file(
    handler: BaseHTTPRequestHandler,
    run_id: str,
    filename: str,
    content_type: str,
    get_run_dir,
    *,
    disposition_filename: str | None = None,
    label: str | None = None,
) -> None:
    """Locates a run file and serves it, or responds with 404.

    Eliminates the repeated pattern of:
      1. Resolve run directory
      2. Check file existence
      3. Read and send bytes or 404

    Args:
        handler: The HTTP request handler instance.
        run_id: The run identifier to locate.
        filename: The file to serve within the run directory.
        content_type: MIME type for the Content-Type header.
        get_run_dir: Callable that resolves run_id → Path | None.
        disposition_filename: Optional attachment filename for downloads.
        label: Human-readable label for 404 error messages.
    """
    display_label = label or filename
    target_dir = get_run_dir(run_id)
    if not target_dir:
        send_json(handler, 404, {
            "status": "error",
            "message": f"{display_label} for run '{run_id}' not found.",
        })
        return

    file_path = target_dir / filename
    if not file_path.exists():
        send_json(handler, 404, {
            "status": "error",
            "message": f"{display_label} for run '{run_id}' not found.",
        })
        return

    try:
        send_file(
            handler,
            file_path,
            content_type,
            disposition_filename=disposition_filename,
        )
    except Exception as exc:
        send_json(handler, 500, {"status": "error", "message": str(exc)})


def ensure_vulnerabilities(result: dict[str, Any]) -> dict[str, Any]:
    """Ensures the result dict contains a 'vulnerabilities' key.

    Lazily evaluates vulnerabilities only when they are missing from the
    result, avoiding redundant calls to ``evaluate_vulnerabilities()``.
    """
    if "vulnerabilities" not in result:
        from src.vulnerability_evaluator import evaluate_vulnerabilities
        result["vulnerabilities"] = evaluate_vulnerabilities(result)
    return result
