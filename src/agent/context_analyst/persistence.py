"""Atomic internal Context Analyst artifact, never an Agent Report or stage update."""
from pathlib import Path
import json
import os
import tempfile

from src.agent.models import ContractError
from .models import ContextAnalystResult, PROMPT_VERSION

ARTIFACT_PATH = Path("agent/context_analysis.json")
MAX_ANALYSES = 64
MAX_ARTIFACT_BYTES = 2_097_152


def _path(run_dir):
    root = Path(run_dir).resolve()
    target = root / ARTIFACT_PATH
    if not target.resolve().is_relative_to(root):
        raise ContractError("Context analysis artifact escapes run directory")
    return target


def load_context_analyses(run_dir):
    target = _path(run_dir)
    try:
        with target.open("rb") as handle:
            raw = handle.read(MAX_ARTIFACT_BYTES + 1)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ContractError("Context analysis artifact exceeds bound")
        data = json.loads(raw)
        if (not isinstance(data, dict) or set(data) != {"schema_version", "prompt_version", "analyses"}
                or data["schema_version"] != "1.0" or data["prompt_version"] != PROMPT_VERSION
                or not isinstance(data["analyses"], list) or len(data["analyses"]) > MAX_ANALYSES):
            raise ContractError("Invalid context analysis artifact")
        results = tuple(ContextAnalystResult.from_dict(item) for item in data["analyses"])
        ids = [r.endpoint_context_id for r in results]
        if any(r.status != "completed" for r in results) or len(ids) != len(set(ids)):
            raise ContractError("Invalid persisted analyses")
        return tuple(sorted(results, key=lambda r: r.endpoint_context_id))
    except FileNotFoundError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ContractError("Invalid context analysis artifact") from exc


def save_context_analyses(run_dir, results):
    """Merge completed results; failed endpoints never erase previous successes.

    Callers serialize writes for a run. No provider calls or artifact/state wiring.
    Corrupt existing artifacts are rejected, not silently replaced.
    """
    if not isinstance(results, (list, tuple)) or len(results) > MAX_ANALYSES:
        raise ContractError("Invalid analysis batch")
    if any(not isinstance(r, ContextAnalystResult) for r in results):
        raise ContractError("Invalid result")
    successful = [ContextAnalystResult.from_dict(r.to_dict()) for r in results if r.status == "completed"]
    ids = [r.endpoint_context_id for r in successful]
    if len(ids) != len(set(ids)):
        raise ContractError("Duplicate analysis endpoint")
    target = _path(run_dir)
    existing = load_context_analyses(run_dir) if target.exists() else ()
    if not successful:
        return target if target.exists() else None
    merged = {r.endpoint_context_id: r for r in existing}
    merged.update({r.endpoint_context_id: r for r in successful})
    if len(merged) > MAX_ANALYSES:
        raise ContractError("Persisted endpoint bound exceeded")
    artifact = {"schema_version": "1.0", "prompt_version": PROMPT_VERSION,
                "analyses": [merged[eid].to_dict() for eid in sorted(merged)]}
    payload = json.dumps(artifact, sort_keys=True, indent=2).encode()
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise ContractError("Context analysis artifact exceeds bound")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".tmp_context_analysis_", suffix=".json", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload); handle.flush(); os.fsync(handle.fileno())
        os.replace(name, target)
    finally:
        Path(name).unlink(missing_ok=True)
    return target
