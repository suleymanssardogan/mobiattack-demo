"""Atomic internal Test Planner artifact, never an Agent Report or stage update."""
from pathlib import Path
import json
import os
import tempfile

from src.agent.models import ContractError
from .models import TestPlannerResult, PROMPT_VERSION, SUCCESS_STATES

ARTIFACT_PATH = Path("agent/test_plans.json")
MAX_PLANS = 64
MAX_ARTIFACT_BYTES = 2_097_152


def _path(run_dir):
    root = Path(run_dir).resolve()
    target = root / ARTIFACT_PATH
    if not target.resolve().is_relative_to(root):
        raise ContractError("Test plan artifact escapes run directory")
    return target


def load_test_plans(run_dir):
    target = _path(run_dir)
    try:
        with target.open("rb") as handle:
            raw = handle.read(MAX_ARTIFACT_BYTES + 1)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ContractError("Test plan artifact exceeds bound")
        data = json.loads(raw)
        if (not isinstance(data, dict) or set(data) != {"schema_version", "prompt_version", "plans"}
                or data["schema_version"] != "1.0" or data["prompt_version"] != PROMPT_VERSION
                or not isinstance(data["plans"], list) or len(data["plans"]) > MAX_PLANS):
            raise ContractError("Invalid test plan artifact")
        results = tuple(TestPlannerResult.from_dict(item) for item in data["plans"])
        ids = [r.endpoint_context_id for r in results]
        if any(r.status not in SUCCESS_STATES for r in results) or len(ids) != len(set(ids)):
            raise ContractError("Invalid persisted plans")
        return tuple(sorted(results, key=lambda r: r.endpoint_context_id))
    except FileNotFoundError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ContractError("Invalid test plan artifact") from exc


def save_test_plans(run_dir, results):
    """Merge successful results; failed endpoints never erase previous successes.

    Callers serialize writes for a run. No provider calls or artifact/state wiring.
    Corrupt existing artifacts are rejected, not silently replaced.
    """
    if not isinstance(results, (list, tuple)) or len(results) > MAX_PLANS:
        raise ContractError("Invalid plan batch")
    if any(not isinstance(r, TestPlannerResult) for r in results):
        raise ContractError("Invalid result")
    successful = [TestPlannerResult.from_dict(r.to_dict()) for r in results if r.status in SUCCESS_STATES]
    ids = [r.endpoint_context_id for r in successful]
    if len(ids) != len(set(ids)):
        raise ContractError("Duplicate plan endpoint")
    target = _path(run_dir)
    existing = load_test_plans(run_dir) if target.exists() else ()
    if not successful:
        return target if target.exists() else None
    merged = {r.endpoint_context_id: r for r in existing}
    merged.update({r.endpoint_context_id: r for r in successful})
    if len(merged) > MAX_PLANS:
        raise ContractError("Persisted endpoint bound exceeded")
    artifact = {"schema_version": "1.0", "prompt_version": PROMPT_VERSION,
                "plans": [merged[eid].to_dict() for eid in sorted(merged)]}
    payload = json.dumps(artifact, sort_keys=True, indent=2).encode()
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise ContractError("Test plan artifact exceeds bound")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".tmp_test_plans_", suffix=".json", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload); handle.flush(); os.fsync(handle.fileno())
        os.replace(name, target)
    finally:
        Path(name).unlink(missing_ok=True)
    return target
