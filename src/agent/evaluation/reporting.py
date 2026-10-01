"""Atomic development-only reports, outside product evidence/state trees."""
import json
import os
from pathlib import Path
import tempfile
from src.agent.models import ContractError
from .models import BenchmarkRunResult
from .privacy import validate_privacy


def write_benchmark_report(result, output_root="benchmark_results/agent_v1"):
    if not isinstance(result, BenchmarkRunResult): raise ContractError("Benchmark result required")
    root = Path(output_root).resolve()
    if root.name != "agent_v1" or root.parent.name != "benchmark_results" or "demo_runs" in root.parts:
        raise ContractError("Benchmark output must use a development-only benchmark_results/agent_v1 root")
    target = root / result.run_id / "benchmark_report.json"
    if not target.resolve().is_relative_to(root): raise ContractError("Benchmark report escapes output root")
    data = result.to_dict()
    # Count-bound scales with declared dataset/repeat limits; no raw model content.
    validate_privacy(data, budget=[250000])
    payload = (json.dumps(data, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    if len(payload) > 8_388_608: raise ContractError("Benchmark report exceeds bound")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".tmp_benchmark_", suffix=".json", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload); handle.flush(); os.fsync(handle.fileno())
        os.replace(name, target)
    finally: Path(name).unlink(missing_ok=True)
    return target
