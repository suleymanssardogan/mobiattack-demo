"""Versioned development-only benchmark records, separate from scan artifacts."""
from dataclasses import asdict, dataclass, field
import hashlib
import json
from src.agent.models import ContractError, identifier, timestamp
from src.dynamic.context.models import EndpointContext
from src.agent.context_analyst.models import PROMPT_VERSION as ANALYST_PROMPT
from src.agent.test_planner.models import PROMPT_VERSION as PLANNER_PROMPT

BENCHMARK_VERSION = "agent_benchmark_v1"
SCORING_VERSION = "scoring_v1"
ROLES = ("context_analyst", "test_planner")


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    category: str
    description: str
    endpoint_context: EndpointContext
    expected: dict
    coverage_metadata: dict
    precondition_names: tuple[str, ...]

    def to_dict(self): return json.loads(json.dumps(asdict(self), sort_keys=True))


@dataclass(frozen=True)
class BenchmarkDataset:
    version: str
    cases: tuple[BenchmarkCase, ...]

    def __post_init__(self):
        if self.version != BENCHMARK_VERSION or not isinstance(self.cases, tuple) or not 1 <= len(self.cases) <= 64:
            raise ContractError("Invalid benchmark dataset")
        ids = [c.case_id for c in self.cases]
        endpoints = [c.endpoint_context.endpoint_context_id for c in self.cases]
        if len(ids) != len(set(ids)) or len(endpoints) != len(set(endpoints)):
            raise ContractError("Duplicate benchmark case/endpoint IDs")

    @property
    def fingerprint(self):
        payload = {"version": self.version, "cases": [c.to_dict() for c in sorted(self.cases, key=lambda c: c.case_id)]}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class BenchmarkRunResult:
    run_id: str
    created_at: str
    dataset_fingerprint: str
    roles: dict
    policy: dict
    aggregate: dict
    cases: tuple[dict, ...]
    runs_per_case: int
    benchmark_version: str = BENCHMARK_VERSION
    scoring_version: str = SCORING_VERSION
    schema_version: str = "1.0"
    prompt_versions: dict = field(default_factory=lambda: {"context_analyst": ANALYST_PROMPT, "test_planner": PLANNER_PROMPT})

    def __post_init__(self):
        identifier(self.run_id, "run_id"); timestamp(self.created_at)
        if self.benchmark_version != BENCHMARK_VERSION or self.scoring_version != SCORING_VERSION or self.schema_version != "1.0":
            raise ContractError("Unsupported benchmark result version")

    def to_dict(self): return json.loads(json.dumps(asdict(self), sort_keys=True))
