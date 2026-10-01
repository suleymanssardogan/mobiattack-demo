"""Provider-neutral text/structured-output boundary; no tool or provider SDK."""
from dataclasses import dataclass, field
import re
import math
from typing import Any, Protocol

from .models import ContractError


@dataclass(frozen=True)
class ModelMetadata:
    provider: str = "unspecified"
    model: str = "unspecified"
    model_version: str | None = None
    latency_ms: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None

    def __post_init__(self):
        if self.provider not in {"unspecified", "fake", "stub", "local", "openai", "anthropic", "google"}:
            raise ContractError("Invalid provider metadata")
        if not isinstance(self.model, str) or not re.fullmatch(r"[a-z][a-z0-9_.:-]{0,63}", self.model):
            raise ContractError("Invalid model identifier")

        if self.model_version is not None and (not isinstance(self.model_version, str)
                or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}", self.model_version)):
            raise ContractError("Invalid model version")
        for name in ("input_tokens", "output_tokens"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ContractError("Invalid token metadata")
        for name in ("latency_ms", "cost_usd"):
            value = getattr(self, name)
            if value is not None and (type(value) not in (int, float) or not math.isfinite(value) or value < 0):
                raise ContractError("Invalid timing/cost metadata")


@dataclass(frozen=True)
class ModelRequest:
    prompt_version: str
    instruction: str
    input_data: dict[str, Any]
    output_schema: dict[str, Any]
    attempt: int
    correction: str | None = None


@dataclass(frozen=True)
class ModelReply:
    data: Any
    metadata: ModelMetadata = field(default_factory=ModelMetadata)


class AgentModelClient(Protocol):
    def generate(self, request: ModelRequest) -> ModelReply:
        """Return structured output only. No tool calls or executable action channel."""
