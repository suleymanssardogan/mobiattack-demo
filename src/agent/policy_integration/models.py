"""Internal evaluation envelope around the canonical PolicyDecision."""
from dataclasses import asdict, dataclass, fields
import json
from src.agent.models import ContractError, PolicyDecision, POLICY_VERSION, identifier, timestamp


@dataclass(frozen=True)
class PolicyEvaluationResult:
    evaluation_id: str
    planning_id: str
    endpoint_context_id: str
    created_at: str
    status: str
    decisions: tuple[PolicyDecision, ...] = ()
    schema_version: str = "1.0"
    policy_version: str = POLICY_VERSION

    def __post_init__(self):
        for key in ("evaluation_id", "planning_id", "endpoint_context_id"):
            identifier(getattr(self, key), key)
        timestamp(self.created_at)
        if (self.schema_version != "1.0" or self.policy_version != POLICY_VERSION
                or self.status not in {"evaluated", "no_proposals", "not_processed"}
                or not isinstance(self.decisions, tuple) or len(self.decisions) > 16
                or any(not isinstance(d, PolicyDecision) or d.policy_version != self.policy_version for d in self.decisions)):
            raise ContractError("Invalid policy evaluation")
        ids = [d.proposal_id for d in self.decisions]
        if len(ids) != len(set(ids)):
            raise ContractError("Duplicate proposal decision")
        if (self.status == "evaluated") != bool(self.decisions):
            raise ContractError("Policy status/count mismatch")
        if any(d.endpoint_context_id is None or d.hypothesis_id is None or d.test_id is None
               or (d.decision != "deny" and d.endpoint_context_id != self.endpoint_context_id) for d in self.decisions):
            raise ContractError("Detached policy decision")

    def to_dict(self):
        data = json.loads(json.dumps(asdict(self), sort_keys=True))
        data.update({"decision_count": self.decision_count, "allow_count": self.allow_count,
                     "deny_count": self.deny_count, "needs_evidence_count": self.needs_evidence_count})
        return data

    @property
    def decision_count(self): return len(self.decisions)

    @property
    def allow_count(self): return sum(d.decision == "allow" for d in self.decisions)

    @property
    def deny_count(self): return sum(d.decision == "deny" for d in self.decisions)

    @property
    def needs_evidence_count(self): return sum(d.decision == "needs_evidence" for d in self.decisions)

    @property
    def trace(self):
        return {"policy_version": self.policy_version, "planning_id": self.planning_id,
                "endpoint_context_id": self.endpoint_context_id,
                "decisions": [{"proposal_id": d.proposal_id, "decision_id": d.decision_id,
                               "hypothesis_id": d.hypothesis_id, "test_id": d.test_id,
                               "decision": d.decision, "reason_code": d.reason_code, "reason": d.reason,
                               "evidence_refs": list(d.validated_evidence_refs)} for d in self.decisions]}

    @classmethod
    def from_dict(cls, data):
        counts = {"decision_count", "allow_count", "deny_count", "needs_evidence_count"}
        if not isinstance(data, dict) or set(data) != {f.name for f in fields(cls)} | counts:
            raise ContractError("Invalid policy evaluation fields")
        values = {k: v for k, v in data.items() if k not in counts}
        if not isinstance(values["decisions"], (tuple, list)):
            raise ContractError("Invalid decision collection")
        values["decisions"] = tuple(PolicyDecision.from_dict(d) for d in values["decisions"])
        try:
            result = cls(**values)
            if any(type(data[k]) is not int or data[k] != getattr(result, k) for k in counts):
                raise ContractError("Invalid policy result counts")
            return result
        except (TypeError, ValueError, AttributeError) as exc:
            raise ContractError("Invalid policy evaluation") from exc
