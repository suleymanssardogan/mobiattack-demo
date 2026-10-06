"""Offline model doubles only; none implement tools, HTTP or attack actions."""
from copy import deepcopy

from src.agent.model_client import ModelMetadata, ModelReply
from src.agent.context_analyst.validation import gap_id, record_id

TIME = "2026-10-01T12:00:00Z"


def valid_output(request):
    source = request.input_data
    eid = source["endpoint_context_id"]
    context_ref = source["evidence_refs"]["endpoint_context"][0]
    gaps = [{"gap_id": gap_id(eid, d), "endpoint_context_id": eid, **d, "blocked_test_ids": []}
            for d in source["coverage"]["gaps"]]
    hypotheses = [{"hypothesis_id": record_id("hyp", eid + kind), "endpoint_context_id": eid,
                   "hypothesis_type": kind, **descriptor, "status": "hypothesis"}
                  for kind, descriptor in sorted(source["hypothesis_catalog"].items())]
    return {"schema_version": "1.0", "endpoint_context_id": eid,
        "endpoint_role": "resource_endpoint" if "resource_endpoint" in source["supported_roles"] else "unknown",
        "observation": {"observation_id": record_id("obs", eid), "endpoint_context_id": eid,
            "facts": [f["statement"] for f in source["fact_catalog"]], "evidence_refs": [context_ref],
            "coverage_gaps": [g["gap_id"] for g in gaps],
            "created_at": request.input_data.get("analysis_created_at", TIME)},
        "hypotheses": hypotheses, "coverage_gaps": gaps}


class FakeModelClient:
    def __init__(self, transform=None, error=None):
        self.requests = []
        self.transform = transform
        self.error = error

    def generate(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        data = valid_output(request)
        if self.transform:
            data = self.transform(deepcopy(data), request)
        return ModelReply(data, ModelMetadata("fake", "fixture-v1"))
