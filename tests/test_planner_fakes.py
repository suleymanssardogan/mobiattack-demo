"""Offline Planner fake reusing Task 9.2's model-client test boundary."""
from copy import deepcopy
from src.agent.model_client import ModelReply, ModelMetadata
from src.agent.test_planner.validation import proposal_id
from tests.context_analyst_fakes import FakeModelClient


class PlannerFake(FakeModelClient):
    def generate(self, request):
        self.requests.append(request)
        if self.error: raise self.error
        source = request.input_data
        variants = request.output_schema["properties"]["proposals"].get("items", {}).get("oneOf", [])
        created_at = variants[0]["properties"]["created_at"]["const"] if variants else "2026-10-01T12:00:00Z"
        data = {"schema_version": "1.0", "endpoint_context_id": source["endpoint_context_id"],
            "proposals": [{**c, "proposal_id": proposal_id(source["endpoint_context_id"], c["hypothesis_id"], c["test_id"]),
                "endpoint_context_id": source["endpoint_context_id"], "created_at": created_at}
                for c in source["proposal_candidates"]]}
        if self.transform: data = self.transform(deepcopy(data), request)
        return ModelReply(data, ModelMetadata("fake", "fixture-v1"))
