"""Offline fixtures for scorer calibration; no production providers or SDKs."""
from copy import deepcopy
from src.agent.model_client import ModelMetadata, ModelReply
from src.agent.context_analyst.validation import gap_id, record_id
from src.agent.test_planner.validation import proposal_id


class PerfectFixtureClient:
    def __init__(self, dataset):
        self.expected = {c.endpoint_context.endpoint_context_id: c.expected for c in dataset.cases}
        self.calls = 0

    def generate(self, request):
        self.calls += 1
        source = request.input_data; eid = source["endpoint_context_id"]; gold = self.expected[eid]
        if request.prompt_version == "context_analyst_v1":
            gaps = [{"gap_id": gap_id(eid, d), "endpoint_context_id": eid, **d, "blocked_test_ids": []} for d in source["coverage"]["gaps"]]
            data = {"schema_version": "1.0", "endpoint_context_id": eid, "endpoint_role": gold["expected_endpoint_role"],
                "observation": {"observation_id": record_id("obs", eid), "endpoint_context_id": eid,
                    "facts": [f["statement"] for f in source["fact_catalog"]],
                    "evidence_refs": source["evidence_refs"]["endpoint_context"], "coverage_gaps": [g["gap_id"] for g in gaps],
                    "created_at": request.output_schema["properties"]["observation"]["properties"]["created_at"]["const"]},
                "hypotheses": [{"hypothesis_id": record_id("hyp", eid + kind), "endpoint_context_id": eid,
                    "hypothesis_type": kind, **source["hypothesis_catalog"][kind], "status": "hypothesis"}
                    for kind in sorted(gold["expected_hypothesis_types"])], "coverage_gaps": gaps}
        elif request.prompt_version == "test_planner_v1":
            variants = request.output_schema["properties"]["proposals"].get("items", {}).get("oneOf", [])
            time = variants[0]["properties"]["created_at"]["const"] if variants else None
            data = {"schema_version": "1.0", "endpoint_context_id": eid,
                "proposals": [{**c, "proposal_id": proposal_id(eid, c["hypothesis_id"], c["test_id"]),
                               "endpoint_context_id": eid, "created_at": time}
                    for c in source["proposal_candidates"] if c["test_id"] in gold["expected_test_ids"]]}
        else: raise ValueError("Unsupported benchmark role")
        return ModelReply(deepcopy(data), ModelMetadata("fake", "perfect_fixture", model_version="v1"))


class HallucinatingFixtureClient(PerfectFixtureClient):
    def generate(self, request):
        reply = super().generate(request); data = reply.data
        target = data["observation"] if request.prompt_version == "context_analyst_v1" else (data["proposals"][0] if data["proposals"] else data)
        target.setdefault("evidence_refs", []).append("dynamic/traffic.json#transaction_id=tx_fake_999")
        return ModelReply(data, ModelMetadata("fake", "hallucinating_fixture", model_version="v1"))


class InvalidSchemaFixtureClient(PerfectFixtureClient):
    def generate(self, request):
        self.calls += 1
        return ModelReply("{invalid JSON", ModelMetadata("fake", "invalid_schema_fixture", model_version="v1"))


class OverplanningFixtureClient(PerfectFixtureClient):
    def generate(self, request):
        reply = super().generate(request); data = reply.data
        if request.prompt_version == "context_analyst_v1":
            data["finding"] = "synthetic forbidden finding"
        else:
            data["proposals"].append({"test_id": "AI_SMART_HACK", "endpoint_context_id": request.input_data["endpoint_context_id"],
                "hypothesis_id": "hyp_unsupported", "evidence_refs": [], "requested_action": {"tool_name": "forbidden"}})
        return ModelReply(data, ModelMetadata("fake", "overplanning_fixture", model_version="v1"))
