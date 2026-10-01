"""Immutable V1 test descriptions. No test implementation or execution hook."""
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class CatalogEntry:
    test_id: str
    name: str
    category: str
    risk_class: str
    required_context: tuple[str, ...]
    required_evidence: tuple[str, ...]
    allowed_mutations: tuple[str, ...]
    validation_requirements: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    auto_execution_allowed: bool
    allowed_actions: tuple[str, ...]
    abstract_action: str = ""


def _entry(test_id, name, risk, contexts, evidence, mutations, auto, action):
    return CatalogEntry(test_id, name, test_id.lower(), risk, contexts, evidence, mutations,
        ("Compare expected and observed behavior using linked evidence",
         "HTTP status, crash and tool success alone are insufficient",
         "Reproduction evidence required before confirmation"),
        ("Policy denial", "Missing required evidence", "Scope boundary", "Inconclusive validation"),
        auto, (action,), {
            "AUTHENTICATION_PRESENCE": "review_authentication_presence",
            "OBJECT_AUTHORIZATION": "validate_object_access_behavior",
            "FUNCTION_AUTHORIZATION": "validate_function_access_behavior",
            "SESSION_HANDLING": "validate_session_dependency",
            "INPUT_VALIDATION": "validate_input_handling",
            "PARAMETER_CONSISTENCY": "validate_parameter_consistency",
        }[test_id])


TEST_CATALOG = MappingProxyType({e.test_id: e for e in (
    _entry("AUTHENTICATION_PRESENCE", "Review authentication presence metadata", "passive",
           ("auth",), ("endpoint_context",), ("none",), True, "review_evidence"),
    _entry("OBJECT_AUTHORIZATION", "Object authorization contract", "medium",
           ("dynamic.observed",), ("endpoint_context", "traffic_transaction"), ("none",), False, "object_access"),
    _entry("FUNCTION_AUTHORIZATION", "Function authorization contract", "high",
           ("dynamic.observed",), ("endpoint_context", "traffic_transaction"), ("none",), False, "function_access"),
    _entry("SESSION_HANDLING", "Session handling contract", "low",
           ("auth",), ("endpoint_context", "traffic_transaction"), ("none",), False, "session_check"),
    _entry("INPUT_VALIDATION", "Input validation contract", "low",
           ("request.body_present",), ("endpoint_context", "traffic_transaction"), ("body_parameter",), True, "input_check"),
    _entry("PARAMETER_CONSISTENCY", "Parameter consistency contract", "low",
           ("dynamic.observed",), ("endpoint_context", "traffic_transaction"),
           ("none", "query_parameter", "body_parameter"), True, "check_parameter"),
)})
