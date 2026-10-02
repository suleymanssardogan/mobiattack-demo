"""Security contracts and executor scaffolding; no live test implementations."""
from .contracts import (
    DynamicTestRequest, DynamicTestExecutionResult, DynamicValidationResult,
    EvidenceReference, check_request_safety, validate_execution, validate_result,
)

__all__ = ['DynamicTestRequest', 'DynamicTestExecutionResult', 'DynamicValidationResult',
           'EvidenceReference', 'check_request_safety', 'validate_execution', 'validate_result']

from .executor import DeterministicSecurityExecutor

__all__.append("DeterministicSecurityExecutor")
