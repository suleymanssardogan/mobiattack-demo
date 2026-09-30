"""Shared constants and reusable data structures for MobiAttack-v2.

Centralizes magic strings, default configuration values, and repeated
data structures to eliminate duplication across the codebase.
"""

from __future__ import annotations

# Default ADB device serial used in the presentation/demo environment.
PRESENTATION_ADB_SERIAL = "emulator-5554"

# iOS vulnerability evaluation placeholder — used consistently across
# orchestrator, report generator, web server, and vulnerability evaluator.
IOS_VULN_NOT_EVALUATED: dict = {
    "status": "not_evaluated",
    "reason": "not_implemented",
    "risk_score": "NOT_EVALUATED",
    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
    "findings": [],
    "message": "iOS vulnerability evaluation is not implemented in Phase 1.",
}

# iOS runtime placeholder — used when runtime analysis is skipped on iOS.
IOS_RUNTIME_NOT_IMPLEMENTED: dict = {
    "status": "not_implemented",
    "platform": "ios",
    "message": "Runtime launch verification is not implemented for iOS in Phase 1.",
}

# Shared pipeline stage names (canonical ordering).
PIPELINE_STAGES = ("acquisition", "preprocessing", "static_analysis", "runtime")


def make_ios_vuln_not_evaluated() -> dict:
    """Returns a deep copy of the iOS vulnerability not-evaluated placeholder."""
    import copy
    return copy.deepcopy(IOS_VULN_NOT_EVALUATED)
