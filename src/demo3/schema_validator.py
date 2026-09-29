"""JSON Schema Validator for Demo 3 Baseline Report.

Supports both official `jsonschema` library and a zero-dependency fallback validator.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA_FILE_PATH = Path(__file__).resolve().parent.parent.parent / "schemas" / "baseline_report.schema.json"


class SchemaValidationError(Exception):
    """Raised when a baseline report fails JSON Schema validation."""

    def __init__(self, message: str, path: str = "") -> None:
        super().__init__(f"Baseline report schema validation failed at '{path}': {message}" if path else f"Baseline report schema validation failed: {message}")
        self.path = path


def get_schema_dict() -> dict[str, Any]:
    """Loads the baseline report JSON Schema from disk."""
    if not SCHEMA_FILE_PATH.is_file():
        raise FileNotFoundError(f"Schema file not found at {SCHEMA_FILE_PATH}")
    with open(SCHEMA_FILE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _validate_builtin(data: dict[str, Any], schema: dict[str, Any]) -> None:
    """Rigorous standard-library validator verifying keys, types, enums, and structures."""
    if not isinstance(data, dict):
        raise SchemaValidationError("Root must be a JSON object", "$")

    # 1. Required top-level fields
    for req in schema.get("required", []):
        if req not in data:
            raise SchemaValidationError(f"Missing required property '{req}'", "$")

    if data.get("schema_version") != "1.0.0":
        raise SchemaValidationError(f"Invalid schema_version '{data.get('schema_version')}', expected '1.0.0'", "$.schema_version")

    # 2. Validate scan
    scan = data.get("scan")
    if not isinstance(scan, dict):
        raise SchemaValidationError("'scan' must be an object", "$.scan")
    for req in ("run_id", "status", "errors", "warnings"):
        if req not in scan:
            raise SchemaValidationError(f"Missing required field '{req}' in scan", "$.scan")
    if scan["status"] not in ("completed", "partial", "failed"):
        raise SchemaValidationError(f"Invalid scan.status '{scan['status']}'", "$.scan.status")
    if not isinstance(scan["errors"], list) or not isinstance(scan["warnings"], list):
        raise SchemaValidationError("errors and warnings must be arrays", "$.scan")

    # 3. Validate artifact
    artifact = data.get("artifact")
    if not isinstance(artifact, dict):
        raise SchemaValidationError("'artifact' must be an object", "$.artifact")
    for req in ("source", "filename", "sha256", "package_name"):
        if req not in artifact:
            raise SchemaValidationError(f"Missing required field '{req}' in artifact", "$.artifact")

    # 4. Validate analysis
    analysis = data.get("analysis")
    if not isinstance(analysis, dict):
        raise SchemaValidationError("'analysis' must be an object", "$.analysis")
    for req in ("files_discovered", "files_analyzed", "files_skipped", "files_failed"):
        if req not in analysis or not isinstance(analysis[req], int) or analysis[req] < 0:
            raise SchemaValidationError(f"Field '{req}' must be a non-negative integer", f"$.analysis.{req}")

    # 5. Validate inventory
    inventory = data.get("inventory")
    if not isinstance(inventory, dict):
        raise SchemaValidationError("'inventory' must be an object", "$.inventory")
    if "candidates" not in inventory or not isinstance(inventory["candidates"], list):
        raise SchemaValidationError("'candidates' must be an array", "$.inventory.candidates")
    if inventory.get("candidate_count") != len(inventory["candidates"]):
        raise SchemaValidationError("candidate_count must match length of candidates array", "$.inventory.candidate_count")

    for idx, cand in enumerate(inventory["candidates"]):
        c_path = f"$.inventory.candidates[{idx}]"
        if not isinstance(cand, dict):
            raise SchemaValidationError("Candidate must be an object", c_path)
        for req in ("id", "type", "value", "occurrence_count", "occurrences"):
            if req not in cand:
                raise SchemaValidationError(f"Candidate missing '{req}'", c_path)
        if cand["type"] not in ("url", "domain", "api_path", "ip_address", "websocket_url", "base_url"):
            raise SchemaValidationError(f"Invalid candidate type '{cand['type']}'", f"{c_path}.type")
        if not isinstance(cand["occurrences"], list) or len(cand["occurrences"]) == 0:
            raise SchemaValidationError("Candidate occurrences must be non-empty array", f"{c_path}.occurrences")
        if cand["occurrence_count"] != len(cand["occurrences"]):
            raise SchemaValidationError("occurrence_count must match len(occurrences)", f"{c_path}.occurrence_count")

        for o_idx, occ in enumerate(cand["occurrences"]):
            o_path = f"{c_path}.occurrences[{o_idx}]"
            if not isinstance(occ, dict):
                raise SchemaValidationError("Occurrence must be an object", o_path)
            for req in ("source_file", "extraction_method", "raw_value", "evidence"):
                if req not in occ:
                    raise SchemaValidationError(f"Occurrence missing '{req}'", o_path)

    # 6. Validate static findings
    findings = data.get("static_findings")
    if not isinstance(findings, list):
        raise SchemaValidationError("'static_findings' must be an array", "$.static_findings")
    for f_idx, f in enumerate(findings):
        f_path = f"$.static_findings[{f_idx}]"
        if not isinstance(f, dict):
            raise SchemaValidationError("Finding must be an object", f_path)
        for req in ("id", "rule_id", "title", "severity"):
            if req not in f:
                raise SchemaValidationError(f"Finding missing '{req}'", f_path)
        if f["severity"] not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            raise SchemaValidationError(f"Invalid severity '{f['severity']}'", f"{f_path}.severity")


def validate_baseline_report(report_dict: dict[str, Any]) -> None:
    """Validates baseline report against JSON schema. Raises SchemaValidationError on failure."""
    schema = get_schema_dict()

    # Try official jsonschema if available
    try:
        import jsonschema  # type: ignore
        try:
            jsonschema.validate(instance=report_dict, schema=schema)
            return
        except jsonschema.exceptions.ValidationError as exc:
            path_str = ".".join(str(p) for p in exc.absolute_path) or "$"
            raise SchemaValidationError(exc.message, path_str) from exc
    except ImportError:
        pass

    # Fallback to rigorous built-in validator
    _validate_builtin(report_dict, schema)
