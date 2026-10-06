"""Lossless planning projection of the already sanitized Analyst boundary.

The full canonical snapshot remains the validator's source of truth. Only empty
collection fields in metadata summaries are omitted; unknown/false flags, shapes,
catalogs, coverage gaps and every evidence/provenance reference are retained.
"""
from .models import ContextAnalystInput


def build_model_context(context: ContextAnalystInput) -> dict:
    data = context.to_dict()
    for section in ("dynamic_context", "request_context", "response_context"):
        data[section] = {key: value for key, value in data[section].items()
                         if value != [] and value != {}}
    return data
