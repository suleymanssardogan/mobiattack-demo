# Task 7.1.1: Conservative static/dynamic path identity

Only explicit static placeholders (`{id}`, `:userId`, `<account_id>`) can match a different concrete dynamic segment. Each placeholder matches one non-empty segment. Numeric and UUID literals require equality. Dynamic placeholder syntax cannot parameterize a static literal. Host normalization, query exclusion, method scoring, and explicit template aggregation remain unchanged.

Confidence remains exact: high; template: medium; host_path: medium; method_mismatch: low.

## Static candidate reference provenance

The current `src/api_candidate_extractor.py` emits candidates without an ID. Canonical static report sanitization copies candidate fields and does not invent IDs. If an input candidate supplies `id`, `candidate_id`, or `endpoint_id`, correlation reuses it (in that precedence order).

Otherwise, `static_candidate_id` retains the existing deterministic `stat_cand_<one-based input index>` correlation-side reference. It is not a field originally present in the static report and is stable for the same ordered candidate input. Correlation provenance records `static_candidate_id_origin` as `source_report` or `correlation_reference`, and `static_candidate_id_source_field` as the actual source field or null. The source report is not modified. Deterministic correlation ID generation is unchanged.

This change performs passive deterministic correlation only. No request replay, active API testing, AuthN/AuthZ testing, vulnerability generation, Dynamic Analysis Report, or Agent Analysis was introduced.
