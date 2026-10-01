# MobiAttack Agent Analysis specification — V1 foundation

Status: Task 9.4 adds explicit deterministic Test Planner → Policy Gate evaluation
after the accepted Context Analyst, Test Planner and Task 9.1 foundation. No live external provider is configured;
only a provider-neutral interface and offline test doubles are included. No tool
calling, executor, active API testing, findings, PoC or Agent Report is enabled.
`agent_analysis` remains `not_available`. Existing static/dynamic artifacts,
report-serving and public scan-state semantics remain unchanged.

## Canonical product principles

```text
NO EVIDENCE → NO FINDING
NO REPRODUCTION → NO CONFIRMED FINDING
AGENT OUTPUT ≠ EVIDENCE
AGENT OUTPUT ≠ FINDING
TOOL OUTPUT ≠ VALIDATED FINDING
OBSERVED ≠ CAUSED
NOT OBSERVED ≠ ABSENT
INCOMPLETE COVERAGE ≠ SECURE
EVERY FINDING MUST HAVE PROVENANCE
EVERY ACTIVE ACTION MUST PASS POLICY
```

An observation is a fact summary with references, never a security verdict.
A hypothesis or proposal is not a finding. HTTP 200, a crash, or successful tool
execution alone cannot validate a vulnerability. Missing coverage cannot establish
absence, security, or impossibility of findings. Free-form model text never
becomes trusted evidence merely because it conforms to a schema.

## Current evidence foundation and pipeline

Inputs below are canonical run-relative artifact names, consumed as sanitized,
relevant summaries. They are not reimplemented by Agent Analysis.

| Artifact | Role and availability boundary |
| --- | --- |
| `static_analysis_report.json` | Static discovery and source provenance; canonical candidate IDs reused when present |
| `dynamic_analysis_report.json` | Validated summary of executed exploration, traffic/runtime visibility and coverage |
| `dynamic/api_correlation.json` | Directional, deterministic static-to-runtime endpoint associations |
| `dynamic/endpoint_contexts.json` | EndpointContext identity, methods, parameter names/shapes, auth presence and linked evidence IDs |
| `dynamic/runtime_evidence.json` | Action-linked runtime observations, not causation proof |
| `dynamic/traffic.json` | Transactions; agent input uses summaries and references rather than raw traffic |
| `dynamic/traffic_evidence.json` | Action-to-transaction correlation and visibility limitations |
| `dynamic/route_graph.json` | Selected route/action context rather than the entire graph |
| `dynamic/timeline.json` | Existing chronological evidence when available; missing data remains unavailable |

Availability must be established from actual canonical artifacts. Merely knowing
a filename, correlation ID, or transaction ID does not prove the referenced data
exists. A correlation-side surrogate static candidate reference is not a claim
that the static source schema originally contained that ID; preserve the existing
`static_candidate_id_origin` and source-field provenance.

```text
APK / IPA
→ API Discovery
→ Runtime Traffic
→ Endpoint Context
→ Relevant Security Tests
→ Validation
→ Evidence / PoC
→ CI/CD Release Gate
```

This is the intended product pipeline. Relevant tests, execution, findings, PoC
and release gating are future phases. Agent Analysis begins after EndpointContext
exists, including its explicit visibility and coverage limitations. Static-only
contexts do not imply available runtime transactions. Platform and capture
limitations are carried forward, not silently upgraded.

## Exactly three future reasoning roles

| Role | Responsibility | Forbidden |
| --- | --- | --- |
| Context Analyst | Interpret EndpointContext, endpoint role, auth/session/resource/input characteristics; identify available/missing evidence and coverage gaps | Vulnerability declaration, tools, request mutation, severity, invented endpoints/parameters |
| Test Planner | Consume analyst summaries and EndpointContext; select only catalog tests; produce TestProposal with preconditions and referenced relevance | Direct execution, arbitrary test types, invented endpoints, finding-success claims |
| Evidence Verifier | Compare executor observations with criteria; return validated/rejected/inconclusive/blocked with provenance and reproducibility | HTTP 200/crash/tool success as confirmation, invented evidence |

These roles are specification only. No production instruction prompts or role
runtime are included. Future prompts must require structured output, citations to
provided evidence, uncertainty, privacy and policy compliance.

## Deterministic non-agent components

- **Policy Gate:** implemented here as pure proposal eligibility validation.
- **Test Catalog:** implemented as immutable descriptive entries with stable IDs.
- **Schema Validator:** strict dataclasses/dictionary parsing, domain links and
  lifecycle validation implemented here; unknown fields fail.
- **Evidence Store:** existing artifacts remain authoritative; a future store can
  resolve their summaries and IDs. This task defines a caller-supplied index,
  not a new store or loader.
- **Coverage Engine:** future deterministic aggregation of gaps; no new engine.
- **Deterministic Executor:** future only; ToolExecutionResult defines its output
  contract, with no executable callback, command, HTTP payload or implementation.

## Feedback loop and re-plan triggers

```text
Observe
→ Context Update
→ Reason / Plan
→ Policy Check
→ Act
→ Tool Output
→ Validate
→ Observe Again
```

Compact equivalent:

```text
Plan → Act → Observe → New Context → Re-plan → New Act
```

Act is future deterministic execution after a current policy decision. Re-planning
is trigger-based, NOT continuous and not automatic after every step. Allowed
triggers are:

1. New endpoint/context discovered.
2. New resource identifier discovered.
3. New session/auth metadata becomes available.
4. Previous test result differs from expected behavior.
5. Inconclusive validation with additional obtainable evidence.
6. Hypothesis rejected.
7. New runtime evidence materially changes endpoint context.

The trigger and next-action decision belong in the structured trace. Terminal
cases stop when evidence is unavailable, policy denies, scope is crossed, or
validation is inconclusive without obtainable evidence. Any future new proposal
must be revalidated; an old ALLOW is not a permanent action authorization.

## Autonomy and policy semantics

```text
Agent proposes
↓
Policy Gate validates
↓
Only whitelisted low-risk tests may later execute automatically
↓
Deterministic Executor performs action
```

No reasoning role may bypass policy. In Task 9.1, `allow` means only that the
proposal passes deterministic contract checks against the supplied snapshot.
It executes nothing, writes nothing and does not enable a runtime. Future actual
execution also requires target ownership/scope, authorized identities and current
policy at execution time; these are not inferred from EndpointContext metadata.

## Finding lifecycle and legal transitions

```text
hypothesis → planned → executed → observed → validated → confirmed
```

`hypothesis ≠ finding`; `observed ≠ validated`; `validated ≠ confirmed unless
reproduction requirements are met`.

| Current | Allowed next states |
| --- | --- |
| hypothesis | planned, rejected, inconclusive, blocked |
| planned | executed, blocked, rejected |
| executed | observed, inconclusive, blocked |
| observed | validated, rejected, inconclusive, blocked |
| validated | confirmed, inconclusive, rejected |
| confirmed, rejected, inconclusive, blocked | none within this lifecycle |

Rejected/inconclusive/blocked outcomes may trigger a new linked hypothesis in a
future runtime; they cannot silently revive this lifecycle or skip states.
`validate_transition` rejects unknown/illegal edges. Entering validated requires
a validated ValidationResult with evidence and criteria; entering confirmed
requires that result to be reproducible with reproduction references. This helper
validates a contract edge; it does not persist or emit a finding. Future promotion
must additionally resolve references, verify executor/validation lineage and assess
actual expected-vs-observed behavior. A boolean or an agent-written result alone
cannot serve as reproduction proof.

## Domain schemas and strict validation

Implementation: `src/agent/models.py`. Frozen dataclasses support strict
`from_dict` parsing and `to_dict`; unknown fields, invalid enums, missing IDs,
invalid timezone-aware timestamps and unsupported action types fail. Evidence
references are canonical run-relative artifact paths, optionally followed by a
stable typed ID fragment. Actionable hypotheses and proposals require at least
one reference. Canonical syntax is not proof of existence: Policy Gate resolves
proposal references through the trusted scan-scoped index and context links.

| Contract | Canonical fields |
| --- | --- |
| AgentObservation | observation_id, endpoint_context_id, facts, evidence_refs, coverage_gaps (gap IDs), created_at |
| AgentHypothesis | hypothesis_id, endpoint_context_id, hypothesis_type, statement, evidence_refs, required_evidence, status |
| TestProposal | proposal_id, hypothesis_id, endpoint_context_id, test_id, reason, evidence_refs, required_context, requested_action, risk_class, created_at |
| PolicyDecision | decision_id, proposal_id, decision, reason_code, reason, validated_evidence_refs |
| ToolExecutionResult | execution_id, proposal_id, test_id, started_at, completed_at, status, request_refs, response_refs, output_refs, error |
| ValidationResult | validation_id, proposal_id, execution_id, state, evidence_refs, validation_criteria, observed_behavior, reason, reproducible, reproduction_refs |
| CoverageGap | gap_id, endpoint_context_id (nullable for scan-wide gaps), kind, description, evidence_refs, blocked_test_ids |
| TransparentValidationTrace | trace_id, hypothesis_id, proposal_id, policy_decision_id, observed_facts, evidence_refs, validation_criteria, next_action_decision, stop_reason, execution_id, validation_id |

AgentHypothesis status is restricted to hypothesis/planned/rejected/inconclusive/
blocked, so it cannot self-promote to a confirmed finding. ValidationResult states
are exactly validated/rejected/inconclusive/blocked. Validated requires evidence;
reproducible requires explicit reproduction references distinct from the original evidence and validated state. Missing
evidence may be recorded for inconclusive/blocked outcomes without fabricated refs.
ToolExecutionResult status is completed/failed/blocked, never validated/confirmed.
Completed output requires references and ordered timestamps. Tool output is not a
finding. No verdict/severity/security-success fields exist on observations.

RequestedAction fields: action, host, canonical path, method, execution_mode
(automatic/manual), mutation and ParameterReference tuples (location/name only).
There are no commands, credential values, payloads, request bodies or arbitrary
URLs. V1 supports query/body parameter names actually present in request summaries;
path/header mutation is unsupported rather than inferred. Parameter consistency
requires an explicit referenced parameter; input mutation requires a matching
parameter location and name. One canonical template
path remains the existing EndpointContext identity; a future concrete target must
be selected from observed transaction references, not manufactured from a template.

Schema validation cannot prove that a free-form fact is true. Every observation
fact must cite supporting references through the observation evidence set; a future
verifier must compare facts and claimed semantics with authoritative evidence.
`validate_trace_links` checks hypothesis/proposal/policy/execution/validation IDs,
endpoint consistency, allowed execution lineage and referenced evidence membership.
Proposal hypothesis existence must similarly be resolved by a future caller before
execution; the pure Policy Gate does not pretend to be a hypothesis store.

## Transparent attack validation

Store product-safe structured decision traces only, never private chain-of-thought
or hidden reasoning transcripts. Trace references resolve to:

- Observed facts and hypothesis.
- Selected test/proposal and evidence references.
- Policy decision.
- Tool invocation (execution ID) and output references, when execution exists.
- Validation criteria, expected-vs-observed summary and result.
- Next action decision and stop reason.

Pre-execution traces have null execution/validation IDs; denied plans do not invent
an invocation. `validate_trace_links` rejects mismatched foreign keys and unlinked
trace references. Example future trace: resource identifier observed → hypothesis
that authorization needs validation → catalog proposal → policy allows → executor
reference → response/status/body-shape delta → inconclusive validation → request
additional evidence. This is a decision record, not a reasoning transcript or
confirmation of a vulnerability.

## Test Catalog — V1 descriptive contracts

Implementation: `src/agent/test_catalog.py`. The mapping and entries are immutable.
Entries have test_id, name, category, risk_class, required_context,
required_evidence, allowed_mutations, validation_requirements, stop_conditions,
auto_execution_allowed and allowed_actions. No entry contains an executable hook.

| test_id | Risk | Future automatic eligibility | Contract action |
| --- | --- | --- | --- |
| AUTHENTICATION_PRESENCE | passive | true | review_evidence |
| OBJECT_AUTHORIZATION | medium | false | object_access |
| FUNCTION_AUTHORIZATION | high | false | function_access |
| SESSION_HANDLING | low | false | session_check |
| INPUT_VALIDATION | low | true | input_check |
| PARAMETER_CONSISTENCY | low | true | check_parameter |

These are descriptive placeholders, not implemented security tests. Required
contexts and evidence are metadata preconditions, not a claim that ownership,
identity pairs or expected authorization behavior already exist. Future executable
tests require additional validated operational preconditions before enabling them.
Catalog validation requires comparison against linked expected/observed evidence;
HTTP status/crash/tool success alone is insufficient, and confirmation requires
reproduction. Stop conditions include policy denial, missing evidence, scope
boundary and inconclusive validation. Tests cannot be invented by the planner.

Risk vocabulary: passive, low, medium, high, destructive. Passive may qualify;
low may qualify only under its whitelist. Medium is blocked unless a future
explicit policy enables it; high/destructive are blocked in V1. Manual mode does
not bypass the risk block. Destructive action/mutation is always denied, including
attempts to mislabel it as passive. The schema recognizes a delete_resource marker
solely so policy can reject it, not as an executable catalog capability.

Future automatic eligibility requires ALL: known catalog test; auto flag true;
passive/low catalog-matching risk; existing EndpointContext; existing required
evidence and context; parameters backed by evidence; no destructive mutation;
Policy Gate ALLOW. No test currently executes automatically.

## Policy Gate contract and evidence index

Implementation: `src/agent/policy.py`, `evaluate_proposal(proposal,
endpoint_contexts, evidence_index)`. This pure function accepts a strict model or
untrusted dictionary, existing EndpointContext instances keyed by ID, and a
caller-owned index of EvidenceRecord(reference, endpoint_context_id, kind).

The caller must construct the index from successfully resolved canonical artifacts
for ONE scan. Agent-supplied indexes are forbidden. Missing/corrupt/unresolved
records must be omitted; files are not read by this gate. No filename existence
assumption is made. Identity-level fragments supported by the V1 policy index:

- `dynamic/endpoint_contexts.json#endpoint_context_id=...`
- `dynamic/traffic.json#transaction_id=...`
- `static_analysis_report.json#candidate_id=...` (honor source/surrogate provenance)
- `dynamic/api_correlation.json#correlation_id=...`
- `dynamic/runtime_evidence.json#action_id=...`
- `dynamic/traffic_evidence.json#action_id=...`

Other canonical files may be referenced in domain summaries; index-supported
identity selectors remain deliberately narrower. References require the same
endpoint ID and membership in existing EndpointContext evidence_refs. Missing
transactions explicitly listed by the context cannot satisfy evidence requirements.
Whole-file references cannot satisfy an actionable endpoint prerequisite. A static
candidate selector requires source_report provenance and the same source ID.
Correlation-side surrogate IDs must be referenced through ApiCorrelation or
EndpointContext, never represented as an ID originally present in the static report.

The gate checks schema, known catalog ID, existing endpoint identity, risk match,
passive/low eligibility, exact literal host/path and evidenced method, catalog action
and mutation, automatic whitelist, indexed references, required evidence kinds,
required context, and evidenced query/body parameter names. No numeric/UUID wildcard,
fuzzy endpoint/host matching, URL inference or path expansion occurs.

Decisions: allow / deny / needs_evidence. Stable reason codes:
ALLOWED, UNKNOWN_TEST, UNKNOWN_ENDPOINT_CONTEXT, MISSING_EVIDENCE,
MISSING_REQUIRED_CONTEXT, PARAMETER_NOT_IN_EVIDENCE, RISK_NOT_ALLOWED,
DESTRUCTIVE_ACTION, AUTO_EXECUTION_NOT_ALLOWED, SCHEMA_INVALID,
ENDPOINT_NOT_IN_EVIDENCE, UNSUPPORTED_ACTION. Missing evidence/context returns
needs_evidence (never ALLOW); malformed/unsupported/unsafe inputs deny.
Deterministic decision IDs and sanitized reason text do not echo raw proposals.

The gate does not call LLMs/network/tools, execute or mutate requests, change
artifacts, infer missing endpoint data, generate findings, or assign severity.

## Evidence lineage and privacy boundary

```text
Finding
→ ValidationResult
→ ToolExecutionResult
→ TestProposal
→ AgentHypothesis
→ EndpointContext
→ ApiCorrelation
→ TrafficTransaction / Static Candidate
→ Provenance
```

This is future finding lineage, not a currently implemented finding emitter.
Every future stage resolves links to actual scan-scoped evidence; a schema-valid
agent statement or fabricated reference cannot originate new authoritative evidence.

Future agent input is EndpointContext + relevant evidence summaries + Coverage
Context + a Test Catalog subset. Do not send full raw JADX output, entire logs,
full traffic dumps, full route graphs, raw credentials or unnecessary historical
scans. Secret values (bearer tokens, cookies/session values, passwords, API keys,
refresh tokens, authorization values) are forbidden in agent input/output. Use
presence/type/reference only. References never contain query strings or values.
The schemas have no credential-value fields, reject extra fields and detect common
accidental credential text. Pattern guards cannot detect every secret: callers must
use existing sanitized summaries and enforce privacy before model boundaries.

## CoverageGap semantics

Kinds: static_not_observed, https_visibility_unavailable, max_steps, max_depth,
input_skipped, traffic_unavailable, external_package, system_ui, policy_blocked,
required_evidence_unavailable. Each has stable gap ID, optional endpoint ID,
description, supporting refs when obtainable, and blocked test IDs. A missing
artifact gap can honestly have no evidence ref; it must not fabricate a file.
CoverageGap exists independently of hypotheses, tests and validation results.
No gap may be converted into “secure”, “not vulnerable”, or “no findings possible”.

## Future milestone: vulnerability chaining (backlog, no runtime)

```text
Validated Step A → produces new evidence/context → enables Step B
→ Step B produces validated evidence → enables Step C
```

NO EVIDENCE → NO CHAIN EDGE. Future conceptual schemas:

- **AttackPath:** path_id, scan_id, step_ids, edges, state, evidence_refs.
- **AttackPathStep:** step_id, proposal_id, execution_id, validation_id,
  endpoint_context_id, validation_state, produced_evidence_refs.
- **Chain edge:** source_step_id, target_step_id, evidence_refs,
  dependency_reason, validation_state.

A dependency must reference validated evidence enabling the next step; an agent
claim cannot create an edge. Every new step receives its own policy check.
Future loop: Observe → validate new capability → update context → re-plan → policy
gate → next action. No chain executor or chained attack runtime exists in V1.

## Future milestone: PoC contract (no execution)

PoC is NOT an LLM statement. PoC requires deterministic execution, reproducible
sequence, evidence references and validated expected-vs-observed behavior.
Future **PoCRecord**: poc_id, finding_id, steps, request_refs, response_refs,
expected_behavior, observed_behavior, validation_refs, reproducible.
Steps reference ordered deterministic executions; repeated evidence must establish
reproducibility. Agent may propose a plan but may not claim “PoC generated” without
deterministic executor evidence. No PoC artifact or execution is created here.

## Future milestone: historical scan processing (backlog)

Future **HistoricalFindingReference**: historical_scan_id, finding_id, fingerprint,
endpoint_identity, validation_refs, validated_at, code_runtime_version,
requires_revalidation. Historical processing may compare previous finding
fingerprints, validated attack paths, endpoint inventories, resolved findings,
new/changed endpoints, changed runtime behavior and changed coverage.

Goal: focus new scans on changed functionality while preserving prior validated
evidence history. Previously validated ≠ currently validated. Historical facts
are not automatically current evidence; code/runtime changes may require
revalidation. Historical references are separate from the current scan index.
No active historical memory, persistence or scan-diff engine is implemented here.

## Task 9.1 foundation boundaries and verification

Future conceptual schemas above live only in this specification. Task 9.1 adds
no production prompts, tool calling, executor, runtime orchestration, attacks,
Agent Report or scan-state wiring. Tool calling waits for stable catalog, schemas,
policy and validated agent output. Existing `agent_analysis=not_available` and
Agent Report availability=false remain unchanged. No `agent_report.json` is emitted.

Focused tests cover schemas, invalid output, lifecycle/reproduction, policy risks,
endpoint/parameter/evidence bindings, trace links, privacy and passive implementation
boundaries. Relevant endpoint-context, correlation, dynamic-report, scan-state,
orchestrator and static-report suites must remain green.


## Task 9.2 — isolated Context Analyst V1

Architecture:

```text
One canonical EndpointContext
→ deterministic input selection/sanitization
→ context_analyst_v1 instruction + strict output schema
→ AgentModelClient.generate
→ deterministic identity/evidence/semantic validation
→ AgentObservation + AgentHypothesis[] + CoverageGap[]
→ optional agent/context_analysis.json internal artifact
```

The service is callable independently and has no production orchestrator, HTTP
route, automatic scan invocation, product-stage completion or Agent Report wiring.
Task 9.1's no-runtime/no-prompt boundary described its foundation milestone; this
section authorizes only the first read-only reasoning role. Test Planner, Evidence
Verifier, tools and deterministic execution remain future phases.

### Input adapter and bounds

`build_context_analyst_input` selects permitted fields from one existing
EndpointContext without mutating it. `load_context_analyst_input` reuses the
canonical EndpointContextArtifact loader, resolving one endpoint ID from
`dynamic/endpoint_contexts.json`; duplicates/missing IDs fail. It checks artifact
size (2 MiB) and run-directory containment. Other endpoints never enter a prompt.

Allowlisted input sections are endpoint identity, static provenance/match metadata,
observed methods/transaction/action IDs, request header/key names and shapes,
response status/content type/shape summaries, three-state auth flags, runtime
observation flags, visibility, bounded supplied coverage metadata and canonical
references. Raw headers, request/response body values, credentials, logs, JADX,
arbitrary graph fields, unrelated endpoints and local source paths are discarded.
Body-shape leaves can only be known type tags or unknown; objects/arrays have
bounded width/depth/node budgets. Source collections above hard limits fail before
a model call, rather than creating an unbounded prompt.

Input maximum: 32 KiB; named/ID collections: 32 selected values; source collection
hard limit: 256; body shapes: 4 selected, depth 3, 256 nodes per shape; action/route
summaries: 8 each; reference universe: 64. Values are sorted before selection.
Any selected-summary truncation is explicit as input_truncated and a coverage gap.
Coverage metadata accepts only availability/boundary flags and enumerated stop
reasons. This is an adapter over existing metadata, not a second Coverage Engine.

References are assembled only from the selected context and its linked IDs.
Transactions recorded missing are excluded. Actual source candidate IDs may refer
to static report selectors; correlation-side surrogates never become source-report
selectors. An optional trusted available_evidence_refs set can only narrow the
universe, not add references. The in-memory context is a caller-supplied canonical
snapshot; the adapter does not pretend to resolve every source artifact itself.

Unknown != false. Auth flags absent from summaries, subtype-redacted flags and
static-only/unavailable-transaction auth context stay null. Body absence without
observational evidence stays unknown. Unavailable runtime evidence cannot create
false event-absence facts. Static-only describes not observed within available
traffic, not unused/dead/false positive; dynamic-only does not blame extraction.
Method mismatches preserve static and observed methods separately. Numeric/UUID
literal paths do not create resource placeholders. Path identifier detection reuses
existing explicit segment syntax; named query/body identifiers are descriptive,
never proof of ownership.

### Versioned instruction and model boundary

The production asset is `src/agent/context_analyst/context_analyst_v1.txt`, loaded
through prompts.py. Version is context_analyst_v1. It requires supplied evidence,
unknown/coverage preservation, no unsupported security inference, no TestProposal,
no executable recommendations, no findings/private reasoning and strict JSON.

AgentModelClient is a minimal generate(ModelRequest) → ModelReply protocol.
Requests carry versioned instruction, detached sanitized input, output schema,
attempt number and optional fixed correction. Reply metadata is limited to a
provider label and model identifier, not arbitrary provider responses or secrets.
No provider SDK, external dependency or credential setup was added. Offline fakes
live only under tests. A future caller supplies an authorized provider implementation;
this task does not call a live external service.

### Output and bounded reasoning semantics

ContextAnalystInput and ContextAnalystResult are wrappers; the existing canonical
AgentObservation, AgentHypothesis and CoverageGap are reused without parallel
redefinitions or changes to their existing fields. Descriptive endpoint_role lives
on the result wrapper. Role vocabulary is authentication_endpoint, resource_endpoint,
collection_endpoint, profile_endpoint, transaction_endpoint, upload_endpoint,
unknown. Only roles supported by supplied input are accepted; unknown is always valid.

The input adapter supplies a fact catalog and evidence-backed hypothesis candidates.
V1 deliberately constrains observations to these supported statements and requires
the known identity/runtime/method/auth/visibility facts to survive summarization.
The model chooses supported descriptive role and relevant optional questions; it
cannot invent prose facts or findings. This narrow choice boundary provides stronger
semantic checks than accepting arbitrary schema-valid security prose.

Hypothesis vocabulary: object_authorization_candidate,
function_authorization_candidate, authentication_behavior_candidate,
session_behavior_candidate, input_validation_candidate,
parameter_consistency_candidate, coverage_limitation. Each candidate has explicit
input preconditions, a safe question/condition statement, supporting refs and
missing evidence. All initial states are hypothesis. Static-only administrative
paths alone do not enable authorization hypotheses. Authorization/session presence
cannot establish correctness; resource identifiers cannot establish ownership.
CoverageGap records remain separate and mandatory; an optional coverage_limitation
question does not replace or promote a gap to a finding.

Output validation rejects unknown fields at every canonical record, unsupported
hypothesis/role/statement/precondition, missing or fabricated refs, endpoint changes,
lifecycle promotion, omitted known facts/gaps and inconsistent ID links. Observation,
hypothesis and gap IDs are deterministic and constrained by the schema. Every output
ref must belong to the original input universe, even if a client mutates its detached
request copy. Schemas derive canonical field/required names from existing dataclasses;
context-specific semantic constraints are additionally enforced deterministically.

Maximum model output is 32 KiB, with 32 items per collection, depth 8 and a bounded
validation node budget. JSON strings and structured replies are supported; duplicate
JSON keys and prose-only responses fail. Output ordering and analysis IDs normalize
fact/reference/hypothesis/gap ordering. A successful result records analysis ID,
prompt version, endpoint ID, canonical records, role, safe model metadata, creation
time, input references, attempts and fixed validation diagnostic codes.

Only product-safe trace metadata is exposed: prompt version, input refs, observation,
hypothesis and gap IDs, diagnostic codes and provider/model labels. No chain-of-thought,
raw failed output or raw provider exception is stored.

### Failure, retries and optional persistence

States: completed, invalid_output, model_error, input_invalid. Failure carries no
observation, hypotheses or invented gaps. Invalid input never calls the client.
Schema/semantic invalid output may retry once (max_attempts 1 or 2); the correction
is fixed and never includes rejected output. Provider errors stop without echoing
credentials or raw exceptions. There is no open-ended retry loop.

The optional batch helper sorts endpoints, defaults to at most 16 (hard max 32),
sends one endpoint per request and preserves successes when another endpoint fails.
Duplicate endpoint identities and oversized batches fail deterministically.

Successful results can be explicitly persisted at
`demo_runs/<run_id>/agent/context_analysis.json`. This internal artifact contains
schema_version, prompt_version and analyses sorted by endpoint_context_id. Atomic
replacement preserves the previous file on failure. Serialized writes merge successful
endpoint results and do not erase successes because another endpoint failed. A retained
record keeps its original created_at; it is a previous successful analysis snapshot,
not a claim that a newer failed attempt succeeded. Corrupt existing artifacts fail
instead of being silently overwritten. Persistence is bounded at 64 endpoints/2 MiB.

No persistence call changes scan_state.json, Agent Report availability or product
stage semantics. agent_analysis remains not_available. No agent_report.json,
TestProposal, Policy Gate invocation, tool call, request execution, replay, fuzzing,
exploit, vulnerability confirmation, PoC, Test Planner runtime or Evidence Verifier
runtime is introduced.


## Task 9.3 — Test Planner V1 runtime

`src/agent/test_planner/` consumes one EndpointContext plus a completed, currently
grounded ContextAnalystResult. It reuses the Analyst sanitizer and validator,
rejects mismatched endpoint IDs/stale facts, and exposes only sanitized identity,
 presence flags, input names/shapes, evidence refs, hypotheses and coverage. Raw
 secrets, body values, logs, filesystem paths and unrelated endpoints are excluded.

The deterministic hypothesis-to-test mapping narrows the immutable canonical
catalog before the model boundary. Runtime-dependent tests require observed
transaction evidence and available traffic coverage. Object authorization requires
resource identifiers; session handling requires session-related presence metadata;
input validation follows the catalog's body-input prerequisite; parameter
consistency requires multiple parameters or a method mismatch. Authentication
presence is descriptive metadata review, including known absence where appropriate,
not a claim that login requires an Authorization header. Function authorization is
withheld: the current Analyst boundary cannot establish independent role/permission
evidence beyond path naming. Catalog risk and auto-execution metadata are unchanged.

The existing TestProposal fields remain canonical. RequestedAction additionally
supports catalog-defined abstract actions with execution_mode `proposal_only`.
For this mode, host/path/method must be empty, mutation must be `none`, and parameters
must be empty. Existing concrete actions retain automatic/manual validation.
This representation specifies conceptual relevance, never a request target.

The versioned asset `test_planner_v1.txt` and shared AgentModelClient interface
allow selecting supplied, grounded candidates or returning an empty plan. Reasons
and preconditions are bounded deterministic summaries; the model chooses relevance,
not new tests, evidence, arbitrary prose or payloads. Proposal validation checks all
ten canonical fields, supplied hypothesis links, catalog membership, exact risk,
abstract action, current endpoint, required support refs, missing preconditions,
ID and timestamp. Unknown, finding, execution and approval fields are rejected.

Proposal IDs hash endpoint_context_id + hypothesis_id + test_id. Identical validated
proposals deduplicate; conflicting duplicates reject. Result states are completed,
no_relevant_tests, invalid_output, model_error and input_invalid. No relevant tests
is successful and does not force work. Invalid output retries at most once;
model errors terminate immediately and do not echo raw provider errors. Trace data
contains only versions, IDs, evidence references and validation error codes.

Explicit persistence writes `demo_runs/<run_id>/agent/test_plans.json` atomically,
merging successful endpoint records in deterministic order. Failed endpoint attempts
do not erase previous successes; corrupt artifacts reject. Records are bounded to
64 endpoints/2 MiB. The optional batch helper invokes isolated single-endpoint
planning, default limit 16 and hard maximum 32, with no whole-scan reasoning.

The Planner does not invoke Policy Gate. No execution approval, tools, executor,
network request, request replay, fuzzing, verifier, findings, severity, PoC or
agent_report.json is introduced. Public agent_analysis remains not_available.
Task 9.4 Policy Gate integration remains outside this implementation.


## Task 9.4 — explicit Planner ↔ Policy Gate integration

`src/agent/policy_integration/` accepts one EndpointContext, completed and currently
grounded ContextAnalystResult, TestPlannerResult or bounded TestProposal[], plus
the existing caller-verified scan-scoped EvidenceRecord index. It rebuilds the
sanitized input and revalidates proposals without invoking either reasoning role.
Hypothesis, endpoint, catalog risk, bounded references, abstract action, fixed
reason/preconditions and deterministic proposal identity remain enforced.

The pure existing Gate supports proposal_only abstract actions with no request
construction or execution. Legacy concrete contract evaluation remains isolated
from the integration adapter, which rejects concrete/raw instructions. Passive
and low risk may be allowed if all required evidence/context exists. Medium/high
and destructive risks remain blocked. Catalog auto_execution_allowed is retained;
proposal_only is not automatic execution and never approves an execution mode.

Unknown/hallucinated references deny; a declared but unavailable transaction or
missing verified index record needs_evidence. Catalog dotted prerequisites are
checked against EndpointContext, including unknown versus known auth presence.
Human-readable Planner prerequisites require explicit caller-verified
PreconditionRecord metadata with linked canonical evidence; string equality or
credential presence does not prove expected behavior, ownership or authentication.
No automatic production resolver of those semantics is introduced. Omission means
needs_evidence. HTTPS gaps do not globally deny tests. Stale or structurally invalid
upstream analysis cannot be used to authorize proposals.

Canonical PolicyDecision adds policy_version=`policy_v1` and optional endpoint,
hypothesis and test IDs. Integration populates source lineage. Existing reason
codes remain; UNKNOWN_HYPOTHESIS and HALLUCINATED_EVIDENCE distinguish specific
integrity failures from insufficient evidence. Safe missing-context reasons identify
the prerequisite; traces contain source IDs, decisions, reason codes/reasons and
validated refs, never private reasoning. Stable decision IDs include policy version
and the existing proposal/decision/reason-code/evidence convention, with no clock.

PolicyEvaluationResult carries evaluation/planning/endpoint IDs, version, created_at,
canonical decisions and derived allow/deny/needs_evidence/total counts. Evaluated
records contain decisions; no_relevant_tests produces no_proposals with zero.
Failed Planner statuses and invalid envelopes produce not_processed with zero;
no fake proposals or policy decisions are invented. Individual invalid proposals
in the proposal-array adapter produce deny linked to supplied IDs. Neither
needs_evidence nor denial triggers re-planning or Context Analyst re-runs.

Explicit atomic persistence writes agent/policy_decisions.json with schema/policy
versions and endpoint-sorted evaluation envelopes, each containing proposal-sorted
decisions. Merge bounds are 64 endpoint records/2 MiB; writes for one run must be
serialized by callers. Skipped evaluations preserve earlier successes; failures do
not alter upstream artifacts. Corrupt prior artifacts reject rather than overwrite.

POLICY ALLOW ≠ EXECUTE. No tools, model calls, network, executor, replay, mutation,
fuzzing, verifier, PoC, findings or Agent Report are introduced. Public
agent_analysis remains not_available. Evaluation is explicit, not automatically
wired into the Planner or public scan orchestration.

Agent development uses focused task tests plus directly affected adjacent suites.
Full historical regressions/integration run only at explicitly requested checkpoints,
approximately every three Agent implementation tasks. Task 9.4 is not a checkpoint.


## Task 9.5 — model selection and development evaluation

Models are selected by versioned benchmark evidence, not hardcoded architectural
assumptions. Future routing may select different AgentModelClient implementations
for Context Analyst and Test Planner; no winning model or production provider is
selected now. Evidence Verifier remains outside the current implemented roles.

The development-only `agent_benchmark_v1` dataset and `scoring_v1` harness preserve
production prompt versions, structured gold expectations and separate role metrics.
Raw rejected outputs are audited ephemerally for grounding, role-boundary and schema
violations; reports persist safe counts/enums/IDs, not raw responses or private
reasoning. Overreach/miss proxies measure benchmark task behavior, not production
vulnerability false-positive/negative rates. Policy remains deterministic and stops
at decisions. Reports live under benchmark_results/agent_v1, outside scan artifacts.

Task 9.5 is the explicitly requested full regression checkpoint. Benchmark runtime
introduces no live provider, tool/executor, active API testing, verification/finding,
PoC, Agent Report or public stage update; agent_analysis remains not_available.
