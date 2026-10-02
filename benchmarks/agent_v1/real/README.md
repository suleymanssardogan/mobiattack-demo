# Real pilot dataset — real_pilot_v1

Task 9.5.2 populated this directory with **1 real unreviewed candidate from
1 authorized training application**. No case has human-reviewed gold yet.
The pilot is NOT_READY_FOR_LOCAL_MODEL_BENCHMARK: additional usable development
and holdout application evidence plus independent human gold review are missing.
See TASK_9_5_2_COMPLETION.md and examples/task_9_5_2/population_status.json.
Examples under examples/task_9_5_1 remain synthetic and are never real input.

The candidate review template is in real/review_queue. It contains empty
structured labels, not an Agent answer. Set labels/status/reviewer only after
independent human inspection, then apply with save_review as described below.

The synthetic core stays in benchmarks/agent_v1/cases with its original manifest.
The separate real family uses agent_benchmark_v1 and real_pilot_v1.

## Authorized import

1. Run an owned, explicitly authorized, appropriately licensed open-source, or
   training app through the existing MobiAttack pipeline:
   APK → static analysis → dynamic exploration → traffic evidence →
   API correlation → dynamic/endpoint_contexts.json.
2. Record authorization locally. Metadata stores only a source classification;
   it cannot prove consent and must not contain account/owner names.
3. Import that explicit artifact. The importer never scans arbitrary folders,
   runs an app, calls a model, sends requests or replays traffic:

~~~bash
python -m src.agent.evaluation.real_dataset \
  --endpoint-contexts <authorized-run>/dynamic/endpoint_contexts.json \
  --app-id app_001 \
  --source-type owned_app \
  --split development \
  --scan-reference scan_001 \
  --output benchmarks/agent_v1/real
~~~

Output is the dataset root, not the app directory. Use --app-id app_004
--split holdout to reserve an app for final comparison. Names are user-selected
aliases, never hardcoded application identities. Pilot target: 3–4 apps with
complementary auth/session, resource/object and input/query/body coverage;
reserve at least one entire app as holdout.

Output:
real/manifest.json
real/apps/<app_id>/metadata.json
real/apps/<app_id>/cases/<stable_case_id>.json

Re-importing an existing app is rejected to protect reviewed work. Use a new
versioned dataset snapshot for revised source evidence. JSON files use atomic
replacement, not a multi-file transaction; validation detects inconsistent
counts after interrupted writes.

## Privacy

Hosts are aliased by default using an app-scoped deterministic digest.
Different hosts remain different. No fuzzy matching or exported reverse mapping.
Numeric/UUID path segments become stable literal resource aliases, never
templates. Explicit templates remain explicit. Email/phone-like segments are
minimized; query values are removed.

For names, account slugs, addresses or other identifiers whose sensitivity
cannot be determined syntactically, supply repeatable --sensitive-path-segment
values and inspect exported candidates. This is lightweight minimization, not
general DLP. Python callers can preserve a public host with alias_hosts=False;
CLI imports always alias hosts.

Only structural names, type-only shapes, boolean/unknown presence, statuses,
visibility, provenance IDs and bounded coverage survive. Raw credentials,
headers, bodies, logs and source paths are dropped. Unexpected shape values
become unknown. Unsafe IDs and filesystem endpoint identities are rejected.
Safe canonical context/evidence IDs stay traceable. Source artifacts are never
written. Scan references must be sanitized identifiers.

## Human review

4. Generate a separate label template; do not edit input:

~~~python
import json
from pathlib import Path
from src.agent.evaluation.real_dataset import load_real_cases, review_template
cases = load_real_cases(reviewed_only=False)  # development only
Path("review_labels.json").write_text(json.dumps(review_template(cases[0]), indent=2))
~~~

5. Set anonymous reviewer_ids to reviewer_1 and optionally reviewer_2; inspect
   source evidence independently of Analyst or Planner answers.
6. Assign structured labels and reviewed, disputed or excluded status.
7. Apply labels and validate:

~~~python
from src.agent.evaluation.real_dataset import save_review, validate_real_dataset
labels = json.loads(Path("review_labels.json").read_text())
save_review("benchmarks/agent_v1/real", labels)
validate_real_dataset()
~~~

Candidates begin unreviewed with gold=null. Official selection includes only
reviewed cases. Excluded cases remain on disk but never enter scoring selection,
even with reviewed_only=False. Disputed cases are available only for inspection.
App counts and review summary update when saving labels.

Gold reuses scorer fields: allowed/expected/forbidden hypothesis lists,
expected/forbidden test IDs, expected_endpoint_role, expected_coverage_gaps,
unknown_fields, expected_policy_outcomes and must_not_emit_finding=true.
Lists support zero or multiple labels. Expected hypotheses must be allowed;
positive and negative labels cannot conflict. No prose gold. The current scorer
has no acceptable_test_ids vocabulary; this task adds none. Endpoint role stays
the current singular enum. Human labels may disagree with current deterministic
heuristics: missed human-supported hypotheses must remain scoreable.

Empty labels are valid for ambiguous/no-relevant-test cases. Exclude cases
with unclear truth rather than force labels. Notes must be short and safe.
No synthetic expected-behavior precondition proofs are inserted into real cases.
A human policy-outcome label is not authentication/ownership proof.

## Splits, scoring and freeze

8. Reserve one app as holdout; splits are explicit and stable at app level:

~~~python
development = load_real_cases()  # reviewed, non-holdout only
final_comparison = load_real_cases(include_holdout=True)
~~~

Both validate the dataset. Final comparison selection is explicit.
Administrative validation can inspect holdout gold; it never feeds it to
prompts. Do not tune prompts, hypothesis/catalog mappings or scoring weights
using holdout cases.

RealBenchmarkCase.model_input() uses the production Context Analyst adapter
with canonical input only. Gold, reviewer notes, split and tags stay scorer-only.
scoring_case() provides the existing BenchmarkCase shape and refuses
non-reviewed cases. The synthetic benchmark runner stays unchanged and never
automatically ingests this directory. Future comparison wiring must explicitly
load reviewed real cases and use model_input; never send to_dict to a model.

Python import accepts coverage_metadata for scan-level traffic/exploration
limits. The CLI never invents scan-level coverage. Endpoint visibility,
runtime confirmation, missing references and match type remain available.
Static-only means not observed in available runtime traffic, never unused.
Dynamic-only means no matching static candidate, never proof of analyzer failure.

9. Before Task 9.6 freeze dataset version, gold, splits, prompt versions
   (context_analyst_v1/test_planner_v1), scoring_v1 and snapshot fingerprint.
   Increment real dataset version when input/gold/splits change. The initial
   importer/validator accepts only real_pilot_v1; a next version requires an
   explicit schema/version update, not silent relabeling. Archive the whole
   frozen snapshot outside the mutable import workspace.

Task 9.6 may implement local Qwen, DeepSeek or other compatible clients through
AgentModelClient. No such client, execution, live comparison or model winner
is introduced here.

Development artifacts never belong in demo_runs/<run_id>/agent.
agent_analysis remains not_available. No agent_report.json, executor,
tool calling, findings or active API testing.

Focused tests: pytest tests/test_real_benchmark_dataset.py -q.
No full regression checkpoint for Task 9.5.1.
