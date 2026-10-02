# Task 9.5.3 candidate evaluation

Actual acquisition and compatibility receipts; no synthetic cases or gold labels.
Official training sources were investigated first. The user then explicitly expanded
scope to normal Play Store applications. Those are explicitly_authorized_app for local
analysis and normal passive UI exploration, with no vendor/backend security authorization claim.

| Candidate | Compatibility | Contexts | Selected |
|---|---|---:|---|
| app_004 | compatible | 0 | no |
| app_005 | compatible | 0 | no |
| app_006 | compatible | 0 | no |
| app_007 | excluded | None | no |
| app_008 | unsupported_android_version | None | no |
| app_009 | unsupported_android_version | None | no |
| app_010 | compatible | 0 | no |
| app_011 | compatible | 0 | no |

See candidate_matrix.json for source URLs, releases/commits, SHA-256 hashes,
split APK component hashes, authorization scope, failures and capture limitations.
Raw APKs and lab artifacts remain ignored under artifacts/task_9_5_3 and demo_runs.

Two genuine pipeline blockers were fixed: configurable capture port (default remains
8080) and static parsing of declared enabled launcher aliases. APK manifests, SDK and
ABI declarations were not modified. The existing website on 8080 remained running.

DATA_COLLECTION_READY=false; MODEL_BENCHMARK_READY=false.
New cases imported: 0. Existing app_001: preserved, unreviewed, gold=null.
No empty application was assigned a development or holdout split.
