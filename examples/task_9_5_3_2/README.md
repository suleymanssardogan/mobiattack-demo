# Retrofit V1 real-source measurements

Already-acquired Task 9.5.3 decoded artifacts only. No new apps, runtime traffic,
downloads or installations. The updated canonical extractor measured all five apps.

Wikipedia: 127 valid method/path declarations; 0 supported structural base bindings;
0 canonical Retrofit candidates. Other four apps: 0 qualifying declarations/candidates.

Unbound records are development diagnostics, never scan candidates or benchmark
EndpointContexts. Paths have query values omitted; source-relative file, method and
annotation/value positions are preserved. No raw logs, credentials or host filesystem
paths are included.

before_after.json reads baseline counts from original canonical reports and records
updated extraction counts. Candidate lists did not change, so original canonical
EndpointContext artifacts were retained and correlation/context stages were not rerun.

wikipedia_base_binding_diagnostic.json identifies the unsupported R8 constructor,
method-argument base and create(Class) flow. No arbitrary domain substitution.

Real declaration fixture and receipt: tests/fixtures/retrofit at repository root.
Completion report: TASK_9_5_3_2_COMPLETION.md.
