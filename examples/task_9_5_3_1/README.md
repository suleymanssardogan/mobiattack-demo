# Static discovery diagnostic receipts

Development-only source inventory for the five existing Task 9.5.3 applications.
This directory is not a benchmark dataset and never feeds the benchmark importer.

Before/after inventories record aggregate counts plus at most 512 representative
signals, prioritizing explicit context. The bound is 2 MB/file and 128 MB/app.
Occurrences include duplicated Smali/Java/resource representations. They are not
unique endpoint counts. Network-context triage is not an API classifier.

URL hosts/paths are hashed; query, fragment and userinfo dropped. Original relative
source file and line are retained for local inspection. Raw source lines, binary
payloads, account data and filesystem paths are not exported. Native string line
numbers are null because they are not textual source line numbers.

before_after.json records actual canonical static/correlation/EndpointContext
reruns from existing artifacts, with original runtime evidence reused. No download,
installation, exploration, request generation, benchmark import or gold labeling.

See STATIC_API_DISCOVERY_DIAGNOSTIC.md and TASK_9_5_3_1_COMPLETION.md at repo root.
