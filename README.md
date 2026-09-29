# MobiAttack — Mobile Security Analysis Platform

MobiAttack is a deterministic mobile security analysis engine and structured static-analysis verification platform supporting Android (monolithic APK and Split APKs) and iOS (IPA).

---

## DEMO 3 — Deterministic Static Extraction, Normalization & Structured Baseline

**Demo 3** establishes a reliable, structured-data static analysis baseline designed to serve as the ground-truth data contract for future runtime correlation and agentic security modules.

### Demo 3 Pipeline Flow

```
Application Link (Direct APK / Google Play Store / IPA)
        ↓
APK / Package Acquisition
        ↓
Archive & Format Validation
        ↓
Decompilation / Artifact Extraction (Apktool / JADX)
        ↓
Deterministic File Walking (sorted traversal, type filtering, error accounting)
        ↓
Rule-based Candidate Extraction (URLs, Domains, API Paths, IPs, WebSockets)
        ↓
Raw Candidates (with source file, line number, and raw evidence snippet)
        ↓
Normalization (canonical scheme/host, port stripping, case-safe path preservation)
        ↓
Deduplication (canonical equivalence grouping WITHOUT losing provenance)
        ↓
Structured Candidate Objects (type, value, components, occurrences list)
        ↓
JSON Schema Validation (strict validation against schemas/baseline_report.schema.json)
        ↓
baseline_report.json (version 1.0.0 machine-readable artifact)
        ↓
Human-Readable Dossier (report.html) & Interactive Web Dashboard
```

---

## Core Concepts & Guarantees in Demo 3

### 1. Static Candidate vs Confirmed Vulnerability
- A **Candidate** represents a statically observed endpoint or network artifact (e.g. `https://api.example.com/v1/users`).
- It does **not** imply that the endpoint is active, reachable at runtime, or vulnerable.
- Candidates and static security findings (e.g. `cleartext_traffic_permitted`, `android:debuggable=true`) are strictly separated in both the structured data model and the UI.

### 2. Semantic-Preserving Normalization
- Hostnames and schemes are canonicalized to lowercase (e.g. `HTTPS://API.EXAMPLE.COM` → `https://api.example.com`).
- Standard default ports (`:80`, `:443`) are stripped.
- Path and query parameters preserve their exact casing and characters (e.g. `/v1/UserProfile?Token=AbCdEf` is never lowercased) to avoid breaking semantic meaning.
- Obvious syntax artifacts (trailing quotes, semicolons, brackets) are cleanly stripped.

### 3. Deduplication with Complete Provenance Preservation
- If the same endpoint appears in 10 different files (e.g. `ApiClient.smali`, `UserService.smali`, `config.json`), it is collapsed into **1 canonical candidate**.
- **Deduplication does NOT destroy provenance**: The canonical candidate retains an `occurrences` array documenting every physical observation:
  ```json
  {
    "id": "cand-8f2a1b9c3d4e",
    "type": "url",
    "value": "https://api.example.com/v1/users",
    "components": {
      "scheme": "https",
      "host": "api.example.com",
      "path": "/v1/users"
    },
    "occurrence_count": 3,
    "occurrences": [
      {
        "source_file": "smali/com/example/network/ApiClient.smali",
        "line_number": 148,
        "extraction_method": "network_url_pattern",
        "raw_value": "https://api.example.com/v1/users",
        "evidence": "const-string v1, \"https://api.example.com/v1/users\""
      },
      {
        "source_file": "smali/com/example/services/UserService.smali",
        "line_number": 72,
        "extraction_method": "network_url_pattern",
        "raw_value": "https://api.example.com/v1/users",
        "evidence": "const-string v0, \"https://api.example.com/v1/users\""
      },
      {
        "source_file": "assets/config.json",
        "line_number": 12,
        "extraction_method": "network_url_pattern",
        "raw_value": "https://api.example.com/v1/users",
        "evidence": "\"user_endpoint\": \"https://api.example.com/v1/users\""
      }
    ]
  }
  ```

### 4. Source & Minimal Evidence
Every candidate observation answers four fundamental questions:
1. **WHAT WAS FOUND?** The observed value and candidate type.
2. **WHERE WAS IT FOUND?** Source file path and line number.
3. **WHAT RAW CONTENT CAUSED THE MATCH?** Minimal un-truncated contextual code snippet (with sensitive data redacted).
4. **WHICH RULE PRODUCED IT?** Specific rule or regex identifier.

### 5. Deterministic Accounting: Completed vs Partial vs Failed
The scanner explicitly distinguishes between clean zero-finding scans and partial or aborted scans:
- **`completed`**: All discovered files were successfully analyzed with zero read/encoding failures (`files_failed == 0`). A scan reporting 0 candidates with status `completed` is verified clean.
- **`partial`**: Analysis completed over a subset of files, but some files could not be decoded or parsed (`files_failed > 0` and `files_analyzed > 0`).
- **`failed`**: The analysis could not analyze any files or experienced fatal decoding errors (`files_analyzed == 0` and `files_failed > 0`).

### 6. JSON Schema Validation & Machine Contract
- **Schema Location**: [`schemas/baseline_report.schema.json`](schemas/baseline_report.schema.json)
- **Schema Version**: `"1.0.0"`
- **Validation**: All baseline reports are strictly validated against the JSON Schema before being persisted as `baseline_report.json`. Validation errors raise explicit exceptions and are never silently ignored.

---

## Strictly Out of Scope (NOT IMPLEMENTED YET)

Demo 3 deliberately establishes the static foundation. The following are future roadmap phases:
- Dynamic analysis / instrumentation
- Runtime traffic interception (mitmproxy, Burp Suite)
- Autonomous AI security agents
- LLM-based vulnerability inference
- Active exploitation & automated PoC generation
- Vulnerability chaining & release gates

---

## System Requirements

- **Python**: 3.10 or newer (Standard library only; zero mandatory third-party pip dependencies).
- **Android Tools**:
  - `adb` (connected emulator or device, e.g. `127.0.0.1:5555`).
  - `apktool` (2.9+ recommended).
  - `jadx` (1.5+ recommended).
  - Java Runtime Environment (JRE/JDK 11+).

---

## Quick Start & Running the Demo

### 1. Launch the Web Dashboard
```bash
python3 scripts/run_web_demo.py --port 8082 --open-browser
```
Open [http://127.0.0.1:8082](http://127.0.0.1:8082) in your browser.

### 2. Run an Analysis
1. Select a preset (e.g. `MSTG Kotlin (Direct APK)` or `Flashlight (Splend)`).
2. Click **Start Analysis**.
3. View the **API Candidates** tab to inspect the Demo 3 Deterministic Static Inventory with canonical candidate counts and expandable provenance drawers.
4. Download the machine-readable contract by clicking **Baseline Report (Demo 3)** (`baseline_report.json`).

---

## Running Automated Tests

Run the full automated test suite (381 unit & integration tests):

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

Or run the focused Demo 3 test suite:
```bash
python3 -m unittest tests/test_demo3_pipeline.py
```
