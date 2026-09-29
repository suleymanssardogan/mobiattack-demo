# MobiAttack V2: Architecture & Implementation Plan for Split APK Pipeline Support (Task 14)

## 1. Scope & Objective Definition

Task 14 establishes **split-aware pipeline support** across MobiAttack V2:
- Discover all installed APK splits for a given package on the connected Android device.
- Safely pull all splits to an isolated workspace and record deterministic metadata (size, SHA-256).
- Inventory and classify each split using evidence-based heuristics (with strict fallback to `unknown`/`other`).
- Preprocess each split independently in its own isolated sub-workspace to prevent filesystem collisions (`classes.dex`, `AndroidManifest.xml`, `resources.arsc`, `smali/`).
- Handle per-split tool behavior deterministically (e.g. no DEX in ABI/resource splits, decompilation warnings) without dropping components.
- Run **EXISTING** V1 analyzers (structure, network indicators, static API candidate extraction) across all applicable split smali/resource roots, attaching explicit `source_apk` provenance to all discovered evidence.
- Aggregate manifest components without pretending to perform complex build-time manifest reconstruction.
- Aggregate native library discovery (`filename`, `abi`, `source_apk`, `source_path`) with **NO** new native security assessments (no NX, RELRO, canaries, or symbol grading in Task 14).
- Preserve existing API candidate schema without inventing new static fields.
- Expose the split package layout and component inventory in the dashboard and reports without security grading or vulnerability verdicts.

---

## 2. Core Architectural Principles

1. **Non-Equivalence Principle**: When multiple APKs exist, `base.apk != complete application package`. All installed splits returned by `pm path` belong to the analyzed package set.
2. **Provenance Preservation**: Do NOT silently merge or flatten files. Every extracted indicator, smali root, DEX file, asset, native library, and component catalog entry must retain its `source_apk` provenance.
3. **No Unnecessary Runtime Churn**: The Play Store package is already installed on the device. The normal Play Store analysis pipeline does **not** uninstall and reinstall it via `adb install-multiple`; it pulls the installed splits directly, analyzes them, and launches/observes the existing installation.
4. **No Premature Analyzer Scope Creep**: Task 14 strictly adapts the existing analysis pipeline to split layouts. New security checks (native binary hardening, IPC audits, new HTTP frameworks, secret heuristics) are deferred to subsequent tasks.

---

## 3. Split Acquisition & Evidence-Based Inventory

### 3.1 Device Discovery
Query device via ADB:
```bash
adb -s <serial> shell pm path <package_id>
```
Sample multi-APK output:
```text
package:/data/app/~~.../base.apk
package:/data/app/~~.../split_config.arm64_v8a.apk
package:/data/app/~~.../split_config.tr.apk
package:/data/app/~~.../split_config.xxhdpi.apk
package:/data/app/~~.../split_extra_feature.apk
```

### 3.2 Evidence-Based Classification
Split classification uses file structure, manifest metadata, and naming evidence:
- **`base`**: Contains the master `AndroidManifest.xml` with no `split` attribute in `<manifest>`, core entry points, and primary app package definition.
- **`config_abi`**: APK containing compiled `.so` binaries under `lib/<abi>/` with minimal/no DEX.
- **`config_locale`**: APK containing localized XML resource tables (e.g. `res/values-<lang>/`) with no DEX.
- **`config_density`**: APK containing DPI-specific graphics/drawables with no DEX.
- **`feature`**: Split declaring a `split="<name>"` attribute in its manifest or delivering secondary DEX bytecode and assets.
- **`unknown` / `other`**: Any split whose structure or metadata does not conclusively match known config/feature patterns. **Non-base splits are never forced into an assumed category without evidence.**

### 3.3 Acquisition Ledger (`package_set.json`)
Every pulled APK is stored in `workspace/package_set/apks/` and validated independently:
```json
{
  "package_name": "com.example.app",
  "package_layout": "split",
  "split_count": 4,
  "components": [
    {
      "filename": "base.apk",
      "role": "base",
      "device_path": "/data/app/~~.../base.apk",
      "local_path": "workspace/package_set/apks/base.apk",
      "size_bytes": 42109812,
      "sha256": "3a1f9e...",
      "is_valid_zip": true
    },
    {
      "filename": "split_config.arm64_v8a.apk",
      "role": "config_abi",
      "device_path": "/data/app/~~.../split_config.arm64_v8a.apk",
      "local_path": "workspace/package_set/apks/split_config.arm64_v8a.apk",
      "size_bytes": 8450122,
      "sha256": "e7c201...",
      "is_valid_zip": true
    }
  ]
}
```

---

## 4. Isolated Decomposition & Preprocessing Architecture

### 4.1 Collision-Proof Directory Layout
To eliminate cross-split filename collisions (`classes.dex`, `AndroidManifest.xml`, `resources.arsc`, `smali/`), each split is disassembled in its own sub-workspace:

```text
workspace/
├── package_set/
│   ├── package_set.json
│   └── apks/
│       ├── base.apk
│       ├── split_config.arm64_v8a.apk
│       └── split_config.tr.apk
└── processed/
    ├── base/
    │   ├── raw_apk/
    │   ├── apktool_out/
    │   │   ├── AndroidManifest.xml
    │   │   ├── res/
    │   │   ├── smali/
    │   │   └── smali_classes2/
    │   └── jadx_out/
    │       └── sources/
    ├── split_config.arm64_v8a/
    │   ├── raw_apk/
    │   └── apktool_out/
    │       └── lib/arm64-v8a/*.so
    └── split_config.tr/
        ├── raw_apk/
        └── apktool_out/
            └── res/values-tr/strings.xml
```

### 4.2 Deterministic Per-Split Preprocessing & Failure Handling
Different splits naturally contain different contents. Preprocessing handles these deterministically:
- **DEX-less splits (ABI, density, locale)**: JADX decompilation is skipped or logs an expected `no_dex` status without marking the split as failed.
- **Resource decoding warnings**: Captured in component preprocessing logs; usable files are retained.
- **Per-Component Status**: Each component in `package_set.json` tracks its own preprocessing state:
  ```json
  {
    "filename": "split_config.arm64_v8a.apk",
    "apktool_status": "success",
    "jadx_status": "skipped_no_dex",
    "warnings": []
  }
  ```
- **Resilience**: An error in an optional split does not abort the entire pipeline. The package-level run records a warning and proceeds with all validly preprocessed splits.

---

## 5. Aggregation with Provenance Retention

### 5.1 Manifest Component Aggregation (Not Reconstruction)
- The base APK's `AndroidManifest.xml` serves as the primary application manifest (permissions, exported components, application class, target SDK).
- When a split APK contains an additional or partial manifest, its declared components and permissions are parsed and added to an aggregated component catalog, tagged with `source_apk`.
- No speculative Android build-system manifest merging is performed.

### 5.2 Native Library Inventory
Native libraries found in `base.apk` or any ABI split (e.g. `split_config.arm64_v8a.apk`) are cataloged:
```json
{
  "name": "libnative-lib.so",
  "abi": "arm64-v8a",
  "source_apk": "split_config.arm64_v8a.apk",
  "source_path": "lib/arm64-v8a/libnative-lib.so",
  "size_bytes": 1048576
}
```
*Note: Hardening checks (NX, RELRO, canary, banned APIs) are explicitly excluded from Task 14.*

### 5.3 Existing Static Analyzers with Provenance
1. **Network Indicator Extractor**:
   - Runs against all smali folders and resource XML files across all preprocessed splits.
   - Every extracted indicator retains provenance:
     ```json
     {
       "indicator": "https://api.backend.com/v1",
       "type": "url",
       "source_apk": "base.apk",
       "source_file": "smali/com/app/Network.smali",
       "line": 45
     }
     ```
2. **Static API Candidate Extractor**:
   - Evaluates call contexts across all smali roots from all splits containing code.
   - Preserves existing schema fields, augmenting each candidate with `source_apk`.
   - Does not alter candidate classification semantics.

---

## 6. Unified Static Context Schema

The aggregated static context representation includes:
```json
{
  "package_name": "com.example.app",
  "package_layout": "split",
  "split_count": 3,
  "components": [
    {
      "filename": "base.apk",
      "role": "base",
      "size_bytes": 35123000,
      "sha256": "...",
      "preprocessing_status": "success"
    },
    {
      "filename": "split_config.arm64_v8a.apk",
      "role": "config_abi",
      "size_bytes": 5210000,
      "sha256": "...",
      "preprocessing_status": "success"
    }
  ],
  "manifest_summary": { ... },
  "native_libraries": [ ... ],
  "network_indicators": [ ... ],
  "api_candidates": [ ... ]
}
```

---

## 7. Dashboard & Reporting Specifications

- **Package Layout Badge**: `Single APK` or `Split APK (N components)`.
- **Component Inventory Table**:
  - Filename (`base.apk`, `split_config.arm64_v8a.apk`)
  - Detected Role (`base`, `config_abi`, `config_locale`, `config_density`, `feature`, `unknown`)
  - Size & SHA-256
  - Preprocessing Status (`success`, `skipped_no_dex`, `warning`)
- **Evidence Provenance Column**:
  - Network indicators and API candidate lists display a `Source APK` badge linking evidence to its originating split.
- **Reporting Stance**: Purely factual and evidential; no vulnerability verdicts or security scores.

---

## 8. Phased Implementation Plan

To ensure strict stability and testability, Task 14 will be executed in four controlled phases:

```
[Phase A: Acquisition & Inventory]
       │
       ▼
[Phase B: Isolated Preprocessing]
       │
       ▼
[Phase C: Provenance Aggregation]
       │
       ▼
[Phase D: Dashboard & Reports]
```

### Phase A: Split Acquisition, Inventory & Validation
- Enhance `play_store_acquirer.py` to parse all lines from `pm path`.
- Pull all APKs into `workspace/package_set/apks/`.
- Validate ZIP structure and calculate SHA-256 for each split.
- Generate `package_set.json` with classification (base / config_abi / config_locale / config_density / feature / unknown).
- *Verification*: Unit tests for single vs multi-APK pulling, metadata extraction, and unknown split classification.

### Phase B: Per-Split Isolated Preprocessing
- Enhance `apk_preprocessor.py` to accept a package set.
- Deconstruct each split into `workspace/processed/<split_name>/`.
- Safely handle DEX-less splits (skip JADX, keep apktool resources/libs).
- Record per-split preprocessing status and warnings in `package_set.json`.
- *Verification*: Tests with synthetic multi-split packages verifying no directory collisions and clean handling of DEX-less splits.

### Phase C: Analyzer Execution & Provenance Aggregation
- Pass all smali roots, resource dirs, and native lib dirs to existing extractors (`apk_structure_extractor.py`, `network_indicator_extractor.py`, `api_candidate_extractor.py`).
- Add `source_apk` to all extracted records without altering existing field schemas.
- Build unified `static_context.json`.
- *Verification*: Assert provenance tags on all extracted indicators and verify backward compatibility with single-APK packages.

### Phase D: Dashboard & Report Integration
- Update `demo_web_server.py`, `report_generator.py`, and the analysis dashboard.
- Display `Package Layout: split` and the component inventory table.
- Display `Source APK` on indicator tables.
- *Verification*: Dashboard rendering tests, report generation tests, and full regression run of all existing 251 tests.

---

## 9. Verification & Test Requirements

1. **Single APK Regression**: All 251 existing baseline tests must pass without alteration.
2. **Split Classification Tests**:
   - Base + ABI split
   - Base + Locale split
   - Base + Density split
   - Unknown/unclassified split (fallback to `unknown` without crashing)
3. **Workspace Isolation Tests**: Ensure identical file names in different splits do not overwrite each other.
4. **Validation Tests**: Independent SHA-256 and ZIP validation per split.
5. **Preprocessing Resilience**: Zero-code/resource-only splits handled cleanly; failed optional splits do not crash pipeline.
6. **Provenance Integrity**: Verify `source_apk` is present on every item in aggregated network indicators, native libraries, and API candidates.
7. **Unified Context & Reporting**: Verify `static_context.json`, `report.json`, and `report.html` correctly render multi-APK metadata.
