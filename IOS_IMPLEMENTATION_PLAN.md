# MobiAttack V2 — iOS Static Analysis Pipeline Implementation Plan

## Executive Summary

This engineering plan details the design and staged implementation for introducing **iOS static package analysis** to MobiAttack V2 while strictly preserving the stability, correctness, and 100% test pass-rate of the existing Android pipeline (monolithic APKs and Split APK sets).

MobiAttack follows an **evidence-first, deterministic security analysis principle**:
> **Absence of evidence is not evidence of absence.**
> **Unsupported analysis must never be represented as a negative finding.**
> **Prefer missing a finding over producing an unsupported or fabricated finding.**

---

## 1. Current Architecture Review

### 1.1 Architecture & Pipeline Flow
The existing MobiAttack V2 system is organized around a 4-stage deterministic execution pipeline:
```
Target Input (URL / Package ID)
      ↓
Stage 1: Acquisition (src/apk_acquirer.py, src/play_store_acquirer.py, src/split_acquirer.py)
      ↓
Stage 2: Preprocessing (src/apk_preprocessor.py, src/split_preprocessor.py)
      ↓
Stage 3: Static Analysis (src/manifest_parser.py, src/apk_structure_extractor.py,
                          src/network_indicator_extractor.py, src/api_candidate_extractor.py,
                          src/static_context_builder.py, src/split_static_context_builder.py)
      ↓
Stage 4: Runtime Observation (src/android_runtime_launcher.py)
      ↓
Reporting & Presentation (src/report_generator.py, src/demo_web_server.py)
```

### 1.2 Identified Android-Specific Couplings
1. **Input Classification (`src/url_classifier.py`)**: Explicitly blocks `platform == "ios"` with `"type": "not_implemented"`.
2. **Orchestrator (`src/demo_orchestrator.py`)**: Fails fast if `platform == "ios"` (`raise DemoOrchestrationError(..., stage="acquisition")`). Assumes all inputs produce APK files, Apktool outputs, or ADB runtime launch.
3. **Static Context Builders (`src/static_context_builder.py`, `src/split_static_context_builder.py`)**: Expect `AndroidManifest.xml`, `classes*.dex`, Smali directories, and Dalvik/ART registers.
4. **Report Generator (`src/report_generator.py`)**: Hardcoded Android labels (e.g. `Launcher Activity`, `DEX Count`, `Smali Roots`, `No permissions declared in AndroidManifest.xml`).
5. **Dashboard Server (`src/demo_web_server.py`)**: Blocks iOS runs at API level (`/api/run`), disables the UI "Start Analysis" button when iOS radio is checked, and renders Android-specific tab cards.

---

## 2. Proposed Platform Boundary

To introduce iOS cleanly without regressing Android, we establish an isolated platform boundary:

```
                            User Input (URL / File Path)
                                         ↓
                            Platform Detection & Routing
                              (src/platform_detector.py)
                                /                     \
           [Android Target: .apk / Play Store]    [iOS Target: .ipa]
                                |                              |
                     Android Pipeline               iOS Static Pipeline
                  (src/apk_*, src/split_*)             (src/ios/*)
                                \                             /
                                 \                           /
                                  ↓                         ↓
                               Normalized Analysis Context
                                  (Compatible Contract)
                                         ↓
                        Shared Presentation & Reporting
                    ├── Web Dashboard (Dynamic Platform Labels)
                    └── Exportable Reports (report.json & report.html)
```

### Key Architectural Isolation Rules
1. **Zero Churn on Working Android Code**: Existing Android analyzers (`manifest_parser.py`, `apk_structure_extractor.py`, `apk_preprocessor.py`, `split_*.py`, etc.) will NOT be moved or refactored.
2. **Dedicated iOS Namespace**: All iOS extraction logic resides in `src/ios/`.
3. **Platform-Agnostic Context**: Both pipelines produce dictionaries conforming to the normalized analysis contract.
4. **Factual Integrity**: Static extraction only produces `FACT` states. No guesswork, no vulnerability grading, no synthetic API endpoints.

---

## 3. New Modules Specification

All new iOS capabilities will be implemented as modular, standard-library-first Python components under `src/ios/`:

| Module Path | Responsibilities | Key Dependencies |
| :--- | :--- | :--- |
| `src/platform_detector.py` | Deterministic file type & archive structure verification (`.apk` vs `.ipa` vs `invalid`). | Standard `zipfile` |
| `src/ios/__init__.py` | Package exports and iOS analyzer definitions. | None |
| `src/ios/ipa_extractor.py` | Safe ZIP archive extraction, Zip-Slip prevention, `Payload/*.app` discovery, deterministic metadata. | `zipfile`, `pathlib`, `hashlib` |
| `src/ios/plist_parser.py` | `plistlib`-based parsing of XML & binary `Info.plist`. Extracts metadata, declared usage descriptions, and ATS facts. | `plistlib` (No regex) |
| `src/ios/entitlements_parser.py` | Conservative extraction of app entitlements from embedded provisioning profiles / signature metadata. | `plistlib`, `subprocess` (conservative) |
| `src/ios/macho_analyzer.py` | Validates Mach-O binary format, architectures, 32/64-bit, linked dynamic libraries (`otool`/header parsing). | `subprocess`, `struct` |
| `src/ios/ios_structure_extractor.py` | File & directory inventory: embedded `.framework` bundles, `.dylib` binaries, asset catalogs, extensions (`.appex`), plists, JSONs. | `pathlib` |
| `src/ios/ios_network_indicator_extractor.py` | Deterministic discovery of URLs, domains, IP addresses, and file paths with exact provenance. | `re`, `pathlib` |
| `src/ios/ios_static_context_builder.py` | Aggregates all iOS factual data into the normalized static analysis schema. | Internal iOS modules |

---

## 4. Existing Files Requiring Surgical Modification

| Existing File | Required Changes | Regression Guard |
| :--- | :--- | :--- |
| `src/url_classifier.py` | Add classification for `.ipa` direct URLs/paths (`type: "direct_ipa"`) when `platform == "ios"`. | Existing Android classification branches (`direct_apk`, `play_store`) remain 100% untouched. |
| `src/demo_orchestrator.py` | Add branch for `platform == "ios"`: execute iOS Acquisition, Preprocessing (extraction), and Static Analysis. Mark Runtime as `not_implemented`. | Android monolithic and Split APK pipeline paths remain completely unchanged. |
| `src/report_generator.py` | Adapt `build_report_dict` and `render_html_report` to condition on `platform == "ios"`. Render iOS metadata (Bundle ID, Executable, Frameworks, ATS, Usage Descriptions) and suppress Android labels. | Android report rendering branch is preserved with identical layout. |
| `src/demo_web_server.py` | Unblock iOS platform in `/api/run`. Enable "Start Analysis" button in UI when iOS is selected. Dynamically update tab labels based on run platform. | Android UI behavior and API request handling remain identical. |

---

## 5. Normalized Analysis Context Schema

The normalized analysis context provides a unified dictionary contract that the shared dashboard and report generator consume:

```json
{
  "platform": "ios",
  "application": {
    "bundle_identifier": "com.example.app",
    "bundle_name": "Example",
    "display_name": "Example App",
    "executable": "ExampleApp",
    "version": "1.2.0",
    "build": "1042",
    "minimum_os_version": "15.0",
    "supported_platforms": ["iPhoneOS"],
    "device_family": ["iPhone", "iPad"],
    "filename": "app.ipa",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "size_bytes": 14205810
  },
  "configuration": {
    "info_plist": {
      "raw_keys_count": 48
    },
    "usage_descriptions": [
      {
        "key": "NSCameraUsageDescription",
        "value": "Used to scan QR codes for account linking.",
        "classification": "declared_usage_description",
        "evidence": {
          "source_file": "Payload/ExampleApp.app/Info.plist",
          "extraction_method": "plistlib"
        }
      }
    ],
    "ats": {
      "allows_arbitrary_loads": false,
      "allows_local_networking": true,
      "exception_domains": [
        {
          "domain": "internal.example.com",
          "includes_subdomains": true,
          "allows_insecure_http_loads": true
        }
      ],
      "classification": "configuration_fact"
    },
    "entitlements": {
      "status": "extracted",
      "extraction_method": "embedded.mobileprovision",
      "items": {
        "application-identifier": "TEAMID.com.example.app",
        "aps-environment": "production",
        "keychain-access-groups": ["TEAMID.com.example.app"]
      }
    }
  },
  "structure": {
    "app_bundle_path": "Payload/ExampleApp.app",
    "executable": {
      "name": "ExampleApp",
      "architectures": ["arm64"],
      "bitness": 64,
      "file_type": "Mach-O 64-bit executable arm64",
      "linked_libraries": [
        "/System/Library/Frameworks/UIKit.framework/UIKit",
        "/System/Library/Frameworks/Foundation.framework/Foundation"
      ],
      "uuid": "4B1C696A-4A73-3E49-8FB3-5684D47AE35E"
    },
    "frameworks": [
      {
        "name": "Alamofire.framework",
        "relative_path": "Frameworks/Alamofire.framework",
        "type": "framework_bundle"
      }
    ],
    "resources": {
      "total_count": 284,
      "plist_files": ["Info.plist"],
      "json_files": ["config.json"],
      "asset_catalogs": ["Assets.car"],
      "localization_dirs": ["en.lproj", "tr.lproj"]
    },
    "extensions": []
  },
  "network_indicators": {
    "network_urls": [
      {
        "value": "https://api.example.com/v1",
        "type": "network_url",
        "source_file": "Payload/ExampleApp.app/Info.plist",
        "line_number": null,
        "offset": null,
        "source_type": "plist"
      }
    ],
    "domains": [
      {
        "value": "api.example.com",
        "type": "domain",
        "source_file": "Payload/ExampleApp.app/Info.plist",
        "line_number": null,
        "offset": null,
        "source_type": "plist"
      }
    ],
    "ip_addresses": [],
    "path_candidates": [],
    "local_file_urls": []
  },
  "api_candidates": [],
  "evidence": [
    {
      "fact": "CFBundleIdentifier",
      "value": "com.example.app",
      "evidence": {
        "source_file": "Payload/ExampleApp.app/Info.plist",
        "extraction_method": "plistlib"
      }
    }
  ]
}
```

---

## 6. Deterministic Error Model

MobiAttack strictly separates error categories to prevent misleading security representations:

| Error State | Semantic Meaning | Example Occurrence |
| :--- | :--- | :--- |
| `not_found` | Target artifact or key is legitimately absent in the package. | No `Frameworks/` directory present in app bundle. |
| `not_extracted` | Component was not processed during extraction. | Resource file skipped due to extraction boundary rules. |
| `unsupported` | Platform tooling or execution environment cannot evaluate the feature. | `otool` binary not available on non-macOS system. |
| `unknown` | Value cannot be deterministically classified with available evidence. | Mach-O file format variant with unrecognized magic bytes. |
| `not_applicable` | Operation or section is semantically invalid for this platform. | Dalvik DEX Multidex metrics queried for an iOS IPA. |
| `parse_failed` | Target file exists but violates syntax or is truncated. | Corrupted binary plist that cannot be deserialized by `plistlib`. |
| `tool_failed` | External tool executed but returned a non-zero exit code. | `otool` subprocess exited with status 1. |
| `invalid_input` | Input archive does not satisfy structural IPA requirements. | ZIP file does not contain `Payload/*.app`. |

> **Critical Invariant:** `tool_failed != feature_not_present`. A failure of `otool` or `codesign` must be recorded as `tool_failed` or `unsupported`, never as "no dynamic libraries linked" or "no entitlements".

---

## 7. Evidence Model & Confidence/Truth Model

Every extracted item must include its provenance chain:
- **`source_file`**: Canonical relative path within the extracted bundle (e.g. `Payload/ExampleApp.app/Info.plist`).
- **`extraction_method`**: Specific method/tool used (`plistlib`, `macho_parser`, `otool_load_commands`, `strings_extraction`).
- **`offset` / `location`**: Byte offset or key path if applicable.

### Truth States
- **`FACT`**: Factual observation directly verified from artifact bits (100% of Phase 1 iOS static output).
- **`INFERENCE`**: Deductions from combining multiple facts (strictly avoided in Phase 1).
- **`VALIDATED`**: Proven by observed live runtime execution (zero in Phase 1 for iOS).

---

## 8. Test Strategy

All tests will use **synthetic, minimal, programmatically generated fixtures** (zero dependency on copyrighted App Store IPAs or network connectivity):

1. **`tests/test_platform_detector.py`**:
   - Valid APK fixture (`AndroidManifest.xml` + `classes.dex`).
   - Valid IPA fixture (`Payload/Test.app/Info.plist`).
   - Corrupt ZIP file.
   - ZIP without `Payload/`.
   - ZIP with `Payload/` but no `.app` directory.
   - Non-existent file path.

2. **`tests/test_ipa_extractor.py`**:
   - Safe extraction verification.
   - Zip-Slip security test: Archive with `../../evil.txt` is rejected and raises `IpaExtractionError`.
   - Symlink security test: Symlinks pointing outside extraction root are handled safely.
   - Extraction metadata verification (`app_bundle`, `extracted_files`, `status`).

3. **`tests/test_plist_parser.py`**:
   - Parsing XML `Info.plist`.
   - Parsing binary `Info.plist` (using `plistlib.dump(..., fmt=plistlib.FMT_BINARY)`).
   - Missing `Info.plist` (`not_found`).
   - Malformed/corrupted plist (`parse_failed`).
   - Declared usage descriptions extraction (`NSCameraUsageDescription`, etc.).
   - ATS configuration extraction (`NSAllowsArbitraryLoads`, exception domains).

4. **`tests/test_entitlements_parser.py`**:
   - Extraction from synthetic embedded provisioning profile.
   - Missing provisioning profile (`not_found`).
   - Tool execution failure handling (`unsupported` / `tool_failed`).

5. **`tests/test_macho_analyzer.py`**:
   - Header magic validation (64-bit Mach-O `0xfeedfacf`, FAT/Universal `0xcafebabe`).
   - Architecture identification (`arm64`, `x86_64`).
   - Fallback when `otool` is unavailable (`unsupported`).
   - Non-zero tool returncode handling (`tool_failed`).

6. **`tests/test_ios_structure_extractor.py`**:
   - Framework directory inventory (`.framework` bundles, standalone `.dylib` files).
   - Resource file counting (plists, json, asset catalogs).

7. **`tests/test_ios_network_indicator_extractor.py`**:
   - URLs extracted from `Info.plist` and JSON configs.
   - Binary string extraction from simulated Mach-O with system-noise filters.
   - Evidence preservation (`source_file`, `source_type`).

8. **`tests/test_ios_static_context_builder.py`**:
   - Schema validation against the normalized contract.
   - Invariant check: `api_candidates` is strictly an empty list `[]`.

9. **`tests/test_ios_orchestrator_integration.py`**:
   - End-to-end execution of `run_demo` with synthetic IPA.
   - Verify report generation (`report.json` and `report.html`).
   - Verify runtime stage reports `not_implemented` cleanly without crashing.

10. **Android Regression Verification**:
    - Execute all 329 existing Android tests to verify zero regressions.

---

## 9. Regression Risks & Mitigation Plan

| Identified Risk | Severity | Concrete Mitigation |
| :--- | :--- | :--- |
| Breaking `url_classifier.py` for Android URLs. | High | Keep Android regexes and flow unchanged. Only evaluate `.ipa` if `platform == "ios"` or path ends with `.ipa`. Run `tests/test_url_classifier.py`. |
| Regressing Android pipeline in `demo_orchestrator.py`. | Critical | Isolate iOS flow inside `if classification.get("platform") == "ios":` block. Android monolithic and Split APK logic remains identical. |
| Breaking HTML report generation for Android runs. | High | Condition sections on `report.get("application", {}).get("platform") == "ios"`. Android path retains exact existing markup. Run `tests/test_report_generator.py`. |
| Breaking existing web server API or UI. | Medium | Preserve existing endpoints. Only update `/api/run` to accept iOS and pass to orchestrator. Run `tests/test_demo_web_server.py`. |
| Sandbox permission denial during local execution. | Medium | Use pure Python standard library for IPA parsing; invoke external tools with defensive error handling and timeouts. |

---

## 10. Phase-by-Phase Implementation Order

- [ ] **Phase A: Platform Detection & Safe IPA Extraction**
  - Create `src/platform_detector.py`.
  - Create `src/ios/__init__.py`.
  - Create `src/ios/ipa_extractor.py`.
  - Add unit tests `tests/test_platform_detector.py` and `tests/test_ipa_extractor.py`.
  - Run tests and verify Android regression baseline.

- [ ] **Phase B: Info.plist, Usage Descriptions, ATS & Entitlements Parsing**
  - Create `src/ios/plist_parser.py`.
  - Create `src/ios/entitlements_parser.py`.
  - Add unit tests `tests/test_plist_parser.py` and `tests/test_entitlements_parser.py`.
  - Run tests.

- [ ] **Phase C: Mach-O Analysis & Framework Inventory**
  - Create `src/ios/macho_analyzer.py`.
  - Create `src/ios/ios_structure_extractor.py`.
  - Add unit tests `tests/test_macho_analyzer.py` and `tests/test_ios_structure_extractor.py`.
  - Run tests.

- [ ] **Phase D: Network Indicator Extraction**
  - Create `src/ios/ios_network_indicator_extractor.py`.
  - Add unit tests `tests/test_ios_network_indicator_extractor.py`.
  - Run tests.

- [ ] **Phase E: Normalized Static Context Builder**
  - Create `src/ios/ios_static_context_builder.py`.
  - Add unit tests `tests/test_ios_static_context_builder.py`.
  - Run tests.

- [ ] **Phase F: Orchestrator, Report Generator & Dashboard Integration**
  - Update `src/url_classifier.py` for `.ipa`.
  - Update `src/demo_orchestrator.py` to route iOS targets.
  - Update `src/report_generator.py` for iOS report rendering.
  - Update `src/demo_web_server.py` to enable iOS execution and dynamic UI labels.
  - Create architecture documentation `IOS_ANALYSIS_ARCHITECTURE.md`.
  - Add integration tests `tests/test_ios_orchestrator_integration.py`.

- [ ] **Phase G: Full Test Suite & Zero-Regression Verification**
  - Run full test suite: all 329 existing Android tests + all new iOS unit tests.
  - Verify zero failures or regressions.
