# iOS Static Analysis Architecture — MobiAttack V2

## Overview

MobiAttack V2 introduces a clean, deterministic static analysis pipeline for Apple iOS applications (`.ipa` archives) while preserving the production stability of the Android analysis pipeline (`.apk`, Google Play Store, Split APKs).

The shared dashboard, reporting layer, and orchestration boundaries are platform-aware and evidence-backed, strictly adhering to the core engineering principle:

> **"Precision is more important than recall. If evidence is insufficient: DO NOT GUESS. DO NOT INFER. DO NOT CREATE A FINDING."**

---

## Core Principles & Guarantees

1. **"Absence of evidence is not evidence of absence."**
   - The absence of declared capabilities, network strings, or configurations in static artifacts does not prove they do not exist or cannot be reached dynamically at runtime.
2. **"Unsupported analysis must never be represented as a negative finding."**
   - If a feature, tool, or runtime capability is unsupported or unavailable on the host, it must be explicitly reported as `unsupported` or `not_implemented` — never as `clean`, `secure`, or `failed`.
3. **"Static network indicator does not imply API endpoint."**
   - Raw URL strings, domains, IP addresses, and path constants extracted from binaries or plists are purely indicators of string literals. They do not imply HTTP methods, request bodies, authentication requirements, authorization context, or runtime network communication.
4. **"Artifact → Deterministic Extraction → Evidence → FACT"**
   - Every meaningful extracted fact points directly to verifiable evidence: `source_file`, `extraction_method`, and (where available) `offset`, `plist_key`, or `tool`.
   - No vulnerability verdicts, arbitrary risk scores, or speculative findings are generated in this phase.

---

## High-Level Architecture

```
                               Target Input
                                    │
                                    ▼
                         Platform Content Detector
                       (ZIP Inspection / Signatures)
                        ├── Is valid APK?  ──► Android Pipeline
                        ├── Is valid IPA?  ──► iOS Pipeline
                        └── Unknown / Bad  ──► Rejection (400)
                                    │
           ┌────────────────────────┴────────────────────────┐
           ▼                                                 ▼
   Android Pipeline                                  iOS Pipeline
   ├── APK Acquisition                               ├── IPA Safe Extraction (Zip-Slip safe)
   ├── Preprocessing (Apktool/JADX)                  ├── Info.plist Parsing (plistlib XML/Binary)
   ├── Manifest & DEX Static Analysis                ├── Bundle Structure Inventory (.app, Frameworks)
   └── Emulator Runtime (ADB / MuMu)                 ├── Mach-O Header & Load Commands
                                                     ├── Entitlements Extraction
                                                     └── Static Network Indicators
           │                                                 │
           └────────────────────────┬────────────────────────┘
                                    │
                                    ▼
                         Normalized Static Context
                       (Platform-Aware Schema)
                                    │
                     ┌──────────────┴──────────────┐
                     ▼                             ▼
              Shared Dashboard             JSON / HTML Reports
           (Adaptive Platform UI)        (report.json, report.html)
```

---

## Pipeline Comparison

| Component | Android Pipeline (Baseline) | iOS Pipeline (V2 Phase 1) | Shared Layer Boundary |
| :--- | :--- | :--- | :--- |
| **Input Source** | Direct `.apk` URL, Google Play Store URL | Direct `.ipa` URL or local path | Normalized input descriptor (`url`, `platform`) |
| **Packaging Layout** | Single APK, Split APK set (`base.apk` + splits) | Apple IPA container (`Payload/*.app/`) | Archive structure metadata |
| **Primary Descriptor**| `AndroidManifest.xml` | `Info.plist` (XML / binary plist) | Standardized application identity block |
| **Executable Format** | Dalvik Executable (`classes*.dex`) | Apple Mach-O (Thin / Universal Fat) | Executable metadata & architecture inventory |
| **Decompilation** | Smali (`apktool`), Java source (`jadx`) | Not applicable / Out of scope for Phase 1 | Clean separation — no fake decompilation |
| **Capabilities** | `<uses-permission>` tags | Declared usage descriptions (`NS*UsageDescription`)| Categorized permission facts |
| **Components** | Activities, Services, Receivers, Providers | Frameworks (`.framework`, `.dylib`), PlugIns (`.appex`)| Embedded binary and component inventory |
| **Entitlements** | App permissions & signature level | `embedded.mobileprovision` / `codesign` entitlements | Key-value factual entitlements mapping |
| **Network Discovery** | JADX AST regex + string pool search | Regex scanning on plists, JSON, and Mach-O strings | Static network indicators categorized by type |
| **API Candidates** | Call-context extracted HTTP candidates | **Strictly empty (`[]`)** in Phase 1 | Shared UI tab, explicitly marked unsupported |
| **Runtime Analysis** | ADB device/emulator install, launch, PID check | **Not implemented** in Phase 1 | Runtime status: `not_implemented` (not failed)|
| **Vulnerabilities** | Deterministic static rule evaluation | **CLEAN / 0 findings** (no verdicts in Phase 1) | Findings list and risk score badge |

---

## iOS Pipeline Stages

### Stage 1: Platform Detection & Safe Extraction (`src/platform_detector.py`, `src/ios/ipa_extractor.py`)
- **Content-Based Detection:** Does not rely solely on `.ipa` file extensions. Verifies:
  1. Valid ZIP archive signature.
  2. Presence of a top-level `Payload/` directory.
  3. Presence of exactly one main `Payload/*.app/` application bundle directory.
  4. Ambiguous nested or multiple top-level bundles are flagged explicitly (`ambiguous_app_bundles`), never guessed.
- **Zip-Slip & Path Traversal Prevention:**
  - Absolute paths within archive entries are rejected.
  - Path components with `..` directory traversal are rejected.
  - Symlinks with targets pointing outside the extraction root are rejected.
- **Resource Constraints:** Extraction operates under bounded file counts and total byte extraction ceilings to prevent ZIP bomb denial-of-service.

### Stage 2: Info.plist & Structure Inventory (`src/ios/plist_parser.py`, `src/ios/ios_structure_extractor.py`)
- **Deterministic Parsing:** Uses Python standard library `plistlib` supporting both XML and binary Apple plists. Regular expression parsing of plists is strictly prohibited.
- **Factual Value Extraction:**
  - `CFBundleIdentifier`, `CFBundleName`, `CFBundleDisplayName`, `CFBundleExecutable`, `CFBundleShortVersionString`, `CFBundleVersion`, `MinimumOSVersion`, `CFBundleSupportedPlatforms`, `UIDeviceFamily`.
  - Custom URL schemes (`CFBundleURLTypes`) and queries schemes (`LSApplicationQueriesSchemes`).
  - App Transport Security (`NSAppTransportSecurity`) configuration facts (`NSAllowsArbitraryLoads`, `NSExceptionDomains`).
- **Declared Usage Descriptions:** Keys such as `NSCameraUsageDescription` and `NSLocationWhenInUseUsageDescription` are recorded as `declared_usage_description`, *never* as `permission_used`.
- **Bundle Inventory:**
  - Scans `Payload/*.app/Frameworks/` for `.framework` and `.dylib` components.
  - Scans `Payload/*.app/PlugIns/` for `.appex` extension bundles.
  - Catalogs resource file counts (plists, JSON configs, localization `.lproj` folders).

### Stage 3: Mach-O Analysis & Entitlements (`src/ios/macho_analyzer.py`, `src/ios/entitlements_parser.py`)
- **Executable Location:** Selected strictly from `CFBundleExecutable` in `Info.plist`.
- **Pure Python Mach-O Parser:**
  - Validates Mach-O magic headers: Thin 32-bit (`0xfeedface`), Thin 64-bit (`0xfeedfacf`), Universal Fat (`0xcafebabe` / `0xbebafeca`).
  - Identifies architectures (`arm64`, `armv7`, `x86_64`), Mach-O file type (e.g. `MH_EXECUTE`), bitness, and UUID (`LC_UUID`).
  - Inspects `LC_ENCRYPTION_INFO` / `LC_ENCRYPTION_INFO_64` to record factual binary encryption properties (`cryptid`, `encryption_state`). `cryptid` is treated strictly as factual binary metadata, never as a vulnerability verdict or analysis failure.
  - Parses `LC_LOAD_DYLIB` commands for linked dynamic libraries.
- **Safe Subprocess Invocation:**
  - When system tools like `otool -L` or `codesign -d --entitlements :-` are used, invocations are executed with `shell=False`, argument lists, strict timeouts, stdout/stderr capture, and return code validation.
  - Binaries are **never executed**.
- **Entitlements Extraction & Provenance:**
  - Keeps entitlement sources strictly distinct: `embedded_mobileprovision` (provisioning profile) vs `codesign_entitlements` (Mach-O code signature).
  - Every entitlement record retains its discrete `source_type`, `source_file`, and `extraction_method`.
  - Provisioning profile entitlements represent developer/provisioning capability limits and are not automatically equivalent to effective runtime behavior.
  - Extracted entitlements are treated as factual configuration attributes, not vulnerabilities.

### Stage 4: Network Indicators (`src/ios/ios_network_indicator_extractor.py`)
- **Extraction Scope:**
  - Structured text files (`Info.plist`, embedded plists, JSON configuration files).
  - Main Mach-O binary and embedded framework strings.
- **Noise Filtering:**
  - Filters out Apple DTD/XML schema namespaces (`http://www.apple.com/DTDs/PropertyList-1.0.dtd`).
  - Standardizes indicators into: `network_url`, `domain`, `ip_address`, `path_candidate`, and `local_file_url`.
- **Static vs Runtime Boundary:**
  - Static indicators prove only that a string constant exists in the package; they do not prove runtime use or navigation.

### Stage 5: Normalized Static Context (`src/ios/ios_static_context_builder.py`)
- Aggregates all extracted facts into the unified MobiAttack schema:
  - `application`: Bundle ID, names, version, executable, minimum OS version.
  - `configuration`: Usage descriptions, URL schemes, ATS facts, entitlements (with provenance).
  - `structure`: Main executable facts, frameworks, extensions, resource counts.
  - `network_indicators`: Categorized network string constants with file and offset provenance.
  - `api_candidates`: Strictly empty (`[]`) for Phase 1.
  - `limitations`: Explicit list of what was and was not analyzed.
  - `evidence`: Provenance records pointing to source files and extraction methods.

---

## Error and Status Model

Analysis states are strictly separated to prevent conflating missing features with failures:

| State Tag | Meaning | Handling in MobiAttack V2 |
| :--- | :--- | :--- |
| `success` | Feature was analyzed and evidence was collected. | Rendered in dashboard and report. |
| `not_found` | Tool/parser ran successfully, but feature was absent in artifact. | Emitted as 0 items or `None`; not an error. |
| `unsupported` | Host or environment lacks the capability (e.g. non-macOS host running `otool`). | Reported explicitly as `unsupported`. Never represented as clean or failed. |
| `not_implemented` | Analysis module is intentionally not implemented in this phase (e.g. iOS Runtime). | Truthfully labeled as `not_implemented`. Never reported as a pipeline failure. |
| `not_evaluated` | Evaluation phase was not performed (e.g. iOS vulnerability analysis in Phase 1). | Truthfully labeled as `status: not_evaluated`, `reason: not_implemented`. Never reported as CLEAN (0 findings != clean, not evaluated != secure). |
| `tool_failed` | Available tool was invoked but terminated with a non-zero exit code or error. | Error recorded in stage details with return code and stderr. |
| `parse_failed` | Malformed file encountered during parsing (e.g. invalid plist XML). | Captured with explicit reason; fallback applied where appropriate. |
| `invalid_input` | Input target is not a valid archive or binary format. | Pipeline returns 400 with actionable message. |

---

## Evidence Model

Every meaningful fact in the static context includes provenance metadata:
```json
{
  "fact": "CFBundleIdentifier",
  "value": "com.example.app",
  "evidence": {
    "source_file": "Payload/App.app/Info.plist",
    "plist_key": "CFBundleIdentifier",
    "extraction_method": "plistlib"
  }
}
```
Confidence grading is boolean (`FACT`); no synthetic numeric percentages or unsupported validation verdicts are generated.

---

## Shared UI & Reporting Adaptations

The local web dashboard (`src/demo_web_server.py`) and reports (`report.json`, `report.html`) dynamically adapt based on `platform`:
- **Overview Tab:** Shows Bundle ID, Display Name, Version, Minimum OS, Executable, Mach-O Architectures, Framework Count, and Usage Descriptions for iOS. Android-specific fields (`Package Layout`, `Split Components`, `Launcher Activity`, `DEX Count`) are omitted.
- **Application Tab:** Shows declared usage descriptions and custom URL schemes instead of Android permissions and activities.
- **Structure Tab:** Shows Mach-O executable metadata, embedded frameworks, app extensions, and provisioning entitlements instead of DEX multidex and smali roots.
- **Runtime Tab:** Clearly displays `iOS runtime analysis: Not implemented (Static-only analysis)` without generating fake PIDs or foreground states.
- **Security Findings / Vulnerabilities:** Displays `Vulnerability Analysis: Not evaluated (Reason: iOS vulnerability evaluation is not implemented in Phase 1. 0 findings != clean, not evaluated != secure, unsupported != passed)`. Never represents unperformed analysis as CLEAN or passed.

---

## Supported vs. Unsupported Features Summary

### Currently Supported in iOS Static Analysis (V2)
- Direct `.ipa` URL downloading and local file path analysis.
- Safe archive validation, Zip-Slip prevention, and payload extraction.
- Deterministic Info.plist XML and binary parsing.
- App identity, versioning, minimum OS, and device family extraction.
- Declared usage description cataloging.
- Custom URL scheme discovery.
- App Transport Security (ATS) factual configuration extraction.
- Factual inventory of `Frameworks/` (`.framework`, `.dylib`) and `PlugIns/` (`.appex`).
- Pure Python Mach-O parsing (architectures, 32/64-bit, type, UUID, encryption detection).
- Native and codesign entitlements parsing.
- Static network indicator regex extraction with noise filtering.
- Normalized static context generation.
- Platform-adapted interactive dashboard and unified JSON/HTML reporting.

### Explicitly Unsupported in Phase 1 (Out of Scope)
- Apple App Store IPA acquisition / DRM decryption.
- Apple ID / FairPlay account automation.
- iOS binary execution or dynamic instrumentation (Frida, lldb, jailbreak hooks).
- iOS device launching, process monitoring (PID), or foreground verification.
- Live network traffic interception (Burp Suite, MITM proxies).
- Speculative API candidate generation from raw URL strings (`api_candidates: []`).
- Automated vulnerability verdict generation or security risk grading for iOS.
