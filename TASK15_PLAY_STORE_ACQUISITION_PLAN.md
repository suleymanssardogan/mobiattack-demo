# TASK 15 — ROBUST PLAY STORE URL → APK PACKAGE ACQUISITION PLAN

**Workspace**: `/Users/suleymansardogan/Desktop/mobiattack-v2/`  
**Baseline**: MobiAttack V2 with Task 14 Split APK Support complete (297 tests passing).  
**Strict Invariants**:
- V1 (`mobiattack-v1`) remains untouched.
- No unofficial APK mirror scraping (no APKMirror, APKPure, Uptodown, etc.).
- No pretending a Play Store HTML page contains an APK binary.
- No faking successful acquisition.
- If Play Store reports an app is incompatible, unavailable, or requires sign-in, return the real, machine-readable reason.
- Monolithic and Split APK post-installation pipelines from Task 14 are fully reused.

---

## 1. Current Behavior vs. Missing Behavior

| Capability | Current V2 State | Missing / Required for Task 15 |
|---|---|---|
| **URL Parsing** | `classify_input_url()` handles `https://play.google.com/store/apps/details?id=<pkg>` and query params. | Retain and add test coverage for complex parameters (`id + hl`, `id + hl + gl`), invalid IDs, and conservative validation. |
| **Installed Package Resolution** | Checks `pm path <pkg>`. If installed, pulls single APK or delegates to `acquire_split_package_set`. | If not installed, currently raises `PlayStoreAcquisitionError("Package is not installed...")` and terminates acquisition immediately. |
| **Store Page Launch** | Has `open_play_store_on_device()` using `android.intent.action.VIEW` with HTTPS URL. | Must try `market://details?id=<pkg>` first with fallback to HTTPS, recording `play_store_open_status` and `play_store_open_method`. |
| **Installation Handling** | None. Manual clicking was required outside the orchestrator. | Support **Manual** (poll `pm path` with configurable timeout) and **UI Automation** (opt-in UI inspection and install button triggering). |
| **UI Automation & Safety** | None. | Native `uiautomator dump` XML parsing, button detection (English "Install", Turkish "Yükle"), and strict safety halts for payments, logins, and incompatibilities. |
| **Failure Classification** | Generic `PlayStoreAcquisitionError`. | Deterministic machine-readable reason codes (`device_not_compatible`, `sign_in_required`, `installation_timeout`, `download_failed`, etc.). |
| **Dashboard & Report UX** | Shows "Open in Play Store" button upon failure. | Live progress through acquisition states; "Play Store Install Mode" control (Manual vs. Automatic); acquisition metadata in `report.json`/`report.html`. |

---

## 2. Acquisition State Machine

```
               [ User submits Play Store URL ]
                              │
                              ▼
                  [ package_id_extracted ]
                              │
                              ▼
              [ checking_device_installation ]
               (adb shell pm path <pkg>)
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
       [ Already Installed ]           [ Not Installed ]
              │                               │
              │                               ▼
              │                     [ opening_play_store ]
              │                      1. market://details?id=...
              │                      2. https://... (fallback)
              │                               │
              │               ┌───────────────┴───────────────┐
              │               ▼                               ▼
              │      [ Mode: Manual ]             [ Mode: UI Automation ]
              │               │                               │
              │               │                     [ inspect_play_store_ui ]
              │               │                     (uiautomator dump)
              │               │                               │
              │               │               ┌───────────────┴───────────────┐
              │               │               ▼                               ▼
              │               │        [ Blocked/Incompatible ]        [ Install Found ]
              │               │        (Sign-in, Payment,               ("Install" / "Yükle")
              │               │         Device Incompatible)                  │
              │               │               │                               ▼
              │               │         [ Halt with Reason ]             [ Tap Button ]
              │               │                                               │
              │               └───────────────┬───────────────────────────────┘
              │                               ▼
              │                  [ waiting_for_installation ]
              │                   (poll pm path every 2-3s)
              │                               │
              │               ┌───────────────┴───────────────┐
              │               ▼                               ▼
              │        [ Installed ]                     [ Timeout ]
              │               │                               │
              │               │                         [ Halt Error ]
              │               │                 (installation_timeout)
              └───────────────┬───────────────────────────────┘
                              ▼
                 [ package_installed ]
                              │
                              ▼
             [ acquiring_installed_package ]
               (pm path returns 1 or N paths)
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
     [ Single APK: Monolithic ]      [ Multiple APKs: Split (Task 14) ]
     - pull base.apk                 - acquire_split_package_set()
     - validate structure            - inventory & package_set.json
              └───────────────┬───────────────┘
                              ▼
                   [ package_acquired ]
                              │
                              ▼
            [ Existing V2 Downstream Pipeline ]
              (Preprocessing → Static Analysis → Runtime → Reports)
```

---

## 3. Proposed Modules & Functions

### A. Dedicated UI Automation Module: `src/play_store_ui_automator.py` [NEW]
Keeps ADB UI interaction and XML hierarchy parsing completely decoupled from file acquisition logic:
1. `dump_window_hierarchy(serial: str, adb_bin: str, timeout: float = 10.0) -> ET.Element`:
   Executes `adb shell uiautomator dump /sdcard/window_dump.xml`, reads XML content, and cleans remote temporary file.
2. `parse_node_bounds(bounds_str: str) -> tuple[int, int, int, int] | None`:
   Parses `"[x1,y1][x2,y2]"` into `(x1, y1, x2, y2)`.
3. `inspect_play_store_screen(root: ET.Element) -> PlayStoreScreenInspection`:
   - Returns a structured dataclass:
     - `package_detected`: bool
     - `screen_type`: `"app_details" | "search_results" | "error_dialog" | "unknown"`
     - `is_installed`: bool (detects "Open", "Uninstall", "Aç", "Kaldır")
     - `install_button_bounds`: `(x1, y1, x2, y2)` | None
     - `install_button_label`: str | None ("Install", "Yükle", "Get", "Update", "Güncelle")
     - `is_blocked`: bool
     - `blocked_reason`: str | None (`"device_not_compatible"`, `"sign_in_required"`, `"payment_required"`, `"account_error"`, `"download_failed"`)
4. `tap_screen_bounds(serial: str, bounds: tuple[int, int, int, int], adb_bin: str) -> None`:
   Computes center coordinate `((x1+x2)//2, (y1+y2)//2)` and executes `adb shell input tap x y`.
5. `attempt_play_store_ui_install(serial: str, package_name: str, adb_bin: str) -> dict`:
   Orchestrates screen inspection, verifies safety invariants, triggers install tap, and returns actionable diagnostics.

### B. Extended Play Store Acquirer: `src/play_store_acquirer.py` [MODIFY]
1. `open_play_store_on_device(serial, package_name, play_store_url, adb_bin)`:
   - First attempt: `market://details?id=<package_name>`.
   - If market protocol fails or cannot resolve, fallback: `https://play.google.com/store/apps/details?id=<package_name>`.
   - Returns `{"open_status": "success" | "failed", "open_method": "market_uri" | "https_fallback", "target_url": str}`.
2. `wait_for_device_installation(serial, package_name, timeout_seconds, poll_interval, adb_bin, progress_callback) -> list[str]`:
   - Polls `query_package_paths()` every `poll_interval` seconds until installed or `timeout_seconds` reached.
   - Emits progress updates during polling.
3. `acquire_play_store_package(package_name, output_dir, serial, adb_bin, timeout_seconds, install_mode, install_wait_timeout_seconds, progress_callback)`:
   - Coordinates the full state machine: check installed $\to$ open store $\to$ automated or manual install $\to$ poll $\to$ pull monolithic or split package.

### C. Pipeline Orchestrator Integration: `src/demo_orchestrator.py` [MODIFY]
1. `run_demo(...)` signature extended with:
   - `install_mode: str = "manual"` (`"manual"` or `"ui_automation"`)
   - `install_wait_timeout_seconds: float = 180.0`
2. Acquisition stage progress emits detailed granular messages:
   - `"Checking connected Android device for installed package..."`
   - `"Opening application in Google Play Store..."`
   - `"Waiting for user installation in emulator (timeout: 180s)..."` (manual mode)
   - `"Inspecting Play Store screen and attempting automated installation..."` (ui_automation mode)
   - `"Package installation verified on device. Pulling installed APK package-set..."`
3. Proper handling of failure codes (`device_not_compatible`, `sign_in_required`, `installation_timeout`) as factual acquisition outcomes rather than generic crash exceptions.

### D. Web Dashboard Updates: `src/demo_web_server.py` [MODIFY]
1. **Control Panel**:
   - Add "Play Store Install Mode" radio options near the Start button:
     - `○ Manual` (default)
     - `○ Automatic (Experimental)`
2. **API Endpoint `/api/run`**:
   - Accepts `"install_mode": "manual" | "ui_automation"`.
   - Forwards to `start_run()` and orchestrator worker.
3. **Real-Time Stage Card UX**:
   - Shows live sub-status (`opening_play_store`, `waiting_for_installation`, `device_not_compatible`).
   - If manual mode: displays actionable guidance banner: *"Install the application in the emulator. MobiAttack will continue automatically after installation is detected."*
   - If `device_not_compatible`: displays warning badge and message directly in the card without collapsing into an uninformative crash.

### E. Report Model Updates: `src/report_generator.py` [MODIFY]
1. `build_report_dict()`:
   - Includes acquisition diagnostics:
     - `initially_installed`: bool
     - `install_mode`: `"manual"` | `"ui_automation"`
     - `play_store_open_status`: `"success"` | `"failed"`
     - `play_store_open_method`: `"market_uri"` | `"https_fallback"`
     - `install_status`: `"already_installed"` | `"installed_via_manual"` | `"installed_via_ui_automation"` | `"device_not_compatible"` | ...
2. `render_html_report()`:
   - In Section 4 "APK Acquisition", display the Play Store installation lifecycle facts cleanly in the table.

---

## 4. Failure Classification & Machine-Readable Semantics

| Reason Code | Trigger Condition | UX Message |
|---|---|---|
| `already_installed` | Package path found on first check | Package already installed on device. |
| `installed_via_manual` | Installed while polling in manual mode | Package installation confirmed on device. |
| `installed_via_ui_automation` | Installed after automated UI button trigger | Automated installation succeeded. |
| `device_not_compatible` | Play Store UI displays "Your device isn't compatible with this version." | Target application is incompatible with this device/architecture. |
| `sign_in_required` | Play Store prompts for Google Account Sign In | Google Play Store sign-in required on emulator. |
| `payment_required` | Price / Buy / Purchase detected instead of free Install | Application is paid; automated purchase is prohibited for safety. |
| `installation_timeout` | Polling elapsed without package appearing in `pm path` | Package was not installed within the allowed waiting period. |
| `package_not_found` | Play Store shows "Item not found" or "URL not found" | Package ID was not found on Google Play Store. |
| `play_store_not_available` | `com.android.vending` missing or intent fails to open | Google Play Store app is not available on connected device. |
| `ui_automation_failed` | UI automation could not identify an Install button or hierarchy dump failed | Automated UI installation could not proceed; switch to Manual mode. |

---

## 5. Testing Strategy (24 Test Cases)

New test module: `tests/test_play_store_acquisition_v2.py`:

1. **URL Parsing**:
   - `test_01_play_store_url_with_id_only`: `https://play.google.com/store/apps/details?id=com.example.app`
   - `test_02_play_store_url_with_id_and_hl`: `https://play.google.com/store/apps/details?id=com.example.app&hl=en`
   - `test_03_play_store_url_with_id_hl_and_gl`: `https://play.google.com/store/apps/details?id=com.example.app&hl=tr&gl=TR`
   - `test_04_malformed_package_id_rejected`: Invalid package formats rejected cleanly with descriptive error.
2. **Device Installation & Intent Resolution**:
   - `test_05_already_installed_package_skips_store_open`: Package found immediately bypasses store open.
   - `test_06_non_installed_package_triggers_acquisition_flow`: Non-installed package begins store open workflow.
   - `test_07_market_uri_primary_open`: Uses `market://details?id=<pkg>` as primary intent.
   - `test_08_https_fallback_when_market_fails`: Falls back to HTTPS when market URI returns error.
3. **Manual Installation Mode**:
   - `test_09_manual_mode_enters_waiting_state`: Emits `waiting_for_installation` with instructions.
   - `test_10_installation_detected_during_polling`: Polling detects newly installed app and resumes.
   - `test_11_installation_timeout_raises_clear_error`: Exceeding timeout raises `installation_timeout`.
4. **Safety & Block Detection**:
   - `test_12_sign_in_required_detection`: XML hierarchy with "Sign in" / "Giriş yap" halts safely.
   - `test_13_download_failure_detection`: Play Store download error alerts return `download_failed`.
   - `test_14_device_incompatible_detection`: Detects "Your device isn't compatible with this version."
   - `test_15_play_store_not_available`: Missing store app or ADB intent error returns `play_store_not_available`.
5. **UI Automation**:
   - `test_16_ui_automation_detects_english_install_button`: Identifies node with `text="Install"` and computes coordinates.
   - `test_17_ui_automation_detects_turkish_yukle_button`: Identifies node with `text="Yükle"`.
   - `test_18_ui_automation_disabled_by_default`: Default configuration uses `install_mode="manual"`.
6. **Pipeline Integration & Regressions**:
   - `test_19_successful_monolithic_acquisition_after_install`: Newly installed single APK runs through monolithic pipeline.
   - `test_20_successful_split_acquisition_after_install`: Newly installed split APK runs through Task 14 split pipeline.
   - `test_21_direct_apk_regression`: Direct APK URLs continue working without modification.
   - `test_22_existing_installed_play_store_regression`: Pre-installed Play Store apps continue working without delay.
   - `test_23_task_14_split_tests_pass`: All Task 14 split tests remain 100% green.
   - `test_24_full_test_suite_passes`: Entire V2 suite passes cleanly.

---

## 6. Live Validation Target

- Target URL: `https://play.google.com/store/apps/details?id=com.sec.android.app.popupcalculator&hl=en`
- Expected behavior:
  1. URL classified as Play Store with package `com.sec.android.app.popupcalculator`.
  2. Checked on device `127.0.0.1:5555` $\to$ not installed.
  3. Opens `market://details?id=com.sec.android.app.popupcalculator` on emulator.
  4. In UI Automation mode: inspects UI $\to$ detects `"Your device isn't compatible with this version."` $\to$ cleanly reports `device_not_compatible` without crashing.
  5. In Manual mode: prompts user in dashboard with wait timer and continues if installed.
