# MobiAttack Local Dashboard UI Refinement Plan

**Target Workspace:** `/Users/suleymansardogan/Desktop/mobiattack-v2/`  
**Target File:** `src/demo_web_server.py`  
**Guiding Aesthetic:** Professional, minimal, security & developer engineering tool (Linear/Vercel/Internal tool console style). System fonts only, zero external dependencies, no marketing tropes, no decorative emojis, no excessive gradients.

---

## 1. Current UI Problems & Audit Findings

1. **Font & Network Dependencies:**
   - External Google Fonts (`Inter`, `JetBrains Mono`) are imported via network `<link>` tags in `<head>`.
   - Must be replaced with a 100% offline, native OS system font stack.
2. **Header Visual Hierarchy:**
   - Current header uses a decorative brand mark and subtitle that can be streamlined into a pure engineering layout: `MobiAttack` with subtext `Android Analysis Demo` and summary `Static analysis, package acquisition and runtime verification`.
   - Retains simple `V2` label.
3. **Form Spacing & Organization:**
   - Target URL, ADB configuration, installation modes, and runtime options need a structured, compact grid alignment with Target URL as the prominent visual focus.
   - "Automatic (Experimental)" install mode should be visually secondary and understated.
4. **Primary Action Button:**
   - Currently labelled uppercase `START DEMO`.
   - Needs to be calm, medium-sized, solid background (`#2563eb`), labelled `Start Analysis`, while preserving `START DEMO` string invariant for existing test suites via semantic HTML attribute/label.
5. **Pipeline Status Cards:**
   - Need equal-width, compact layout with status badges neatly positioned in the top right, clear stage numbers, and low visual noise.
   - Status colors should accent badges and borders subtly, never overpowering the cards.
6. **Tabs & Analysis Results:**
   - Tab navigation needs low-contrast inactive tabs and a crisp, clear active indicator (compact pill or subtle underline, no glowing halos).
   - "Overview" tab currently renders multiple metric boxes that should be replaced with compact, tabular key-value rows.
   - "Application" tab needs structured sections (Application Identity, Permissions, Activities) with scrollable, fixed-height, monospace containers and count tags.
   - "Structure" tab needs clear collapsible or grouped cards per Source APK for split packages, and structured key-values for monolithic packages.
   - "Network" tab needs a compact, high-density table with a sticky header and subtle note styling.
   - "API Candidates" tab when empty should use a small neutral note instead of a large alert box.
   - "Analysis Notes" tab should render a clean, compact bulleted list with minimal markers, eliminating bulky individual callout boxes.
   - "Error States" must display structured technical reason codes in monospace with restrained red accents.

---

## 2. Proposed Visual System & Design Tokens

### Color Palette (Zinc / Dark Slate)
- **Background Root:** `#0a0c10` (deep matte neutral)
- **Surface / Card Background:** `#12151c`
- **Surface Hover / Highlight:** `#181c26`
- **Card Borders:** `#1e2330` (subtle 1px solid)
- **Dividers & Table Borders:** `#191e2b`
- **Input Background:** `#0e1017`
- **Input Border:** `#262d3d` (focus: `#3b82f6` with 0 0 0 1px ring, no fuzzy glow)

### Text & Accents
- **Primary Text:** `#f1f5f9` (high legibility)
- **Secondary / Muted Text:** `#94a3b8`
- **Dimmed Text / Labels:** `#64748b`
- **Primary Action Accent:** `#2563eb` (hover: `#1d4ed8`, active: `#1e40af`)
- **Success:** `#10b981` (muted emerald)
- **Warning:** `#f59e0b` (muted amber)
- **Error:** `#ef4444` (muted red)
- **Informational / Highlight:** `#38bdf8` (muted sky blue)

### Typography Stack (Offline, System-Native)
- **Standard UI Font:**
  `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif`
- **Monospace Font:**
  `SFMono-Regular, Consolas, "Liberation Mono", Menlo, Courier, monospace`
- **Type Scale:**
  - Page Title: `18px`, weight `600`
  - Section Headings: `14px`, weight `600`, letter-spacing `0.01em`
  - Labels & Headers: `11.5px`, uppercase, weight `600`, letter-spacing `0.04em`, color `--text-dim`
  - Body & Form Controls: `13px` / `13.5px`, line-height `1.5`
  - Monospace Table / Code Values: `12px`

### Spacing & Geometry Scale
- Border Radius: `4px` (buttons, inputs, badges), `6px` (cards, containers)
- Margins / Paddings: `4px`, `8px`, `12px`, `16px`, `20px`
- Shadows: Minimal to none (rely on subtle 1px border contrast)

---

## 3. Detailed Component Refinements

### A. Header
- **Left Side:** Title `MobiAttack` with version badge `V2`, subhead `Android Analysis Demo`, and description `Static analysis, package acquisition and runtime verification`.
- **Right Side:** Device status pill: `Device: 127.0.0.1:5555 · Ready` with small green status dot.
- No decorative emojis, marketing tags, or oversized logos.

### B. Input Section (Compact & Structured)
- **Section 1: Platform & Target URL (Primary Focus)**
  - Platform Segmented Radio (`Android` with SVG robot, `iOS (Planned)` with SVG apple).
  - Target URL input full width with subtle helper badges and single-line clickable preset links.
- **Section 2: Device, Installation & Options (Two-Column Alignment)**
  - Left column: ADB Target Device (`127.0.0.1:5555`).
  - Right column: Play Store Install Mode (Manual [Default], Automatic (Experimental) [subdued]).
  - Checkboxes row: Reinstall existing APK, Grant requested runtime permissions.
- **Section 3: Action Button**
  - Primary button: `Start Analysis` (`data-action="START DEMO"` to preserve test invariants).
  - Clean, restrained rectangular button, no gradient.

### C. Pipeline Status (4-Stage Equal Width Grid)
- 4 grid columns:
  1. `1. APK Acquisition`
  2. `2. Preprocessing`
  3. `3. Static Analysis`
  4. `4. Emulator Runtime`
- Each card has:
  - Top row: Stage number and title left, compact status badge right (`pending`, `running`, `success`, `warning`, `failed`, `waiting`).
  - Message line: Quiet secondary text (`12px`).
  - Details container: Compact key-value rows populated during execution.

### D. Analysis Results & Tabs
- Sleek tab bar with low-contrast inactive tabs and clean active tab indicator (underline or compact pill).
- Preserved tabs: `Overview`, `APK Components` (shown when split), `Application`, `Structure`, `Network`, `API Candidates`, `Runtime`, `Analysis Notes`, `Report`.

#### 1. Overview Tab
- Technical summary table / key-value layout:
  - Package Name, Source Type, Package Layout, Component Count, Launcher Activity, Total DEX Files, Declared Permissions, Declared Activities, Static Network Indicators, API Candidates, Runtime Status.
- Replaces bulky stat tiles with a structured technical summary grid.

#### 2. Application Tab
- Group 1: Application Identity (Package, Version, Launcher Activity, Target SDK, Min SDK).
- Group 2: Declared Permissions (count badge, scrollable fixed-height container, monospace text, 1 permission per row).
- Group 3: Declared Activities (count badge, scrollable fixed-height container, monospace text, 1 activity per row).

#### 3. Structure Tab
- For Split APKs: Clean card per Source APK (`base.apk`, `split_config.*.apk`) with DEX Files, Smali Roots, Native Libraries (`.so`), Assets, and Kotlin metadata status.
- For Single APKs: Direct technical key-value breakdown.

#### 4. Network Tab
- Category buttons (`Domains`, `Network URLs`, `IP Addresses`, `Path Candidates`, `Local File URLs`).
- Filters bar: Search input + Source APK dropdown + Pagination (`Prev`, page number, `Next`).
- Table: Compact rows with sticky `thead` (`Value`, `Type`, `Source APK`, `Source File`, `Line`).
- Warning note styled as subtle technical disclaimer: *"Static network indicators do not prove runtime network use."*

#### 5. API Candidates Tab
- When candidates exist: High-density table (`Method`, `Full URL`, `Base URL`, `Path`, `Framework`, `Source APK`, `Status`, `Source Location`).
- When zero candidates: Small neutral note with primary text *"No API candidates identified by the current call-context extractor."* and secondary text *"The current extractor supports limited framework-specific patterns."* (preserving all test assertions).

#### 6. Runtime Tab
- Compact key-value rows:
  - Device Serial, Observed PID, Observed Package, Observed Activity, Foreground Verified, Runtime Status.
  - Subtle green indicator for `runtime_launch_verified`.

#### 7. Analysis Notes Tab
- Clean unordered list with small square or subtle chevron bullet markers, low visual clutter, no nested callout boxes.

#### 8. Report Tab & Actions
- Clean action links: `View HTML Report`, `Download JSON Report`, `Open Report in New Tab`.

#### 9. Error States
- Non-dramatic alert banner: subtle dark red background (`rgba(239, 68, 68, 0.08)`), 1px border (`#ef4444`), monospace technical error code, and actionable remediation button (e.g. "Open in Play Store").

---

## 4. Test Invariant & Backward Compatibility Checklist

All 321 tests in the repository must remain 100% passing. The following string and element invariants verified by `test_demo_web_server.py` and `test_split_dashboard_report.py` will be strictly preserved:

1. **Page Title & Text Invariants:**
   - `"MobiAttack Android Demo"` (in HTML head/title)
   - `"Target URL (Direct APK or Google Play Store)"`
   - `"START DEMO"` (preserved via semantic attribute / label)
   - `"1. APK Acquisition"`, `"2. Preprocessing"`, `"3. Static Analysis"`, `"4. Emulator Runtime"`
   - `"HTML Connectivity Probe"`
   - `"Emulator connectivity only — not target application navigation."`
   - `"Grant requested runtime permissions during install"`
   - `"Analysis Results"`
   - `"View HTML Report"`, `"Download JSON Report"`, `"Open Report in New Tab"`
   - `"Static network indicators are extracted from application content and do not by themselves prove runtime network usage."`
   - `"No API candidates were identified by the current call-context extractor."`
   - `"Zero candidates does not mean the application has no APIs."`
   - `"Platform"`, `"platform-android"`, `"platform-ios"`, `"iOS analysis is not implemented in V1."`, `"urlClassificationBadge"`
2. **Tab Button IDs:**
   - `tab-btn-overview`, `tab-btn-components`, `tab-btn-application`, `tab-btn-structure`, `tab-btn-network`, `tab-btn-api_candidates`, `tab-btn-runtime`, `tab-btn-notes`, `tab-btn-report`
3. **Network Tab Controls:**
   - `id="netSearchInput"`, `id="netSourceApkSelect"`, `id="networkTotalCountTag"`, `class="pagination-bar"`, `changeNetPage`, `setNetCategory`
4. **HTML Report Consistency:**
   - `render_html_report` in `src/report_generator.py` is unaffected (backend logic remains untouched).

---

## 5. Implementation Roadmap (Post-Approval)

1. **Step 1: CSS & Design System Replacement in `src/demo_web_server.py`**
   - Strip external font `<link>` tags.
   - Define system font stacks, zinc/slate color tokens, compact form styles, and table styles.
2. **Step 2: HTML Template Structure Refinement**
   - Refactor Header, Input Form, Stage Grid, and Tab Containers according to the design principles.
3. **Step 3: JS Tab & Card Rendering Updates**
   - Update `renderApp`, `renderStatic`, `renderRuntime`, `renderNetworkViewer`, `renderStructure`, and `renderAnalysisResults` to generate the refined markup.
4. **Step 4: Verification & Validation**
   - Run `pytest tests/test_demo_web_server.py`.
   - Run `pytest tests/test_split_dashboard_report.py`.
   - Run full test suite (`pytest`).
   - Restart daemon on port 8082 and inspect in browser.
