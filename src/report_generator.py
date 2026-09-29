"""Deterministic Analysis Report Generator for MobiAttack-v2.

Produces structured machine-readable JSON reports (report.json) and standalone,
clean, printable HTML reports (report.html) directly from pipeline execution results.
Strictly preserves fact vs inference boundaries without security verdicts or scoring.
Supports both monolithic APKs and Split APK packages with component provenance.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def build_report_dict(
    run_id: str,
    pipeline_result: dict[str, Any] | None,
    error: str | None = None,
    current_stage: str | None = None,
    connectivity_probe: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Builds a standardized, machine-readable report dictionary.

    Args:
        run_id: Unique identifier for the demo run.
        pipeline_result: Result dictionary returned by run_demo, if available.
        error: Error message if the run failed.
        current_stage: Failed or current stage name if the run did not complete.
        connectivity_probe: Optional Task 10 connectivity probe result.

    Returns:
        Standardized report dictionary.
    """
    res = pipeline_result or {}
    demo_status = res.get("demo_status") or ("completed" if not error and res else "failed")

    # 1. Extraction of core blocks
    acq = res.get("acquisition") or {}
    prep = res.get("preprocessing") or {}
    static = res.get("static_analysis") or {}
    app = static.get("application") or static.get("app") or res.get("application") or {}
    struct = static.get("structure") or {}
    net = static.get("network_indicators") or {}
    candidates = static.get("api_candidates") or []
    runtime = res.get("runtime") or {}

    # Split package metadata
    package_layout = (
        static.get("package_layout")
        or acq.get("package_layout")
        or ("split" if acq.get("split_count") or acq.get("components") else "monolithic")
    )
    split_count = (
        static.get("split_count")
        or acq.get("split_count")
        or (len(acq.get("components", [])) if acq.get("components") else (1 if package_layout == "monolithic" else 0))
    )
    # Merge component metadata from acquisition and preprocessing
    merged_components = []
    acq_comps = acq.get("components") or []
    prep_comps = prep.get("components") or []
    acq_map = {c.get("filename"): c for c in acq_comps}
    prep_map = {c.get("filename"): c for c in prep_comps}
    all_filenames = list(dict.fromkeys([c.get("filename") for c in acq_comps + prep_comps if c.get("filename")]))

    for fn in all_filenames:
        c_acq = dict(acq_map.get(fn, {}))
        c_prep = dict(prep_map.get(fn, {}))
        merged = {**c_acq, **c_prep}
        raw_st = c_prep.get("raw_extract_status") or c_acq.get("preprocessing", {}).get("raw_extract_status") or "-"
        apk_st = c_prep.get("apktool_status") or c_acq.get("preprocessing", {}).get("apktool_status") or "-"
        jadx_st = c_prep.get("jadx_status") or c_acq.get("preprocessing", {}).get("jadx_status") or "-"
        warns = c_prep.get("warnings") or c_acq.get("preprocessing", {}).get("warnings") or []
        merged["preprocessing"] = {
            "raw_extract_status": raw_st,
            "apktool_status": apk_st,
            "jadx_status": jadx_st,
            "warnings": warns,
        }
        merged["raw_extract_status"] = raw_st
        merged["apktool_status"] = apk_st
        merged["jadx_status"] = jadx_st
        merged_components.append(merged)

    apk_components = merged_components if merged_components else (acq.get("components") or prep.get("components") or [])

    if "dex_count" not in struct or struct.get("dex_count") is None:
        struct["dex_count"] = struct.get("total_dex_count", sum(c.get("dex_count", 0) for c in apk_components))
    split_structure = (
        struct.get("components")
        or static.get("structure", {}).get("components")
        or []
    )
    manifest_evidence = static.get("manifest_evidence") or []

    # Source metadata
    input_info = res.get("input") or {}
    platform = acq.get("platform") or input_info.get("platform") or "android"
    source_type = acq.get("source_type") or "direct_apk"
    input_url = acq.get("input_url") or input_info.get("url") or "unknown"
    acq["platform"] = platform
    acq["source_type"] = source_type
    acq["input_url"] = input_url

    # Application overview data
    package_name = app.get("package_name") or acq.get("package_name") or "unknown"
    launcher_activity = app.get("launcher_activity") or "unknown"
    filename = acq.get("filename") or "unknown"
    sha256 = acq.get("sha256") or "unknown"
    size_bytes = acq.get("size_bytes")

    if str(platform).lower() == "ios":
        bundle_id = app.get("bundle_identifier") or "unknown"
        display_name = app.get("display_name") or app.get("bundle_name") or "unknown"
        application_data = {
            "platform": "ios",
            "bundle_identifier": bundle_id,
            "bundle_name": app.get("bundle_name"),
            "display_name": display_name,
            "executable": app.get("executable") or "unknown",
            "version": app.get("version") or "unknown",
            "build": app.get("build") or "unknown",
            "minimum_os_version": app.get("minimum_os_version") or "unknown",
            "supported_platforms": app.get("supported_platforms", []),
            "device_family": app.get("device_family", []),
            "package_name": bundle_id,
            "launcher_activity": "-",
            "filename": filename,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "is_valid_ipa": acq.get("validation", {}).get("is_valid_ipa", True) if acq else None,
        }
        analysis_notes = [
            "Analysis is limited to static package analysis of the provided IPA archive.",
            "Static network indicators prove only that the string constant exists in the package; they do not prove runtime use.",
            "Declared usage descriptions indicate capability declarations in Info.plist; they do not prove runtime permission access.",
            "App Transport Security (ATS) settings are recorded as factual configuration; security interpretation belongs to a later phase.",
            "Runtime launch verification is not implemented for iOS in Phase 1.",
            "No vulnerability exploitation was performed.",
            "No security verdict was produced.",
        ]
        limitations = [
            "Runtime launch verification and process monitoring are not implemented for iOS targets in Phase 1.",
            "Call-context API candidate extraction is not implemented for iOS in Phase 1 (zero candidates reported).",
            "Dynamic instrumentation, traffic interception (MITM/Burp), and deep UI exploration were not performed.",
            "No security verdict, vulnerability score, or risk classification is provided.",
        ]
    else:
        application_data = {
            "package_name": package_name,
            "launcher_activity": launcher_activity,
            "filename": filename,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "is_valid_apk": acq.get("validation", {}).get("is_valid_apk", False) if acq else None,
        }

        # Deterministic analysis notes
        analysis_notes = []
        jadx_status = prep.get("jadx", {}).get("status")
        if jadx_status == "success_with_warnings":
            analysis_notes.append("JADX completed with warnings (exit code 3). Decompiled source may contain partial warnings.")
        elif jadx_status == "success":
            analysis_notes.append("JADX decompilation completed successfully without warnings.")

        if package_layout == "split":
            analysis_notes.append("Split package analysis: only installed splits returned by pm path on the device were analyzed.")
            if apk_components:
                for comp in apk_components:
                    c_prep = comp.get("preprocessing") or {}
                    for w in c_prep.get("warnings", []):
                        analysis_notes.append(f"[{comp.get('filename')}] {w}")

        analysis_notes.append("Static network indicators are extracted from application content and do not by themselves prove runtime network usage.")
        analysis_notes.append("API candidates are static call-context candidates extracted from Smali register flows and do not represent confirmed runtime endpoints.")

    if len(candidates) == 0:
        analysis_notes.append("No API candidates were identified by the current call-context extractor.")
        analysis_notes.append("Static network indicators may still exist. The current V1 API candidate extractor supports limited framework-specific call patterns. Zero candidates does not mean the application has no APIs.")

    if runtime.get("status") == "runtime_launch_verified":
        analysis_notes.append("The application process was observed and the expected package/activity was detected in the foreground.")
    elif runtime.get("status"):
        analysis_notes.append(f"Runtime execution finished with status: {runtime.get('status')}.")

    if connectivity_probe:
        analysis_notes.append("HTML connectivity probe checks emulator reachability via ADB reverse and does not represent target application navigation.")

    analysis_notes.append("No vulnerability exploitation was performed.")
    analysis_notes.append("No security verdict was produced.")

    # Strict limitations
    limitations: list[str] = [
        "Analysis is limited to static heuristics and basic process/activity foreground observation.",
        "V1 API candidate extractor only tracks specific call-context register patterns (e.g. Fuel).",
        "Emulator connectivity verification uses browser intent and does not evaluate application network security posture.",
        "Dynamic instrumentation, traffic interception (MITM/Burp), and deep UI exploration were not performed.",
        "No security verdict, vulnerability score, or risk classification is provided.",
    ]
    if package_layout == "split":
        limitations.append("Split package analysis is limited to installed splits returned by pm path. Dynamic feature modules or config splits not delivered to the device were not analyzed.")

    report: dict[str, Any] = {
        "report_version": "1.0",
        "run_id": run_id,
        "demo_status": demo_status,
        "package_layout": package_layout,
        "split_count": split_count,
        "apk_components": apk_components,
        "split_structure": split_structure,
        "manifest_evidence": manifest_evidence,
        "application": application_data,
        "acquisition": acq,
        "preprocessing": prep,
        "structure": struct,
        "permissions": static.get("permissions") or [],
        "activities": static.get("activities") or [],
        "network_indicators": net,
        "api_candidates": candidates,
        "runtime": runtime,
        "connectivity_probe": connectivity_probe or {},
        "analysis_notes": analysis_notes,
        "limitations": limitations,
        "platform": platform,
    }

    if str(platform).lower() == "ios":
        report["configuration"] = static.get("configuration") or {}
        report["vulnerabilities"] = {
            "status": "not_evaluated",
            "reason": "not_implemented",
            "risk_score": "NOT_EVALUATED",
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
            "findings": [],
            "message": "iOS vulnerability evaluation is not implemented in Phase 1.",
        }
    elif "vulnerabilities" in res:
        report["vulnerabilities"] = res["vulnerabilities"]

    if demo_status == "failed" or error:
        report["failed_stage"] = current_stage or "unknown"
        report["failure_reason"] = error or "Stage execution failed."

    return report


def _render_ios_html_report(report: dict[str, Any]) -> str:
    """Generates a standalone, dependency-free printable HTML report for iOS IPA analysis."""
    run_id = html.escape(str(report.get("run_id", "unknown")))
    demo_status = html.escape(str(report.get("demo_status", "unknown")))
    app = report.get("application", {})
    acq = report.get("acquisition", {})
    prep = report.get("preprocessing", {})
    struct = report.get("structure", {})
    cfg = report.get("configuration", {}) or {}
    net = report.get("network_indicators", {})
    notes = report.get("analysis_notes", [])
    limits = report.get("limitations", [])

    bundle_id = html.escape(str(app.get("bundle_identifier", "-")))
    display_name = html.escape(str(app.get("display_name", "-")))
    executable = html.escape(str(app.get("executable", "-")))
    version = html.escape(str(app.get("version", "-")))
    build = html.escape(str(app.get("build", "-")))
    min_os = html.escape(str(app.get("minimum_os_version", "-")))
    filename = html.escape(str(app.get("filename", "-")))
    sha256 = html.escape(str(app.get("sha256", "-")))
    size_bytes = app.get("size_bytes")
    size_str = f"{size_bytes:,} bytes" if isinstance(size_bytes, int) else "-"

    # Structure / Mach-O details
    exe_info = struct.get("executable", {})
    archs = html.escape(", ".join(exe_info.get("architectures", [])) or "unknown")
    bitness = str(exe_info.get("bitness", "-"))
    file_type = html.escape(str(exe_info.get("file_type", "-")))
    uuid_val = html.escape(str(exe_info.get("uuid", "-")))

    frameworks = struct.get("frameworks", [])
    fw_rows = []
    for fw in frameworks:
        fw_name = html.escape(str(fw.get("name", "-")))
        fw_type = html.escape(str(fw.get("type", "-")))
        fw_path = html.escape(str(fw.get("relative_path", "-")))
        fw_rows.append(f"<tr><td><code>{fw_name}</code></td><td><span class='badge badge-accent'>{fw_type}</span></td><td><code>{fw_path}</code></td></tr>")

    fw_html = f"""
    <table class="data-table">
      <thead><tr><th>Name</th><th>Type</th><th>Relative Path</th></tr></thead>
      <tbody>{''.join(fw_rows) if fw_rows else '<tr><td colspan="3" class="empty-text">No embedded frameworks discovered.</td></tr>'}</tbody>
    </table>
    """

    res_info = struct.get("resources", {})
    res_html = f"""
    <table class="data-table">
      <tbody>
        <tr><td><strong>Total Files in Bundle:</strong></td><td>{res_info.get('total_files_count', 0)} files</td></tr>
        <tr><td><strong>Plist Files:</strong></td><td>{res_info.get('plist_count', 0)} files</td></tr>
        <tr><td><strong>JSON Files:</strong></td><td>{res_info.get('json_count', 0)} files</td></tr>
        <tr><td><strong>Asset Catalogs:</strong></td><td>{html.escape(', '.join(res_info.get('asset_catalogs', [])) or 'None')}</td></tr>
        <tr><td><strong>Localizations:</strong></td><td>{html.escape(', '.join(res_info.get('localization_dirs', [])) or 'None')}</td></tr>
      </tbody>
    </table>
    """

    # Usage Descriptions & URL Schemes
    usage_descs = cfg.get("usage_descriptions", [])
    if usage_descs:
        u_rows = []
        for u in usage_descs:
            k = html.escape(str(u.get("key", "")))
            v = html.escape(str(u.get("value", "")))
            src = html.escape(str(u.get("evidence", {}).get("source_file", "Info.plist")))
            u_rows.append(f"<tr><td><code>{k}</code></td><td>{v}</td><td><span class='badge badge-muted'>declared_usage_description</span></td><td><code>{src}</code></td></tr>")
        usage_html = f"""
        <table class="data-table">
          <thead><tr><th>Key</th><th>Declared String</th><th>Classification</th><th>Evidence Source</th></tr></thead>
          <tbody>{''.join(u_rows)}</tbody>
        </table>
        """
    else:
        usage_html = "<p class='empty-text'>No usage descriptions declared in Info.plist.</p>"

    url_schemes = cfg.get("url_schemes", [])
    if url_schemes:
        s_rows = []
        for s in url_schemes:
            if isinstance(s, dict):
                s_name = html.escape(str(s.get("scheme", "")))
                s_desc = html.escape(str(s.get("name", "-") or "-"))
            else:
                s_name = html.escape(str(s))
                s_desc = "-"
            s_rows.append(f"<tr><td><code>{s_name}://</code></td><td>{s_desc}</td></tr>")
        schemes_html = f"""
        <h4 style="margin-top:16px; margin-bottom:6px;">Declared URL Schemes ({len(url_schemes)})</h4>
        <table class="data-table">
          <thead><tr><th>URL Scheme</th><th>Scheme Name / Identifier</th></tr></thead>
          <tbody>{''.join(s_rows)}</tbody>
        </table>
        """
    else:
        schemes_html = """
        <h4 style="margin-top:16px; margin-bottom:6px;">Declared URL Schemes (0)</h4>
        <p class='empty-text'>No custom URL schemes declared.</p>
        """

    # ATS Configuration
    ats = cfg.get("ats", {})
    allows_arb = ats.get("allows_arbitrary_loads", False)
    allows_local = ats.get("allows_local_networking", False)
    exc_domains = ats.get("exception_domains", [])
    exc_rows = []
    for d in exc_domains:
        d_name = html.escape(str(d.get("domain", "-")))
        insec = "Yes" if d.get("allows_insecure_http_loads") else "No"
        subd = "Yes" if d.get("includes_subdomains") else "No"
        exc_rows.append(f"<tr><td><code>{d_name}</code></td><td>{insec}</td><td>{subd}</td></tr>")

    ats_html = f"""
    <table class="data-table">
      <tbody>
        <tr><td><strong>Allows Arbitrary Loads:</strong></td><td><code>{allows_arb}</code></td></tr>
        <tr><td><strong>Allows Local Networking:</strong></td><td><code>{allows_local}</code></td></tr>
        <tr><td><strong>Exception Domains Count:</strong></td><td>{len(exc_domains)}</td></tr>
      </tbody>
    </table>
    {f'''<h4 style="margin-top:12px; margin-bottom:6px;">ATS Exception Domains</h4>
    <table class="data-table"><thead><tr><th>Domain</th><th>Allows Insecure HTTP</th><th>Includes Subdomains</th></tr></thead>
    <tbody>{"".join(exc_rows)}</tbody></table>''' if exc_rows else ''}
    """

    # Entitlements
    ents = cfg.get("entitlements", {})
    ent_items = ents.get("items", {})
    ent_status = html.escape(str(ents.get("status", "not_found")))
    if ent_items:
        e_rows = []
        for ek, ev in ent_items.items():
            ek_esc = html.escape(str(ek))
            ev_esc = html.escape(str(ev))
            e_rows.append(f"<tr><td><code>{ek_esc}</code></td><td><code>{ev_esc}</code></td></tr>")
        ent_html = f"""
        <p style="margin-bottom:8px;">Extraction Status: <span class="badge badge-success">{ent_status}</span> (Source: <code>{html.escape(str(ents.get('source', '-')))}</code>)</p>
        <table class="data-table"><thead><tr><th>Entitlement Key</th><th>Value</th></tr></thead><tbody>{''.join(e_rows)}</tbody></table>
        """
    else:
        ent_html = f"<p class='empty-text'>Entitlements status: {ent_status} ({html.escape(str(ents.get('reason', 'no entitlements extracted')))}).</p>"

    # Network Indicators
    net_urls = net.get("network_urls", [])
    domains = net.get("domains", [])
    ips = net.get("ip_addresses", [])
    paths = net.get("path_candidates", [])

    def render_indicator_table(items: list[dict], label: str, default_type: str) -> str:
        if not items:
            return f"<p class='empty-text'>No {html.escape(label.lower())} discovered.</p>"
        rows = []
        for it in items[:100]:
            val = html.escape(str(it.get("value", "")))
            itype = html.escape(str(it.get("type", default_type)))
            src = html.escape(str(it.get("source_file", "")))
            line = str(it.get("line_number") or it.get("offset") or "-")
            rows.append(f"<tr><td><code>{val}</code></td><td><span class='badge badge-muted'>{itype}</span></td><td><code>{src}</code></td><td>{line}</td></tr>")
        return f"""
        <table class="data-table">
          <thead><tr><th>Indicator Value</th><th>Type</th><th>Source Artifact</th><th>Location</th></tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
        """

    urls_html = render_indicator_table(net_urls, "Network URLs", "network_url")
    domains_html = render_indicator_table(domains, "Domains", "domain")
    ips_html = render_indicator_table(ips, "IP Addresses", "ip_address")
    paths_html = render_indicator_table(paths, "Path Candidates", "path_candidate")

    notes_html = "".join(f"<li>{html.escape(str(n))}</li>" for n in notes)
    limits_html = "".join(f"<li>{html.escape(str(l))}</li>" for l in limits)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>MobiAttack iOS Report &mdash; {bundle_id}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 24px; }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    .header-card {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
    h1, h2, h3, h4 {{ color: #f8fafc; margin-bottom: 12px; }}
    .section {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 18px; margin-bottom: 20px; }}
    .data-table {{ width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }}
    .data-table th, .data-table td {{ border: 1px solid #1f2937; padding: 8px 10px; text-align: left; }}
    .data-table th {{ background: #1f2937; color: #94a3b8; font-weight: 600; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
    .badge-accent {{ background: #2563eb; color: #fff; }}
    .badge-success {{ background: #10b981; color: #fff; }}
    .badge-muted {{ background: #374151; color: #94a3b8; }}
    .note-box {{ background: #182234; border-left: 4px solid #3b82f6; padding: 10px 14px; border-radius: 4px; font-size: 13px; color: #93c5fd; margin-top: 10px; }}
    .empty-text {{ color: #64748b; font-style: italic; font-size: 13px; }}
    code {{ font-family: SFMono-Regular, Consolas, Menlo, monospace; color: #38bdf8; }}
    ul {{ margin-left: 20px; line-height: 1.6; font-size: 13px; color: #cbd5e1; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header-card">
      <h1>MobiAttack iOS Analysis Report</h1>
      <p style="color:#94a3b8; font-size:14px;">Deterministic Static Security Analysis Report</p>
    </div>

    <div class="section">
      <h2>1. Run Information</h2>
      <table class="data-table">
        <tbody>
          <tr><td><strong>Run ID:</strong></td><td><code>{run_id}</code></td></tr>
          <tr><td><strong>Platform:</strong></td><td><span class="badge badge-accent">iOS</span></td></tr>
          <tr><td><strong>Status:</strong></td><td><span class="badge badge-success">{demo_status}</span></td></tr>
        </tbody>
      </table>
    </div>

    <div class="section">
      <h2>2. Application Overview</h2>
      <table class="data-table">
        <tbody>
          <tr><td><strong>Bundle Identifier:</strong></td><td><code>{bundle_id}</code></td></tr>
          <tr><td><strong>Display Name:</strong></td><td>{display_name}</td></tr>
          <tr><td><strong>Executable:</strong></td><td><code>{executable}</code></td></tr>
          <tr><td><strong>Version / Build:</strong></td><td>{version} (build {build})</td></tr>
          <tr><td><strong>Minimum OS:</strong></td><td>{min_os}</td></tr>
          <tr><td><strong>Package File:</strong></td><td><code>{filename}</code> ({size_str})</td></tr>
          <tr><td><strong>SHA-256:</strong></td><td><code>{sha256}</code></td></tr>
        </tbody>
      </table>
    </div>

    <div class="section">
      <h2>3. Application Structure & Mach-O</h2>
      <h4 style="margin-top:6px;">Main Executable</h4>
      <table class="data-table">
        <tbody>
          <tr><td><strong>Architectures:</strong></td><td><code>{archs}</code></td></tr>
          <tr><td><strong>Bitness:</strong></td><td>{bitness}-bit</td></tr>
          <tr><td><strong>File Type:</strong></td><td>{file_type}</td></tr>
          <tr><td><strong>UUID:</strong></td><td><code>{uuid_val}</code></td></tr>
        </tbody>
      </table>
      <h4 style="margin-top:16px;">Embedded Frameworks ({len(frameworks)})</h4>
      {fw_html}
      <h4 style="margin-top:16px;">Resources Summary</h4>
      {res_html}
    </div>

    <div class="section">
      <h2>4. Declared Usage Descriptions & URL Schemes</h2>
      <h4 style="margin-top:6px; margin-bottom:6px;">Usage Descriptions ({len(usage_descs)})</h4>
      {usage_html}
      {schemes_html}
    </div>

    <div class="section">
      <h2>5. Entitlements & ATS Configuration</h2>
      <h4>App Transport Security (ATS)</h4>
      {ats_html}
      <h4 style="margin-top:16px;">Entitlements</h4>
      {ent_html}
    </div>

    <div class="section">
      <h2>6. Static Network Indicators</h2>
      <h4>Network URLs ({len(net_urls)})</h4>
      {urls_html}
      <h4 style="margin-top:14px;">Domains ({len(domains)})</h4>
      {domains_html}
      <h4 style="margin-top:14px;">IP Addresses ({len(ips)})</h4>
      {ips_html}
      <h4 style="margin-top:14px;">Path Candidates ({len(paths)})</h4>
      {paths_html}
    </div>

    <div class="section">
      <h2>7. Vulnerability Analysis</h2>
      <div class="note-box" style="background: #1e1b2e; border-left: 4px solid #a855f7; color: #e9d5ff;">
        <strong>Status:</strong> Not evaluated<br/>
        <strong>Reason:</strong> iOS vulnerability evaluation is not implemented in Phase 1.<br/>
        <span style="font-size:12px; color:#c4b5fd; margin-top:4px; display:inline-block;">
          Note: 0 findings does not imply the application is clean or secure. Absence of evaluation is not a negative finding.
        </span>
      </div>
    </div>

    <div class="section">
      <h2>8. Static API Candidates</h2>
      <div class="note-box">
        Zero candidates extracted. Static call-context API candidate extraction is not implemented for iOS in Phase 1.
      </div>
    </div>

    <div class="section">
      <h2>9. Runtime Verification</h2>
      <div class="note-box">
        Runtime launch verification is not implemented for iOS targets in Phase 1.
      </div>
    </div>

    <div class="section">
      <h2>10. Analysis Notes</h2>
      <ul>{notes_html}</ul>
    </div>

    <div class="section">
      <h2>11. Limitations</h2>
      <ul>{limits_html}</ul>
    </div>
  </div>
</body>
</html>
"""


def render_html_report(report: dict[str, Any]) -> str:
    """Generates a standalone, dependency-free, printable HTML report."""
    app_platform = (
        report.get("platform")
        or report.get("application", {}).get("platform")
        or report.get("acquisition", {}).get("platform")
        or "android"
    )
    if str(app_platform).lower() == "ios":
        return _render_ios_html_report(report)

    run_id = html.escape(str(report.get("run_id", "unknown")))
    demo_status = html.escape(str(report.get("demo_status", "unknown")))
    app = report.get("application", {})
    acq = report.get("acquisition", {})
    prep = report.get("preprocessing", {})
    struct = report.get("structure", {})
    perms = report.get("permissions", [])
    acts = report.get("activities", [])
    net = report.get("network_indicators", {})
    candidates = report.get("api_candidates", [])
    runtime = report.get("runtime", {})
    probe = report.get("connectivity_probe", {})
    notes = report.get("analysis_notes", [])
    limits = report.get("limitations", [])

    package_layout = report.get("package_layout", "monolithic")
    split_count = report.get("split_count", 1)
    apk_components = report.get("apk_components", [])
    split_structure = report.get("split_structure", [])

    pkg_name = html.escape(str(app.get("package_name", "-")))
    launcher_act = html.escape(str(app.get("launcher_activity", "-")))
    filename = html.escape(str(app.get("filename", "-")))
    sha256 = html.escape(str(app.get("sha256", "-")))
    size_bytes = app.get("size_bytes")
    size_str = f"{size_bytes:,} bytes" if isinstance(size_bytes, int) else "-"

    platform_val = html.escape(str(acq.get("platform", "android")).upper())
    source_type_val = html.escape(str(acq.get("source_type", "direct_apk")))
    input_url_val = html.escape(str(acq.get("input_url", "-")))

    layout_display = f"Split APK ({split_count} components)" if package_layout == "split" else "Single APK"

    play_rows = ""
    if acq.get("source_type") == "play_store":
        pkg_id = html.escape(str(acq.get("package_name", "-")))
        dev_inst = "Yes" if acq.get("installed_on_device") else "No"
        initially_inst = "Yes" if acq.get("initially_installed") else "No"
        inst_mode = html.escape(str(acq.get("install_mode", "manual")))
        inst_status = html.escape(str(acq.get("install_status", "already_installed")))
        open_method = html.escape(str(acq.get("play_store_open_method", "none")))
        play_rows = f"""
        <tr><td><strong>Play Store Package:</strong></td><td><code>{pkg_id}</code></td></tr>
        <tr><td><strong>Initially Installed:</strong></td><td>{initially_inst}</td></tr>
        <tr><td><strong>Install Mode:</strong></td><td><code>{inst_mode}</code></td></tr>
        <tr><td><strong>Install Status:</strong></td><td><code>{inst_status}</code></td></tr>
        <tr><td><strong>Play Store Open Method:</strong></td><td><code>{open_method}</code></td></tr>
        <tr><td><strong>Installed on Device:</strong></td><td>{dev_inst}</td></tr>
        """

    jadx = prep.get("jadx", {})
    jadx_status = str(jadx.get("status", "not_executed"))
    jadx_warn = jadx_status == "success_with_warnings"

    apktool = prep.get("apktool", {})
    raw = prep.get("raw_apk", {})

    status_color = "#22c55e" if demo_status == "completed" else "#ef4444"

    # Preprocessing / Component inventory
    if package_layout == "split" and apk_components:
        comp_rows = []
        for c in apk_components:
            fn = html.escape(str(c.get("filename", "-")))
            role = html.escape(str(c.get("role", "-")))
            sz = c.get("size_bytes")
            if isinstance(sz, int):
                if sz >= 1024 * 1024:
                    sz_str = f"{sz / (1024 * 1024):.2f} MB"
                elif sz >= 1024:
                    sz_str = f"{sz / 1024:.1f} KB"
                else:
                    sz_str = f"{sz} B"
            else:
                sz_str = "-"
            h_sha = html.escape(str(c.get("sha256", "-")))
            d_cnt = str(c.get("dex_count", 0))
            c_prep = c.get("preprocessing") or {}
            raw_st = c_prep.get("raw_extract_status") or c.get("raw_extract_status", "-")
            apktool_st = c_prep.get("apktool_status") or c.get("apktool_status", "-")
            jadx_st = c_prep.get("jadx_status") or c.get("jadx_status", "-")

            def badge_for_st(st_val: str) -> str:
                st_esc = html.escape(str(st_val))
                if st_val == "success":
                    return f'<span class="badge badge-success">{st_esc}</span>'
                elif st_val == "success_with_warnings":
                    return f'<span class="badge badge-warning">{st_esc}</span>'
                elif st_val == "skipped_no_dex":
                    return f'<span class="badge badge-muted">{st_esc}</span>'
                else:
                    return f'<span class="badge badge-muted">{st_esc}</span>'

            comp_rows.append(f"""
            <tr>
              <td><strong><code>{fn}</code></strong></td>
              <td><span class="badge badge-accent">{role}</span></td>
              <td>{sz_str}</td>
              <td><code title="{h_sha}">{h_sha[:10]}...</code></td>
              <td>{d_cnt}</td>
              <td>{badge_for_st(raw_st)}</td>
              <td>{badge_for_st(apktool_st)}</td>
              <td>{badge_for_st(jadx_st)}</td>
            </tr>
            """)
        prep_html = f"""
        <div style="font-weight:600; font-size:14px; margin-bottom:8px; color:var(--accent);">APK Component Inventory</div>
        <table class="data-table">
          <thead>
            <tr>
              <th>Filename</th>
              <th>Role</th>
              <th>Size</th>
              <th>SHA-256</th>
              <th>DEX Count</th>
              <th>Raw Extract</th>
              <th>Apktool</th>
              <th>JADX</th>
            </tr>
          </thead>
          <tbody>
            {''.join(comp_rows)}
          </tbody>
        </table>
        <div class="note-box">
          <strong>Component note:</strong> DEX-less splits (e.g. config splits) intentionally skip JADX decompilation (<code>skipped_no_dex</code>), which is normal informational state. Only installed splits returned by <code>pm path</code> were analyzed.
        </div>
        """
    else:
        prep_html = f"""
        <table class="data-table">
          <thead><tr><th>Component</th><th>Status</th><th>Details</th></tr></thead>
          <tbody>
            <tr>
              <td><strong>Raw APK Extraction</strong></td>
              <td><span class="badge badge-success">extracted</span></td>
              <td>{raw.get('file_count', 0)} files unpacked</td>
            </tr>
            <tr>
              <td><strong>Apktool Disassembly</strong></td>
              <td><span class="badge {'badge-success' if apktool.get('status') == 'success' else 'badge-muted'}">{html.escape(str(apktool.get('status', 'not_executed')))}</span></td>
              <td>Exit code {apktool.get('returncode', '-')}</td>
            </tr>
            <tr>
              <td><strong>JADX Decompilation</strong></td>
              <td><span class="badge {'badge-warning' if jadx_warn else ('badge-success' if jadx_status == 'success' else 'badge-muted')}">{html.escape(jadx_status)}</span></td>
              <td>Exit code {jadx.get('returncode', '-')} {('(Completed with warnings)' if jadx_warn else '')}</td>
            </tr>
          </tbody>
        </table>
        """

    # Structure info
    if package_layout == "split" and split_structure:
        split_struct_blocks = []
        for sc in split_structure:
            s_apk = html.escape(str(sc.get("source_apk", "-")))
            s_role = html.escape(str(sc.get("role", "-")))
            s_dex = sc.get("dex_files", [])
            s_dex_cnt = sc.get("dex_count", len(s_dex))
            s_multi = sc.get("is_multidex", False)
            s_libs = sc.get("native_libraries", [])
            s_has_native = sc.get("has_native_code", False)
            s_assets = sc.get("assets", [])
            s_smali = sc.get("smali_roots", [])
            s_kt = sc.get("has_kotlin_metadata", False)
            split_struct_blocks.append(f"""
            <div class="info-card" style="margin-bottom:12px;">
              <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
                <strong style="color:var(--accent);">Source APK: <code>{s_apk}</code></strong>
                <span class="badge badge-accent">{s_role}</span>
              </div>
              <table class="data-table">
                <tbody>
                  <tr><td><strong>DEX Files ({s_dex_cnt}):</strong></td><td>{html.escape(', '.join(s_dex) if s_dex else 'None')} (multidex={s_multi})</td></tr>
                  <tr><td><strong>Native Libraries ({len(s_libs)}):</strong></td><td>{html.escape(', '.join(s_libs[:5]) if s_libs else 'None')}{' ...' if len(s_libs) > 5 else ''} (has_native_code={s_has_native})</td></tr>
                  <tr><td><strong>Assets Count:</strong></td><td>{len(s_assets)} files {f"({html.escape(', '.join(s_assets[:3]))})" if s_assets else ""}</td></tr>
                  <tr><td><strong>Smali Roots:</strong></td><td>{html.escape(', '.join(s_smali) if s_smali else 'None')}</td></tr>
                  <tr><td><strong>Kotlin Metadata:</strong></td><td>{'Present in APK' if s_kt else 'Not detected'}</td></tr>
                </tbody>
              </table>
            </div>
            """)
        struct_html = "".join(split_struct_blocks)
    else:
        dex_files = struct.get("dex_files", [])
        dex_count = struct.get("dex_count", len(dex_files))
        is_multidex = struct.get("is_multidex", False)
        native_libs = struct.get("native_libraries", [])
        has_native = struct.get("has_native_code", False)
        assets = struct.get("assets", [])
        smali_roots = struct.get("smali_roots", [])
        has_kotlin_meta = struct.get("has_kotlin_metadata", False)

        struct_html = f"""
        <table class="data-table">
          <tbody>
            <tr><td><strong>DEX Count:</strong></td><td>{dex_count} (multidex={is_multidex})</td></tr>
            <tr><td><strong>DEX Files:</strong></td><td>{html.escape(', '.join(dex_files) if dex_files else 'None')}</td></tr>
            <tr><td><strong>Native Libraries:</strong></td><td>{len(native_libs)} libraries (has_native_code={has_native})</td></tr>
            {f"<tr><td><strong>Native Files:</strong></td><td><code>{html.escape(', '.join(native_libs[:10]))}{' ...' if len(native_libs) > 10 else ''}</code></td></tr>" if native_libs else ""}
            <tr><td><strong>Assets Count:</strong></td><td>{len(assets)} files</td></tr>
            <tr><td><strong>Smali Roots:</strong></td><td>{html.escape(', '.join(smali_roots) if smali_roots else 'None')}</td></tr>
            <tr><td><strong>Kotlin Metadata:</strong></td><td>{'Present in APK' if has_kotlin_meta else 'Not detected'}</td></tr>
          </tbody>
        </table>
        <div class="note-box">
          <strong>Structural note:</strong> "Kotlin metadata present" confirms Kotlin module or metadata indicators were discovered; it does not assume authoring language of third-party libraries.
        </div>
        """

    # Permissions info
    if perms:
        perms_rows = "".join(f"<li><code>{html.escape(str(p))}</code></li>" for p in perms)
        perms_html = f"<div class='count-badge'>{len(perms)} Permissions Declared</div><ul class='code-list'>{perms_rows}</ul>"
    else:
        perms_html = "<p class='empty-text'>No permissions declared in AndroidManifest.xml.</p>"

    # Activities info
    if acts:
        acts_rows = "".join(f"<li><code>{html.escape(str(a))}</code></li>" for a in acts)
        acts_html = f"<div class='count-badge'>{len(acts)} Activities Declared</div><ul class='code-list'>{acts_rows}</ul>"
    else:
        acts_html = "<p class='empty-text'>No activities declared in AndroidManifest.xml.</p>"

    # Network Indicators info
    net_urls = net.get("network_urls", [])
    domains = net.get("domains", [])
    ips = net.get("ip_addresses", [])
    paths = net.get("path_candidates", [])
    local_files = net.get("local_file_urls", [])

    def render_indicator_table(items: list[dict], label: str, default_type: str) -> str:
        if not items:
            return f"<p class='empty-text'>No {html.escape(label.lower())} discovered.</p>"
        rows = []
        for it in items[:100]:
            if isinstance(it, dict):
                val = html.escape(str(it.get("value", "")))
                itype = html.escape(str(it.get("type", default_type)))
                s_apk = html.escape(str(it.get("source_apk", "-")))
                src = html.escape(str(it.get("source_file", "")))
                line = str(it.get("line_number", ""))
            else:
                val = html.escape(str(it))
                itype = html.escape(default_type)
                s_apk = "-"
                src = "-"
                line = ""
            rows.append(f"<tr><td><code>{val}</code></td><td><span class='badge badge-muted'>{itype}</span></td><td><code>{s_apk}</code></td><td><code>{src}</code></td><td>{line}</td></tr>")
        
        count_notice = (
            f"<p class='empty-text'>(Showing first 100 of {len(items)} {html.escape(label.lower())} indicators.)</p>"
            if len(items) > 100
            else f"<p class='empty-text'>(Total {len(items)} {html.escape(label.lower())} indicators.)</p>"
        )
        return f"""
        <table class="data-table">
          <thead><tr><th>Value</th><th>Type</th><th>Source APK</th><th>Source File</th><th>Line</th></tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>
        {count_notice}
        """

    net_html = f"""
    <div class="disclaimer-banner">
      <strong>Notice:</strong> Static network indicators prove the presence of strings in extracted application artifacts. They do not by themselves prove runtime network usage.
    </div>
    <h4>Network URLs ({len(net_urls)})</h4>
    {render_indicator_table(net_urls, "Network URLs", "network_url")}
    <h4>Domains ({len(domains)})</h4>
    {render_indicator_table(domains, "Domains", "domain")}
    <h4>IP Addresses ({len(ips)})</h4>
    {render_indicator_table(ips, "IP Addresses", "ip_address")}
    <h4>Path Candidates ({len(paths)})</h4>
    {render_indicator_table(paths, "Path Candidates", "path_candidate")}
    <h4>Local File URLs ({len(local_files)})</h4>
    {render_indicator_table(local_files, "Local File URLs", "local_file_url")}
    """

    # API Candidates info
    if candidates:
        cand_rows = []
        for c in candidates:
            m = html.escape(str(c.get("method", "-")))
            full = html.escape(str(c.get("full_url") or "-"))
            base = html.escape(str(c.get("base_url") or "-"))
            path_val = html.escape(str(c.get("path") or "-"))
            fw = html.escape(str(c.get("framework") or "-"))
            s_apk = html.escape(str(c.get("source_apk") or "-"))
            st = html.escape(str(c.get("status") or "static_api_candidate"))
            src = html.escape(str(c.get("source_file") or "-"))
            ln = str(c.get("request_line", "-"))
            cand_rows.append(f"""
            <tr>
              <td><span class="badge badge-accent">{m}</span></td>
              <td><code>{full}</code></td>
              <td><code>{base}</code></td>
              <td><code>{path_val}</code></td>
              <td>{fw}</td>
              <td><code>{s_apk}</code></td>
              <td><code>{src}:{ln}</code></td>
              <td><span class="badge badge-muted">{st}</span></td>
            </tr>
            """)
        api_html = f"""
        <table class="data-table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Full URL</th>
              <th>Base URL</th>
              <th>Path</th>
              <th>Framework</th>
              <th>Source APK</th>
              <th>Source Location</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>{''.join(cand_rows)}</tbody>
        </table>
        """
    else:
        api_html = """
        <div class="info-card">
          <div style="font-weight:600; margin-bottom:6px; color:#38bdf8;">
            No API candidates were identified by the current call-context extractor.
          </div>
          <div style="color:#94a3b8; font-size:13px; line-height:1.5;">
            The current V1 call-context extractor supports limited framework-specific patterns. Zero candidates does not mean the application has no APIs.
          </div>
        </div>
        """

    # Runtime info
    adb_serial = html.escape(str(runtime.get("adb", {}).get("serial", "-")))
    inst = runtime.get("install", {})
    lnc = runtime.get("launch", {})
    rt = runtime.get("runtime", {})
    rt_status = html.escape(str(runtime.get("status", "not_executed")))

    runtime_html = f"""
    <table class="data-table">
      <tbody>
        <tr><td><strong>Device Serial:</strong></td><td><code>{adb_serial}</code></td></tr>
        <tr><td><strong>Install Result:</strong></td><td>{'Success' if inst.get('success') else ('Skipped (pre-installed)' if inst.get('skipped') else 'Failed / Not Executed')}</td></tr>
        <tr><td><strong>Reinstall Allowed:</strong></td><td>{inst.get('reinstall', False)}</td></tr>
        <tr><td><strong>Grant Permissions (-g):</strong></td><td>{inst.get('grant_permissions', False)}</td></tr>
        <tr><td><strong>Launched Component:</strong></td><td><code>{html.escape(str(lnc.get('component', '-')))}</code></td></tr>
        <tr><td><strong>Observed PID:</strong></td><td><code>{html.escape(str(rt.get('pid', '-')))}</code></td></tr>
        <tr><td><strong>Observed Package:</strong></td><td><code>{html.escape(str(rt.get('observed_package', '-')))}</code></td></tr>
        <tr><td><strong>Observed Activity:</strong></td><td><code>{html.escape(str(rt.get('observed_activity', '-')))}</code></td></tr>
        <tr><td><strong>Foreground Verified:</strong></td><td>{'Yes' if rt.get('foreground_verified') else 'No'}</td></tr>
        <tr><td><strong>Runtime Status:</strong></td><td><span class="badge badge-accent">{rt_status}</span></td></tr>
      </tbody>
    </table>
    <div class="note-box">
      The application process was observed and the expected package/activity was detected in the foreground.
    </div>
    """

    # Probe info
    probe_url = html.escape(str(probe.get("probe_url", "-")))
    probe_hit = probe.get("probe_hit", False)
    probe_count = probe.get("hit_count", 0)
    probe_status = html.escape(str(probe.get("status", "not_executed")))

    probe_html = f"""
    <table class="data-table">
      <tbody>
        <tr><td><strong>Probe URL:</strong></td><td><code>{probe_url}</code></td></tr>
        <tr><td><strong>Probe Hit:</strong></td><td>{'Yes' if probe_hit else 'No'}</td></tr>
        <tr><td><strong>Hit Count:</strong></td><td>{probe_count}</td></tr>
        <tr><td><strong>Status:</strong></td><td><span class="badge badge-accent">{probe_status}</span></td></tr>
      </tbody>
    </table>
    <div class="note-box">
      Emulator connectivity only &mdash; not target application navigation. Verifies browser/emulator network reachability via ADB reverse.
    </div>
    """

    # Notes & Limitations
    notes_html = "".join(f"<li>{html.escape(str(n))}</li>" for n in notes)
    limits_html = "".join(f"<li>{html.escape(str(l))}</li>" for l in limits)

    fail_html = ""
    if demo_status == "failed":
        failed_stage = html.escape(str(report.get("failed_stage", "unknown")))
        failure_reason = html.escape(str(report.get("failure_reason", "No reason specified.")))
        fail_html = f"""
        <div class="failure-banner">
          <strong>Run Failure:</strong> Execution terminated at stage <code>{failed_stage}</code>.<br/>
          <strong>Reason:</strong> {failure_reason}
        </div>
        """

    total_net_count = len(net_urls) + len(domains) + len(ips) + len(paths) + len(local_files)

    overview_extra_rows = ""
    if package_layout == "split":
        overview_extra_rows = f"""
        <tr><td><strong>Total DEX Count:</strong></td><td>{struct.get('dex_count', 0)}</td></tr>
        <tr><td><strong>Network Indicators:</strong></td><td>{total_net_count}</td></tr>
        <tr><td><strong>API Candidates:</strong></td><td>{len(candidates)}</td></tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MobiAttack Analysis Report - {pkg_name}</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --border: #334155;
      --accent: #38bdf8;
      --success: #22c55e;
      --warning: #f59e0b;
      --error: #ef4444;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
      max-width: 1000px;
      margin: 0 auto;
    }}
    header {{
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }}
    h1 {{ font-size: 24px; font-weight: 700; color: #fff; }}
    .subtitle {{ font-size: 14px; color: var(--text-muted); margin-top: 4px; }}
    h2 {{
      font-size: 16px;
      font-weight: 600;
      color: var(--accent);
      margin-top: 28px;
      margin-bottom: 12px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    h4 {{ font-size: 13px; font-weight: 600; color: var(--text-muted); margin: 12px 0 6px; }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      font-size: 11px;
      font-weight: 700;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .badge-success {{ background: rgba(34, 197, 94, 0.15); color: var(--success); }}
    .badge-warning {{ background: rgba(245, 158, 11, 0.15); color: var(--warning); }}
    .badge-error {{ background: rgba(239, 68, 68, 0.15); color: var(--error); }}
    .badge-muted {{ background: rgba(148, 163, 184, 0.15); color: var(--text-muted); }}
    .badge-accent {{ background: rgba(56, 189, 248, 0.15); color: var(--accent); }}
    .data-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      margin-bottom: 16px;
    }}
    .data-table th, .data-table td {{
      padding: 8px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    .data-table th {{
      background: var(--card-bg);
      font-weight: 600;
      color: var(--text-muted);
    }}
    .data-table td code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      word-break: break-all;
    }}
    .code-list {{
      list-style: none;
      max-height: 240px;
      overflow-y: auto;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 14px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      margin-bottom: 14px;
    }}
    .code-list li {{ padding: 3px 0; border-bottom: 1px dashed var(--border); }}
    .code-list li:last-child {{ border-bottom: none; }}
    .count-badge {{ font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 6px; }}
    .disclaimer-banner {{
      background: rgba(245, 158, 11, 0.08);
      border-left: 4px solid var(--warning);
      padding: 10px 14px;
      font-size: 12px;
      margin: 12px 0;
      border-radius: 0 6px 6px 0;
    }}
    .failure-banner {{
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid var(--error);
      padding: 12px 16px;
      border-radius: 6px;
      margin-bottom: 20px;
      color: var(--error);
    }}
    .note-box {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      padding: 10px 14px;
      font-size: 12px;
      border-radius: 6px;
      margin: 10px 0 16px;
      font-style: italic;
    }}
    .info-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 14px;
      margin-bottom: 14px;
    }}
    .empty-text {{ font-size: 13px; color: var(--text-muted); font-style: italic; margin-bottom: 10px; }}
    ul.bullet-list {{ padding-left: 20px; font-size: 13px; margin-bottom: 14px; }}
    ul.bullet-list li {{ margin-bottom: 6px; }}
    @media print {{
      body {{ background: #fff !important; color: #000 !important; padding: 0 !important; }}
      .data-table th {{ background: #eee !important; }}
      .code-list {{ max-height: none !important; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>1. MobiAttack Android Demo Analysis Report</h1>
    <div class="subtitle">Deterministic Android Security Analysis & Runtime Evidence Dossier</div>
  </header>

  {fail_html}

  <h2>2. Run Information</h2>
  <table class="data-table">
    <tbody>
      <tr><td><strong>Run ID:</strong></td><td><code>{run_id}</code></td></tr>
      <tr><td><strong>Demo Status:</strong></td><td><span class="badge" style="background:{status_color}22; color:{status_color};">{demo_status}</span></td></tr>
      <tr><td><strong>Package Layout:</strong></td><td><span class="badge badge-accent">{layout_display}</span></td></tr>
      <tr><td><strong>Report Version:</strong></td><td>1.0</td></tr>
    </tbody>
  </table>

  <h2>3. Application Overview</h2>
  <table class="data-table">
    <tbody>
      <tr><td><strong>Package Name:</strong></td><td><code>{pkg_name}</code></td></tr>
      <tr><td><strong>Launcher Activity:</strong></td><td><code>{launcher_act}</code></td></tr>
      <tr><td><strong>Package Layout:</strong></td><td><span class="badge badge-accent">{layout_display}</span></td></tr>
      {overview_extra_rows}
      <tr><td><strong>APK Filename:</strong></td><td><code>{filename}</code></td></tr>
      <tr><td><strong>SHA-256:</strong></td><td><code>{sha256}</code></td></tr>
      <tr><td><strong>File Size:</strong></td><td>{size_str}</td></tr>
    </tbody>
  </table>

  <h2>4. APK Acquisition</h2>
  <table class="data-table">
    <tbody>
      <tr><td><strong>Platform:</strong></td><td>{platform_val}</td></tr>
      <tr><td><strong>Source Type:</strong></td><td><code>{source_type_val}</code></td></tr>
      <tr><td><strong>Input URL:</strong></td><td><code>{input_url_val}</code></td></tr>
      {play_rows}
      <tr><td><strong>Package Layout:</strong></td><td>{layout_display}</td></tr>
      <tr><td><strong>Filename:</strong></td><td><code>{filename}</code></td></tr>
      <tr><td><strong>SHA-256 Digest:</strong></td><td><code>{sha256}</code></td></tr>
      <tr><td><strong>Package Verification:</strong></td><td>{'Valid APK format' if acq.get('validation', {}).get('is_valid_apk') else 'Unverified'}</td></tr>
    </tbody>
  </table>

  <h2>5. Preprocessing</h2>
  {prep_html}

  <h2>6. Application Structure</h2>
  {struct_html}

  <h2>7. Permissions</h2>
  {perms_html}

  <h2>8. Activities</h2>
  {acts_html}

  <h2>9. Static Network Indicators</h2>
  {net_html}

  <h2>10. Static API Candidates</h2>
  {api_html}

  <h2>11. Runtime Evidence</h2>
  {runtime_html}

  <h2>12. HTML Connectivity Probe</h2>
  {probe_html}

  <h2>13. Analysis Notes</h2>
  <ul class="bullet-list">
    {notes_html}
  </ul>

  <h2>14. Limitations</h2>
  <ul class="bullet-list">
    {limits_html}
  </ul>
</body>
</html>
"""


def generate_reports(
    run_dir: Path,
    run_id: str,
    pipeline_result: dict[str, Any] | None,
    error: str | None = None,
    current_stage: str | None = None,
    connectivity_probe: dict[str, Any] | None = None,
) -> tuple[Path, Path]:
    """Generates and persists report.json and report.html into run_dir.

    Args:
        run_dir: Path to directory for the run (e.g. demo_runs/run_...).
        run_id: Identifier for the run.
        pipeline_result: Pipeline results dictionary if run completed or reached static stage.
        error: Error string if run failed.
        current_stage: Stage tag where failure or execution ended.
        connectivity_probe: Standalone Task 10 probe data if recorded.

    Returns:
        tuple containing (json_path, html_path).
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    report_dict = build_report_dict(
        run_id=run_id,
        pipeline_result=pipeline_result,
        error=error,
        current_stage=current_stage,
        connectivity_probe=connectivity_probe,
    )

    json_path = run_dir / "report.json"
    html_path = run_dir / "report.html"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    html_content = render_html_report(report_dict)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    # Demo 3: Generate and validate baseline_report.json against JSON Schema
    try:
        from src.demo3.baseline_reporter import build_baseline_report, save_baseline_report
        baseline_dict = build_baseline_report(
            run_id=run_id,
            pipeline_result=pipeline_result,
            error=error,
        )
        save_baseline_report(run_dir, baseline_dict)
    except Exception as exc:
        pass

    return json_path, html_path
