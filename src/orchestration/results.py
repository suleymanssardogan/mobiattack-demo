"""Inventory aggregation and Android result/report assembly."""
from __future__ import annotations

from typing import Callable
from src.orchestration.common import _emit_progress


def scan_split_inventory(workspaces_dir):
    demo3_scan = None
    try:
        from src.demo3.scanner import scan_artifacts_deterministically
        component_roots = sorted((workspaces_dir / "processed").glob("*/apktool_out"))
        if component_roots:
            scans = [scan_artifacts_deterministically(root) for root in component_roots]
            numeric_keys = ("files_discovered", "files_analyzed", "files_skipped", "files_failed")
            statistics = {key: sum(scan["statistics"].get(key, 0) for scan in scans) for key in numeric_keys}
            statistics["failed_files"] = [
                {**item, "component": root.parent.name}
                for root, scan in zip(component_roots, scans)
                for item in scan["statistics"].get("failed_files", [])
            ]
            demo3_scan = {
                "status": "partial" if statistics["files_failed"] else "completed",
                "statistics": statistics,
                # The split static context already combines component
                # indicators with source APK provenance for the inventory.
                "candidates": [],
            }
    except Exception:
        pass
    return demo3_scan


def scan_single_inventory(apktool_root):
    demo3_scan = None
    try:
        from src.demo3.scanner import scan_artifacts_deterministically
        demo3_scan = scan_artifacts_deterministically(apktool_root)
    except Exception:
        pass
    return demo3_scan


def refresh_post_static_correlation(root_path):
    """Join the final same-run Static artifact with existing Dynamic evidence.

    Exploration precedes report generation, so its early correlation may have
    had no Static artifact. This is an offline projection, never another scan.
    """
    import json
    from src.orchestration.artifacts import _wire_api_correlation, _wire_endpoint_contexts
    from src.orchestration.lifecycle import _wire_dynamic_analysis_report
    static_path = root_path / 'static_analysis_report.json'
    session_path = root_path / 'dynamic/session.json'
    if not static_path.is_file() or not session_path.is_file():
        return None
    static = json.loads(static_path.read_text())
    session = json.loads(session_path.read_text())
    if static.get('run_id') != root_path.name or not session.get('session_id'):
        return None
    correlation = _wire_api_correlation(root_path, session['session_id'],
        _wire_endpoint_contexts=_wire_endpoint_contexts)
    if correlation is not None:
        _wire_dynamic_analysis_report(root_path)
    return correlation


def finish_android_run(*, url, platform, adb_serial, reinstall, grant_permissions,
                       acq_meta, prep_meta, static_context, runtime_meta, demo3_scan,
                       root_path, progress_callback, default_source_type,
                       _finalize_scan_state_post_run: Callable):
    final_result = {
        "input": {
            "url": url,
            "platform": platform,
            "source_type": acq_meta.get("source_type", default_source_type),
            "package_name": acq_meta.get("package_name"),
            "adb_serial": adb_serial,
            "reinstall": reinstall,
            "grant_permissions": grant_permissions,
        },
        "acquisition": acq_meta,
        "preprocessing": prep_meta,
        "static_analysis": static_context,
        "runtime": runtime_meta,
        "demo3_scan": demo3_scan,
        "demo_status": "completed",
    }
    try:
        from src.report_generator import generate_reports
        generate_reports(run_dir=root_path, run_id=root_path.name, pipeline_result=final_result)
        refresh_post_static_correlation(root_path)
    except Exception:
        pass
    _finalize_scan_state_post_run(root_path)
    _emit_progress(
        progress_callback,
        "demo",
        "completed",
        "Demo pipeline execution completed.",
        final_result,
    )
    return final_result
