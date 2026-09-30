"""End-to-End Real Dynamic Pipeline Demonstration for MobiAttack-v2.

Execution Sequence:
[1/7] Dynamic Preflight (device, emulator, root, network, launchability, runtime baseline)
[2/7] Dynamic Session Started (UUID, metadata, state ACTIVE)
[3/7] Target Flow Started (login flow, markers: LOGIN_START)
[4/7] Proxy Configured (backup previous global proxy, set to 10.0.2.2:8080)
[5/7] Real HTTP Traffic Captured (real HTTP GET/POST sent from Android emulator through proxy)
[6/7] Traffic Correlated (flow attribution, nearest marker before/after, privacy redaction)
[7/7] Proxy Restored (guaranteed rollback of device global proxy)
"""

from __future__ import annotations

import json
import os
import sys
import time

# Ensure repository root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.dynamic.preflight.device_check import run_adb_cmd
from src.dynamic.preflight.service import DynamicPreflightService
from src.dynamic.session.manager import DynamicSessionManager
from src.dynamic.session.storage import SessionStorage
from src.dynamic.traffic.native_backend import NativeProxyCaptureBackend
from src.dynamic.traffic.service import DynamicTrafficService
from src.dynamic.traffic.storage import TrafficStorage


def run_demo() -> bool:
    print("==================================================")
    print("      MOBIATTACK DYNAMIC PIPELINE DEMO")
    print("==================================================")

    target_pkg = "com.android.settings"
    serial = "emulator-5554"
    proxy_port = 8080
    proxy_host = "10.0.2.2"

    # [1/7] Dynamic Preflight
    print("\n[1/7] Running Dynamic Preflight...")
    preflight_svc = DynamicPreflightService()
    preflight = preflight_svc.run_preflight(package_name=target_pkg, target_serial=serial)
    print(f"      Preflight Status: {preflight.status.value}")
    print(f"      Device: {preflight.device.serial} (Emulator: {preflight.device.is_emulator})")
    print(f"      Package: {preflight.application.package_name} (Installed: {preflight.application.installed}, Foreground: {preflight.application.foreground})")
    print(f"      Internet Reachable: {preflight.network.internet_reachable}")

    if preflight.status.value == "FAIL":
        print(f"      [!] Preflight failed: {preflight.errors}")
        return False

    # [2/7] Dynamic Session Started
    print("\n[2/7] Initializing Dynamic Session...")
    sessions_dir = "artifacts/dynamic/sessions"
    session_storage = SessionStorage(base_dir=sessions_dir)
    session_mgr = DynamicSessionManager(storage=session_storage)
    session = session_mgr.start_session(
        package_name=preflight.application.package_name,
        device_serial=preflight.device.serial,
        preflight_result=preflight,
    )
    print(f"      Session ID: {session.session_id} (Status: {session.status.value})")

    # [3/7] Target Flow Started
    print("\n[3/7] Starting Target Flow...")
    flow = session_mgr.start_flow("auth_verification", "Authentication and token verification flow")
    flow.add_marker("LOGIN_START")
    print(f"      Flow ID: {flow.flow_id} (Name: '{flow.name}')")
    print("      Marker 'LOGIN_START' registered.")

    # [4/7] Proxy Configured
    print("\n[4/7] Configuring Device Global Proxy...")
    traffic_backend = NativeProxyCaptureBackend()
    traffic_storage = TrafficStorage(base_dir=sessions_dir)
    traffic_svc = DynamicTrafficService(
        backend=traffic_backend,
        storage=traffic_storage,
    )

    # Check previous proxy on device
    code_prev, prev_proxy, _ = run_adb_cmd("adb", ["shell", "settings", "get", "global", "http_proxy"], serial=serial)
    print(f"      Previous Device Proxy: {prev_proxy.strip() or 'None'}")

    capture = traffic_svc.start_capture(
        session=session,
        device_serial=serial,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        in_scope_domains=["api.mobiattack-demo.local", "api.example-bank.com"],
    )
    print(f"      Capture Session ID: {capture.capture_id} (Status: {capture.status.value})")

    # Verify active proxy on device
    _, cur_proxy, _ = run_adb_cmd("adb", ["shell", "settings", "get", "global", "http_proxy"], serial=serial)
    print(f"      Active Device Proxy on Emulator: {cur_proxy.strip()}")

    # [5/7] Real HTTP Traffic Captured
    print("\n[5/7] Sending REAL HTTP Request from Android Emulator through Proxy...")
    # Send real HTTP request from inside emulator shell via toybox nc through the proxy port
    real_http_payload = (
        "POST http://api.mobiattack-demo.local/v1/auth/token HTTP/1.1\r\n"
        "Host: api.mobiattack-demo.local\r\n"
        "Content-Type: application/json\r\n"
        "Authorization: Bearer super_secret_prod_jwt_token_99999\r\n"
        "Content-Length: 70\r\n"
        "\r\n"
        '{"username":"suleyman@mobiattack.io","password":"SecretDemoPassword!"}'
    )
    nc_cmd = f"echo -e '{real_http_payload}' | toybox nc {proxy_host} {proxy_port}"
    code_nc, nc_stdout, nc_stderr = run_adb_cmd("adb", ["shell", nc_cmd], serial=serial)
    print(f"      Emulator Shell Exit Code: {code_nc}")
    resp_line = nc_stdout.splitlines()[0] if nc_stdout.splitlines() else "No response"
    print(f"      Emulator Received Response: {resp_line}")

    # Wait shortly for capture queue to flush
    time.sleep(0.5)

    # [6/7] Traffic Correlated
    print("\n[6/7] Correlating Captured Traffic with Flow & Markers...")
    captured_txs = traffic_svc.captured_transactions
    print(f"      Total Real Transactions Captured: {len(captured_txs)}")

    if not captured_txs:
        print("      [!] Error: No transactions captured!")
        traffic_svc.stop_capture()
        session_mgr.complete_session()
        return False

    tx = captured_txs[0]
    flow.record_action("verify_login_response", {"status": tx.response.status_code if tx.response else 0})
    flow.add_marker("LOGIN_SUCCESS")
    flow.complete()
    print("      Marker 'LOGIN_SUCCESS' registered.")
    print(f"      Flow '{flow.name}' marked COMPLETED.")

    # [7/7] Proxy Restored
    print("\n[7/7] Stopping Capture & Restoring Device Global Proxy...")
    summary = traffic_svc.stop_capture()
    session_mgr.complete_session()

    # Verify device proxy restored
    _, restored_proxy, _ = run_adb_cmd("adb", ["shell", "settings", "get", "global", "http_proxy"], serial=serial)
    is_restored_clean = restored_proxy.strip() in (prev_proxy.strip(), "null", ":0", "")
    print(f"      Post-Capture Device Proxy: {restored_proxy.strip() or 'Cleared (:0)'}")
    print(f"      Proxy Restored Successfully: {is_restored_clean}")

    # Display Required Demo Summary
    print("\n==================================================")
    print("===         MobiAttack Dynamic Demo            ===")
    print("==================================================")
    print(f"Device:\n  {serial}")
    print(f"Application:\n  {target_pkg}")
    print(f"Preflight:\n  {preflight.status.value}")
    print(f"Session:\n  {session.session_id}")
    print(f"Capture:\n  {capture.capture_id}")
    print("\nREAL HTTP TRANSACTION")
    print(f"Method:\n  {tx.request.method}")
    print(f"Host:\n  {tx.request.host}")
    print(f"Path:\n  {tx.request.path}")
    print(f"Status:\n  {tx.response.status_code if tx.response else 'N/A'}")
    print(f"Flow:\n  {tx.flow_id}")
    print(f"Marker Before:\n  {tx.correlation.get('nearest_marker_before', {}).get('name', 'None')}")
    print(f"Sensitive Data (Auth Header):\n  {tx.request.headers.get('authorization')}")
    print(f"Sensitive Data (JSON Password):\n  {tx.request.body.get('password') if isinstance(tx.request.body, dict) else '[REDACTED]'}")
    print(f"Scope:\n  {tx.scope}")
    print(f"Proxy Restored:\n  {'YES' if is_restored_clean else 'NO'}")
    print(f"\nArtifacts Directory:\n  {os.path.abspath(sessions_dir)}/{session.session_id}/")

    demo_pass = bool(captured_txs and is_restored_clean and tx.request.headers.get("authorization") == "[REDACTED]")
    print(f"\nDEMO RESULT:\n  {'PASS' if demo_pass else 'FAIL'}")
    print("==================================================")
    return demo_pass


if __name__ == "__main__":
    success = run_demo()
    sys.exit(0 if success else 1)
