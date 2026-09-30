"""Live demonstration script for Dynamic Proxy Readiness & Traffic Capture."""

from __future__ import annotations

import json
import os
import sys

# Ensure repository root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.dynamic.session.manager import DynamicSessionManager
from src.dynamic.session.models import utc_now_iso
from src.dynamic.session.storage import SessionStorage
from src.dynamic.traffic.capture_backend import TrafficCaptureBackend
from src.dynamic.traffic.models import TrafficTransaction
from src.dynamic.traffic.service import DynamicTrafficService
from src.dynamic.traffic.storage import TrafficStorage


class SimulatedCaptureBackend:
    """Mock/Simulated capture backend that generates realistic traffic streams without mitmproxy binary."""

    def __init__(self) -> None:
        self.running = False
        self.transactions: list[TrafficTransaction] = []

    def check_available(self) -> bool:
        return True

    def start(self, listen_host: str, listen_port: int, on_transaction_captured=None) -> None:
        self.running = True

    def stop(self, timeout_seconds: float = 5.0) -> None:
        self.running = False

    def is_alive(self) -> bool:
        return self.running

    def get_captured_transactions(self) -> list[TrafficTransaction]:
        return self.transactions


def main() -> None:
    print("=== MobiAttack-v2: Dynamic Proxy Readiness & Traffic Capture Demo ===")

    # 1. Initialize Dynamic Session Manager & Traffic Service
    session_storage = SessionStorage(base_dir="artifacts/dynamic/sessions")
    session_mgr = DynamicSessionManager(storage=session_storage)
    session = session_mgr.start_session(
        package_name="com.example.bank",
        device_serial="emulator-5554",
    )
    print(f"[+] Dynamic Session Started: {session.session_id}")

    # 2. Check Proxy Readiness
    backend = SimulatedCaptureBackend()
    traffic_storage = TrafficStorage(base_dir="artifacts/dynamic/sessions")
    traffic_service = DynamicTrafficService(backend=backend, storage=traffic_storage)

    readiness = traffic_service.check_readiness(device_serial="emulator-5554")
    print(f"[+] Proxy Readiness Check: {readiness.status.value}")
    print(f"    - Proxy Host: {readiness.proxy_host}:{readiness.proxy_port}")
    print(f"    - Device Reachable: {readiness.device_reachable_proxy}")
    print(f"    - Warnings: {readiness.warnings}")

    # 3. Start Flow 1 & Traffic Capture
    login_flow = session_mgr.start_flow("login", "User authentication flow")
    login_flow.add_marker("LOGIN_START")

    capture = traffic_service.start_capture(
        session=session,
        device_serial="emulator-5554",
        in_scope_domains=["api.example-bank.com"],
    )
    print(f"[+] Traffic Capture Started: {capture.capture_id} (Status: {capture.status.value})")

    # 4. Simulate App HTTP Traffic
    print("[+] Simulating App HTTP Traffic...")
    now_ts = utc_now_iso()
    tx1 = traffic_service.record_raw_transaction(
        raw_req={
            "timestamp": now_ts,
            "method": "POST",
            "url": "https://api.example-bank.com/v1/auth/login",
            "headers": {
                "Host": "api.example-bank.com",
                "Content-Type": "application/json",
                "Authorization": "Bearer super_secret_user_token_12345",
            },
            "body": json.dumps({
                "email": "user@example-bank.com",
                "password": "ClearTextPassword456!",
                "device_id": "android_uuid_999",
            }),
        },
        raw_resp={
            "timestamp": now_ts,
            "status_code": 200,
            "headers": {
                "Content-Type": "application/json",
                "Set-Cookie": "session_id=abcdef123456789; Secure; HttpOnly",
            },
            "body": json.dumps({"status": "success", "user_id": 42}),
        },
        duration_ms=124.5,
    )
    print(f"    -> Transaction 1: {tx1.request.method} {tx1.request.host}{tx1.request.path} (Status: {tx1.response.status_code})")
    print(f"       Correlated Flow: {tx1.flow_id}")
    print(f"       Nearest Marker Before: {tx1.correlation.get('nearest_marker_before')}")
    print(f"       Scope: {tx1.scope}")
    print(f"       Redacted Auth Header: {tx1.request.headers.get('authorization')}")
    print(f"       Redacted Password: {tx1.request.body.get('password')}")

    login_flow.add_marker("LOGIN_SUCCESS")
    login_flow.complete()

    # 5. Stop Capture & Complete Session
    summary = traffic_service.stop_capture()
    session_mgr.complete_session()

    print("\n--- Capture Summary ---")
    print(json.dumps(summary.to_dict(), indent=2, ensure_ascii=False))

    print("\n--- Normalized Transaction Artifact (Sample) ---")
    print(json.dumps(tx1.to_dict(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
