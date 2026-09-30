"""Demonstration script for MobiAttack-v2 Dynamic Session Manager & Target Flow Recording."""

from __future__ import annotations

import json
import os
import sys

# Ensure repository root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.dynamic.preflight.models import (
    ApplicationInfo,
    DeviceInfo,
    NetworkInfo,
    PreflightResult,
    PreflightStatus,
    RuntimeBaseline,
)
from src.dynamic.session.manager import DynamicSessionManager
from src.dynamic.session.storage import SessionStorage


def main() -> None:
    print("=== MobiAttack-v2: Dynamic Session & Target Flow Demo ===")

    # 1. Simulate a verified preflight result with emulator warning
    preflight = PreflightResult(
        stage="dynamic_preflight",
        device=DeviceInfo(
            connected=True,
            serial="emulator-5554",
            state="device",
            is_emulator=True,
        ),
        application=ApplicationInfo(
            package_name="com.example.banking",
            installed=True,
            launchable=True,
            main_activity="com.example.banking.MainActivity",
        ),
        runtime=RuntimeBaseline(
            launch_success=True,
            pid=4812,
        ),
        network=NetworkInfo(
            internet_reachable=True,
            dns_configured=True,
        ),
        status=PreflightStatus.WARN,
        warnings=["Android Emulator environment detected."],
    )

    # 2. Initialize Session Manager with local demo storage
    storage = SessionStorage(base_dir="artifacts/dynamic/sessions")
    manager = DynamicSessionManager(storage=storage)

    # 3. Start Session
    session = manager.start_session(
        package_name="com.example.banking",
        device_serial="emulator-5554",
        preflight_result=preflight,
    )
    print(f"[+] Started Dynamic Session: {session.session_id} (Status: {session.status.value})")

    # 4. Target Flow 1: User Authentication
    login_flow = manager.start_flow(name="login", description="User authentication and token acquisition")
    print(f"[+] Started Flow: '{login_flow.name}' ({login_flow.flow_id})")

    login_flow.add_marker("LOGIN_START")
    login_flow.record_action("tap_email_field", {"input_id": "txt_email"})
    login_flow.record_action(
        "enter_credentials",
        {
            "username": "tester@example.com",
            "password": "SuperSecretPassword123!",  # Automatically redacted!
            "auth_token": "Bearer sample_token_secret",  # Automatically redacted!
        },
    )
    login_flow.record_note("Login form filled with test account")
    login_flow.add_marker("LOGIN_SUBMIT")
    login_flow.record_action("tap_login_button")
    login_flow.add_marker("LOGIN_SUCCESS")
    login_flow.complete()
    print(f"[+] Flow '{login_flow.name}' completed with {len(login_flow.flow.events)} events.")

    # 5. Target Flow 2: Money Transfer
    transfer_flow = manager.start_flow(name="money_transfer", description="Quick funds transfer")
    print(f"[+] Started Flow: '{transfer_flow.name}' ({transfer_flow.flow_id})")
    transfer_flow.add_marker("TRANSFER_START")
    transfer_flow.record_action("select_recipient", {"recipient_account": "ACC-98765"})
    transfer_flow.record_action("enter_amount", {"amount": 250.0, "currency": "TRY"})
    transfer_flow.add_marker("TRANSFER_SUBMIT")
    transfer_flow.record_action("tap_confirm_transfer")
    transfer_flow.add_marker("TRANSFER_SUCCESS")
    transfer_flow.complete()
    print(f"[+] Flow '{transfer_flow.name}' completed.")

    # 6. Complete Session
    manager.complete_session()
    print(f"[+] Session '{session.session_id}' completed successfully.")

    # 7. Print Normalized Session Output
    print("\n--- Normalized Session Output (session.json) ---")
    print(json.dumps(session.to_dict(), indent=2, ensure_ascii=False))

    # 8. Print Chronological Timeline
    print("\n--- Chronological Timeline (timeline.json) ---")
    timeline = manager.get_timeline()
    print(json.dumps(timeline, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
