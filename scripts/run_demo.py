#!/usr/bin/env python3
"""Command-line interface entry point for MobiAttack-v1 Demo Orchestration.

Thin wrapper delegating directly to src.demo_orchestrator.run_demo.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add project root to sys.path so scripts can run directly
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.demo_orchestrator import DemoOrchestrationError, format_demo_summary, run_demo


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MobiAttack-v1 End-to-End Mobile Application Security Demo Orchestrator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Direct or redirected HTTP/HTTPS download URL for target Android APK",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Target output directory for downloads and processing workspaces",
    )
    parser.add_argument(
        "--adb-serial",
        default=None,
        help="Explicit Android device/emulator serial (auto-selects if single device attached)",
    )
    parser.add_argument(
        "--reinstall",
        action="store_true",
        help="Instruct ADB to reinstall existing application package with -r",
    )
    parser.add_argument(
        "--grant-permissions",
        action="store_true",
        help="Instruct ADB to grant all runtime permissions during install with -g",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print concise human-readable summary instead of raw JSON",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="Subprocess timeout ceiling in seconds for preprocessing and ADB",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = run_demo(
            url=args.url,
            output_root=args.output,
            adb_serial=args.adb_serial,
            reinstall=args.reinstall,
            grant_permissions=args.grant_permissions,
            timeout_seconds=args.timeout,
        )

        if args.summary:
            print(format_demo_summary(result))
        else:
            print(json.dumps(result, indent=2))

        return 0

    except DemoOrchestrationError as err:
        print(f"\n[DEMO FAILED] Stage: {err.stage}", file=sys.stderr)
        print(f"Cause: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"\n[UNEXPECTED ERROR] {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
