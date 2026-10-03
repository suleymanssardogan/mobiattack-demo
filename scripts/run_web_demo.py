#!/usr/bin/env python3
"""CLI runner to launch the MobiAttack-v1 Local Web Demo Dashboard."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time
import webbrowser

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.system_env import ensure_system_paths
ensure_system_paths()

from src.demo_web_server import DemoWebServer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Launch MobiAttack-v1 Local Web Demo Dashboard",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host address to bind the web server (defaults to loopback for security)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Local port to bind the web server",
    )
    parser.add_argument(
        "--runs-dir",
        default="demo_runs",
        help="Directory where individual demo runs and workspaces are isolated",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Automatically open the web dashboard in default system browser",
    )
    parser.add_argument("--traffic-proxy-port", type=int, default=18080, help="Dynamic traffic capture port")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    server = DemoWebServer(
        host=args.host,
        port=args.port,
        runs_root=args.runs_dir,
        traffic_proxy_port=args.traffic_proxy_port,
    )

    try:
        server.start()
    except Exception as err:
        print(f"Failed to start web server on {args.host}:{args.port}: {err}", file=sys.stderr)
        return 1

    dashboard_url = server.base_url
    print("\n" + "=" * 60)
    print("MobiAttack demo dashboard:")
    print(f"{dashboard_url}")
    print("=" * 60)
    print("Serving live interactive dashboard. Press Ctrl+C to stop.\n")

    if args.open_browser:
        try:
            webbrowser.open(dashboard_url)
        except Exception:
            pass

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nShutting down MobiAttack demo dashboard...")
    finally:
        server.stop()
        print("Server stopped cleanly.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
