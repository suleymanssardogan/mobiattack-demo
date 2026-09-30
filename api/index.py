import os
import sys
from pathlib import Path

# Add project root directory to sys.path so modules like src.demo_web_server are importable
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Ensure writable temporary directory and declare serverless environment
os.environ.setdefault("DEMO_RUNS_DIR", "/tmp/demo_runs")
os.environ.setdefault("VERCEL", "1")

from src.system_env import ensure_system_paths
ensure_system_paths()

from src.demo_web_server import DemoWebServer, _DemoRequestHandler

# Initialize singleton web server instance for serverless environment
_server_instance = DemoWebServer(host="0.0.0.0", port=8080, runs_root=os.environ["DEMO_RUNS_DIR"])
_DemoRequestHandler._global_web_server = _server_instance


class handler(_DemoRequestHandler):
    """Vercel Serverless Function entry point."""
    pass
