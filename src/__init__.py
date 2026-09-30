"""MobiAttack-v1 Core Package."""

from src.system_env import ensure_system_paths

ensure_system_paths()

from src.manifest_parser import parse_manifest

__all__ = ["parse_manifest", "ensure_system_paths"]

