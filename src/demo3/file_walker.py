"""Deterministic File Walker with explicit accounting and error isolation for Demo 3."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Generator

from src.demo3.candidate_model import ScanStatistics

# Supported textual extensions for candidate extraction
SUPPORTED_EXTENSIONS = {
    ".xml",
    ".smali",
    ".json",
    ".properties",
    ".txt",
    ".js",
    ".html",
    ".htm",
    ".java",
    ".kt",
    ".yaml",
    ".yml",
    ".conf",
    ".ini",
    ".strings",
}

# Obvious binary / media assets to safely skip
EXCLUDED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".mp3",
    ".mp4",
    ".ogg",
    ".wav",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".eot",
    ".dex",
    ".arsc",
    ".so",
    ".dylib",
    ".a",
    ".bin",
    ".dat",
    ".jar",
    ".class",
    ".zip",
    ".apk",
    ".ipa",
}


def deterministic_walk(
    root_dir: str | Path,
    stats: ScanStatistics | None = None,
) -> Generator[tuple[Path, str], None, None]:
    """Recursively yields (file_path, relative_posix_path) in strictly deterministic order.

    Updates `stats` (ScanStatistics) with discovered, analyzed, skipped, and failed files.
    """
    root_path = Path(root_dir).resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Root path does not exist: {root_dir}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Root path is not a directory: {root_dir}")

    # Gather all file paths deterministically
    all_files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames.sort()  # deterministic directory ordering
        for fn in sorted(filenames):
            all_files.append(Path(dirpath) / fn)

    all_files.sort(key=lambda p: p.relative_to(root_path).as_posix())

    for fpath in all_files:
        if stats:
            stats.files_discovered += 1

        rel_path = fpath.relative_to(root_path).as_posix()
        ext = fpath.suffix.lower()

        # Apktool keeps the original binary manifest beside the decoded text
        # manifest. It is expected binary input, not a failed text scan.
        if rel_path == "original/AndroidManifest.xml":
            if stats:
                stats.files_skipped += 1
            continue

        # Check explicit exclusions or non-supported types
        if ext in EXCLUDED_EXTENSIONS or (ext not in SUPPORTED_EXTENSIONS and not fpath.name.lower().endswith("manifest.xml")):
            if stats:
                stats.files_skipped += 1
            continue

        # Test readability and encoding
        try:
            with fpath.open("r", encoding="utf-8") as f:
                # Read sample to ensure valid UTF-8
                f.read(8192)
        except (UnicodeDecodeError, OSError) as exc:
            if stats:
                stats.files_failed += 1
                stats.failed_files.append({
                    "file": rel_path,
                    "reason": f"Encoding/read error: {type(exc).__name__}",
                })
            continue

        if stats:
            stats.files_analyzed += 1

        yield fpath, rel_path
