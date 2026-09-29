"""Safe IPA Extraction Module for MobiAttack V2.

Safely unpacks iOS IPA archives, verifies structure, prevents Zip-Slip / path traversal,
and discovers application bundles without executing binaries or loading native libraries.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import zipfile

from src.platform_detector import detect_platform

DEFAULT_MAX_FILES: int = 50_000
DEFAULT_MAX_TOTAL_BYTES: int = 2 * 1024 * 1024 * 1024  # 2 GB


class IpaExtractionError(ValueError):
    """Raised when IPA extraction or structural validation fails."""
    pass


def _compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 digest of a file in streaming chunks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def extract_ipa(
    ipa_path: str | Path,
    output_dir: str | Path,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> dict:
    """Safely extracts an iOS IPA archive to the specified destination directory.

    Enforces strict security checks:
      - Validates that the archive is a structurally sound iOS package.
      - Rejects Zip-Slip / path traversal attempts (relative '..' and absolute paths).
      - Rejects symlink targets that escape the extraction root.
      - Enforces maximum file count and total extracted size limits (zip bomb protection).
      - Identifies the primary Payload/*.app bundle.

    Args:
        ipa_path: Path to the target .ipa file.
        output_dir: Destination directory where files will be unpacked.
        max_files: Ceiling on the total number of files extracted.
        max_total_bytes: Ceiling on the cumulative uncompressed size in bytes.

    Returns:
        Structured extraction metadata dictionary:
            ipa_path: Canonical path to input IPA.
            output_dir: Canonical path to output directory.
            app_bundle: Relative path to primary .app bundle (e.g. 'Payload/Test.app').
            app_bundle_dir: Canonical filesystem path to primary .app bundle directory.
            extracted_files: Count of extracted files/directories.
            total_extracted_bytes: Cumulative uncompressed size in bytes.
            sha256: SHA-256 of the input IPA.
            size_bytes: Size of the input IPA in bytes.
            has_info_plist: bool
            status: 'success'

    Raises:
        IpaExtractionError: If the archive is invalid, unsafe, or exceeds safety limits.
    """
    path = Path(ipa_path).resolve()
    if not path.is_file():
        raise IpaExtractionError(f"Target IPA file does not exist: '{ipa_path}'")

    # 1. Platform & Content Structural Detection
    detection = detect_platform(path)
    if detection.get("platform") != "ios" or not detection.get("valid"):
        reason = detection.get("reason", "Not a valid iOS IPA archive.")
        raise IpaExtractionError(f"IPA structural validation failed: {reason}")

    dest_dir = Path(output_dir).resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    file_size = path.stat().st_size
    file_sha256 = _compute_sha256(path)

    # 2. Iterate Archive Entries with Safety Audits
    total_uncompressed_bytes = 0
    extracted_entries_count = 0

    try:
        with zipfile.ZipFile(path, "r") as zf:
            infolist = zf.infolist()

            # Pre-audit all members before extracting
            for member in infolist:
                # Normalize filename
                norm_name = member.filename.replace("\\", "/")

                # Path traversal checks
                if norm_name.startswith("/") or norm_name.startswith("\\"):
                    raise IpaExtractionError(
                        f"Unsafe absolute path rejected in IPA: '{member.filename}'"
                    )

                # Check for path traversal components
                parts = norm_name.split("/")
                if ".." in parts:
                    raise IpaExtractionError(
                        f"Zip-slip path traversal attempt rejected: '{member.filename}'"
                    )

                # Destination boundary check
                target_path = (dest_dir / norm_name).resolve()
                try:
                    if not target_path.is_relative_to(dest_dir):
                        raise IpaExtractionError(
                            f"Target path escapes extraction root: '{member.filename}'"
                        )
                except AttributeError:
                    # Python < 3.9 fallback
                    if not str(target_path).startswith(str(dest_dir) + os.sep) and str(target_path) != str(dest_dir):
                        raise IpaExtractionError(
                            f"Target path escapes extraction root: '{member.filename}'"
                        )

                # Cumulative resource limits
                total_uncompressed_bytes += member.file_size
                if total_uncompressed_bytes > max_total_bytes:
                    raise IpaExtractionError(
                        f"IPA exceeds maximum allowed uncompressed size: {total_uncompressed_bytes} > {max_total_bytes} bytes"
                    )

            if len(infolist) > max_files:
                raise IpaExtractionError(
                    f"IPA exceeds maximum allowed file count: {len(infolist)} > {max_files}"
                )

            # 3. Safe Extraction
            for member in infolist:
                norm_name = member.filename.replace("\\", "/")
                target_path = (dest_dir / norm_name).resolve()

                # Check if entry is a symlink
                is_symlink = (member.external_attr >> 16) & stat.S_IFLNK == stat.S_IFLNK

                if member.is_dir() or norm_name.endswith("/"):
                    target_path.mkdir(parents=True, exist_ok=True)
                    extracted_entries_count += 1
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)

                if is_symlink:
                    # Read link destination and audit that it does not escape extraction root
                    link_target_bytes = zf.read(member)
                    try:
                        link_target_str = link_target_bytes.decode("utf-8", errors="replace")
                    except Exception:
                        continue

                    resolved_link_dest = (target_path.parent / link_target_str).resolve()
                    try:
                        if not resolved_link_dest.is_relative_to(dest_dir):
                            # Unsafe symlink target escapes dest_dir - skip or reject
                            raise IpaExtractionError(
                                f"Symlink target escapes extraction root: '{member.filename}' -> '{link_target_str}'"
                            )
                    except AttributeError:
                        if not str(resolved_link_dest).startswith(str(dest_dir) + os.sep):
                            raise IpaExtractionError(
                                f"Symlink target escapes extraction root: '{member.filename}' -> '{link_target_str}'"
                            )

                    # Create safe symlink or write as regular file if filesystem supports
                    if target_path.is_symlink() or target_path.exists():
                        target_path.unlink()
                    try:
                        os.symlink(link_target_str, target_path)
                    except OSError:
                        # Fallback for environments without symlink privileges: write link path text
                        with open(target_path, "w", encoding="utf-8") as f:
                            f.write(link_target_str)
                else:
                    # Extract regular file safely
                    with zf.open(member, "r") as src, open(target_path, "wb") as dst:
                        while chunk := src.read(65536):
                            dst.write(chunk)

                extracted_entries_count += 1

    except zipfile.BadZipFile as exc:
        raise IpaExtractionError(f"Corrupt IPA ZIP archive: {exc}") from exc
    except (IpaExtractionError, ValueError):
        raise
    except Exception as exc:
        raise IpaExtractionError(f"Failed to extract IPA: {exc}") from exc

    # 4. Resolve Primary App Bundle
    app_bundle_rel = detection.get("app_bundle")
    if not app_bundle_rel:
        raise IpaExtractionError("Could not resolve primary application bundle in extracted IPA.")

    app_bundle_dir = (dest_dir / app_bundle_rel).resolve()
    if not app_bundle_dir.is_dir():
        raise IpaExtractionError(f"Extracted app bundle directory missing: '{app_bundle_dir}'")

    has_info_plist = (app_bundle_dir / "Info.plist").is_file()

    return {
        "ipa_path": str(path),
        "output_dir": str(dest_dir),
        "app_bundle": app_bundle_rel,
        "app_bundle_dir": str(app_bundle_dir),
        "extracted_files": extracted_entries_count,
        "total_extracted_bytes": total_uncompressed_bytes,
        "sha256": file_sha256,
        "size_bytes": file_size,
        "has_info_plist": has_info_plist,
        "status": "success",
    }
