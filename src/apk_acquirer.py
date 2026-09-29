"""URL to APK Acquisition Module for MobiAttack-v1.

Fetches Android APK packages from HTTP/HTTPS URLs, follows redirects,
enforces safety and size limits, determines sanitized filenames, performs
structural validation (ZIP + AndroidManifest.xml + classes*.dex), computes SHA-256,
and outputs deterministic acquisition metadata.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

# Strict Android DEX pattern: classes.dex, classes2.dex, classes3.dex, etc.
# Secondary DEX numbering strictly starts at 2 (rejects classes0.dex, classes1.dex).
STRICT_DEX_PATTERN = re.compile(r"^classes([2-9]\d*)?\.dex$")

# Default acquisition limits
DEFAULT_TIMEOUT_SECONDS: float = 30.0
DEFAULT_MAX_SIZE_BYTES: int = 2 * 1024 * 1024 * 1024  # 2 GB


class ApkAcquisitionError(ValueError):
    """Raised when URL acquisition, HTTP request, or structural validation fails."""
    pass


class SchemeRestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that validates each redirect destination scheme."""

    def http_error_302(self, req, fp, code, msg, headers):
        location = headers.get("location") or headers.get("uri")
        if location:
            target = urllib.parse.urljoin(req.full_url, location)
            scheme = urllib.parse.urlparse(target).scheme.lower()
            if scheme not in ("http", "https"):
                raise ApkAcquisitionError(
                    f"Redirect to unsupported scheme rejected: '{scheme}' (target: '{target}')"
                )
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ApkAcquisitionError(
                f"Redirect to unsupported scheme rejected: '{scheme}' (target: '{newurl}')"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _dex_sort_key(name: str) -> tuple[int, int]:
    """Deterministic sort key for DEX files: classes.dex first, then classes2, classes3..."""
    m = STRICT_DEX_PATTERN.match(name)
    if not m:
        return (2, 0)
    suffix = m.group(1)
    if suffix is None:
        return (0, 1)
    return (1, int(suffix))


def validate_apk_structure(file_path: str | Path) -> dict:
    """Structurally validates whether a file is an Android APK package.

    Checks:
      1. Is a valid, readable ZIP archive.
      2. Contains root-level 'AndroidManifest.xml'.
      3. Contains at least one convention-compliant DEX file (classes.dex, classes2.dex...).

    Returns deterministic validation facts dictionary.
    """
    path = Path(file_path)
    if not path.is_file():
        return {
            "is_zip": False,
            "has_android_manifest": False,
            "dex_files": [],
            "has_dex": False,
            "is_valid_apk": False,
        }

    if not zipfile.is_zipfile(path):
        return {
            "is_zip": False,
            "has_android_manifest": False,
            "dex_files": [],
            "has_dex": False,
            "is_valid_apk": False,
        }

    try:
        with zipfile.ZipFile(path, "r") as zip_ref:
            namelist = zip_ref.namelist()
            has_manifest = "AndroidManifest.xml" in namelist
            dex_files = [
                name for name in namelist
                if STRICT_DEX_PATTERN.match(name)
            ]
            dex_files.sort(key=_dex_sort_key)
            has_dex = len(dex_files) > 0
            is_valid = bool(has_manifest and has_dex)

            return {
                "is_zip": True,
                "has_android_manifest": has_manifest,
                "dex_files": dex_files,
                "has_dex": has_dex,
                "is_valid_apk": is_valid,
            }
    except (zipfile.BadZipFile, OSError):
        return {
            "is_zip": False,
            "has_android_manifest": False,
            "dex_files": [],
            "has_dex": False,
            "is_valid_apk": False,
        }


def extract_filename_from_content_disposition(header_value: str | None) -> str | None:
    """Safely extracts candidate filename from Content-Disposition header.

    Supports standard filename= and RFC 5987 / RFC 6266 filename*= directives.
    """
    if not header_value:
        return None

    # Check for RFC 5987 / 6266 filename*= (e.g., filename*=UTF-8''app-release.apk)
    star_match = re.search(
        r'''filename\*\s*=\s*(?:[A-Za-z0-9_-]+'[^']*')?([^;]+)''',
        header_value,
        re.IGNORECASE,
    )
    if star_match:
        val = star_match.group(1).strip().strip('"\'')
        return urllib.parse.unquote(val)

    # Check for standard filename="name" or filename=name
    std_match = re.search(
        r'''filename\s*=\s*(?:"([^"]+)"|([^;\s]+))''',
        header_value,
        re.IGNORECASE,
    )
    if std_match:
        return std_match.group(1) if std_match.group(1) is not None else std_match.group(2)

    return None


def sanitize_filename(candidate: str | None, fallback: str = "downloaded_package") -> str:
    """Sanitizes an untrusted candidate filename.

    Strips directory traversals (../, ..\\), null bytes, control characters,
    path separators, and reserved symbols. Does not append .apk extension here;
    that is strictly applied only after structural validation.
    """
    if not candidate:
        return fallback

    # Strip null bytes and control characters
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", str(candidate))

    # Standardize backslashes and strip directory components
    cleaned = cleaned.replace("\\", "/")
    cleaned = cleaned.split("/")[-1].strip()

    # Strip leading dots and traversal artifacts
    cleaned = re.sub(r"^\.+", "", cleaned).strip()

    # Replace forbidden path characters
    cleaned = re.sub(r'[<>:"/\\|?*]', "_", cleaned).strip()

    # If nothing remains, use fallback
    if not cleaned:
        return fallback

    return cleaned


def acquire_apk(
    url: str,
    output_dir: str | Path,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_size_bytes: int = DEFAULT_MAX_SIZE_BYTES,
) -> dict:
    """Safely downloads and validates an Android APK from an HTTP(S) URL.

    Args:
        url: User-provided HTTP or HTTPS URL.
        output_dir: Destination directory to store the validated APK.
        timeout: Network timeout in seconds (default 30.0s).
        max_size_bytes: Maximum allowed download size in bytes (default 2GB).

    Returns:
        Deterministic acquisition metadata dictionary.

    Raises:
        ApkAcquisitionError: On unsupported schemes, connection errors, HTTP errors,
                             redirect violations, size limit violations, existing file collisions,
                             or structural validation failures.
    """
    if not isinstance(url, str) or not url.strip():
        raise ApkAcquisitionError("URL must be a non-empty string.")

    cleaned_url = url.strip()
    parsed = urllib.parse.urlparse(cleaned_url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ApkAcquisitionError(
            f"Unsupported URL scheme: '{parsed.scheme}'. Only http:// and https:// are supported."
        )
    if not parsed.netloc:
        raise ApkAcquisitionError(f"Malformed URL missing host: '{cleaned_url}'")

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Prepare temporary file in destination directory
    temp_file = tempfile.NamedTemporaryFile(
        dir=out_path,
        delete=False,
        prefix=".tmp_acq_",
    )
    temp_path = Path(temp_file.name)
    temp_file.close()

    try:
        req = urllib.request.Request(
            cleaned_url,
            headers={"User-Agent": "MobiAttack-Acquirer/1.0"},
        )
        opener = urllib.request.build_opener(SchemeRestrictedRedirectHandler())

        try:
            response = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as err:
            raise ApkAcquisitionError(f"HTTP request failed with status {err.code}: {err.reason}") from err
        except urllib.error.URLError as err:
            raise ApkAcquisitionError(f"Network error connecting to '{cleaned_url}': {err.reason}") from err
        except (TimeoutError, OSError) as err:
            raise ApkAcquisitionError(f"Connection timed out or failed: {err}") from err

        with response:
            final_url = response.geturl()
            final_parsed = urllib.parse.urlparse(final_url)
            final_scheme = final_parsed.scheme.lower()
            if final_scheme not in ("http", "https"):
                raise ApkAcquisitionError(
                    f"Final redirected URL has unsupported scheme: '{final_scheme}' (url: '{final_url}')"
                )

            status_code = getattr(response, "status", None) or response.getcode()
            if status_code != 200:
                raise ApkAcquisitionError(f"Expected HTTP status 200, received: {status_code}")

            content_type = response.headers.get("Content-Type", "")

            # Check Content-Length if available
            content_length_hdr = response.headers.get("Content-Length")
            if content_length_hdr:
                content_length = None
                try:
                    content_length = int(content_length_hdr)
                except (ValueError, TypeError):
                    pass
                if content_length is not None and content_length > max_size_bytes:
                    raise ApkAcquisitionError(
                        f"Content-Length ({content_length} bytes) exceeds maximum limit "
                        f"of {max_size_bytes} bytes."
                    )

            # Stream chunks to temp file while updating SHA-256 and tracking size
            hasher = hashlib.sha256()
            size_bytes = 0
            chunk_size = 65536  # 64 KB

            with open(temp_path, "wb") as f_out:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    size_bytes += len(chunk)
                    if size_bytes > max_size_bytes:
                        raise ApkAcquisitionError(
                            f"Downloaded data exceeded maximum limit of {max_size_bytes} bytes."
                        )
                    hasher.update(chunk)
                    f_out.write(chunk)

            # Perform structural APK validation on downloaded content
            validation = validate_apk_structure(temp_path)
            if not validation["is_valid_apk"]:
                reasons = []
                if not validation["is_zip"]:
                    reasons.append("file is not a valid ZIP archive")
                if not validation["has_android_manifest"]:
                    reasons.append("archive missing AndroidManifest.xml")
                if not validation["has_dex"]:
                    reasons.append("archive missing valid convention-compliant classes*.dex")
                reason_str = ", ".join(reasons) if reasons else "structural validation failed"
                raise ApkAcquisitionError(f"Downloaded content is not a valid Android APK: {reason_str}")

            # Candidate filename determination:
            # 1. Content-Disposition header
            # 2. Basename of final URL path
            # 3. Fallback: "downloaded_package"
            cd_hdr = response.headers.get("Content-Disposition")
            candidate_name = extract_filename_from_content_disposition(cd_hdr)
            if not candidate_name:
                url_path = urllib.parse.unquote(final_parsed.path)
                candidate_name = os.path.basename(url_path.rstrip("/"))

            safe_name = sanitize_filename(candidate_name, fallback="downloaded_package")

            # Apply .apk extension ONLY after structural validation succeeds
            if not safe_name.lower().endswith(".apk"):
                safe_name = f"{safe_name}.apk"

            # Check for existing destination file collision (do not overwrite silently)
            final_path = out_path / safe_name
            if final_path.exists():
                raise ApkAcquisitionError(
                    f"Destination file already exists: '{final_path.name}'. Silently overwriting is prohibited."
                )

            # Atomically move temporary file to final path
            os.replace(temp_path, final_path)
            temp_path = None  # Signal that temp file was safely relocated

            # Determine clean saved_path
            try:
                saved_path = final_path.relative_to(Path.cwd()).as_posix()
            except ValueError:
                saved_path = final_path.as_posix()

            redirected = bool(cleaned_url != final_url)
            return {
                "input_url": cleaned_url,
                "requested_url": cleaned_url,
                "final_url": final_url,
                "redirected": redirected,
                "status_code": status_code,
                "content_type": content_type,
                "content_disposition": cd_hdr,
                "http": {
                    "status_code": status_code,
                    "content_type": content_type,
                    "content_disposition": cd_hdr,
                },
                "filename": safe_name,
                "saved_path": saved_path,
                "size_bytes": size_bytes,
                "sha256": hasher.hexdigest(),
                "package_type": "apk",
                "validation": validation,
            }

    finally:
        # Clean up temporary file if it was not atomically moved
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
