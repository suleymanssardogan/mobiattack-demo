"""Unit and integration tests for URL to APK Acquisition module."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import io
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.parse
import zipfile

from src.apk_acquirer import (
    ApkAcquisitionError,
    acquire_apk,
    extract_filename_from_content_disposition,
    sanitize_filename,
    validate_apk_structure,
)


def make_test_apk_bytes(
    dex_names: list[str] | None = None,
    include_manifest: bool = True,
    extra_files: dict[str, bytes] | None = None,
) -> bytes:
    """Creates an in-memory ZIP archive representing an APK."""
    if dex_names is None:
        dex_names = ["classes.dex"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        if include_manifest:
            zf.writestr("AndroidManifest.xml", b"<manifest></manifest>")
        for dex in dex_names:
            zf.writestr(dex, b"dex_dummy_data")
        if extra_files:
            for fname, fdata in extra_files.items():
                zf.writestr(fname, fdata)
    return buf.getvalue()


class MockHttpHandler(BaseHTTPRequestHandler):
    """Local HTTP mock server for acquisition tests."""

    def log_message(self, format, *args):
        # Suppress standard HTTP server console logging during tests
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/valid.apk":
            apk_bytes = make_test_apk_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.android.package-archive")
            self.send_header("Content-Length", str(len(apk_bytes)))
            self.end_headers()
            self.wfile.write(apk_bytes)

        elif path == "/custom_name_in_header":
            apk_bytes = make_test_apk_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="from_header.apk"')
            self.send_header("Content-Length", str(len(apk_bytes)))
            self.end_headers()
            self.wfile.write(apk_bytes)

        elif path == "/rfc5987_header":
            apk_bytes = make_test_apk_bytes()
            self.send_response(200)
            self.send_header("Content-Disposition", "attachment; filename*=UTF-8''special%20app.apk")
            self.send_header("Content-Length", str(len(apk_bytes)))
            self.end_headers()
            self.wfile.write(apk_bytes)

        elif path == "/traversal_header":
            apk_bytes = make_test_apk_bytes()
            self.send_response(200)
            self.send_header("Content-Disposition", 'attachment; filename="../../traversal_app.apk"')
            self.send_header("Content-Length", str(len(apk_bytes)))
            self.end_headers()
            self.wfile.write(apk_bytes)

        elif path == "/no_extension":
            apk_bytes = make_test_apk_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(apk_bytes)))
            self.end_headers()
            self.wfile.write(apk_bytes)

        elif path == "/redirect_302":
            self.send_response(302)
            self.send_header("Location", "/valid.apk")
            self.end_headers()

        elif path == "/redirect_301_to_custom":
            self.send_response(301)
            self.send_header("Location", "/custom_name_in_header")
            self.end_headers()

        elif path == "/redirect_unsupported_scheme":
            self.send_response(302)
            self.send_header("Location", "file:///etc/passwd")
            self.end_headers()

        elif path == "/not_found":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

        elif path == "/server_error":
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"500 Internal Error")

        elif path == "/fake_html.apk":
            html_content = b"<html><body>This is an HTML page disguised as APK</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(html_content)))
            self.end_headers()
            self.wfile.write(html_content)

        elif path == "/zip_no_manifest.apk":
            zip_bytes = make_test_apk_bytes(include_manifest=False)
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(zip_bytes)))
            self.end_headers()
            self.wfile.write(zip_bytes)

        elif path == "/zip_no_dex.apk":
            zip_bytes = make_test_apk_bytes(dex_names=[])
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(zip_bytes)))
            self.end_headers()
            self.wfile.write(zip_bytes)

        elif path == "/large_content_length.apk":
            self.send_response(200)
            # Lie about Content-Length > 1MB
            self.send_header("Content-Length", "10000000")
            self.end_headers()
            self.wfile.write(b"header_oversize")

        elif path == "/stream_oversize.apk":
            self.send_response(200)
            self.end_headers()
            # Stream 256KB without Content-Length
            self.wfile.write(b"A" * (256 * 1024))

        elif path == "/incorrect_content_type_valid_apk":
            apk_bytes = make_test_apk_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(apk_bytes)))
            self.end_headers()
            self.wfile.write(apk_bytes)

        elif path == "/apk_content_type_invalid_body":
            bad_bytes = b"NOT_A_REAL_APK_CORRUPT_BYTES_XYZ"
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.android.package-archive")
            self.send_header("Content-Length", str(len(bad_bytes)))
            self.end_headers()
            self.wfile.write(bad_bytes)

        else:
            self.send_response(404)
            self.end_headers()


class TestApkAcquisitionUnit(unittest.TestCase):
    """Unit tests for URL validation, filename sanitization, structural validation, and local HTTP."""

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockHttpHandler)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2.0)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    # --- 1. URL Scheme & Syntax Validation Tests ---

    def test_01_rejects_unsupported_schemes(self):
        unsupported = [
            "file:///path/to/app.apk",
            "ftp://example.com/app.apk",
            "data:application/zip;base64,AAA",
            "javascript:alert(1)",
        ]
        for url in unsupported:
            with self.subTest(url=url):
                with self.assertRaises(ApkAcquisitionError) as ctx:
                    acquire_apk(url, self.output_dir)
                self.assertIn("Unsupported URL scheme", str(ctx.exception))

    def test_02_rejects_malformed_urls(self):
        malformed = [
            "",
            "   ",
            "http://",
            "https://",
            "not_a_url",
        ]
        for url in malformed:
            with self.subTest(url=url):
                with self.assertRaises(ApkAcquisitionError):
                    acquire_apk(url, self.output_dir)

    # --- 2. Filename Sanitization & Header Parsing ---

    def test_03_content_disposition_standard_filename(self):
        header = 'attachment; filename="my_sample_app.apk"'
        extracted = extract_filename_from_content_disposition(header)
        self.assertEqual(extracted, "my_sample_app.apk")

    def test_04_content_disposition_unquoted_filename(self):
        header = "attachment; filename=my_sample_app.apk"
        extracted = extract_filename_from_content_disposition(header)
        self.assertEqual(extracted, "my_sample_app.apk")

    def test_05_content_disposition_rfc5987_filename(self):
        header = "attachment; filename*=UTF-8''encoded%20app%20name.apk"
        extracted = extract_filename_from_content_disposition(header)
        self.assertEqual(extracted, "encoded app name.apk")

    def test_06_filename_path_traversal_sanitization(self):
        dangerous = [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\cmd.exe",
            "/absolute/path/file.apk",
            "C:\\Users\\test\\app.apk",
            "....//malicious.apk",
            "\x00hidden.apk",
        ]
        for name in dangerous:
            with self.subTest(name=name):
                sanitized = sanitize_filename(name)
                self.assertNotIn("/", sanitized)
                self.assertNotIn("\\", sanitized)
                self.assertNotIn("..", sanitized)
                self.assertNotIn("\x00", sanitized)

    def test_07_fallback_filename_on_empty(self):
        self.assertEqual(sanitize_filename(None), "downloaded_package")
        self.assertEqual(sanitize_filename(""), "downloaded_package")
        self.assertEqual(sanitize_filename("   "), "downloaded_package")
        self.assertEqual(sanitize_filename("///"), "downloaded_package")

    # --- 3. Strict Structural APK Validation Tests ---

    def test_08_valid_minimal_apk_structure(self):
        apk_path = self.output_dir / "test.apk"
        apk_path.write_bytes(make_test_apk_bytes(["classes.dex"]))
        val = validate_apk_structure(apk_path)
        self.assertTrue(val["is_zip"])
        self.assertTrue(val["has_android_manifest"])
        self.assertEqual(val["dex_files"], ["classes.dex"])
        self.assertTrue(val["has_dex"])
        self.assertTrue(val["is_valid_apk"])

    def test_09_multidex_structure_accepted_and_sorted(self):
        apk_path = self.output_dir / "multidex.apk"
        apk_path.write_bytes(make_test_apk_bytes(["classes3.dex", "classes.dex", "classes2.dex"]))
        val = validate_apk_structure(apk_path)
        self.assertTrue(val["is_valid_apk"])
        self.assertEqual(val["dex_files"], ["classes.dex", "classes2.dex", "classes3.dex"])

    def test_10_strict_dex_naming_rejects_classes0_and_classes1(self):
        # classes0.dex and classes1.dex are invalid secondary DEX names under Android conventions
        apk_path = self.output_dir / "invalid_dex.apk"
        apk_path.write_bytes(make_test_apk_bytes(["classes0.dex", "classes1.dex", "classes_backup.dex"]))
        val = validate_apk_structure(apk_path)
        self.assertFalse(val["has_dex"])
        self.assertEqual(val["dex_files"], [])
        self.assertFalse(val["is_valid_apk"])

    def test_11_zip_missing_manifest_rejected(self):
        apk_path = self.output_dir / "no_manifest.apk"
        apk_path.write_bytes(make_test_apk_bytes(["classes.dex"], include_manifest=False))
        val = validate_apk_structure(apk_path)
        self.assertTrue(val["is_zip"])
        self.assertFalse(val["has_android_manifest"])
        self.assertFalse(val["is_valid_apk"])

    def test_12_zip_missing_dex_rejected(self):
        apk_path = self.output_dir / "no_dex.apk"
        apk_path.write_bytes(make_test_apk_bytes(dex_names=[]))
        val = validate_apk_structure(apk_path)
        self.assertTrue(val["is_zip"])
        self.assertFalse(val["has_dex"])
        self.assertFalse(val["is_valid_apk"])

    def test_13_non_zip_file_rejected(self):
        bad_path = self.output_dir / "fake.apk"
        bad_path.write_text("not a zip file", encoding="utf-8")
        val = validate_apk_structure(bad_path)
        self.assertFalse(val["is_zip"])
        self.assertFalse(val["is_valid_apk"])

    # --- 4. HTTP Download & Acquisition Workflow Tests ---

    def test_14_valid_http_apk_download(self):
        url = f"{self.base_url}/valid.apk"
        meta = acquire_apk(url, self.output_dir)

        self.assertEqual(meta["input_url"], url)
        self.assertEqual(meta["final_url"], url)
        self.assertEqual(meta["status_code"], 200)
        self.assertEqual(meta["content_type"], "application/vnd.android.package-archive")
        self.assertEqual(meta["filename"], "valid.apk")
        self.assertEqual(meta["package_type"], "apk")
        self.assertTrue(meta["validation"]["is_valid_apk"])
        self.assertTrue(Path(meta["saved_path"]).exists())
        self.assertGreater(meta["size_bytes"], 0)
        self.assertEqual(len(meta["sha256"]), 64)

    def test_15_filename_from_content_disposition(self):
        url = f"{self.base_url}/custom_name_in_header"
        meta = acquire_apk(url, self.output_dir)
        self.assertEqual(meta["filename"], "from_header.apk")
        self.assertTrue((self.output_dir / "from_header.apk").exists())

    def test_16_filename_from_rfc5987_header(self):
        url = f"{self.base_url}/rfc5987_header"
        meta = acquire_apk(url, self.output_dir)
        self.assertEqual(meta["filename"], "special app.apk")
        self.assertTrue((self.output_dir / "special app.apk").exists())

    def test_17_sanitizes_content_disposition_path_traversal(self):
        url = f"{self.base_url}/traversal_header"
        meta = acquire_apk(url, self.output_dir)
        self.assertEqual(meta["filename"], "traversal_app.apk")
        # Ensure file was created strictly inside output_dir
        self.assertTrue((self.output_dir / "traversal_app.apk").exists())

    def test_18_apk_extension_applied_after_validation_when_missing(self):
        url = f"{self.base_url}/no_extension"
        meta = acquire_apk(url, self.output_dir)
        # Final URL path was /no_extension -> basename was no_extension
        # Because content is a valid APK, .apk is appended
        self.assertEqual(meta["filename"], "no_extension.apk")
        self.assertTrue((self.output_dir / "no_extension.apk").exists())

    def test_19_redirect_302_followed_and_urls_preserved(self):
        url = f"{self.base_url}/redirect_302"
        meta = acquire_apk(url, self.output_dir)
        self.assertEqual(meta["input_url"], url)
        self.assertEqual(meta["final_url"], f"{self.base_url}/valid.apk")
        self.assertEqual(meta["status_code"], 200)
        self.assertEqual(meta["filename"], "valid.apk")

    def test_20_redirect_to_unsupported_scheme_rejected(self):
        url = f"{self.base_url}/redirect_unsupported_scheme"
        with self.assertRaises(ApkAcquisitionError) as ctx:
            acquire_apk(url, self.output_dir)
        self.assertIn("unsupported scheme", str(ctx.exception).lower())
        # Verify no temp files leaked
        tmp_files = list(self.output_dir.glob(".tmp_acq_*"))
        self.assertEqual(len(tmp_files), 0)

    def test_21_http_404_handled_cleanly(self):
        url = f"{self.base_url}/not_found"
        with self.assertRaises(ApkAcquisitionError) as ctx:
            acquire_apk(url, self.output_dir)
        self.assertIn("404", str(ctx.exception))
        self.assertEqual(len(list(self.output_dir.glob(".tmp_acq_*"))), 0)

    def test_22_http_500_handled_cleanly(self):
        url = f"{self.base_url}/server_error"
        with self.assertRaises(ApkAcquisitionError) as ctx:
            acquire_apk(url, self.output_dir)
        self.assertIn("500", str(ctx.exception))
        self.assertEqual(len(list(self.output_dir.glob(".tmp_acq_*"))), 0)

    def test_23_html_disguised_as_apk_rejected(self):
        url = f"{self.base_url}/fake_html.apk"
        with self.assertRaises(ApkAcquisitionError) as ctx:
            acquire_apk(url, self.output_dir)
        self.assertIn("not a valid Android APK", str(ctx.exception))
        # Ensure no final .apk and no temporary file
        self.assertFalse((self.output_dir / "fake_html.apk").exists())
        self.assertEqual(len(list(self.output_dir.glob(".tmp_acq_*"))), 0)

    def test_24_zip_without_manifest_rejected(self):
        url = f"{self.base_url}/zip_no_manifest.apk"
        with self.assertRaises(ApkAcquisitionError) as ctx:
            acquire_apk(url, self.output_dir)
        self.assertIn("missing AndroidManifest.xml", str(ctx.exception))
        self.assertFalse((self.output_dir / "zip_no_manifest.apk").exists())
        self.assertEqual(len(list(self.output_dir.glob(".tmp_acq_*"))), 0)

    def test_25_zip_without_dex_rejected(self):
        url = f"{self.base_url}/zip_no_dex.apk"
        with self.assertRaises(ApkAcquisitionError) as ctx:
            acquire_apk(url, self.output_dir)
        self.assertIn("missing valid convention-compliant classes*.dex", str(ctx.exception))
        self.assertFalse((self.output_dir / "zip_no_dex.apk").exists())
        self.assertEqual(len(list(self.output_dir.glob(".tmp_acq_*"))), 0)

    # --- 5. Collision & Safety Limit Tests ---

    def test_26_collision_existing_destination_not_overwritten(self):
        # Pre-create valid.apk in output_dir
        existing_file = self.output_dir / "valid.apk"
        existing_file.write_bytes(b"PRESERVED_CONTENT")

        url = f"{self.base_url}/valid.apk"
        with self.assertRaises(ApkAcquisitionError) as ctx:
            acquire_apk(url, self.output_dir)

        self.assertIn("already exists", str(ctx.exception))
        # Verify existing file was NOT overwritten
        self.assertEqual(existing_file.read_bytes(), b"PRESERVED_CONTENT")
        # Verify no temp file remained
        self.assertEqual(len(list(self.output_dir.glob(".tmp_acq_*"))), 0)

    def test_27_content_length_limit_aborts_early(self):
        url = f"{self.base_url}/large_content_length.apk"
        with self.assertRaises(ApkAcquisitionError) as ctx:
            acquire_apk(url, self.output_dir, max_size_bytes=1000)
        self.assertIn("exceeds maximum limit", str(ctx.exception))
        self.assertEqual(len(list(self.output_dir.glob(".tmp_acq_*"))), 0)

    def test_28_stream_size_limit_aborts_and_cleans_temp(self):
        url = f"{self.base_url}/stream_oversize.apk"
        with self.assertRaises(ApkAcquisitionError) as ctx:
            acquire_apk(url, self.output_dir, max_size_bytes=1024)
        self.assertIn("exceeded maximum limit", str(ctx.exception))
        self.assertEqual(len(list(self.output_dir.glob(".tmp_acq_*"))), 0)
        self.assertEqual(len(list(self.output_dir.glob("*.apk"))), 0)

    def test_29_redirect_flag_and_requested_url_recorded(self):
        url = f"{self.base_url}/redirect_302"
        meta = acquire_apk(url, self.output_dir)
        self.assertTrue(meta["redirected"])
        self.assertEqual(meta["requested_url"], url)
        self.assertEqual(meta["final_url"], f"{self.base_url}/valid.apk")

    def test_30_content_disposition_recorded_in_metadata(self):
        url = f"{self.base_url}/custom_name_in_header"
        meta = acquire_apk(url, self.output_dir)
        self.assertIn("attachment", str(meta.get("content_disposition") or ""))
        self.assertEqual(meta["http"]["content_disposition"], 'attachment; filename="from_header.apk"')
        self.assertEqual(meta["http"]["status_code"], 200)

    def test_31_incorrect_content_type_with_valid_apk_body_succeeds(self):
        # Server sends text/plain, but body is structurally a valid APK (ZIP + AndroidManifest + classes.dex)
        url = f"{self.base_url}/incorrect_content_type_valid_apk"
        meta = acquire_apk(url, self.output_dir)
        self.assertEqual(meta["content_type"], "text/plain")
        self.assertTrue(meta["validation"]["is_valid_apk"])
        self.assertTrue(Path(meta["saved_path"]).exists())

    def test_32_apk_content_type_with_invalid_body_fails_structural_validation(self):
        # Server claims application/vnd.android.package-archive, but body is corrupt non-APK bytes
        url = f"{self.base_url}/apk_content_type_invalid_body"
        with self.assertRaises(ApkAcquisitionError) as ctx:
            acquire_apk(url, self.output_dir)
        self.assertIn("not a valid Android APK", str(ctx.exception))
        self.assertEqual(len(list(self.output_dir.glob(".tmp_acq_*"))), 0)

    def test_33_sha256_matches_downloaded_bytes_exactly(self):
        import hashlib
        url = f"{self.base_url}/valid.apk"
        meta = acquire_apk(url, self.output_dir)
        saved_file = Path(meta["saved_path"])
        file_bytes = saved_file.read_bytes()
        calculated_sha = hashlib.sha256(file_bytes).hexdigest()
        self.assertEqual(meta["sha256"], calculated_sha)

    def test_34_saved_artifact_strictly_within_output_dir(self):
        url = f"{self.base_url}/traversal_header"
        meta = acquire_apk(url, self.output_dir)
        saved_path = Path(meta["saved_path"]).resolve()
        self.assertTrue(saved_path.is_relative_to(self.output_dir.resolve()))
        self.assertEqual(saved_path.parent, self.output_dir.resolve())


class TestRealOwaspApkAcquisitionIntegration(unittest.TestCase):
    """Integration test against actual OWASP MSTG-Android-Kotlin.apk sample."""

    def setUp(self):
        repo_root = Path(__file__).resolve().parent.parent if (Path(__file__).resolve().parent.parent / "MSTG-Android-Kotlin.apk").is_file() else Path(__file__).resolve().parent.parent.parent
        self.owasp_apk = repo_root / "MSTG-Android-Kotlin.apk"
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_owasp_apk_structural_validation_ground_truth(self):
        self.assertTrue(self.owasp_apk.is_file(), f"OWASP APK not found at {self.owasp_apk}")

        val = validate_apk_structure(self.owasp_apk)
        self.assertTrue(val["is_zip"])
        self.assertTrue(val["has_android_manifest"])
        self.assertEqual(val["dex_files"], ["classes.dex"])
        self.assertTrue(val["has_dex"])
        self.assertTrue(val["is_valid_apk"])

    def test_owasp_apk_acquisition_via_local_server(self):
        """Simulates remote acquisition of the actual OWASP APK via local HTTP server."""
        self.assertTrue(self.owasp_apk.is_file())
        apk_data = self.owasp_apk.read_bytes()

        class OwaspHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.android.package-archive")
                self.send_header("Content-Disposition", 'attachment; filename="MSTG-Android-Kotlin.apk"')
                self.send_header("Content-Length", str(len(apk_data)))
                self.end_headers()
                self.wfile.write(apk_data)

        server = HTTPServer(("127.0.0.1", 0), OwaspHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            url = f"http://127.0.0.1:{port}/download"
            meta = acquire_apk(url, self.output_dir)

            self.assertEqual(meta["status_code"], 200)
            self.assertEqual(meta["filename"], "MSTG-Android-Kotlin.apk")
            self.assertEqual(meta["size_bytes"], len(apk_data))
            self.assertEqual(meta["package_type"], "apk")
            self.assertTrue(meta["validation"]["is_valid_apk"])
            self.assertEqual(meta["validation"]["dex_files"], ["classes.dex"])

            # Verify saved file exists and matches original binary bytes exactly
            saved_file = self.output_dir / "MSTG-Android-Kotlin.apk"
            self.assertTrue(saved_file.is_file())
            self.assertEqual(saved_file.read_bytes(), apk_data)

        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
