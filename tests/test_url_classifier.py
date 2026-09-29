"""Tests for URL Classifier and Platform Routing."""

import unittest

from src.url_classifier import classify_input_url


class TestUrlClassifier(unittest.TestCase):
    def test_direct_apk_standard(self):
        url = "https://example.com/downloads/sample.apk"
        res = classify_input_url(url, platform="android")
        self.assertEqual(res["platform"], "android")
        self.assertEqual(res["type"], "direct_apk")
        self.assertEqual(res["normalized_url"], url)
        self.assertIsNone(res["package_name"])

    def test_direct_apk_case_insensitive(self):
        url = "http://example.org/files/App.APK"
        res = classify_input_url(url, platform="android")
        self.assertEqual(res["type"], "direct_apk")

    def test_direct_apk_with_query_params(self):
        url = "https://example.com/builds/app.apk?version=1.2.0&auth=token123"
        res = classify_input_url(url, platform="android")
        self.assertEqual(res["type"], "direct_apk")

    def test_play_store_valid_package_id(self):
        url = "https://play.google.com/store/apps/details?id=com.example.app"
        res = classify_input_url(url, platform="android")
        self.assertEqual(res["platform"], "android")
        self.assertEqual(res["type"], "play_store")
        self.assertEqual(res["package_name"], "com.example.app")

    def test_play_store_extra_query_params(self):
        url = "https://play.google.com/store/apps/details?id=owasp.sat.agoat&hl=en&gl=US"
        res = classify_input_url(url, platform="android")
        self.assertEqual(res["type"], "play_store")
        self.assertEqual(res["package_name"], "owasp.sat.agoat")

    def test_play_store_missing_id_param(self):
        url = "https://play.google.com/store/apps/details?hl=en"
        res = classify_input_url(url, platform="android")
        self.assertEqual(res["type"], "unsupported")
        self.assertIn("missing required 'id'", res.get("reason", ""))

    def test_play_store_malformed_package_id(self):
        url = "https://play.google.com/store/apps/details?id=123-invalid-package!"
        res = classify_input_url(url, platform="android")
        self.assertEqual(res["type"], "unsupported")
        self.assertIn("Malformed Play Store package identifier", res.get("reason", ""))

    def test_normal_webpage_unsupported(self):
        url = "https://example.com/app/index.html"
        res = classify_input_url(url, platform="android")
        self.assertEqual(res["type"], "unsupported")
        self.assertIn("Unsupported Android URL", res.get("reason", ""))

    def test_github_repo_url_unsupported(self):
        url = "https://github.com/OWASP/Android-InsecureBankv2"
        res = classify_input_url(url, platform="android")
        self.assertEqual(res["type"], "unsupported")

    def test_invalid_scheme(self):
        url = "ftp://example.com/app.apk"
        res = classify_input_url(url, platform="android")
        self.assertEqual(res["type"], "unsupported")

    def test_ios_platform_not_implemented(self):
        url = "https://example.com/app.apk"
        res = classify_input_url(url, platform="ios")
        self.assertEqual(res["platform"], "ios")
        self.assertEqual(res["type"], "not_implemented")
        self.assertEqual(res["message"], "iOS analysis is not implemented in V1.")


if __name__ == "__main__":
    unittest.main()
