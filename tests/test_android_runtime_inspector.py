"""Unit tests for the live Android runtime inspector module."""

from unittest.mock import MagicMock, patch
import unittest

from src.android_runtime_inspector import (
    inspect_runtime_process,
    parse_logcat_lines,
    parse_meminfo_output,
)


class TestAndroidRuntimeInspector(unittest.TestCase):

    def test_parse_meminfo_output(self):
        sample_meminfo = """
Applications Memory Usage (in Kilobytes):
** MEMINFO in pid 1121 [com.example.app] **
                   Pss  Private  Private  SwapPss      Rss     Heap     Heap     Heap
                 Total    Dirty    Clean    Dirty    Total     Size    Alloc     Free
                ------   ------   ------   ------   ------   ------   ------   ------
  Native Heap     2048     1000        0     6442     1012    16720     7171     5262
  Dalvik Heap     4096      500        0     6167      596     7968     6040     1928
        TOTAL    32768      328     9844    19406    81144    24688    13211     7190
        """
        res = parse_meminfo_output(sample_meminfo)
        self.assertEqual(res["total_pss_kb"], 32768)
        self.assertEqual(res["total_pss_mb"], 32.0)
        self.assertEqual(res["native_heap_kb"], 2048)
        self.assertEqual(res["dalvik_heap_kb"], 4096)
        self.assertEqual(res["status"], "measured")

    def test_parse_logcat_lines_clean(self):
        clean_lines = [
            "09-30 12:00:01.000 I/MyApp(100): Application started normally",
            "09-30 12:00:02.000 D/MyApp(100): View rendered successfully",
        ]
        res = parse_logcat_lines(clean_lines)
        self.assertEqual(res["lines_captured"], 2)
        self.assertFalse(res["has_leak_warnings"])
        self.assertEqual(res["leak_count"], 0)

    def test_parse_logcat_lines_detects_sensitive_data_and_exceptions(self):
        leaky_lines = [
            "09-30 12:00:01.000 D/Auth(100): Sending Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 to server",
            "09-30 12:00:02.000 D/Login(100): User password=SecretPassword123",
            "09-30 12:00:03.000 E/AndroidRuntime(100): FATAL EXCEPTION: main",
        ]
        res = parse_logcat_lines(leaky_lines)
        self.assertTrue(res["has_leak_warnings"])
        self.assertEqual(res["leak_count"], 3)
        findings = res["leak_findings"]
        types = [f["pattern_type"] for f in findings]
        self.assertIn("auth_token", types)
        self.assertIn("credential", types)
        self.assertIn("unhandled_exception", types)
        # Check that secret was masked in evidence
        pw_finding = [f for f in findings if f["pattern_type"] == "credential"][0]
        self.assertNotIn("SecretPassword123", pw_finding["evidence"])
        self.assertIn("****", pw_finding["evidence"])

    @patch("subprocess.run")
    def test_inspect_runtime_process(self, mock_run):
        # First call is dumpsys meminfo, second is logcat
        mock_mem = MagicMock(returncode=0, stdout="TOTAL    16384\nNative Heap    1024\nDalvik Heap    2048\n")
        mock_log = MagicMock(returncode=0, stdout="09-30 12:00:01.000 I/App(10): Normal log\n")
        mock_run.side_effect = [mock_mem, mock_log]

        res = inspect_runtime_process(
            adb_bin="adb",
            serial="emulator-5554",
            package_name="com.example.app",
            pid=10,
        )
        self.assertIn("memory_footprint", res)
        self.assertEqual(res["memory_footprint"]["total_pss_mb"], 16.0)
        self.assertIn("logcat_audit", res)
        self.assertEqual(res["logcat_audit"]["lines_captured"], 1)


if __name__ == "__main__":
    unittest.main()
