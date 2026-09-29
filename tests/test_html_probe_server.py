"""Unit and real MuMu integration tests for HTML Probe Server module."""

import json
from pathlib import Path
import shutil
import subprocess
import time
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
import urllib.request

from src.html_probe_server import (
    AdbReverseError,
    ProbeServer,
    configure_adb_reverse,
    remove_adb_reverse,
    start_probe_server,
    stop_probe_server,
    trigger_device_browser,
)


class TestHtmlProbeServerUnit(unittest.TestCase):
    """Unit tests for ProbeServer HTTP behavior and in-memory hit tracking."""

    def setUp(self):
        # Use port 0 for dynamic OS port assignment
        self.server = start_probe_server(host="127.0.0.1", port=0)
        self.base_url = self.server.base_url

    def tearDown(self):
        stop_probe_server(self.server)

    def test_01_server_starts_and_binds_port(self):
        self.assertGreater(self.server.port, 0)
        self.assertTrue(self.base_url.startswith("http://127.0.0.1:"))

    def test_02_probe_endpoint_returns_200_and_html(self):
        url = self.server.get_probe_url("test-run-1")
        req = urllib.request.Request(url, headers={"User-Agent": "MobiAttack-Test-Agent"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            body = resp.read().decode("utf-8")
            self.assertIn("MobiAttack Demo Probe", body)
            self.assertIn("Page successfully loaded.", body)

    def test_03_first_request_records_hit_and_increments(self):
        # Initial state before request
        status_before = self.server.get_status("run-abc")
        self.assertFalse(status_before["hit"])
        self.assertEqual(status_before["hit_count"], 0)

        # First request
        url = self.server.get_probe_url("run-abc")
        req1 = urllib.request.Request(url, headers={"User-Agent": "Agent-Alpha"})
        with urllib.request.urlopen(req1):
            pass

        status_after1 = self.server.get_status("run-abc")
        self.assertTrue(status_after1["hit"])
        self.assertEqual(status_after1["hit_count"], 1)
        self.assertEqual(status_after1["last_user_agent"], "Agent-Alpha")
        self.assertEqual(status_after1["request_path"], "/probe/run-abc")

        # Second request increments hit_count
        req2 = urllib.request.Request(url, headers={"User-Agent": "Agent-Beta"})
        with urllib.request.urlopen(req2):
            pass

        status_after2 = self.server.get_status("run-abc")
        self.assertTrue(status_after2["hit"])
        self.assertEqual(status_after2["hit_count"], 2)
        self.assertEqual(status_after2["last_user_agent"], "Agent-Beta")

    def test_04_multiple_run_ids_remain_isolated(self):
        url_a = self.server.get_probe_url("run-A")
        url_b = self.server.get_probe_url("run-B")

        # Hit run-A twice
        urllib.request.urlopen(url_a)
        urllib.request.urlopen(url_a)

        # Hit run-B once
        urllib.request.urlopen(url_b)

        # run-C never hit
        status_a = self.server.get_status("run-A")
        status_b = self.server.get_status("run-B")
        status_c = self.server.get_status("run-C")

        self.assertEqual(status_a["hit_count"], 2)
        self.assertEqual(status_b["hit_count"], 1)
        self.assertFalse(status_c["hit"])
        self.assertEqual(status_c["hit_count"], 0)

    def test_05_status_endpoint_returns_json(self):
        # Hit run-json
        urllib.request.urlopen(self.server.get_probe_url("run-json"))

        # Query GET /status/run-json
        status_url = f"{self.base_url}/status/run-json"
        with urllib.request.urlopen(status_url) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("application/json", resp.headers.get("Content-Type", ""))
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["run_id"], "run-json")
            self.assertTrue(data["hit"])
            self.assertEqual(data["hit_count"], 1)

    def test_06_server_stops_cleanly_and_releases_port(self):
        port = self.server.port
        self.server.stop()

        # Try to connect after stop; should fail
        with self.assertRaises(urllib.error.URLError):
            urllib.request.urlopen(f"http://127.0.0.1:{port}/probe/after-stop", timeout=1.0)


class TestAdbReverseHelpers(unittest.TestCase):
    """Unit tests for ADB reverse port forwarding and browser intent helper."""

    @patch("shutil.which", return_value=None)
    def test_07_missing_adb_executable_raises_error(self, mock_which):
        with self.assertRaises(AdbReverseError) as ctx:
            configure_adb_reverse("emulator-5554", 8080, 8080)
        self.assertIn("adb' not found", str(ctx.exception))

    def test_08_empty_serial_raises_error(self):
        with self.assertRaises(AdbReverseError) as ctx:
            configure_adb_reverse("", 8080, 8080)
        self.assertIn("Explicit adb_serial is required", str(ctx.exception))

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/adb")
    def test_09_configure_adb_reverse_command_arguments(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="8080\n", stderr=""
        )
        res = configure_adb_reverse("emulator-5554", device_port=8080, host_port=8080)
        self.assertTrue(res["success"])
        self.assertEqual(res["serial"], "emulator-5554")
        self.assertEqual(res["device_port"], 8080)
        self.assertEqual(res["host_port"], 8080)

        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, ["/bin/adb", "-s", "emulator-5554", "reverse", "tcp:8080", "tcp:8080"])
        self.assertNotIn("shell", mock_run.call_args[1])

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/adb")
    def test_10_configure_adb_reverse_failure_handling(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error: closed"
        )
        with self.assertRaises(AdbReverseError) as ctx:
            configure_adb_reverse("emulator-5554", 8080, 8080)
        self.assertIn("adb reverse failed", str(ctx.exception))

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/adb")
    def test_11_remove_adb_reverse_command_arguments(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        success = remove_adb_reverse("emulator-5554", device_port=8080)
        self.assertTrue(success)

        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, ["/bin/adb", "-s", "emulator-5554", "reverse", "--remove", "tcp:8080"])

    @patch("subprocess.run")
    @patch("shutil.which", return_value="/bin/adb")
    def test_12_trigger_device_browser_arguments(self, mock_which, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Starting: Intent ...\n", stderr=""
        )
        url = "http://127.0.0.1:8080/probe/test"
        res = trigger_device_browser("emulator-5554", url)
        self.assertTrue(res["connectivity_intent_dispatched"])

        cmd = mock_run.call_args[0][0]
        self.assertEqual(
            cmd,
            ["/bin/adb", "-s", "emulator-5554", "shell", "am", "start", "-a", "android.intent.action.VIEW", "-d", url],
        )
        self.assertNotIn("shell", mock_run.call_args[1])


class TestRealMumuProbeConnectivity(unittest.TestCase):
    """Live integration test against connected MuMu emulator (127.0.0.1:5555)."""

    def test_real_mumu_probe_connectivity(self):
        adb_bin = shutil.which("adb")
        if not adb_bin:
            self.skipTest("ADB binary not found on system PATH")

        # Check if 127.0.0.1:5555 is connected
        from src.android_runtime_launcher import get_connected_devices, AndroidRuntimeError
        try:
            devices = get_connected_devices()
        except AndroidRuntimeError:
            self.skipTest("ADB server not running or device check failed")
        if "127.0.0.1:5555" not in devices:
            self.skipTest("Device 127.0.0.1:5555 is not connected in 'device' state")

        target_serial = "127.0.0.1:5555"
        probe_port = 8089
        run_id = f"mumu-probe-{int(time.time())}"

        # 1. Start local probe server
        server = start_probe_server(host="127.0.0.1", port=probe_port)

        try:
            # 2. Configure adb reverse tcp:8089 tcp:8089
            rev_res = configure_adb_reverse(
                adb_serial=target_serial,
                device_port=probe_port,
                host_port=probe_port,
            )
            self.assertTrue(rev_res["success"])

            # 3. Trigger browser intent on emulator targeting probe URL
            probe_url = f"http://127.0.0.1:{probe_port}/probe/{run_id}"
            trigger_device_browser(adb_serial=target_serial, url=probe_url)

            # 4. Bounded wait for probe hit
            start_time = time.monotonic()
            hit_detected = False
            while (time.monotonic() - start_time) < 10.0:
                status = server.get_status(run_id)
                if status["hit"]:
                    hit_detected = True
                    break
                time.sleep(0.5)

            # 5. Assert hit verified
            self.assertTrue(hit_detected, f"Probe hit not received within 10s for {run_id}")
            final_status = server.get_status(run_id)
            self.assertTrue(final_status["hit"])
            self.assertGreaterEqual(final_status["hit_count"], 1)

            # Strict semantic verification: this is an emulator connectivity probe, not target app navigation
            connectivity_probe = "verified" if hit_detected else "unverified"
            self.assertEqual(connectivity_probe, "verified")

        finally:
            # 6. Clean up adb reverse and stop server
            remove_adb_reverse(adb_serial=target_serial, device_port=probe_port)
            stop_probe_server(server)


if __name__ == "__main__":
    unittest.main()
