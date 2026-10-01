"""Comprehensive tests for Android Runtime Observation Primitive V1 (Week 2 — Day 6 Task 6.1).

Verifies all 28 requirements:
1. running process captures PID.
2. missing PID produces process_running false.
3. target foreground recognized.
4. permission dialog foreground represented correctly while target process alive.
5. activity captured.
6. fatal log detected.
7. crash log detected.
8. normal error not automatically crash.
9. bounded log window used.
10. target PID filtering preferred when available.
11. PID filtering fallback works.
12. bearer token redacted.
13. authorization header redacted.
14. password/token/cookie values redacted.
15. host absolute paths redacted.
16. raw multi-megabyte log dump not persisted.
17. subprocess safety timeout respected.
18. timeout handled as controlled observation diagnostic.
19. before/after PID change detected.
20. process death diff detected.
21. activity change diff detected.
22. foreground package change diff detected.
23. newly appearing fatal event detected.
24. same snapshots produce no fake changes.
25. observer executes no UI actions.
26. observer does not mutate RouteGraph.
27. observer does not mutate scan_state.
28. no Frida dependency/import added.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

from src.dynamic.runtime.models import (
    LogEventKind,
    RuntimeDiff,
    RuntimeLogEvent,
    RuntimeSnapshot,
    compare_runtime_snapshots,
    sanitize_log_message,
)
from src.dynamic.runtime.observer import (
    AndroidRuntimeObserver,
    observe_runtime,
    parse_logcat_line,
)


class TestDynamicRuntimeObserver(unittest.TestCase):
    """Verifies all functional, security, sanitization, and diff contracts of AndroidRuntimeObserver."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)
        self.pkg = "com.example.targetapp"
        self.serial = "emulator-5554"

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. running process captures PID
    @patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234)
    @patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": "com.example.targetapp", "observed_activity": "com.example.targetapp.MainActivity"})
    def test_01_running_process_captures_pid(self, mock_fg, mock_pid):
        observer = AndroidRuntimeObserver(serial=self.serial)
        with patch.object(observer, "_collect_bounded_logs", return_value=([], False, False)):
            snap = observer.observe(self.pkg)

        self.assertEqual(snap.pid, 1234)
        self.assertTrue(snap.process_running)
        mock_pid.assert_called_once()

    # 2. missing PID produces process_running false
    @patch("src.dynamic.runtime.observer._find_process_pid", return_value=None)
    @patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": None, "observed_activity": None})
    def test_02_missing_pid_produces_process_running_false(self, mock_fg, mock_pid):
        observer = AndroidRuntimeObserver(serial=self.serial)
        with patch.object(observer, "_collect_bounded_logs", return_value=([], False, False)):
            snap = observer.observe(self.pkg)

        self.assertIsNone(snap.pid)
        self.assertFalse(snap.process_running)

    # 3. target foreground recognized
    @patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234)
    @patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": "com.example.targetapp", "observed_activity": "com.example.targetapp.MainActivity"})
    def test_03_target_foreground_recognized(self, mock_fg, mock_pid):
        observer = AndroidRuntimeObserver(serial=self.serial)
        with patch.object(observer, "_collect_bounded_logs", return_value=([], False, False)):
            snap = observer.observe(self.pkg)

        self.assertEqual(snap.foreground_package, "com.example.targetapp")
        self.assertEqual(snap.foreground_activity, "com.example.targetapp.MainActivity")
        self.assertTrue(snap.is_foreground)

    # 4. permission dialog foreground represented correctly while target process alive
    @patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234)
    @patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": "com.android.permissioncontroller", "observed_activity": "com.android.permissioncontroller.permission.ui.GrantPermissionsActivity"})
    def test_04_permission_dialog_foreground_represented_correctly(self, mock_fg, mock_pid):
        observer = AndroidRuntimeObserver(serial=self.serial)
        with patch.object(observer, "_collect_bounded_logs", return_value=([], False, False)):
            snap = observer.observe(self.pkg)

        # Process alive, but permission controller dialog is in foreground
        self.assertTrue(snap.process_running)
        self.assertEqual(snap.pid, 1234)
        self.assertEqual(snap.foreground_package, "com.android.permissioncontroller")
        self.assertEqual(snap.foreground_activity, "com.android.permissioncontroller.permission.ui.GrantPermissionsActivity")
        self.assertFalse(snap.is_foreground)

    # 5. activity captured
    @patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234)
    @patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": "com.example.targetapp", "observed_activity": "com.example.targetapp.DetailsActivity"})
    def test_05_activity_captured(self, mock_fg, mock_pid):
        snap = observe_runtime(self.pkg, adb_serial=self.serial)
        self.assertEqual(snap.foreground_activity, "com.example.targetapp.DetailsActivity")

    # 6. fatal log detected
    def test_06_fatal_log_detected(self):
        log_sample = "10-01 10:15:30.123  1234  1234 E AndroidRuntime: FATAL EXCEPTION: main\njava.lang.RuntimeException"
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            snap = observer.observe(self.pkg)

        self.assertTrue(snap.fatal_detected)
        self.assertTrue(snap.crash_detected)
        self.assertTrue(any(e.kind == LogEventKind.FATAL.value for e in snap.log_events))

    # 7. crash log detected
    def test_07_crash_log_detected(self):
        log_sample = "10-01 10:15:30.456   500   500 E ActivityManager: Process com.example.targetapp (pid 1234) has died"
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=None), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": None, "observed_activity": None}):
            snap = observer.observe(self.pkg)

        self.assertTrue(snap.crash_detected)
        self.assertTrue(any(e.kind == LogEventKind.CRASH.value for e in snap.log_events))

    # 8. normal error not automatically crash
    def test_08_normal_error_not_automatically_crash(self):
        log_sample = "10-01 10:15:30.789  1234  1234 E Glide: Failed to find GeneratedAppGlideModule"
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            snap = observer.observe(self.pkg)

        self.assertFalse(snap.fatal_detected)
        self.assertFalse(snap.crash_detected)
        self.assertTrue(any(e.kind == LogEventKind.ERROR.value for e in snap.log_events))

    # 9. bounded log window used
    def test_09_bounded_log_window_used(self):
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, max_log_lines=150, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            observer.observe(self.pkg)

        cmd = mock_runner.call_args[0][0]
        self.assertIn("-t", cmd)
        self.assertIn("150", cmd)

    # 10. target PID filtering preferred when available
    def test_10_target_pid_filtering_preferred_when_available(self):
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="10-01 10:00:00.000 I/Test: hello", stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=5566), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            observer.observe(self.pkg)

        cmd = mock_runner.call_args_list[0][0][0]
        self.assertIn("--pid=5566", cmd)

    # 11. PID filtering fallback works
    def test_11_pid_filtering_fallback_works(self):
        # First call with --pid fails (returncode=1), second fallback call succeeds
        failed_proc = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="unknown option --pid")
        ok_proc = subprocess.CompletedProcess(args=[], returncode=0, stdout="10-01 10:00:00.000 I/Fallback: ok", stderr="")
        mock_runner = MagicMock(side_effect=[failed_proc, ok_proc])
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=5566), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            snap = observer.observe(self.pkg)

        self.assertEqual(mock_runner.call_count, 2)
        fallback_cmd = mock_runner.call_args_list[1][0][0]
        self.assertNotIn("--pid=5566", fallback_cmd)
        self.assertTrue(any(e.tag == "Fallback" for e in snap.log_events))
        self.assertTrue(any("falling back to unfiltered" in d for d in snap.diagnostics))

    # 12. bearer token redacted
    def test_12_bearer_token_redacted(self):
        msg = "Sending request with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"
        cleaned = sanitize_log_message(msg)
        self.assertNotIn("eyJhbGci", cleaned)
        self.assertIn("Bearer [REDACTED]", cleaned)

    # 13. authorization header redacted
    def test_13_authorization_header_redacted(self):
        msg = "Headers: Authorization: Bearer abcdef1234567890xyz and Content-Type: application/json"
        cleaned = sanitize_log_message(msg)
        self.assertNotIn("abcdef1234567890xyz", cleaned)
        self.assertIn("Authorization: Bearer [REDACTED]", cleaned)

    # 14. password/token/cookie values redacted
    def test_14_password_token_cookie_values_redacted(self):
        msg = "Login payload: password=SuperSecretPassword123&token=998877665544&cookie=session_id_4455"
        cleaned = sanitize_log_message(msg)
        self.assertNotIn("SuperSecretPassword123", cleaned)
        self.assertNotIn("998877665544", cleaned)
        self.assertNotIn("session_id_4455", cleaned)
        self.assertIn("password=[REDACTED]", cleaned)
        self.assertIn("token=[REDACTED]", cleaned)
        self.assertIn("cookie=[REDACTED]", cleaned)

    # 15. host absolute paths redacted
    def test_15_host_absolute_paths_redacted(self):
        msg = "Loaded native lib from /Users/alice/projects/app/libnative.so or /opt/homebrew/bin/adb"
        cleaned = sanitize_log_message(msg)
        self.assertNotIn("/Users/alice", cleaned)
        self.assertNotIn("/opt/homebrew", cleaned)
        self.assertIn("[host_path]", cleaned)

    # 16. raw multi-megabyte log dump not persisted
    def test_16_raw_multimegabyte_log_dump_not_persisted(self):
        # Generate 500 lines of logs
        lines = [f"10-01 10:00:{i:02d}.000 I/Spam: Line number {i}" for i in range(500)]
        big_dump = "\n".join(lines)
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=big_dump, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, max_log_events=50, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            snap = observer.observe(self.pkg)

        # Log events count is bounded by max_log_events
        self.assertLessEqual(len(snap.log_events), 50)
        serialized = json.dumps(snap.to_dict())
        self.assertLess(len(serialized), 50000)

    # 17. subprocess safety timeout respected
    def test_17_subprocess_safety_timeout_respected(self):
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, timeout_seconds=3.5, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            observer.observe(self.pkg)

        for c in mock_runner.call_args_list:
            _, kwargs = c
            self.assertEqual(kwargs.get("timeout"), 3.5)

    # 18. timeout handled as controlled observation diagnostic
    def test_18_timeout_handled_as_controlled_observation_diagnostic(self):
        mock_runner = MagicMock(side_effect=subprocess.TimeoutExpired(cmd=["logcat"], timeout=2.0))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            snap = observer.observe(self.pkg)

        self.assertIsNotNone(snap)
        self.assertTrue(any("timed out" in d for d in snap.diagnostics))

    # 19. before/after PID change detected
    def test_19_before_after_pid_change_detected(self):
        before = RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)
        after = RuntimeSnapshot(package_name=self.pkg, pid=1002, process_running=True)

        diff = compare_runtime_snapshots(before, after)
        self.assertTrue(diff.pid_changed)
        self.assertEqual(diff.before_pid, 1001)
        self.assertEqual(diff.after_pid, 1002)
        self.assertFalse(diff.process_died)

    # 20. process death diff detected
    def test_20_process_death_diff_detected(self):
        before = RuntimeSnapshot(package_name=self.pkg, pid=1001, process_running=True)
        after = RuntimeSnapshot(package_name=self.pkg, pid=None, process_running=False)

        diff = compare_runtime_snapshots(before, after)
        self.assertTrue(diff.pid_changed)
        self.assertTrue(diff.process_died)
        self.assertFalse(diff.process_spawned)

    # 21. activity change diff detected
    def test_21_activity_change_diff_detected(self):
        before = RuntimeSnapshot(package_name=self.pkg, foreground_activity="com.example.MainActivity")
        after = RuntimeSnapshot(package_name=self.pkg, foreground_activity="com.example.SettingsActivity")

        diff = compare_runtime_snapshots(before, after)
        self.assertTrue(diff.activity_changed)
        self.assertEqual(diff.before_activity, "com.example.MainActivity")
        self.assertEqual(diff.after_activity, "com.example.SettingsActivity")

    # 22. foreground package change diff detected
    def test_22_foreground_package_change_diff_detected(self):
        before = RuntimeSnapshot(package_name=self.pkg, foreground_package=self.pkg)
        after = RuntimeSnapshot(package_name=self.pkg, foreground_package="com.android.settings")

        diff = compare_runtime_snapshots(before, after)
        self.assertTrue(diff.foreground_changed)
        self.assertEqual(diff.before_foreground_package, self.pkg)
        self.assertEqual(diff.after_foreground_package, "com.android.settings")

    # 23. newly appearing fatal event detected
    def test_23_newly_appearing_fatal_event_detected(self):
        before = RuntimeSnapshot(package_name=self.pkg, fatal_detected=False, log_events=[])
        fatal_evt = RuntimeLogEvent(timestamp="10-01 10:00:01.000", level="E", tag="AndroidRuntime", message="FATAL EXCEPTION: main", kind=LogEventKind.FATAL.value)
        after = RuntimeSnapshot(package_name=self.pkg, fatal_detected=True, log_events=[fatal_evt])

        diff = compare_runtime_snapshots(before, after)
        self.assertTrue(diff.fatal_appeared)
        self.assertEqual(diff.new_log_event_count, 1)
        self.assertEqual(diff.new_log_events[0].kind, "fatal")

    # 24. same snapshots produce no fake changes
    def test_24_same_snapshots_produce_no_fake_changes(self):
        snap = RuntimeSnapshot(
            package_name=self.pkg,
            pid=2000,
            process_running=True,
            foreground_package=self.pkg,
            foreground_activity="com.example.MainActivity",
            fatal_detected=False,
            crash_detected=False,
            log_events=[RuntimeLogEvent(timestamp="10-01 10:00:00.000", level="I", tag="App", message="Ready")],
        )
        diff = compare_runtime_snapshots(snap, snap)

        self.assertFalse(diff.pid_changed)
        self.assertFalse(diff.process_died)
        self.assertFalse(diff.process_spawned)
        self.assertFalse(diff.foreground_changed)
        self.assertFalse(diff.activity_changed)
        self.assertFalse(diff.fatal_appeared)
        self.assertFalse(diff.crash_appeared)
        self.assertEqual(diff.new_log_event_count, 0)

    # 25. observer executes no UI actions
    @patch("subprocess.run")
    def test_25_observer_executes_no_ui_actions(self, mock_subproc):
        mock_subproc.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        observer = AndroidRuntimeObserver(serial=self.serial)
        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            observer.observe(self.pkg)

        # Ensure no 'input' commands were ever issued to ADB
        for c in mock_subproc.call_args_list:
            cmd = c[0][0]
            self.assertNotIn("input", cmd)
            self.assertNotIn("tap", cmd)
            self.assertNotIn("keyevent", cmd)

    # 26. observer does not mutate RouteGraph
    def test_26_observer_does_not_mutate_route_graph(self):
        from src.dynamic.route.graph import RouteGraph
        rg = RouteGraph(run_id="rg_test", session_id="sess_test")
        initial_nodes = rg.node_count
        initial_edges = rg.edge_count

        observer = AndroidRuntimeObserver(serial=self.serial)
        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}), \
             patch.object(observer, "_collect_bounded_logs", return_value=([], False, False)):
            observer.observe(self.pkg)

        self.assertEqual(rg.node_count, initial_nodes)
        self.assertEqual(rg.edge_count, initial_edges)

    # 27. observer does not mutate scan_state
    def test_27_observer_does_not_mutate_scan_state(self):
        from src.scan_state import create_initial_scan_state, load_scan_state, save_scan_state
        init_st = create_initial_scan_state(scan_id=self.output_dir.name, target_url="http://example.com/app.apk")
        save_scan_state(self.output_dir, init_st)

        observer = AndroidRuntimeObserver(serial=self.serial)
        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}), \
             patch.object(observer, "_collect_bounded_logs", return_value=([], False, False)):
            observer.observe(self.pkg)

        after_st = load_scan_state(self.output_dir)
        self.assertEqual(init_st, after_st)

    # 28. no Frida dependency/import added
    def test_28_no_frida_dependency_or_import(self):
        import src.dynamic.runtime.models as m_models
        import src.dynamic.runtime.observer as m_obs
        import src.dynamic.runtime as m_pkg

        for mod in (m_models, m_obs, m_pkg):
            source = Path(mod.__file__).read_text(encoding="utf-8")
            self.assertNotIn("frida", source.lower())
            self.assertNotIn("objection", source.lower())
            self.assertNotIn("xposed", source.lower())
        self.assertNotIn("frida", sys.modules)

    # 29. PID-scoped fatal marks target fatal
    def test_29_pid_scoped_fatal_marks_target_fatal(self):
        log_sample = "10-01 10:15:30.123  1234  1234 E AndroidRuntime: FATAL EXCEPTION: main\njava.lang.RuntimeException"
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            snap = observer.observe(self.pkg)

        self.assertTrue(snap.fatal_detected)
        self.assertTrue(snap.crash_detected)
        fatal_evts = [e for e in snap.log_events if e.kind == LogEventKind.FATAL.value]
        self.assertEqual(len(fatal_evts), 1)
        evt = fatal_evts[0]
        self.assertTrue(evt.target_attributed)
        self.assertEqual(evt.attribution, "target")
        self.assertEqual(evt.attribution_reason, "pid_scoped")

    # 30. PID-scoped crash marks target crash
    def test_30_pid_scoped_crash_marks_target_crash(self):
        log_sample = "10-01 10:15:30.123  1234  1234 F libc: Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR)"
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            snap = observer.observe(self.pkg)

        self.assertTrue(snap.fatal_detected)
        self.assertTrue(snap.crash_detected)
        evt = snap.log_events[0]
        self.assertTrue(evt.target_attributed)
        self.assertEqual(evt.attribution, "target")
        self.assertEqual(evt.attribution_reason, "pid_scoped")

    # 31. global unscoped generic FATAL does NOT mark target fatal
    def test_31_global_unscoped_generic_fatal_does_not_mark_target_fatal(self):
        log_sample = "10-01 10:15:30.123 E AndroidRuntime: FATAL EXCEPTION: main\njava.lang.RuntimeException"
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=None), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": None, "observed_activity": None}):
            snap = observer.observe(self.pkg)

        self.assertFalse(snap.fatal_detected)
        self.assertFalse(snap.crash_detected)
        fatal_evts = [e for e in snap.log_events if e.kind == LogEventKind.FATAL.value]
        self.assertEqual(len(fatal_evts), 1)
        evt = fatal_evts[0]
        self.assertEqual(evt.kind, LogEventKind.FATAL.value)
        self.assertFalse(evt.target_attributed)
        self.assertEqual(evt.attribution, "unknown")
        self.assertEqual(evt.attribution_reason, "unscoped_fallback")

    # 32. global unscoped generic crash does NOT mark target crash
    def test_32_global_unscoped_generic_crash_does_not_mark_target_crash(self):
        log_sample = "10-01 10:15:30.123 F libc: Fatal signal 11 (SIGSEGV)"
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=None), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": None, "observed_activity": None}):
            snap = observer.observe(self.pkg)

        self.assertFalse(snap.fatal_detected)
        self.assertFalse(snap.crash_detected)
        self.assertEqual(len(snap.log_events), 1)
        evt = snap.log_events[0]
        self.assertFalse(evt.target_attributed)
        self.assertEqual(evt.attribution, "unknown")

    # 33. global fallback target package death marks target crash
    def test_33_global_fallback_target_package_death_marks_target_crash(self):
        log_sample = f"10-01 10:15:30.456   500   500 E ActivityManager: Process {self.pkg} (pid 1234) has died"
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=None), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": None, "observed_activity": None}):
            snap = observer.observe(self.pkg)

        self.assertTrue(snap.crash_detected)
        self.assertEqual(len(snap.log_events), 1)
        evt = snap.log_events[0]
        self.assertTrue(evt.target_attributed)
        self.assertEqual(evt.attribution, "target")
        self.assertEqual(evt.attribution_reason, "explicit_package_marker")

    # 34. global fallback target ANR marks target crash
    def test_34_global_fallback_target_anr_marks_target_crash(self):
        log_sample = f"10-01 10:15:30.456   500   500 E ActivityManager: ANR in {self.pkg}"
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=None), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": None, "observed_activity": None}):
            snap = observer.observe(self.pkg)

        self.assertTrue(snap.crash_detected)
        self.assertEqual(len(snap.log_events), 1)
        evt = snap.log_events[0]
        self.assertTrue(evt.target_attributed)
        self.assertEqual(evt.attribution, "target")
        self.assertEqual(evt.attribution_reason, "explicit_package_marker")

    # 35. foreign package crash does not mark target crash
    def test_35_foreign_package_crash_does_not_mark_target_crash(self):
        foreign_log = (
            "10-01 10:15:30.456   500   500 E ActivityManager: Process com.other.foreign (pid 9999) has died\n"
            "10-01 10:15:30.457   500   500 E ActivityManager: ANR in com.other.foreign"
        )
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=foreign_log, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=None), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": None, "observed_activity": None}):
            snap = observer.observe(self.pkg)

        self.assertFalse(snap.crash_detected)
        self.assertFalse(snap.fatal_detected)
        for evt in snap.log_events:
            self.assertFalse(evt.target_attributed)
            self.assertEqual(evt.attribution, "unknown")
            self.assertEqual(evt.attribution_reason, "foreign_package")

    # 36. foreign fatal does not create RuntimeDiff.fatal_appeared
    def test_36_foreign_fatal_does_not_create_runtimediff_fatal_appeared(self):
        before = RuntimeSnapshot(package_name=self.pkg, fatal_detected=False, log_events=[])
        foreign_evt = RuntimeLogEvent(
            timestamp="10-01 10:00:01.000",
            level="E",
            tag="AndroidRuntime",
            message="FATAL EXCEPTION: main",
            kind=LogEventKind.FATAL.value,
            target_attributed=False,
            attribution="unknown",
            attribution_reason="unscoped_fallback",
        )
        after = RuntimeSnapshot(package_name=self.pkg, fatal_detected=False, log_events=[foreign_evt])

        diff = compare_runtime_snapshots(before, after)
        self.assertFalse(diff.fatal_appeared)
        self.assertFalse(diff.crash_appeared)
        self.assertEqual(diff.new_log_event_count, 1)

    # 37. target-attributed fatal creates RuntimeDiff.fatal_appeared
    def test_37_target_attributed_fatal_creates_runtimediff_fatal_appeared(self):
        before = RuntimeSnapshot(package_name=self.pkg, fatal_detected=False, log_events=[])
        target_fatal_evt = RuntimeLogEvent(
            timestamp="10-01 10:00:01.000",
            level="E",
            tag="AndroidRuntime",
            message="FATAL EXCEPTION: main",
            kind=LogEventKind.FATAL.value,
            target_attributed=True,
            attribution="target",
            attribution_reason="pid_scoped",
        )
        after = RuntimeSnapshot(package_name=self.pkg, fatal_detected=True, crash_detected=True, log_events=[target_fatal_evt])

        diff = compare_runtime_snapshots(before, after)
        self.assertTrue(diff.fatal_appeared)
        self.assertTrue(diff.crash_appeared)
        self.assertEqual(diff.new_log_event_count, 1)

    # 38. fallback diagnostic records reduced attribution certainty
    def test_38_fallback_diagnostic_records_reduced_attribution_certainty(self):
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=None), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": None, "observed_activity": None}):
            snap = observer.observe(self.pkg)

        self.assertTrue(
            any("PID-scoped logcat unavailable; using attribution-filtered fallback" in d for d in snap.diagnostics),
            f"Expected fallback diagnostic not found in: {snap.diagnostics}"
        )

    # 39. ambiguous event may be retained without target-level crash flag
    def test_39_ambiguous_event_retained_without_target_level_crash_flag(self):
        log_sample = (
            "10-01 10:15:30.123 E AndroidRuntime: FATAL EXCEPTION: main\n"
            "10-01 10:15:30.124 I App: Normal info line"
        )
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=None), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": None, "observed_activity": None}):
            snap = observer.observe(self.pkg)

        self.assertEqual(len(snap.log_events), 2)
        self.assertFalse(snap.fatal_detected)
        self.assertFalse(snap.crash_detected)
        fatal_evt = [e for e in snap.log_events if e.kind == LogEventKind.FATAL.value][0]
        self.assertFalse(fatal_evt.target_attributed)
        self.assertEqual(fatal_evt.attribution, "unknown")

    # 40. since_timestamp filtering works across real logcat timestamp format
    def test_40_since_timestamp_filtering_works_across_real_logcat_format(self):
        log_sample = (
            "10-01 10:15:30.100 I/Test: Too old\n"
            "10-01 10:15:30.300 I/Test: Target event 1\n"
            "10-01 10:15:30.500 I/Test: Target event 2"
        )
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            snap = observer.observe(self.pkg, since_timestamp="2026-10-01T10:15:30.200000+00:00")

        self.assertEqual(len(snap.log_events), 2)
        self.assertEqual(snap.log_events[0].message, "Target event 1")
        self.assertEqual(snap.log_events[1].message, "Target event 2")

    # 41. incompatible/invalid timestamps fail conservatively
    def test_41_incompatible_invalid_timestamps_fail_conservatively(self):
        log_sample = (
            "10-01 10:15:30.100 I/Test: Event 1\n"
            "10-01 10:15:30.200 I/Test: Event 2"
        )
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=1234), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": self.pkg, "observed_activity": "MainActivity"}):
            snap = observer.observe(self.pkg, since_timestamp="completely-invalid-ts")

        # Did not crash, did not drop valid events
        self.assertEqual(len(snap.log_events), 2)
        self.assertTrue(any("Invalid or unparseable since_timestamp" in d for d in snap.diagnostics))

    # 42. no global logcat -c introduced
    def test_42_no_global_logcat_c_introduced(self):
        import src.dynamic.runtime.observer as obs_module
        source = Path(obs_module.__file__).read_text(encoding="utf-8")
        self.assertNotIn("logcat -c", source)
        self.assertNotIn("logcat', '-c", source)
        self.assertNotIn('"logcat", "-c"', source)
        self.assertNotIn("--clear", source)

    # 43. previous sanitization tests remain green and attribution metadata sanitized
    def test_43_attribution_metadata_and_payload_sanitization(self):
        evt = RuntimeLogEvent(
            timestamp="10-01 10:00:00.000",
            level="E",
            tag="Test",
            message="Leaking token=SecretToken12345 and /Users/suleyman/code/leak.txt",
            kind=LogEventKind.ERROR.value,
            target_attributed=False,
            attribution="unknown",
            attribution_reason="reason referencing /Users/suleyman/secret_path and password=SecretPassword123",
        )
        serialized = evt.to_dict()
        self.assertNotIn("SecretToken12345", serialized["message"])
        self.assertNotIn("/Users/suleyman", serialized["message"])
        self.assertIn("token=[REDACTED]", serialized["message"])
        self.assertIn("[host_path]", serialized["message"])

        self.assertNotIn("SecretPassword123", serialized["attribution_reason"])
        self.assertNotIn("/Users/suleyman", serialized["attribution_reason"])
        self.assertIn("password=[REDACTED]", serialized["attribution_reason"])
        self.assertIn("[host_path]", serialized["attribution_reason"])

    # 44. AndroidRuntime context lookahead in fallback attributes fatal exception
    def test_44_android_runtime_context_lookahead_attributes_fatal(self):
        log_sample = (
            "10-01 10:15:30.123 E AndroidRuntime: FATAL EXCEPTION: main\n"
            f"10-01 10:15:30.124 E AndroidRuntime: Process: {self.pkg}, PID: 7788\n"
            "10-01 10:15:30.125 E AndroidRuntime: java.lang.NullPointerException"
        )
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout=log_sample, stderr=""))
        observer = AndroidRuntimeObserver(serial=self.serial, subprocess_runner=mock_runner)

        with patch("src.dynamic.runtime.observer._find_process_pid", return_value=None), \
             patch("src.dynamic.runtime.observer.get_current_activity", return_value={"observed_package": None, "observed_activity": None}):
            snap = observer.observe(self.pkg)

        self.assertTrue(snap.fatal_detected)
        self.assertTrue(snap.crash_detected)
        fatal_evt = [e for e in snap.log_events if e.kind == LogEventKind.FATAL.value][0]
        self.assertTrue(fatal_evt.target_attributed)
        self.assertEqual(fatal_evt.attribution, "target")
        self.assertEqual(fatal_evt.attribution_reason, "context_package_marker")
