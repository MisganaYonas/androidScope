import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from run_injuredandroid_stage import (
    BROADCAST_ACTION,
    BROADCAST_URL,
    HOOKS,
    PACKAGE,
    StageError,
    _adb,
    _get_pid,
    _install_apk,
    _launch_app,
    _launch_receiver_activity,
    _require_device,
    _require_frida_server,
    _require_pid,
    _send_broadcast,
    _validate_apk,
    build_parser,
    main,
)


def _adb_ok(*args, **kwargs):
    return 0, "", ""


def _adb_fail(*args, **kwargs):
    return 1, "", "error"


class AdbHelpersTests(unittest.TestCase):
    def test_require_device_passes_when_state_is_device(self):
        with patch("run_injuredandroid_stage._adb", return_value=(0, "device", "")):
            _require_device("192.168.89.103:5555")  # must not raise

    def test_require_device_raises_when_state_is_not_device(self):
        with patch("run_injuredandroid_stage._adb", return_value=(0, "offline", "")):
            with self.assertRaises(StageError) as ctx:
                _require_device("192.168.89.103:5555")
        self.assertIn("not ready", str(ctx.exception))

    def test_require_device_raises_on_adb_failure(self):
        with patch("run_injuredandroid_stage._adb", return_value=(1, "", "no device")):
            with self.assertRaises(StageError):
                _require_device("192.168.89.103:5555")

    def test_require_frida_server_passes_when_pid_present(self):
        with patch("run_injuredandroid_stage._adb", return_value=(0, "2767", "")):
            _require_frida_server("192.168.89.103:5555")  # must not raise

    def test_require_frida_server_raises_when_not_running(self):
        with patch("run_injuredandroid_stage._adb", return_value=(1, "", "")):
            with self.assertRaises(StageError) as ctx:
                _require_frida_server("192.168.89.103:5555")
        self.assertIn("frida-server", str(ctx.exception))

    def test_install_apk_raises_on_failure(self):
        with patch("run_injuredandroid_stage._adb", return_value=(1, "", "INSTALL_FAILED")):
            with self.assertRaises(StageError) as ctx:
                _install_apk("192.168.89.103:5555", Path("test.apk"))
        self.assertIn("install failed", str(ctx.exception).lower())

    def test_install_apk_succeeds_silently(self):
        with patch("run_injuredandroid_stage._adb", return_value=(0, "Success", "")):
            _install_apk("192.168.89.103:5555", Path("test.apk"))  # must not raise

    def test_get_pid_returns_pid_string_when_running(self):
        with patch("run_injuredandroid_stage._adb", return_value=(0, "3763", "")):
            self.assertEqual(_get_pid("192.168.89.103:5555"), "3763")

    def test_get_pid_returns_none_when_not_running(self):
        with patch("run_injuredandroid_stage._adb", return_value=(1, "", "")):
            self.assertIsNone(_get_pid("192.168.89.103:5555"))

    def test_get_pid_returns_none_for_non_decimal_output(self):
        with patch("run_injuredandroid_stage._adb", return_value=(0, "not-a-pid", "")):
            self.assertIsNone(_get_pid("192.168.89.103:5555"))

    def test_require_pid_raises_when_process_not_found(self):
        with patch("run_injuredandroid_stage._get_pid", return_value=None):
            with self.assertRaises(StageError) as ctx:
                _require_pid("192.168.89.103:5555")
        self.assertIn("not found", str(ctx.exception))

    def test_require_pid_returns_pid_when_running(self):
        with patch("run_injuredandroid_stage._get_pid", return_value="3763"):
            self.assertEqual(_require_pid("192.168.89.103:5555"), "3763")

    def test_send_broadcast_uses_correct_action_and_url(self):
        calls = []
        def fake_adb(serial, *args, **kwargs):
            calls.append(args)
            return 0, "Broadcast completed: result=0", ""

        with patch("run_injuredandroid_stage._adb", side_effect=fake_adb):
            _send_broadcast("192.168.89.103:5555")

        flat = " ".join(calls[0])
        self.assertIn(BROADCAST_ACTION, flat)
        self.assertIn(BROADCAST_URL, flat)
        self.assertIn(PACKAGE, flat)

    def test_launch_receiver_activity_does_not_raise_on_failure(self):
        # Non-fatal: a failed activity launch is a warning, not a StageError.
        with patch("run_injuredandroid_stage._adb", return_value=(1, "", "error")), \
                patch("run_injuredandroid_stage.time.sleep"):
            _launch_receiver_activity("192.168.89.103:5555")  # must not raise


class ParserTests(unittest.TestCase):
    def test_required_arguments(self):
        parser = build_parser()
        args = parser.parse_args([
            "--apk", "InjuredAndroid.apk",
            "--out-dir", "/tmp/out",
            "--application-id", "application-015",
        ])
        self.assertEqual(args.application_id, "application-015")
        self.assertEqual(str(args.apk), "InjuredAndroid.apk")

    def test_default_device_serial(self):
        parser = build_parser()
        args = parser.parse_args([
            "--apk", "x.apk",
            "--out-dir", "/tmp",
            "--application-id", "app-001",
        ])
        self.assertEqual(args.device_serial, "192.168.89.103:5555")

    def test_skip_install_flag(self):
        parser = build_parser()
        args = parser.parse_args([
            "--apk", "x.apk",
            "--out-dir", "/tmp",
            "--application-id", "app-001",
            "--skip-install",
        ])
        self.assertTrue(args.skip_install)


class MainStageTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _base_argv(self, skip_install=True):
        return [
            "--apk", str(self.out_dir / "dummy.apk"),
            "--out-dir", str(self.out_dir),
            "--application-id", "application-015",
            "--device-serial", "192.168.89.103:5555",
            *(["--skip-install"] if skip_install else []),
        ]

    def test_returns_2_when_device_not_ready(self):
        with patch("run_injuredandroid_stage._require_device",
                   side_effect=StageError("Device not ready")):
            result = main(self._base_argv())
        self.assertEqual(result, 2)

    def test_writes_stage_error_json_on_fatal_failure(self):
        with patch("run_injuredandroid_stage._require_device",
                   side_effect=StageError("Device not ready")):
            main(self._base_argv())

        error_file = self.out_dir / "runtime-events.stage-error.json"
        self.assertTrue(error_file.exists())
        data = json.loads(error_file.read_text(encoding="utf-8"))
        self.assertEqual(data["stage"], "injuredandroid_dynamic")
        self.assertIn("Device not ready", data["error"])

    def test_returns_2_when_frida_server_not_running(self):
        with patch("run_injuredandroid_stage._require_device"), \
                patch("run_injuredandroid_stage._require_frida_server",
                      side_effect=StageError("frida-server not running")):
            result = main(self._base_argv())
        self.assertEqual(result, 2)

    def test_returns_2_when_app_does_not_start(self):
        with patch("run_injuredandroid_stage._require_device"), \
                patch("run_injuredandroid_stage._require_frida_server"), \
                patch("run_injuredandroid_stage._launch_app"), \
                patch("run_injuredandroid_stage._require_pid",
                      side_effect=StageError("Process not found")):
            result = main(self._base_argv())
        self.assertEqual(result, 2)

    def test_hooks_list_includes_shim(self):
        self.assertIn("receiver_webview_shim", HOOKS)

    def test_hooks_list_includes_intent_and_webview(self):
        self.assertIn("intent", HOOKS)
        self.assertIn("webview", HOOKS)

    def test_install_skipped_when_flag_set(self):
        install_calls = []
        with patch("run_injuredandroid_stage._require_device"), \
                patch("run_injuredandroid_stage._require_frida_server"), \
                patch("run_injuredandroid_stage._install_apk",
                      side_effect=lambda *a, **k: install_calls.append(a)), \
                patch("run_injuredandroid_stage._launch_app"), \
                patch("run_injuredandroid_stage._require_pid", return_value="3763"), \
                patch("run_injuredandroid_stage._launch_receiver_activity"), \
                patch("run_injuredandroid_stage._run_collection", return_value=0):
            main(self._base_argv(skip_install=True))

        self.assertEqual(install_calls, [])

    def test_install_called_when_flag_not_set(self):
        apk = self.out_dir / "dummy.apk"
        apk.write_bytes(b"")
        install_calls = []
        with patch("run_injuredandroid_stage._require_device"), \
                patch("run_injuredandroid_stage._require_frida_server"), \
                patch("run_injuredandroid_stage._validate_apk"), \
                patch("run_injuredandroid_stage._install_apk",
                      side_effect=lambda *a, **k: install_calls.append(a)), \
                patch("run_injuredandroid_stage._launch_app"), \
                patch("run_injuredandroid_stage._require_pid", return_value="3763"), \
                patch("run_injuredandroid_stage._launch_receiver_activity"), \
                patch("run_injuredandroid_stage._run_collection", return_value=0):
            main([
                "--apk", str(apk),
                "--out-dir", str(self.out_dir),
                "--application-id", "application-015",
                "--device-serial", "192.168.89.103:5555",
            ])

        self.assertEqual(len(install_calls), 1)

    def test_returns_0_on_successful_collection(self):
        schema = {"application_id": "application-015", "events": []}
        (self.out_dir / "runtime-events.json").write_text(
            json.dumps(schema), encoding="utf-8"
        )
        with patch("run_injuredandroid_stage._require_device"), \
                patch("run_injuredandroid_stage._require_frida_server"), \
                patch("run_injuredandroid_stage._launch_app"), \
                patch("run_injuredandroid_stage._require_pid", return_value="3763"), \
                patch("run_injuredandroid_stage._launch_receiver_activity"), \
                patch("run_injuredandroid_stage._run_collection", return_value=0):
            result = main(self._base_argv())
        self.assertEqual(result, 0)

    def test_returns_1_on_collection_with_diagnostics(self):
        with patch("run_injuredandroid_stage._require_device"), \
                patch("run_injuredandroid_stage._require_frida_server"), \
                patch("run_injuredandroid_stage._launch_app"), \
                patch("run_injuredandroid_stage._require_pid", return_value="3763"), \
                patch("run_injuredandroid_stage._launch_receiver_activity"), \
                patch("run_injuredandroid_stage._run_collection", return_value=1):
            result = main(self._base_argv())
        self.assertEqual(result, 1)


class ApkValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _apk(self, name):
        p = self.out_dir / name
        p.write_bytes(b"")
        return p

    def test_raises_when_aapt_unavailable(self):
        apk = self._apk("InjuredAndroid-v1.0.9-release.apk")
        with patch("run_injuredandroid_stage.subprocess.run",
                   side_effect=FileNotFoundError):
            with self.assertRaises(StageError) as ctx:
                _validate_apk(apk)
        self.assertIn("aapt", str(ctx.exception).lower())

    def test_raises_when_aapt_times_out(self):
        apk = self._apk("InjuredAndroid.apk")
        with patch("run_injuredandroid_stage.subprocess.run",
                   side_effect=subprocess.TimeoutExpired("aapt", 30)):
            with self.assertRaises(StageError) as ctx:
                _validate_apk(apk)
        self.assertIn("timed out", str(ctx.exception).lower())

    def test_raises_when_aapt_returns_nonzero(self):
        apk = self._apk("InjuredAndroid.apk")
        fake_result = SimpleNamespace(returncode=1, stdout="", stderr="error: not a valid APK")
        with patch("run_injuredandroid_stage.subprocess.run", return_value=fake_result):
            with self.assertRaises(StageError) as ctx:
                _validate_apk(apk)
        self.assertIn("rc=1", str(ctx.exception))

    def test_accepts_correct_package_from_aapt(self):
        apk = self._apk("some-random-name.apk")
        aapt_out = f"package: name='{PACKAGE}' versionCode='9' versionName='1.0.9'"
        fake_result = SimpleNamespace(returncode=0, stdout=aapt_out, stderr="")
        with patch("run_injuredandroid_stage.subprocess.run", return_value=fake_result):
            _validate_apk(apk)  # must not raise

    def test_rejects_wrong_package_from_aapt(self):
        apk = self._apk("injuredandroid-fake.apk")
        aapt_out = "package: name='com.attacker.malware' versionCode='1'"
        fake_result = SimpleNamespace(returncode=0, stdout=aapt_out, stderr="")
        with patch("run_injuredandroid_stage.subprocess.run", return_value=fake_result):
            with self.assertRaises(StageError) as ctx:
                _validate_apk(apk)
        self.assertIn(PACKAGE, str(ctx.exception))

    def test_raises_when_aapt_reports_no_package_line(self):
        apk = self._apk("weird.apk")
        fake_result = SimpleNamespace(returncode=0, stdout="sdkVersion:'21'\n", stderr="")
        with patch("run_injuredandroid_stage.subprocess.run", return_value=fake_result):
            with self.assertRaises(StageError) as ctx:
                _validate_apk(apk)
        self.assertIn("package name", str(ctx.exception).lower())

    def test_main_rejects_wrong_apk_before_install(self):
        apk = self.out_dir / "com.example.other.apk"
        apk.write_bytes(b"")
        with patch("run_injuredandroid_stage.subprocess.run",
                   side_effect=FileNotFoundError), \
                patch("run_injuredandroid_stage._require_device"), \
                patch("run_injuredandroid_stage._require_frida_server"), \
                patch("run_injuredandroid_stage._install_apk") as mock_install:
            result = main([
                "--apk", str(apk),
                "--out-dir", str(self.out_dir),
                "--application-id", "app-001",
                "--device-serial", "192.168.89.103:5555",
            ])
        self.assertEqual(result, 2)
        mock_install.assert_not_called()


class OutputSchemaTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _run_with_schema(self, schema, collection_rc=0):
        (self.out_dir / "runtime-events.json").write_text(
            json.dumps(schema), encoding="utf-8"
        )
        with patch("run_injuredandroid_stage._require_device"), \
                patch("run_injuredandroid_stage._require_frida_server"), \
                patch("run_injuredandroid_stage._launch_app"), \
                patch("run_injuredandroid_stage._require_pid", return_value="3763"), \
                patch("run_injuredandroid_stage._launch_receiver_activity"), \
                patch("run_injuredandroid_stage._run_collection", return_value=collection_rc):
            return main([
                "--apk", str(self.out_dir / "dummy.apk"),
                "--out-dir", str(self.out_dir),
                "--application-id", "application-015",
                "--device-serial", "192.168.89.103:5555",
                "--skip-install",
            ])

    def test_output_schema_preserves_application_id(self):
        schema = {"application_id": "application-015", "events": []}
        self._run_with_schema(schema)
        written = json.loads(
            (self.out_dir / "runtime-events.json").read_text(encoding="utf-8")
        )
        self.assertEqual(written["application_id"], "application-015")

    def test_output_schema_has_events_key(self):
        schema = {"application_id": "application-015", "events": []}
        self._run_with_schema(schema)
        written = json.loads(
            (self.out_dir / "runtime-events.json").read_text(encoding="utf-8")
        )
        self.assertIn("events", written)

    def test_partial_capture_returns_nonzero(self):
        schema = {"application_id": "application-015", "events": []}
        result = self._run_with_schema(schema, collection_rc=1)
        self.assertEqual(result, 1)

    def test_successful_collection_returns_zero(self):
        # Collector returns 0 only when collection finished cleanly with no diagnostics.
        schema = {"application_id": "application-015", "events": [{"type": "method_call"}]}
        result = self._run_with_schema(schema, collection_rc=0)
        self.assertEqual(result, 0)


class RawEvidenceTests(unittest.TestCase):
    """Stage must not overwrite existing evidence files."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_stage_error_json_written_on_fatal_failure(self):
        with patch("run_injuredandroid_stage._require_device",
                   side_effect=StageError("no device")):
            main([
                "--apk", str(self.out_dir / "dummy.apk"),
                "--out-dir", str(self.out_dir),
                "--application-id", "app-001",
                "--device-serial", "192.168.89.103:5555",
                "--skip-install",
            ])
        error_file = self.out_dir / "runtime-events.stage-error.json"
        self.assertTrue(error_file.exists())
        data = json.loads(error_file.read_text(encoding="utf-8"))
        self.assertIn("error", data)
        self.assertIn("stage", data)

    def test_stage_error_json_not_written_on_success(self):
        schema = {"application_id": "app-001", "events": []}
        (self.out_dir / "runtime-events.json").write_text(
            json.dumps(schema), encoding="utf-8"
        )
        with patch("run_injuredandroid_stage._require_device"), \
                patch("run_injuredandroid_stage._require_frida_server"), \
                patch("run_injuredandroid_stage._launch_app"), \
                patch("run_injuredandroid_stage._require_pid", return_value="3763"), \
                patch("run_injuredandroid_stage._launch_receiver_activity"), \
                patch("run_injuredandroid_stage._run_collection", return_value=0):
            main([
                "--apk", str(self.out_dir / "dummy.apk"),
                "--out-dir", str(self.out_dir),
                "--application-id", "app-001",
                "--device-serial", "192.168.89.103:5555",
                "--skip-install",
            ])
        self.assertFalse((self.out_dir / "runtime-events.stage-error.json").exists())


class BackendContractTests(unittest.TestCase):
    """Verify the stage satisfies the backend runner contract."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_output_file_is_runtime_events_json(self):
        """Backend expects exactly {out_dir}/runtime-events.json."""
        schema = {"application_id": "application-015", "events": []}
        (self.out_dir / "runtime-events.json").write_text(
            json.dumps(schema), encoding="utf-8"
        )
        with patch("run_injuredandroid_stage._require_device"), \
                patch("run_injuredandroid_stage._require_frida_server"), \
                patch("run_injuredandroid_stage._launch_app"), \
                patch("run_injuredandroid_stage._require_pid", return_value="3763"), \
                patch("run_injuredandroid_stage._launch_receiver_activity"), \
                patch("run_injuredandroid_stage._run_collection", return_value=0):
            result = main([
                "--apk", str(self.out_dir / "dummy.apk"),
                "--out-dir", str(self.out_dir),
                "--application-id", "application-015",
                "--device-serial", "192.168.89.103:5555",
                "--skip-install",
            ])
        self.assertEqual(result, 0)
        output = self.out_dir / "runtime-events.json"
        self.assertTrue(output.exists())
        data = json.loads(output.read_text(encoding="utf-8"))
        self.assertIn("application_id", data)
        self.assertIn("events", data)

    def test_exit_code_2_on_fatal_prerequisite_failure(self):
        """Backend must be able to distinguish fatal setup from partial capture."""
        with patch("run_injuredandroid_stage._require_device",
                   side_effect=StageError("no device")):
            result = main([
                "--apk", str(self.out_dir / "dummy.apk"),
                "--out-dir", str(self.out_dir),
                "--application-id", "app-001",
                "--device-serial", "192.168.89.103:5555",
                "--skip-install",
            ])
        self.assertEqual(result, 2)

    def test_shim_hook_in_hooks_list(self):
        """Backend contract: shim must be loaded so the sink is reachable."""
        self.assertIn("receiver_webview_shim", HOOKS)


class HookReadinessOrderingTests(unittest.TestCase):
    """Broadcast must not be sent before the on_hooks_ready callback fires.

    These tests exercise the real _run_collection() function directly,
    using a mock collect_target_events.main that controls exactly when
    (or whether) it calls on_hooks_ready.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _argv(self):
        return [
            "--device-id", "192.168.89.103:5555",
            "--target", "3763",
            "--application-id", "app-001",
            "--hooks", "intent", "webview", "receiver_webview_shim",
            "--output", str(self.out_dir / "runtime-events.json"),
            "--duration", "20",
            "--startup-timeout", "20",
        ]

    def test_broadcast_not_sent_before_on_hooks_ready_fires(self):
        """_send_broadcast must only be called after on_hooks_ready is invoked."""
        import run_injuredandroid_stage as stage

        call_log = []

        def fake_collect_main(argv, on_hooks_ready=None):
            # Record that hooks are ready, then call the callback.
            call_log.append("hooks_ready")
            if on_hooks_ready is not None:
                on_hooks_ready()
            return 0

        broadcast_called = threading.Event()
        original_send = stage._send_broadcast

        def recording_send(serial):
            call_log.append("broadcast")
            broadcast_called.set()
            return True

        with patch("run_injuredandroid_stage._collect_target_events") as mock_cte, \
                patch("run_injuredandroid_stage._send_broadcast",
                      side_effect=recording_send):
            mock_cte.main.side_effect = fake_collect_main
            stage._run_collection(
                "192.168.89.103:5555", "3763", "app-001", str(self.out_dir)
            )

        # hooks_ready must appear before broadcast in the log
        self.assertIn("hooks_ready", call_log)
        self.assertIn("broadcast", call_log)
        self.assertLess(
            call_log.index("hooks_ready"),
            call_log.index("broadcast"),
            msg="broadcast was sent before on_hooks_ready fired",
        )

    def test_broadcast_sent_even_when_hooks_ready_times_out(self):
        """If hooks never signal ready, the stage warns and sends the broadcast anyway."""
        import run_injuredandroid_stage as stage

        broadcast_called = threading.Event()

        def fake_collect_main(argv, on_hooks_ready=None):
            # Deliberately never call on_hooks_ready — simulates hook timeout.
            return 1

        def recording_send(serial):
            broadcast_called.set()
            return True

        with patch("run_injuredandroid_stage._collect_target_events") as mock_cte, \
                patch("run_injuredandroid_stage._send_broadcast",
                      side_effect=recording_send), \
                patch("run_injuredandroid_stage._HOOK_STARTUP_TIMEOUT", 0):
            mock_cte.main.side_effect = fake_collect_main
            result = stage._run_collection(
                "192.168.89.103:5555", "3763", "app-001", str(self.out_dir)
            )

        # Broadcast must still be attempted; result must be non-zero.
        self.assertTrue(broadcast_called.is_set(), "broadcast was never sent")
        self.assertNotEqual(result, 0)

    def test_broadcast_not_sent_before_ready_when_hooks_init_fails(self):
        """If hook init fails immediately, broadcast fires after the failure is recorded."""
        import run_injuredandroid_stage as stage

        call_log = []

        def fake_collect_main(argv, on_hooks_ready=None):
            # Simulate hook init failure: never call on_hooks_ready, return 1 fast.
            call_log.append("collect_returned")
            return 1

        def recording_send(serial):
            call_log.append("broadcast")
            return True

        with patch("run_injuredandroid_stage._collect_target_events") as mock_cte, \
                patch("run_injuredandroid_stage._send_broadcast",
                      side_effect=recording_send), \
                patch("run_injuredandroid_stage._HOOK_STARTUP_TIMEOUT", 0):
            mock_cte.main.side_effect = fake_collect_main
            result = stage._run_collection(
                "192.168.89.103:5555", "3763", "app-001", str(self.out_dir)
            )

        # collect must have returned before broadcast was attempted
        self.assertIn("collect_returned", call_log)
        self.assertIn("broadcast", call_log)
        self.assertLess(
            call_log.index("collect_returned"),
            call_log.index("broadcast"),
            msg="broadcast was sent before collect_target_events.main returned",
        )
        self.assertNotEqual(result, 0)


class CollectorTimeoutTests(unittest.TestCase):
    """Stage must report failure when the collector thread does not finish in time."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_returns_nonzero_when_collector_thread_times_out(self):
        """_run_collection returns 1 when the collector thread outlives the join timeout."""
        import run_injuredandroid_stage as stage

        hang = threading.Event()

        def hanging_collect_main(argv, on_hooks_ready=None):
            if on_hooks_ready is not None:
                on_hooks_ready()  # signal ready so broadcast fires
            hang.wait(timeout=30)  # block until the test releases it
            return 0

        with patch("run_injuredandroid_stage._collect_target_events") as mock_cte, \
                patch("run_injuredandroid_stage._send_broadcast", return_value=True), \
                patch("run_injuredandroid_stage._COLLECTION_WINDOW_SECONDS", 0), \
                patch("run_injuredandroid_stage._BROADCAST_SETTLE_SECONDS", 0), \
                patch("run_injuredandroid_stage._COLLECTOR_JOIN_GRACE_SECONDS", 0):
            mock_cte.main.side_effect = hanging_collect_main
            result = stage._run_collection(
                "192.168.89.103:5555", "3763", "app-001", str(self.out_dir)
            )
            hang.set()  # release the hung thread so the daemon can exit cleanly

        self.assertEqual(result, 1, "expected exit code 1 when collector thread timed out")

    def test_stage_does_not_report_success_on_collector_timeout(self):
        """main() must propagate the non-zero exit code from _run_collection."""
        with patch("run_injuredandroid_stage._run_collection", return_value=1), \
                patch("run_injuredandroid_stage._require_device"), \
                patch("run_injuredandroid_stage._require_frida_server"), \
                patch("run_injuredandroid_stage._launch_app"), \
                patch("run_injuredandroid_stage._require_pid", return_value="3763"), \
                patch("run_injuredandroid_stage._launch_receiver_activity"):
            result = main([
                "--apk", str(self.out_dir / "dummy.apk"),
                "--out-dir", str(self.out_dir),
                "--application-id", "app-001",
                "--device-serial", "192.168.89.103:5555",
                "--skip-install",
            ])
        self.assertEqual(result, 1)

    def test_collector_timeout_does_not_overwrite_partial_output(self):
        """If the collector times out but partial output exists, it must be preserved."""
        import run_injuredandroid_stage as stage

        partial = self.out_dir / "runtime-events.json"
        partial.write_text('{"application_id": "app-001", "events": []}',
                           encoding="utf-8")

        hang = threading.Event()

        def hanging_collect_main(argv, on_hooks_ready=None):
            if on_hooks_ready is not None:
                on_hooks_ready()
            hang.wait(timeout=30)
            return 0

        with patch("run_injuredandroid_stage._collect_target_events") as mock_cte, \
                patch("run_injuredandroid_stage._send_broadcast", return_value=True), \
                patch("run_injuredandroid_stage._COLLECTION_WINDOW_SECONDS", 0), \
                patch("run_injuredandroid_stage._BROADCAST_SETTLE_SECONDS", 0), \
                patch("run_injuredandroid_stage._COLLECTOR_JOIN_GRACE_SECONDS", 0):
            mock_cte.main.side_effect = hanging_collect_main
            stage._run_collection(
                "192.168.89.103:5555", "3763", "app-001", str(self.out_dir)
            )
            hang.set()

        # The pre-existing partial output must not have been deleted or zeroed.
        self.assertTrue(partial.exists(), "partial output file was deleted on timeout")
        import json as _json
        data = _json.loads(partial.read_text(encoding="utf-8"))
        self.assertIn("events", data)


if __name__ == "__main__":
    unittest.main()
