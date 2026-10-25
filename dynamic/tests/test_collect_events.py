import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collect_events import (
    EventCollector,
    HOOK_STATUS_METHODS,
    diagnostics_path,
    prepare_hook_source,
    run_collection,
)


class FakeScript:
    def __init__(self, messages):
        self.callback = None
        self.messages = messages
        self.unloaded = False
        self.posted_messages = []

    def on(self, event_name, callback):
        if event_name == "message":
            self.callback = callback

    def load(self):
        for message in self.messages:
            self.callback(message, None)

    def unload(self):
        self.unloaded = True

    def post(self, message):
        self.posted_messages.append(message)


class FakeSession:
    def __init__(self, messages):
        self.messages = messages
        self.scripts = []
        self.script_sources = []
        self.script_runtimes = []
        self.detached = False

    def create_script(self, source, name=None, runtime=None):
        script = FakeScript(self.messages.get(name, []))
        self.scripts.append(script)
        self.script_sources.append(source)
        self.script_runtimes.append(runtime)
        return script

    def detach(self):
        self.detached = True


class EventCollectorTests(unittest.TestCase):
    def setUp(self):
        self.errors = StringIO()
        self.collector = EventCollector(error_stream=self.errors)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_path = Path(self.temp_dir.name) / "nested" / "runtime-events.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_captures_multiple_send_payloads_without_changing_them(self):
        first = {
            "event_type": "intent_incoming",
            "metadata": {"primitive_extras": [{"key": "test_url", "value": "file:///local"}]},
        }
        second = {
            "event_type": "method_call",
            "class": "android.webkit.WebView",
            "method": "loadUrl",
            "arguments": ["file:///local"],
        }

        self.collector.on_message({"type": "send", "payload": first})
        self.collector.on_message({"type": "send", "payload": second})
        self.collector.export(self.output_path)

        self.assertEqual(json.loads(self.output_path.read_text(encoding="utf-8")), [first, second])
        self.assertEqual(self.collector.diagnostics, [])
        self.assertEqual(self.errors.getvalue(), "")

    def test_exports_valid_empty_array_and_empty_diagnostics(self):
        self.collector.export(self.output_path)

        self.assertEqual(json.loads(self.output_path.read_text(encoding="utf-8")), [])
        self.assertEqual(
            json.loads(diagnostics_path(self.output_path).read_text(encoding="utf-8")),
            [],
        )

    def test_records_frida_errors_separately_from_events(self):
        message = {
            "type": "error",
            "description": "hook initialization failed",
            "stack": "example stack",
            "lineNumber": 42,
        }
        self.collector.on_message(message)
        self.collector.export(self.output_path)

        self.assertEqual(json.loads(self.output_path.read_text(encoding="utf-8")), [])
        self.assertEqual(
            json.loads(diagnostics_path(self.output_path).read_text(encoding="utf-8")),
            [{"kind": "frida_error", "message": message}],
        )
        self.assertIn("hook initialization failed", self.errors.getvalue())

    def test_records_logs_separately_from_events(self):
        message = {"type": "log", "level": "warning", "payload": "hook warning"}
        self.collector.on_message(message)
        self.collector.export(self.output_path)

        self.assertEqual(json.loads(self.output_path.read_text(encoding="utf-8")), [])
        diagnostics = json.loads(diagnostics_path(self.output_path).read_text(encoding="utf-8"))
        self.assertEqual(diagnostics, [{"kind": "frida_log", "message": message}])
        self.assertIn("hook warning", self.errors.getvalue())

    def test_rejects_non_object_payload_and_preserves_diagnostic(self):
        message = {"type": "send", "payload": ["not", "an", "event"]}
        self.collector.on_message(message)
        self.collector.export(self.output_path)

        self.assertEqual(json.loads(self.output_path.read_text(encoding="utf-8")), [])
        diagnostics = json.loads(diagnostics_path(self.output_path).read_text(encoding="utf-8"))
        self.assertEqual(diagnostics[0]["kind"], "collector_error")
        self.assertEqual(diagnostics[0]["message"], message)
        self.assertTrue(self.errors.getvalue())

    def test_rejects_non_json_payload_and_preserves_diagnostic(self):
        message = {"type": "send", "payload": {"invalid": float("nan")}}
        self.collector.on_message(message)
        self.collector.export(self.output_path)

        self.assertEqual(json.loads(self.output_path.read_text(encoding="utf-8")), [])
        diagnostics = json.loads(diagnostics_path(self.output_path).read_text(encoding="utf-8"))
        self.assertEqual(diagnostics[0]["kind"], "collector_error")
        self.assertIn("non-JSON", diagnostics[0]["description"])

    def test_creates_output_parent_directories(self):
        self.assertFalse(self.output_path.parent.exists())

        self.collector.export(self.output_path)

        self.assertTrue(self.output_path.is_file())
        self.assertTrue(diagnostics_path(self.output_path).is_file())

    def test_prepares_hook_with_cli_compatible_java_bridge(self):
        hook_source = "Java.perform(function () { send({event_type: 'test'}); });"
        bridge_source = "var bridge = { available: true };"

        prepared_source = prepare_hook_source(hook_source, bridge_source)

        self.assertIn(
            "Script.evaluate('/frida/bridges/java.js'",
            prepared_source,
        )
        self.assertIn(
            "Object.defineProperty(globalThis, 'Java', { value: bridge });",
            prepared_source,
        )
        self.assertIn("if (!Java.available)", prepared_source)
        self.assertIn(
            "if (typeof Java === 'undefined')",
            prepared_source,
        )
        self.assertIn(
            "Java bridge evaluation did not define Java in this script runtime",
            prepared_source,
        )
        self.assertLess(
            prepared_source.index("Script.evaluate"),
            prepared_source.index(hook_source),
        )
        self.assertTrue(prepared_source.endswith(hook_source))

    def test_waits_for_selected_hook_ready_status(self):
        ready_event = {
            "event_type": "hook_status",
            "method": "intent_hook",
            "metadata": {"status": "ready"},
        }

        self.assertFalse(self.collector.wait_for_hooks(["intent"], timeout=0))
        self.collector.on_message({"type": "send", "payload": ready_event})
        self.assertTrue(self.collector.wait_for_hooks(["intent"], timeout=0))
        self.assertFalse(self.collector.wait_for_hooks(["intent", "webview"], timeout=0))

    def test_does_not_mark_hook_ready_on_initialization_error(self):
        self.collector.on_message(
            {
                "type": "error",
                "description": "Java is not defined",
                "stack": "initialization failed",
            }
        )

        self.assertFalse(self.collector.wait_for_hooks(["intent"], timeout=0))
        self.assertIn(
            "Frida reported startup diagnostics",
            self.collector.hook_startup_error(["intent"]),
        )

    def _run_fake_collection(self, duration, hook_messages=None):
        hook_method = HOOK_STATUS_METHODS["intent"]
        event = {
            "event_type": "hook_status",
            "method": hook_method,
            "metadata": {"status": "ready"},
        }
        if hook_messages is None:
            hook_messages = [{"type": "send", "payload": event}]
        session = FakeSession({"intent": hook_messages})
        device = SimpleNamespace(
            name="test-device",
            attach=lambda target: session,
        )
        manager = SimpleNamespace(
            get_device=lambda device_id: device,
            get_usb_device=lambda timeout: device,
        )
        frida = SimpleNamespace(get_device_manager=lambda: manager)
        args = SimpleNamespace(
            verbose=False,
            duration=duration,
            device_id=None,
            target="123",
            hooks=["intent"],
            output=self.output_path,
            startup_timeout=1,
        )
        return args, frida, session

    def test_run_collection_exports_events_and_detaches_on_normal_shutdown(self):
        args, frida, session = self._run_fake_collection(duration=1)
        stderr = StringIO()

        with patch("collect_events._load_frida", return_value=frida), \
                patch("collect_events.load_java_bridge_source", return_value="var bridge = {};"), \
                patch("collect_events.time.monotonic", side_effect=[0, 0, 1]), \
                redirect_stderr(stderr):
            result = run_collection(args)

        self.assertEqual(result, 0)
        self.assertEqual(
            json.loads(self.output_path.read_text(encoding="utf-8")),
            [
                {
                    "event_type": "hook_status",
                    "method": "intent_hook",
                    "metadata": {"status": "ready"},
                }
            ],
        )
        self.assertTrue(session.scripts[0].unloaded)
        self.assertTrue(session.detached)

    def test_run_collection_exports_events_and_detaches_after_ctrl_c(self):
        args, frida, session = self._run_fake_collection(duration=0)
        stderr = StringIO()

        with patch("collect_events._load_frida", return_value=frida), \
                patch("collect_events.load_java_bridge_source", return_value="var bridge = {};"), \
                patch("collect_events.time.sleep", side_effect=KeyboardInterrupt), \
                redirect_stderr(stderr):
            result = run_collection(args)

        self.assertEqual(result, 0)
        self.assertEqual(
            json.loads(self.output_path.read_text(encoding="utf-8")),
            [
                {
                    "event_type": "hook_status",
                    "method": "intent_hook",
                    "metadata": {"status": "ready"},
                }
            ],
        )
        self.assertTrue(session.scripts[0].unloaded)
        self.assertTrue(session.detached)

    def test_run_collection_reports_initialization_failure_without_claiming_ready(self):
        args, frida, session = self._run_fake_collection(
            duration=1,
            hook_messages=[
                {
                    "type": "error",
                    "description": "Java is not defined",
                    "stack": "initialization failed",
                }
            ],
        )
        stderr = StringIO()

        with patch("collect_events._load_frida", return_value=frida), \
                patch("collect_events.load_java_bridge_source", return_value="var bridge = {};"), \
                redirect_stderr(stderr):
            result = run_collection(args)

        self.assertEqual(result, 1)
        self.assertNotIn("Hooks initialized", stderr.getvalue())
        self.assertIn("Java is not defined", stderr.getvalue())
        self.assertEqual(json.loads(self.output_path.read_text(encoding="utf-8")), [])
        diagnostics = json.loads(
            diagnostics_path(self.output_path).read_text(encoding="utf-8")
        )
        self.assertEqual(diagnostics[0]["kind"], "frida_error")
        self.assertEqual(diagnostics[1]["kind"], "hook_initialization_error")
        self.assertTrue(session.detached)

    def test_run_collection_selects_qjs_and_prepends_java_bridge(self):
        args, frida, session = self._run_fake_collection(duration=1)
        stderr = StringIO()

        with patch("collect_events._load_frida", return_value=frida), \
                patch("collect_events.load_java_bridge_source", return_value="var bridge = {};"), \
                patch("collect_events.time.monotonic", side_effect=[0, 0, 1]), \
                redirect_stderr(stderr):
            result = run_collection(args)

        self.assertEqual(result, 0)
        self.assertEqual(session.script_runtimes, ["qjs"])
        self.assertIn("Script.evaluate('/frida/bridges/java.js'", session.script_sources[0])
        self.assertIn("if (typeof Java === 'undefined')", session.script_sources[0])
        self.assertIn("if (!Java.available)", session.script_sources[0])
        self.assertIn("Java.perform(function ()", session.script_sources[0])


if __name__ == "__main__":
    unittest.main()
