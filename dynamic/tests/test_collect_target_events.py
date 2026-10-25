import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collect_target_events import build_parser, events_for_schema

_WEBVIEW_EVENT = {
    "event_type": "method_call",
    "timestamp": "2026-10-24T09:00:01.000Z",
    "class": "android.webkit.WebView",
    "method": "loadUrl",
    "arguments": ["https://example.invalid"],
    "metadata": {},
}

_RECEIVER_EVENT = {
    "event_type": "method_call",
    "timestamp": "2026-10-24T09:00:00.000Z",
    "class": "b3nac.injuredandroid.TestBroadcastReceiver",
    "method": "onReceive",
    "arguments": ["com.b3nac.injuredandroid.intent.action.CUSTOM_INTENT", "about:blank"],
    "metadata": {
        "broadcast_action": "com.b3nac.injuredandroid.intent.action.CUSTOM_INTENT",
        "extra_key": "url",
        "extra_value": "about:blank",
    },
}


class TargetEventSchemaTests(unittest.TestCase):
    def test_includes_webview_loadurl_event(self):
        result = events_for_schema([_WEBVIEW_EVENT], "app-001")

        self.assertEqual(len(result["events"]), 1)
        event = result["events"][0]
        self.assertEqual(event["class"], "android.webkit.WebView")
        self.assertEqual(event["method"], "loadUrl")
        self.assertEqual(event["arguments"], ["https://example.invalid"])
        self.assertEqual(event["timestamp"], "2026-10-24T09:00:01.000Z")
        self.assertEqual(event["type"], "method_call")

    def test_includes_broadcast_receiver_onreceive_event(self):
        result = events_for_schema([_RECEIVER_EVENT], "app-001")

        self.assertEqual(len(result["events"]), 1)
        event = result["events"][0]
        self.assertEqual(event["class"], "b3nac.injuredandroid.TestBroadcastReceiver")
        self.assertEqual(event["method"], "onReceive")
        self.assertEqual(
            event["arguments"],
            ["com.b3nac.injuredandroid.intent.action.CUSTOM_INTENT", "about:blank"],
        )
        self.assertEqual(event["type"], "method_call")

    def test_sequential_ids_across_multiple_events(self):
        result = events_for_schema([_RECEIVER_EVENT, _WEBVIEW_EVENT], "app-001")

        ids = [e["id"] for e in result["events"]]
        self.assertEqual(ids, ["event-001", "event-002"])

    def test_preserves_exact_application_id(self):
        result = events_for_schema([_WEBVIEW_EVENT], "application-015")

        self.assertEqual(result["application_id"], "application-015")

    def test_excludes_hook_status_events(self):
        hook_status = {
            "event_type": "hook_status",
            "class": "android.app.Activity",
            "method": "intent_hook",
            "arguments": [],
            "timestamp": "2026-10-24T09:00:00.000Z",
            "metadata": {"status": "ready"},
        }
        result = events_for_schema([hook_status, _WEBVIEW_EVENT], "app-001")

        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["method"], "loadUrl")

    def test_includes_runtime_exec_event_with_observed_arguments(self):
        runtime_exec_event = {
            "event_type": "method_call",
            "timestamp": "2026-10-24T09:00:00.000Z",
            "class": "java.lang.Runtime",
            "method": "exec",
            "arguments": ["echo harmless"],
            "metadata": {},
        }
        result = events_for_schema([runtime_exec_event, _WEBVIEW_EVENT], "app-001")

        event = result["events"][0]
        self.assertEqual(event["class"], "java.lang.Runtime")
        self.assertEqual(event["method"], "exec")
        self.assertEqual(event["arguments"], ["echo harmless"])
        self.assertEqual(len(result["events"]), 2)

    def test_excludes_unrelated_method_call_events(self):
        unrelated = {
            "event_type": "method_call",
            "timestamp": "2026-10-24T09:00:02.000Z",
            "class": "java.lang.Runtime",
            "method": "availableProcessors",
            "arguments": [],
            "metadata": {},
        }
        result = events_for_schema([unrelated], "app-001")

        self.assertEqual(result["events"], [])

    def test_rejects_malformed_observed_sink_event_missing_arguments(self):
        bad = {
            "event_type": "method_call",
            "class": "android.webkit.WebView",
            "method": "loadUrl",
            "arguments": "not-an-array",
            "timestamp": "2026-10-24T09:00:00.000Z",
        }
        with self.assertRaisesRegex(ValueError, "arguments or timestamp"):
            events_for_schema([bad], "app-001")

    def test_rejects_malformed_observed_sink_event_missing_timestamp(self):
        bad = {
            "event_type": "method_call",
            "class": "android.webkit.WebView",
            "method": "loadUrl",
            "arguments": ["https://example.invalid"],
        }
        with self.assertRaisesRegex(ValueError, "missing required fields"):
            events_for_schema([bad], "app-001")

    def test_rejects_non_object_event(self):
        with self.assertRaisesRegex(ValueError, "non-object event"):
            events_for_schema(["not-a-dict"], "app-001")

    def test_rejects_missing_application_id(self):
        with self.assertRaisesRegex(ValueError, "application_id"):
            events_for_schema([], "  ")

    def test_rejects_empty_application_id(self):
        with self.assertRaisesRegex(ValueError, "application_id"):
            events_for_schema([], "")

    def test_schema_output_contains_only_id_type_class_method_arguments_timestamp(self):
        result = events_for_schema([_WEBVIEW_EVENT], "app-001")

        event = result["events"][0]
        self.assertEqual(set(event.keys()), {"id", "type", "class", "method", "arguments", "timestamp"})

    def test_default_hooks_include_runtime_exec(self):
        parser = build_parser()
        # parse with only the required --application-id and a dummy --target
        # (build_parser sets defaults; we inspect them without running collection)
        defaults = parser.parse_args(["--target", "dummy", "--application-id", "app-001"])
        self.assertIn("runtime_exec", defaults.hooks)

    def test_default_hooks_include_intent_and_webview(self):
        parser = build_parser()
        defaults = parser.parse_args(["--target", "dummy", "--application-id", "app-001"])
        self.assertIn("intent", defaults.hooks)
        self.assertIn("webview", defaults.hooks)

    def test_empty_raw_events_returns_empty_events_list(self):
        result = events_for_schema([], "application-015")

        self.assertEqual(result, {"application_id": "application-015", "events": []})

    def test_receiver_event_class_is_outer_not_inner_dollar_b(self):
        # The hook targets b3nac.injuredandroid.TestBroadcastReceiver$b at the
        # Frida level but emits the outer class name so the schema stays stable.
        # An event carrying the inner-class name must NOT be included.
        inner_class_event = {
            "event_type": "method_call",
            "timestamp": "2026-10-24T09:00:00.000Z",
            "class": "b3nac.injuredandroid.TestBroadcastReceiver$b",
            "method": "onReceive",
            "arguments": ["com.b3nac.injuredandroid.intent.action.CUSTOM_INTENT", "about:blank"],
            "metadata": {},
        }
        result = events_for_schema([inner_class_event], "app-001")
        self.assertEqual(result["events"], [])


if __name__ == "__main__":
    unittest.main()
