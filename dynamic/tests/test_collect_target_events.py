import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from collect_target_events import events_for_schema


class TargetEventSchemaTests(unittest.TestCase):
    def test_selects_only_target_method_calls_and_preserves_observations(self):
        raw_events = [
            {"event_type": "hook_status", "class": "java.lang.Runtime", "method": "runtime_exec_hook"},
            {
                "event_type": "method_call",
                "timestamp": "2026-10-24T09:00:00.000Z",
                "class": "java.lang.Runtime",
                "method": "exec",
                "arguments": ["echo harmless"],
                "metadata": {},
            },
            {
                "event_type": "method_call",
                "timestamp": "2026-10-24T09:00:01.000Z",
                "class": "android.webkit.WebView",
                "method": "loadUrl",
                "arguments": ["https://example.invalid"],
                "metadata": {},
            },
            {
                "event_type": "method_call",
                "timestamp": "2026-10-24T09:00:02.000Z",
                "class": "java.lang.Runtime",
                "method": "availableProcessors",
                "arguments": [],
            },
        ]

        result = events_for_schema(raw_events, "exact-app-id")

        self.assertEqual(result["application_id"], "exact-app-id")
        self.assertEqual(
            result["events"],
            [
                {
                    "id": "event-001",
                    "type": "method_call",
                    "class": "java.lang.Runtime",
                    "method": "exec",
                    "arguments": ["echo harmless"],
                    "timestamp": "2026-10-24T09:00:00.000Z",
                },
                {
                    "id": "event-002",
                    "type": "method_call",
                    "class": "android.webkit.WebView",
                    "method": "loadUrl",
                    "arguments": ["https://example.invalid"],
                    "timestamp": "2026-10-24T09:00:01.000Z",
                },
            ],
        )

    def test_rejects_malformed_observed_sink_event(self):
        with self.assertRaisesRegex(ValueError, "arguments or timestamp"):
            events_for_schema(
                [
                    {
                        "event_type": "method_call",
                        "class": "java.lang.Runtime",
                        "method": "exec",
                        "arguments": "not-an-array",
                    }
                ],
                "exact-app-id",
            )

    def test_rejects_missing_application_id(self):
        with self.assertRaisesRegex(ValueError, "application_id"):
            events_for_schema([], "  ")


if __name__ == "__main__":
    unittest.main()
