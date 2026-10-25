import sys
import unittest
from pathlib import Path

# Locate the static-analysis directory.
STATIC_ANALYSIS_DIR = Path(__file__).resolve().parents[1]

# Make analyzer.py importable.
sys.path.insert(0, str(STATIC_ANALYSIS_DIR))

from analyzer import analyze_direct_flows


class TestInlineDataFlow(unittest.TestCase):

    def test_intent_extra_to_webview_load_url(self):
        java_lines = [
            '((WebView) findViewById(R.id.Bob)).loadUrl('
            'intent.getExtras().getString("url"));'
        ]

        findings = analyze_direct_flows(
            java_lines,
            "TestBroadcastReceiver.java"
        )

        self.assertEqual(len(findings), 1)

        finding = findings[0]

        self.assertEqual(
            finding["source"]["type"],
            "intent_extra"
        )

        self.assertEqual(
            finding["sink"]["type"],
            "webview_load_url"
        )

        self.assertEqual(
            finding["evidence"]["source_line"],
            1
        )

        self.assertEqual(
            finding["evidence"]["sink_line"],
            1
        )


if __name__ == "__main__":
    unittest.main()
