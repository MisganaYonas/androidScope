import sys
import unittest
from pathlib import Path

STATIC_ANALYSIS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STATIC_ANALYSIS_DIR))

from analyzer import analyze_direct_flows, analyze_runtime_exec_flows

class TestStaticAnalyzer(unittest.TestCase):


    def test_uri_parameter_to_runtime_exec(self):
        java_lines = [
        'String binary = uri.getQueryParameter("binary");',
        'StringBuilder sb = new StringBuilder();',
        'sb.append(binary);',
        'Runtime.getRuntime().exec(sb.toString());',
        ]

        findings = analyze_runtime_exec_flows(
            java_lines,
            "TestActivity.java",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source"]["type"], "uri_parameter")
        self.assertEqual(findings[0]["sink"]["type"], "runtime_exec")
        self.assertEqual(findings[0]["evidence"]["source_line"], 1)
        self.assertEqual(findings[0]["evidence"]["sink_line"], 4)

    def test_no_matching_flow(self):
        java_lines = [
            'String message = "Hello";',
            'System.out.println(message);',
        ]

        findings = analyze_direct_flows(
            java_lines,
            "OrdinaryActivity.java",
        )

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
