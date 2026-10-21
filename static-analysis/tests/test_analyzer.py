import sys
import unittest
from pathlib import Path

STATIC_ANALYSIS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STATIC_ANALYSIS_DIR))

from analyzer import (
    analyze_direct_flows,
    analyze_runtime_exec_flows,
    analyze_sql_flows,
)
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


    def test_uri_parameter_name_does_not_matter(self):
        java_lines = [
            'String command = uri.getQueryParameter("command");',
            'StringBuilder sb = new StringBuilder();',
            'sb.append(command);',
            'Runtime.getRuntime().exec(sb.toString());',
        ]

        findings = analyze_runtime_exec_flows(
            java_lines,
            "CommandActivity.java",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["source"]["variable"],
            "command",
        )
        self.assertEqual(
            findings[0]["sink"]["type"],
            "runtime_exec",
        )


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


    def test_constant_command_has_no_uri_source_finding(self):
        java_lines = [
            'StringBuilder sb = new StringBuilder();',
            'sb.append("ls");',
            'Runtime.getRuntime().exec(sb.toString());',
        ]

        findings = analyze_runtime_exec_flows(
            java_lines,
            "ConstantCommandActivity.java",
        )

        self.assertEqual(findings, [])
    def test_intent_extra_to_sql_exec(self):
        java_lines = [
            'String username = intent.getStringExtra("username");',
            'String query = "SELECT * FROM users WHERE name = \'" + username;',
            'database.execSQL(query);',
        ]

        findings = analyze_sql_flows(
            java_lines,
            "DatabaseActivity.java",
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0]["source"]["type"],
            "intent_extra",
        )
        self.assertEqual(
            findings[0]["sink"]["type"],
            "sql_exec",
        )
if __name__ == "__main__":
    unittest.main()
