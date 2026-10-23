import hashlib
import os
import argparse
import json
import re
import sys
from pathlib import Path


# --------------------------------------------------
# 1. Project paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

SAMPLES_DIR = BASE_DIR / "samples"
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_FILE = OUTPUT_DIR / "findings.json"

DECOMPILED_DIR = (
    BASE_DIR
    / "decompiled"
    / "app"
    / "src"
    / "main"
    / "java"
    / "b3nac"
    / "injuredandroid"
)


# --------------------------------------------------
# 2. Source patterns
# --------------------------------------------------

SOURCE_PATTERNS = {
    "intent_extra": re.compile(
        r'\b(\w+)\s*=\s*'
        r'\w+\.getStringExtra\(\s*"([^"]+)"\s*\)'
    ),

    "intent_data": re.compile(
        r'\b(\w+)\s*=\s*'
        r'\w+\.getData\(\s*\)'
    ),

    "bundle_value": re.compile(
        r'\b(\w+)\s*=\s*'
        r'\w+\.(?:getArguments|getExtras)\(\)'
    ),

    "uri_parameter": re.compile(
        r'\b(\w+)\s*=\s*'
        r'\w+\.getQueryParameter\(\s*"([^"]+)"\s*\)'
    ),
}


# --------------------------------------------------
# 3. Direct sink patterns
# --------------------------------------------------

DIRECT_SINK_PATTERNS = {
    "webview_load_url": re.compile(
        r'\b\w+\.loadUrl\(\s*(\w+)\s*\)'
    ),

    "sql_exec": re.compile(
        r'\b\w+\.execSQL\('
    ),
}
SINK_METADATA = {
    "webview_load_url": {
        "class": "android.webkit.WebView",
        "method": "loadUrl",
    },
    "runtime_exec": {
        "class": "java.lang.Runtime",
        "method": "exec",
    },
    "sql_exec": {
        "class": "android.database.sqlite.SQLiteDatabase",
        "method": "execSQL",
    },
    "sql_raw_query": {
        "class": "android.database.sqlite.SQLiteDatabase",
        "method": "rawQuery",
    },
}



# --------------------------------------------------
# 4. Utility functions
# --------------------------------------------------
def to_relative_path(path):
    """Return a path relative to the AndroidScope project root."""

    path = Path(path).resolve()

    try:
        return path.relative_to(PROJECT_ROOT).as_posix()

    except ValueError:
        return Path(
            os.path.relpath(path, PROJECT_ROOT)
        ).as_posix()
def get_fully_qualified_class(lines, file_path):
    """
    Return the fully qualified Java class name.

    Example:
        package b3nac.injuredandroid;
        public class RCEActivity

    Result:
        b3nac.injuredandroid.RCEActivity
    """

    package_name = ""

    for line in lines:
        package_match = re.match(
            r"\s*package\s+([\w.]+)\s*;",
            line,
        )

        if package_match:
            package_name = package_match.group(1)
            break

    class_name = None

    class_pattern = re.compile(
        r"\b(?:public\s+|protected\s+|private\s+|abstract\s+|final\s+|"
        r"static\s+)*"
        r"(?:class|interface|enum|record)\s+(\w+)"
    )

    for line in lines:
        class_match = class_pattern.search(line)

        if class_match:
            class_name = class_match.group(1)
            break

    if class_name is None:
        class_name = Path(file_path).stem

    if package_name:
        return f"{package_name}.{class_name}"

    return class_name
def make_finding_id(file_path, source_line, sink_line, flow_type):
    """
    Generate a repeatable ID for a finding.
    """

    identity = (
        f"{file_path}:{source_line}:{sink_line}:{flow_type}"
    )

    digest = hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:12]

    return f"static-{digest}"


def create_finding(
    file_path,
    class_name,
    source_type,
    source_variable,
    source_expression,
    source_line,
    sink_type,
    sink_expression,
    sink_line,
    path,
):
    """
    Create a structured candidate finding.
    """

    return {
        "id": make_finding_id(
            str(file_path),
            source_line,
            sink_line,
            sink_type,
        ),
        "type": "candidate_data_flow",
        "class": class_name,
        "source": {
            "type": source_type,
            "variable": source_variable,
            "expression": source_expression,
            "line": source_line,
        },
       "sink": {
           "type": sink_type,
           "class": SINK_METADATA.get(sink_type, {}).get("class"),
           "method": SINK_METADATA.get(sink_type, {}).get("method"),
           "expression": sink_expression,
           "line": sink_line,
     },

        "data_flow": {
            "variable": source_variable,
            "path": path,
        },
        "evidence": {
            "file": to_relative_path(file_path),
            "source_line": source_line,
            "sink_line": sink_line,
        },
        "analysis": {
            "confidence": "low",
            "status": "candidate",
            "limitations": [
                "Detection uses regular expressions, not semantic analysis.",
                "The analyzer does not prove attacker control of the input.",
               "The analyzer does not fully resolve aliases or interprocedural flows.",
                "The analyzer does not prove that a vulnerability is exploitable.",
                "Validation and sanitization require further inspection.",
            ],
        },
    }


# --------------------------------------------------
# 5. Detect direct source-to-sink flows
# --------------------------------------------------

def analyze_direct_flows(lines, file_path):
    findings = []
    class_name = get_fully_qualified_class(
        lines,
        file_path,
    )
    sources = []

    for line_number, line in enumerate(lines, start=1):

        for source_type, pattern in SOURCE_PATTERNS.items():

            match = pattern.search(line)

            if not match:
                continue

            variable = match.group(1)

            sources.append({
                "type": source_type,
                "variable": variable,
                "expression": line.strip(),
                "line": line_number,
            })

    for line_number, line in enumerate(lines, start=1):

        for sink_type, pattern in DIRECT_SINK_PATTERNS.items():

            match = pattern.search(line)

            if not match:
                continue

            # Direct WebView sink:
            # The first captured group is its argument.
            sink_variable = (
                match.group(1)
                if sink_type == "webview_load_url"
                else None
            )

            for source in sources:

                if (
                    sink_variable is not None
                    and source["variable"] == sink_variable
                ):
                    findings.append(
                        create_finding(
                            file_path=file_path,
                            source_type=source["type"],
                            class_name=class_name,
                            source_variable=source["variable"],
                            source_expression=source["expression"],
                            source_line=source["line"],
                            sink_type=sink_type,
                            sink_expression=line.strip(),
                            sink_line=line_number,
                            path=[
                                source["expression"],
                                line.strip(),
                            ],
                        )
                    )

# Detect a source and sink in the same expression.
# Example:
# webView.loadUrl(intent.getExtras().getString("url"))

    inline_patterns = [
    {
        "source_pattern": re.compile(
            r'\b\w+\.getExtras\(\)\.getString\(\s*"([^"]+)"\s*\)'
        ),
        "sink_pattern": re.compile(
            r'\.loadUrl\('
        ),
        "source_type": "intent_extra",
        "sink_type": "webview_load_url",
    }
]

    for line_number, line in enumerate(lines, start=1):
        for rule in inline_patterns:
            source_match = rule["source_pattern"].search(line)
            sink_match = rule["sink_pattern"].search(line)

        if source_match and sink_match:
            parameter_name = source_match.group(1)

            findings.append(
                create_finding(
                    file_path=file_path,
                    class_name=class_name,
                    source_type=rule["source_type"],
                    source_variable=parameter_name,
                    source_expression=source_match.group(0),
                    source_line=line_number,
                    sink_type=rule["sink_type"],
                    sink_expression=line.strip(),
                    sink_line=line_number,
                    path=[
                        source_match.group(0),
                        line.strip(),
                    ],
                )
            )
    return findings


# --------------------------------------------------
# 6. Detect query parameters flowing through
#    StringBuilder into Runtime.exec()
# --------------------------------------------------

# --------------------------------------------------
# Detect untrusted input flowing into SQL execution
# --------------------------------------------------

def analyze_sql_flows(lines, file_path):
    findings = []
    class_name = get_fully_qualified_class(
        lines,
        file_path,
    )
    sources = []
    query_variables = {}

    # Step 1: Identify untrusted input sources.
    for line_number, line in enumerate(lines, start=1):
        for source_type, pattern in SOURCE_PATTERNS.items():
            match = pattern.search(line)

            if not match:
                continue

            sources.append({
                "type": source_type,
                "variable": match.group(1),
                "expression": line.strip(),
                "line": line_number,
            })

    # Step 2: Find query variables that include untrusted input.
    for line_number, line in enumerate(lines, start=1):
        assignment = re.search(
            r'\b(?:String\s+)?(\w+)\s*=\s*(.*)',
            line,
        )

        if not assignment:
            continue

        query_variable = assignment.group(1)
        right_hand_side = assignment.group(2)

        for source in sources:
            if re.search(
                r'\b' + re.escape(source["variable"]) + r'\b',
                right_hand_side,
            ):
                query_variables[query_variable] = {
                    "source": source,
                    "query_expression": line.strip(),
                    "query_line": line_number,
                }

    # Step 3: Check whether a query variable reaches a SQL sink.
    sql_sink_patterns = {
        "sql_exec": re.compile(
            r'\b\w+\.execSQL\(\s*(\w+)'
        ),
        "sql_raw_query": re.compile(
            r'\b\w+\.rawQuery\(\s*(\w+)'
        ),
    }

    for line_number, line in enumerate(lines, start=1):
        for sink_type, pattern in sql_sink_patterns.items():
            match = pattern.search(line)

            if not match:
                continue

            query_variable = match.group(1)

            if query_variable not in query_variables:
                continue

            flow = query_variables[query_variable]
            source = flow["source"]

            findings.append(
                create_finding(
                    file_path=file_path,
                    class_name=class_name,
                    source_type=source["type"],
                    source_variable=source["variable"],
                    source_expression=source["expression"],
                    source_line=source["line"],
                    sink_type=sink_type,
                    sink_expression=line.strip(),
                    sink_line=line_number,
                    path=[
                        source["expression"],
                        flow["query_expression"],
                        line.strip(),
                    ],
                )
            )

    return findings


def analyze_runtime_exec_flows(lines, file_path):
    findings = []
    class_name = get_fully_qualified_class(
        lines,
        file_path,
)



    # Identify query parameters and their source lines.
    sources = []

    for line_number, line in enumerate(lines, start=1):

        match = SOURCE_PATTERNS["uri_parameter"].search(line)

        if not match:
            continue

        sources.append({
            "type": "uri_parameter",
            "variable": match.group(1),
            "parameter": match.group(2),
            "expression": line.strip(),
            "line": line_number,
        })

    # Find Runtime.exec(builder.toString()) calls.
    runtime_exec_pattern = re.compile(
        r'\b(?:\w+\.)?exec\(\s*(\w+)\.toString\(\)\s*\)'
    )

    # Find StringBuilder declarations.
    builder_pattern = re.compile(
        r'\bStringBuilder\s+(\w+)\s*=\s*'
        r'new\s+StringBuilder\s*\('
    )

    # Find append calls on a particular builder.
    append_pattern = re.compile(
        r'\b(\w+)\.append\(\s*(\w+)\s*\)'
    )

    for sink_index, sink_line in enumerate(lines):

        sink_match = runtime_exec_pattern.search(sink_line)

        if not sink_match:
            continue

        builder_name = sink_match.group(1)
        sink_line_number = sink_index + 1

        # Locate the most recent matching builder declaration.
        builder_start = None

        for index in range(sink_index, -1, -1):

            builder_match = builder_pattern.search(lines[index])

            if builder_match and builder_match.group(1) == builder_name:
                builder_start = index
                break

        if builder_start is None:
            continue

        # Check which source variables were appended to
        # this builder before the execution sink.
        appended_variables = set()

        for index in range(builder_start + 1, sink_index):

            append_match = append_pattern.search(lines[index])

            if not append_match:
                continue

            receiver = append_match.group(1)
            argument = append_match.group(2)

            if receiver == builder_name:
                appended_variables.add(argument)

        # Connect matching URI sources to the sink.
        for source in sources:

            if source["line"] >= sink_line_number:
                continue

            if source["variable"] not in appended_variables:
                continue

            findings.append(
                create_finding(
                    file_path=file_path,
                    class_name=class_name,
                    source_type=source["type"],
                    source_variable=source["variable"],
                    source_expression=source["expression"],
                    source_line=source["line"],
                    sink_type="runtime_exec",
                    sink_expression=sink_line.strip(),
                    sink_line=sink_line_number,
                    path=[
                        source["expression"],
                        (
                            f"{builder_name}.append("
                            f"{source['variable']})"
                        ),
                        sink_line.strip(),
                    ],
                )
            )

    return findings


# --------------------------------------------------
# 7. Analyze one Java file
# --------------------------------------------------

def analyze_file(java_file):
    findings = []

    try:
        lines = java_file.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()

    except OSError as error:
        print(f"Could not read {java_file}: {error}")
        return findings

    findings.extend(
        analyze_direct_flows(lines, java_file)
    )

    findings.extend(
        analyze_sql_flows(lines, java_file)
    )

    findings.extend(
        analyze_runtime_exec_flows(lines, java_file)
    )

    return findings
# --------------------------------------------------
# 8. Choose the files to analyze
# --------------------------------------------------

def collect_java_files(input_root):
    if not input_root.exists():
        print(f"Input directory does not exist: {input_root}")
        return []

    return sorted(input_root.rglob("*.java"))


# --------------------------------------------------
# 9. Main function
# --------------------------------------------------

def main():
    # Set up command-line arguments.
    parser = argparse.ArgumentParser(
        description="Analyze Java files for candidate data flows."
    )

    # Default: analyze the sample files.
    # Optional positional argument: analyze another Java directory.
    parser.add_argument(
        "input_directory",
        nargs="?",
        default=str(SAMPLES_DIR),
        help="Directory containing Java files to analyze.",
    )

    # Optional argument: choose the output JSON file.
    parser.add_argument(
        "--out",
        help="Path for the JSON output file.",
    )

    args = parser.parse_args()

    # Resolve the input directory.
    input_root = Path(args.input_directory).resolve()

    # Choose the output file.
    # A user-specified --out path takes priority.
    if args.out:
        output_file = Path(args.out).resolve()

    # Keep sample results separate from the InjuredAndroid report.
    elif input_root == SAMPLES_DIR.resolve():
        output_file = OUTPUT_DIR / "findings-samples.json"

    # Preserve the existing default for other input directories.
    else:
        output_file = OUTPUT_FILE

    # Find Java files to analyze.
    java_files = collect_java_files(input_root)

    # Create the output directory if it does not exist.
    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    all_findings = []

    print(f"Input directory: {input_root}")
    print()

    # Analyze each Java file.
    for java_file in java_files:
        print(f"Analyzing: {java_file.name}")

        findings = analyze_file(java_file)

        all_findings.extend(findings)

        print(f"  Candidate flows: {len(findings)}")

    # Build the JSON report.
    result = {
        "schema_version": "0.1",
        "analyzer": "androidScope-static-analysis",
        "input_directory": to_relative_path(input_root),
        "java_files_analyzed": len(java_files),
        "candidate_flows_found": len(all_findings),
        "findings": all_findings,
    }

    # Write the report to the selected output file.
    output_file.write_text(
        json.dumps(result, indent=4),
        encoding="utf-8",
    )

    # Display the summary.
    print()
    print("Analysis complete.")
    print(f"Java files analyzed: {len(java_files)}")
    print(f"Candidate flows found: {len(all_findings)}")
    print(f"JSON output: {output_file}")


if __name__ == "__main__":
    main()