"""Static stage for the DroidTrace runner.

    APK -> JADX (decompile to Java) -> Member 2's analyzer -> static-result.json

Usage (the runner fills in the values):
    python analyzers/static_stage.py <apk> --out-dir <analysis folder> --application-id <id>

Needs JADX on PATH (or JADX_PATH set to jadx.bat) and Member 2's analyzer at
static-analysis/analyzer.py. For testing without JADX, pass --java-dir <folder of .java files>.

Member 2's raw output is converted to the shared flow format: each flow gets the fully
qualified class, the manifest component_id (matched by class name), and the sink's class
and method as Frida will report them. This is a stop-gap; ideally the analyzer does it.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # repository root
DEFAULT_ANALYZER = ROOT / "static-analysis" / "analyzer.py"

# method name found in the sink expression -> class that Frida reports at runtime
KNOWN_SINKS = {
    "exec": "java.lang.Runtime",
    "loadUrl": "android.webkit.WebView",
    "loadData": "android.webkit.WebView",
    "loadDataWithBaseURL": "android.webkit.WebView",
    "evaluateJavascript": "android.webkit.WebView",
    "execSQL": "android.database.sqlite.SQLiteDatabase",
    "rawQuery": "android.database.sqlite.SQLiteDatabase",
}
PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)


def fail(message: str):
    print(message, file=sys.stderr)
    sys.exit(1)


def decompile(apk: Path, dest: Path):
    jadx = os.environ.get("JADX_PATH") or shutil.which("jadx")
    if not jadx:
        fail("JADX not found. Install it and add it to PATH, or set JADX_PATH to jadx.bat.")
    dest.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([jadx, "-d", str(dest), str(apk)], capture_output=True, text=True)
    if not any(dest.rglob("*.java")):
        detail = (result.stderr or result.stdout).strip()[-400:]
        fail(f"JADX produced no Java files (exit code {result.returncode}): {detail}")
    if result.returncode != 0:  # JADX often reports errors on a few classes but still works
        print(f"warning: JADX reported errors (exit code {result.returncode}) but produced output",
              file=sys.stderr)


def java_root(decompiled: Path, package):
    """Analyze only the app's own package, not every library bundled in the APK."""
    sources = decompiled / "sources" if (decompiled / "sources").is_dir() else decompiled
    if package:
        package_dir = sources.joinpath(*package.split("."))
        if package_dir.is_dir():
            return package_dir
    return sources


def run_analyzer(analyzer: Path, java_dir: Path) -> dict:
    started = time.time() - 2
    result = subprocess.run([sys.executable, str(analyzer), str(java_dir)],
                            cwd=analyzer.parent, capture_output=True, text=True)
    if result.returncode != 0:
        fail(f"static analyzer exited with code {result.returncode}: "
             f"{(result.stderr or result.stdout).strip()[-400:]}")
    output = analyzer.parent / "output" / "findings.json"
    if not output.exists() or output.stat().st_mtime < started:
        fail("static analyzer did not write a fresh output/findings.json")
    return json.loads(output.read_text(encoding="utf-8"))


def class_name(java_file: Path) -> str:
    text = java_file.read_text(encoding="utf-8", errors="ignore")
    match = PACKAGE_RE.search(text)
    return (match.group(1) + "." if match else "") + java_file.stem


def adapt(raw: dict, manifest: dict, root: Path) -> list:
    component_ids = {c.get("name"): c.get("component_id") for c in manifest.get("components", [])}
    flows = []
    for number, finding in enumerate(raw.get("findings", []), start=1):
        evidence, source, sink = (finding.get(k) or {} for k in ("evidence", "source", "sink"))
        java_file = Path(evidence["file"]) if evidence.get("file") else None
        cls = class_name(java_file) if java_file and java_file.exists() else None
        expression = sink.get("expression", "")
        method = next((m for m in KNOWN_SINKS if re.search(rf"\b{m}\s*\(", expression)), None)
        try:
            relative_file = str(java_file.resolve().relative_to(root.resolve()))
        except (ValueError, AttributeError):
            relative_file = java_file.name if java_file else None
        flows.append({
            "id": f"flow-{number:03d}",
            "static_id": finding.get("id"),
            "component_id": component_ids.get(cls) if cls else None,
            "class": cls,
            "type": finding.get("type"),
            "source": f"{source.get('type')}: {source.get('expression', '').strip()}",
            "source_detail": source,
            "sink": {"type": sink.get("type"), "class": KNOWN_SINKS.get(method), "method": method,
                     "expression": expression, "line": sink.get("line")},
            "path": (finding.get("data_flow") or {}).get("path", []),
            "confidence": (finding.get("analysis") or {}).get("confidence"),
            "evidence": {"file": relative_file, "source_line": evidence.get("source_line"),
                         "sink_line": evidence.get("sink_line")},
        })
    return flows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("apk")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--application-id")
    parser.add_argument("--java-dir", help="skip JADX and analyze this folder of .java files")
    parser.add_argument("--analyzer", default=str(DEFAULT_ANALYZER))
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    analyzer = Path(args.analyzer)
    if not analyzer.exists():
        fail(f"static analyzer not found: {analyzer} (merge Member 2's branch first)")

    manifest_path = out_dir / "manifest-result.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}

    if args.java_dir:
        decompiled = Path(args.java_dir)
        java_dir = decompiled
    else:
        apk = Path(args.apk)
        if not apk.exists():
            fail(f"APK not found: {apk}")
        decompiled = out_dir / "decompiled"
        decompile(apk, decompiled)
        java_dir = java_root(decompiled, manifest.get("package_name"))

    raw = run_analyzer(analyzer, java_dir)
    flows = adapt(raw, manifest, decompiled)
    result = {"application_id": args.application_id or manifest.get("application_id"),
              "analyzer": "static-analysis (Member 2) via static_stage.py", "flows": flows}
    (out_dir / "static-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"static: {len(flows)} flow(s) written to static-result.json")


if __name__ == "__main__":
    main()
