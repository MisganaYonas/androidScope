"""Static stage for the DroidTrace runner.

    APK -> JADX (decompile to Java) -> Member 2's analyzer -> static-result.json

Usage (the runner fills in the values):
    python analyzers/static_stage.py <apk> --out-dir <analysis folder> --application-id <id>

Needs JADX on PATH (or JADX_PATH set to jadx.bat) and Member 2's analyzer at
static-analysis/analyzer.py. For testing without JADX, pass --java-dir <folder of .java files>.

Member 2's raw report is converted to the shared flow format. Each flow gets the fully
qualified class, the manifest component_id (matched by class name) and the sink's class and
method as Frida will report them. Newer versions of the analyzer already provide the class and
the sink class/method; for older versions this wrapper derives them.
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

# fallback for older analyzer versions: method name in the sink expression -> class Frida reports
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


def run_analyzer(analyzer: Path, java_dir: Path, raw_out: Path) -> dict:
    """Run Member 2's analyzer. Uses --out; falls back to its fixed output file for old versions."""
    started = time.time() - 2
    raw_out.unlink(missing_ok=True)
    result = subprocess.run([sys.executable, str(analyzer), str(java_dir), "--out", str(raw_out)],
                            cwd=analyzer.parent, capture_output=True, text=True)
    if result.returncode != 0:
        fail(f"static analyzer exited with code {result.returncode}: "
             f"{(result.stderr or result.stdout).strip()[-400:]}")
    report = raw_out
    if not report.exists():  # old analyzer: ignores --out and writes a fixed file
        report = analyzer.parent / "output" / "findings.json"
        if not report.exists() or report.stat().st_mtime < started:
            fail("static analyzer did not write a fresh report")
    data = json.loads(report.read_text(encoding="utf-8"))
    if data.get("java_files_analyzed") == 0:  # the analyzer exits 0 even when the folder is missing
        fail(f"static analyzer found no Java files in {java_dir}")
    return data


def locate(file_text: str) -> Path:
    path = Path(file_text)
    return path if path.is_absolute() else ROOT / path  # newer reports are relative to the repo root


def class_name(java_file: Path) -> str:
    text = java_file.read_text(encoding="utf-8", errors="ignore")
    match = PACKAGE_RE.search(text)
    return (match.group(1) + "." if match else "") + java_file.stem


def adapt(raw: dict, manifest: dict, decompiled: Path) -> list:
    component_ids = {c.get("name"): c.get("component_id") for c in manifest.get("components", [])}
    flows = []
    for number, finding in enumerate(raw.get("findings", []), start=1):
        evidence, source, sink = (finding.get(k) or {} for k in ("evidence", "source", "sink"))
        java_file = locate(evidence["file"]) if evidence.get("file") else None
        cls = finding.get("class")
        if not cls and java_file and java_file.exists():
            cls = class_name(java_file)
        expression = sink.get("expression", "")
        method = sink.get("method") or next(
            (m for m in KNOWN_SINKS if re.search(rf"\b{m}\s*\(", expression)), None)
        sink_class = sink.get("class") or KNOWN_SINKS.get(method)
        file_text = evidence.get("file")
        if file_text and Path(file_text).is_absolute():
            try:
                file_text = str(Path(file_text).resolve().relative_to(decompiled.resolve()))
            except ValueError:
                file_text = Path(file_text).name
        flows.append({
            "id": f"flow-{number:03d}",
            "static_id": finding.get("id"),
            "component_id": component_ids.get(cls) if cls else None,
            "class": cls,
            "type": finding.get("type"),
            "source": f"{source.get('type')}: {source.get('expression', '').strip()}",
            "source_detail": source,
            "sink": {"type": sink.get("type"), "class": sink_class, "method": method,
                     "expression": expression, "line": sink.get("line")},
            "path": (finding.get("data_flow") or {}).get("path", []),
            "confidence": (finding.get("analysis") or {}).get("confidence"),
            "evidence": {"file": file_text, "source_line": evidence.get("source_line"),
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

    raw = run_analyzer(analyzer, java_dir, out_dir / "static-raw.json")
    flows = adapt(raw, manifest, decompiled)
    result = {"application_id": args.application_id or manifest.get("application_id"),
              "analyzer": "static-analysis (Member 2) via static_stage.py", "flows": flows}
    (out_dir / "static-result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"static: {len(flows)} flow(s) written to static-result.json")


if __name__ == "__main__":
    main()
