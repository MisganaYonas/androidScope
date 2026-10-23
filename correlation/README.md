# Correlation Engine

The Correlation Engine serves as the core integration module for the AndroidScope platform. It ingests static analysis data, dynamic runtime observations, and application manifest configurations to construct verified end-to-end attack paths, assign correlation statuses, and produce standard data contracts for the backend and frontend modules.

---

## 1. Key Functionality

- **Multi-Source Integration:** Combines static analysis flows, Frida runtime hook events, and manifest metadata into unified security findings.
- **Smart Component & Reachability Validation:** Checks whether static findings belong to components explicitly marked as exported in the manifest. Unexported or missing components are safely categorized as `reachability: "unknown"` or `"not_exported"` and filtered out from reachable attack paths.
- **Strict Class & Method Matching:** Employs precise boundary checking (`classes_match`) to ensure method sinks match Frida runtime events strictly on exact names or `.` class boundaries, preventing false-positive empty wildcards.
- **Vulnerability Categorization:** Categorizes static findings matched with live runtime events as `CORRELATED`, while unmatched static findings are preserved as `STATIC_CANDIDATE`.
- **Standardized JSON Contracts:** Generates uniform data output files (`attack-paths.json`, `vulnerability-results.json`, `evidence.json`) consumed directly by the UI and API backend.

---

## 2. Input Requirements

The engine requires three input files passed via CLI or loaded as JSON structures:

1. **Manifest File (`manifest-result.json`):** Contains application details, package IDs, and exported status for components (`activities`, `services`, `receivers`, `providers`).
2. **Static Findings (`findings.json`):** Contains static dataflow analysis, entrypoints (sources), target sink classes/methods, and component IDs.
3. **Runtime Events (`sample_events.json`):** Contains live Frida observation hooks with class names, method signatures, and captured execution arguments.

---

## 3. Execution Instructions

Run the script from the repository root directory using Python 3:

```bash
PYTHONPATH=. ./venv/bin/python3 correlation/engine.py \
  <path_to_manifest_result.json> \
  <path_to_static_findings.json> \
  <path_to_runtime_events.json> \
  <output_directory_or_filepath>
```

This command generates three JSON contract files in the `output/` directory.

---

## 4. Output Schemas & Data Contracts

### A. `attack-paths.json`

Defines the step-by-step chain of exploitation from entrypoint to execution.

```json
{
  "application_id": "com.example.app",
  "count": 1,
  "attack_paths": [
    {
      "id": "attack-path-001",
      "application_id": "com.example.app",
      "vulnerability_type": "RCE",
      "status": "CORRELATED",
      "reachability": "exported",
      "component_id": "MainActivity",
      "component_name": "MainActivity",
      "flow_id": "flow-001",
      "nodes": [
        { "step": 1, "type": "External Input", "detail": "Intent" },
        { "step": 2, "type": "Component", "detail": "MainActivity" },
        { "step": 3, "type": "Static Flow", "detail": "flow-001" },
        {
          "step": 4,
          "type": "Sink Method",
          "detail": "android.webkit.WebView.loadUrl"
        },
        {
          "step": 5,
          "type": "Runtime Observation",
          "status": "CORRELATED",
          "evidence_count": 1
        }
      ],
      "evidence_ids": ["evidence-static-001", "evidence-runtime-001-1"]
    }
  ]
}
```

### B. `vulnerability-results.json`

Provides structured summary rows for main vulnerability tables and UI cards.

```json
{
  "application_id": "com.example.app",
  "count": 1,
  "vulnerabilities": [
    {
      "id": "vuln-001",
      "application_id": "com.example.app",
      "attack_path_id": "attack-path-001",
      "vulnerability_type": "RCE",
      "status": "CORRELATED",
      "reachability": "exported",
      "component_id": "MainActivity",
      "component_name": "MainActivity",
      "flow_id": "flow-001"
    }
  ]
}
```

### C. `evidence.json`

Powers drill-down views and detail drawers by linking static flows and dynamic Frida argument logs to attack paths.

```json
{
  "application_id": "com.example.app",
  "count": 2,
  "evidence": [
    {
      "id": "evidence-static-001",
      "attack_path_id": "attack-path-001",
      "type": "static_flow",
      "description": "Static analysis identified flow flow-001 targeting sink loadUrl(Ljava/lang/String;)V"
    },
    {
      "id": "evidence-runtime-001-1",
      "attack_path_id": "attack-path-001",
      "type": "runtime_observation",
      "description": "Runtime execution verified sink android.webkit.WebView.loadUrl with arguments ['http://test.com']"
    }
  ]
}
```

---

## 5. Summary of Recent Updates

- **Explicit Reachability Handling:** Unlisted or missing manifest components are no longer marked as exported by default; they are assigned `reachability: "unknown"` and safely skipped.
- **Strict Boundary Class Matching:** Added explicit boundary checks (`classes_match`) preventing empty string wildcards from matching arbitrary runtime events.
- **Component Names in Steps:** Updated Step 2 in `nodes` to display human-readable component names (`component_name`) alongside component IDs.
- **Frontend Field Alignment:** Output JSON keys standardized (`reachability`, `component_name`, `status`, `nodes`) for direct consumption by frontend views.
