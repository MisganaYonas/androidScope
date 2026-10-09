import json
import os
import sys

def load_json(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r') as f:
        return json.load(f)

def run_correlation(manifest_path_or_data, static_path_or_data, runtime_path_or_data):
    # Support either file paths or direct data dictionaries/lists
    manifest_data = load_json(manifest_path_or_data) if isinstance(manifest_path_or_data, str) else manifest_path_or_data
    static_data = load_json(static_path_or_data) if isinstance(static_path_or_data, str) else static_path_or_data
    runtime_data = load_json(runtime_path_or_data) if isinstance(runtime_path_or_data, str) else runtime_path_or_data

    attack_paths = []

    for flow in static_data:
        component_id = flow.get("component_id")
        vuln_type = flow.get("type", "generic")
        sink_method = flow.get("sink", {}).get("method")

        # Match runtime events against the static flow's sink
        matching_events = [
            ev for ev in runtime_data 
            if ev.get("method") == sink_method or ev.get("class", "") + "." + ev.get("method", "") == sink_method
        ]

        status = "CORRELATED" if matching_events else "STATIC_CANDIDATE"

        # Construct full node sequence for the attack path
        nodes = [
            {"step": 1, "type": "External Input", "detail": flow.get("source", "Unknown Entrypoint")},
            {"step": 2, "type": "Component", "detail": component_id},
            {"step": 3, "type": "Static Flow", "detail": flow.get("id")},
            {"step": 4, "type": "Sink Method", "detail": sink_method},
            {"step": 5, "type": "Runtime Observation", "status": status, "evidence_count": len(matching_events)}
        ]

        attack_path = {
            "id": f"attack-path-{len(attack_paths) + 1}",
            "vulnerability_type": vuln_type,
            "status": status,
            "component_id": component_id,
            "flow_id": flow.get("id"),
            "nodes": nodes,
            "evidence": [ev.get("id", "event-runtime") for ev in matching_events]
        }
        attack_paths.append(attack_path)

    return attack_paths

if __name__ == "__main__":
    print("Member 4 Correlation Engine ready.")
    
    # If arguments are provided: python3 engine.py manifest.json static.json runtime.json output.json
    if len(sys.argv) == 5:
        manifest_in, static_in, runtime_in, output_out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
        results = run_correlation(manifest_in, static_in, runtime_in)
        with open(output_out, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Successfully generated attack paths saved to {output_out}")
    else:
        # Fallback test execution
        sample_manifest = [{"id": "comp-01", "name": "MainActivity", "exported": True}]
        sample_static = [{
            "id": "flow-001",
            "component_id": "comp-01",
            "type": "Remote Code Execution / WebView",
            "source": "Intent.getData()",
            "sink": {"type": "webview", "method": "loadUrl"}
        }]
        sample_runtime = [{
            "id": "event-001",
            "class": "android.webkit.WebView",
            "method": "loadUrl",
            "arguments": ["https://example.com"]
        }]
        paths = run_correlation(sample_manifest, sample_static, sample_runtime)
        print("Test Output:", json.dumps(paths, indent=2))