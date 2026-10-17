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
    
    # If arguments are provided by the backend runner:
    if len(sys.argv) == 5:
        manifest_in, static_in, runtime_in, output_target = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
        attack_paths = run_correlation(manifest_in, static_in, runtime_in)
        
        # Derive vulnerability findings and evidence items from the attack paths for backend storage contract
        vulnerabilities = [
            {
                "id": path["id"].replace("attack-path", "vuln"),
                "vulnerability_type": path["vulnerability_type"],
                "status": path["status"],
                "component_id": path["component_id"],
                "flow_id": path["flow_id"]
            }
            for path in attack_paths
        ]
        
        evidence_items = []
        for path in attack_paths:
            for ev_id in path.get("evidence", []):
                evidence_items.append({
                    "id": ev_id,
                    "attack_path_id": path["id"],
                    "description": f"Runtime observation confirmed sink execution for {path['vulnerability_type']}"
                })
        
        # If a single file path is passed, write just attack paths (fallback); 
        # otherwise, treat it as a directory and write all three required backend contract files.
        if output_target.endswith(".json") and not os.path.isdir(output_target):
            with open(output_target, 'w') as f:
                json.dump(attack_paths, f, indent=2)
            print(f"Successfully saved attack paths to {output_target}")
        else:
            os.makedirs(output_target, exist_ok=True)
            with open(os.path.join(output_target, "attack-paths.json"), 'w') as f:
                json.dump(attack_paths, f, indent=2)
            with open(os.path.join(output_target, "vulnerability-results.json"), 'w') as f:
                json.dump(vulnerabilities, f, indent=2)
            with open(os.path.join(output_target, "evidence.json"), 'w') as f:
                json.dump(evidence_items, f, indent=2)
            print(f"Successfully generated attack-paths.json, vulnerability-results.json, and evidence.json in {output_target}")
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