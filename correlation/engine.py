import json
import os

def load_json(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r') as f:
        return json.load(f)

def run_correlation(manifest_data, static_data, runtime_data):
    attack_paths = []

    for flow in static_data:
        component_id = flow.get("component_id")
        sink_method = flow.get("sink", {}).get("method")

        matching_events = [
            ev for ev in runtime_data 
            if ev.get("method") == sink_method or ev.get("class", "") + "." + ev.get("method", "") == sink_method
        ]

        status = "CORRELATED" if matching_events else "STATIC_CANDIDATE"

        attack_path = {
            "id": f"attack-path-{len(attack_paths) + 1}",
            "status": status,
            "component_id": component_id,
            "flow_id": flow.get("id"),
            "evidence": [ev.get("id", "event-runtime") for ev in matching_events]
        }
        attack_paths.append(attack_path)

    return attack_paths

if __name__ == "__main__":
    print("Member 4 Correlation Engine initialized.")
    
    # Test with sample mock data
    sample_manifest = [{"id": "component-001", "name": "MainActivity", "exported": True}]
    sample_static = [{
        "id": "flow-001",
        "component_id": "component-001",
        "sink": {"type": "webview", "method": "loadUrl"}
    }]
    sample_runtime = [{
        "id": "event-001",
        "class": "android.webkit.WebView",
        "method": "loadUrl",
        "arguments": ["https://example.com"]
    }]

    paths = run_correlation(sample_manifest, sample_static, sample_runtime)
    print("Test Correlation Result:", json.dumps(paths, indent=2))