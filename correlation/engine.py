import json
import os
import sys

def load_json(filepath, required=False):
    if not os.path.exists(filepath):
        if required:
            print(f"Error: Required file missing -> {filepath}", file=sys.stderr)
            sys.exit(1)
        return []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        if required:
            print(f"Error parsing JSON from {filepath}: {e}", file=sys.stderr)
            sys.exit(1)
        return []

def extract_list(data, keys):
    """Safely extracts a list whether the input is a plain list or a wrapped dict like {"flows": [...]}."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in keys:
            if key in data and isinstance(data[key], list):
                return data[key]
        # Fallback: find any value that is a list
        for val in data.values():
            if isinstance(val, list):
                return val
    return []

def run_correlation(manifest_path_or_data, static_path_or_data, runtime_path_or_data, application_id="app-001"):
    # Load data with UTF-8 and handle file existence
    if isinstance(manifest_path_or_data, str):
        manifest_raw = load_json(manifest_path_or_data, required=True)
    else:
        manifest_raw = manifest_path_or_data

    if isinstance(static_path_or_data, str):
        static_raw = load_json(static_path_or_data, required=True)
    else:
        static_raw = static_path_or_data

    if isinstance(runtime_path_or_data, str):
        runtime_raw = load_json(runtime_path_or_data, required=False)
    else:
        runtime_raw = runtime_path_or_data

    # Support wrapped formats (e.g., {"flows": [...]}, {"events": [...]}, {"components": [...]})
    manifest_data = extract_list(manifest_raw, ["components", "manifest", "items", "app"])
    static_data = extract_list(static_raw, ["flows", "static_flows", "items"])
    runtime_data = extract_list(runtime_raw, ["events", "runtime_events", "items"])

    # Build a lookup for exported components from manifest
    exported_components = set()
    for comp in manifest_data:
        comp_id = comp.get("id") or comp.get("name")
        is_exported = comp.get("exported", True)  # default True if not explicitly false
        if is_exported and comp_id:
            exported_components.add(comp_id)

    attack_paths = []
    vulnerabilities = []
    evidence_items = []

    for idx, flow in enumerate(static_data, start=1):
        component_id = flow.get("component_id") or flow.get("component")
        
        # Check if component is exported using manifest data
        if component_id and exported_components and component_id not in exported_components:
            # Skip unexported components or mark accordingly per team rule
            continue

        vuln_type = flow.get("type", "generic")
        sink = flow.get("sink", {})
        sink_class = sink.get("class", "")
        sink_method = sink.get("method", "")

        # Strict matching on class + method (as requested in feedback)
        matching_events = [
            ev for ev in runtime_data 
            if ev.get("class") == sink_class and ev.get("method") == sink_method
        ]

        status = "CORRELATED" if matching_events else "STATIC_CANDIDATE"
        path_id = f"attack-path-{idx:03d}"
        vuln_id = f"vuln-{idx:03d}"

        # Construct 5-node sequence
        nodes = [
            {"step": 1, "type": "External Input", "detail": flow.get("source", "Unknown Entrypoint")},
            {"step": 2, "type": "Component", "detail": component_id or "Unknown Component"},
            {"step": 3, "type": "Static Flow", "detail": flow.get("id", f"flow-{idx:03d}")},
            {"step": 4, "type": "Sink Method", "detail": f"{sink_class}.{sink_method}" if sink_class else sink_method},
            {"step": 5, "type": "Runtime Observation", "status": status, "evidence_count": len(matching_events)}
        ]

        # Gather evidence items (both static flow reference and runtime observations)
        flow_evidence_id = f"evidence-static-{idx:03d}"
        evidence_items.append({
            "id": flow_evidence_id,
            "attack_path_id": path_id,
            "type": "static_flow",
            "description": f"Static analysis identified flow {flow.get('id')} targeting sink {sink_method}"
        })

        runtime_evidence_ids = []
        for ev_idx, ev in enumerate(matching_events, start=1):
            ev_id = ev.get("id", f"evidence-runtime-{idx:03d}-{ev_idx}")
            runtime_evidence_ids.append(ev_id)
            evidence_items.append({
                "id": ev_id,
                "attack_path_id": path_id,
                "type": "runtime_observation",
                "description": f"Runtime execution verified sink {sink_class}.{sink_method} with arguments {ev.get('arguments', [])}"
            })

        attack_path = {
            "id": path_id,
            "application_id": application_id,
            "vulnerability_type": vuln_type,
            "status": status,
            "component_id": component_id,
            "flow_id": flow.get("id"),
            "nodes": nodes,
            "evidence_ids": [flow_evidence_id] + runtime_evidence_ids
        }
        attack_paths.append(attack_path)

        vulnerabilities.append({
            "id": vuln_id,
            "application_id": application_id,
            "attack_path_id": path_id,
            "vulnerability_type": vuln_type,
            "status": status,
            "component_id": component_id,
            "flow_id": flow.get("id")
        })

    return {
        "application_id": application_id,
        "attack_paths": attack_paths,
        "vulnerabilities": vulnerabilities,
        "evidence": evidence_items
    }

if __name__ == "__main__":
    print("Member 4 Correlation Engine ready.")
    
    if len(sys.argv) >= 5:
        manifest_in, static_in, runtime_in, output_target = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
        
        # Run correlation producing wrapped structured schema output
        result = run_correlation(manifest_in, static_in, runtime_in)
        
        if output_target.endswith(".json") and not os.path.isdir(output_target):
            with open(output_target, 'w', encoding='utf-8') as f:
                json.dump(result["attack_paths"], f, indent=2)
            print(f"Successfully saved attack paths to {output_target}")
        else:
            os.makedirs(output_target, exist_ok=True)
            with open(os.path.join(output_target, "attack-paths.json"), 'w', encoding='utf-8') as f:
                json.dump({
                    "application_id": result["application_id"],
                    "count": len(result["attack_paths"]),
                    "attack_paths": result["attack_paths"]
                }, f, indent=2)
            with open(os.path.join(output_target, "vulnerability-results.json"), 'w', encoding='utf-8') as f:
                json.dump({
                    "application_id": result["application_id"],
                    "count": len(result["vulnerabilities"]),
                    "vulnerabilities": result["vulnerabilities"]
                }, f, indent=2)
            with open(os.path.join(output_target, "evidence.json"), 'w', encoding='utf-8') as f:
                json.dump({
                    "application_id": result["application_id"],
                    "count": len(result["evidence"]),
                    "evidence": result["evidence"]
                }, f, indent=2)
            print(f"Successfully generated wrapped schema JSON files in {output_target}")
    else:
        # Fallback test execution
        sample_manifest = {"components": [{"id": "comp-01", "name": "MainActivity", "exported": True}]}
        sample_static = {"flows": [{
            "id": "flow-001",
            "component_id": "comp-01",
            "type": "Remote Code Execution / WebView",
            "source": "Intent.getData()",
            "sink": {"class": "android.webkit.WebView", "method": "loadUrl"}
        }]}
        sample_runtime = {"events": [{
            "id": "event-001",
            "class": "android.webkit.WebView",
            "method": "loadUrl",
            "arguments": ["https://example.com"]
        }]}
        res = run_correlation(sample_manifest, sample_static, sample_runtime)
        print("Test Output:", json.dumps(res, indent=2))