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
    """Safely extracts a list whether the input is a plain list or a wrapped dict like {"flows": [...]}, {"components": [...]}, etc."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in keys:
            if key in data and isinstance(data[key], list):
                return data[key]
        for val in data.values():
            if isinstance(val, list):
                return val
    return []

def extract_application_id(manifest_raw):
    """Extracts application_id from the manifest file if available."""
    if isinstance(manifest_raw, dict):
        for key in ["application_id", "package_name", "app_id", "packageName"]:
            if key in manifest_raw and isinstance(manifest_raw[key], str):
                return manifest_raw[key]
    return "app-001"

def clean_method_name(method_str):
    """Removes parameter signatures (e.g., '(Ljava/lang/String;)V') from method names for robust matching."""
    if not method_str:
        return ""
    return method_str.split("(")[0].strip()

def run_correlation(manifest_path_or_data, static_path_or_data, runtime_path_or_data):
    # Load raw data
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

    # Extract application_id from manifest
    application_id = extract_application_id(manifest_raw)

    # Extract lists from potential wrapper dicts
    manifest_data = extract_list(manifest_raw, ["components", "manifest", "items", "app", "activities", "services", "receivers", "providers"])
    static_data = extract_list(static_raw, ["flows", "static_flows", "items"])
    runtime_data = extract_list(runtime_raw, ["events", "runtime_events", "items"])

    # Build lookup map for components using component_id, id, and name
    # Member 1's exported boolean check
    component_export_map = {}
    for comp in manifest_data:
        c_id = comp.get("component_id") or comp.get("id") or comp.get("name")
        is_exported = comp.get("exported", True) # Default True if omitted
        if c_id:
            component_export_map[c_id] = bool(is_exported)
            # Also map short names if qualified names are used
            if "." in c_id:
                component_export_map[c_id.split(".")[-1]] = bool(is_exported)

    attack_paths = []
    vulnerabilities = []
    evidence_items = []

    for idx, flow in enumerate(static_data, start=1):
        component_id = flow.get("component_id") or flow.get("component") or flow.get("component_name")
        
        # Check export status using component_id, id, or name lookup
        is_exported = True
        if component_id:
            # Check direct match or short name match
            if component_id in component_export_map:
                is_exported = component_export_map[component_id]
            elif "." in component_id and component_id.split(".")[-1] in component_export_map:
                is_exported = component_export_map[component_id.split(".")[-1]]

        if not is_exported:
            # Print warning to stderr when a flow is skipped because component is not exported
            print(f"Warning: Skipping flow '{flow.get('id', idx)}' because component '{component_id}' is not exported.", file=sys.stderr)
            continue

        vuln_type = flow.get("type", "generic")
        sink = flow.get("sink", {})
        sink_class = sink.get("class", "")
        raw_sink_method = sink.get("method", "")
        clean_target_method = clean_method_name(raw_sink_method)

        # Match runtime events on class + clean method name (without signature)
        matching_events = []
        for ev in runtime_data:
            ev_class = ev.get("class", "")
            ev_method = clean_method_name(ev.get("method", ""))
            
            class_match = (not sink_class or not ev_class or sink_class == ev_class or sink_class.endswith(ev_class) or ev_class.endswith(sink_class))
            method_match = (clean_target_method == ev_method)

            if class_match and method_match:
                matching_events.append(ev)

        status = "CORRELATED" if matching_events else "STATIC_CANDIDATE"
        path_id = f"attack-path-{idx:03d}"
        vuln_id = f"vuln-{idx:03d}"

        nodes = [
            {"step": 1, "type": "External Input", "detail": flow.get("source", "Unknown Entrypoint")},
            {"step": 2, "type": "Component", "detail": component_id or "Unknown Component"},
            {"step": 3, "type": "Static Flow", "detail": flow.get("id", f"flow-{idx:03d}")},
            {"step": 4, "type": "Sink Method", "detail": f"{sink_class}.{clean_target_method}" if sink_class else clean_target_method},
            {"step": 5, "type": "Runtime Observation", "status": status, "evidence_count": len(matching_events)}
        ]

        flow_evidence_id = f"evidence-static-{idx:03d}"
        evidence_items.append({
            "id": flow_evidence_id,
            "attack_path_id": path_id,
            "type": "static_flow",
            "description": f"Static analysis identified flow {flow.get('id')} targeting sink {raw_sink_method}"
        })

        runtime_evidence_ids = []
        for ev_idx, ev in enumerate(matching_events, start=1):
            ev_id = ev.get("id", f"evidence-runtime-{idx:03d}-{ev_idx}")
            runtime_evidence_ids.append(ev_id)
            evidence_items.append({
                "id": ev_id,
                "attack_path_id": path_id,
                "type": "runtime_observation",
                "description": f"Runtime execution verified sink {sink_class}.{raw_sink_method} with arguments {ev.get('arguments', [])}"
            })

        attack_paths.append({
            "id": path_id,
            "application_id": application_id,
            "vulnerability_type": vuln_type,
            "status": status,
            "component_id": component_id,
            "flow_id": flow.get("id"),
            "nodes": nodes,
            "evidence_ids": [flow_evidence_id] + runtime_evidence_ids
        })

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
    if len(sys.argv) >= 5:
        manifest_in, static_in, runtime_in, output_target = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
        
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
            print(f"Successfully generated final shared schema JSON files in {output_target}")
    else:
        # Quick test run
        sample_manifest = {"application_id": "com.inj.android", "components": [{"id": "MainActivity", "exported": True}]}
        sample_static = {"flows": [{
            "id": "flow-001",
            "component_id": "MainActivity",
            "type": "RCE",
            "source": "Intent",
            "sink": {"class": "android.webkit.WebView", "method": "loadUrl(Ljava/lang/String;)V"}
        }]}
        sample_runtime = {"events": [{
            "id": "ev-001",
            "class": "android.webkit.WebView",
            "method": "loadUrl",
            "arguments": ["http://test.com"]
        }]}
        res = run_correlation(sample_manifest, sample_static, sample_runtime)
        print(json.dumps(res, indent=2))