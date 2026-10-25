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
    if isinstance(manifest_raw, dict):
        for key in ["application_id", "package_name", "app_id", "packageName"]:
            if key in manifest_raw and isinstance(manifest_raw[key], str):
                return manifest_raw[key]
    return "app-001"

def clean_method_name(method_str):
    if not method_str:
        return ""
    return method_str.split("(")[0].strip()

def classes_match(sink_class, ev_class):
    if not sink_class or not ev_class:
        return False
    if sink_class == ev_class:
        return True
    if sink_class.endswith("." + ev_class) or ev_class.endswith("." + sink_class):
        return True
    return False

def run_correlation(manifest_path_or_data, static_path_or_data, runtime_path_or_data):
    manifest_raw = load_json(manifest_path_or_data, required=True) if isinstance(manifest_path_or_data, str) else manifest_path_or_data
    static_raw = load_json(static_path_or_data, required=True) if isinstance(static_path_or_data, str) else static_path_or_data
    runtime_raw = load_json(runtime_path_or_data, required=False) if isinstance(runtime_path_or_data, str) else runtime_path_or_data

    application_id = extract_application_id(manifest_raw)

    # Check top-level application_id in runtime file if it's a dict
    runtime_top_app_id = None
    if isinstance(runtime_raw, dict):
        for key in ["application_id", "app_id", "package_name"]:
            if key in runtime_raw and isinstance(runtime_raw[key], str):
                runtime_top_app_id = runtime_raw[key]
                break

    notes = []
    # If top-level runtime file app ID doesn't match manifest, ignore events in this file
    if runtime_top_app_id and runtime_top_app_id != application_id:
        msg = f"Runtime file application_id ('{runtime_top_app_id}') mismatched manifest ('{application_id}'). File ignored."
        print(f"Warning: {msg}", file=sys.stderr)
        notes.append(msg)
        runtime_data = []
    else:
        runtime_data = extract_list(runtime_raw, ["events", "runtime_events", "items"])

    manifest_data = extract_list(manifest_raw, ["components", "manifest", "items", "app", "activities", "services", "receivers", "providers"])
    static_data = extract_list(static_raw, ["flows", "static_flows", "items"])

    component_details = {}
    for comp in manifest_data:
        c_id = comp.get("component_id") or comp.get("id") or comp.get("name")
        c_name = comp.get("name") or c_id
        is_exp = comp.get("exported")
        
        info = {"id": c_id, "name": c_name, "exported": is_exp}
        if c_id:
            component_details[c_id] = info
            if "." in c_id:
                component_details[c_id.split(".")[-1]] = info
        if c_name:
            component_details[c_name] = info

    attack_paths = []
    vulnerabilities = []
    evidence_items = []

    for idx, flow in enumerate(static_data, start=1):
        component_id = flow.get("component_id") or flow.get("component") or flow.get("component_name")
        
        matched_comp = None
        if component_id:
            if component_id in component_details:
                matched_comp = component_details[component_id]
            elif "." in component_id and component_id.split(".")[-1] in component_details:
                matched_comp = component_details[component_id.split(".")[-1]]

        component_name = matched_comp.get("name") if matched_comp and matched_comp.get("name") else (component_id or "Unknown Component")

        reachability = "unknown"
        is_exported = False
        
        if matched_comp:
            exp_val = matched_comp.get("exported")
            if exp_val is True:
                is_exported = True
                reachability = "exported"
            elif exp_val is False:
                is_exported = False
                reachability = "not_exported"
            else:
                reachability = "unknown"
        else:
            reachability = "unknown"
            is_exported = False

        if not is_exported or reachability != "exported":
            print(f"Warning: Skipping flow '{flow.get('id', idx)}' because component '{component_id}' reachability is '{reachability}'.", file=sys.stderr)
            continue

        vuln_type = flow.get("type", "generic")
        sink = flow.get("sink", {})
        sink_class = sink.get("class", "")
        raw_sink_method = sink.get("method", "")
        clean_target_method = clean_method_name(raw_sink_method)

        matching_events = []
        for ev in runtime_data:
            ev_app_id = ev.get("application_id") or ev.get("app_id") or ev.get("package_name")
            if ev_app_id and ev_app_id != application_id:
                continue

            ev_class = ev.get("class", "")
            ev_method = clean_method_name(ev.get("method", ""))
            
            # Simple, robust sink class + method match
            if classes_match(sink_class, ev_class) and (clean_target_method == ev_method):
                matching_events.append(ev)

        status = "CORRELATED" if matching_events else "STATIC_CANDIDATE"
        path_id = f"attack-path-{idx:03d}"
        vuln_id = f"vuln-{idx:03d}"

        nodes = [
            {"step": 1, "type": "External Input", "detail": flow.get("source", "Unknown Entrypoint")},
            {"step": 2, "type": "Component", "detail": component_name},
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
            "reachability": reachability,
            "component_id": component_id,
            "component_name": component_name,
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
            "reachability": reachability,
            "component_id": component_id,
            "component_name": component_name,
            "flow_id": flow.get("id")
        })

    res = {
        "application_id": application_id,
        "attack_paths": attack_paths,
        "vulnerabilities": vulnerabilities,
        "evidence": evidence_items
    }
    if notes:
        res["notes"] = "; ".join(notes)
    return res

if __name__ == "__main__":
    if len(sys.argv) >= 5:
        manifest_in, static_in, runtime_in, output_target = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
        result = run_correlation(manifest_in, static_in, runtime_in)
        
        if output_target.endswith(".json") and not os.path.isdir(output_target):
            out_data = result["attack_paths"]
            with open(output_target, 'w', encoding='utf-8') as f:
                json.dump(out_data, f, indent=2)
            print(f"Successfully saved attack paths to {output_target}")
        else:
            os.makedirs(output_target, exist_ok=True)
            
            ap_out = {"application_id": result["application_id"], "count": len(result["attack_paths"]), "attack_paths": result["attack_paths"]}
            vuln_out = {"application_id": result["application_id"], "count": len(result["vulnerabilities"]), "vulnerabilities": result["vulnerabilities"]}
            ev_out = {"application_id": result["application_id"], "count": len(result["evidence"]), "evidence": result["evidence"]}
            
            if "notes" in result:
                ap_out["notes"] = result["notes"]
                vuln_out["notes"] = result["notes"]
                ev_out["notes"] = result["notes"]

            with open(os.path.join(output_target, "attack-paths.json"), 'w', encoding='utf-8') as f:
                json.dump(ap_out, f, indent=2)
            with open(os.path.join(output_target, "vulnerability-results.json"), 'w', encoding='utf-8') as f:
                json.dump(vuln_out, f, indent=2)
            with open(os.path.join(output_target, "evidence.json"), 'w', encoding='utf-8') as f:
                json.dump(ev_out, f, indent=2)
            print(f"Successfully generated updated shared schema JSON files in {output_target}")
    else:
        sample_manifest = {"application_id": "com.inj.android", "components": [{"id": "MainActivity", "name": "MainActivity", "exported": True}]}
        sample_static = {"flows": [{"id": "flow-001", "component_id": "MainActivity", "type": "RCE", "source": "Intent", "sink": {"class": "android.webkit.WebView", "method": "loadUrl(Ljava/lang/String;)V"}}]}
        sample_runtime = {"application_id": "com.inj.android", "events": [{"id": "ev-001", "class": "android.webkit.WebView", "method": "loadUrl", "arguments": ["http://test.com"]}]}
        print(json.dumps(run_correlation(sample_manifest, sample_static, sample_runtime), indent=2))