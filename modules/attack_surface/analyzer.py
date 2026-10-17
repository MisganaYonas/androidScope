
import argparse 
import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def get_android_attribute(element, name):
    """Read an attribute in the Android XML namespace."""
    return element.get(f"{ANDROID_NS}{name}")


def resolve_component_name(package_name, name):
    """Convert relative component names into full names."""
    if not name:
        return None

    if name.startswith("."):
        return package_name + name

    if "." not in name:
        return f"{package_name}.{name}"

    return name


def parse_intent_filters(component):
    """Extract intent actions, categories, and URI declarations."""
    filters = []

    for intent_filter in component.findall("intent-filter"):
        actions = [
            get_android_attribute(item, "name")
            for item in intent_filter.findall("action")
        ]

        categories = [
            get_android_attribute(item, "name")
            for item in intent_filter.findall("category")
        ]

        data_items = []

        for data in intent_filter.findall("data"):
            attributes = [
                "scheme", "host", "port", "path",
                "pathPrefix", "pathPattern", "mimeType",
                "ssp", "sspPrefix"
            ]

            data_items.append({
                name: get_android_attribute(data, name)
                for name in attributes
                if get_android_attribute(data, name) is not None
            })

        filters.append({
            "actions": [x for x in actions if x],
            "categories": [x for x in categories if x],
            "data": data_items
        })

    return filters


def parse_manifest(manifest_path, apk_path):
    root = ET.parse(manifest_path).getroot()
    package_name = root.get("package", "")

    uses_sdk = root.find("uses-sdk")
    target_sdk = (
        get_android_attribute(uses_sdk, "targetSdkVersion")
        if uses_sdk is not None else None
    )

    permissions = []

    for element in root:
        if element.tag.startswith("uses-permission"):
            name = get_android_attribute(element, "name")
            if name:
                permissions.append(name)

    components = []
    application = root.find("application")

    component_types = {
        "activity": "activity",
        "activity-alias": "activity_alias",
        "service": "service",
        "receiver": "receiver",
        "provider": "provider"
    }

    if application is not None:
        for tag, component_type in component_types.items():
            for element in application.findall(tag):
                name = resolve_component_name(
                    package_name,
                    get_android_attribute(element, "name")
                )

                exported_raw = get_android_attribute(
                    element, "exported"
                )

                intent_filters = parse_intent_filters(element)

                if exported_raw is None:
                    exported_declared = None
                    exported_source = "not_declared"
                else:
                    exported_declared = (
                        exported_raw.lower() == "true"
                    )
                    exported_source = "manifest"

                if exported_declared is True:
                    reachability = "potentially_external"
                elif exported_declared is False:
                    reachability = "not_exported"
                elif intent_filters:
                    reachability = "needs_platform_rule_evaluation"
                else:
                    reachability = "unknown"

                item = {
                    "component_id": (
                        f"component-{len(components) + 1:03d}"
                    ),
                    "type": component_type,
                    "name": name,
                    "exported_declared": exported_declared,
                    "exported_source": exported_source,
                    "reachability": reachability,
                    "permission": get_android_attribute(
                        element, "permission"
                    ),
                    "enabled": get_android_attribute(
                        element, "enabled"
                    ),
                    "intent_filters": intent_filters
                }

                if component_type == "activity_alias":
                    item["target_activity"] = resolve_component_name(
                        package_name,
                        get_android_attribute(element, "targetActivity")
                    )

                components.append(item)

    return {
        "application_id": package_name,
        "apk_file": apk_path.name,
        "target_sdk": target_sdk,
        "permissions": permissions,
        "components": components,
        "summary": {
            "component_count": len(components),
            "potentially_external_count": sum(
                item["reachability"] == "potentially_external"
                for item in components
            )
        }
    }


def analyze_apk(apk_path, output_path):
    apk_path = Path(apk_path).resolve()
    output_path = Path(output_path).resolve()

    if not apk_path.is_file() or apk_path.suffix.lower() != ".apk":
        raise ValueError(f"APK file not found: {apk_path}")

    with tempfile.TemporaryDirectory(prefix="droidtrace_") as temp:
        decoded_dir = Path(temp) / "decoded"

        command = [
            r"C:\apktool\apktool.bat",
            "d",
            "--only-manifest",
            "-f",
            "-o", str(decoded_dir),
            str(apk_path)
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            shell=True,
            input=""
        )

        if result.returncode != 0:
            raise RuntimeError(
                result.stderr or result.stdout or "Apktool failed"
            )

        manifest_path = decoded_dir / "AndroidManifest.xml"

        if not manifest_path.is_file():
            raise FileNotFoundError(
                "Decoded AndroidManifest.xml was not found."
            )

        report = parse_manifest(manifest_path, apk_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("Analysis complete!")
    print(f"Package: {report['application_id']}")
    print(f"Components: {report['summary']['component_count']}")
    print(f"JSON saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="DroidTrace APK attack-surface analyzer"
    )

    parser.add_argument("apk", help="Path to an APK file")
    parser.add_argument(
        "-o", "--output",
        default="attack_surface.json",
        help="Path for the JSON output"
    )

    args = parser.parse_args()

    try:
        analyze_apk(args.apk, args.output)
    except (
        ValueError,
        RuntimeError,
        FileNotFoundError,
        ET.ParseError,
        OSError
    ) as error:
        parser.exit(1, f"Error: {error}\n")


if __name__ == "__main__":
    main()
