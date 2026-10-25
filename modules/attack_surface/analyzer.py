
import argparse
import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import os
import shutil
from pathlib import Path


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

def find_apktool():
    """Find Apktool using environment, PATH, then the Windows default."""
    candidates = []

    configured_path = os.environ.get("APKTOOL_PATH")
    if configured_path:
        candidates.append(configured_path.strip().strip('"'))

    path_executable = shutil.which("apktool")
    if path_executable:
        candidates.append(path_executable)

    candidates.append(r"C:\apktool\apktool.bat")

    checked = []
    for candidate in candidates:
        if not candidate or candidate in checked:
            continue
        checked.append(candidate)

        if Path(candidate).is_file():
            return candidate

    locations = "\n".join(f"  - {path}" for path in checked)
    raise FileNotFoundError(
        "Apktool not found. Checked these locations:\n" + locations
    )


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


def get_effective_exported(
    component_type, exported_declared, intent_filters, target_sdk
):
    """Return declared or inferred exported status.

    target_sdk is the SDK declared in the manifest. If it is missing
    or invalid, use API 1 as a legacy-default assumption for inference;
    this assumption does not mean the manifest declared target SDK 1.

    For apps targeting API 31+, an activity, activity alias, service,
    or receiver with intent filters must explicitly declare
    android:exported. If it does not, return None because the effective
    status needs platform-rule evaluation.
    """
    if exported_declared is not None:
        return exported_declared

    try:
        effective_target_sdk = int(target_sdk) if target_sdk else 1
    except (TypeError, ValueError):
        effective_target_sdk = 1

    if (
        effective_target_sdk >= 31
        and intent_filters
        and component_type in {
            "activity", "activity_alias", "service", "receiver"
        }
    ):
        return None

    if component_type == "provider":
        return effective_target_sdk <= 16

    if component_type in {
        "activity", "activity_alias", "service", "receiver"
    }:
        return bool(intent_filters)

    return None


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
                    exported_source = "inferred_from_manifest_defaults"
                else:
                    exported_declared = exported_raw.lower() == "true"
                    exported_source = "manifest"

                exported_effective = get_effective_exported(component_type, exported_declared, intent_filters, target_sdk)

                if exported_effective is True:
                    reachability = "potentially_external"
                elif exported_effective is False:
                    reachability = "not_exported"
                elif intent_filters:
                    reachability = "needs_platform_rule_evaluation"
                else:
                    reachability = "unknown"

                exported_inference_note = None

                if exported_declared is None:
                    if reachability == "needs_platform_rule_evaluation":
                        exported_inference_note = (
                            "android:exported is not declared for a component "
                            "with an intent filter and target SDK 31 or higher; "
                            "effective exported status is unresolved."
                        )
                    elif exported_source == "inferred_from_manifest_defaults":
                        try:
                            note_target_sdk = (
                                int(target_sdk) if target_sdk else None
                            )
                        except (TypeError, ValueError):
                            note_target_sdk = None

                        if note_target_sdk is None:
                            exported_inference_note = (
                                "Target SDK is missing or invalid; exported status "
                                "was inferred using API 1 legacy defaults. "
                                f"Inferred exported status: {exported_effective}."
                            )
                        else:
                            exported_inference_note = (
                                "android:exported is not declared; exported status "
                                "was inferred using manifest defaults for target "
                                f"SDK {note_target_sdk}. "
                                f"Inferred exported status: {exported_effective}."
                            )

                item = {
                     "component_id": (
                        f"component-{len(components) + 1:03d}"
                    ),
                    "type": component_type,
                    "name": name,
                    "exported_declared": exported_declared,
                    "exported": exported_effective,
                    "exported_source": exported_source,
                    "exported_inference_note": exported_inference_note,
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
        "package_name": package_name,
        "apk_file": apk_path.name,
        "target_sdk": target_sdk,
        "target_sdk_source": (
            "manifest"
            if target_sdk is not None
            else "not_declared"
        ),
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

def analyze_apk(apk_path, output_path, application_id=None):
    apk_path = Path(apk_path).resolve()
    output_path = Path(output_path).resolve()

    if not apk_path.is_file() or apk_path.suffix.lower() != ".apk":
        raise ValueError(f"APK file not found: {apk_path}")

    with tempfile.TemporaryDirectory(prefix="droidtrace_") as temp:
        decoded_dir = Path(temp) / "decoded"

        apktool_path = find_apktool()
        command = [
            apktool_path,
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
        if application_id is not None:
            report["application_id"] = application_id

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("Analysis complete!")
    print(f"Application ID: {report['application_id']}")
    print(f"Android package: {report['package_name']}")
    print(f"Target SDK: {report['target_sdk']}")
    print(f"Target SDK Source: {report['target_sdk_source']}")
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
    parser.add_argument(
        "--application-id",
        default=None,
        help="Backend application ID, e.g. application-004"
    )

    args = parser.parse_args()

    try:
        analyze_apk(args.apk, args.output, application_id=args.application_id)
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
