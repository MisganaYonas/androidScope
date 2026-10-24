# androidScope
Android security analysis platform for mapping attack surfaces, tracing runtime behavior, and visualizing potential attack paths.

## Running the Attack-Surface Analyzer

### Requirements

- Python 3
- Apktool installed and accessible at `C:\apktool\apktool.bat` on Windows
- An Android APK file to analyze

The analyzer uses Apktool to decode the APK's Android manifest. Ensure Apktool is installed on the machine that runs the analyzer.

### Run the analyzer

From the repository root:

```powershell
python .\modules\attack_surface\analyzer.py `
  "$env:USERPROFILE\Downloads\InjuredAndroid-1.0.12-release.apk" `
  -o ".\shared\examples\manifest-result.json" `
  --application-id "example-injuredandroid"
```

Replace the APK path with the path to your own APK. The `--application-id` value is the platform/backend's application identifier; it is not the Android package name.

Arguments:

- `APK_PATH`: required positional path to the APK.
- `-o` / `--output`: destination JSON report path.
- `--application-id`: optional identifier supplied by the backend.

The analyzer creates the output directory if necessary, writes a JSON report, and exits with a nonzero status when analysis fails.

### Output schema

The report contains:

- `application_id`: platform/backend identifier, when supplied.
- `package_name`: Android package name from the manifest.
- `apk_file`: APK path or filename recorded by the analyzer.
- `target_sdk`: target SDK version, or `null` when unavailable.
- `permissions`: permissions declared by the application.
- `components`: discovered activities, activity aliases, services, receivers, and providers.
- `summary.component_count`: number of discovered components.
- `summary.potentially_external_count`: number classified as potentially externally reachable.

Each component includes:

- `component_id`: identifier unique within this report, such as `component-001`.
- `type`: component type.
- `name`: fully qualified component name.
- `exported_declared`: explicit manifest `android:exported` value, or `null` when omitted.
- `exported`: effective or inferred exported status (`true`, `false`, or `null` if unknown).
- `exported_source`: `"manifest"` when `android:exported` is explicitly declared, or    `"inferred_from_manifest_defaults"` when the analyzer infers the effective exported status because the attribute is omitted.
- `target_sdk`: the declared target SDK, or `null` if absent from
  the manifest. `compileSdkVersion` is not a substitute.
- `target_sdk_source`: `"manifest"` if the target SDK is declared,
  or `"not_declared"` otherwise.
- `reachability`: reachability classification.
- `permission`: component-level permission, if declared.
- `enabled`: manifest enabled value, if declared.
- `intent_filters`: intent filters, including their actions, categories, and data attributes.
- `target_activity`: target activity for an activity alias, when applicable.

**`exported_inference_note`**

A string explaining why the component's exported status was inferred or remains unresolved, or `null` when the component has an explicitly declared `android:exported` value.

Possible explanations include:
- The target SDK is missing or invalid, so API 1 legacy defaults were used for inference. This is an assumption and does not mean the APK declares target SDK 1.
- The target SDK is 31 or higher, an eligible component has an intent filter, and `android:exported` is not declared, so the effective status remains unresolved.

This field is present on every component. Existing fields and values, including `exported`, `exported_source`, and `reachability`, remain unchanged.

### Exported-status and reachability assumptions

The analyzer preserves an explicit `android:exported` value when one is present.

When `android:exported` is omitted, the analyzer infers a default based on component type and intent filters. Providers require separate handling because their default behavior depends on the app's target SDK. If the target SDK is unavailable, any inferred provider status relies on the analyzer's documented fallback assumption.

For apps targeting Android 12 (API 31) or later, components with intent filters generally must explicitly declare `android:exported`. An inferred value in the report does not establish that Android will install or run the app successfully.

Reachability labels are analysis hints, not proof of exploitability:

- `potentially_external`: the component is classified as exported.
- `not_exported`: the component is classified as not exported.
- `needs_platform_rule_evaluation`: additional platform-specific evaluation is required.
- `unknown`: the analyzer cannot confidently determine the status.

An exported component may still be protected by permissions or other checks. A potentially external component is not automatically vulnerable.

### Example report

See [`shared/examples/manifest-result.json`](../../shared/examples/manifest-result.json) for a report generated from InjuredAndroid.
