# Intent extra to WebView runtime fixture

This small Android app exercises an Intent string extra flowing into
`WebView.loadUrl()` so the existing AndroidScope Frida hooks can be checked
together. The Activity only accepts a `file:///android_asset/` test URL with a
short alphanumeric run ID. It makes no network requests and needs no Internet
permission.

The source assignment and sink call intentionally use the static analyzer's
existing `getStringExtra(...)` to `loadUrl(variable)` pattern.

This is a controlled end-to-end observation test, not general taint tracking:
seeing the same unique value in both events verifies this specific exercised
case only.

## Prerequisites

- Windows PowerShell, JDK 17, Gradle 8.9, and Android SDK Platform 35.
- Python 3.9+ with the Frida Python bindings matching the device server, for
  example `python -m pip install frida==17.22.2`.
- The Frida tools package, which provides the Java bridge bundle used by the
  collector, for example `python -m pip install frida-tools==14.11.0`.
- An Android emulator/device connected to ADB.
- Frida client and a compatible Frida server running on the device. The app
  process must be attachable by Frida; a rooted emulator is one supported setup.
- The repository cloned on the host running Gradle, ADB, and Frida.

Check the tools and device before starting:

```powershell
java -version
gradle --version
adb devices
frida --version
```

## Build and install

Run these commands from the repository root:

```powershell
gradle -p dynamic\tests\fixtures\intent-webview assembleDebug
adb install -r dynamic\tests\fixtures\intent-webview\app\build\outputs\apk\debug\app-debug.apk
adb shell am force-stop com.androidscope.dynamicfixture
adb shell monkey -p com.androidscope.dynamicfixture 1
```

The launcher Activity keeps the app process alive for Frida to attach. Leave
the app running on its introductory screen.

## Collect events and exercise the flow

In a second PowerShell terminal at the repository root, run the collector.
It attaches to the already-running launcher Activity, loads the existing
Intent and WebView hooks, and writes the event array and a separate diagnostics
file. Keep this terminal open:

```powershell
python dynamic\collect_events.py --target com.androidscope.dynamicfixture --hooks intent webview --output dynamic\output\intent-webview-events.json
```

For Linux/macOS, the equivalent command is:

```sh
python3 dynamic/collect_events.py --target com.androidscope.dynamicfixture --hooks intent webview --output dynamic/output/intent-webview-events.json
```

Wait for the collector to print `Hooks initialized`. The collector waits for
both selected hooks to emit `hook_status` with `metadata.status: "ready"` and
exits with an error instead of starting collection if initialization fails or
times out. In a third terminal, start the exported test Activity with a unique,
harmless test value:

```powershell
$runId = "androidscope-20261023-01"
$testUrl = "file:///android_asset/test-page.html?run=$runId"
adb shell am start -n com.androidscope.dynamicfixture/.IntentWebViewActivity --es test_url "$testUrl"
```

Linux/macOS:

```sh
run_id=androidscope-20261023-01
test_url="file:///android_asset/test-page.html?run=$run_id"
adb shell am start -n com.androidscope.dynamicfixture/.IntentWebViewActivity --es test_url "$test_url"
```

Use a new run ID for each run. Keep it to letters, digits, and hyphens. The
`file:///android_asset/` URL resolves only to the HTML packaged in this fixture.
No external URL or destination is used.

## Stop and verify the exported JSON

After the page loads, press **Ctrl+C** in the collector terminal. It unloads
the hooks, detaches, and atomically saves a JSON array to
`dynamic/output/intent-webview-events.json`. Frida or collector errors are
printed to stderr and saved separately to
`dynamic/output/intent-webview-events.errors.json`. The default output, if
`--output` is omitted, is `dynamic/output/runtime-events.json`, with
`runtime-events.errors.json` as its diagnostics file. A normal zero-event
collection still writes `[]`.

Verify that both events contain the exact test URL using the fixture verifier:

```powershell
python dynamic\tests\verify_intent_webview_events.py dynamic\output\intent-webview-events.json $runId
```

Linux/macOS:

```sh
python3 dynamic/tests/verify_intent_webview_events.py dynamic/output/intent-webview-events.json "$run_id"
```

Both checks must report `PASS`: one for an `intent_incoming` event whose
`metadata.primitive_extras` contains `test_url` equal to the constructed URL,
and one for a `method_call` event for `android.webkit.WebView.loadUrl` whose
first argument and `metadata.url` equal that same URL. The verifier exits
nonzero if either observation is missing. The local page rendering is
additional confirmation, not a substitute for checking the saved events.

## Troubleshooting

- **No process to attach:** Confirm the launcher screen is open and
  `adb shell pidof com.androidscope.dynamicfixture` returns a PID.
- **Frida attach or script errors:** Confirm the device is listed by
  `adb devices`, the Frida client/server versions are compatible, and the
  server is running with permission to attach to the app.
- **Collector reports `Java` unavailable or times out before initialization:**
  Confirm the installed `frida-tools` package contains the Java bridge bundle
  and check the reported diagnostics. The collector initializes the bridge and
  checks `Java.available` before loading each hook. If a selected hook never
  reports ready, it does not claim collection started.
- **Missing `intent_incoming`:** Check that the hook reported ready before
  running `adb shell am start`; repeat the Activity launch with a fresh run ID.
- **Missing `loadUrl`:** Check the incoming event has a non-truncated
  `test_url` value beginning with the exact local prefix. The fixture rejects
  other values without loading them.
- **The app shows its explanatory message:** The `test_url` extra was absent or
  did not satisfy the fixture's local-asset URL and run-ID checks.
- **Build fails:** Verify JDK 17, Gradle 8.9, Android SDK Platform 35, and that
  the Android SDK location is configured for Gradle.

This repository fixture and its instructions have not been emulator-validated
unless a test run is separately recorded. A passing build or source inspection
does not establish that Frida observed the runtime events on a particular
device.
