# Dynamic Analysis — Current State

## 1. Purpose

Dynamic analysis observes what an APK actually does while it is running. The current instrumentation uses ADB to interact with an Android target and Frida hooks to capture selected runtime behavior as structured events.

This complements static analysis:

- Static analysis determines what the APK *could potentially do* from its code and configuration.
- Dynamic analysis observes what the APK *actually does when executed* under the exercised runtime conditions.

The dynamic component is intended to capture security-relevant evidence that can later be compared with static findings. It is not a general-purpose application logger or an automated vulnerability scanner.

## 2. Current Architecture

The current dynamic-analysis implementation is a set of focused Frida scripts:

```text
dynamic/
├── collect_events.py
├── frida/
│   ├── webview_hook.js
│   ├── intent_hook.js
│   └── activity_lifecycle_hook.js
└── tests/
    ├── test_collect_events.py
    ├── verify_intent_webview_events.py
    └── fixtures/
        └── intent-webview/
```

The controlled Intent-extra-to-WebView test fixture is under
`dynamic/tests/fixtures/intent-webview/`. Its README documents how to build and
install the app, collect events with the existing Intent and WebView hooks, and
verify the same local test URL in both events. The collector records events; it
does not implement taint tracking.

- `webview_hook.js` observes selected WebView APIs, navigation callbacks, and WebChromeClient callbacks.
- `intent_hook.js` observes Activity intent retrieval, new intents, and Activity launches, recording selected Intent fields and safe primitive extras.
- `activity_lifecycle_hook.js` observes Activity lifecycle callback dispatch and records the concrete Activity class and lifecycle state.

The scripts are independent Frida hooks. `collect_events.py` is a small host
utility that attaches to an already-running process, loads selected hooks, and
exports received events. There is no automated app launcher or static/dynamic
correlation engine in this dynamic component.

## 3. Implemented Runtime Sensors

### WebView Runtime Hook

`webview_hook.js` currently monitors:

- `WebView.loadUrl(String)`
- `WebView.loadUrl(String, Map)`
- `WebView.loadData(String, String, String)`
- `WebView.loadDataWithBaseURL(String, String, String, String, String)`
- `WebView.evaluateJavascript(String, ValueCallback)`
- `WebView.addJavascriptInterface(Object, String)`
- `WebView.setWebViewClient(WebViewClient)`
- Both `WebViewClient.shouldOverrideUrlLoading` overloads taking a `String` or `WebResourceRequest`
- `WebViewClient.onPageStarted`
- `WebViewClient.onPageFinished`
- `WebViewClient.onLoadResource`
- `WebChromeClient.onConsoleMessage(ConsoleMessage)`
- `WebChromeClient.onJsAlert(WebView, String, String, JsResult)`

The overloaded methods use explicit Frida `.overload(...)` selection. This was necessary for `WebChromeClient.onConsoleMessage`, which also has a `(String, int, String)` overload; selecting `onConsoleMessage(ConsoleMessage)` avoids ambiguous hook initialization.

The script emits events through Frida `send()` using the common fields `event_type`, `timestamp`, `class`, `method`, `arguments`, and `metadata`. It includes `return_value` when the hooked method returns a value. Event types include `method_call`, `webview_page_started`, `webview_page_finished`, `console_message`, and `hook_status`.

**Runtime validation:** The hook was run against InjuredAndroid, and the following were observed:

- `WebView.loadData`
- `WebViewClient.onLoadResource`
- `WebViewClient.onPageStarted`
- `WebViewClient.onPageFinished`

Other hooks are implemented in the script, but the runtime observations above are the WebView events verified for this project state.

### Intent / IPC Runtime Hook

`intent_hook.js` currently monitors these `android.app.Activity` methods:

- `Activity.getIntent()`
- `Activity.onNewIntent(Intent)`
- `Activity.startActivity(Intent)`
- `Activity.startActivity(Intent, Bundle)`

All four use explicit Frida overload selection.

Incoming and outgoing events use the shared structured-event shape. Intent metadata includes, where present:

- Activity class
- Action, data URI, MIME type, and package
- Explicit component package and class
- Categories and flags
- Extra keys
- Allowlisted primitive extra values (strings, booleans, characters, numeric wrappers and directly exposed primitive values)

Strings are limited to 1,024 characters. Arbitrary or complex extra objects are not serialized; their keys are still recorded. This limits unnecessary collection of potentially sensitive data and avoids treating complex objects as safe scalar values.

During live testing, Android's one-argument `startActivity(Intent)` delegated to the Bundle overload, which initially made one launch appear as two events. The hook was adjusted to suppress a nested event during that delegation. A normal Activity launch then produced one outgoing event rather than two.

**Runtime validation:** On a rooted Android 11 Genymotion emulator with InjuredAndroid and Frida 17.22.2:

- An `intent_incoming` event was observed through `getIntent()`.
- That incoming event included String, integer, and Boolean extras.
- An Activity launch produced an `intent_outgoing` event containing the explicit target component.

### Activity Lifecycle Runtime Hook

`activity_lifecycle_hook.js` monitors the lifecycle dispatch methods on `android.app.Instrumentation`:

- `callActivityOnCreate(Activity, Bundle)`
- `callActivityOnStart(Activity)`
- `callActivityOnResume(Activity)`
- `callActivityOnPause(Activity)`
- `callActivityOnStop(Activity)`
- `callActivityOnDestroy(Activity)`

These methods are explicitly selected with Frida `.overload(...)`. Hooking the framework's Activity dispatch boundary allows the sensor to observe lifecycle dispatch for app-defined Activity subclasses without treating a base-class method hook as coverage of overridden callbacks.

For each dispatch, the script sends an `activity_lifecycle` event with the concrete Activity class name, the corresponding lifecycle method, a timestamp, arguments, and `metadata.lifecycle_state`. For `onCreate`, the only Bundle information recorded is whether the saved-instance-state Bundle was present; its contents are not dumped. Events report lifecycle dispatch only and do not imply that the component is externally reachable, vulnerable, or that its callback completed successfully.

**Runtime validation:** With InjuredAndroid on the rooted Android 11 Genymotion emulator and Frida 17.22.2, the hook emitted events for all six lifecycle states across a spawned launch, app background/foreground, Activity navigation, and back navigation:

- `onCreate` / `created`
- `onStart` / `started`
- `onResume` / `resumed`
- `onPause` / `paused`
- `onStop` / `stopped`
- `onDestroy` / `destroyed`

## 4. Frida Environment Used for Testing

The current runtime validations used:

- Windows host
- ADB connection to a rooted Android 11 Genymotion emulator
- Frida 17.22.2 client and server, with `frida-server` running as root on the Android VM
- InjuredAndroid as the test application

Machine-specific usernames, device addresses, and other local identifiers are intentionally omitted.

## 5. Runtime Event Model

Events are sent as structured objects rather than plain console messages so a future collector or correlation engine can consume the method identity, arguments, timestamps, and context as fields.

### JSON Event Collector

`dynamic/collect_events.py` uses the Frida Python bindings, loads the existing
hook scripts, and appends each JSON-serializable object delivered in a Frida
`send` message to an ordered JSON array. Frida errors, script logs, and invalid
messages are kept separately in a sibling `.errors.json` array and reported to
stderr; they are not mixed into runtime event records. Both files are written
through a temporary file and atomically replaced on normal shutdown or Ctrl+C.
An empty collection is exported as `[]`.

Frida CLI runs user scripts inside a REPL agent that provides a lazy `Java`
global and answers `frida:load-bridge` requests. Raw Python
`Session.create_script()` does not run that agent and does not automatically
define `Java`; a standalone hook beginning with `Java.perform(...)` therefore
fails with `ReferenceError: 'Java' is not defined`. The collector prepares each
hook by evaluating the Java bridge bundle shipped with `frida-tools` through
Frida's `Script.evaluate()` API, defining the `Java` global, and checking
`Java.available` before evaluating the unchanged hook in the `qjs` runtime used
by the CLI by default. It waits for a `hook_status` ready event from every
selected hook before reporting collection started; Frida errors, missing Java
support, or a startup timeout are reported and prevent a ready state.

For example, `runtime-events.json` contains an array like:

```json
[
  {
    "event_type": "method_call",
    "timestamp": "2026-10-06T19:00:00.000Z",
    "class": "android.webkit.WebView",
    "method": "loadUrl",
    "arguments": ["file:///android_asset/test-page.html?run=sample-1"],
    "metadata": {
      "url": "file:///android_asset/test-page.html?run=sample-1"
    }
  }
]
```

The event object is the original Frida `send` payload; the collector does not
add wrapper fields to it. The diagnostics sidecar is a JSON array whose items
identify the diagnostic `kind` and retain the Frida message when JSON-safe.

Run from the repository root:

```powershell
python dynamic\collect_events.py --target com.androidscope.dynamicfixture --hooks intent webview --output dynamic\output\intent-webview-events.json
```

The default target is the fixture package, the default device is the first
connected USB device, all three hooks load by default, and the default output
is `dynamic/output/runtime-events.json`. Use `--device-id` for an explicit
Frida device, `--target` for a process name or PID, `--hooks` to select one or
more of `intent`, `webview`, and `lifecycle`, `--startup-timeout` to set the
hook readiness deadline, and `--verbose` for per-event progress. The host needs
the matching Frida Python bindings and `frida-tools` package. Press Ctrl+C to
unload hooks, detach, and save. The fixture README documents the corresponding
Linux/macOS commands and a JSON verification step.
Use `frida-ls-devices` to list available Frida device IDs.

Run collector unit tests from the repository root with:

```powershell
python -m unittest discover -s dynamic\tests -p "test_collect_events.py" -v
```

The collector stores runtime events only. It neither launches the application
nor proves a data flow or vulnerability.

The WebView hook's event shape is:

```json
{
  "event_type": "method_call",
  "timestamp": "2026-10-06T19:00:00.000Z",
  "class": "android.webkit.WebView",
  "method": "loadUrl",
  "arguments": ["https://example.com"],
  "metadata": {
    "url": "https://example.com"
  }
}
```

The example shows fields emitted by the current hook; timestamp value and URL are illustrative. `return_value` is added by the hooks when a return value is available.

## 6. What Dynamic Analysis Can Currently Observe

| Capability | Status | Evidence |
|---|---|---|
| WebView API execution | Implemented + tested | InjuredAndroid runtime; `loadData` observed |
| WebView navigation lifecycle | Implemented + tested | Runtime events for page started, page finished, and resource loading |
| WebView JavaScript evaluation and interface registration | Implemented; not listed among verified runtime observations | Hooks exist in `webview_hook.js` |
| WebView console messages and JavaScript alerts | Implemented; not listed among verified runtime observations | Explicit `onConsoleMessage(ConsoleMessage)` and `onJsAlert(...)` hooks exist |
| Incoming Activity Intent observation | Implemented + tested | `intent_incoming` observed from `getIntent()` with primitive extras |
| New Activity Intent observation | Implemented; not separately verified at runtime | `onNewIntent(Intent)` hook exists |
| Outgoing Activity launches | Implemented + tested | `intent_outgoing` observed for an InjuredAndroid Activity launch |
| Activity lifecycle dispatch | Implemented + tested | All six lifecycle states observed for InjuredAndroid Activities |
| Structured Frida runtime events | Implemented + tested | Structured WebView and Intent events observed in Frida output |
| S0 — Intent extra to WebView URL flow (IntentWebViewActivity) | Verified with exported JSON | `intent_incoming` and `WebView.loadUrl` both contain matching `test_url`; page start and finish also observed; run ID `s0-regression-01` |
| S1 — addJavascriptInterface and evaluateJavascript (JsiBridgeActivity) | Verified with exported JSON | 5 checks: `addJavascriptInterface` (interface_name=AndroidBridge), `loadUrl`, `onPageStarted`, `onPageFinished`, `evaluateJavascript` (script=document.title) |
| S2 — deep-link and onNewIntent (DeepLinkActivity, singleTop) | Verified with exported JSON | 4 checks: `getIntent` with run ID `dl-first-01`, `loadUrl` run 1, `onNewIntent` with run ID `dl-second-01`, `loadUrl` run 2 |

## 7. What Dynamic Analysis Does NOT Do Yet

The current implementation does not provide:

- Complete runtime taint tracking
- Automatic source-to-sink data-flow tracking
- Attack-path generation
- Static/dynamic finding correlation
- A unified report generator
- Lifecycle observations are limited to Activity callbacks dispatched through the hooked `Instrumentation` methods; other Android component lifecycles are not instrumented
- Service, BroadcastReceiver, or ContentProvider instrumentation
- Complete Intent/IPC coverage beyond the listed Activity methods
- Broad network, file, process execution, or sensitive-storage instrumentation
- An automated vulnerability scanner

These are not current capabilities and should not be inferred from the existing hooks.

## 8. Testing Status

| Validation | Status | Scope |
|---|---|---|
| JavaScript syntax validation (`node --check`) | Passed | All three Frida hook scripts |
| Mocked Frida/API validation | Passed | WebView overload/event, Intent overload/metadata, and lifecycle overload/event smoke tests |
| Real emulator validation | Passed | InjuredAndroid on rooted Android 11 Genymotion with Frida 17.22.2 |
| WebView runtime event observation | Passed | `loadData`, `onLoadResource`, `onPageStarted`, `onPageFinished` |
| Intent runtime event observation | Passed | Incoming Intent with primitive extras and outgoing Activity launch |
| Activity lifecycle runtime event observation | Passed | `onCreate`, `onStart`, `onResume`, `onPause`, `onStop`, and `onDestroy` |
| S0 Intent-to-WebView fixture (IntentWebViewActivity) | PASS | `verify_intent_webview_events.py` against `s0-intent-webview-events.json`; 2 checks passed; run ID `s0-regression-01` |
| S1 JavascriptInterface and evaluateJavascript (JsiBridgeActivity) | PASS | `verify_jsi_events.py` against `s1-jsi-events.json`; 5 checks passed |
| S2 deep-link and onNewIntent (DeepLinkActivity) | PASS | `verify_deeplink_events.py` against `s2-deeplink-events.json`; 4 checks passed; run IDs `dl-first-01` / `dl-second-01` |
| JSON event collector unit tests | PASS — 14 tests | `dynamic/tests/test_collect_events.py`; Java bridge bootstrap, hook readiness/failure, message handling, serialization, mocked shutdown |
| Fixture event verifier with representative JSON | Passed | Synthetic matching Intent/WebView events; no emulator used |
| `git diff --check` | Clean | No whitespace errors |

The tests establish the listed behaviors only; they do not establish that every implemented hook is exercised or that unimplemented capabilities are supported.

For this milestone, 14 collector unit tests passed. All three scenario verifiers
passed against the exported event JSON files in `dynamic/output/`. The three
Frida hook scripts and `collect_events.py` are unchanged from their committed
state. `git diff --check` is clean.

**Correlated observations do not by themselves prove causal data flow, taint
propagation, vulnerability, or exploitability.** The verifiers confirm that the
same unique value appeared in both an Intent event and a WebView event during
the exercised run. They do not establish that no other code path could produce
the same value, that the data flow is exploitable, or that the fixture
represents a general taint-tracking capability.

## 9. Completed Milestone — Runtime Verification

The dynamic-analysis runtime verification milestone is complete. The fixture
exercises three scenarios (S0, S1, S2) against the controlled
`com.androidscope.dynamicfixture` app, and all verifiers pass against the
exported event JSON. The next milestone is correlation and attack-path
generation: cross-referencing dynamic observations with static findings to
produce ranked, evidence-backed attack paths. No correlation engine or
attack-path generator is implemented yet.
