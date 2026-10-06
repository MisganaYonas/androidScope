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
└── frida/
    ├── webview_hook.js
    ├── intent_hook.js
    └── activity_lifecycle_hook.js
```

- `webview_hook.js` observes selected WebView APIs, navigation callbacks, and WebChromeClient callbacks.
- `intent_hook.js` observes Activity intent retrieval, new intents, and Activity launches, recording selected Intent fields and safe primitive extras.
- `activity_lifecycle_hook.js` observes Activity lifecycle callback dispatch and records the concrete Activity class and lifecycle state.

The scripts are independent and can be loaded separately with Frida. There is not yet a dynamic-analysis host, unified loader, event store, or correlation engine in the repository.

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

## 7. What Dynamic Analysis Does NOT Do Yet

The current implementation does not provide:

- Complete runtime taint tracking
- Automatic source-to-sink data-flow tracking
- Attack-path generation
- Static/dynamic finding correlation
- A runtime event collector, storage layer, or correlation engine
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

The tests establish the listed behaviors only; they do not establish that every implemented hook is exercised or that unimplemented capabilities are supported.

## 9. Current Goal

The current goal is to establish a clear, verified baseline for the dynamic-analysis work before adding more sensors. Future work should be incremental and security-focused: select a next runtime category based on the static-analysis evidence and correlation needs, define the event evidence it should produce, and validate it against a real application. No additional runtime category or correlation engine is implemented by this state document.
