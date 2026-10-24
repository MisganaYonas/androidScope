# Dynamic-analysis runtime evidence

This directory contains two preserved InjuredAndroid runtime captures for
application ID `application-015`.

## Files

| File | Contents |
|---|---|
| `runtime-events-submission.json` | Normalized event object from the initial capture: the observed `TestBroadcastReceiver.onReceive` and `WebView.loadUrl` calls. |
| `runtime-events-submission.raw.json` | Six original Frida observations from that capture, including hook readiness, both method calls, and WebView page callbacks. |
| `runtime-events-submission.raw.errors.json` | Collector diagnostics for the initial capture; an empty array indicates no recorded diagnostics. |
| `runtime-events-followup.json` | Normalized event object from the follow-up: the observed receiver and WebView method calls. |
| `runtime-events-followup.raw.json` | Seventeen original Frida observations: hook readiness, two method calls, WebView page callbacks, and ten Activity lifecycle events. |
| `runtime-events-followup.raw.errors.json` | Collector diagnostics for the follow-up capture; an empty array indicates no recorded diagnostics. |

## Collection and validation

Both captures used the existing AndroidScope Frida Intent and WebView hooks
against InjuredAndroid on the connected Android 11 Genymotion device. The
follow-up also enabled the existing Activity lifecycle hook. Hooks were
attached before opening `TestBroadcastReceiver` and sending the verified
package-restricted `CUSTOM_INTENT` broadcast with `url=about:blank`. A
temporary Frida-only shim supplied the WebView view expected by this Activity;
the APK's receiver handled the broadcast and made the observed `loadUrl` call.
The shim did not itself call `loadUrl`, and the APK was not modified.

The normalized JSON preserves method identity, arguments, and timestamps from
the raw Frida `method_call` records. Event IDs are assigned during formatting.
Both normalized captures were checked against their respective raw logs, their
JSON/schema fields were validated, and their diagnostics arrays were empty.
The follow-up counts were verified as 17 raw records, ten lifecycle records,
and two normalized method calls.

## Integration caveat

The `application_id` is `application-015`. Normalized events use
`type: "method_call"` and contain `id`, `type`, `class`, `method`,
`arguments`, and `timestamp`. Lifecycle and WebView navigation callbacks stay
in the raw Frida files; the normalized target-event converter only includes
the receiver and WebView method calls. These observations document exercised
runtime behavior only; they do not establish general taint propagation,
causality, or exploitability. The receiver call was observed with the
Frida-only UI shim active, which should be disclosed when interpreting or
correlating the evidence.
