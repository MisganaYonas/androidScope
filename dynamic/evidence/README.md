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

## Receiver and APK identity

In the installed APK manifest, `b3nac.injuredandroid.TestBroadcastReceiver`
is declared as an Activity, not as a manifest `<receiver>`. Its DEX contains
the inner class
`b3nac.injuredandroid.TestBroadcastReceiver$b`, which implements `onReceive`
and is dynamically registered by the Activity. Frida hooks that inner
implementation; the normalized `class` field uses the enclosing Activity
name to retain the project correlation name. The actual receiver implementation
is therefore `$b`, not the manifest-declared Activity itself.

The installed package was later checked on 2026-10-24: versionName `1.0.9`,
versionCode `17`, SHA-256
`b6b8d2dbd7a428b7754e6e537ba5790c35a73253533454e0768dbf1520a7ed15`.
This differs from the teammate-provided expected SHA-256
`53d432d25214df585a391fc0fea3adace88539bea81576351313657288e2a679`.
The capture-time APK hash was not recorded, so byte-for-byte identity with the
teammate's static-analysis APK is not established. The installed package
metadata reports first install and last update on 2026-10-06; no further APK
origin/provenance information was available locally.

## Integration caveat

The `application_id` is `application-015`. Normalized events use
`type: "method_call"` and contain `id`, `type`, `class`, `method`,
`arguments`, and `timestamp`. Lifecycle and WebView navigation callbacks stay
in the raw Frida files; the normalized target-event converter only includes
the receiver and WebView method calls. These observations document exercised
runtime behavior only; they do not establish general taint propagation,
causality, or exploitability. The receiver call was observed with the
Frida-only UI shim active, which should be disclosed when interpreting or
correlating the evidence. The captures contain no observed `Runtime.exec`
call. The `runtime-events-submission.json` and
`runtime-events-followup.json` files in this directory are the validated
captures. The generated `dynamic/output/` files are separate working output
and should not be substituted for these preserved evidence files.
