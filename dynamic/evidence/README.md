# Dynamic-analysis runtime evidence

This directory contains two preserved historical InjuredAndroid runtime
captures and an exact-APK recapture (including an unmodified trial) for
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
| `runtime-events-exact-apk.json` | Normalized exact-APK capture: the observed receiver and `WebView.loadUrl` calls. |
| `runtime-events-exact-apk.raw.json` | Five Frida observations from the exact-APK capture: three hook readiness records and two method calls. |
| `runtime-events-exact-apk.raw.errors.json` | Collector diagnostics for the exact-APK capture; an empty array indicates no recorded diagnostics. |
| `runtime-events-exact-apk-unmodified-trial.json` | No-shim exact-APK trial: the receiver call was observed before the APK crashed on its null WebView. |
| `runtime-events-exact-apk-unmodified-trial.raw.json` | Four original Frida observations from the no-shim trial: three hook readiness records and the receiver call. |
| `runtime-events-exact-apk-unmodified-trial.raw.errors.json` | Collector teardown diagnostics from the no-shim trial; the process crash destroyed the loaded Frida scripts. |

## Exact-APK recapture

The new capture was taken on 2026-10-24 against the already-installed package
`b3nac.injuredandroid`, without reinstalling or modifying the APK. The installed
`base.apk` and `C:\Users\User\Downloads\InjuredAndroid-installed-new.apk` both
have SHA-256
`53d432d25214df585a391fc0fea3adace88539bea81576351313657288e2a679`.
Installed metadata reports versionName `1.0.9` and versionCode `17`. The
device is Android 11, x86_64, at ADB serial `192.168.172.101:5555`.
The Windows `frida.exe` CLI was blocked by the existing Application Control
policy, which was not changed; the installed Frida 17.22.2 Python bindings
loaded the same repository hook scripts directly.

The Intent, WebView, and `Runtime.exec` Frida hooks were attached to the
`InjuredAndroid` process and reported ready before opening
`b3nac.injuredandroid/.TestBroadcastReceiver`. The test then sent the
package-restricted broadcast:

```text
am broadcast -a com.b3nac.injuredandroid.intent.action.CUSTOM_INTENT -p b3nac.injuredandroid --es url about:blank
```

The no-shim trial first observed `TestBroadcastReceiver$b.onReceive` with the
requested action and `url=about:blank`, then the APK threw a
`NullPointerException` when it called `WebView.loadUrl` on the null view found
at ID `0x7f080003`. This confirms the view workaround was necessary to observe
the intended sink. For the final capture, the existing
`frida/test_broadcast_receiver_webview_shim.js` was loaded before opening the
Activity. It added a runtime-only WebView with that ID after the Activity's
original `onCreate`; it did not change the APK or call `loadUrl`. The actual
receiver handled the broadcast and made the observed `loadUrl("about:blank")`
call. These final results are therefore shim-assisted and are labeled as such.

The final raw capture contains five records: readiness for the Intent, WebView,
and `Runtime.exec` hooks, followed by the observed receiver and
`WebView.loadUrl` method calls. The normalized capture contains two events,
`event-001` (`TestBroadcastReceiver.onReceive`) and `event-002`
(`WebView.loadUrl`), with `application_id: application-015`; its diagnostics
array is empty. The `Runtime.exec` hook was active, but no `Runtime.exec` call
was observed, so none is recorded.

Manifest inspection shows `TestBroadcastReceiver` is an Activity, and package
manager resolution found no manifest receiver for
`com.b3nac.injuredandroid.intent.action.CUSTOM_INTENT`. The Activity's DEX
registers the inner class `TestBroadcastReceiver$b` with an `IntentFilter` for
that action in `onCreate`; the inner class implements `onReceive`, reads the
`url` extra, looks up the WebView by ID, and calls `loadUrl`. Runtime delivery
to `onReceive` confirms this dynamically registered path. The normalized
schema reports the enclosing Activity name for the receiver method.

This is evidence of the exercised behavior only. The no-shim crash and
shim-assisted success reflect the Activity's missing view under these test
conditions; they do not establish general taint propagation, causality, or
exploitability. The historical captures below predate this exact-APK run and
retain their original identity caveat.

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

## Historical receiver and APK identity

In the APK used for the historical captures, `b3nac.injuredandroid.TestBroadcastReceiver`
was declared as an Activity, not as a manifest `<receiver>`. Its DEX contains
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
