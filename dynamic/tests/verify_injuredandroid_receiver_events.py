#!/usr/bin/env python3
"""Verify a collected InjuredAndroid run contains the expected receiver-to-WebView events.

Checks (against the raw Frida event array written by collect_events.py):
  1. method_call  b3nac.injuredandroid.TestBroadcastReceiver.onReceive
       arguments[0] == BROADCAST_ACTION
       metadata.extra_value == expected URL
  2. method_call  android.webkit.WebView.loadUrl
       arguments[0] == expected URL
  3. onReceive timestamp precedes loadUrl timestamp
  4. Both events present in the same file (same capture)

Reports whether the capture is shim-assisted (receiver_webview_shim hook_status present)
or unmodified-app (no shim hook_status), and whether the path is complete or partial.
"""

import argparse
import json
from pathlib import Path

BROADCAST_ACTION = "com.b3nac.injuredandroid.intent.action.CUSTOM_INTENT"
RECEIVER_CLASS = "b3nac.injuredandroid.TestBroadcastReceiver"
WEBVIEW_CLASS = "android.webkit.WebView"
SHIM_METHOD = "receiver_webview_shim"


def _meta(event):
    m = event.get("metadata")
    return m if isinstance(m, dict) else {}


def verify_events(events, expected_url):
    """Return a dict of check results and capture metadata."""
    receiver_event = None
    webview_event = None
    shim_active = False

    for e in events:
        if not isinstance(e, dict):
            continue
        et = e.get("event_type")
        cls = e.get("class")
        method = e.get("method")

        if et == "hook_status" and cls == RECEIVER_CLASS and method == SHIM_METHOD:
            shim_active = True
            continue

        if (
            et == "method_call"
            and cls == RECEIVER_CLASS
            and method == "onReceive"
            and receiver_event is None
        ):
            args = e.get("arguments") or []
            if args and args[0] == BROADCAST_ACTION:
                receiver_event = e

        if (
            et == "method_call"
            and cls == WEBVIEW_CLASS
            and method == "loadUrl"
            and webview_event is None
        ):
            args = e.get("arguments") or []
            if args and args[0] == expected_url:
                webview_event = e

    checks = {}

    checks["receiver_action_correct"] = (
        receiver_event is not None
        and (receiver_event.get("arguments") or [None])[0] == BROADCAST_ACTION
    )

    checks["receiver_url_extra_correct"] = (
        receiver_event is not None
        and _meta(receiver_event).get("extra_value") == expected_url
    )

    checks["webview_loadurl_observed"] = webview_event is not None

    checks["webview_url_matches_receiver_extra"] = (
        webview_event is not None
        and receiver_event is not None
        and _meta(receiver_event).get("extra_value")
        == (webview_event.get("arguments") or [None])[0]
    )

    checks["receiver_precedes_webview"] = (
        receiver_event is not None
        and webview_event is not None
        and isinstance(receiver_event.get("timestamp"), str)
        and isinstance(webview_event.get("timestamp"), str)
        and receiver_event["timestamp"] <= webview_event["timestamp"]
    )

    return checks, shim_active, receiver_event, webview_event


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "events_file",
        type=Path,
        help="Raw JSON array written by collect_events.py (the .raw.json file).",
    )
    parser.add_argument(
        "expected_url",
        help="The URL value expected in the url extra and WebView.loadUrl argument.",
    )
    args = parser.parse_args(argv)

    try:
        events = json.loads(args.events_file.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"could not read valid event JSON: {error}")

    if not isinstance(events, list):
        parser.error("event file must contain a JSON array")

    checks, shim_active, receiver_event, webview_event = verify_events(
        events, args.expected_url
    )

    shim_label = "shim-assisted" if shim_active else "unmodified-app"
    print(f"capture type: {shim_label}")

    if receiver_event is None:
        print("receiver_action_correct: FAIL (no onReceive event found)")
    if webview_event is None:
        print("webview_loadurl_observed: FAIL (no matching WebView.loadUrl event found)")

    all_passed = True
    for name, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"{name}: {status}")
        if not passed:
            all_passed = False

    if not checks["webview_loadurl_observed"]:
        print(
            "note: WebView.loadUrl was not observed. "
            "Without the shim, the original APK crashes before reaching loadUrl. "
            "Re-run with receiver_webview_shim enabled to capture the full path."
        )

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
