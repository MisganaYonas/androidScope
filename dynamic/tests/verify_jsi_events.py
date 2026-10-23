#!/usr/bin/env python3
"""Verify a collected run contains the expected JSI and evaluateJavascript events.

Checks (against the exact schema emitted by webview_hook.js):
  1. method_call  android.webkit.WebView.addJavascriptInterface
       metadata.interface_name == "AndroidBridge"
  2. method_call  android.webkit.WebView.loadUrl
       metadata.url == JSI_PAGE_URL
  3. webview_page_started  android.webkit.WebViewClient.onPageStarted
       metadata.url == JSI_PAGE_URL
  4. webview_page_finished android.webkit.WebViewClient.onPageFinished
       metadata.url == JSI_PAGE_URL
  5. method_call  android.webkit.WebView.evaluateJavascript
       metadata.script == EVAL_SCRIPT
"""

import argparse
import json
from pathlib import Path

JSI_PAGE_URL = "file:///android_asset/jsi-test-page.html"
BRIDGE_NAME = "AndroidBridge"
EVAL_SCRIPT = "document.title"


def _meta(event):
    m = event.get("metadata")
    return m if isinstance(m, dict) else {}


def verify_events(events):
    checks = {
        "addJavascriptInterface": False,
        "loadUrl": False,
        "onPageStarted": False,
        "onPageFinished": False,
        "evaluateJavascript": False,
    }

    for e in events:
        if not isinstance(e, dict):
            continue
        et = e.get("event_type")
        cls = e.get("class")
        method = e.get("method")
        meta = _meta(e)

        if (et == "method_call"
                and cls == "android.webkit.WebView"
                and method == "addJavascriptInterface"
                and meta.get("interface_name") == BRIDGE_NAME):
            checks["addJavascriptInterface"] = True

        if (et == "method_call"
                and cls == "android.webkit.WebView"
                and method == "loadUrl"
                and meta.get("url") == JSI_PAGE_URL):
            checks["loadUrl"] = True

        if (et == "webview_page_started"
                and cls == "android.webkit.WebViewClient"
                and method == "onPageStarted"
                and meta.get("url") == JSI_PAGE_URL):
            checks["onPageStarted"] = True

        if (et == "webview_page_finished"
                and cls == "android.webkit.WebViewClient"
                and method == "onPageFinished"
                and meta.get("url") == JSI_PAGE_URL):
            checks["onPageFinished"] = True

        if (et == "method_call"
                and cls == "android.webkit.WebView"
                and method == "evaluateJavascript"
                and meta.get("script") == EVAL_SCRIPT):
            checks["evaluateJavascript"] = True

    return checks


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events_file", type=Path,
                        help="JSON array written by collect_events.py")
    args = parser.parse_args(argv)

    try:
        events = json.loads(args.events_file.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"could not read valid event JSON: {error}")

    if not isinstance(events, list):
        parser.error("event file must contain a JSON array")

    checks = verify_events(events)
    all_passed = True
    for name, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"{name}: {status}")
        if not passed:
            all_passed = False

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
