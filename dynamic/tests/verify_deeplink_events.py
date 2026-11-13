#!/usr/bin/env python3
"""Verify a collected run contains the expected onNewIntent and loadUrl events.

Requires two distinct run IDs supplied as positional arguments.

Checks (against the exact schema emitted by intent_hook.js and webview_hook.js):
  1. intent_incoming via getIntent (first launch, run_id_1)
       method == "getIntent"
       metadata.primitive_extras contains {key: "test_url", value: <url_1>}
  2. method_call WebView.loadUrl (first launch)
       metadata.url == <url_1>
  3. intent_incoming via onNewIntent (second launch, run_id_2)
       method == "onNewIntent"
       metadata.primitive_extras contains {key: "test_url", value: <url_2>}
  4. method_call WebView.loadUrl (second launch)
       metadata.url == <url_2>
"""

import argparse
import json
from pathlib import Path

URL_PREFIX = "file:///android_asset/test-page.html?run="
ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")


def _meta(event):
    m = event.get("metadata")
    return m if isinstance(m, dict) else {}


def _has_extra(meta, key, value):
    extras = meta.get("primitive_extras")
    if not isinstance(extras, list):
        return False
    return any(
        isinstance(x, dict) and x.get("key") == key and x.get("value") == value
        for x in extras
    )


def verify_events(events, url_1, url_2):
    checks = {
        "getIntent_run1": False,
        "loadUrl_run1": False,
        "onNewIntent_run2": False,
        "loadUrl_run2": False,
    }

    for e in events:
        if not isinstance(e, dict):
            continue
        et = e.get("event_type")
        cls = e.get("class")
        method = e.get("method")
        meta = _meta(e)

        if (et == "intent_incoming"
                and cls == "android.app.Activity"
                and method == "getIntent"
                and _has_extra(meta, "test_url", url_1)):
            checks["getIntent_run1"] = True

        if (et == "method_call"
                and cls == "android.webkit.WebView"
                and method == "loadUrl"
                and meta.get("url") == url_1):
            checks["loadUrl_run1"] = True

        if (et == "intent_incoming"
                and cls == "android.app.Activity"
                and method == "onNewIntent"
                and _has_extra(meta, "test_url", url_2)):
            checks["onNewIntent_run2"] = True

        if (et == "method_call"
                and cls == "android.webkit.WebView"
                and method == "loadUrl"
                and meta.get("url") == url_2):
            checks["loadUrl_run2"] = True

    return checks


def _validate_run_id(parser, run_id):
    if not run_id or not all(c in ALLOWED_CHARS for c in run_id):
        parser.error(f"run_id must contain only letters, digits, and hyphens: {run_id!r}")
    if run_id == run_id:  # always true; real check below
        pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events_file", type=Path,
                        help="JSON array written by collect_events.py")
    parser.add_argument("run_id_1",
                        help="Run ID used in the first (onCreate) launch")
    parser.add_argument("run_id_2",
                        help="Run ID used in the second (onNewIntent) launch")
    args = parser.parse_args(argv)

    for rid in (args.run_id_1, args.run_id_2):
        if not rid or not all(c in ALLOWED_CHARS for c in rid):
            parser.error(
                f"run IDs must contain only letters, digits, and hyphens: {rid!r}"
            )
    if args.run_id_1 == args.run_id_2:
        parser.error("run_id_1 and run_id_2 must be different")

    try:
        events = json.loads(args.events_file.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"could not read valid event JSON: {error}")

    if not isinstance(events, list):
        parser.error("event file must contain a JSON array")

    url_1 = URL_PREFIX + args.run_id_1
    url_2 = URL_PREFIX + args.run_id_2
    checks = verify_events(events, url_1, url_2)

    all_passed = True
    for name, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        print(f"{name}: {status}")
        if not passed:
            all_passed = False

    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
