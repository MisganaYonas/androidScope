#!/usr/bin/env python3
"""Verify a collected fixture run contains its Intent and WebView URL events."""

import argparse
import json
from pathlib import Path


URL_PREFIX = "file:///android_asset/test-page.html?run="


def verify_events(events, expected_url):
    intent_observed = False
    webview_observed = False

    for event in events:
        if not isinstance(event, dict):
            continue

        metadata = event.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}

        if event.get("event_type") == "intent_incoming":
            extras = metadata.get("primitive_extras", [])
            if isinstance(extras, list) and any(
                isinstance(extra, dict)
                and extra.get("key") == "test_url"
                and extra.get("value") == expected_url
                for extra in extras
            ):
                intent_observed = True

        arguments = event.get("arguments")
        if not isinstance(arguments, list):
            arguments = []
        if (
            event.get("event_type") == "method_call"
            and event.get("class") == "android.webkit.WebView"
            and event.get("method") == "loadUrl"
            and arguments
            and arguments[0] == expected_url
            and metadata.get("url") == expected_url
        ):
            webview_observed = True

    return intent_observed, webview_observed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events_file", type=Path, help="JSON array written by collect_events.py")
    parser.add_argument("run_id", help="The unique run ID supplied in the test_url extra")
    args = parser.parse_args(argv)

    allowed_run_id_characters = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
    )
    if not args.run_id or any(
        character not in allowed_run_id_characters for character in args.run_id
    ):
        parser.error("run_id must contain only letters, digits, and hyphens")

    try:
        events = json.loads(args.events_file.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        parser.error(f"could not read valid event JSON: {error}")

    if not isinstance(events, list):
        parser.error("event file must contain a JSON array")

    expected_url = URL_PREFIX + args.run_id
    intent_observed, webview_observed = verify_events(events, expected_url)
    print(f"Intent extra contains expected test_url: {'PASS' if intent_observed else 'FAIL'}")
    print(f"WebView.loadUrl contains expected test_url: {'PASS' if webview_observed else 'FAIL'}")
    return 0 if intent_observed and webview_observed else 1


if __name__ == "__main__":
    raise SystemExit(main())
