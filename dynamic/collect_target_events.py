#!/usr/bin/env python3
"""Collect InjuredAndroid sink calls into the teammate-facing event schema."""

import json
import sys
from pathlib import Path

import collect_events


BASE_DIR = Path(__file__).resolve().parent
RUNTIME_HOOK = BASE_DIR / "frida" / "runtime_exec_hook.js"
TARGET_SINKS = {
    ("java.lang.Runtime", "exec"),
    ("android.webkit.WebView", "loadUrl"),
    ("b3nac.injuredandroid.TestBroadcastReceiver", "onReceive"),
}

_REQUIRED_FIELDS = {"event_type", "class", "method", "arguments", "timestamp"}


def events_for_schema(raw_events, application_id):
    """Select observed target method calls and preserve their runtime values."""
    if not isinstance(application_id, str) or not application_id.strip():
        raise ValueError("application_id must be a non-empty value supplied by the teammate")

    events = []
    for raw_event in raw_events:
        if not isinstance(raw_event, dict):
            raise ValueError("raw event collection contains a non-object event")
        if (
            raw_event.get("event_type") != "method_call"
            or (raw_event.get("class"), raw_event.get("method")) not in TARGET_SINKS
        ):
            continue

        missing = _REQUIRED_FIELDS - raw_event.keys()
        if missing:
            raise ValueError(
                f"observed sink event is missing required fields: {', '.join(sorted(missing))}"
            )

        arguments = raw_event.get("arguments")
        timestamp = raw_event.get("timestamp")
        if not isinstance(arguments, list) or not isinstance(timestamp, str) or not timestamp:
            raise ValueError("observed sink event is missing arguments or timestamp")

        events.append(
            {
                "id": f"event-{len(events) + 1:03d}",
                "type": "method_call",
                "class": raw_event["class"],
                "method": raw_event["method"],
                "arguments": arguments,
                "timestamp": timestamp,
            }
        )

    return {"application_id": application_id, "events": events}


def build_parser():
    collect_events.HOOKS["runtime_exec"] = RUNTIME_HOOK
    collect_events.HOOK_STATUS_METHODS["runtime_exec"] = "runtime_exec_hook"

    parser = collect_events.build_parser()
    parser.description = __doc__
    target_action = next(action for action in parser._actions if action.dest == "target")
    target_action.required = True
    target_action.default = None
    target_action.help = "Attached process name or PID on the connected device; must already be running."
    parser.set_defaults(hooks=["intent", "webview", "runtime_exec"])
    hooks_action = next(action for action in parser._actions if action.dest == "hooks")
    hooks_action.help = "Hooks to load (default: intent webview runtime_exec)."
    parser.add_argument(
        "--application-id",
        required=True,
        help="Exact application ID supplied by the analysis teammate.",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    final_output = Path(args.output)
    raw_output = final_output.with_name(f"{final_output.stem}.raw{final_output.suffix}")
    args.output = raw_output

    exit_code = collect_events.run_collection(args)

    if not raw_output.exists():
        return exit_code if exit_code != 0 else 1

    try:
        raw_events = json.loads(raw_output.read_text(encoding="utf-8"))
        if not isinstance(raw_events, list):
            raise ValueError("raw event collection is not a JSON array")
        output = events_for_schema(raw_events, args.application_id)
        collect_events.atomic_write_json(final_output, output)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"[collector_error] Could not create teammate event file: {error}", file=sys.stderr)
        return 1

    print(
        f"Saved {len(output['events'])} observed sink events to {final_output}.",
        file=sys.stderr,
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
