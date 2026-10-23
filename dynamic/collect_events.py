#!/usr/bin/env python3
"""Attach existing AndroidScope Frida hooks and export their events as JSON."""

import argparse
import importlib.resources
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
HOOKS = {
    "intent": BASE_DIR / "frida" / "intent_hook.js",
    "webview": BASE_DIR / "frida" / "webview_hook.js",
    "lifecycle": BASE_DIR / "frida" / "activity_lifecycle_hook.js",
}
HOOK_STATUS_METHODS = {
    "intent": "intent_hook",
    "webview": "webview_hook",
    "lifecycle": "activity_lifecycle_hook",
}
DEFAULT_TARGET = "com.androidscope.dynamicfixture"
DEFAULT_OUTPUT = BASE_DIR / "output" / "runtime-events.json"
DEFAULT_STARTUP_TIMEOUT = 15


def atomic_write_json(path, value):
    """Write JSON beside its destination and atomically replace the file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(value, temporary_file, ensure_ascii=False, indent=2, allow_nan=False)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def diagnostics_path(output_path):
    output_path = Path(output_path)
    return output_path.with_name(f"{output_path.stem}.errors{output_path.suffix}")


class EventCollector:
    """Keep Frida send payloads separate from script and collector diagnostics."""

    def __init__(self, verbose=False, error_stream=None):
        self.events = []
        self.diagnostics = []
        self.verbose = verbose
        self.error_stream = error_stream if error_stream is not None else sys.stderr
        self._condition = threading.Condition()
        self._ready_hooks = set()
        self._failed_hooks = set()

    def record_diagnostic(self, kind, message, description):
        diagnostic = {"kind": kind, "message": message}
        try:
            json.dumps(diagnostic, allow_nan=False)
        except (TypeError, ValueError):
            diagnostic = {"kind": kind, "description": description}

        with self._condition:
            self.diagnostics.append(diagnostic)
            self.error_stream.write(f"[{kind}] {description}\n")
            self.error_stream.flush()

    def on_message(self, message, data=None):
        """Handle the message callback used by Frida Script.on('message', ...)."""
        with self._condition:
            if not isinstance(message, dict):
                self.record_diagnostic(
                    "collector_error",
                    None,
                    "Received a non-object Frida message",
                )
                return

            message_type = message.get("type")
            if message_type == "send":
                payload = message.get("payload")
                if not isinstance(payload, dict):
                    self.record_diagnostic(
                        "collector_error",
                        message,
                        "Ignoring Frida send payload that is not a structured object",
                    )
                    return

                try:
                    json.dumps(payload, allow_nan=False)
                except (TypeError, ValueError) as error:
                    self.record_diagnostic(
                        "collector_error",
                        message,
                        f"Ignoring non-JSON Frida send payload: {error}",
                    )
                    return

                self.events.append(payload)
                if payload.get("event_type") == "hook_status":
                    self._record_hook_status(payload)
                if self.verbose:
                    event_type = payload.get("event_type", "unknown")
                    class_name = payload.get("class", "")
                    method_name = payload.get("method", "")
                    identity = ".".join(
                        str(value) for value in (class_name, method_name) if value
                    )
                    suffix = f" {identity}" if identity else ""
                    print(f"[event] {event_type}{suffix}", file=self.error_stream)
                self._condition.notify_all()
                return

            if message_type == "error":
                description = message.get("description") or "Frida script error"
                if message.get("stack"):
                    description = f"{description}\n{message['stack']}"
                self.record_diagnostic("frida_error", message, description)
                self._condition.notify_all()
                return

            if message_type == "log":
                description = message.get("payload") or "Frida script log message"
                self.record_diagnostic("frida_log", message, str(description))
                self._condition.notify_all()
                return

            self.record_diagnostic(
                "frida_message",
                message,
                f"Received unhandled Frida message type: {message_type!r}",
            )
            self._condition.notify_all()

    def _record_hook_status(self, payload):
        method = payload.get("method")
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict):
            return
        status = metadata.get("status")
        if status == "ready" and method in HOOK_STATUS_METHODS.values():
            self._ready_hooks.add(method)
        elif status not in (None, "ready"):
            self._failed_hooks.add(method)

    def wait_for_hooks(self, hook_names, timeout):
        """Wait until every selected hook reports ready or initialization fails."""
        expected = {HOOK_STATUS_METHODS[name] for name in hook_names}
        deadline = time.monotonic() + timeout
        with self._condition:
            while not expected.issubset(self._ready_hooks):
                if self._failed_hooks.intersection(expected) or self.diagnostics:
                    return False
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
            return True

    def hook_startup_error(self, hook_names):
        expected = {HOOK_STATUS_METHODS[name] for name in hook_names}
        failed = sorted(expected.intersection(self._failed_hooks))
        if failed:
            return f"Selected hook(s) reported initialization failure: {', '.join(failed)}"
        if self.diagnostics:
            kinds = sorted({diagnostic.get("kind", "unknown") for diagnostic in self.diagnostics})
            return (
                "Frida reported startup diagnostics before all selected hooks "
                f"became ready ({', '.join(kinds)}); inspect the diagnostics file"
            )
        missing = sorted(expected.difference(self._ready_hooks))
        if missing:
            return (
                "Timed out waiting for selected hook(s) to report ready: "
                f"{', '.join(missing)}"
            )
        return None

    def export(self, output_path):
        """Atomically export an event array and a separate diagnostic array."""
        with self._condition:
            events = list(self.events)
            diagnostics = list(self.diagnostics)

        output_path = Path(output_path)
        atomic_write_json(output_path, events)
        error_path = diagnostics_path(output_path)
        atomic_write_json(error_path, diagnostics)
        return output_path, error_path


def load_java_bridge_source():
    """Load the same bundled Java bridge source used by the Frida CLI."""
    try:
        bridge_resource = (
            importlib.resources.files("frida_tools")
            .joinpath("bridges")
            .joinpath("java.js")
        )
        return bridge_resource.read_text(encoding="utf-8")
    except (ImportError, ModuleNotFoundError, OSError) as error:
        raise RuntimeError(
            "Frida's Java bridge was not found. Install Frida tools matching "
            "the client version (for example, python -m pip install frida-tools)."
        ) from error


def prepare_hook_source(hook_source, java_bridge_source):
    """Expose Frida's bundled Java bridge before evaluating a Java-based hook."""
    bridge_initializer = (
        "(function () {\n"
        f"{java_bridge_source}\n"
        "Object.defineProperty(globalThis, 'Java', { value: bridge });\n"
        "return bridge;\n"
        "})();"
    )
    return (
        "Script.evaluate('/frida/bridges/java.js', "
        f"{json.dumps(bridge_initializer)});\n"
        "if (typeof Java === 'undefined') {\n"
        "  throw new Error('Java bridge evaluation did not define Java in this script runtime');\n"
        "}\n"
        "if (!Java.available) {\n"
        "  throw new Error('Android Java VM is not available in this process');\n"
        "}\n"
        f"{hook_source}"
    )


def build_parser():
    parser = argparse.ArgumentParser(
        description="Collect events from the existing AndroidScope Frida hooks."
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=(
            "Attached process name or PID (default: "
            f"{DEFAULT_TARGET}). The process must already be running."
        ),
    )
    parser.add_argument(
        "--device-id",
        help="Frida device ID. Defaults to the first connected USB device.",
    )
    parser.add_argument(
        "--hooks",
        nargs="+",
        choices=tuple(HOOKS),
        default=list(HOOKS),
        help="Hooks to load (default: intent webview lifecycle).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"JSON event-array output path (default: {DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0,
        metavar="SECONDS",
        help="Stop after this many seconds; zero collects until Ctrl+C (default).",
    )
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=DEFAULT_STARTUP_TIMEOUT,
        metavar="SECONDS",
        help=(
            "Maximum seconds to wait for every selected hook to report ready "
            f"(default: {DEFAULT_STARTUP_TIMEOUT})."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print a short line for each captured event.",
    )
    return parser


def _load_frida():
    try:
        import frida
    except ImportError as error:
        raise RuntimeError(
            "Frida Python bindings are required. Install a version matching "
            "the device Frida server, for example: python -m pip install frida==17.22.2"
        ) from error
    return frida


def _device_for(frida, device_id):
    manager = frida.get_device_manager()
    if device_id:
        return manager.get_device(device_id)
    return manager.get_usb_device(timeout=10)


def run_collection(args):
    collector = EventCollector(verbose=args.verbose)
    scripts = []
    session = None
    exit_code = 0
    interrupted = False

    if args.duration < 0 or args.startup_timeout <= 0:
        invalid_option = (
            "--duration must be zero or greater"
            if args.duration < 0
            else "--startup-timeout must be greater than zero"
        )
        collector.record_diagnostic(
            "collector_error",
            None,
            invalid_option,
        )
        exit_code = 2
    else:
        try:
            frida = _load_frida()
            java_bridge_source = load_java_bridge_source()
            device = _device_for(frida, args.device_id)
            target = int(args.target) if args.target.isdecimal() else args.target
            session = device.attach(target)

            for hook_name in args.hooks:
                hook_path = HOOKS[hook_name]
                hook_source = hook_path.read_text(encoding="utf-8")
                source = prepare_hook_source(hook_source, java_bridge_source)
                script = session.create_script(source, name=hook_name, runtime="qjs")
                script.on("message", collector.on_message)
                scripts.append(script)
                script.load()

            if not collector.wait_for_hooks(args.hooks, args.startup_timeout):
                startup_error = collector.hook_startup_error(args.hooks)
                collector.record_diagnostic("hook_initialization_error", None, startup_error)
                exit_code = 1
                raise RuntimeError(startup_error)

            print(
                f"Hooks initialized. Collecting from {args.target} on {device.name}; "
                f"hooks: {', '.join(args.hooks)}. Press Ctrl+C to stop.",
                file=sys.stderr,
            )

            start_time = time.monotonic()
            while args.duration == 0 or time.monotonic() - start_time < args.duration:
                time.sleep(0.2)
        except KeyboardInterrupt:
            interrupted = True
            print("\nStopping collection and saving events...", file=sys.stderr)
        except Exception as error:
            exit_code = 1
            if not any(
                diagnostic.get("kind") == "hook_initialization_error"
                for diagnostic in collector.diagnostics
            ):
                collector.record_diagnostic("collector_error", None, str(error))
        finally:
            for script in reversed(scripts):
                try:
                    script.unload()
                except Exception as error:
                    collector.record_diagnostic(
                        "collector_error",
                        None,
                        f"Could not unload Frida script: {error}",
                    )
                    exit_code = 1

            if session is not None:
                try:
                    session.detach()
                except Exception as error:
                    collector.record_diagnostic(
                        "collector_error",
                        None,
                        f"Could not detach from Frida session: {error}",
                    )
                    exit_code = 1

    try:
        output_path, error_path = collector.export(args.output)
        print(
            f"Saved {len(collector.events)} events to {output_path} "
            f"({len(collector.diagnostics)} diagnostics in {error_path}).",
            file=sys.stderr,
        )
    except OSError as error:
        print(f"[collector_error] Could not save collector output: {error}", file=sys.stderr)
        exit_code = 1

    if collector.diagnostics:
        exit_code = 1
    if interrupted and exit_code == 0:
        return 0
    return exit_code


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return run_collection(args)


if __name__ == "__main__":
    raise SystemExit(main())
