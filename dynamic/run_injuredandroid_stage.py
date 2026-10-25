#!/usr/bin/env python3
"""InjuredAndroid dynamic analysis stage.

Satisfies the backend dynamic-stage contract:
  receive --apk, --out-dir, --application-id
  write   {out_dir}/runtime-events.json  (application_id + events schema)

This script is explicitly scoped to the InjuredAndroid scenario on a
pre-configured Android device. It is NOT a general APK runner.

Prerequisites
-------------
Host:
  pip install frida==17.22.2 frida-tools

Device (must be satisfied before running):
  - ADB-reachable Android device (USB or TCP, e.g. 192.168.89.103:5555)
  - frida-server matching version 17.22.2 running as root on the device
  - The device must be rooted; frida-server must be started manually or via
    a startup script before invoking this stage.

Scenario
--------
  1. Install the APK via ADB (skipped if --skip-install is set).
  2. Launch the app and wait for its process to appear.
  3. Launch TestBroadcastReceiver so the receiver class is loaded.
  4. Attach Frida hooks (intent, webview, receiver_webview_shim).
  5. Wait for all hooks to report ready.
  6. Send the CUSTOM_INTENT broadcast with url=about:blank.
  7. Wait for the collection window, then save raw + normalized output.

Exit codes
----------
  0  Collection completed; runtime-events.json written.
  1  Collection completed with diagnostics or partial results.
  2  Fatal setup failure (device unreachable, install failed, etc.).
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

_DYNAMIC_DIR = Path(__file__).resolve().parent
if str(_DYNAMIC_DIR) not in sys.path:
    sys.path.insert(0, str(_DYNAMIC_DIR))

import collect_target_events as _collect_target_events

PACKAGE = "b3nac.injuredandroid"
MAIN_ACTIVITY = f"{PACKAGE}/.MainActivity"
RECEIVER_ACTIVITY = f"{PACKAGE}/.TestBroadcastReceiver"
BROADCAST_ACTION = "com.b3nac.injuredandroid.intent.action.CUSTOM_INTENT"
BROADCAST_URL = "about:blank"

HOOKS = ["intent", "webview", "receiver_webview_shim"]

_LAUNCH_WAIT_SECONDS = 5
_ACTIVITY_WAIT_SECONDS = 3
_HOOK_STARTUP_TIMEOUT = 20
_COLLECTION_WINDOW_SECONDS = 15
_BROADCAST_SETTLE_SECONDS = 3
_COLLECTOR_JOIN_GRACE_SECONDS = 10


class StageError(Exception):
    """Fatal setup or device error; maps to exit code 2."""


def _adb(device_serial, *args, timeout=15):
    """Run an adb command and return (returncode, stdout, stderr)."""
    cmd = ["adb"]
    if device_serial:
        cmd += ["-s", device_serial]
    cmd += list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        raise StageError(
            "adb not found on PATH. Install Android platform-tools and ensure "
            "adb is accessible."
        )
    except subprocess.TimeoutExpired:
        raise StageError(f"adb command timed out after {timeout}s: {' '.join(cmd)}")


def _validate_apk(apk_path):
    """Confirm the APK declares the expected InjuredAndroid package ID.

    Uses ``aapt dump badging`` to read the manifest package name.
    Raises StageError in every case where the package cannot be confirmed:
      - aapt not on PATH
      - aapt times out
      - aapt returns a non-zero exit code
      - the declared package name does not match PACKAGE
    """
    apk_path = Path(apk_path)
    try:
        result = subprocess.run(
            ["aapt", "dump", "badging", str(apk_path)],
            capture_output=True, text=True, timeout=30,
        )
    except FileNotFoundError:
        raise StageError(
            "aapt is not available on PATH. Install Android build-tools and "
            "ensure aapt is accessible before running this stage. "
            "Reliable APK validation requires aapt."
        )
    except subprocess.TimeoutExpired:
        raise StageError(
            "aapt timed out reading the APK. The file may be corrupt or "
            "inaccessible. Resolve the issue before running this stage."
        )

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise StageError(
            f"aapt could not read the APK (rc={result.returncode}): {detail!r}. "
            "Ensure the file is a valid Android package."
        )

    for line in result.stdout.splitlines():
        if line.startswith("package:"):
            if f"name='{PACKAGE}'" in line:
                return  # confirmed
            raise StageError(
                f"APK package does not match the expected target {PACKAGE!r}. "
                "This stage only supports InjuredAndroid. "
                f"aapt reported: {line.strip()!r}"
            )

    raise StageError(
        "aapt did not report a package name for this APK. "
        "The file may not be a valid Android package."
    )


def _require_device(device_serial):
    rc, out, err = _adb(device_serial, "get-state")
    if rc != 0 or out != "device":
        raise StageError(
            f"Device not ready (state={out!r}, rc={rc}). "
            "Check ADB connection and that the device is authorised."
        )


def _install_apk(device_serial, apk_path):
    print(f"[stage] Installing {apk_path} ...", file=sys.stderr)
    rc, out, err = _adb(device_serial, "install", "-r", str(apk_path), timeout=120)
    if rc != 0:
        raise StageError(f"APK install failed (rc={rc}): {err or out}")
    print("[stage] Install succeeded.", file=sys.stderr)


def _launch_app(device_serial):
    print(f"[stage] Launching {PACKAGE} ...", file=sys.stderr)
    rc, out, err = _adb(
        device_serial, "shell", "am", "start", "-n", MAIN_ACTIVITY, timeout=20
    )
    if rc != 0:
        raise StageError(f"Could not launch app (rc={rc}): {err or out}")
    time.sleep(_LAUNCH_WAIT_SECONDS)


def _get_pid(device_serial):
    rc, out, _ = _adb(device_serial, "shell", "pidof", PACKAGE)
    pid = out.strip()
    if rc != 0 or not pid.isdecimal():
        return None
    return pid


def _require_pid(device_serial):
    pid = _get_pid(device_serial)
    if not pid:
        raise StageError(
            f"Process {PACKAGE} not found after launch. "
            "The app may have crashed on startup."
        )
    return pid


def _launch_receiver_activity(device_serial):
    print("[stage] Opening TestBroadcastReceiver to load receiver class ...", file=sys.stderr)
    rc, out, err = _adb(
        device_serial, "shell", "am", "start", "-n", RECEIVER_ACTIVITY, timeout=20
    )
    if rc != 0:
        # Non-fatal: the hook retry loop will handle a missing class.
        print(
            f"[stage] Warning: could not open receiver activity (rc={rc}): {err or out}",
            file=sys.stderr,
        )
    time.sleep(_ACTIVITY_WAIT_SECONDS)


def _send_broadcast(device_serial):
    print(f"[stage] Sending broadcast with url={BROADCAST_URL!r} ...", file=sys.stderr)
    rc, out, err = _adb(
        device_serial,
        "shell", "am", "broadcast",
        "-a", BROADCAST_ACTION,
        "-p", PACKAGE,
        "--es", "url", BROADCAST_URL,
        timeout=15,
    )
    if rc != 0:
        print(
            f"[stage] Warning: broadcast command returned rc={rc}: {err or out}",
            file=sys.stderr,
        )
    else:
        print(f"[stage] Broadcast delivered: {out}", file=sys.stderr)
    return rc == 0


def _require_frida_server(device_serial):
    rc, out, _ = _adb(device_serial, "shell", "pidof", "frida-server")
    if rc != 0 or not out.strip():
        raise StageError(
            "frida-server is not running on the device. "
            "Start it as root before running this stage: "
            "adb shell 'su -c /data/local/tmp/frida-server &'"
        )


def _run_collection(device_serial, pid, application_id, out_dir):
    """Drive _collect_target_events.main() in-process and return exit_code."""
    import threading

    final_output = Path(out_dir) / "runtime-events.json"

    argv = [
        "--device-id", device_serial,
        "--target", pid,
        "--application-id", application_id,
        "--hooks", *HOOKS,
        "--output", str(final_output),
        "--duration", str(_COLLECTION_WINDOW_SECONDS + _BROADCAST_SETTLE_SECONDS + 2),
        "--startup-timeout", str(_HOOK_STARTUP_TIMEOUT),
    ]

    result_holder = [None]
    ready_event = threading.Event()

    def _collect():
        result_holder[0] = _collect_target_events.main(
            argv, on_hooks_ready=ready_event.set
        )

    thread = threading.Thread(target=_collect, daemon=True)
    thread.start()

    if not ready_event.wait(timeout=_HOOK_STARTUP_TIMEOUT + 5):
        print(
            "[stage] Warning: hooks did not report ready within timeout; "
            "sending broadcast anyway.",
            file=sys.stderr,
        )

    _send_broadcast(device_serial)
    thread.join(timeout=_COLLECTION_WINDOW_SECONDS + _BROADCAST_SETTLE_SECONDS + _COLLECTOR_JOIN_GRACE_SECONDS)

    if thread.is_alive():
        print(
            "[stage] Warning: collector thread did not finish within the allotted "
            "timeout. Output may be incomplete.",
            file=sys.stderr,
        )
        return 1

    return result_holder[0] if result_holder[0] is not None else 1


def build_parser():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--apk",
        required=True,
        type=Path,
        help="Path to the InjuredAndroid APK to install.",
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Directory to write runtime-events.json (and raw sidecar files).",
    )
    parser.add_argument(
        "--application-id",
        required=True,
        help="Exact application ID supplied by the analysis teammate.",
    )
    parser.add_argument(
        "--device-serial",
        default="192.168.89.103:5555",
        help=(
            "ADB device serial or host:port for ADB-over-TCP "
            "(default: 192.168.89.103:5555)."
        ),
    )
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Skip APK installation (use if the APK is already installed).",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        print(f"[stage] Checking device {args.device_serial} ...", file=sys.stderr)
        _require_device(args.device_serial)

        print("[stage] Checking frida-server ...", file=sys.stderr)
        _require_frida_server(args.device_serial)

        if not args.skip_install:
            if not args.apk.is_file():
                raise StageError(f"APK not found: {args.apk}")
            _validate_apk(args.apk)
            _install_apk(args.device_serial, args.apk)

        _launch_app(args.device_serial)
        pid = _require_pid(args.device_serial)
        print(f"[stage] App running at PID {pid}.", file=sys.stderr)

        _launch_receiver_activity(args.device_serial)

        # Confirm PID is still alive after activity launch.
        pid = _require_pid(args.device_serial)

        print("[stage] Starting collection ...", file=sys.stderr)
        exit_code = _run_collection(
            args.device_serial, pid, args.application_id, out_dir
        )

        output_file = out_dir / "runtime-events.json"
        if output_file.exists():
            try:
                schema = json.loads(output_file.read_text(encoding="utf-8"))
                n = len(schema.get("events", []))
                print(
                    f"[stage] Done. {n} sink event(s) written to {output_file}.",
                    file=sys.stderr,
                )
            except (json.JSONDecodeError, OSError):
                pass

        return exit_code

    except StageError as error:
        print(f"[stage] Fatal: {error}", file=sys.stderr)
        # Write a machine-readable failure record so the backend can report it.
        failure = {"stage": "injuredandroid_dynamic", "error": str(error)}
        try:
            from collect_events import atomic_write_json
            atomic_write_json(out_dir / "runtime-events.stage-error.json", failure)
        except OSError as write_err:
            print(f"[stage] Could not write stage-error record: {write_err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
