"""Runs the analyzers for one analysis, stage by stage, and keeps status.json current."""
import json
import subprocess
import sys
from pathlib import Path

from . import storage

BACKEND_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BACKEND_DIR / "analyzers.json"


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _save(folder: Path, status: dict) -> None:
    storage.write_json(folder / "status.json", status)


def _run_stage(spec: dict, apk: Path, folder: Path, timeout: int, application_id: str):
    """Run one analyzer. Returns None on success, or an error message."""
    cmd = [part.format(apk=str(apk), out_dir=str(folder), application_id=application_id)
           for part in spec["command"]]
    if cmd[0] == "python":
        cmd[0] = sys.executable  # use the same Python that runs the backend
    try:
        result = subprocess.run(cmd, cwd=BACKEND_DIR, capture_output=True,
                                text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"timed out after {timeout} seconds"
    except OSError as exc:
        return f"could not start analyzer: {exc}"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-500:]
        return f"analyzer exited with code {result.returncode}: {detail}"
    for name in spec["outputs"]:
        path = folder / name
        if not path.exists():
            return f"analyzer finished but did not create {name}"
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            return f"{name} is not valid JSON"
    return None


def run_analysis(analysis_id: str) -> None:
    folder = storage.analysis_dir(analysis_id).resolve()
    status = storage.read_json(folder / "status.json")
    apk = (storage.APK_DIR / f"{status['application_id']}.apk").resolve()
    status["status"] = "running"
    _save(folder, status)

    try:
        config = load_config()
    except (OSError, ValueError) as exc:
        status["status"] = "failed"
        status["errors"]["config"] = f"cannot read analyzers.json: {exc}"
        _save(folder, status)
        return

    for stage in storage.STAGES:
        spec = config["stages"].get(stage)
        if spec is None:
            error = "no command configured in analyzers.json"
        elif spec.get("skip_if_exists") and all((folder / o).exists() for o in spec["outputs"]):
            status["stages"][stage] = "done"
            status["notes"][stage] = "used a file that was already uploaded"
            _save(folder, status)
            continue
        else:
            status["stages"][stage] = "running"
            _save(folder, status)
            error = _run_stage(spec, apk, folder, config.get("timeout_seconds", 300),
                               status["application_id"])

        if error:
            status["stages"][stage] = "failed"
            status["errors"][stage] = error
            status["status"] = "failed"
            _save(folder, status)
            return  # later stages depend on this one, so stop here
        status["stages"][stage] = "done"
        _save(folder, status)

    status["status"] = "completed"
    _save(folder, status)
