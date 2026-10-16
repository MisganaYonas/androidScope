"""Simple file-based storage. One folder per analysis, one JSON file per module."""
import json
from pathlib import Path

DATA_DIR = Path("data")
APK_DIR = DATA_DIR / "apks"
ANALYSIS_DIR = DATA_DIR / "analyses"

# Which module writes which file (this is the contract with Members 1-4)
RESULT_FILES = {
    "manifest": "manifest-result.json",        # Member 1
    "static": "static-result.json",            # Member 2
    "dynamic": "runtime-events.json",          # Member 3
    "correlation": "attack-paths.json",        # Member 4
    "findings": "vulnerability-results.json",  # Member 4
    "evidence": "evidence.json",               # Member 4
}
STAGES = ["manifest", "static", "dynamic", "correlation"]


def init_dirs():
    APK_DIR.mkdir(parents=True, exist_ok=True)
    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)


def next_id(prefix: str, folder: Path) -> str:
    """application-001, analysis-002, ... based on what already exists."""
    n = len(list(folder.iterdir())) + 1
    return f"{prefix}-{n:03d}"


def analysis_dir(analysis_id: str) -> Path:
    return ANALYSIS_DIR / analysis_id


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))
