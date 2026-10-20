"""Stand-in analyzer for testing the runner. Writes sample JSON for one stage.

    python analyzers/fake_analyzer.py <stage> --apk app.apk --out-dir folder [--fail]

Real analyzers follow the same contract: take an APK path and an output folder,
write the stage's JSON file(s) into that folder, exit 0 on success and
non-zero (with a message on stderr) on failure.
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app import mock_data, storage  # noqa: E402

KEYS = {"manifest": ["manifest"], "static": ["static"], "dynamic": ["dynamic"],
        "correlation": ["correlation", "findings", "evidence"]}

parser = argparse.ArgumentParser()
parser.add_argument("stage", choices=KEYS)
parser.add_argument("--apk", required=True)
parser.add_argument("--out-dir", required=True)
parser.add_argument("--fail", action="store_true", help="simulate a crash")
args = parser.parse_args()

if not Path(args.apk).exists():
    sys.exit(f"APK not found: {args.apk}")
if args.fail:
    sys.exit(f"fake {args.stage} analyzer crashed on purpose")

time.sleep(1)  # pretend to work
for key in KEYS[args.stage]:
    storage.write_json(Path(args.out_dir) / storage.RESULT_FILES[key], mock_data.ALL[key])
print(f"{args.stage}: done")
