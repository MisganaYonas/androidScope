# androidScope Backend (Member 5)

The backend is the connection layer of the platform. The frontend talks only to this API, and this API stores and serves the output of every analysis module.

    Frontend -> Backend API -> Analysis modules (Members 1-4)

## Run it

From the `backend/` folder:

    pip install -r requirements.txt
    uvicorn app.main:app --reload

Then open http://127.0.0.1:8000/docs for an interactive page where every endpoint can be tried.

## How an analysis runs

`POST /api/analysis/start` creates the analysis and returns immediately. A runner then executes the analyzers in the background, in this order: manifest (Member 1), static (Member 2), dynamic (Member 3), correlation (Member 4).

The frontend should **poll** `GET /api/analysis/{id}` until `status` is `completed` or `failed`. The response looks like:

    {
      "analysis_id": "analysis-001",
      "application_id": "application-001",
      "status": "running",
      "stages": {"manifest": "done", "static": "running", "dynamic": "pending", "correlation": "pending"},
      "errors": {},
      "notes": {}
    }

Stage values: `pending`, `running`, `done`, `failed`. If a stage fails, its message appears in `errors`, the overall status becomes `failed`, and later stages are not run.

If runtime events were already uploaded (`POST /api/analysis/{id}/runtime-events`), the dynamic stage is skipped and the uploaded file is used.

## Plugging in an analyzer (analyzers.json)

Every stage is one command listed in `analyzers.json`. These placeholders are filled in by the runner:

- `{apk}` the path of the uploaded APK
- `{out_dir}` the analysis folder where the stage must save its output
- `{application_id}` the backend's ID for the uploaded APK (for example `application-004`)

Contract for an analyzer: take the APK path and the output folder, write the stage's JSON file(s) into that folder (names are in the table below), exit with code 0 on success, and exit non-zero with a message on stderr on failure. Output that is missing or not valid JSON counts as a failure.

To plug in a real analyzer, replace the `command` for its stage. For example, for Member 1:

    "command": ["python", "../member1/analyze.py", "--apk", "{apk}", "--out-dir", "{out_dir}"]

The manifest stage calls Member 1's real analyzer (`modules/attack_surface/analyzer.py`). The static stage runs `analyzers/static_stage.py`, which decompiles the APK with JADX and runs Member 2's analyzer in `static-analysis/` (install JADX and either put it on PATH or set `JADX_PATH` to the full path of `jadx.bat`; Java is required). The dynamic and correlation stages still use the stand-in `analyzers/fake_analyzer.py`, which writes sample JSON for each stage (add `"--fail"` to a command to test failure handling). Set the environment variable `DROIDTRACE_MOCK=1` to skip the analyzers and return the sample JSON instantly (the analysis is `completed` immediately).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Check the server is running |
| POST | `/api/apk/upload` | Upload an `.apk` (form field `file`), returns `application_id` |
| POST | `/api/analysis/start` | Body `{"application_id": "..."}`, returns `analysis_id` right away; analysis runs in the background |
| GET | `/api/analysis/{id}` | Status of the analysis and its stages (poll this) |
| GET | `/api/components/{id}` | Manifest/component result (Member 1) |
| GET | `/api/static/{id}` | Static data-flow result (Member 2) |
| GET | `/api/runtime-events/{id}` | Runtime events (Member 3) |
| POST | `/api/analysis/{id}/runtime-events` | Upload runtime events JSON (Member 3, manual for now) |
| GET | `/api/attack-paths/{id}` | Correlated attack paths (Member 4) |
| GET | `/api/vulnerabilities/{id}` | Findings (Member 4) |
| GET | `/api/evidence/{id}` | Evidence items (Member 4) |

A result that does not exist yet returns 404 with the missing file name.

## Where each module saves its output

Each analysis has its own folder, `data/analyses/<analysis-id>/`, with one JSON file per module:

| File | Written by |
|---|---|
| `manifest-result.json` | Member 1 (attack surface) |
| `static-result.json` | Member 2 (static analysis) |
| `runtime-events.json` | Member 3 (dynamic analysis) |
| `attack-paths.json` | Member 4 (correlation) |
| `vulnerability-results.json` | Member 4 (findings) |
| `evidence.json` | Member 4 (evidence) |
| `status.json` | Backend |

The file names are defined in `app/storage.py` (`RESULT_FILES`).

## Matching rule for names

Frida sees real class and method names at runtime, not our IDs. Every record that refers to code should carry both its ID and its `class` and `method` (for example `com.example.MainActivity` and `onCreate(Landroid/os/Bundle;)V`). Member 4 matches static and runtime results on `class` + `method`. IDs link objects inside the final output.

## Try it quickly

    curl -X POST http://127.0.0.1:8000/api/apk/upload -F "file=@InjuredAndroid.apk"
    curl -X POST http://127.0.0.1:8000/api/analysis/start -H "Content-Type: application/json" -d "{\"application_id\": \"application-001\"}"
    curl http://127.0.0.1:8000/api/analysis/analysis-001
    curl http://127.0.0.1:8000/api/attack-paths/analysis-001

## Not included yet

Login, user accounts, cloud deployment, advanced databases. The first version only needs the pipeline to work.
