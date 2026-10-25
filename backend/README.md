# androidScope Backend (Member 5)

The backend connects the frontend to the analysis modules. The frontend talks to this API, which stores and serves each module’s results.

    Frontend -> Backend API -> Analysis modules (Members 1–4)

## Run it

From the `backend/` folder:

    pip install -r requirements.txt
    uvicorn app.main:app --reload

Then open <http://127.0.0.1:8000/docs> to try the endpoints interactively.

## How an analysis runs

`POST /api/analysis/start` creates an analysis and returns immediately. The runner then executes these stages in order:

1. Manifest analysis (Member 1)
2. Static analysis (Member 2)
3. Dynamic analysis (Member 3)
4. Correlation (Member 4)

The frontend should poll `GET /api/analysis/{id}` until `status` is `completed` or `failed`. The response looks like:

    {
      "analysis_id": "analysis-001",
      "application_id": "application-001",
      "status": "running",
      "stages": {"manifest": "done", "static": "running", "dynamic": "pending", "correlation": "pending"},
      "errors": {},
      "notes": {}
    }

Stage values are `pending`, `running`, `done`, or `failed`. If a stage fails, its message appears in `errors`, the overall status becomes `failed`, and later stages do not run.

### Uploading runtime events

Upload runtime events **after** the initial analysis has completed:

`POST /api/analysis/{id}/runtime-events`

The JSON body must contain:

- `application_id`: the ID for the same APK used by this analysis
- `events`: an array of event objects

The backend rejects an unknown analysis with `404`, an upload for an analysis that is not completed or an app ID that does not match with `409`, and an invalid request body with `422`.

After accepting the events, the backend saves `runtime-events.json` and reruns **only the correlation stage**. It does not rerun manifest, static, or dynamic analysis. Poll `GET /api/analysis/{id}` for the correlation status.

Example request:

    {
      "application_id": "application-001",
      "events": []
    }

An empty array is valid, but contains no runtime evidence.

## Plugging in an analyzer (`analyzers.json`)

Every stage is configured as one command in `analyzers.json`. The runner fills in these placeholders:

- `{apk}`: path to the uploaded APK
- `{out_dir}`: analysis folder where the stage must save its output
- `{application_id}`: backend ID for the uploaded APK, such as `application-004`

Each analyzer must accept the APK path and output folder, write its JSON result file or files into that folder, exit with code `0` on success, and exit nonzero with an error message on failure. Missing or invalid JSON output counts as a failure.

The manifest stage calls Member 1’s analyzer at `modules/attack_surface/analyzer.py`. The static stage runs `analyzers/static_stage.py`, which decompiles the APK with JADX and runs Member 2’s analyzer in `static-analysis/`. Install JADX and either put it on `PATH` or set `JADX_PATH` to the full path of `jadx.bat`; Java is also required.

The dynamic stage currently uses `analyzers/fake_analyzer.py` as a stand-in. The correlation stage calls the real engine at `correlation/engine.py`. To test failure handling, add `"--fail"` to a fake analyzer command.

Set `DROIDTRACE_MOCK=1` to skip the analyzers and return sample JSON immediately. This mode is for development and demonstration, not real APK evidence.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Check that the server is running |
| POST | `/api/apk/upload` | Upload an `.apk` using multipart field `file`; returns `application_id` |
| POST | `/api/analysis/start` | Body `{"application_id": "..."}`; returns `analysis_id` while analysis runs in the background |
| GET | `/api/analysis/{id}` | Analysis status and stage states |
| GET | `/api/components/{id}` | Manifest and component result (Member 1) |
| GET | `/api/static/{id}` | Static data-flow result (Member 2) |
| GET | `/api/runtime-events/{id}` | Runtime events (Member 3) |
| POST | `/api/analysis/{id}/runtime-events` | Upload matching runtime events after analysis completes; saves them and reruns correlation |
| GET | `/api/attack-paths/{id}` | Correlated attack paths (Member 4) |
| GET | `/api/vulnerabilities/{id}` | Findings (Member 4) |
| GET | `/api/evidence/{id}` | Evidence items (Member 4) |

A result endpoint returns `404` if its result file is not available.

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

Frida sees real class and method names at runtime, not our IDs. Each event that refers to code should include its `class` and `method` values, such as `com.example.MainActivity` and `onCreate(Landroid/os/Bundle;)V`. The correlation engine matches static and runtime results using class and method names. IDs link objects inside the final output.

## Try it quickly

Run the following from a terminal with the backend running. Replace the example APK path and IDs with the values from your own upload and analysis.

Upload an APK:

    curl -X POST http://127.0.0.1:8000/api/apk/upload -F "file=@InjuredAndroid.apk"

Start analysis using the returned `application_id`:

    curl -X POST http://127.0.0.1:8000/api/analysis/start -H "Content-Type: application/json" -d "{\"application_id\":\"application-001\"}"

Poll until the status is `completed`:

    curl http://127.0.0.1:8000/api/analysis/analysis-001

After completion, upload runtime events using the same `application_id`:

    curl -X POST http://127.0.0.1:8000/api/analysis/analysis-001/runtime-events -H "Content-Type: application/json" -d "{\"application_id\":\"application-001\",\"events\":[]}"

Poll the analysis status again, then retrieve results:

    curl http://127.0.0.1:8000/api/analysis/analysis-001
    curl http://127.0.0.1:8000/api/attack-paths/analysis-001

## Remaining hardening work

- Replace the dynamic stand-in with Member 3’s collector and agree on the runtime-event handoff.
- Restrict wildcard CORS to the frontend origins the team actually uses.
- Add APK size and content validation; the current upload check only checks the `.apk` filename extension.
- Make mock-mode result IDs follow the current analysis instead of using fixed sample IDs.
- Add backend tests for valid and invalid runtime-event uploads, application ID matching, and correlation reruns.
- Add authentication and deployment protections before exposing the API beyond local development.

Login, user accounts, cloud deployment, and advanced database storage are not included in this first version.