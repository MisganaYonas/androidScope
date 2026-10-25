# androidScope Backend (Member 5)

The backend is the connection layer of the platform. The frontend talks only to this API, and this API stores and serves the output of every analysis module.

    Frontend -> Backend API -> Analysis modules (Members 1-4)

## Run it

From the `backend/` folder:

    pip install -r requirements.txt
    uvicorn app.main:app --reload

Then open http://127.0.0.1:8000/docs for an interactive page where every endpoint can be tried.

## Mock mode

`MOCK_MODE = True` in `app/main.py`. While it is on, `POST /api/analysis/start` fills the analysis folder with sample JSON (`app/mock_data.py`) describing one complete attack path. This lets the frontend be built before the real analyzers exist. The sample names are placeholders, not real analysis output.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Check the server is running |
| POST | `/api/apk/upload` | Upload an `.apk` (form field `file`), returns `application_id` |
| POST | `/api/analysis/start` | Body `{"application_id": "..."}`, returns `analysis_id` and stage status |
| GET | `/api/analysis/{id}` | Status of the analysis and its stages |
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
    curl http://127.0.0.1:8000/api/attack-paths/analysis-001

## Integrating an analyzer

Each analyzer should be runnable as a command that takes an APK path and writes its JSON file, for example:

    python analyze.py --apk path/to/app.apk --out result.json

Send the command to Member 5 so the backend runner can call it.

## Not included yet

Login, user accounts, cloud deployment, advanced databases. The first version only needs the pipeline to work.
