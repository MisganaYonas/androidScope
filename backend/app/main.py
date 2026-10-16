from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import mock_data, storage

# While True, "start analysis" fills the folder with sample JSON.
# Later: set False and let the runner call the real analyzers.
MOCK_MODE = True

app = FastAPI(title="DroidTrace API")
app.add_middleware(  # lets the frontend dev server call this API
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)
storage.init_dirs()


class StartRequest(BaseModel):
    application_id: str


def _load(analysis_id: str, key: str):
    """Read one module's result file, or return a clear 404."""
    path = storage.analysis_dir(analysis_id) / storage.RESULT_FILES[key]
    if not path.exists():
        raise HTTPException(404, f"{storage.RESULT_FILES[key]} not available for {analysis_id}")
    return storage.read_json(path)


@app.get("/api/health")
def health():
    return {"status": "ok", "mock_mode": MOCK_MODE}


@app.post("/api/apk/upload")
async def upload_apk(file: UploadFile = File(...)):
    if not (file.filename or "").lower().endswith(".apk"):
        raise HTTPException(400, "Please upload a .apk file")
    application_id = storage.next_id("application", storage.APK_DIR)
    (storage.APK_DIR / f"{application_id}.apk").write_bytes(await file.read())
    return {"application_id": application_id, "apk_name": file.filename}


@app.post("/api/analysis/start")
def start_analysis(req: StartRequest):
    apk = storage.APK_DIR / f"{req.application_id}.apk"
    if not apk.exists():
        raise HTTPException(404, "Unknown application_id")
    analysis_id = storage.next_id("analysis", storage.ANALYSIS_DIR)
    folder = storage.analysis_dir(analysis_id)
    folder.mkdir()

    status = {"analysis_id": analysis_id, "application_id": req.application_id,
              "status": "pending", "stages": {s: "pending" for s in storage.STAGES}}
    if MOCK_MODE:
        for key, data in mock_data.ALL.items():
            storage.write_json(folder / storage.RESULT_FILES[key], data)
        status["status"] = "completed"
        status["stages"] = {s: "done" for s in storage.STAGES}
    storage.write_json(folder / "status.json", status)
    return status


@app.get("/api/analysis/{analysis_id}")
def get_analysis(analysis_id: str):
    path = storage.analysis_dir(analysis_id) / "status.json"
    if not path.exists():
        raise HTTPException(404, "Unknown analysis_id")
    return storage.read_json(path)


@app.get("/api/components/{analysis_id}")
def get_components(analysis_id: str):
    return _load(analysis_id, "manifest")


@app.get("/api/static/{analysis_id}")
def get_static(analysis_id: str):
    return _load(analysis_id, "static")


@app.get("/api/runtime-events/{analysis_id}")
def get_runtime_events(analysis_id: str):
    return _load(analysis_id, "dynamic")


@app.post("/api/analysis/{analysis_id}/runtime-events")
def upload_runtime_events(analysis_id: str, events: dict):
    """Member 3 runs Frida manually at first and posts the resulting JSON here."""
    folder = storage.analysis_dir(analysis_id)
    if not folder.exists():
        raise HTTPException(404, "Unknown analysis_id")
    storage.write_json(folder / storage.RESULT_FILES["dynamic"], events)
    return {"saved": storage.RESULT_FILES["dynamic"]}


@app.get("/api/attack-paths/{analysis_id}")
def get_attack_paths(analysis_id: str):
    return _load(analysis_id, "correlation")


@app.get("/api/vulnerabilities/{analysis_id}")
def get_vulnerabilities(analysis_id: str):
    return _load(analysis_id, "findings")


@app.get("/api/evidence/{analysis_id}")
def get_evidence(analysis_id: str):
    return _load(analysis_id, "evidence")
