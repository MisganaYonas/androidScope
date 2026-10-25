# DroidTrace Frontend ↔ Backend Integration Contract

This note is based on the supplied **Project Architecture** and **Project Division** PDFs. It records the frontend assumptions that must be agreed with Member 5 before merging.

## 1. Architecture

`Frontend → Backend REST API → APK/static/dynamic analysis → correlation engine → JSON results → Frontend visualization`

The frontend must not call Frida or analyzer modules directly. JSON is the interchange format. Use the same IDs across modules (`application_id`, `component_id`, `class_id`, `method_id`, `source_id`, `sink_id`, `event_id`, `evidence_id`, `attack_path_id`, `finding_id`).

## 2. Endpoints named in the PDFs

- `POST /api/apk/upload`
- `POST /api/analysis/start`
- `GET /api/analysis/{id}`
- `GET /api/vulnerabilities/{id}`
- `GET /api/attack-paths/{id}`

The PDFs name these routes but do **not** fully specify their request/response schemas. Confirm those details with Member 5 before merging. The HTML adapter currently assumes the upload uses `multipart/form-data` with a `file` field; upload returns `apk_id`, `application_id`, `id`, or `upload_id`; start accepts JSON `{ "apk_id": "..." }`; start returns `analysis_id` or `id`; status is in `status` or `state`.

## 3. Suggested shared JSON response shapes

These are proposed integration examples, not schemas explicitly defined in the PDFs. Agree and version them in `shared/schemas/` before relying on them.

### Component / manifest result

```json
{
  "application_id": "application-001",
  "components": [
    {
      "component_id": "component-001",
      "application_id": "application-001",
      "type": "activity",
      "name": "com.example.MainActivity",
      "exported": true,
      "intent_filters": ["android.intent.action.VIEW"]
    }
  ]
}
```

### Runtime event

```json
{
  "event_id": "event-001",
  "type": "method_call",
  "class": "android.webkit.WebView",
  "method": "loadUrl",
  "arguments": ["https://example.com"],
  "timestamp": "ISO-8601 timestamp"
}
```

### Attack path

```json
{
  "attack_path_id": "attack-path-001",
  "status": "CORRELATED",
  "nodes": ["component-001", "source-001", "method-001", "sink-001"],
  "evidence": ["evidence-001", "evidence-002"]
}
```

### Initial path statuses

Use the PDF terms exactly: `STATIC_CANDIDATE`, `RUNTIME_OBSERVED`, `CORRELATED`. Do not label a static candidate as a confirmed vulnerability. A component by itself is not necessarily a vulnerability.

## 4. Reachability rule

`exported: true` can be displayed as exported/reachable according to the manifest result. `exported: false` is not exported. If the field is missing or null, show **Reachability Unknown**. Never convert unknown into `true`, never count it as externally reachable, and never present it as a confirmed attack entry point.

## 5. Frontend configuration

Open `droidtrace-frontend-updated.html` and find `API_CONFIG` near the top of the JavaScript. Change `baseUrl` to the backend host/port your team uses. The default is `http://127.0.0.1:8000`.

If the frontend is opened as a local HTML file or served from another port, the backend may need CORS configured for that origin. A browser CORS error must be fixed in the backend configuration; it is not solved by changing the visual design.

## 6. Git workflow from the PDFs

- Work on `feature/member6-frontend` (or the team's agreed equivalent).
- Open a Pull Request into `develop`.
- Test the combined frontend and backend before merging to `main`.
- Do not push unfinished work directly to `main`.
- Coordinate any shared schema changes before changing field names.

## 7. Integration checklist

- [ ] Member 5 confirms upload field name and upload response shape.
- [ ] Member 5 confirms the analysis-start request body and response ID field.
- [ ] Member 5 confirms terminal status values and error response format.
- [ ] Team agrees on whether IDs are `id` or typed IDs such as `component_id` in each object.
- [ ] Team agrees on the exact attack-path node structure (objects vs ID strings) and finding structure.
- [ ] Team agrees on the shared schemas under `shared/schemas/`.
- [ ] Backend CORS allows the frontend origin.
- [ ] Test one full InjuredAndroid path end-to-end before adding more detectors.

**Important:** The updated frontend has a backend adapter, but no frontend can guarantee a zero-error merge until the backend request/response schemas are agreed and tested together. The adapter surfaces API and schema errors in the upload status instead of silently pretending that analysis succeeded.
