"""Hand-written sample results so the frontend (Member 6) can integrate before
the real analyzers exist. Names are placeholders, not real analysis output."""

APP_ID = "application-001"
CLS = "com.b3nac.injuredandroid.MainActivity"
LOAD_URL = "loadUrl(Ljava/lang/String;)V"

MANIFEST = {
    "application_id": APP_ID,
    "package_name": "com.b3nac.injuredandroid",
    "components": [
        {"id": "component-001", "application_id": APP_ID, "type": "activity",
         "name": CLS, "exported": True,
         "intent_filters": ["android.intent.action.VIEW"]},
        {"id": "component-002", "application_id": APP_ID, "type": "receiver",
         "name": "com.b3nac.injuredandroid.SomeReceiver", "exported": True,
         "intent_filters": []},
    ],
    "permissions": ["android.permission.INTERNET"],
}

STATIC = {
    "application_id": APP_ID,
    "flows": [{
        "id": "flow-001",
        "component_id": "component-001",
        "source": {"id": "source-001", "type": "intent_extra", "name": "url"},
        "sink": {"id": "sink-001", "type": "webview", "method_id": "method-002"},
        "methods": [
            {"id": "method-001", "class": CLS, "method": "onCreate(Landroid/os/Bundle;)V"},
            {"id": "method-002", "class": "android.webkit.WebView", "method": LOAD_URL},
        ],
        "path": ["getIntent()", "getStringExtra(\"url\")", "WebView.loadUrl(url)"],
    }],
}

RUNTIME_EVENTS = {
    "application_id": APP_ID,
    "events": [],
}
ATTACK_PATHS = {
    "application_id": APP_ID,
    "attack_paths": [{
        "id": "attack-path-001", "status": "CORRELATED",
        "nodes": ["component-001", "source-001", "method-001", "sink-001", "event-001"],
        "evidence": ["evidence-001", "evidence-002"],
    }],
}

FINDINGS = {
    "application_id": APP_ID,
    "findings": [{
        "id": "finding-001", "attack_path_id": "attack-path-001",
        "title": "Intent extra reaches WebView.loadUrl",
        "status": "CORRELATED",
    }],
}

EVIDENCE = {
    "application_id": APP_ID,
    "evidence": [
        {"id": "evidence-001", "kind": "static", "ref": "flow-001"},
        {"id": "evidence-002", "kind": "runtime", "ref": "event-001"},
    ],
}

# file key (see storage.RESULT_FILES) -> sample content
ALL = {
    "manifest": MANIFEST, "static": STATIC, "dynamic": RUNTIME_EVENTS,
    "correlation": ATTACK_PATHS, "findings": FINDINGS, "evidence": EVIDENCE,
}
