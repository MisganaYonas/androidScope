# Dynamic Analysis

## Video Presentation

[Watch the dynamic analysis presentation](https://drive.google.com/file/d/1xdxxIBh_XM1QaiPp-1jN5TguECQn6PQC/view?usp=drivesdk)

## My Contribution

- Implemented Frida hooks to observe Activity Intent retrieval and launches, including incoming and outgoing Intent details and selected primitive extras.
- Implemented WebView hooks for selected APIs and callbacks, including `loadUrl`, page navigation, JavaScript interfaces, and JavaScript evaluation.
- Added Activity lifecycle instrumentation for create, start, resume, pause, stop, and destroy dispatches.
- Built a collector that attaches to a running Android app, loads the selected hooks, receives structured runtime events, and writes the events and diagnostics to separate JSON files.
- Created controlled fixture scenarios to verify Intent-to-WebView behavior, JavaScript interface/evaluation behavior, and deep-link/`onNewIntent` behavior.
- Kept runtime observations evidence-focused: the hooks record exercised behavior; they do not provide general taint tracking or independently prove a vulnerability.

See [CURRENT_STATE.md](CURRENT_STATE.md) for implementation details, validation status, and limitations.
