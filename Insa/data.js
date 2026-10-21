window.demoData = {
  application: {
    name: "InjuredAndroid.apk",
    packageName: "b3nac.injuredandroid",
    analysisId: "analysis-demo-001"
  },
  componentCounts: {
    activities: 5,
    services: 2,
    receivers: 2,
    providers: 1
  },
  components: [
    { name: "MainActivity", type: "Activity", exported: true, note: "Main entry point" },
    { name: "LoginActivity", type: "Activity", exported: true, note: "Login screen" },
    { name: "DataService", type: "Service", exported: false, note: "Background processing" },
    { name: "BootReceiver", type: "Broadcast Receiver", exported: true, note: "Boot event handler" },
    { name: "FileProvider", type: "Provider", exported: false, note: "File sharing component" }
  ],
  attackPaths: [
    {
      status: "STATIC_CANDIDATE",
      explanation: "Illustrative path only. Runtime confirmation has not been established.",
      nodes: [
        { label: "External Input", detail: "Input from an external source", icon: "01" },
        { label: "MainActivity", detail: "Potential entry point", icon: "02" },
        { label: "Intent Extra", detail: "Example URL parameter", icon: "03" },
        { label: "WebView.loadUrl()", detail: "Potential URL loading", icon: "04" },
        { label: "Runtime Check", detail: "Requires runtime evidence", icon: "05", runtime: false }
      ]
    }
  ],
  evidence: [
    {
      id: "evidence-001",
      title: "Exported activity example",
      type: "Static analysis",
      description: "Example evidence for an activity that may be reachable externally.",
      source: "Illustrative manifest entry",
      snippet: "android:exported=\"true\"",
      confidenceNote: "An exported component is not automatically a vulnerability."
    },
    {
      id: "evidence-002",
      title: "Runtime verification",
      type: "Runtime observation",
      description: "No real runtime observation is included in this sample.",
      source: "Demo data",
      snippet: "",
      confidenceNote: "Do not treat this record as proof of runtime behavior."
    }
  ]
};
