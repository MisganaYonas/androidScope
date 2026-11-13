Java.perform(function () {
  const Activity = Java.use("b3nac.injuredandroid.TestBroadcastReceiver");
  const WebView = Java.use("android.webkit.WebView");
  const onCreate = Activity.onCreate.overload("android.os.Bundle");
  const contentViewId = 0x7f080003;

  onCreate.implementation = function (savedInstanceState) {
    onCreate.call(this, savedInstanceState);

    const webView = WebView.$new(this);
    webView.setId(contentViewId);
    this.setContentView(webView);
    console.log("[receiver-webview-shim] Installed WebView with receiver lookup ID 0x7f080003");
  };

  send({
    event_type: "hook_status",
    timestamp: new Date().toISOString(),
    class: "b3nac.injuredandroid.TestBroadcastReceiver",
    method: "receiver_webview_shim",
    arguments: [],
    metadata: {
      status: "ready",
      content_view_id: contentViewId
    }
  });
});
