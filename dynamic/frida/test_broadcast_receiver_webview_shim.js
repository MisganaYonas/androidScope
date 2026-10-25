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

  console.log("[receiver-webview-shim] Ready; launch TestBroadcastReceiver to install its WebView");
});
