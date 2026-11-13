package com.androidscope.dynamicfixture;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.LinearLayout;

public class JsiBridgeActivity extends Activity {
    static final String JSI_PAGE_URL = "file:///android_asset/jsi-test-page.html";
    static final String EVAL_SCRIPT = "document.title";
    static final String BRIDGE_NAME = "AndroidBridge";

    private WebView webView;

    public static final class AndroidBridge {
        @JavascriptInterface
        public String ping() {
            return "pong";
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.addJavascriptInterface(new AndroidBridge(), BRIDGE_NAME);
        webView.loadUrl(JSI_PAGE_URL);

        Button evalButton = new Button(this);
        evalButton.setText("Evaluate JS");
        evalButton.setOnClickListener(v -> webView.evaluateJavascript(EVAL_SCRIPT, null));

        LinearLayout.LayoutParams webParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f);
        LinearLayout.LayoutParams btnParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.addView(webView, webParams);
        layout.addView(evalButton, btnParams);
        setContentView(layout);
    }
}
