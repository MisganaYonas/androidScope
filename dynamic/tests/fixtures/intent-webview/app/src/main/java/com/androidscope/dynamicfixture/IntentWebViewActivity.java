package com.androidscope.dynamicfixture;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.webkit.WebView;
import android.widget.TextView;

public class IntentWebViewActivity extends Activity {
    private static final String TEST_URL_PREFIX =
            "file:///android_asset/test-page.html?run=";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        String url = intent.getStringExtra("test_url");
        if (!isAllowedTestUrl(url)) {
            TextView message = new TextView(this);
            message.setText("Pass a local AndroidScope test_url extra to run the fixture.");
            setContentView(message);
            return;
        }

        WebView webView = new WebView(this);
        setContentView(webView);
        webView.loadUrl(url);
    }

    private boolean isAllowedTestUrl(String url) {
        if (url == null || !url.startsWith(TEST_URL_PREFIX)) {
            return false;
        }
        String runId = url.substring(TEST_URL_PREFIX.length());
        return runId.matches("[A-Za-z0-9-]{1,64}");
    }
}
