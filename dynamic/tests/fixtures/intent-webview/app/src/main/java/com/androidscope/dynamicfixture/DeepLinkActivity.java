package com.androidscope.dynamicfixture;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.webkit.WebView;
import android.widget.TextView;

public class DeepLinkActivity extends Activity {
    private static final String TEST_URL_PREFIX =
            "file:///android_asset/test-page.html?run=";

    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);
        setContentView(webView);
        loadFromIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        loadFromIntent(intent);
    }

    private void loadFromIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        String url = intent.getStringExtra("test_url");
        if (isAllowedTestUrl(url)) {
            webView.loadUrl(url);
        } else {
            TextView message = new TextView(this);
            message.setText("Pass a local AndroidScope test_url extra to run the fixture.");
            setContentView(message);
        }
    }

    private boolean isAllowedTestUrl(String url) {
        if (url == null || !url.startsWith(TEST_URL_PREFIX)) {
            return false;
        }
        String runId = url.substring(TEST_URL_PREFIX.length());
        return runId.matches("[A-Za-z0-9-]{1,64}");
    }
}
