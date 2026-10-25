package com.androidscope.dynamicfixture;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView message = new TextView(this);
        message.setText(
                "AndroidScope Intent-to-WebView test fixture. "
                        + "Attach Frida, then start IntentWebViewActivity with the documented test_url extra.");
        setContentView(message);
    }
}
