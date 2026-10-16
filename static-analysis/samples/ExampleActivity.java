package samples;

import android.content.Intent;
import android.net.Uri;
import android.webkit.WebView;

public class ExampleActivity {

    public void loadWebPage(Intent intent, WebView webView) {

        // SOURCE: Read input from an Intent extra.
        String url = intent.getStringExtra("url");

        // SINK: Pass the input to WebView.
        webView.loadUrl(url);
    }

    public void executeCommand(Uri data) {

        // SOURCE: Read input from a URI query parameter.
        String binary = data.getQueryParameter("binary");

        // SOURCE: Read another URI query parameter.
        String parameter = data.getQueryParameter("param");

        // TRANSFORMATION: Combine the inputs into a command string.
        StringBuilder command = new StringBuilder();
        command.append("/example/files/");
        command.append(binary);
        command.append(" ");
        command.append(parameter);

        // SINK: Pass the constructed string to Runtime.exec().
        Runtime runtime = Runtime.getRuntime();
        runtime.exec(command.toString());
    }
}