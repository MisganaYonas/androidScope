Java.perform(function () {
  function safeString(value) {
    try {
      return value == null ? null : value.toString();
    } catch (e) {
      return "[unavailable]";
    }
  }

  function eventValue(value) {
    if (value == null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      return value;
    }
    return safeString(value);
  }

  function emitEvent(eventType, className, methodName, args, metadata, returnValue) {
    const event = {
      event_type: eventType,
      timestamp: new Date().toISOString(),
      class: className,
      method: methodName,
      arguments: args || [],
      metadata: metadata || {}
    };

    if (typeof returnValue !== "undefined") {
      event.return_value = eventValue(returnValue);
    }

    try {
      send(event);
    } catch (e) {
      console.log("[androidScope] Failed to send event: " + safeString(e));
    }
  }

  function invokeAndEmit(overload, receiver, args, eventType, className, methodName, eventArgs, metadata) {
    const result = overload.call(receiver, ...args);
    emitEvent(eventType, className, methodName, eventArgs, metadata, result);
    return result;
  }

  try {
    const WebView = Java.use("android.webkit.WebView");
    const WebViewClient = Java.use("android.webkit.WebViewClient");
    const WebChromeClient = Java.use("android.webkit.WebChromeClient");

    const loadUrl = WebView.loadUrl.overload("java.lang.String");
    loadUrl.implementation = function (url) {
      return invokeAndEmit(loadUrl, this, [url], "method_call", "android.webkit.WebView", "loadUrl", [safeString(url)], {
        url: safeString(url)
      });
    };

    const loadUrlWithHeaders = WebView.loadUrl.overload("java.lang.String", "java.util.Map");
    loadUrlWithHeaders.implementation = function (url, headers) {
      return invokeAndEmit(loadUrlWithHeaders, this, [url, headers], "method_call", "android.webkit.WebView", "loadUrl", [safeString(url), safeString(headers)], {
        url: safeString(url),
        headers: safeString(headers)
      });
    };

    const loadData = WebView.loadData.overload("java.lang.String", "java.lang.String", "java.lang.String");
    loadData.implementation = function (data, mimeType, encoding) {
      return invokeAndEmit(loadData, this, [data, mimeType, encoding], "method_call", "android.webkit.WebView", "loadData", [
        safeString(data),
        safeString(mimeType),
        safeString(encoding)
      ], {
        mime_type: safeString(mimeType),
        encoding: safeString(encoding)
      });
    };

    const loadDataWithBaseURL = WebView.loadDataWithBaseURL.overload(
      "java.lang.String",
      "java.lang.String",
      "java.lang.String",
      "java.lang.String",
      "java.lang.String"
    );
    loadDataWithBaseURL.implementation = function (baseUrl, data, mimeType, encoding, historyUrl) {
      return invokeAndEmit(loadDataWithBaseURL, this, [baseUrl, data, mimeType, encoding, historyUrl], "method_call", "android.webkit.WebView", "loadDataWithBaseURL", [
        safeString(baseUrl),
        safeString(data),
        safeString(mimeType),
        safeString(encoding),
        safeString(historyUrl)
      ], {
        base_url: safeString(baseUrl),
        mime_type: safeString(mimeType),
        encoding: safeString(encoding),
        history_url: safeString(historyUrl)
      });
    };

    const addJavascriptInterface = WebView.addJavascriptInterface.overload("java.lang.Object", "java.lang.String");
    addJavascriptInterface.implementation = function (obj, name) {
      const targetClass = obj && obj.getClass ? safeString(obj.getClass().getName()) : safeString(obj);
      return invokeAndEmit(addJavascriptInterface, this, [obj, name], "method_call", "android.webkit.WebView", "addJavascriptInterface", [
        targetClass,
        safeString(name)
      ], {
        interface_name: safeString(name),
        target_class: targetClass
      });
    };

    const evaluateJavascript = WebView.evaluateJavascript.overload(
      "java.lang.String",
      "android.webkit.ValueCallback"
    );
    evaluateJavascript.implementation = function (script, callback) {
      return invokeAndEmit(evaluateJavascript, this, [script, callback], "method_call", "android.webkit.WebView", "evaluateJavascript", [
        safeString(script),
        callback == null ? null : safeString(callback.getClass().getName())
      ], {
        script: safeString(script)
      });
    };

    const setWebViewClient = WebView.setWebViewClient.overload("android.webkit.WebViewClient");
    setWebViewClient.implementation = function (client) {
      const clientClass = client && client.getClass ? safeString(client.getClass().getName()) : safeString(client);
      return invokeAndEmit(setWebViewClient, this, [client], "method_call", "android.webkit.WebView", "setWebViewClient", [
        clientClass
      ], {
        client_class: clientClass
      });
    };

    const shouldOverrideUrlLoadingString = WebViewClient.shouldOverrideUrlLoading.overload(
      "android.webkit.WebView",
      "java.lang.String"
    );
    shouldOverrideUrlLoadingString.implementation = function (view, url) {
      const packageName = view && view.getContext ? safeString(view.getContext().getPackageName()) : null;
      return invokeAndEmit(shouldOverrideUrlLoadingString, this, [view, url], "method_call", "android.webkit.WebViewClient", "shouldOverrideUrlLoading", [
        safeString(url)
      ], {
        url: safeString(url),
        package_name: packageName,
        overload: "android.webkit.WebView,java.lang.String"
      });
    };

    const shouldOverrideUrlLoadingRequest = WebViewClient.shouldOverrideUrlLoading.overload(
      "android.webkit.WebView",
      "android.webkit.WebResourceRequest"
    );
    shouldOverrideUrlLoadingRequest.implementation = function (view, request) {
      let url = null;
      try {
        url = request && request.getUrl ? safeString(request.getUrl()) : null;
      } catch (e) {
        url = "[unavailable]";
      }
      return invokeAndEmit(shouldOverrideUrlLoadingRequest, this, [view, request], "method_call", "android.webkit.WebViewClient", "shouldOverrideUrlLoading", [
        url
      ], {
        url: url,
        overload: "android.webkit.WebView,android.webkit.WebResourceRequest"
      });
    };

    const onPageStarted = WebViewClient.onPageStarted.overload(
      "android.webkit.WebView",
      "java.lang.String",
      "android.graphics.Bitmap"
    );
    onPageStarted.implementation = function (view, url, favicon) {
      return invokeAndEmit(onPageStarted, this, [view, url, favicon], "webview_page_started", "android.webkit.WebViewClient", "onPageStarted", [
        safeString(url)
      ], {
        url: safeString(url)
      });
    };

    const onPageFinished = WebViewClient.onPageFinished.overload("android.webkit.WebView", "java.lang.String");
    onPageFinished.implementation = function (view, url) {
      return invokeAndEmit(onPageFinished, this, [view, url], "webview_page_finished", "android.webkit.WebViewClient", "onPageFinished", [
        safeString(url)
      ], {
        url: safeString(url)
      });
    };

    const onLoadResource = WebViewClient.onLoadResource.overload("android.webkit.WebView", "java.lang.String");
    onLoadResource.implementation = function (view, url) {
      return invokeAndEmit(onLoadResource, this, [view, url], "method_call", "android.webkit.WebViewClient", "onLoadResource", [
        safeString(url)
      ], {
        url: safeString(url)
      });
    };

    const onConsoleMessage = WebChromeClient.onConsoleMessage.overload("android.webkit.ConsoleMessage");
    onConsoleMessage.implementation = function (consoleMessage) {
      const metadata = {
        message: consoleMessage ? safeString(consoleMessage.message()) : null,
        source_id: consoleMessage ? safeString(consoleMessage.sourceId()) : null,
        line_number: consoleMessage ? consoleMessage.lineNumber() : null,
        message_level: consoleMessage ? safeString(consoleMessage.messageLevel()) : null
      };
      return invokeAndEmit(onConsoleMessage, this, [consoleMessage], "console_message", "android.webkit.WebChromeClient", "onConsoleMessage", [
        consoleMessage == null ? null : "android.webkit.ConsoleMessage"
      ], metadata);
    };

    const onJsAlert = WebChromeClient.onJsAlert.overload(
      "android.webkit.WebView",
      "java.lang.String",
      "java.lang.String",
      "android.webkit.JsResult"
    );
    onJsAlert.implementation = function (view, url, message, result) {
      return invokeAndEmit(onJsAlert, this, [view, url, message, result], "method_call", "android.webkit.WebChromeClient", "onJsAlert", [
        safeString(url),
        safeString(message)
      ], {
        url: safeString(url),
        message: safeString(message)
      });
    };

    emitEvent("hook_status", "android.webkit.WebView", "webview_hook", [], {
      status: "ready"
    });
  } catch (err) {
    console.log("[androidScope] Frida hook initialization failed: " + safeString(err));
  }
});
