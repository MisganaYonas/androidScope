Java.perform(function () {
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
      event.return_value = returnValue;
    }

    try {
      send(event);
    } catch (error) {
      console.log("[androidScope] Failed to send Intent event: " + error);
    }
  }

  function callJava(object, methodName, signature, args) {
    const method = object[methodName].overload.apply(object[methodName], signature);
    return method.call.apply(method, [object].concat(args || []));
  }

  function readValue(object, methodName, signature, args, errors) {
    try {
      return callJava(object, methodName, signature, args);
    } catch (error) {
      errors.push(methodName + ": " + error);
      return null;
    }
  }

  function safeString(value, errors, label) {
    if (value == null) {
      return null;
    }

    try {
      return value.toString();
    } catch (error) {
      errors.push(label + ": " + error);
      return null;
    }
  }

  function getActivityClass(activity, errors) {
    const activityClass = readValue(activity, "getClass", [], [], errors);
    return safeString(readValue(activityClass, "getName", [], [], errors), errors, "activity_class");
  }

  function captureCategories(categories, errors) {
    const values = [];
    if (categories == null) {
      return values;
    }

    const iterator = readValue(categories, "iterator", [], [], errors);
    if (iterator == null) {
      return values;
    }

    while (readValue(iterator, "hasNext", [], [], errors)) {
      const value = readValue(iterator, "next", [], [], errors);
      if (value == null) {
        break;
      }
      const category = safeString(value, errors, "category");
      if (category != null) {
        values.push(category);
      }
    }
    return values;
  }

  function capturePrimitiveExtra(value, errors, key) {
    if (value == null) {
      return null;
    }

    if (typeof value === "string") {
      const truncated = value.length > 1024;
      return {
        type: "string",
        value: truncated ? value.substring(0, 1024) : value,
        truncated: truncated
      };
    }
    if (typeof value === "boolean") {
      return { type: "boolean", value: value };
    }
    if (typeof value === "number") {
      return isFinite(value) ? { type: "number", value: value } : null;
    }

    const valueClass = readValue(value, "getClass", [], [], errors);
    const className = safeString(readValue(valueClass, "getName", [], [], errors), errors, "extra." + key + ".class");
    if (className == null) {
      return null;
    }

    if (className === "java.lang.String") {
      let stringValue = safeString(value, errors, "extra." + key);
      if (stringValue == null) {
        return null;
      }
      const truncated = stringValue.length > 1024;
      if (truncated) {
        stringValue = stringValue.substring(0, 1024);
      }
      return { type: "string", value: stringValue, truncated: truncated };
    }

    if (className === "java.lang.Boolean") {
      const booleanValue = safeString(value, errors, "extra." + key);
      return { type: "boolean", value: booleanValue === "true" };
    }

    if (className === "java.lang.Character") {
      return { type: "char", value: safeString(value, errors, "extra." + key) };
    }

    if (className === "java.lang.Byte" ||
        className === "java.lang.Short" ||
        className === "java.lang.Integer" ||
        className === "java.lang.Float" ||
        className === "java.lang.Double") {
      const numericString = safeString(value, errors, "extra." + key);
      if (numericString != null) {
        const numericValue = Number(numericString);
        if (isFinite(numericValue)) {
          return { type: className.substring("java.lang.".length).toLowerCase(), value: numericValue };
        }
      }
      return null;
    }

    if (className === "java.lang.Long") {
      return { type: "long", value: safeString(value, errors, "extra." + key) };
    }

    return null;
  }

  function captureExtras(bundle, errors) {
    const extraKeys = [];
    const primitiveExtras = [];
    if (bundle == null) {
      return { extra_keys: extraKeys, primitive_extras: primitiveExtras };
    }

    const keys = readValue(bundle, "keySet", [], [], errors);
    if (keys == null) {
      return { extra_keys: extraKeys, primitive_extras: primitiveExtras };
    }

    const iterator = readValue(keys, "iterator", [], [], errors);
    if (iterator == null) {
      return { extra_keys: extraKeys, primitive_extras: primitiveExtras };
    }

    while (readValue(iterator, "hasNext", [], [], errors)) {
      const keyObject = readValue(iterator, "next", [], [], errors);
      const key = safeString(keyObject, errors, "extra_key");
      if (key == null) {
        continue;
      }
      extraKeys.push(key);

      try {
        const value = callJava(bundle, "get", ["java.lang.String"], [key]);
        const primitive = capturePrimitiveExtra(value, errors, key);
        if (primitive != null) {
          primitiveExtras.push({ key: key, type: primitive.type, value: primitive.value, truncated: primitive.truncated || false });
        }
      } catch (error) {
        errors.push("extra." + key + ": " + error);
      }
    }

    return { extra_keys: extraKeys, primitive_extras: primitiveExtras };
  }

  function captureIntent(intent, activity) {
    const errors = [];
    const activityClass = activity == null ? null : getActivityClass(activity, errors);
    const metadata = {
      activity_class: activityClass,
      action: null,
      data_uri: null,
      mime_type: null,
      package: null,
      component: null,
      categories: [],
      flags: null,
      extra_keys: [],
      primitive_extras: []
    };

    if (intent == null) {
      metadata.capture_errors = errors;
      return metadata;
    }

    metadata.action = safeString(readValue(intent, "getAction", [], [], errors), errors, "action");
    metadata.data_uri = safeString(readValue(intent, "getDataString", [], [], errors), errors, "data_uri");
    metadata.mime_type = safeString(readValue(intent, "getType", [], [], errors), errors, "mime_type");
    metadata.package = safeString(readValue(intent, "getPackage", [], [], errors), errors, "package");

    const component = readValue(intent, "getComponent", [], [], errors);
    if (component != null) {
      metadata.component = {
        package: safeString(readValue(component, "getPackageName", [], [], errors), errors, "component.package"),
        class: safeString(readValue(component, "getClassName", [], [], errors), errors, "component.class")
      };
    }

    metadata.categories = captureCategories(readValue(intent, "getCategories", [], [], errors), errors);
    metadata.flags = readValue(intent, "getFlags", [], [], errors);

    const extras = captureExtras(readValue(intent, "getExtras", [], [], errors), errors);
    metadata.extra_keys = extras.extra_keys;
    metadata.primitive_extras = extras.primitive_extras;

    if (errors.length > 0) {
      metadata.capture_errors = errors;
    }
    return metadata;
  }

  let startActivityDepth = 0;

  function invokeStartActivity(overload, receiver, intent, options, hasOptions, signature) {
    if (startActivityDepth === 0) {
      const metadata = captureIntent(intent, receiver);
      metadata.overload_signature = signature;
      if (hasOptions) {
        metadata.options_bundle_present = options != null;
      }
      emitEvent("intent_outgoing", "android.app.Activity", "startActivity", [signature], metadata);
    }

    startActivityDepth++;
    try {
      if (!hasOptions) {
        return overload.call(receiver, intent);
      }
      return overload.call(receiver, intent, options);
    } finally {
      startActivityDepth--;
    }
  }

  try {
    const Activity = Java.use("android.app.Activity");
    const Intent = "android.content.Intent";
    const Bundle = "android.os.Bundle";

    const getIntent = Activity.getIntent.overload();
    getIntent.implementation = function () {
      const intent = getIntent.call(this);
      const metadata = captureIntent(intent, this);
      emitEvent("intent_incoming", "android.app.Activity", "getIntent", [], metadata, {
        class: Intent,
        ...metadata
      });
      return intent;
    };

    const onNewIntent = Activity.onNewIntent.overload(Intent);
    onNewIntent.implementation = function (intent) {
      const metadata = captureIntent(intent, this);
      emitEvent("intent_incoming", "android.app.Activity", "onNewIntent", [Intent], metadata);
      return onNewIntent.call(this, intent);
    };

    const startActivity = Activity.startActivity.overload(Intent);
    startActivity.implementation = function (intent) {
      return invokeStartActivity(startActivity, this, intent, null, false, "android.content.Intent");
    };

    const startActivityWithOptions = Activity.startActivity.overload(Intent, Bundle);
    startActivityWithOptions.implementation = function (intent, options) {
      return invokeStartActivity(startActivityWithOptions, this, intent, options, true, "android.content.Intent,android.os.Bundle");
    };

    emitEvent("hook_status", "android.app.Activity", "intent_hook", [], {
      status: "ready",
      hooks: [
        "getIntent()",
        "onNewIntent(android.content.Intent)",
        "startActivity(android.content.Intent)",
        "startActivity(android.content.Intent, android.os.Bundle)"
      ]
    });
  } catch (error) {
    console.log("[androidScope] Intent hook initialization failed: " + error);
  }
});
