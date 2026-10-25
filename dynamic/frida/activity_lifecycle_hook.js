Java.perform(function () {
  function getActivityClass(activity) {
    try {
      return activity.getClass().getName().toString();
    } catch (error) {
      return "unknown";
    }
  }

  function emitLifecycleEvent(activity, methodName, lifecycleState, args, metadata) {
    const event = {
      event_type: "activity_lifecycle",
      timestamp: new Date().toISOString(),
      class: getActivityClass(activity),
      method: methodName,
      arguments: args || [],
      metadata: Object.assign({
        lifecycle_state: lifecycleState
      }, metadata || {})
    };

    try {
      send(event);
    } catch (error) {
      console.log("[androidScope] Failed to send Activity lifecycle event: " + error);
    }
  }

  try {
    const Instrumentation = Java.use("android.app.Instrumentation");
    const Activity = "android.app.Activity";
    const Bundle = "android.os.Bundle";

    const callActivityOnCreate = Instrumentation.callActivityOnCreate.overload(Activity, Bundle);
    callActivityOnCreate.implementation = function (activity, savedInstanceState) {
      emitLifecycleEvent(activity, "onCreate", "created", [
        savedInstanceState == null ? null : Bundle
      ], {
        saved_instance_state_present: savedInstanceState != null
      });
      return callActivityOnCreate.call(this, activity, savedInstanceState);
    };

    const callActivityOnStart = Instrumentation.callActivityOnStart.overload(Activity);
    callActivityOnStart.implementation = function (activity) {
      emitLifecycleEvent(activity, "onStart", "started", []);
      return callActivityOnStart.call(this, activity);
    };

    const callActivityOnResume = Instrumentation.callActivityOnResume.overload(Activity);
    callActivityOnResume.implementation = function (activity) {
      emitLifecycleEvent(activity, "onResume", "resumed", []);
      return callActivityOnResume.call(this, activity);
    };

    const callActivityOnPause = Instrumentation.callActivityOnPause.overload(Activity);
    callActivityOnPause.implementation = function (activity) {
      emitLifecycleEvent(activity, "onPause", "paused", []);
      return callActivityOnPause.call(this, activity);
    };

    const callActivityOnStop = Instrumentation.callActivityOnStop.overload(Activity);
    callActivityOnStop.implementation = function (activity) {
      emitLifecycleEvent(activity, "onStop", "stopped", []);
      return callActivityOnStop.call(this, activity);
    };

    const callActivityOnDestroy = Instrumentation.callActivityOnDestroy.overload(Activity);
    callActivityOnDestroy.implementation = function (activity) {
      emitLifecycleEvent(activity, "onDestroy", "destroyed", []);
      return callActivityOnDestroy.call(this, activity);
    };

    send({
      event_type: "hook_status",
      timestamp: new Date().toISOString(),
      class: "android.app.Instrumentation",
      method: "activity_lifecycle_hook",
      arguments: [],
      metadata: {
        status: "ready",
        lifecycle_methods: ["onCreate", "onStart", "onResume", "onPause", "onStop", "onDestroy"]
      }
    });
  } catch (error) {
    console.log("[androidScope] Activity lifecycle hook initialization failed: " + error);
  }
});
