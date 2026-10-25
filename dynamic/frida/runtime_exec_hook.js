Java.perform(function () {
  function emitEvent(className, methodName, args) {
    send({
      event_type: "method_call",
      timestamp: new Date().toISOString(),
      class: className,
      method: methodName,
      arguments: args,
      metadata: {}
    });
  }

  function serializeArgument(value, type) {
    if (value == null) {
      return null;
    }

    if (type === "string_array") {
      const values = [];
      for (let index = 0; index < value.length; index += 1) {
        values.push(value[index] == null ? null : value[index].toString());
      }
      return values;
    }

    return value.toString();
  }

  function emitHookStatus(status, error) {
    send({
      event_type: "hook_status",
      timestamp: new Date().toISOString(),
      class: "java.lang.Runtime",
      method: "runtime_exec_hook",
      arguments: [],
      metadata: error ? { status: status, error: error.toString() } : { status: status }
    });
  }

  try {
    const Runtime = Java.use("java.lang.Runtime");
    const Thread = Java.use("java.lang.Thread");
    const execDepthByThread = Object.create(null);
    const overloads = [
      { signature: ["java.lang.String"], types: ["string"] },
      { signature: ["[Ljava.lang.String;"], types: ["string_array"] },
      { signature: ["java.lang.String", "[Ljava.lang.String;"], types: ["string", "string_array"] },
      { signature: ["java.lang.String", "[Ljava.lang.String;", "java.io.File"], types: ["string", "string_array", "file"] },
      { signature: ["[Ljava.lang.String;", "[Ljava.lang.String;"], types: ["string_array", "string_array"] },
      { signature: ["[Ljava.lang.String;", "[Ljava.lang.String;", "java.io.File"], types: ["string_array", "string_array", "file"] }
    ];

    overloads.forEach(function (descriptor) {
      const exec = Runtime.exec.overload.apply(Runtime.exec, descriptor.signature);
      exec.implementation = function () {
        const args = Array.prototype.slice.call(arguments);
        const threadId = Thread.currentThread().getId().toString();
        const depth = execDepthByThread[threadId] || 0;
        execDepthByThread[threadId] = depth + 1;

        if (depth === 0) {
          emitEvent(
            "java.lang.Runtime",
            "exec",
            args.map(function (value, index) {
              return serializeArgument(value, descriptor.types[index]);
            })
          );
        }

        try {
          return exec.call.apply(exec, [this].concat(args));
        } finally {
          if (depth === 0) {
            delete execDepthByThread[threadId];
          } else {
            execDepthByThread[threadId] = depth;
          }
        }
      };
    });

    emitHookStatus("ready");
  } catch (error) {
    emitHookStatus("failed", error);
  }
});
