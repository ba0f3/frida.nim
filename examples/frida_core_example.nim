import os, posix, strutils, frida/core, json

proc on_detached(session: ptr FridaSession, reason: FridaSessionDetachReason, crash: ptr FridaCrash, user_data: pointer)
proc on_message(script: ptr FridaScript, message: cstring, data: ptr GBytes, user_data: pointer)
proc on_signal(signo: cint) {.noconv.}
proc stop(user_data: pointer): bool

var loop: ptr GMainLoop

proc main() =
  var
    target_pid: uint32
    manager: ptr FridaDeviceManager
    error: ptr GError
    devices: ptr FridaDeviceList
    num_devices: int32
    local_device: ptr FridaDevice
    session: ptr FridaSession

  if paramCount() != 1:
    quit "Usage: " & paramStr(0) & " <pid>"

  target_pid = parseInt(paramStr(1)).uint32

  frida_init()

  loop = g_main_loop_new(nil, true)
  signal(SIGINT, on_signal)
  signal(SIGTERM, on_signal)

  manager = frida_device_manager_new()
  devices = frida_device_manager_enumerate_devices_sync(manager, nil, addr error)
  assert error == nil

  local_device = nil
  num_devices = frida_device_list_size(devices)
  for i in 0..<num_devices:
    var device = frida_device_list_get(devices, i)
    echo "[*] Found device: ", frida_device_get_name(device)

    if frida_device_get_dtype(device) == FRIDA_DEVICE_TYPE_LOCAL:
      local_device = cast[ptr FridaDevice](g_object_ref(device))
    g_object_unref(device)
  assert local_device != nil

  frida_unref(devices)
  devices = nil

  session = frida_device_attach_sync(local_device, target_pid, FRIDA_REALM_NATIVE, nil, addr error)
  if error == nil:
    var
      script: ptr FridaScript
      options: ptr FridaScriptOptions
    g_signal_connect(session, "detached", on_detached, nil)
    if frida_session_is_detached(session):
      frida_unref(session)
      echo"[*] Detached"
    else:
      echo "[*] Attached"
      options = frida_script_options_new()
      frida_script_options_set_name(options, "example")
      frida_script_options_set_runtime(options, FRIDA_SCRIPT_RUNTIME_QJS)
      script = frida_session_create_script_sync(session, """
        Interceptor.attach(Module.getExportByName(null, 'open'), {
          onEnter(args) {
            console.log(`[*] open(\"${args[0].readUtf8String()}\")`);
          }
        });
        Interceptor.attach(Module.getExportByName(null, 'close'), {
          onEnter(args) {
            console.log(`[*] close(${args[0].toInt32()})`);
          }
        });
        """, options, nil, addr error)
      assert error == nil

      g_clear_object(addr options)

      g_signal_connect(script, "message", on_message, nil)

      frida_script_load_sync(script, nil, addr error)
      assert error == nil

      echo "[*] Script loaded"

      if g_main_loop_is_running(loop):
        g_main_loop_run(loop)

      echo "[*] Stopped"
      frida_script_unload_sync(script, nil, nil)
      frida_unref(script)
      echo "[*] Unloaded"

      frida_session_detach_sync(session, nil, nil)
      frida_unref(session)
      echo"[*] Detached"
  else:
    echo "Failed to attach: ", error.message
    g_error_free(error)

  frida_unref(local_device)
  frida_device_manager_close_sync(manager, nil, nil)
  frida_unref(manager)
  echo "[*] Closed"
  g_main_loop_unref(loop)

proc on_detached(session: ptr FridaSession, reason: FridaSessionDetachReason, crash: ptr FridaCrash, user_data: pointer) =
  echo "on_detached: reason=",  reason, " crash=", cast[int](crash)
  g_idle_add(stop, nil)

proc on_message(script: ptr FridaScript, message: cstring, data: ptr GBytes, user_data: pointer) =
  let node = parseJson($message)
  if node.hasKey("type") and node["type"].getStr() == "log":
    let payload = node["payload"].getStr()
    echo payload
  else:
    echo "on_message", message

proc on_signal(signo: cint) =
  echo "on_signal"
  g_idle_add(stop, nil)

proc stop(user_data: pointer): bool =
  echo "stop"
  g_main_loop_quit(loop)
  return false

when isMainModule:
  main()