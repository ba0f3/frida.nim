when not compileOption("threads"):
  {.error: "Frida core library require --threads:on to run".}

{.passL: "-lfrida-core -latomic -lresolv".}

import private/common
export privatte/common

type
  FridaDeviceManager* = object
  FridaDeviceList* = object
  FridaDevice* = object
  FridaRemoteDeviceOptions* = object
  FridaApplicationList* = object
  FridaApplication* = object
  FridaProcessList* = object
  FridaProcess* = object
  FridaProcessMatchOptions* = object
  FridaSpawnOptions* = object
  FridaFrontmostQueryOptions* = object
  FridaApplicationQueryOptions* = object
  FridaProcessQueryOptions* = object
  FridaSessionOptions* = object
  FridaSpawnList* = object
  FridaSpawn* = object
  FridaChildList* = object
  FridaChild* = object
  FridaCrash* = object
  FridaBus* = object
  FridaSession* = object
  FridaScript* = object
  FridaScriptOptions* = object
  FridaPeerOptions* = object
  FridaRelay* = object
  FridaPortalOptions* = object
  FridaPortalMembership* = object
  FridaRpcClient* = object
  FridaRpcPeer* = object
  FridaInjector* = object
  FridaControlService* = object
  FridaControlServiceOptions* = object
  FridaPortalService* = object
  FridaEndpointParameters* = object
  FridaAuthenticationService* = object
  FridaStaticAuthenticationService* = object
  FridaFileMonitor* = object
  FridaHostSession* = object

  FridaRuntime* = enum
    FRIDA_RUNTIME_GLIB,
    FRIDA_RUNTIME_OTHER

  FridaDeviceType* = enum
    FRIDA_DEVICE_TYPE_LOCAL,
    FRIDA_DEVICE_TYPE_REMOTE,
    FRIDA_DEVICE_TYPE_USB

  FridaAgentMessageKind* = enum
    FRIDA_AGENT_MESSAGE_KIND_SCRIPT = 1,
    FRIDA_AGENT_MESSAGE_KIND_DEBUGGER

  FridaChildOrigin* = enum
    FRIDA_CHILD_ORIGIN_FORK,
    FRIDA_CHILD_ORIGIN_EXEC,
    FRIDA_CHILD_ORIGIN_SPAWN

  FridaPeerSetup* = enum
    FRIDA_PEER_SETUP_ACTIVE,
    FRIDA_PEER_SETUP_PASSIVE,
    FRIDA_PEER_SETUP_ACTPASS,
    FRIDA_PEER_SETUP_HOLDCONN


  FridaPortConflictBehavior* = enum
    FRIDA_PORT_CONFLICT_BEHAVIOR_FAIL,
    FRIDA_PORT_CONFLICT_BEHAVIOR_PICK_NEXT

  FridaRealm* = enum
    FRIDA_REALM_NATIVE,
    FRIDA_REALM_EMULATED

  FridaRelayKind* = enum
    FRIDA_RELAY_KIND_TURN_UDP,
    FRIDA_RELAY_KIND_TURN_TCP,
    FRIDA_RELAY_KIND_TURN_TLS

  FridaScope* = enum
    FRIDA_SCOPE_MINIMAL,
    FRIDA_SCOPE_METADATA,
    FRIDA_SCOPE_FULL

  FridaScriptRuntime* = enum
    FRIDA_SCRIPT_RUNTIME_DEFAULT,
    FRIDA_SCRIPT_RUNTIME_QJS,
    FRIDA_SCRIPT_RUNTIME_V8

  FridaSessionDetachReason* = enum
    FRIDA_SESSION_DETACH_REASON_APPLICATION_REQUESTED = 1,
    FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED,
    FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED,
    FRIDA_SESSION_DETACH_REASON_CONNECTION_TERMINATED,
    FRIDA_SESSION_DETACH_REASON_DEVICE_LOST

  FridaStdio* = enum
    FRIDA_STDIO_INHERIT,
    FRIDA_STDIO_PIPE

  FridaUnloadPolicy* = enum
    FRIDA_UNLOAD_POLICY_IMMEDIATE,
    FRIDA_UNLOAD_POLICY_RESIDENT,
    FRIDA_UNLOAD_POLICY_DEFERRED

  FridaWebServiceFlavor* = enum
    FRIDA_WEB_SERVICE_FLAVOR_CONTROL,
    FRIDA_WEB_SERVICE_FLAVOR_CLUSTER

  FridaWebServiceTransport* = enum
    FRIDA_WEB_SERVICE_TRANSPORT_PLAIN,
    FRIDA_WEB_SERVICE_TRANSPORT_TLS

  GAppLaunchContext* = object
  GAppInfo* = object
  GAsyncResult* = object
  GAsyncInitable* = object
  GBufferedInputStream* = object
  GBufferedOutputStream* = object
  GCancellable* = object
  GCharsetConverter* = object
  GConverter* = object
  GConverterInputStream* = object
  GConverterOutputStream* = object
  GDatagramBased* = object
  GDataInputStream* = object
  GSimplePermission* = object
  GZlibCompressor* = object
  GZlibDecompressor* = object

  GSimpleActionGroup* = object
  GRemoteActionGroup* = object
  GDBusActionGroup* = object
  GActionMap* = object
  GActionGroup* = object
  GPropertyAction* = object
  GSimpleAction* = object
  GAction* = object
  GApplication* = object
  GApplicationCommandLine* = object
  GSettingsBackend* = object
  GSettings* = object
  GPermission* = object

  GAsyncReadyCallback* = object

  GVariant* = object
  GHashTable* = object
  GIOStream* = object
  GTlsCertificate* = object
  GTypeInterface* = object

  GWeakNotify* = proc(data: pointer, where_the_object_was: ptr GObject)

  GClosure* = object

  GCallback* = pointer # proc()
  GClosureNotify* = proc(data: pointer, closure: ptr GClosure)

  GConnectFlags* = enum
    G_CONNECT_NONE,
    G_CONNECT_AFTER = 1 shl 0,
    G_CONNECT_SWAPPED = 1 shl 1

  GSignalMatchType* = enum
    G_SIGNAL_MATCH_ID = 1 shl 0,
    G_SIGNAL_MATCH_DETAIL = 1 shl 1,
    G_SIGNAL_MATCH_CLOSURE = 1 shl 2,
    G_SIGNAL_MATCH_FUNC = 1 shl 3,
    G_SIGNAL_MATCH_DATA = 1 shl 4,
    G_SIGNAL_MATCH_UNBLOCKED = 1 shl 5

  GSourceFunc* = proc (user_data: pointer): bool
  GChildWatchFunc* = proc (pid: int32, status: uint32, user_data: pointer)

{.push importc: "_frida_$1", cdecl, discardable.}

##  --- signal handlers ---
proc g_signal_has_handler_pending*(instance: pointer, signal_id: uint32, detail: GQuark, may_be_blocked: bool): bool
proc g_signal_connect_closure_by_id*(instance: pointer, signal_id: uint32, detail: GQuark, closure: ptr GClosure, after: bool): uint32
proc g_signal_connect_closure*(instance: pointer, detailed_signal: cstring, closure: ptr GClosure, after: bool): uint32
proc g_signal_connect_data*(instance: pointer, detailed_signal: cstring, c_handler: GCallback, data: pointer, destroy_data: GClosureNotify, connect_flags: GConnectFlags): uint32
proc g_signal_handler_block*(instance: pointer, handler_id: uint32)
proc g_signal_handler_unblock*(instance: pointer, handler_id: uint32)
proc g_signal_handler_disconnect*(instance: pointer, handler_id: uint32)
proc g_signal_handler_is_connected*(instance: pointer, handler_id: uint32): bool
proc g_signal_handler_find*(instance: pointer, mask: GSignalMatchType, signal_id: uint32, detail: GQuark, closure: ptr GClosure, fn: pointer, data: pointer): uint32
proc g_signal_handlers_block_matched*(instance: pointer, mask: GSignalMatchType, signal_id: uint32, detail: GQuark, closure: ptr GClosure, fn: pointer, data: pointer): uint32
proc g_signal_handlers_unblock_matched*(instance: pointer, mask: GSignalMatchType, signal_id: uint32, detail: GQuark, closure: ptr GClosure, fn: pointer, data: pointer): uint32
proc g_signal_handlers_disconnect_matched*(instance: pointer, mask: GSignalMatchType, signal_id: uint32, detail: GQuark, closure: ptr GClosure, fn: pointer, data: pointer): uint32
proc g_clear_signal_handler*(handler_id_ptr: ptr uint32, instance: pointer)

template g_signal_connect*(instance: pointer, detailed_signal: cstring, c_handler: GCallback, data: pointer) =
    g_signal_connect_data(instance, detailed_signal, c_handler, data, nil, G_CONNECT_NONE)


proc g_main_loop_new*(context: ptr GMainContext, is_running: bool): ptr GMainLoop
proc g_main_loop_run*(loop: ptr GMainLoop)
proc g_main_loop_quit*(loop: ptr GMainLoop)
proc g_main_loop_ref*(loop: ptr GMainLoop): ptr GMainLoop
proc g_main_loop_unref*(loop: ptr GMainLoop)
proc g_main_loop_is_running*(loop: ptr GMainLoop): bool
proc g_main_loop_get_context*(loop: ptr GMainLoop): ptr GMainContext

#proc g_object_new_valist*(object_type: GType, first_property_name: cstring, var_args: va_list): ptr GObject

proc g_object_setv*(obj: ptr GObject, n_properties: uint32, names: ptr cstring, values: ptr GValue)
#proc g_object_set_valist*(obj: ptr GObject, first_property_name: cstring, var_args: va_list)
proc g_object_getv*(obj: ptr GObject, n_properties: uint32, names: ptr cstring, values: ptr GValue)
#proc g_object_get_valist*(obj: ptr GObject, first_property_name: cstring, var_args: va_list)
proc g_object_set_property*(obj: ptr GObject, property_name: cstring, value: ptr GValue)
proc g_object_get_property*(obj: ptr GObject, property_name: cstring, value: ptr GValue)
proc g_object_freeze_notify*(obj: ptr GObject)
proc g_object_notify*(obj: ptr GObject, property_name: cstring)
#proc g_object_notify_by_pspec*(obj: ptr GObject, pspec: ptr GParamSpec)
proc g_object_thaw_notify*(obj: ptr GObject)
proc g_object_is_floating*(obj: pointer): bool
proc g_object_ref_sink*(obj: pointer): pointer
proc g_object_ref*(obj: pointer): pointer
proc g_object_unref*(obj: pointer)
proc g_object_weak_ref*(obj: ptr GObject, notify: GWeakNotify, data: pointer)
proc g_object_weak_unref*(obj: ptr GObject, notify: GWeakNotify, data: pointer)
proc g_object_add_weak_pointer*(obj: ptr GObject, weak_pointer_location: ptr pointer)
proc g_object_remove_weak_pointer*(obj: ptr GObject, weak_pointer_location: ptr pointer)

#proc g_clear_object*(obj_ptr: ptr ptr GObject)
proc g_clear_object*(obj_ptr: pointer)


proc g_error_free*(error: ptr GError)

proc g_timeout_add_full*(priority: uint32, interval: uint32, function: GSourceFunc, data: pointer, notify: GDestroyNotify): uint32
proc g_timeout_add*(interval: uint32, function: GSourceFunc, data: pointer): uint32
proc g_timeout_add_seconds_full*(priority: uint32, interval: uint32, function: GSourceFunc, data: pointer, notify: GDestroyNotify): uint32
proc g_timeout_add_seconds*(interval: uint32, function: GSourceFunc, data: pointer): uint32
proc g_child_watch_add_full*(priority: uint32, pid: int32, function: GChildWatchFunc, data: pointer, notify: GDestroyNotify): uint32
proc g_child_watch_add*(pid: int32, function: GChildWatchFunc, data: pointer): uint32
proc g_idle_add*(function: GSourceFunc, data: pointer): uint32
proc g_idle_add_full*(priority: uint32, function: GSourceFunc, data: pointer, notify: GDestroyNotify): uint32
proc g_idle_remove_by_data*(data: pointer): bool
proc g_main_context_invoke_full*(context: ptr GMainContext, priority: uint32, function: GSourceFunc, data: pointer, notify: GDestroyNotify)
proc g_main_context_invoke*(context: ptr GMainContext, function: GSourceFunc, data: pointer)

{.pop.}

{.push importc, cdecl, discardable.}

##  Library lifetime
proc frida_init*()
proc frida_shutdown*()
proc frida_deinit*()
proc frida_get_main_context*(): ptr GMainContext

##  Object lifetime
proc frida_unref*(obj: pointer)

##  Library versioning
proc frida_version*(major: ptr uint32, minor: ptr uint32, micro: ptr uint32, nano: ptr uint32)
proc frida_version_string*(): cstring

##  DeviceManager
type FridaDeviceManagerPredicate* = proc (device: ptr FridaDevice, user_data: pointer): bool

proc frida_device_manager_new*(): ptr FridaDeviceManager
proc frida_device_manager_close*(self: ptr FridaDeviceManager, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_manager_close_finish*(self: ptr FridaDeviceManager, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_device_manager_close_sync*(self: ptr FridaDeviceManager, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_device_manager_get_device_by_id*(self: ptr FridaDeviceManager, id: cstring, timeout: int32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_manager_get_device_by_id_finish*(self: ptr FridaDeviceManager, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_get_device_by_id_sync*(self: ptr FridaDeviceManager, id: cstring, timeout: int32, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_get_device_by_type*(self: ptr FridaDeviceManager, `type`: FridaDeviceType, timeout: int32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_manager_get_device_by_type_finish*(self: ptr FridaDeviceManager, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_get_device_by_type_sync*(self: ptr FridaDeviceManager, `type`: FridaDeviceType, timeout: int32, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_get_device*(self: ptr FridaDeviceManager, predicate: FridaDeviceManagerPredicate, predicate_target: pointer, timeout: int32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_manager_get_device_finish*(self: ptr FridaDeviceManager, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_get_device_sync*(self: ptr FridaDeviceManager, predicate: FridaDeviceManagerPredicate, predicate_target: pointer, timeout: int32, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_find_device_by_id*(self: ptr FridaDeviceManager, id: cstring, timeout: int32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_manager_find_device_by_id_finish*(self: ptr FridaDeviceManager, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_find_device_by_id_sync*(self: ptr FridaDeviceManager, id: cstring, timeout: int32, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_find_device_by_type*(self: ptr FridaDeviceManager, `type`: FridaDeviceType, timeout: int32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_manager_find_device_by_type_finish*(self: ptr FridaDeviceManager, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_find_device_by_type_sync*(self: ptr FridaDeviceManager, `type`: FridaDeviceType, timeout: int32, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_find_device*(self: ptr FridaDeviceManager, predicate: FridaDeviceManagerPredicate, predicate_target: pointer, timeout: int32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_manager_find_device_finish*(self: ptr FridaDeviceManager, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_find_device_sync*(self: ptr FridaDeviceManager, predicate: FridaDeviceManagerPredicate, predicate_target: pointer, timeout: int32, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_enumerate_devices*(self: ptr FridaDeviceManager, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_manager_enumerate_devices_finish*(self: ptr FridaDeviceManager, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaDeviceList
proc frida_device_manager_enumerate_devices_sync*(self: ptr FridaDeviceManager, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaDeviceList
proc frida_device_manager_add_remote_device*(self: ptr FridaDeviceManager, address: cstring, options: ptr FridaRemoteDeviceOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_manager_add_remote_device_finish*(self: ptr FridaDeviceManager, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_add_remote_device_sync*(self: ptr FridaDeviceManager, address: cstring, options: ptr FridaRemoteDeviceOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaDevice
proc frida_device_manager_remove_remote_device*(self: ptr FridaDeviceManager, address: cstring, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_manager_remove_remote_device_finish*(self: ptr FridaDeviceManager, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_device_manager_remove_remote_device_sync*(self: ptr FridaDeviceManager, address: cstring, cancellable: ptr GCancellable, error: ptr ptr GError)

##  DeviceList
proc frida_device_list_size*(self: ptr FridaDeviceList): int32
proc frida_device_list_get*(self: ptr FridaDeviceList, index: int32): ptr FridaDevice

##  Device
type FridaDeviceProcessPredicate* = proc (process: ptr FridaProcess, user_data: pointer): bool

proc frida_device_get_id*(self: ptr FridaDevice): cstring
proc frida_device_get_name*(self: ptr FridaDevice): cstring
proc frida_device_get_icon*(self: ptr FridaDevice): ptr GVariant
proc frida_device_get_dtype*(self: ptr FridaDevice): FridaDeviceType
proc frida_device_get_bus*(self: ptr FridaDevice): ptr FridaBus
proc frida_device_get_manager*(self: ptr FridaDevice): ptr FridaDeviceManager
proc frida_device_is_lost*(self: ptr FridaDevice): bool
proc frida_device_query_system_parameters*(self: ptr FridaDevice, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_query_system_parameters_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr GHashTable
proc frida_device_query_system_parameters_sync*(self: ptr FridaDevice, cancellable: ptr GCancellable, error: ptr ptr GError): ptr GHashTable
proc frida_device_get_frontmost_application*(self: ptr FridaDevice, options: ptr FridaFrontmostQueryOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_get_frontmost_application_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaApplication
proc frida_device_get_frontmost_application_sync*(self: ptr FridaDevice, options: ptr FridaFrontmostQueryOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaApplication
proc frida_device_enumerate_applications*(self: ptr FridaDevice, options: ptr FridaApplicationQueryOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_enumerate_applications_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaApplicationList
proc frida_device_enumerate_applications_sync*(self: ptr FridaDevice, options: ptr FridaApplicationQueryOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaApplicationList
proc frida_device_get_process_by_pid*(self: ptr FridaDevice, pid: uint32, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_get_process_by_pid_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaProcess
proc frida_device_get_process_by_pid_sync*(self: ptr FridaDevice, pid: uint32, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaProcess
proc frida_device_get_process_by_name*(self: ptr FridaDevice, name: cstring, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_get_process_by_name_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaProcess
proc frida_device_get_process_by_name_sync*(self: ptr FridaDevice, name: cstring, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaProcess
proc frida_device_get_process*(self: ptr FridaDevice, predicate: FridaDeviceProcessPredicate, predicate_target: pointer, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_get_process_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaProcess
proc frida_device_get_process_sync*(self: ptr FridaDevice, predicate: FridaDeviceProcessPredicate, predicate_target: pointer, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaProcess
proc frida_device_find_process_by_pid*(self: ptr FridaDevice, pid: uint32, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_find_process_by_pid_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaProcess
proc frida_device_find_process_by_pid_sync*(self: ptr FridaDevice, pid: uint32, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaProcess
proc frida_device_find_process_by_name*(self: ptr FridaDevice, name: cstring, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_find_process_by_name_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaProcess
proc frida_device_find_process_by_name_sync*(self: ptr FridaDevice, name: cstring, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaProcess
proc frida_device_find_process*(self: ptr FridaDevice, predicate: FridaDeviceProcessPredicate, predicate_target: pointer, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_find_process_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaProcess
proc frida_device_find_process_sync*(self: ptr FridaDevice, predicate: FridaDeviceProcessPredicate, predicate_target: pointer, options: ptr FridaProcessMatchOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaProcess
proc frida_device_enumerate_processes*(self: ptr FridaDevice, options: ptr FridaProcessQueryOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_enumerate_processes_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaProcessList
proc frida_device_enumerate_processes_sync*(self: ptr FridaDevice, options: ptr FridaProcessQueryOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaProcessList
proc frida_device_enable_spawn_gating*(self: ptr FridaDevice, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_enable_spawn_gating_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_device_enable_spawn_gating_sync*(self: ptr FridaDevice, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_device_disable_spawn_gating*(self: ptr FridaDevice, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_disable_spawn_gating_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_device_disable_spawn_gating_sync*(self: ptr FridaDevice, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_device_enumerate_pending_spawn*(self: ptr FridaDevice, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_enumerate_pending_spawn_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaSpawnList
proc frida_device_enumerate_pending_spawn_sync*(self: ptr FridaDevice, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaSpawnList
proc frida_device_enumerate_pending_children*(self: ptr FridaDevice, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_enumerate_pending_children_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaChildList
proc frida_device_enumerate_pending_children_sync*(self: ptr FridaDevice, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaChildList
proc frida_device_spawn*(self: ptr FridaDevice, program: cstring, options: ptr FridaSpawnOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_spawn_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): uint32
proc frida_device_spawn_sync*(self: ptr FridaDevice, program: cstring, options: ptr FridaSpawnOptions, cancellable: ptr GCancellable, error: ptr ptr GError): uint32
proc frida_device_input*(self: ptr FridaDevice, pid: uint32, data: ptr GBytes, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_input_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_device_input_sync*(self: ptr FridaDevice, pid: uint32, data: ptr GBytes, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_device_resume*(self: ptr FridaDevice, pid: uint32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_resume_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_device_resume_sync*(self: ptr FridaDevice, pid: uint32, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_device_kill*(self: ptr FridaDevice, pid: uint32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_kill_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_device_kill_sync*(self: ptr FridaDevice, pid: uint32, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_device_attach*(self: ptr FridaDevice, pid: uint32, options: ptr FridaSessionOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_attach_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaSession
proc frida_device_attach_sync*(self: ptr FridaDevice, pid: uint32, options: ptr FridaSessionOptions | FridaRealm, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaSession
proc frida_device_inject_library_file*(self: ptr FridaDevice, pid: uint32, path: cstring, entrypoint: cstring, data: cstring, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_inject_library_file_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): uint32
proc frida_device_inject_library_file_sync*(self: ptr FridaDevice, pid: uint32, path: cstring, entrypoint: cstring, data: cstring, cancellable: ptr GCancellable, error: ptr ptr GError): uint32
proc frida_device_inject_library_blob*(self: ptr FridaDevice, pid: uint32, blob: ptr GBytes, entrypoint: cstring, data: cstring, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_inject_library_blob_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): uint32
proc frida_device_inject_library_blob_sync*(self: ptr FridaDevice, pid: uint32, blob: ptr GBytes, entrypoint: cstring, data: cstring, cancellable: ptr GCancellable, error: ptr ptr GError): uint32
proc frida_device_open_channel*(self: ptr FridaDevice, address: cstring, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_open_channel_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr GIOStream
proc frida_device_open_channel_sync*(self: ptr FridaDevice, address: cstring, cancellable: ptr GCancellable, error: ptr ptr GError): ptr GIOStream
proc frida_device_get_host_session*(self: ptr FridaDevice, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_device_get_host_session_finish*(self: ptr FridaDevice, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaHostSession
proc frida_device_get_host_session_sync*(self: ptr FridaDevice, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaHostSession

##  RemoteDeviceOptions
proc frida_remote_device_options_new*(): ptr FridaRemoteDeviceOptions
proc frida_remote_device_options_get_certificate*(self: ptr FridaRemoteDeviceOptions): ptr GTlsCertificate
proc frida_remote_device_options_get_origin*(self: ptr FridaRemoteDeviceOptions): cstring
proc frida_remote_device_options_get_token*(self: ptr FridaRemoteDeviceOptions): cstring
proc frida_remote_device_options_get_keepalive_interval*(self: ptr FridaRemoteDeviceOptions): int32
proc frida_remote_device_options_set_certificate*(self: ptr FridaRemoteDeviceOptions, value: ptr GTlsCertificate)
proc frida_remote_device_options_set_origin*(self: ptr FridaRemoteDeviceOptions, value: cstring)
proc frida_remote_device_options_set_token*(self: ptr FridaRemoteDeviceOptions, value: cstring)
proc frida_remote_device_options_set_keepalive_interval*(self: ptr FridaRemoteDeviceOptions, value: int32)

##  ApplicationList
proc frida_application_list_size*(self: ptr FridaApplicationList): int32
proc frida_application_list_get*(self: ptr FridaApplicationList, index: int32): ptr FridaApplication

#  Application
proc frida_application_get_identifier*(self: ptr FridaApplication): cstring
proc frida_application_get_name*(self: ptr FridaApplication): cstring
proc frida_application_get_pid*(self: ptr FridaApplication): uint32
proc frida_application_get_parameters*(self: ptr FridaApplication): ptr GHashTable

##  ProcessList
proc frida_process_list_size*(self: ptr FridaProcessList): int32
proc frida_process_list_get*(self: ptr FridaProcessList, index: int32): ptr FridaProcess

##  Process
proc frida_process_get_pid*(self: ptr FridaProcess): uint32
proc frida_process_get_name*(self: ptr FridaProcess): cstring
proc frida_process_get_parameters*(self: ptr FridaProcess): ptr GHashTable

##  ProcessMatchOptions
proc frida_process_match_options_new*(): ptr FridaProcessMatchOptions
proc frida_process_match_options_get_timeout*(self: ptr FridaProcessMatchOptions): int32
proc frida_process_match_options_get_scope*(self: ptr FridaProcessMatchOptions): FridaScope
proc frida_process_match_options_set_timeout*(self: ptr FridaProcessMatchOptions, value: int32)
proc frida_process_match_options_set_scope*(self: ptr FridaProcessMatchOptions, value: FridaScope)

##  SpawnOptions
proc frida_spawn_options_new*(): ptr FridaSpawnOptions
proc frida_spawn_options_get_argv*(self: ptr FridaSpawnOptions, result_length: ptr int32): ptr cstring
proc frida_spawn_options_get_envp*(self: ptr FridaSpawnOptions, result_length: ptr int32): ptr cstring
proc frida_spawn_options_get_env*(self: ptr FridaSpawnOptions, result_length: ptr int32): ptr cstring
proc frida_spawn_options_get_cwd*(self: ptr FridaSpawnOptions): cstring
proc frida_spawn_options_get_stdio*(self: ptr FridaSpawnOptions): FridaStdio
proc frida_spawn_options_get_aux*(self: ptr FridaSpawnOptions): ptr GHashTable
proc frida_spawn_options_set_argv*(self: ptr FridaSpawnOptions, value: ptr cstring, value_length: int32)
proc frida_spawn_options_set_envp*(self: ptr FridaSpawnOptions, value: ptr cstring, value_length: int32)
proc frida_spawn_options_set_env*(self: ptr FridaSpawnOptions, value: ptr cstring, value_length: int32)
proc frida_spawn_options_set_cwd*(self: ptr FridaSpawnOptions, value: cstring)
proc frida_spawn_options_set_stdio*(self: ptr FridaSpawnOptions, value: FridaStdio)
proc frida_spawn_options_set_aux*(self: ptr FridaSpawnOptions, value: ptr GHashTable)

##  FrontmostQueryOptions
proc frida_frontmost_query_options_new*(): ptr FridaFrontmostQueryOptions
proc frida_frontmost_query_options_get_scope*(
    self: ptr FridaFrontmostQueryOptions): FridaScope
proc frida_frontmost_query_options_set_scope*(
    self: ptr FridaFrontmostQueryOptions, value: FridaScope)

##  ApplicationQueryOptions
proc frida_application_query_options_new*(): ptr FridaApplicationQueryOptions
proc frida_application_query_options_get_scope*(
    self: ptr FridaApplicationQueryOptions): FridaScope
proc frida_application_query_options_select_identifier*(
    self: ptr FridaApplicationQueryOptions, identifier: cstring)
proc frida_application_query_options_has_selected_identifiers*(
    self: ptr FridaApplicationQueryOptions): bool
proc frida_application_query_options_enumerate_selected_identifiers*(
    self: ptr FridaApplicationQueryOptions, fn: GFunc, user_data: pointer)
proc frida_application_query_options_set_scope*(
    self: ptr FridaApplicationQueryOptions, value: FridaScope)

##  ProcessQueryOptions
proc frida_process_query_options_new*(): ptr FridaProcessQueryOptions
proc frida_process_query_options_get_scope*(self: ptr FridaProcessQueryOptions): FridaScope
proc frida_process_query_options_select_pid*(self: ptr FridaProcessQueryOptions, pid: uint32)
proc frida_process_query_options_has_selected_pids*(
    self: ptr FridaProcessQueryOptions): bool
proc frida_process_query_options_enumerate_selected_pids*(
    self: ptr FridaProcessQueryOptions, fn: GFunc, user_data: pointer)
proc frida_process_query_options_set_scope*(self: ptr FridaProcessQueryOptions, value: FridaScope)

##  SessionOptions
proc frida_session_options_new*(): ptr FridaSessionOptions
proc frida_session_options_get_realm*(self: ptr FridaSessionOptions): FridaRealm
proc frida_session_options_get_persist_timeout*(self: ptr FridaSessionOptions): uint32
proc frida_session_options_set_realm*(self: ptr FridaSessionOptions, value: FridaRealm)
proc frida_session_options_set_persist_timeout*(self: ptr FridaSessionOptions, value: uint32)

##  SpawnList
proc frida_spawn_list_size*(self: ptr FridaSpawnList): int32
proc frida_spawn_list_get*(self: ptr FridaSpawnList, index: int32): ptr FridaSpawn

##  Spawn
proc frida_spawn_get_pid*(self: ptr FridaSpawn): uint32
proc frida_spawn_get_identifier*(self: ptr FridaSpawn): cstring

##  ChildList
proc frida_child_list_size*(self: ptr FridaChildList): int32
proc frida_child_list_get*(self: ptr FridaChildList, index: int32): ptr FridaChild

##  Child
proc frida_child_get_pid*(self: ptr FridaChild): uint32
proc frida_child_get_parent_pid*(self: ptr FridaChild): uint32
proc frida_child_get_origin*(self: ptr FridaChild): FridaChildOrigin
proc frida_child_get_identifier*(self: ptr FridaChild): cstring
proc frida_child_get_path*(self: ptr FridaChild): cstring
proc frida_child_get_argv*(self: ptr FridaChild, result_length: ptr int32): ptr cstring
proc frida_child_get_envp*(self: ptr FridaChild, result_length: ptr int32): ptr cstring

##  Crash
proc frida_crash_get_pid*(self: ptr FridaCrash): uint32
proc frida_crash_get_process_name*(self: ptr FridaCrash): cstring
proc frida_crash_get_summary*(self: ptr FridaCrash): cstring
proc frida_crash_get_report*(self: ptr FridaCrash): cstring
proc frida_crash_get_parameters*(self: ptr FridaCrash): ptr GHashTable
##  Bus

proc frida_bus_get_device*(self: ptr FridaBus): ptr FridaDevice
proc frida_bus_is_detached*(self: ptr FridaBus): bool
proc frida_bus_attach*(self: ptr FridaBus, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_bus_attach_finish*(self: ptr FridaBus, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_bus_attach_sync*(self: ptr FridaBus, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_bus_post*(self: ptr FridaBus, json: cstring, data: ptr GBytes)
##  Session

proc frida_session_get_pid*(self: ptr FridaSession): uint32
proc frida_session_get_persist_timeout*(self: ptr FridaSession): uint32
proc frida_session_get_device*(self: ptr FridaSession): ptr FridaDevice
proc frida_session_is_detached*(self: ptr FridaSession): bool
proc frida_session_detach*(self: ptr FridaSession, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_session_detach_finish*(self: ptr FridaSession, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_session_detach_sync*(self: ptr FridaSession, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_session_resume*(self: ptr FridaSession, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_session_resume_finish*(self: ptr FridaSession, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_session_resume_sync*(self: ptr FridaSession, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_session_enable_child_gating*(self: ptr FridaSession, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_session_enable_child_gating_finish*(self: ptr FridaSession, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_session_enable_child_gating_sync*(self: ptr FridaSession, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_session_disable_child_gating*(self: ptr FridaSession, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_session_disable_child_gating_finish*(self: ptr FridaSession, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_session_disable_child_gating_sync*(self: ptr FridaSession, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_session_create_script*(self: ptr FridaSession, source: cstring, options: ptr FridaScriptOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_session_create_script_finish*(self: ptr FridaSession, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaScript
proc frida_session_create_script_sync*(self: ptr FridaSession, source: cstring, options: ptr FridaScriptOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaScript
proc frida_session_create_script_from_bytes*(self: ptr FridaSession, bytes: ptr GBytes, options: ptr FridaScriptOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_session_create_script_from_bytes_finish*(self: ptr FridaSession, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaScript
proc frida_session_create_script_from_bytes_sync*(self: ptr FridaSession, bytes: ptr GBytes, options: ptr FridaScriptOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaScript
proc frida_session_compile_script*(self: ptr FridaSession, source: cstring, options: ptr FridaScriptOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_session_compile_script_finish*(self: ptr FridaSession, result: ptr GAsyncResult, error: ptr ptr GError): ptr GBytes
proc frida_session_compile_script_sync*(self: ptr FridaSession, source: cstring, options: ptr FridaScriptOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr GBytes
proc frida_session_enable_debugger*(self: ptr FridaSession, port: uint16, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_session_enable_debugger_finish*(self: ptr FridaSession, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_session_enable_debugger_sync*(self: ptr FridaSession, port: uint16, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_session_disable_debugger*(self: ptr FridaSession, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_session_disable_debugger_finish*(self: ptr FridaSession, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_session_disable_debugger_sync*(self: ptr FridaSession, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_session_setup_peer_connection*(self: ptr FridaSession, options: ptr FridaPeerOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_session_setup_peer_connection_finish*(self: ptr FridaSession, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_session_setup_peer_connection_sync*(self: ptr FridaSession, options: ptr FridaPeerOptions, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_session_join_portal*(self: ptr FridaSession, address: cstring, options: ptr FridaPortalOptions, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_session_join_portal_finish*(self: ptr FridaSession, result: ptr GAsyncResult, error: ptr ptr GError): ptr FridaPortalMembership
proc frida_session_join_portal_sync*(self: ptr FridaSession, address: cstring, options: ptr FridaPortalOptions, cancellable: ptr GCancellable, error: ptr ptr GError): ptr FridaPortalMembership
##  Script

proc frida_script_is_destroyed*(self: ptr FridaScript): bool
proc frida_script_load*(self: ptr FridaScript, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_script_load_finish*(self: ptr FridaScript, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_script_load_sync*(self: ptr FridaScript, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_script_unload*(self: ptr FridaScript, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_script_unload_finish*(self: ptr FridaScript, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_script_unload_sync*(self: ptr FridaScript, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_script_eternalize*(self: ptr FridaScript, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_script_eternalize_finish*(self: ptr FridaScript, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_script_eternalize_sync*(self: ptr FridaScript, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_script_post*(self: ptr FridaScript, json: cstring, data: ptr GBytes)
##  ScriptOptions

proc frida_script_options_new*(): ptr FridaScriptOptions
proc frida_script_options_get_name*(self: ptr FridaScriptOptions): cstring
proc frida_script_options_get_runtime*(self: ptr FridaScriptOptions): FridaScriptRuntime
proc frida_script_options_set_name*(self: ptr FridaScriptOptions, value: cstring)
proc frida_script_options_set_runtime*(self: ptr FridaScriptOptions, value: FridaScriptRuntime)
##  PeerOptions

proc frida_peer_options_new*(): ptr FridaPeerOptions
proc frida_peer_options_get_stun_server*(self: ptr FridaPeerOptions): cstring
proc frida_peer_options_clear_relays*(self: ptr FridaPeerOptions)
proc frida_peer_options_add_relay*(self: ptr FridaPeerOptions, relay: ptr FridaRelay)
proc frida_peer_options_enumerate_relays*(self: ptr FridaPeerOptions, fn: GFunc, user_data: pointer)
proc frida_peer_options_set_stun_server*(self: ptr FridaPeerOptions, value: cstring)
##  Relay

proc frida_relay_new*(address: cstring, username: cstring, password: cstring, kind: FridaRelayKind): ptr FridaRelay
proc frida_relay_get_address*(self: ptr FridaRelay): cstring
proc frida_relay_get_username*(self: ptr FridaRelay): cstring
proc frida_relay_get_password*(self: ptr FridaRelay): cstring
proc frida_relay_get_kind*(self: ptr FridaRelay): FridaRelayKind
##  PortalOptions

proc frida_portal_options_new*(): ptr FridaPortalOptions
proc frida_portal_options_get_certificate*(self: ptr FridaPortalOptions): ptr GTlsCertificate
proc frida_portal_options_get_token*(self: ptr FridaPortalOptions): cstring
proc frida_portal_options_get_acl*(self: ptr FridaPortalOptions, result_length: ptr int32): ptr cstring
proc frida_portal_options_set_certificate*(self: ptr FridaPortalOptions, value: ptr GTlsCertificate)
proc frida_portal_options_set_token*(self: ptr FridaPortalOptions, value: cstring)
proc frida_portal_options_set_acl*(self: ptr FridaPortalOptions, value: ptr cstring, value_length: int32)
##  PortalMembership

proc frida_portal_membership_get_id*(self: ptr FridaPortalMembership): uint32
proc frida_portal_membership_terminate*(self: ptr FridaPortalMembership, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_portal_membership_terminate_finish*(self: ptr FridaPortalMembership, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_portal_membership_terminate_sync*(self: ptr FridaPortalMembership, cancellable: ptr GCancellable, error: ptr ptr GError)
##  RpcClient

proc frida_rpc_client_new*(peer: ptr FridaRpcPeer): ptr FridaRpcClient
proc frida_rpc_client_get_peer*(self: ptr FridaRpcClient): ptr FridaRpcPeer
proc frida_rpc_client_call*(self: ptr FridaRpcClient, `method`: cstring, args: ptr ptr GJsonNode, args_length: int32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_rpc_client_call_finish*(self: ptr FridaRpcClient, result: ptr GAsyncResult, error: ptr ptr GError): ptr GJsonNode
proc frida_rpc_client_try_handle_message*(self: ptr FridaRpcClient, json: cstring): bool
##  RpcPeer

type
  FridaRpcPeerIface* {.bycopy.} = object
    parent_iface*: GTypeInterface
    post_rpc_message*: proc (self: ptr FridaRpcPeer, json: cstring, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
    post_rpc_message_finish*: proc (self: ptr FridaRpcPeer, result: ptr GAsyncResult, error: ptr ptr GError)


proc frida_rpc_peer_post_rpc_message*(self: ptr FridaRpcPeer, json: cstring, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_rpc_peer_post_rpc_message_finish*(self: ptr FridaRpcPeer, result: ptr GAsyncResult, error: ptr ptr GError)
##  Injector

proc frida_injector_new*(): ptr FridaInjector
proc frida_injector_new_inprocess*(): ptr FridaInjector
proc frida_injector_close*(self: ptr FridaInjector, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_injector_close_finish*(self: ptr FridaInjector, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_injector_close_sync*(self: ptr FridaInjector, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_injector_inject_library_file*(self: ptr FridaInjector, pid: uint32, path: cstring, entrypoint: cstring, data: cstring, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_injector_inject_library_file_finish*(self: ptr FridaInjector, result: ptr GAsyncResult, error: ptr ptr GError): uint32
proc frida_injector_inject_library_file_sync*(self: ptr FridaInjector, pid: uint32, path: cstring, entrypoint: cstring, data: cstring, cancellable: ptr GCancellable, error: ptr ptr GError): uint32
proc frida_injector_inject_library_blob*(self: ptr FridaInjector, pid: uint32, blob: ptr GBytes, entrypoint: cstring, data: cstring, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_injector_inject_library_blob_finish*(self: ptr FridaInjector, result: ptr GAsyncResult, error: ptr ptr GError): uint32
proc frida_injector_inject_library_blob_sync*(self: ptr FridaInjector, pid: uint32, blob: ptr GBytes, entrypoint: cstring, data: cstring, cancellable: ptr GCancellable, error: ptr ptr GError): uint32
proc frida_injector_demonitor*(self: ptr FridaInjector, id: uint32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_injector_demonitor_finish*(self: ptr FridaInjector, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_injector_demonitor_sync*(self: ptr FridaInjector, id: uint32, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_injector_demonitor_and_clone_state*(self: ptr FridaInjector, id: uint32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_injector_demonitor_and_clone_state_finish*(self: ptr FridaInjector, result: ptr GAsyncResult, error: ptr ptr GError): uint32
proc frida_injector_demonitor_and_clone_state_sync*(self: ptr FridaInjector, id: uint32, cancellable: ptr GCancellable, error: ptr ptr GError): uint32
proc frida_injector_recreate_thread*(self: ptr FridaInjector, pid: uint32, id: uint32, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_injector_recreate_thread_finish*(self: ptr FridaInjector, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_injector_recreate_thread_sync*(self: ptr FridaInjector, pid: uint32, id: uint32, cancellable: ptr GCancellable, error: ptr ptr GError)
##  ControlService

proc frida_control_service_new*(endpoint_params: ptr FridaEndpointParameters, options: ptr FridaControlServiceOptions): ptr FridaControlService
proc frida_control_service_new_with_host_session*(
    host_session: ptr FridaHostSession, endpoint_params: ptr FridaEndpointParameters, options: ptr FridaControlServiceOptions): ptr FridaControlService
proc frida_control_service_get_host_session*(self: ptr FridaControlService): ptr FridaHostSession
proc frida_control_service_get_endpoint_params*(self: ptr FridaControlService): ptr FridaEndpointParameters
proc frida_control_service_get_options*(self: ptr FridaControlService): ptr FridaControlServiceOptions
proc frida_control_service_start*(self: ptr FridaControlService, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_control_service_start_finish*(self: ptr FridaControlService, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_control_service_start_sync*(self: ptr FridaControlService, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_control_service_stop*(self: ptr FridaControlService, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_control_service_stop_finish*(self: ptr FridaControlService, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_control_service_stop_sync*(self: ptr FridaControlService, cancellable: ptr GCancellable, error: ptr ptr GError)
##  ControlServiceOptions

proc frida_control_service_options_new*(): ptr FridaControlServiceOptions
proc frida_control_service_options_get_enable_preload*(
    self: ptr FridaControlServiceOptions): bool
proc frida_control_service_options_get_report_crashes*(
    self: ptr FridaControlServiceOptions): bool
proc frida_control_service_options_set_enable_preload*(
    self: ptr FridaControlServiceOptions, value: bool)
proc frida_control_service_options_set_report_crashes*(
    self: ptr FridaControlServiceOptions, value: bool)
##  PortalService

proc frida_portal_service_new*(cluster_params: ptr FridaEndpointParameters, control_params: ptr FridaEndpointParameters): ptr FridaPortalService
proc frida_portal_service_get_device*(self: ptr FridaPortalService): ptr FridaDevice
proc frida_portal_service_get_cluster_params*(self: ptr FridaPortalService): ptr FridaEndpointParameters
proc frida_portal_service_get_control_params*(self: ptr FridaPortalService): ptr FridaEndpointParameters
proc frida_portal_service_start*(self: ptr FridaPortalService, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_portal_service_start_finish*(self: ptr FridaPortalService, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_portal_service_start_sync*(self: ptr FridaPortalService, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_portal_service_stop*(self: ptr FridaPortalService, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_portal_service_stop_finish*(self: ptr FridaPortalService, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_portal_service_stop_sync*(self: ptr FridaPortalService, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_portal_service_kick*(self: ptr FridaPortalService, connection_id: uint32)
proc frida_portal_service_post*(self: ptr FridaPortalService, connection_id: uint32, json: cstring, data: ptr GBytes)
proc frida_portal_service_narrowcast*(self: ptr FridaPortalService, tag: cstring, json: cstring, data: ptr GBytes)
proc frida_portal_service_broadcast*(self: ptr FridaPortalService, json: cstring, data: ptr GBytes)
proc frida_portal_service_enumerate_tags*(self: ptr FridaPortalService, connection_id: uint32, result_length: ptr int32): ptr cstring
proc frida_portal_service_tag*(self: ptr FridaPortalService, connection_id: uint32, tag: cstring)
proc frida_portal_service_untag*(self: ptr FridaPortalService, connection_id: uint32, tag: cstring)

##  EndpointParameters
proc frida_endpoint_parameters_new*(address: cstring, port: uint16, certificate: ptr GTlsCertificate, origin: cstring, auth_service: ptr FridaAuthenticationService, asset_root: ptr GFile): ptr FridaEndpointParameters
proc frida_endpoint_parameters_get_address*(self: ptr FridaEndpointParameters): cstring
proc frida_endpoint_parameters_get_port*(self: ptr FridaEndpointParameters): uint16
proc frida_endpoint_parameters_get_certificate*(self: ptr FridaEndpointParameters): ptr GTlsCertificate
proc frida_endpoint_parameters_get_origin*(self: ptr FridaEndpointParameters): cstring
proc frida_endpoint_parameters_get_auth_service*(self: ptr FridaEndpointParameters): ptr FridaAuthenticationService
proc frida_endpoint_parameters_get_asset_root*(self: ptr FridaEndpointParameters): ptr GFile
proc frida_endpoint_parameters_set_asset_root*(self: ptr FridaEndpointParameters, value: ptr GFile)

##  AuthenticationService
type
  FridaAuthenticationServiceIface* {.bycopy.} = object
    parent_iface*: GTypeInterface
    authenticate*: proc (self: ptr FridaAuthenticationService, token: cstring, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
    authenticate_finish*: proc (self: ptr FridaAuthenticationService, result: ptr GAsyncResult, error: ptr ptr GError): cstring

proc frida_authentication_service_authenticate*(self: ptr FridaAuthenticationService, token: cstring, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_authentication_service_authenticate_finish*( self: ptr FridaAuthenticationService, result: ptr GAsyncResult, error: ptr ptr GError): cstring

##  StaticAuthenticationService
proc frida_static_authentication_service_new*(token: cstring): ptr FridaStaticAuthenticationService
proc frida_static_authentication_service_get_token_hash*(self: ptr FridaStaticAuthenticationService): cstring

##  FileMonitor
proc frida_file_monitor_new*(path: cstring): ptr FridaFileMonitor
proc frida_file_monitor_get_path*(self: ptr FridaFileMonitor): cstring
proc frida_file_monitor_enable*(self: ptr FridaFileMonitor, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_file_monitor_enable_finish*(self: ptr FridaFileMonitor, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_file_monitor_enable_sync*(self: ptr FridaFileMonitor, cancellable: ptr GCancellable, error: ptr ptr GError)
proc frida_file_monitor_disable*(self: ptr FridaFileMonitor, cancellable: ptr GCancellable, callback: GAsyncReadyCallback, user_data: pointer)
proc frida_file_monitor_disable_finish*(self: ptr FridaFileMonitor, result: ptr GAsyncResult, error: ptr ptr GError)
proc frida_file_monitor_disable_sync*(self: ptr FridaFileMonitor, cancellable: ptr GCancellable, error: ptr ptr GError)

##  Errors
proc frida_error_quark*(): GQuark
type
  FridaError* = enum
    FRIDA_ERROR_SERVER_NOT_RUNNING,
    FRIDA_ERROR_EXECUTABLE_NOT_FOUND,
    FRIDA_ERROR_EXECUTABLE_NOT_SUPPORTED,
    FRIDA_ERROR_PROCESS_NOT_FOUND,
    FRIDA_ERROR_PROCESS_NOT_RESPONDING,
    FRIDA_ERROR_INVALID_ARGUMENT,
    FRIDA_ERROR_INVALID_OPERATION,
    FRIDA_ERROR_PERMISSION_DENIED,
    FRIDA_ERROR_ADDRESS_IN_USE,
    FRIDA_ERROR_TIMED_OUT,
    FRIDA_ERROR_NOT_SUPPORTED,
    FRIDA_ERROR_PROTOCOL,
    FRIDA_ERROR_TRANSPORT

{.pop.}