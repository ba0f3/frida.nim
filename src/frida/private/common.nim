type
  GQuark* = uint32

  GError* = object
    domain*: GQuark
    code*: int32
    message*: cstring

  GType* = uint32
  GBytes* = object
  GArray* = object
    data*: ptr char
    len*: uint32
  GByteArray* = object
    data*: ptr uint8
    len*: uint32
  GPtrArray* = object
    pdata*: pointer
    len*: uint32

  GTypeClass* = object
    g_type*: GType

  GTypeInstance* = object
    g_class*: GTypeClass

  GObject* = object
    g_type_instance*: GTypeInstance
    ref_count*: uint32
    qdata*: pointer

  GValueData* {.union} = object
    v_int*: int32
    v_uint*: uint32
    v_long*: int32
    v_ulong: uint32
    v_int64*: int64
    v_uint64*: uint64
    v_float*: float32
    v_double*: float64
    v_pointer*: pointer

  GValue* = object
    g_type: GType
    data: array[2, GValueData]

  GCompareFunc* = proc(a, b: pointer): int32
  GCompareDataFunc* = proc(a, b, user_data: pointer): int32
  GEqualFunc* = proc(a, b: pointer): int32
  GDestroyNotify* = proc(data: pointer)
  GFunc* = proc(data, user_data: pointer)
  GHashFunc* = proc(key: pointer): uint32
  GHFunc* = proc(key, value, user_data: pointer)


  GJsonNode* = object
  GJsonObject* = object
  GJsonArray* = object

  GJsonNodeType* = enum
    JSON_NODE_OBJECT, JSON_NODE_ARRAY, JSON_NODE_VALUE, JSON_NODE_NULL

  GErrorInitFunc* = proc(error: ptr GError)
  GErrorCopyFunc* = proc(src_error: ptr GError, dest_error: ptr GError)
  GErrorClearFunc* = proc(error: ptr GError)

  GMenuModel* = object
  GNotification* = object

  GDrive* = object
  GFileEnumerator* = object
  GFileMonitor* = object
  GFilterInputStream* = object
  GFilterOutputStream* = object

  GFile* = object
  GFileInfo* = object

  GUserDirectory* = enum
    G_USER_DIRECTORY_DESKTOP,
    G_USER_DIRECTORY_DOCUMENTS,
    G_USER_DIRECTORY_DOWNLOAD,
    G_USER_DIRECTORY_MUSIC,
    G_USER_DIRECTORY_PICTURES,
    G_USER_DIRECTORY_PUBLIC_SHARE,
    G_USER_DIRECTORY_TEMPLATES,
    G_USER_DIRECTORY_VIDEOS,
    G_USER_N_DIRECTORIES

  GDebugKey* = object
    key*: cstring
    value*: uint32

  GFormatSizeFlags* = enum
    G_FORMAT_SIZE_DEFAULT     = 0,
    G_FORMAT_SIZE_LONG_FORMAT = 1 shl 0,
    G_FORMAT_SIZE_IEC_UNITS   = 1 shl 1,
    G_FORMAT_SIZE_BITS        = 1 shl 2

  GThreadError* = enum
    G_THREAD_ERROR_AGAIN

  GThreadCallbacks* = object
    on_thread_init*: proc()
    on_thread_realize*: proc()
    on_thread_dispose*: proc()
    on_thread_finalize*: proc()

  GThread* = object

  GMutex* = object
    p*: pointer
    i*: array[2, uint32]

  GRecMutex* = object
    p*: pointer
    i*: array[2, uint32]

  GRWLock* = object
    p*: pointer
    i*: array[2, uint32]

  GCond* = object
    p*: pointer
    i*: array[2, uint32]
  GPrivate* = object

  GOnceStatus* = enum
    G_ONCE_STATUS_NOTCALLED,
    G_ONCE_STATUS_PROGRESS,
    G_ONCE_STATUS_READY

  GOnce* = object
    status*: GOnceStatus
    retval*: pointer

  GPrivateFlags* = enum
    G_PRIVATE_DESTROY_LATE = 1 shl 0,
    G_PRIVATE_DESTROY_LAST = 1 shl 1,

  GTimeZone* = object

  GTimeSpan* = uint64
  GDateTime* = object

  GMainContext* = object
  GMainLoop* = object
  GSource* = object
  GSourcePrivate* = object
  GSourceCallbackFuncs* = object
  GSourceFuncs* = object
