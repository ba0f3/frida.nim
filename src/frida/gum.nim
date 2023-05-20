#when not compileOption("threads"):
#  {.error: "Frida gumjs library require --threads:on to run".}
{.experimental: "codeReordering".}
{.passL: "-lfrida-gumjs -latomic -lresolv".}

import ./private/common
export common


const
  GUM_MAX_PATH = 260
  GUM_MAX_TYPE_NAME = 16
  GUM_MAX_SYMBOL_NAME = 2048

  GUM_MAX_THREADS = 768
  GUM_MAX_CALL_DEPTH = 32
  GUM_MAX_BACKTRACE_DEPTH = 16

type
  #[ gumdef.h ]#
  GumCpuContext* = object
  GumAddress* = uint64
  GumMemoryRange* = object
    baseAddress*: GumAddress
    size*: csize_t
  GumCpuType* = enum
    GUM_CPU_INVALID
    GUM_CPU_IA32
    GUM_CPU_AMD64
    GUM_CPU_ARM
    GUM_CPU_ARM64
    GUM_CPU_MIPS

  #[ gumapiresolver.h ]#
  GumApiResolver* = object
  GumApiDetails* = object
    name*: cstring
    address*: GumAddress
  GumFoundApiFunc* = proc(details: ptr GumApiDetails, userData: pointer): bool

  #[ gumbacktracer.h ]#
  GumBacktracer* = object

  #[ gumcloak.h ]#
  GumCloak* = object
  GumCloakFoundThreadFunc* = proc(id: GumThreadId, userData: pointer): bool
  GumCloakFoundRangeFunc* = proc(memRange: ptr GumMemoryRange, userData: pointer): bool
  GumCloakFoundFDFunc* = proc(fd: int, userData: pointer): bool

  #[ gumcodeallocator.h ]#
  GumCodeAllocator* = object
  GumCodeSlice* = object
  GUmCodeDeflector* = object

  #[ gumcodesegment.h ]#
  GumCodeSegment* = object

  #[ gumdarwingrather.h ]#
  GumDarwinGrafterFlags* = enum
    GUM_DARWIN_GRAFTER_FLAGS_NONE                   = 0
    GUM_DARWIN_GRAFTER_FLAGS_INGEST_FUNCTION_STARTS = (1 shl 0)
    GUM_DARWIN_GRAFTER_FLAGS_INGEST_IMPORTS         = (1 shl 1)
    GUM_DARWIN_GRAFTER_FLAGS_TRANSFORM_LAZY_BINDS   = (1 shl 2)
  GumDarwinGrafter* = object

  #[ gumdarwinmodule.h ]#
  GumDarwinModule* = object
  GumDarwinModuleFiletype* = uint
  GumDarwinCpuType* = int
  GumDarwinCpuSubtype* = int

  GumDarwinModuleImage* = object
  GumDarwinModuleImageSegment* = object
  GumDarwinSectionDetails* = object
  GumDarwinChainedFixupsDetails* = object
  GumDarwinRebaseDetails* = object
  GumDarwinBindDetails* = object
  GumDarwinThreadedItem* = object
  GumDarwinInitPointersDetails* = object
  GumDarwinInitOffsetsDetails* = object
  GumDarwinTermPointersDetails* = object
  GumDarwinFunctionStartsDetails* = object
  GumDarwinSegment* = object
  GumDarwinExportDetails* = object
  GumDarwinSymbolDetails* = object
  GumDarwinRebaseType* = uint8
  GumDarwinBindType* = uint8
  GumDarwinThreadedItemType* = uint8
  GumDarwinBindOrdinal* = int
  GumDarwinBindSymbolFlags* = uint8
  GumDarwinExportSymbolKind* = uint8
  GumDarwinExportSymbolFlags* = uint8

  GumDarwinPort* = uint
  GumDarwinPageProtection* = int

  GumFoundDarwinExportFunc* = proc(details: ptr GumDarwinExportDetails, userData: pointer): bool
  GumFoundDarwinSymbolFunc* = proc(details: ptr GumDarwinSymbolDetails, userData: pointer): bool
  GumFoundDarwinSectionFunc* = proc(details: ptr GumDarwinSectionDetails, userData: pointer): bool
  GumFoundDarwinChainedFixupsFunc* = proc(details: ptr GumDarwinChainedFixupsDetails, userData: pointer): bool
  GumFoundDarwinRebaseFunc* = proc(details: ptr GumDarwinRebaseDetails, userData: pointer): bool
  GumFoundDarwinBindFunc* = proc(details: ptr GumDarwinBindDetails, userData: pointer): bool
  GumFoundDarwinInitPointersFunc* = proc(details: ptr GumDarwinInitPointersDetails, userData: pointer): bool
  GumFoundDarwinInitOffsetsFunc* = proc(details: ptr GumDarwinInitOffsetsDetails, userData: pointer): bool
  GumFoundDarwinTermPointersFunc* = proc(details: ptr GumDarwinTermPointersDetails, userData: pointer): bool
  GumFoundDarwinDependencyFunc* = proc(path: cstring, userData: pointer): bool
  GumFoundDarwinFunctionStartsFunc* = proc(details: ptr GumDarwinFunctionStartsDetails, userData: pointer): bool

  GumDyldInfoCommand* = object
  GumSymtabCommand* = object
  GumDysymtabCommand* = object

  GumDarwinModuleFlags* = enum
    GUM_DARWIN_MODULE_FLAGS_NONE = 0
    GUM_DARWIN_MODULE_FLAGS_HEADER_ONLY = (1 shl 0)

  GumChainedFixupsHeader* = object
  GumChainedStartsInImage* = object
  GumChainedStartsInSegment* = object

  GumChainedImportFormat* = uint32
  GumChainedSymbolFormat* = uint32
  GumChainedPtrFormat* = uint16

  GumChainedImport* = object
  GumChainedImportAddend* = object
  GumChainedImportAddend64* = object

  GumChainedPtr64Rebase* = object
  GumChainedPtr64Bind* = object
  GumChainedPtrArm64eRebase* = object
  GumChainedPtrArm64eBind* = object
  GumChainedPtrArm64eBind24* = object
  GumChainedPtrArm64eAuthRebase* = object
  GumChainedPtrArm64eAuthBind* = object
  GumChainedPtrArm64eAuthBind24* = object

  #[ gumevent.h]#
  GumEventType* = enum
    GUM_NOTHING     = 0
    GUM_CALL        = (1 shl 0)
    GUM_RET         = (1 shl 1)
    GUM_EXEC        = (1 shl 2)
    GUM_BLOCK       = (1 shl 3)
    GUM_COMPILE     = (1 shl 4)
  GumEvent* = object
    kind*: GumEventType
  GumCallEvent* = object
  GumRetEvent* = object
  GumExecEvent* = object
  GumBlockEvent* = object
  GumCompileEvent* = object

  #[ gumeventsink.h]#
  GumEventSink* = object
  GumDefaultEventSink* = object
  GumCallbackEventSink* = object

  GumEventSinkCallback* = proc(event: ptr GumEvent, cpuContext: ptr GumCpuContext, userData: pointer)

  #[ gumexceptor.h ]#
  GumExceptor* = object
  GumExceptionDetails* = object
  GumExceptionMemoryDetails* = object
  GumExceptionHandler* = proc(details: ptr GumExceptionDetails, userData: pointer): bool

  GumExceptorScope* = object

  #[ gumfunction.h ]#
  GumFunctionDetails* = object

  #[ gumheapapi.h ]#
  GumHeapApi* = object
  GumHeapApiList* = GArray
  GumMallocFunc* = proc(size: csize_t): pointer
  GumCallocFunc* = proc(num: csize_t, size: csize_t): pointer
  GumReallocFunc* = proc(oldAddress: pointer, newSize: csize_t): pointer
  GumFreeFunc* = proc(address: pointer)
  GumMallocDbgFunc* = proc(size: csize_t, blockType: int, filename: cstring, linenumber: int): pointer
  GumCallocDbgFunc* = proc(num: csize_t, size: csize_t, blockType: int, filename: cstring, linenumber: int): pointer
  GumReallocDbgFunc* = proc(oldAddress: pointer, newSize: csize_t, blockType: int, filename: cstring, linenumber: int): pointer
  GumFreeDbgFunc* = proc(address: pointer, blockType: int)
  GumCrtReportBlockTypeFunc* = proc(blck: pointer): int

  #[ guminterceptor.c ]#
  GumInterceptor* = object
  GumInvocationStack* = GArray
  GumInvocationState* = uint

  GumAttachReturn* = enum
    GUM_ATTACH_WRONG_TYPE       = -4
    GUM_ATTACH_POLICY_VIOLATION = -3
    GUM_ATTACH_ALREADY_ATTACHED = -2
    GUM_ATTACH_WRONG_SIGNATURE  = -1
    GUM_ATTACH_OK               =  0

  GumReplaceReturn* = enum
    GUM_REPLACE_WRONG_TYPE       = -4
    GUM_REPLACE_POLICY_VIOLATION = -3
    GUM_REPLACE_ALREADY_REPLACED = -2
    GUM_REPLACE_WRONG_SIGNATURE  = -1
    GUM_REPLACE_OK               =  0

  #[ guminvocationcontext.h ]#
  GumInvocationBackend* = object
  GumInvocationContext* = object

  GumPointCut* = enum
    GUM_POINT_ENTER
    GUM_POINT_LEAVE

  #[ guminvocationlistener.h ]#
  GumInvocationListener* = object

  GumInvocationCallback* = proc(context: ptr GumInvocationContext, userData: pointer)

  #[ gumkernel.h ]#
  GumKernelModuleRangeDetails* = object

  GumFoundKernelModuleRangeFunc* = proc(details: ptr GumKernelModuleRangeDetails, userData: pointer): bool

  #[ gummemory.h ]#
  GumPtrauthSupport* = uint
  GumRwxSupport
  GumMemoryOperation

  GumAddressSpec* = object
  GumMatchPattern* = object
  GumMemoryRange* = object

  GumMemoryIsNearFunc* = proc(memory: pointer, address: pointer): bool

  GumMemoryPatchApplyFunc* = proc(mem: pointer, userData: pointer)
  GumMemoryScanMatchFunc* = proc(address: GumAddress, size: csize_t): bool

  GumPageProtection* = enum
    GUM_PAGE_NO_ACCESS = 0
    GUM_PAGE_READ      = (1 shl 0)
    GUM_PAGE_WRITE     = (1 shl 1)
    GUM_PAGE_EXECUTE   = (1 shl 2)

  #[ gumprocess.h ]#
  GumThreadId* = csize_t
  GumResolveSymbolContext* = object
  GumThreadDetails* = object
  GumModuleDetails* = object
  GumImportType* = uint
  GumExportType* = uint
  GumSymbolTyp* = uint
  GumImportDetails* = object
  GumExportDetails* = object
  GumSymbolDetails* = object
  GumSymbolSection* = object
  GumRangeDetails* = object
  GumFileMapping* = object
  GumMallocRangeDetails* = object

  GumCodeSigningPolicy* = enum
    GUM_CODE_SIGNING_OPTIONAL
    GUM_CODE_SIGNING_REQUIRED

  GumThreadState* = enum
    GUM_THREAD_RUNNING = 1
    GUM_THREAD_STOPPED
    GUM_THREAD_WAITING
    GUM_THREAD_UNINTERRUPTIBLE
    GUM_THREAD_HALTED

  GumModifyThreadFunc* = proc(tjreadId: GumThreadId, cpuContext: ptr GumCpuContext, userData: pointer)
  GumFoundThreadFunc* = proc(details: ptr GumThreadDetails, userData: pointer): bool
  GumFoundModuleFunc* = proc(details: ptr GumModuleDetails, userData: pointer): bool
  GumFoundImportFunc* = proc(details: ptr GumImportDetails, userData: pointer): bool
  GumFoundExportFunc* = proc(details: ptr GumExportDetails, userData: pointer): bool
  GumFoundSymbolFunc* = proc(details: ptr GumSymbolDetails, userData: pointer): bool
  GumFoundRangeFunc* = proc(details: ptr GumRangeDetails, userData: pointer): bool
  GumFoundMallocRangeFunc* = proc(details: ptr GumMallocRangeDetails, userData: pointer): bool
  GumResolveExportFunc* = proc(moduleName: cstring, symbolName: cstring, userData: pointer): GumAddress


  #[ gumreturnaddress.h ]#
  GumReturnAddress* = pointer
  GumReturnAddressArray* = object
    len*: uint
    items*: array[GUM_MAX_BACKTRACE_DEPTH, GumReturnAddress]
  GumReturnAddressDetails* = object
    address*: GumReturnAddress
    moduleName*: array[GUM_MAX_PATH + 1, char]
    functioName*: array[GUM_MAX_SYMBOL_NAME + 1, char]
    fileName*: array[GUM_MAX_PATH + 1, char]
    limeNumber*: uint
    column*: uint

{.push importc: "$1", cdecl, discardable.}

#[ gum.h ]#
proc gum_init*()
proc gum_shutdown*()
proc gum_deinit*()

proc gum_init_embedded*()
proc gum_deinit_embedded*()

proc gum_prepare_to_fork*()
proc gum_recover_from_fork_in_parent*()
proc gum_recover_from_fork_in_child*()

#[ gumapiresolver.h ]#
proc gum_api_resolver_make*(kind: string): ptr GumApiResolver
proc gum_api_resolver_enumerate_matches*(self: ptr GumApiResolver, query: cstring, fn: GumFoundApiFunc, userData: pointer, error: ptr ptr GError)

#[ gumbacktracer.h ]#
proc gum_backtracer_make_accurate*(): ptr GumBacktracer
proc gum_backtracer_make_fuzzy*(): ptr GumBacktracer
proc gum_backtracer_generate*(self: ptr GumBacktracer, cpuContext: ptr GumCpuContext, returnAddresses: ptr GumReturnAddressArray)
proc gum_backtracer_generate_with_limit*(self: ptr GumBacktracer, cpuContext: ptr GumCpuContext, returnAddresses: ptr GumReturnAddressArray, limit: uint)

#[ gumreturnaddress.h ]#
proc gum_return_address_details_from_address*(address: GumReturnAddress, details: ptr GumReturnAddressDetails): bool
proc gum_return_address_array_is_equal*(array1: ptr GumReturnAddressArray, array2: ptr GumReturnAddressArray): bool

#[ gumcloak.h ]#
proc gum_cloak_add_thread*(id : GumThreadId)
proc gum_cloak_remove_thread*(id: GumThreadId)
proc gum_cloak_has_thread*(id: GumThreadId): bool
proc gum_cloak_enumerate_threads (fn: GumCloakFoundThreadFunc, userData: pointer)

proc gum_cloak_add_range*(memRange: ptr GumMemoryRange)
proc gum_cloak_remove_range*(memRange: ptr GumMemoryRange)
proc gum_cloak_has_range_containing*(address: GumAddress): bool
proc gum_cloak_clip_range*(memRange: ptr GumMemoryRange): ptr GArray
proc gum_cloak_enumerate_ranges*(fn: GumCloakFoundRangeFunc, userData: pointer)

proc gum_cloak_add_file_descriptor*(fd: int)
proc gum_cloak_remove_file_descriptor*(fd: int)
proc gum_cloak_has_file_descriptor*(fd: int): bool
proc gum_cloak_enumerate_file_descriptors*(fn: GumCloakFoundFDFunc, userData: pointer)

#[ gumcodeallocator.h ]#
proc gum_code_allocator_init*(allocator: ptr GumCodeAllocator, sliceSize: csize_t)
proc gum_code_allocator_free*(allocator: ptr GumCodeAllocator)

proc gum_code_allocator_alloc_slice*(self: ptr GumCodeAllocator): ptr GumCodeSlice
proc gum_code_allocator_try_alloc_slice_near*(self: ptr GumCodeAllocator, spec: ptr GumAddressSpec, alignment: csize_t): ptr GumCodeSlice
proc gum_code_allocator_commit*(self: ptr GumCodeAllocator)
proc gum_code_slice_ref*(slice: ptr GumCodeSlice): ptr GumCodeSlice
proc gum_code_slice_unref*(slice: GumCodeSlice)

proc gum_code_allocator_alloc_deflector*(self: ptr GumCodeAllocator, caller: ptr  GumAddressSpec,returnAddress: pointer, target: pointer, dedicated: bool): ptr GumCodeDeflector
proc gum_code_deflector_ref*(deflector: ptr GumCodeDeflector): ptr GumCodeDeflector
proc gum_code_deflector_unref*(deflector: GumCodeDeflector)

#[ gumcodesigment.h ]#
proc gum_code_segment_is_supported*(): bool
proc gum_code_segment_new*(size: csize_t, spec: ptr GumAddressSpec): ptr GumCodeSegment
proc gum_code_segment_free*(segment: ptr GumCodeSegment)

proc gum_code_segment_get_address*(self: ptr GumCodeSegment): pointer
proc gum_code_segment_get_size*(self: ptr GumCodeSegment): csize_t
proc gum_code_segment_get_virtual_size*(self: ptr GumCodeSegment): csize_t

proc gum_code_segment_realize*(self: ptr GumCodeSegment)
proc gum_code_segment_map*(self: ptr GumCodeSegment, sourceOffset: csize_t, sourceSize: csize_t, targetAddress: pointer)
proc gum_code_segment_mark*(code: pointer, size: csize_t, error: ptr ptr GError): bool

#[ gumdarwingrather.h ]#
proc gum_darwin_grafter_new_from_file*(path: cstring, flags: GumDarwinGrafterFlags): ptr GumDarwinGrafter
proc gum_darwin_grafter_add*(self: ptr GumDarwinGrafter, codeOffset: uint32)
proc gum_darwin_grafter_graft*(self: ptr GumDarwinGrafter , error: ptr ptr GError): bool

#[ gumdarwinmodule.h ]#
proc gum_darwin_module_new_from_file*(path: cstring, cpuType: GumCpuType, ptrauthSupport: GumPtrauthSupport, flags: GumDarwinModuleFlags, error: ptr ptr GError): ptr GumDarwinModule
proc gum_darwin_module_new_from_blob*(blob: ptr GBytes, cpuType: GumCpuType, ptrauthSupport: GumPtrauthSupport, flags: GumDarwinModuleFlags, error: ptr ptr GError): ptr GumDarwinModule
proc gum_darwin_module_new_from_memory*(name: cstring, task: GumDarwinPort, baseAddress: GumAddress, flags: GumDarwinModuleFlags, error: ptr ptr GError): ptr GumDarwinModule

proc gum_darwin_module_load*(self: ptr GumDarwinModule, error: ptr ptr GError): bool

proc gum_darwin_module_resolve_export*(self: ptr GumDarwinModule, symbol: cstring, details: ptr GumDarwinExportDetails): bool
proc gum_darwin_module_resolve_symbol_address*(self: ptr GumDarwinModule, symbol: cstring): GumAddress
proc gum_darwin_module_get_lacks_exports_for_reexports*(self: ptr GumDarwinModule): bool
proc gum_darwin_module_enumerate_imports*(self: ptr GumDarwinModule, fn: GumFoundImportFunc, resolver: GumResolveExportFunc, userData: pointer)
proc gum_darwin_module_enumerate_exports*(self: ptr GumDarwinModule, fn: GumFoundDarwinExportFunc, userData: pointer)
proc gum_darwin_module_enumerate_symbols*(self: ptr GumDarwinModule, fn: GumFoundDarwinSymbolFunc, userData: pointer)
proc gum_darwin_module_get_slide*(self: ptr GumDarwinModule ): GumAddress
proc gum_darwin_module_get_nth_segment*(self: ptr GumDarwinModule, index: csize_t): ptr GumDarwinSegment
proc gum_darwin_module_enumerate_sections*(self: ptr GumDarwinModule, fn: GumFoundDarwinSectionFunc, userData: pointer)
proc gum_darwin_module_is_address_in_text_section*(self: ptr GumDarwinModule, address: GumAddress): bool
proc gum_darwin_module_enumerate_chained_fixups*(self: ptr GumDarwinModule, fn: GumFoundDarwinChainedFixupsFunc, userData: pointer)
proc gum_darwin_module_enumerate_rebases*(self: ptr GumDarwinModule, fn: GumFoundDarwinRebaseFunc, userData: pointer)
proc gum_darwin_module_enumerate_binds*(self: ptr GumDarwinModule, fn: GumFoundDarwinBindFunc, userData: pointer)
proc gum_darwin_module_enumerate_lazy_binds*(self: ptr GumDarwinModule, fn: GumFoundDarwinBindFunc, userData: pointer)
proc gum_darwin_module_enumerate_init_pointers*(self: ptr GumDarwinModule, fn: GumFoundDarwinInitPointersFunc, userData: pointer)
proc gum_darwin_module_enumerate_init_offsets*(self: ptr GumDarwinModule, fn: GumFoundDarwinInitOffsetsFunc, userData: pointer)
proc gum_darwin_module_enumerate_term_pointers*(self: ptr GumDarwinModule, fn: GumFoundDarwinTermPointersFunc, userData: pointer)
proc gum_darwin_module_enumerate_dependencies*(self: ptr GumDarwinModule, fn: GumFoundDarwinDependencyFunc, userData: pointer)
proc gum_darwin_module_enumerate_function_starts*(self: ptr GumDarwinModule, fn: GumFoundDarwinFunctionStartsFunc, userData: pointer)
proc gum_darwin_module_get_dependency_by_ordinal*(self: ptr GumDarwinModule, ordinal: int): cstring
proc gum_darwin_module_ensure_image_loaded*(self: ptr GumDarwinModule, error: ptr ptr GError): bool

proc gum_darwin_threaded_item_parse*(value: uint64, result: ptr GumDarwinThreadedItem)

proc gum_darwin_module_image_new*(): ptr GumDarwinModuleImage
proc gum_darwin_module_image_dup*(other: ptr GumDarwinModuleImage): ptr GumDarwinModuleImage
proc gum_darwin_module_image_free*(image: ptr GumDarwinModuleImage)

#[ gumeventsink.h ]#
proc gum_event_sink_query_mask (self: ptr GumEventSink): GumEventType
proc gum_event_sink_start*(self: ptr GumEventSink)
proc gum_event_sink_process*(self: ptr GumEventSink, event: ptr GumEvent, cpuContext: ptr GumCpuContext)
proc gum_event_sink_flush*(self: ptr GumEventSink)
proc gum_event_sink_stop*(self: ptr GumEventSink)

proc gum_event_sink_make_default*(): ptr GumEventSink
proc gum_event_sink_make_from_callback*(mask: GumEventType, callbackk: GumEventSinkCallback, data: pointer, dataDestory: GDestroyNotify): ptr GumEventSink

#[ gumexceptor.h ]#
proc gum_exceptor_disable*()

proc gum_exceptor_obtain*(): ptr GumExceptor

proc gum_exceptor_reset*(self: ptr GumExceptor);

proc gum_exceptor_add*(self: ptr GumExceptor, fn: GumExceptionHandler, userData: pointer)
proc gum_exceptor_remove*(self: ptr GumExceptor, fn: GumExceptionHandler, userData: pointer)

proc gum_exceptor_catch*(self: ptr GumExceptor, scope: ptr GumExceptorScope): bool
proc gum_exceptor_has_scope*(self: ptr GumExceptor, threadId: GumThreadId): bool

proc gum_exception_details_to_string*(details: ptr GumExceptionDetails): cstring

#[ gumfunction.h ]#

#[ gumheapapi.h ]#
proc gum_process_find_heap_apis*(): ptr GumHeapApiList

proc gum_heap_api_list_new*(): ptr GumHeapApiList
proc gum_heap_api_list_copy*(list: ptr GumHeapApiList): ptr GumHeapApiList
proc gum_heap_api_list_free*(list: ptr GumHeapApiList)

proc gum_heap_api_list_add*(self: ptr GumHeapApiList, api: ptr GumHeapApi)
proc gum_heap_api_list_get_nth*(self: ptr GumHeapApiList, n: uint): ptr GumHeapApi

#[ guminterceptor.h ]#
proc gum_interceptor_obtain*(): ptr GumInterceptor
proc gum_interceptor_attach*(self: ptr GumInterceptor, functionAddress: pointer, listener: ptr GumInvocationListener, listenerFunctionData: pointer): GumAttachReturn
proc gum_interceptor_detach*(self: ptr GumInterceptor, listener: ptr GumInvocationListener): GumAttachReturn

proc gum_interceptor_replace*(self: ptr GumInterceptor, functionAddress: pointer, replacementFunction: pointer, replacementData: pointer, originalFunction: pointer): GumReplaceReturn
proc gum_interceptor_replace_fast*(self: ptr GumInterceptor, functionAddress: pointer, replacementFunction: pointer, originalFunction: pointer): GumReplaceReturn
proc gum_interceptor_revert*(self: ptr GumInterceptor, functionAddress: pointer)

proc gum_interceptor_begin_transaction*(self: ptr GumInterceptor)
proc gum_interceptor_end_transaction*(self: ptr GumInterceptor)
proc gum_interceptor_flush*(self: ptr GumInterceptor)

proc gum_interceptor_get_current_invocation*(): GumInvocationContext
proc gum_interceptor_get_current_stack*(): GumInvocationStack

proc gum_interceptor_ignore_current_thread*(self: ptr GumInterceptor);
proc gum_interceptor_unignore_current_thread*(self: ptr GumInterceptor);
proc gum_interceptor_maybe_unignore_current_thread*(self: ptr GumInterceptor): bool

proc gum_interceptor_ignore_other_threads*(self: ptr GumInterceptor)
proc gum_interceptor_unignore_other_threads*(self: ptr GumInterceptor)

proc gum_invocation_stack_translate*(self: ptr GumInvocationStack, returnAddress: pointer): pointer

proc gum_interceptor_save*(state: ptr GumInvocationState);
proc gum_interceptor_restore*(state: ptr GumInvocationState)

#[ guminvocationcontext.h ]#
proc gum_invocation_context_get_point_cut*(context: ptr GumInvocationContext): GumPointCut

proc gum_invocation_context_get_nth_argument*(context: ptr GumInvocationContext, n: uint): pointer
proc gum_invocation_context_replace_nth_argument*(context: ptr GumInvocationContext, n: uint, value: pointer)
proc gum_invocation_context_get_return_value*(context: ptr GumInvocationContext): pointer
proc gum_invocation_context_replace_return_value*(context: ptr GumInvocationContext, value: pointer)

proc gum_invocation_context_get_return_address*(context: ptr GumInvocationContext): pointer

proc gum_invocation_context_get_thread_id*(context: ptr GumInvocationContext): uint
proc gum_invocation_context_get_depth*(context: ptr GumInvocationContext): uint

proc gum_invocation_context_get_listener_thread_data*(context: ptr GumInvocationContext, requiredSize: csize_t): pointer
proc gum_invocation_context_get_listener_function_data*(context: ptr GumInvocationContext): pointer
proc gum_invocation_context_get_listener_invocation_data*(context: ptr GumInvocationContext, requiredSize: csize_t): pointer

proc gum_invocation_context_get_replacement_data*(context: ptr GumInvocationContext): pointer

#[ guminvocationlistener.h ]#
proc gum_make_call_listener*(onEnter: GumInvocationCallback , onLeave: GumInvocationCallback, data: pointer, dataDestroy: GDestroyNotify): ptr GumInvocationListener
proc gum_make_probe_listener*(onHit: GumInvocationCallback, data: pointer, dataDestroy: GDestroyNotify): ptr GumInvocationListener

proc gum_invocation_listener_on_enter*(self: ptr GumInvocationContext, context: ptr GumInvocationContext)
proc gum_invocation_listener_on_leave*(self: ptr GumInvocationContext, context: ptr GumInvocationContext)

#[ gumkernel.h ]#
proc gum_kernel_api_is_available*(): bool
proc gum_kernel_query_page_size*(): uint
proc gum_kernel_alloc_n_pages*(nPages: uint): GumAddress
proc gum_kernel_free_pages*(mem: GumAddress)
proc gum_kernel_try_mprotect*(address: GumAddress, size: csize_t, prot: GumPageProtection): bool
proc gum_kernel_read*(address: GumAddress, len: csize_t, nBytesRead: ptr csize_t): ptr uint8
proc gum_kernel_write*(address: GumAddress, bytes: ptr uint8, len: csize_t): bool
proc gum_kernel_scan*(memRange: ptr GumMemoryRange, pattern: ptr GumMatchPattern, fn: GumMemoryScanMatchFunc, userData: pointer)
proc gum_kernel_enumerate_ranges*(prot: GumPageProtection, fn: GumFoundRangeFunc, userData: pointer)
proc gum_kernel_enumerate_module_ranges*(moduleName: cstring, prot: GumPageProtection, fn: GumFoundKernelModuleRangeFunc, userData: pointer)
proc gum_kernel_enumerate_modules*(fn: GumFoundModuleFunc, userData: pointer)
proc gum_kernel_find_base_address*(): GumAddress
proc gum_kernel_set_base_address*(base: GumAddress)

#[ gumlibc.h ]#
proc gum_memset*(dst: pointer, c: int, n: csize_t): pointer
proc gum_memcpy*(dst: pointer, src: pointer, n: csize_t): pointer
proc gum_memmove*(dst: pointer, src: pointer, n: csize_t): pointer

#[ gummemory.h]#
GUM_API void gum_internal_heap_ref (void);
GUM_API void gum_internal_heap_unref (void);

GUM_API gpointer gum_sign_code_pointer (gpointer value);
GUM_API gpointer gum_strip_code_pointer (gpointer value);
GUM_API GumAddress gum_sign_code_address (GumAddress value);
GUM_API GumAddress gum_strip_code_address (GumAddress value);
GUM_API GumPtrauthSupport gum_query_ptrauth_support (void);
GUM_API guint gum_query_page_size (void);
GUM_API gboolean gum_query_is_rwx_supported (void);
GUM_API GumRwxSupport gum_query_rwx_support (void);
GUM_API gboolean gum_memory_is_readable (gconstpointer address, gsize len);
GUM_API guint8 * gum_memory_read (gconstpointer address, gsize len,
    gsize * n_bytes_read);
GUM_API gboolean gum_memory_write (gpointer address, const guint8 * bytes,
    gsize len);
GUM_API gboolean gum_memory_patch_code (gpointer address, gsize size,
    GumMemoryPatchApplyFunc apply, gpointer apply_data);
GUM_API gboolean gum_memory_mark_code (gpointer address, gsize size);

GUM_API void gum_memory_scan (const GumMemoryRange * range,
    const GumMatchPattern * pattern, GumMemoryScanMatchFunc func,
    gpointer user_data);

GUM_API GumMatchPattern * gum_match_pattern_new_from_string (
    const gchar * pattern_str);
GUM_API GumMatchPattern * gum_match_pattern_ref (GumMatchPattern * pattern);
GUM_API void gum_match_pattern_unref (GumMatchPattern * pattern);
GUM_API guint gum_match_pattern_get_size (const GumMatchPattern * pattern);
GUM_API GPtrArray * gum_match_pattern_get_tokens (
    const GumMatchPattern * pattern);

GUM_API void gum_ensure_code_readable (gconstpointer address, gsize size);

GUM_API void gum_mprotect (gpointer address, gsize size,
    GumPageProtection prot);
GUM_API gboolean gum_try_mprotect (gpointer address, gsize size,
    GumPageProtection prot);

GUM_API void gum_clear_cache (gpointer address, gsize size);

GUM_API guint gum_peek_private_memory_usage (void);

GUM_API gpointer gum_malloc (gsize size);
GUM_API gpointer gum_malloc0 (gsize size);
GUM_API gsize gum_malloc_usable_size (gconstpointer mem);
GUM_API gpointer gum_calloc (gsize count, gsize size);
GUM_API gpointer gum_realloc (gpointer mem, gsize size);
GUM_API gpointer gum_memalign (gsize alignment, gsize size);
GUM_API gpointer gum_memdup (gconstpointer mem, gsize byte_size);
GUM_API void gum_free (gpointer mem);

GUM_API gpointer gum_alloc_n_pages (guint n_pages, GumPageProtection prot);
GUM_API gpointer gum_try_alloc_n_pages (guint n_pages, GumPageProtection prot);
GUM_API gpointer gum_alloc_n_pages_near (guint n_pages, GumPageProtection prot,
    const GumAddressSpec * spec);
GUM_API gpointer gum_try_alloc_n_pages_near (guint n_pages,
    GumPageProtection prot, const GumAddressSpec * spec);
GUM_API void gum_query_page_allocation_range (gconstpointer mem, guint size,
    GumMemoryRange * range);
GUM_API void gum_free_pages (gpointer mem);

GUM_API gpointer gum_memory_allocate (gpointer address, gsize size,
    gsize alignment, GumPageProtection prot);
GUM_API gpointer gum_memory_allocate_near (const GumAddressSpec * spec,
    gsize size, gsize alignment, GumPageProtection prot);
GUM_API gboolean gum_memory_free (gpointer address, gsize size);
GUM_API gboolean gum_memory_release (gpointer address, gsize size);
GUM_API gboolean gum_memory_recommit (gpointer address, gsize size,
    GumPageProtection prot);
GUM_API gboolean gum_memory_discard (gpointer address, gsize size);
GUM_API gboolean gum_memory_decommit (gpointer address, gsize size);

GUM_API gboolean gum_address_spec_is_satisfied_by (const GumAddressSpec * spec,
    gconstpointer address);

GUM_API GumMemoryRange * gum_memory_range_copy (const GumMemoryRange * range);
GUM_API void gum_memory_range_free (GumMemoryRange * range);

{.pop.}


