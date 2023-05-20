#when not compileOption("threads"):
#  {.error: "Frida gumjs library require --threads:on to run".}
{.experimental: "codeReordering".}
{.passL: "-lfrida-gum -latomic -lresolv".}

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
  GumOS* = uint
  GumCpuContext* = object
  GumAddress* = uint64

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
  GumRwxSupport* = uint
  GumMemoryOperation* = uint

  GumAddressSpec* = object
  GumMatchPattern* = object
  GumMemoryRange* = object
    baseAddress*: GumAddress
    size*: csize_t

  GumMemoryIsNearFunc* = proc(memory: pointer, address: pointer): bool

  GumMemoryPatchApplyFunc* = proc(mem: pointer, userData: pointer)
  GumMemoryScanMatchFunc* = proc(address: GumAddress, size: csize_t): bool

  GumPageProtection* = enum
    GUM_PAGE_NO_ACCESS = 0
    GUM_PAGE_READ      = (1 shl 0)
    GUM_PAGE_WRITE     = (1 shl 1)
    GUM_PAGE_EXECUTE   = (1 shl 2)

  #{ gummemoryaccessmonitor.h ]#
  GumMemoryAccessMonitor* = object
  GumMemoryAccessDetails* = object

  GumMemoryAccessNotify* = proc(monitor: ptr GumMemoryAccessMonitor, details: ptr GumMemoryAccessDetails, userData: pointer)

  #[ gummemorymap.h ]#
  GumMemoryMap* = object

  #[ gummetalarray.h ]#
  GumMetalArray* = object

  #[ gummetalhash.h ]#
  GumMetalHashTable* = object
  GumMetalHashTableIter* = object

  #[ gummoduleapiresolver.h ]#
  GumModuleApiResolver* = object

  #[ gummodulemap.h ]#
  GumModuleMap* = object

  GumModuleMapFilterFunc* = proc(details: ptr GumModuleDetails, userData: pointer): bool

  #[ gumprocess.h ]#
  GumProcessId* = uint
  GumThreadId* = csize_t
  GumResolveSymbolContext* = object
  GumThreadDetails* = object
  GumModuleDetails* = object
  GumImportType* = uint
  GumExportType* = uint
  GumSymbolType* = uint
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

  #[ gumspinlock.h ]#
  GumSpinlock* = object

  #[ gumstalker.h ]#
  GumStalker* = object
  GumStalkerTransformer* = object
  GumDefaultStalkerTransformer* = object
  GumCallbackStalkerTransformer* = object
  GumStalkerObserver* = object
  GumStalkerIterator* = object
  GumStalkerOutput* = object
  GumBackpatch* = object
  GumBackpatchInstruction* = object

  GumStalkerWriter* = object
  GumProbeId* = uint
  GumCallDetails* = object

  GumStalkerIncrementFunc* = proc(self: ptr GumStalkerObserver)
  GumStalkerNotifyBackpatchFunc* = proc(self: ptr GumStalkerObserver, packpath: ptr GumBackpatch, size: csize_t)
  GumStalkerSwitchCallbackFunc* = proc(self: ptr GumStalkerObserver, fromAddress: pointer, startAddress: pointer, fromInsn: pointer, target: ptr pointer)
  GumStalkerTransformerCallback* = proc(iter: ptr GumStalkerIterator, output: ptr GumStalkerOutput, userData: pointer)
  GumStalkerCallout* = proc(cpuContext: ptr GumCpuContext, userData: pointer)
  GumCallProbeCallback* = proc(details: ptr GumCallDetails, userData: pointer)

  #[ gumsymbolutil.h ]#
  GumDebugSymbolDetails* = object

  #{ gumtls.h ]#
  GumTlsKey* = object

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

#[ gumcloak.h ]#
proc gum_cloak_add_thread*(id : GumThreadId)
proc gum_cloak_remove_thread*(id: GumThreadId)
proc gum_cloak_has_thread*(id: GumThreadId): bool
proc gum_cloak_enumerate_threads*(fn: GumCloakFoundThreadFunc, userData: pointer)

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
proc gum_event_sink_query_mask*(self: ptr GumEventSink): GumEventType
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
proc gum_internal_heap_ref*()
proc gum_internal_heap_unref*()

proc gum_sign_code_pointer*(value: pointer): pointer
proc gum_strip_code_pointer*(value: pointer): pointer
proc gum_sign_code_address*(value: GumAddress): GumAddress
proc gum_strip_code_address*(value: GumAddress): GumAddress
proc gum_query_ptrauth_support*(): GumPtrauthSupport
proc gum_query_page_size*(): uint
proc gum_query_is_rwx_supported*(): bool
proc gum_query_rwx_support*(): GumRwxSupport
proc gum_memory_is_readable*(address: pointer, len: csize_t): bool
proc gum_memory_read*(address: pointer, len: csize_t , nBytesRead: ptr csize_t): ptr uint8
proc gum_memory_write*(address: pointer, bytes: ptr uint8, len: csize_t): bool
proc gum_memory_patch_code*(address: pointer , size: csize_t, apply: GumMemoryPatchApplyFunc, applyData: pointer): bool
proc gum_memory_mark_code*(address: pointer, size: csize_t): bool

proc gum_memory_scan*(memRange: ptr GumMemoryRange, pattern: ptr GumMatchPattern, fb: GumMemoryScanMatchFunc, userData: pointer)

proc gum_match_pattern_new_from_string*(patternStr: cstring): ptr GumMatchPattern
proc gum_match_pattern_ref*(pattern: ptr GumMatchPattern): ptr GumMatchPattern
proc gum_match_pattern_unref*(pattern: ptr GumMatchPattern)
proc gum_match_pattern_get_size*(patter: ptr GumMatchPattern): uint
proc gum_match_pattern_get_tokens*(pattern: ptr GumMatchPattern): ptr GPtrArray

proc gum_ensure_code_readable*(address: pointer, size: csize_t)

proc gum_mprotect*(address: pointer, size: csize_t, prot: GumPageProtection)
proc gum_try_mprotect*(address: pointer, size: csize_t, prot: GumPageProtection): bool

proc gum_clear_cache*(address: pointer, size: csize_t)

proc gum_peek_private_memory_usage*(): uint

proc gum_malloc*(size: csize_t): pointer
proc gum_malloc0*(size: csize_t): pointer
proc gum_malloc_usable_size*(mem: pointer): csize_t
proc gum_calloc*(count: csize_t, size: csize_t): pointer
proc gum_realloc*(mem: pointer, size: csize_t): pointer
proc gum_memalign*(alignment: csize_t, size: csize_t): pointer
proc gum_memdup*(mem: pointer, byteSize: csize_t): pointer
proc gum_free*(mem: pointer)

proc gum_alloc_n_pages*(nPages: uint, prot: GumPageProtection): pointer
proc gum_try_alloc_n_pages*(nPages: uint, prot: GumPageProtection): pointer
proc gum_alloc_n_pages_near*(nPages: uint, prot: GumPageProtection, spec: ptr GumAddressSpec): pointer
proc gum_try_alloc_n_pages_near*(nPages: uint, prot: GumPageProtection, spec: ptr GumAddressSpec): pointer
proc gum_query_page_allocation_range*(mem: pointer, size: uint, memRange: ptr GumMemoryRange)
proc gum_free_pages*(mem: pointer)

proc gum_memory_allocate*(address: pointer, size: csize_t, alignment: csize_t, prot: GumPageProtection): pointer
proc gum_memory_allocate_near*(spec: ptr GumAddressSpec, size: csize_t, alignment: csize_t, prot: GumPageProtection): pointer
proc gum_memory_free*(address: pointer, size: csize_t): bool
proc gum_memory_release*(address: pointer, size: csize_t): bool
proc gum_memory_recommit*(address: pointer, size: csize_t, prot: GumPageProtection): bool
proc gum_memory_discard*(address: pointer, size: csize_t): bool
proc gum_memory_decommit*(address: pointer, size: csize_t): bool

proc gum_address_spec_is_satisfied_by*(spec: ptr GumAddressSpec, address: pointer): bool

proc gum_memory_range_copy*(memRange: ptr GumMemoryRange): ptr  GumMemoryRange
proc gum_memory_range_free*(memRange: ptr GumMemoryRange)

#{ gummemoryaccessmonitor.h ]#
proc gum_memory_access_monitor_new*(ranges: ptr GumMemoryRange, numRanges: uint, accessMask: GumPageProtection, autoReset: bool, fn: GumMemoryScanMatchFunc, data: pointer, dataDestroy: GDestroyNotify): ptr GumMemoryAccessMonitor

proc gum_memory_access_monitor_enable*(self: ptr GumMemoryAccessMonitor, error: ptr ptr GError): bool
proc gum_memory_access_monitor_disable*(self: ptr GumMemoryAccessMonitor)

#[ gummemorymap.h ]#
proc gum_memory_map_new*(prot: GumPageProtection): ptr GumMemoryMap

proc gum_memory_map_contains*(self: ptr GumMemoryMap, memRange: ptr GumMemoryRange): bool

proc gum_memory_map_update*(self: ptr GumMemoryMap)

#[ gummetalarray.h ]#
proc gum_metal_array_init*(arr: ptr GumMetalArray, elementSize: uint)
proc gum_metal_array_free*(arr: ptr GumMetalArray)

proc gum_metal_array_element_at*(self: GumMetalArray, index: uint): pointer
proc gum_metal_array_insert_at*(self: GumMetalArray, index: uint): pointer
proc gum_metal_array_remove_at*(self: GumMetalArray, index: uint);
proc gum_metal_array_remove_all*(self: GumMetalArray);
proc gum_metal_array_append*(self: GumMetalArray): pointer

proc gum_metal_array_get_extents*(self: GumMetalArray, start: ptr pointer, `end`: ptr pointer)
proc gum_metal_array_ensure_capacity*(self: GumMetalArray, capacity: uint)

#[ gummetalhash.h ]#
proc gum_metal_hash_table_new*(hashFunc: GHashFunc, keyEqualFunc: GEqualFunc): ptr GumMetalHashTable
proc gum_metal_hash_table_new_full*(hashFunc: GHashFunc, keyEqualFunc: GEqualFunc, keyDestroyFunc: GDestroyNotify, valueDestroyFunc: GDestroyNotify): ptr GumMetalHashTable
proc gum_metal_hash_table_destroy*(hashTable: ptr GumMetalHashTable);
proc gum_metal_hash_table_insert*(hashTable: ptr GumMetalHashTable, key: pointer, value: pointer): bool
proc gum_metal_hash_table_replace*(hashTable: ptr GumMetalHashTable, key: pointer, value: pointer): bool
proc gum_metal_hash_table_add*(hashTable: ptr GumMetalHashTable, key: pointer): bool
proc gum_metal_hash_table_remove*(hashTable: ptr GumMetalHashTable, key: pointer): bool
proc gum_metal_hash_table_remove_all*(hashTable: ptr GumMetalHashTable)
proc gum_metal_hash_table_steal*(hashTable: ptr GumMetalHashTable, key: pointer): bool
proc gum_metal_hash_table_steal_all*(hashTable: ptr GumMetalHashTable)
proc gum_metal_hash_table_lookup*(hashTable: ptr GumMetalHashTable, key: pointer): pointer
proc gum_metal_hash_table_contains*(hashTable: ptr GumMetalHashTable, key: pointer): bool
proc gum_metal_hash_table_lookup_extended*(hashTable: ptr GumMetalHashTable, lookupKey: pointer, origKey: ptr pointer, value: ptr pointer): bool
proc gum_metal_hash_table_foreach*(hashTable: ptr GumMetalHashTable, fn: GHFunc, userData: pointer);
proc gum_metal_hash_table_find*(hashTable: ptr GumMetalHashTable, predicate: GHRFunc, userData: pointer): pointer
proc gum_metal_hash_table_foreach_remove*(hashTable: ptr GumMetalHashTable, fn: GHRFunc, userData: pointer): uint
proc gum_metal_hash_table_foreach_steal*(hashTable: ptr GumMetalHashTable, fn: GHRFunc, userData: pointer): uint
proc gum_metal_hash_table_size*(hashTable: ptr GumMetalHashTable): uint

proc gum_metal_hash_table_iter_init*(iter: ptr GumMetalHashTableIter, hashTable: ptr GumMetalHashTable)
proc gum_metal_hash_table_iter_next*(iter: ptr GumMetalHashTableIter, key: ptr pointer, value: ptr pointer): bool
proc gum_metal_hash_table_iter_get_hash_table*(iter: ptr GumMetalHashTableIter): ptr GumMetalHashTable
proc gum_metal_hash_table_iter_remove*(iter: ptr GumMetalHashTableIter)
proc gum_metal_hash_table_iter_replace*(iter: ptr GumMetalHashTableIter, value: pointer)
proc gum_metal_hash_table_iter_steal*(iter: ptr GumMetalHashTableIter)

proc gum_metal_hash_table_ref*(hashTable: ptr GumMetalHashTable): ptr GumMetalHashTable
proc gum_metal_hash_table_unref*(hashTable: ptr GumMetalHashTable)

#[ gummoduleapiresolver.h ]#
proc gum_module_api_resolver_new*(): GumApiResolver

#[ gummodulemap.h ]#
proc gum_module_map_new*(): ptr GumModuleMap
proc gum_module_map_new_filtered*(fn: GumModuleMapFilterFunc, data: pointer, dataDestroy: GDestroyNotify): ptr GumModuleMap

proc gum_module_map_find*(self: ptr GumModuleMap, address: GumAddress): ptr  GumModuleDetails

proc gum_module_map_update*(self: ptr GumModuleMap)

proc gum_module_map_get_values*(self: ptr GumModuleMap): ptr GArray

#[ gumprocess.h]#
proc gum_process_get_native_os*(): GumOS
proc gum_process_get_code_signing_policy*(): GumCodeSigningPolicy
proc gum_process_set_code_signing_policy*(policy: GumCodeSigningPolicy)
proc gum_process_query_libc_name*(): cstring
proc gum_process_is_debugger_attached*(): bool
proc gum_process_get_id*():  GumProcessId
proc gum_process_get_current_thread_id*(): GumThreadId
proc gum_process_has_thread*(threadId: GumThreadId): bool
proc gum_process_modify_thread*(threadId: GumThreadId, fn: GumModifyThreadFunc, userData: pointer): bool
proc gum_process_enumerate_threads*(fn: GumFoundThreadFunc, userData: pointer)
proc gum_process_resolve_module_pointer*(pt: pointer, path: cstring, memRange: ptr GumMemoryRange): bool
proc gum_process_enumerate_modules*(fn: GumFoundModuleFunc, userData: pointer)
proc gum_process_enumerate_ranges*(prot: GumPageProtection, fn: GumFoundRangeFunc, userData: pointer)
proc gum_process_enumerate_malloc_ranges*(fn: GumFoundMallocRangeFunc, userData: pointer)
proc gum_thread_try_get_ranges*(ranges: ptr GumMemoryRange, maxLength: uint): uint
proc gum_thread_get_system_error*(): int
proc gum_thread_set_system_error*(value: int)
proc gum_thread_suspend*(threadId: GumThreadId, error: ptr ptr GError): bool
proc gum_thread_resume*(threadId: GumThreadId, error: ptr ptr GError): bool
proc gum_module_load*(moduleName: cstring, error: ptr ptr GError): bool
proc gum_module_ensure_initialized*(moduleName: cstring): bool
proc gum_module_enumerate_imports*(moduleName: cstring, fn: GumFoundImportFunc, userData: pointer)
proc gum_module_enumerate_exports*(moduleName: cstring, fn: GumFoundExportFunc, userData: pointer)
proc gum_module_enumerate_symbols*(moduleName: cstring, fn: GumFoundSymbolFunc, userData: pointer)
proc gum_module_enumerate_ranges*(moduleName: cstring, prot: GumPageProtection, fn: GumFoundRangeFunc, userData: pointer)
proc gum_module_find_base_address*(moduleName: cstring): GumAddress
proc gum_module_find_export_by_name*(moduleName: cstring, symbolName: cstring): GumAddress
proc gum_module_find_symbol_by_name*(moduleName: cstring, symbolName: cstring): GumAddress

proc gum_code_signing_policy_to_string*(policy: GumCodeSigningPolicy): cstring

proc gum_module_details_copy*(module: ptr GumModuleDetails): ptr GumModuleDetails
proc gum_module_details_free*(module: ptr GumModuleDetails)

proc gum_symbol_type_to_string*(kind: GumSymbolType): cstring

#[ gumreturnaddress.h ]#
proc gum_return_address_details_from_address*(address: GumReturnAddress, details: ptr GumReturnAddressDetails): bool

proc gum_return_address_array_is_equal*(array1: ptr GumReturnAddressArray, array2: ptr GumReturnAddressArray): bool

#[ gumspinlock.h ]#
proc gum_spinlock_init*(spinlock: ptr GumSpinlock)

proc gum_spinlock_acquire*(spinlock: ptr GumSpinlock)
proc gum_spinlock_release*(spinlock: ptr GumSpinlock)

#[ gumstalker.h ]#

proc gum_stalker_is_supported*(): bool

proc gum_stalker_activate_experimental_unwind_support*()

proc gum_stalker_new*(): ptr GumStalker

proc gum_stalker_exclude*(self: ptr GumStalker, memRange: ptr GumMemoryRange)

proc gum_stalker_get_trust_threshold*(self: ptr GumStalker): int
proc gum_stalker_set_trust_threshold*(self: ptr GumStalker, trustThreshold: int)

proc gum_stalker_flush*(self: ptr GumStalker)
proc gum_stalker_stop*(self: ptr GumStalker)
proc gum_stalker_garbage_collect*(self: ptr GumStalker): bool

proc gum_stalker_follow_me*(self: ptr GumStalker, transformer: ptr GumStalkerTransformer, sink: ptr GumEventSink)
proc gum_stalker_unfollow_me*(self: ptr GumStalker)
proc gum_stalker_is_following_me*(self: ptr GumStalker): bool

proc gum_stalker_follow*(self: ptr GumStalker, threadId: GumThreadId, transformer: ptr GumStalkerTransformer, sink: ptr GumEventSink)
proc gum_stalker_unfollow*(self: ptr GumStalker, threadId: GumThreadId)

proc gum_stalker_activate*(self: ptr GumStalker, target: pointer)
proc gum_stalker_deactivate*(self: ptr GumStalker)

proc gum_stalker_set_observer*(self: ptr GumStalker, observer: ptr GumStalkerObserver)

proc gum_stalker_prefetch*(self: ptr GumStalker, address: pointer , recycleCount: int)
proc gum_stalker_prefetch_backpatch*(self: ptr GumStalker, notification: ptr GumBackpatch)
proc gum_stalker_recompile*(self: ptr GumStalker, address: pointer)

proc gum_stalker_backpatch_get_from*(backpatch: ptr GumBackpatch): pointer
proc gum_stalker_backpatch_get_to*(backpatch: ptr GumBackpatch): pointer

proc gum_stalker_invalidate*(self: ptr GumStalker, address: pointer)
proc gum_stalker_invalidate_for_thread*(self: ptr GumStalker, threadId: GumThreadId, address: pointer)

proc gum_stalker_add_call_probe*(self: ptr GumStalker, targetAddress: pointer, callback: GumCallProbeCallback, data: pointer, notify: GDestroyNotify): GumProbeId
proc gum_stalker_remove_call_probe*(self: ptr GumStalker, id: GumProbeId)

proc gum_stalker_transformer_make_default*(): ptr GumStalkerTransformer
proc gum_stalker_transformer_make_from_callback*(callback: GumStalkerTransformerCallback, data: pointer, dataDestroy: GDestroyNotify): ptr GumStalkerTransformer

proc gum_stalker_transformer_transform_block*(self: ptr GumStalkerTransformer, iter: ptr GumStalkerIterator, otuput: ptr GumStalkerOutput)

proc gum_stalker_iterator_next*(self: ptr GumStalkerIterator, insn: ptr pointer): bool
proc gum_stalker_iterator_keep*(self: ptr GumStalkerIterator)
proc gum_stalker_iterator_put_callout*(self: ptr GumStalkerIterator, callout: GumStalkerCallout, data: pointer, dataDestroy: GDestroyNotify)

proc gum_stalker_observer_notify_backpatch*(observer: ptr GumStalkerObserver, backpatch: ptr GumBackpatch , size: csize_t)

proc gum_stalker_observer_switch_callback*(observer: ptr GumStalkerObserver, fromAddress: pointer, startAdress: pointer, fromInsn: pointer, target: ptr pointer)

#[ gumsymbolutil.h ]#
proc gum_symbol_details_from_address*(address: pointer, details: ptr GumDebugSymbolDetails): bool
proc gum_symbol_name_from_address*(address: pointer): cstring

proc gum_find_function*(name: cstring): pointer
proc gum_find_functions_named* (name: cstring): ptr GArray
proc gum_find_functions_matching* (s: cstring): ptr GArray
proc gum_load_symbols*(path: cstring): bool

#{ gumtls.h ]#
proc gum_tls_key_new*(): GumTlsKey
proc gum_tls_key_free*(key: GumTlsKey)

proc gum_tls_key_get_value*(key: GumTlsKey): pointer
proc gum_tls_key_set_value*(key: GumTlsKey, value: pointer)

{.pop.}


