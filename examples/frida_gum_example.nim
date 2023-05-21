import os, frida/gum
import ba0f3/[cptr, logger]


const
  TARGET_FUNCTION_ADDRESS = 0xBEEF

var
  interceptor: ptr GumInterceptor
  listener: ptr GumInvocationListener

proc onEnter(context: ptr GumInvocationContext, userData: pointer) =
  # on enter
  var
    arg1 = gum_invocation_context_get_nth_argument(context, 0) # this
    arg2 = gum_invocation_context_get_nth_argument(context, 1) # pData
    arg3 = cast[int](gum_invocation_context_get_nth_argument(context, 2)) # nLen

  # do something with arguments


proc onLeave(context: ptr GumInvocationContext, userData: pointer) =
  # on leave
  var retVal = cast[int](gum_invocation_context_get_return_value(context))

  # do somthing with return value

  # detach listener if you dont want to use it anymore
  gum_interceptor_begin_transaction(interceptor)
  gum_interceptor_detach(interceptor, listener)
  gum_interceptor_end_transaction(interceptor)


when isMainModule:
  when appType != "lib":
    {.error: "this file must compile with --app:lib switch".}

  gum_init()

  interceptor = gum_interceptor_obtain()
  listener = gum_make_call_listener(onEnter, onLeave, nil, nil)
  gum_interceptor_begin_transaction(interceptor)
  gum_interceptor_attach(interceptor, cast[pointer](TARGET_FUNCTION_ADDRESS), listener, nil)
  gum_interceptor_end_transaction(interceptor)

