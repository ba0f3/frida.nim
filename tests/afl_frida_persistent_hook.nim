import frida/gum

#include "/home/huy/workspace/AFLplusplus/qemu_mode/qemuafl/qemuafl/api.h"

const OBJECT_ADDR = 0xDEADFACE

proc afl_persistent_hook(regs: ptr GumCpuContext, guest_base: uint64, input_buf: ptr uint8, input_buf_len: uint32) {.exportc, dynlib.} =
  echo "afl_persistent_hook. len = ", input_buf_len

  # do a length check matching the target!
  copyMem(cast[pointer](regs.rdi), input_buf, input_buf_len)
  regs.rsi = input_buf_len


  #[
  var
    esp = cast[ptr ptr UncheckedArray[pointer]](regs.esp)
    arg1 = addr esp[0]
    arg2 = esp[1]
    arg3 = addr esp[2]

  arg1[] = cast[pointer](OBJECT_ADDR)

  copyMem(arg2, input_buf, input_buf_len)
  arg3[] = cast[pointer](input_buf_len)
  ]#

  #[
  void **esp = (void **)regs->esp;
  void  *arg1 = esp[0];
  void **arg2 = &esp[1];
  memcpy(arg1, input_buf, input_buf_len);
  *arg2 = (void *)input_buf_len;
  ]#


proc afl_persistent_hook_init(): int {.exportc, dynlib.} =
  echo "afl_persistent_hook"
  return 1