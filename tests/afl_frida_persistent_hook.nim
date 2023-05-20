import frida/gum

proc afl_persistent_hook(regs: ptr GumCpuContext, guest_base: uint64, input_buf: ptr uint8, input_buf_len: uint32) {.exportc.} =
  # do a length check matching the target!
  copyMem(cast[pointer](regs.rdi), input_buf, input_buf_len)
  regs.rsi = input_buf_len

proc afl_persistent_hook_init(): int {.exportc.} =
  # do hooking and preparation heregit add
  return 1