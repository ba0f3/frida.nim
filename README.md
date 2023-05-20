## frida.nim

This repository contains wrappers for `frida-core` and  `frida-gum` libraries

`frida-x-devkit` are not included, you must download and install them manually.

- The devkits for the respective platform can be found at [Frida releases on GitHub](https://github.com/frida/frida/releases),
- Download and put them in LIBRARY_PATH
  - For linux put library in to `/usr/lib/x86_64-linux-gnu` for x86_64 and `/usr/lib/i386-linux-gnu` for x86
- Or you can specify absolute path to devkit with `FRIDA_CORE_PATH` & `FRIDA_GUM_PATH`
  - Eg: `nim c -d:FRIDA_GUM_PATH=/home/user/libs/libfrida-gum.a tests/frida_persistent_hook.nim`

