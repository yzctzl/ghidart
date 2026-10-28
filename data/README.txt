Runtime language files packaged with the extension.

languages/AARCH64.ldefs selects the official decoder and Dart configuration.
languages/AARCH64dart.pspec defines register roles and processor defaults.
languages/AARCH64dart.cspec defines the Dart calling convention.
languages/AARCH64dart.opinion supplies loader language hints.

AARCH64.sla, AARCH64.dwarf and manuals/AARCH64.idx are copied from the selected
Ghidra installation during the build. They are generated, ignored files;
ghidart does not maintain a separate ARM64 instruction decoder.
