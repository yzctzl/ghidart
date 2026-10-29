# ghidart

English | [简体中文](README.zh-CN.md)

A Ghidra extension for Dart AOT, currently supporting ARM64.
It reuses Ghidra's official ARM64 decoder and decompiler, preserving original
instructions and register storage.

Features:

- Dart managed ABI: X15 stack, CPU/FPU/stack arguments, returns and register preservation.
- Independent machine-code function discovery, control-flow analysis and call-chain argument/return recovery.
- RuntimeEntry, write-barrier, stack-check and Mint helper contracts for verified SDKs.
- Optional `b4a.json` import of code boundaries and alternate-entry labels after checking binary identity and mappings.

**Experimental: correctness and stability have not been comprehensively verified.**
Unknown indirect branches, SDKs and calling conventions remain unknown.
General native/FFI support, live Runtime returns on dynamic stacks and on-device
debugging are not fully supported or validated. Import of b4a classes, names,
object pools and higher-level analysis is also incomplete.

## Installation

Requires Ghidra 12.2 PUBLIC and Java 25. A Gradle Wrapper is included.

```sh
export JAVA_HOME=/path/to/jdk-25
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC
./gradlew --no-daemon buildExtension
```

Install the ZIP from `dist/` through Ghidra's **File → Install Extensions**, then
restart Ghidra. Alternatively, run `./gradlew --no-daemon installExtension` to
install into the Ghidra directory above. Restart any running Ghidra after updating.

## Usage

1. For ELF, choose **Dart AOT ELF**. For Mach-O, use the official loader and select
   language `AARCH64:LE:64:dart`, compiler `dart`; choose the ARM64 slice for FAT files.
2. Place a matching `b4a.json` beside the binary, or set
   **Dart AOT Code Boundaries → b4a.json path**. Identity or mapping mismatches reject the import.
3. Without boundary data, select a Dart managed code region and run
   **Dart Machine Code Functions** once. Add known entries through **Confirmed entry addresses**.
4. Run **Dart ABI** on the functions and relevant callees, then open the decompiler.

Machine-code discovery and ABI analysis are disabled by default to avoid scanning
mixed native code or decompiling the entire input during import. Incomplete control
flow is marked `Dart: incomplete CFG`. User-edited bodies, signatures and call-site
prototypes are protected. Ghidart messages appear in the Ghidra Console.
The Dart language uses register names such as `VMSP` and `THR`; physical names
such as `x15` and `x26` remain aliases of the same registers for debugging.

Exact SDK helper profiles have been verified for Android 3.10.8, iOS 2.19.6 and
macOS 3.11.5. Other versions can still use the general managed ABI; special contracts
apply only when identity, layout and instruction evidence match.

## Files and verification

Sources are in `src/main/java/ghidart/`; language definitions are in `data/languages/`.
The build copies the official decoder, avoiding a separately maintained ARM64 instruction set.
See [B4A_INTERFACE.md](B4A_INTERFACE.md) for the b4a data format.

The original lightweight verifiers are in `tests/`. Local application samples and
large validation materials are excluded from the release package. With matching
binaries and `b4a.json` samples available, run offline identity checks:

```sh
./gradlew --no-daemon verifySamples -PsamplesDir=/path/to/samples
```

See [samples/README.md](samples/README.md) for the directory layout. Passing these
checks does not mean Ghidra analysis has run. See [LICENSE](LICENSE) for licensing
and template attribution.

English is the default documentation language. Keep this README and
[README.zh-CN.md](README.zh-CN.md) synchronized whenever either changes.
Interface, sample and test documentation is maintained in English only.
