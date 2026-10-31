# ghidart

English | [简体中文](README.zh-CN.md)

A Ghidra extension for Dart AOT, currently supporting ARM64.
It reuses Ghidra's official ARM64 sources and decompiler, preserving original
instructions and register storage.

Features:

- Dart managed ABI: X15 stack, CPU/FPU/stack arguments, returns and register preservation.
- Independent machine-code function discovery, control-flow analysis and call-chain argument/return recovery.
- RuntimeEntry, write-barrier, stack-check and Mint helper contracts recovered from supported machine-code patterns.
- Clearer compressed Smi extraction using standard sign-extension operations.
- Optional parameter access shapes inferred from machine-code memory uses, without snapshot layouts.
- PP-relative access and constant-use indexing, with references for proved concrete addresses and calls.
- Finite indirect-jump recovery through native switch/SSA analysis and complete CFG checks.
- Optional native heap-base expression names and explicit-length character data types.
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
   language `AARCH64:LE:64:dart`, compiler `dart` (or `dart-r23` for Dart 2.13-era binaries
   with dedicated x23 heap base); choose the ARM64 slice for FAT files.
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

L1 ABI analysis uses machine-code evidence, without snapshot hashes or Thread
layout profiles. **Dart ABI → Infer observed memory shapes** can additionally
replace raw parameter-relative field accesses with observed offset members.
It is disabled by default, requires a recovered physical prototype and rejects
mixed numeric uses or escapes. These types describe observed accesses, not Dart
classes or complete objects. Reanalysis revokes unchanged generated hints;
edited layouts are preserved as user prototypes.

After ABI recovery, optionally run **Dart Value Uses** on selected functions.
It decompiles each selected function, so a whole-program run can take a long time.
The task monitor shows the current function, stage and completed count. The
per-function decompiler timeout defaults to 20 seconds and is configurable;
the final summary includes failures and timeouts.
It saves PP origins, byte offsets, access widths and constant uses in the database.
Run `ShowDartValueUses.java` to print them in the Console. Concrete references appear
in normal Ghidra navigation; PP offsets alone do not identify pool entries or strings.
Rerun the analysis after changing code or signatures. It is disabled by default.

**Dart Value Uses → Name heap-base expressions** optionally names exact `HBS << 32`
intermediates as `heap_base`. Their arithmetic remains visible; instructions,
registers and call contracts are unchanged. Reanalysis removes unchanged generated
names and preserves user edits. The option is disabled by default.

When a character payload's address, byte length and encoding are independently
known, apply built-in `dart_chars8` (Latin-1) or `dart_chars16le` (UTF-16LE) to that
range through the Data Type Manager. These types preserve NULs and UTF-16 code
units in the database/Listing; edit raw UTF-16 units in Bytes. They do not discover
Dart objects or infer lengths/encodings. The stock decompiler still uses C-string
rules when inlining a character pointer: embedded NUL content is not fully inlined.
Run **ShowDartCharacters.java** on typed data or an instruction referencing it to
print the full payload, address, byte length and escaped code units in the console.
This view preserves NULs and lone surrogates without changing decompiler semantics.
Automatic Dart string discovery is not implemented; it requires object facts from L2/L3.

Supported stack-check and write-barrier call sites receive local
contracts; direct shared helpers require matching saves, restores and result slots.
Unresolved indirect destinations remain indirect. L2/L3 metadata can add stronger facts.

## Compatibility

L1 targets ARM64 Dart 2.10 through the current stable release (3.13.7).
SDK source checks cover 30 release tags; real-binary checks cover selected versions,
not every release or OS combination. Versions before 2.10 are outside the current scope.

The common model handles stack and register arguments, old/new barrier masks,
individual/paired Q saves and old/new Mint allocation paths from machine-code evidence.
For the 2.13-era ABI with a dedicated x23 heap base, select `dart-r23` explicitly;
it is derived from the common compiler specification, without snapshot hashes.

This update fixes unconditional `b.al` decoding. Accept Ghidra's language upgrade
when opening an existing database, then rerun discovery and ABI analysis as needed.
User-edited functions remain protected.

## Files and verification

L2 groundwork provides a bounded snapshot byte reader and a shared function-boundary
publisher. Snapshot decoding and object publication are planned L2 work.

Sources are in `src/main/java/ghidart/`; language definitions are in `data/languages/`.
The build references the installed official ARM64 sources through Ghidra's module
macro. A small SLEIGH wrapper exposes equivalent signed-word arithmetic; it keeps
instruction encodings and register storage unchanged.
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
