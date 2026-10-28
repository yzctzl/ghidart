# Local verification samples

Each sample has its own directory containing the original binary and matching `b4a.json`:

```text
samples/
  android-arm64/
    libapp.so
    b4a.json
  ios-arm64/
    App
    b4a.json
  macos-arm64/
    App
    b4a.json
```

Name ELF binaries `libapp.so` and Mach-O binaries `App`. For FAT Mach-O, verify
the ARM64 slice: the hash of the whole container cannot replace the slice hash in JSON.

Set `JAVA_HOME` and `GHIDRA_INSTALL_DIR`, then run:

```sh
./gradlew --no-daemon verifySamples -PsamplesDir=/path/to/samples
```

This checks JSON and binary identity only; it does not run Ghidra analysis.
Sample application files are excluded from Git and extension packages.
[manifest.json](manifest.json) records the identities of the paired samples.
