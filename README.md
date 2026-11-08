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
- AOT snapshot decoding for function entries, explicit-length strings and scoped object-pool data (L2).
- Optional b4a integration (L3): code boundaries, scoped class/function names, raw field layouts,
  Thread/pool descriptions, operand references and Listing-only IL from one `b4a.json`.

**Experimental: correctness and stability have not been comprehensively verified.**
Unknown indirect branches, SDKs and calling conventions remain unknown.
General native/FFI support, live Runtime returns on dynamic stacks and on-device
debugging are not fully supported or validated. b4a printed types and IL are displayed
as exported evidence, not translated into physical ABI or replacement P-code.

## Installation

Prebuilt ZIPs are available on [Releases](https://github.com/yzctzl/ghidart/releases).
Use the Ghidra version stated in the release. Tag pushes build against the latest
stable Ghidra release; manual workflow runs can select a specific Ghidra release tag.
A successful build checks compilation and packaging, not full runtime compatibility.

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
2. Choose one initial boundary source:
   - Supported snapshot, without b4a: keep **Dart AOT Objects** (L2) enabled during
     Auto Analyze, or run it from One Shot. It creates
     functions and entry labels, strings, object relationships and scoped pools.
   - Matching `b4a.json`: **Dart b4a Import** (L3) is enabled by default when a sidecar
     exists beside the binary. You can disable it, run it from One Shot, or set
     **b4a.json path** in its analyzer options. L3 runs first and supplies boundaries;
     L2 stays enabled to decode objects, strings and pool references without
     repeating L3 boundaries or replacing its names. Rejected imports leave L2
     to provide boundaries as well. **Dart ABI** remains independent.
     **Dart AOT Code Boundaries** is disabled by default for every snapshot format;
     run it manually from One Shot for boundaries alone. It does not publish THR/PP
     views; run **Dart AOT Objects** for those, with or without b4a.
   - Unreadable/custom snapshot: select the managed executable region and run
     **Dart Machine Code Functions** (L1). Add known entries through
     **Confirmed entry addresses** if needed.
3. Select the functions of interest and run **Dart ABI**, then open the decompiler.
   ABI recovery is still required after L2 or b4a supplies boundaries.
4. Optionally run **Dart Value Uses** after ABI recovery.

All six analyzers are available under **Analysis → One Shot** for the Dart language.
L2 and b4a import read their complete input, regardless of selection;
selection limits the machine-code discovery and ABI/value analysis entry sets.
When L2 cannot decode a new input, it can run L1 discovery inside an independently
bounded instruction image. Without that boundary, select the managed region explicitly.
Existing L2 generations are preserved on rejection; ABI analysis remains independent.
A language **upgrade** updates the database's language model;
it does not rerun analysis or change saved analyzer options.

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
Choose **Dart → Show Value Uses** to print them in the Console. Concrete references appear
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
Choose **Dart → Show Characters** on typed data or an instruction referencing it to
print the full payload, address, byte length and escaped code units in the console.
This view preserves NULs and lone surrogates without changing decompiler semantics.
For supported snapshots, optionally run **Dart AOT Objects** before **Dart ABI**.
This L2 analyzer reads mapped snapshot symbols independently of b4a, creates function
and alternate-entry boundaries, defines string payloads in **Defined Strings**, and
keeps object identities and pool slots as database records. Browse **Symbol Tree →
Namespaces → Packages / SDK / App / Runtime / Unresolved** for declarations. Package
URIs retain package/path/class nesting. Obfuscated libraries without a recoverable
URI appear under **Packages → UnknownSource**, not as guessed packages.
Top-level functions belong to their library; methods and known allocation/field stubs
belong to their class. Shared code has one function body and scoped declaration aliases.
Ghidra's Functions tree is mainly for global functions; use Namespaces for ownership
and **Window → Functions** for a searchable table of all physical functions.

Choose **Dart → Browse Dart Records** at code or a string to inspect its object/pool
relationships in a docked panel. Double-click a relationship to follow it; real
locations also navigate to Listing. **Back** returns to the previous record.
Logical identities display their scope, record number and name, not a heap address.
They do not create Symbol Tree labels or ordinary XREFs. Code-to-string references
still point to original character bytes, so **Defined Strings → References** leads
back to actual uses. Metadata-only strings remain accessible in the records panel.
Pool edges describe snapshot initial values, not constants guaranteed after runtime
mutation. Serialized string prefixes are separate from their characters.

**Library → THR** lists observed Thread offsets, enriched with field names from b4a when available. **Library → PP → scope → pool**
lists decoded pool slots; b4a-only imports use **PP → Export** until L2 binds the global
pool. Selecting a field/slot shows its actual instruction uses in ordinary **XREFs**.
Targets use named `THR:offset` / `PP:offset` (or pool-specific PP spaces), not bare
`OTHER` records. These are non-loaded offset models with unknown bytes, not runtime
memory or constant object pointers. Object-graph edges stay in Dart Records and do
not enter ordinary XREFs. Unused fields have no invented references. THR offset XREFs come from decoded
instructions without a layout; field names require the matching b4a export.
L2 supplies pool identities independently.
These logical identities are not runtime heap addresses. Declaration relationships,
types, logical signatures and decoded integers are retained as database properties;
logical parameter counts do not replace machine-code ABI inference. Serialized
object fields and byte spans are retained alongside these views. Adapted root layouts
also retain named roots, field value/offset references and static tables as navigable
slots. Static fields link to their serialized initial values, including shared fields;
these describe snapshot state, not values after runtime mutation. Types and instances
link to their classes. Code objects and resolved dispatch entries link to their instruction entries;
deferred targets remain unresolved until their loading unit is available. Function
declarations retain their Code links even without a local body; `LazyCompile` is
identified as a helper, not mislabeled as a compiled business function. Integer and
double values are shown on logical identities and pool slots, with exact double bits.
Fixed user-class layouts appear under **Data Type Manager → Dart → L2**. Field
positions are converted from target words to bytes; tagged slots are not treated as
native pointers, and unknown unboxed numeric types remain raw storage. Inherited fields
use the retained superclass relationship. SDK-defined base identities such as null,
bools, sentinels and internal Class objects retain named records in the object graph.
Cached VM identities remain separate; unavailable runtime contents are not inferred.

Open a deferred `*-<id>.part.so`/`.dylib` with its root and ancestor units beside it.
L2 reads parent reference tables temporarily, validates program identity and applies
that unit's Code/pool patches. For other filenames set **Parent AOT file** to the
immediate parent binary. Missing/wrong parents reject L2 without inventing addresses.
**Dart Value Uses** can name unambiguous pool-load locals after ABI recovery; it
preserves their inferred types and user edits. Names include available initial string/base-object
hints, without folding mutable snapshot values.
It also tracks known class-allocation results and non-patchable pool instances
through SSA copies and unambiguous merges. Exact field accesses link to retained
Field declarations, including inherited fields; generated locals carry class/field
names. Whole SSA locals proved to hold one full-width tagged Class use Ghidra's
native shifted-pointer type (`ADJ(obj)->field`); compressed values remain integers.
**Dart → Show Value Uses** reports object, argument and return provenance.
Unknown calls, ambiguous values and missing declarations stop this propagation;
logical signatures are not substituted for the physical ABI.
Hashes only suggest a reader: failed hints fall back to complete structural decoding,
and conflicting interpretations are rejected. Full version coverage remains under
development. Pool offsets alone do not identify an object or string at a code use site.

L2 is enabled by default for new Dart imports. Unknown formats, unadapted roots or invalid cluster data are rejected;
L1 remains independent. A successful run reports function-name, string and pool-slot counts
and `Root stream fully consumed` in the console. `L2 rejected` means no L2 data was published.
Repeating the same input is harmless. If published snapshot
bytes or mappings change, L2 preserves the existing generation and rejects replacement;
use a fresh import for changed binaries or an older published fact generation. Format profiles cover selected SDK layouts,
not every release between 2.10 and 3.13.

Supported stack-check and write-barrier call sites receive local
contracts; direct shared helpers require matching saves, restores and result slots.
Unresolved indirect destinations remain indirect. L2/L3 metadata can add stronger facts.

## b4a integration (L3)

Run **Analysis → One Shot → Dart b4a Import** on a matching ARM64 ELF or Mach-O.
A sidecar beside the binary enables it by default; saved analyzer choices take precedence.
Manual One Shot execution remains available. The original file identity and
loaded RVA checks must agree. Import is transactional; cancellation or failure rolls
back its changes. The same document is skipped on repeat. A different document
requires a fresh database so existing user changes are not silently replaced.
Large exports may take minutes and need disk-backed temporary space; a small
RAM-backed `/tmp` can fill. Set Java's `-Djava.io.tmpdir=/path/on/disk` before
starting Ghidra when needed.

Browse **Symbol Tree → Namespaces → Packages / SDK / App → path → class**
for methods and aliases, and **Data Type Manager → Dart → B4a → Classes** for raw
class layouts. There is no parallel `Entries` tree. Exported functions without a
class declaration use `Runtime` as a fallback. User edits are preserved.

IL and operand descriptions appear in the Listing's **Dart Analysis** field,
not in ordinary comments consumed by the decompiler. **DartViewsPlugin** installs
this field when a Dart program opens; enable the plugin under **File → Configure**
if needed. Full records remain available through **Dart → Show Dart Records**.
JSON headers, code-unit records and empty padding do not create visible data slots.

L2 and L3 share the library/class tree. L3 supplies preferred names, declarations
and boundaries; L2 supplies decoded objects, real string bytes and pool identity.
L2 also contributes alternate entries and disjoint helpers missing from the export,
without replacing existing function bodies. Class scopes/records are joined by CID.
Exported Thread/pool descriptions stay in the Listing. Where an L2-proved PP access
matches an exported offset, its description is attached to that same scoped slot.
No `B4aValues` copy or description-address reference is created. Code-to-character
references continue to use the original file-backed strings.

Serialized Class/Function/Code identities and pool relationships are retained in a
separate bidirectional index. Internal `OTHER` keys identify database records; no
analysis-owned object edges appear in ordinary XREFs or the namespace tree.
User-created references and labels are preserved. Raw class layouts live in the
Data Type Manager. `objs.txt` is an instance text dump; the JSON supplies class
metadata and L2 supplies the object graph.
If snapshot decoding is unavailable, L3 names and annotations still work, but missing
object addresses are not fabricated. Run **Dart ABI** as usual.

Reimporting the same document upgrades the old zero-slot/text-overlay presentation
while preserving user code names/comments. Modified synthetic metadata is rejected
rather than discarded. Then run **Dart AOT Objects** to refresh L2. Existing generated
object references and namespace scaffolding migrate transactionally; user-owned symbols and references
are retained.

Imported IL currently records a range, kind and display text. It is retained as
analysis evidence, not executed as replacement P-code. Semantic lifting requires
structured operands, widths and side effects plus validation against the instructions.

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

Sources are organized under `src/main/java/ghidart/`:

- `analysis/`: function discovery, ABI, value/object uses and P-code injection.
- `snapshot/`: L2 format profiles, decoding, objects, types and database publication.
- `importer/`: ELF loading, b4a validation and semantic import.
- `datatype/`: explicit-length character data types.
- `listing/`: native Console actions and the operand field retained for saved layouts.

Shared logging lives in `analysis/`. Moved character and operand classes register
Ghidra class-name translations for existing databases and layouts.

Language definitions are in `data/languages/`.
The build references the installed official ARM64 sources through Ghidra's module
macro. A small SLEIGH wrapper exposes equivalent signed-word arithmetic; it keeps
instruction encodings and register storage unchanged.
See [B4A_INTERFACE.md](B4A_INTERFACE.md) for the b4a data format.

Samples and verification tools are local development materials, excluded from Git
and extension packages. When `tests/VerifyB4a.java` is available locally,
`./gradlew --no-daemon verifySamples -PsamplesDir=/path/to/samples` checks paired
binary/JSON identities without running Ghidra analysis. See [LICENSE](LICENSE)
for licensing and template attribution.

English is the default documentation language. Keep this README and
[README.zh-CN.md](README.zh-CN.md) synchronized whenever either changes.
Interface, sample and test documentation is maintained in English only.
