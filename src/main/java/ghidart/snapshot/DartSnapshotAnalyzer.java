package ghidart.snapshot;

import com.google.gson.Gson;
import ghidart.analysis.DartAnalysisLog;
import ghidart.analysis.DartFunctionAnalyzer;
import ghidart.analysis.DartPoolReferences;
import ghidart.datatype.DartLatin1DataType;
import ghidart.datatype.DartUtf16DataType;
import ghidart.importer.DartAotAnalyzer;
import ghidart.importer.DartCodeIndex;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * L2 producer: validate serialized AOT facts before touching the database.
 *
 * <p>L1 never invokes this reader. ELF and Mach-O supply the same mapped snapshot
 * symbols. Parsed strings retain their serialized byte addresses, while logical
 * object identities live in non-loaded OTHER memory: they are not runtime heap
 * addresses and cannot accidentally participate in debugger module mappings.
 * Functions use the same bounded publisher as b4a; this class owns no CFG engine.
 */
public final class DartSnapshotAnalyzer extends AbstractAnalyzer {
  private static final String FACTS = "ghidart.L2.objects.v1";
  private static final String OWNER = "ghidart.L2";
  private static final int FACT_GENERATION = 10;
  private static final Gson JSON = new Gson();
  private static final String PARENT_FILE = "Parent AOT file";
  private String parentFile = "";

  public record Snapshot(String scope, Address data, Address instructions, byte[] bytes,
      DartClusterParser.Result objects, DartInstructionsTable table,
      List<DartCodeIndex.CodeUnit> units, boolean vmReferences, String identity) {}

  /** Only complete, unambiguous scopes may survive another scope's rejection. */
  private record Recovery(List<Snapshot> snapshots, String failure) {}

  public DartSnapshotAnalyzer() {
    super("Dart AOT Objects", "Read validated AOT boundaries, objects, pools and strings (L2).",
        AnalyzerType.BYTE_ANALYZER);
    setPriority(AnalysisPriority.DISASSEMBLY.before().before());
    setSupportsOneTimeAnalysis();
  }

  @Override
  public boolean canAnalyze(Program program) {
    return "AARCH64:LE:64:dart".equals(program.getLanguageID().toString());
  }

  @Override
  public boolean getDefaultEnablement(Program program) {
    return false;
  }

  @Override
  public void registerOptions(Options options, Program program) {
    options.registerOption(PARENT_FILE, "", null,
        "Parent AOT binary for a non-root loading unit. Empty uses the standard sibling filename.");
  }

  @Override
  public void optionsChanged(Options options, Program program) {
    parentFile = options.getString(PARENT_FILE, "");
  }

  @Override
  public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
      throws CancelledException {
    try (var output = new DartAnalysisLog(program, log)) {
      try {
        Recovery recovery = DartLoadingUnits.isUnit(program, parentFile)
            ? new Recovery(DartLoadingUnits.read(program, parentFile, monitor), "")
            : readForPublication(program, monitor);
        List<Snapshot> snapshots = recovery.snapshots();
        if (snapshots.isEmpty()) {
          recoverL1(program, "UNAVAILABLE", "No mapped AOT snapshot symbols", monitor, output.messages());
          return true;
        }
        // Cluster decoding, reference bounds and image ranges are checked before the
        // transaction. No weak caches or partial Results escape this pass.
        int transaction = program.startTransaction("Publish Dart AOT objects");
        boolean commit = false;
        try (var graph = DartObjectGraph.batch(program, monitor)) {
          DartObjectGraph.migrate(program, monitor);
          ghidart.listing.DartNamespaces.migrate(program, monitor);
          for (Snapshot snapshot : snapshots) publish(program, snapshot, monitor, output.messages());
          DartAotAnalyzer.shortenEntryLabels(program, monitor);
          boolean slotDisplay = enhance(program, OWNER + ".slotDisplay", 1, "slot display", () -> {
            ghidart.listing.DartSlotViews.upgradeAnchors(program, monitor);
          }, output.messages());
          ghidart.importer.B4aImporter.restoreModelReferences(program, monitor);
          monitor.checkCancelled();
          boolean partial = !recovery.failure().isEmpty() || !slotDisplay
              || snapshots.stream().anyMatch(snapshot -> program.getOptions(OWNER)
                  .getBoolean(OWNER + "." + snapshot.scope() + ".partial", false));
          var options = program.getOptions(OWNER);
          options.setString("L2.status", partial ? "PARTIAL" : "PUBLISHED");
          if (recovery.failure().isEmpty()) {
            options.removeOption("L2.recovery.error");
          } else {
            options.setString("L2.recovery.error", recovery.failure());
            logRecovery(program, snapshots, recovery.failure(), monitor, output.messages());
          }
          graph.flush();
          monitor.checkCancelled();
          commit = true;
        } finally {
          program.endTransaction(transaction, commit);
        }
        return true;
      } catch (IOException | IllegalArgumentException | MemoryAccessException e) {
        monitor.checkCancelled();
        recoverL1(program, "REJECTED", "L2 rejected: " + e.getMessage(), monitor, output.messages());
        return false;
      }
    }
  }

  /** Rejection never edits a published generation. New inputs can use bounded L1.
   * Own the transaction as well as the publication path: direct scripts and
   * independent ProgramDB callers need not already have an analysis transaction.
   */
  private static void recoverL1(Program program, String status, String reason,
      TaskMonitor monitor, MessageLog log) throws CancelledException {
    int transaction = program.startTransaction("Coordinate Dart L1 recovery");
    boolean commit = false;
    try {
      program.getOptions(OWNER).setString("L2.status", status);
      boolean published = java.util.Arrays.stream(program.getMemory().getBlocks())
          .anyMatch(block -> block.getName().startsWith("DartObjects_"));
      var managed = findManagedExecutableRange(program);
      if (published) {
        log.appendMsg("Dart AOT Objects", reason
            + "; existing L2 generation preserved; automatic recovery was not run.");
      } else if (!managed.isEmpty()) {
        log.appendMsg("Dart AOT Objects", reason + "; running L1 recovery in bounded instruction image.");
        DartFunctionAnalyzer.recover(program, new AddressSet(), managed, true, monitor, log);
      } else {
        log.appendMsg("Dart AOT Objects", reason + "; select managed code region for L1 recovery.");
      }
      monitor.checkCancelled();
      commit = true;
    } finally {
      program.endTransaction(transaction, commit);
    }
  }

  /** A symbol locates an image, never the containing native text block.
   * The image's own bounded envelope is independent of clustered object layouts.
   * Missing/invalid envelopes leave recovery to an explicit user selection.
   */
  private static AddressSet findManagedExecutableRange(Program program) {
    AddressSet range = new AddressSet();
    for (String name : List.of(
        "kDartVmSnapshotInstructions", "kDartIsolateSnapshotInstructions", "kDartSnapshotText",
        "_kDartVmSnapshotInstructions", "_kDartIsolateSnapshotInstructions", "_kDartSnapshotText")) {
      for (var symbol : program.getSymbolTable().getGlobalSymbols(name)) {
        if (symbol.getSource() != SourceType.IMPORTED) continue;
        Address start = symbol.getAddress();
        try {
          long size = new DartStream(bytes(program, start, 32)).readInt64();
          if (size < 32 || (size & 15) != 0 || size > Integer.MAX_VALUE) continue;
          Address end = start.addNoWrap(size - 1);
          if (program.getMemory().getExecuteSet().contains(start, end)) {
            range.add(start.add(32), end);
          }
        } catch (IOException | MemoryAccessException
            | ghidra.program.model.address.AddressOverflowException e) {
          // A modified image without an independently bounded envelope is not
          // permission to scan unrelated native instructions.
        }
      }
    }
    return range;
  }

  /** An isolate uses the VM reference table, but a VM snapshot is self-contained.
   * Retry only that independently framed scope after full-input rejection. Every
   * candidate must finish its objects, roots and instruction validation; a hash
   * never authorizes publishing a prefix or choosing between conflicting facts.
   * Loading units deliberately keep their existing parent validation path.
   */
  private static Recovery readForPublication(Program program, TaskMonitor monitor)
      throws IOException, MemoryAccessException, CancelledException {
    try {
      return new Recovery(read(program, monitor), "");
    } catch (IOException rejected) {
      Address data = symbol(program, "kDartVmSnapshotData");
      if (data == null) throw rejected; // Merged snapshots have no independent prefix.
      var envelope = DartSnapshotHeader.inspect(clusteredBytes(program, data), 0, true);
      Snapshot selected = null;
      String meaning = null;
      for (var profile : DartVersionProfile.candidates(envelope)) {
        monitor.checkCancelled();
        Snapshot candidate;
        try {
          candidate = read(program, "vm", data, symbol(program, "kDartVmSnapshotInstructions"),
              null, true, profile, monitor);
        } catch (IOException | IllegalArgumentException | MemoryAccessException e) {
          continue;
        }
        String facts = interpretation(List.of(candidate));
        if (selected != null && !meaning.equals(facts)) {
          throw new IOException("ambiguous independent VM layouts; " + rejected.getMessage(), rejected);
        }
        if (selected == null) {
          selected = candidate;
          meaning = facts;
        }
      }
      if (selected == null) throw rejected;
      return new Recovery(List.of(selected), rejected.getMessage());
    }
  }

  /** L1 may cover the rejected scope, never replace the retained L2 scope. */
  private static void logRecovery(Program program, List<Snapshot> retained, String reason,
      TaskMonitor monitor, MessageLog log)
      throws CancelledException {
    log.appendMsg("Dart AOT Objects", "L2 partial: independent VM facts retained; " + reason);
    if (program.getMemory().getBlock("DartObjects_isolate") != null
        && program.getOptions(OWNER).contains(OWNER + ".isolate")) {
      log.appendMsg("Dart AOT Objects",
          "Existing isolate generation preserved; automatic L1 recovery was not run.");
      return;
    }
    var remaining = findManagedExecutableRange(program);
    for (var snapshot : retained) {
      long end = snapshot.table().uniqueRanges.stream()
          .mapToLong(range -> range.pcOffset + range.size).max().orElse(0);
      if (end > 0) remaining.delete(snapshot.instructions(), snapshot.instructions().add(end - 1));
    }
    if (!remaining.isEmpty()) {
      log.appendMsg("Dart AOT Objects", "Running bounded L1 only in the unpublished instruction image.");
      DartFunctionAnalyzer.recover(program, new AddressSet(), remaining, true, monitor, log);
    }
  }

  static List<Snapshot> read(Program program, TaskMonitor monitor)
      throws IOException, MemoryAccessException, CancelledException {
    Address data = symbol(program, "kDartVmSnapshotData");
    if (data == null) data = symbol(program, "kDartIsolateSnapshotData");
    if (data == null) data = symbol(program, "kDartSnapshotData");
    if (data == null) return List.of();
    var envelope = DartSnapshotHeader.inspect(clusteredBytes(program, data), 0, false);
    List<Snapshot> selected = null;
    String interpretation = null;
    var failures = new ArrayList<String>();
    for (var profile : DartVersionProfile.candidates(envelope)) {
      monitor.checkCancelled();
      List<Snapshot> candidate;
      try {
        candidate = read(program, profile, monitor);
      } catch (IOException | IllegalArgumentException | MemoryAccessException e) {
        failures.add(profile.dartVersion + ": " + e.getMessage());
        continue;
      }
      // A matching hash is an optimization only after complete decoding and validation.
      if (DartVersionProfile.isHashHint(envelope, profile)) return candidate;
      String facts = interpretation(candidate);
      if (selected != null && !interpretation.equals(facts)) {
        throw new IOException("ambiguous AOT layouts: "
            + selected.getFirst().objects().profile.dartVersion + " / " + profile.dartVersion);
      }
      if (selected == null) {
        selected = candidate;
        interpretation = facts;
      }
    }
    if (selected != null) return selected;
    throw new IOException("no validated AOT format (" + String.join("; ", failures) + ")");
  }

  /** Compare retained meanings, not candidate version labels or a plausible first cluster. */
  private static String interpretation(List<Snapshot> snapshots) throws IOException {
    var factsJson = new com.google.gson.GsonBuilder()
        .addSerializationExclusionStrategy(new com.google.gson.ExclusionStrategy() {
          @Override
          public boolean shouldSkipClass(Class<?> type) {
            return false;
          }

          @Override
          public boolean shouldSkipField(com.google.gson.FieldAttributes field) {
            return field.getDeclaringClass() == DartClusterParser.Result.class
                && Set.of("profile", "header", "vm", "diagnostics").contains(field.getName());
          }
        }).create();
    MessageDigest digest = digest();
    try (var writer = new java.io.OutputStreamWriter(new java.security.DigestOutputStream(
        java.io.OutputStream.nullOutputStream(), digest), java.nio.charset.StandardCharsets.UTF_8)) {
      for (var snapshot : snapshots) {
        var objects = snapshot.objects();
        factsJson.toJson(objects, writer);
        factsJson.toJson(snapshot.table(), writer);
        factsJson.toJson(snapshot.units(), writer);
        // Layout-dependent interpretations must agree as well as raw records.
        // Otherwise identical bytes could silently acquire different class/value links.
        var typeClasses = new java.util.TreeMap<Integer, Integer>();
        for (var type : objects.types) typeClasses.put(type.refId, objects.typeClassId(type));
        factsJson.toJson(typeClasses, writer);
        var fieldStorage = new java.util.TreeMap<Integer, DartClusterParser.FieldStorage>();
        for (var field : objects.fields) fieldStorage.put(field.refId, objects.fieldStorage(field));
        factsJson.toJson(fieldStorage, writer);
      }
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  private static List<Snapshot> read(Program program, DartVersionProfile profile, TaskMonitor monitor)
      throws IOException, MemoryAccessException, CancelledException {
    var result = new ArrayList<Snapshot>();
    DartClusterParser.Result vm = null;
    Address vmData = symbol(program, "kDartVmSnapshotData");
    if (vmData != null) {
      Snapshot snapshot = read(program, "vm", vmData,
          symbol(program, "kDartVmSnapshotInstructions"), null, true, profile, monitor);
      result.add(snapshot);
      vm = snapshot.objects();
    }
    Address isolate = symbol(program, "kDartIsolateSnapshotData");
    Address instructions = symbol(program, "kDartIsolateSnapshotInstructions");
    if (isolate == null) {
      isolate = symbol(program, "kDartSnapshotData");
      instructions = symbol(program, "kDartSnapshotText");
    }
    if (isolate != null) result.add(read(program, "isolate", isolate, instructions, vm, false, profile, monitor));
    return List.copyOf(result);
  }

  private static Snapshot read(Program program, String scope, Address data, Address instructions,
      DartClusterParser.Result vm, boolean isVm, DartVersionProfile profile, TaskMonitor monitor)
      throws IOException, MemoryAccessException, CancelledException {
    return read(program, scope, data, instructions, vm, isVm, profile, monitor, false);
  }

  static Snapshot readUnit(Program program, DartClusterParser.Result parent, String parentIdentity, TaskMonitor monitor)
      throws IOException, MemoryAccessException, CancelledException {
    Address data = symbol(program, "kDartIsolateSnapshotData");
    Address instructions = symbol(program, "kDartIsolateSnapshotInstructions");
    if (data == null) {
      data = symbol(program, "kDartSnapshotData");
      instructions = symbol(program, "kDartSnapshotText");
    }
    var unit = read(program, "isolate", data, instructions, parent, false, parent.profile, monitor, true);
    MessageDigest identity = digest();
    identity.update(unit.identity().getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    identity.update(parentIdentity.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    return new Snapshot(unit.scope(), unit.data(), unit.instructions(), unit.bytes(), unit.objects(),
        unit.table(), unit.units(), unit.vmReferences(), HexFormat.of().formatHex(identity.digest()));
  }

  private static Snapshot read(Program program, String scope, Address data, Address instructions,
      DartClusterParser.Result vm, boolean isVm, DartVersionProfile profile, TaskMonitor monitor,
      boolean unit) throws IOException, MemoryAccessException, CancelledException {
    if (data == null) throw new IOException("missing " + scope + " data image");
    if (instructions == null) throw new IOException("missing " + scope + " instruction image");
    monitor.setMessage("Reading Dart " + scope + " snapshot (layout " + profile.dartVersion + ")");
    byte[] clustered = clusteredBytes(program, data);
    var header = unit ? DartSnapshotHeader.parseLoadingUnit(clustered, 0, profile)
        : DartSnapshotHeader.parse(clustered, 0, profile, isVm);
    if (header.featureFlags.stream().noneMatch(flag -> flag.equals("arm64") || flag.startsWith("arm64-"))) {
      throw new IOException("snapshot is not ARM64");
    }
    long imageOffset = DartInstructionsTable.roundUp(header.totalSize, header.profile.topLevelCid16 ? 16 : 64);
    long imageSize = new DartStream(bytes(program, data.add(imageOffset), 8)).readInt64();
    if (imageSize < 16 || imageSize > Integer.MAX_VALUE - imageOffset) {
      throw new IOException("invalid read-only data image extent");
    }
    byte[] input = bytes(program, data, (int) (imageOffset + imageSize));
    monitor.checkCancelled();
    if (vm != null && header.numBaseObjects != vm.header.numObjects) {
      throw new IOException("VM / isolate base-reference counts differ");
    }
    var objects = DartClusterParser.parseSnapshot(input, header, header.profile, vm, monitor::isCancelled);
    if (objects.roots == null) {
      throw new IOException("root layout is not yet adapted for Dart " + header.profile.dartVersion
          + "; no L2 facts published");
    }
    var table = header.profile.codeTextOffsetDelta
        ? DartInstructionsTable.fromCodeEntries(objects.codes)
        : DartInstructionsTable.parse(input, header, header.profile);
    long end = DartInstructionsTable.readInstructionPayloadEnd(
        bytes(program, instructions, 0x80), 0, header.profile);
    if (end <= 0 || !program.getMemory().getExecuteSet().contains(instructions, instructions.add(end - 1))) {
      throw new IOException("instruction payload is not mapped executable memory");
    }
    try {
      table = table.withInstructionLimit(end);
    } catch (IOException e) {
      throw new IOException(scope + " instructions at " + instructions + ": " + e.getMessage(), e);
    }
    long mainCodes = objects.codes.stream().filter(code -> code.clusterIndex >= 0).count();
    if (mainCodes != table.length - table.firstEntryWithCode) {
      throw new IOException("Code / instruction table cardinality differs");
    }
    for (var declaration : objects.namedObjects) {
      monitor.checkCancelled();
      if (declaration.cid != objects.profile.cids.function) continue;
      var record = objects.object(declaration.refId);
      if (record != null && record.scalars().length > 0) {
        objects.codeReference(record.scalars()[0], table.firstEntryWithCode);
      }
    }
    var units = boundaries(program, instructions, objects, table);
    MessageDigest digest = digest();
    digest.update(input);
    byte[] chunk = new byte[65536];
    for (long offset = 0; offset < end; offset += chunk.length) {
      monitor.checkCancelled();
      int count = (int) Math.min(chunk.length, end - offset);
      if (program.getMemory().getBytes(instructions.add(offset), chunk, 0, count) != count) {
        throw new IOException("truncated instruction image");
      }
      digest.update(chunk, 0, count);
    }
    return new Snapshot(scope, data, instructions, input, objects, table, units, vm != null && !unit,
        HexFormat.of().formatHex(digest.digest()));
  }

  private static byte[] clusteredBytes(Program program, Address data)
      throws IOException, MemoryAccessException {
    var stream = new DartStream(bytes(program, data, 20));
    if (stream.readInt32() != DartSnapshotHeader.SNAPSHOT_MAGIC) throw new IOException("snapshot magic");
    long length = stream.readInt64();
    if (length < 49 || length > Integer.MAX_VALUE - 4L) throw new IOException("snapshot extent");
    return bytes(program, data, (int) length + 4);
  }

  private static List<DartCodeIndex.CodeUnit> boundaries(Program program, Address image,
      DartClusterParser.Result objects, DartInstructionsTable table) throws IOException {
    Map<Integer, DartClusterParser.CodeEntry> codes = new LinkedHashMap<>();
    for (var code : objects.codes) if (code.clusterIndex >= 0) codes.put(code.clusterIndex, code);
    var units = new ArrayList<DartCodeIndex.CodeUnit>();
    long base = image.subtract(program.getImageBase());
    for (var range : table.uniqueRanges) {
      long start = base + range.pcOffset;
      long end = start + range.size;
      var roles = new java.util.TreeMap<Long, java.util.LinkedHashSet<String>>();
      Long primary = null;
      for (int slot : range.slots) {
        var code = codes.get(slot - table.firstEntryWithCode);
        if (code == null) continue;
        boolean mono = (code.payloadInfo & 1) != 0;
        long normal = start + objects.profile.normalEntryOffset(code.payloadInfo);
        long unchecked = code.payloadInfo >>> 1;
        addEntry(roles, normal, "normal", start, end);
        addEntry(roles, normal + unchecked, "unchecked", start, end);
        // ReadInstructions initializes all four cached entries even when they
        // coincide. Preserve their roles rather than dropping aliased entries.
        if (mono) addEntry(roles, start, "switchable_miss", start, end);
        long monomorphic = start + (mono ? 8 : 0);
        addEntry(roles, monomorphic, "monomorphic", start, end);
        addEntry(roles, monomorphic + unchecked, "monomorphic_unchecked", start, end);
        if (primary == null) primary = normal;
        for (int pc : objects.exceptionEntries(code.exceptionRef)) {
          addEntry(roles, start + pc, "exception", start, end);
        }
      }
      if (primary == null) {
        primary = start;
        addEntry(roles, start, "normal", start, end);
      }
      var entries = roles.entrySet().stream()
          .map(entry -> new DartCodeIndex.Entry(entry.getKey(), Set.copyOf(entry.getValue()))).toList();
      units.add(new DartCodeIndex.CodeUnit(start, end, primary, entries));
    }
    return List.copyOf(units);
  }

  private static void addEntry(Map<Long, java.util.LinkedHashSet<String>> entries, long address,
      String role, long start, long end) throws IOException {
    if (address < start || address >= end || (address & 3) != 0) {
      throw new IOException(role + " entry outside owning payload");
    }
    entries.computeIfAbsent(address, ignored -> new java.util.LinkedHashSet<>()).add(role);
  }

  private static void publish(Program program, Snapshot snapshot, TaskMonitor monitor, MessageLog log)
      throws CancelledException, IOException, MemoryAccessException {
    String option = OWNER + "." + snapshot.scope();
    String identity = FACT_GENERATION + ":" + snapshot.identity() + ":"
        + snapshot.data() + ":" + snapshot.instructions();
    // Older published facts used +24 even for the +20 ARM64 entry prefix.
    // Do not silently retain their stale boundaries, call targets or user edits.
    if (snapshot.objects().profile.normalEntryOffset(1) == 20) identity += ":arm64-entry20";
    String previous = program.getOptions(OWNER).getString(option, "");
    if (identity.equals(previous)) {
      enrich(program, snapshot, monitor, log);
      log.appendMsg("Dart AOT Objects", snapshot.scope() + ": validated facts already published.");
      return;
    }
    // Never silently overwrite a previous generation, which may have user edits.
    if (!previous.isEmpty()) {
      if (identity.endsWith(":arm64-entry20") && !previous.endsWith(":arm64-entry20")) {
        throw new IOException("older ARM64 L2 facts used +24 instead of +20 normal entries; "
            + "existing analysis preserved; use a fresh import");
      }
      throw new IOException("snapshot/schema changed; existing L2 generation preserved; use a fresh import");
    }
    String blockName = "DartObjects_" + snapshot.scope();
    if (program.getMemory().getBlock(blockName) != null) throw new IOException("object block name conflict");
    var objects = snapshot.objects();
    long references = objects.header.numObjects + 1;
    var roots = objects.roots;
    long rootSlots = roots == null ? 0 : (long) roots.references().size()
        + roots.staticFields().length + roots.sharedStaticFields().length
        + roots.dispatchCodeIndices().length;
    long size = Math.multiplyExact(references + objects.imagePoolEntries().size() + rootSlots, 8L);
    // Separate serialized scopes without creating new address spaces. Ghidra
    // 12.2 leaves stale address-set ranges when an OTHER overlay is rolled back.
    // These addresses describe database identities only, never runtime pointers.
    long scopeStart = snapshot.scope().equals("vm") ? 0x1_0000_0000L : 0x2_0000_0000L;
    if (size > 0x1_0000_0000L) throw new IOException("logical object scope is too large");
    Address zero = program.getAddressFactory().getAddressSpace("OTHER").getAddress(scopeStart);
    MemoryBlock block;
    try {
      block = program.getMemory().createInitializedBlock(blockName, zero, size, (byte) 0, monitor, false);
    } catch (ghidra.framework.store.LockException | ghidra.program.model.mem.MemoryConflictException
        | ghidra.program.model.address.AddressOverflowException e) {
      throw new IOException("cannot create logical object block", e);
    }
    block.setRead(true);
    block.setWrite(false);
    block.setExecute(false);
    block.setArtificial(true);
    block.setComment("ghidart L2 logical object identities, NOT runtime heap addresses. " + identity);
    Address anchor = block.getStart();
    StringPropertyMap facts = property(program);
    detail(facts, anchor, "clusters", objects.clusters);
    var identityType = new StructureDataType("DartSerializedObjectId", 0);
    identityType.add(DWordDataType.dataType, "reference", "Serialized identity, not a heap pointer");
    identityType.add(DWordDataType.dataType, "cid", "Serialized cluster class ID");
    byte[] identities = new byte[Math.toIntExact(references * 8)];
    var identityBytes = java.nio.ByteBuffer.wrap(identities).order(java.nio.ByteOrder.LITTLE_ENDIAN);
    for (int ref = 0; ref < references; ref++) {
      identityBytes.putInt(ref * 8, ref);
      // Base references have no local cluster. Do not mislabel them as CID 0.
      identityBytes.putInt(ref * 8 + 4, -1);
    }
    if (objects.header.isLoadingUnit) {
      for (var parent = objects.vm; parent != null; parent = parent.vm) {
        for (var object : parent.objects.values()) {
          monitor.checkCancelled();
          identityBytes.putInt(object.refId() * 8 + 4, object.cid());
          detail(facts, anchor.add(object.refId() * 8L), "inherited", object);
          for (int ref : object.references()) if (ref > 0) {
            reference(program, anchor.add(object.refId() * 8L), anchor.add(ref * 8L));
          }
        }
        for (var string : parent.strings) {
          // Parent character bytes belong to another file, not this image.
          // Retain the complete value without inventing a local heap address.
          detail(facts, anchor.add(string.refId * 8L), "inheritedString",
              Map.of("value", string.value, "encoding", string.isOneByte ? "latin1" : "utf16le"));
        }
      }
    }
    for (var cluster : objects.clusters) {
      for (int ref = cluster.startRef; ref < cluster.stopRef; ref++) identityBytes.putInt(ref * 8 + 4, cluster.cid);
    }
    program.getMemory().setBytes(anchor, identities);
    if (snapshot.vmReferences()) {
      MemoryBlock vmBlock = program.getMemory().getBlock("DartObjects_vm");
      if (vmBlock != null && program.getOptions(OWNER).contains(OWNER + ".vm")) {
        // ProgramDeserializationRoots carries the entire VM reference table,
        // preserving its indices. The count was checked before publication.
        for (int ref = 1; ref <= objects.header.numBaseObjects; ref++) {
          monitor.checkCancelled();
          reference(program, anchor.add((long) ref * 8), vmBlock.getStart().add((long) ref * 8));
        }
      }
    }
    try {
      program.getListing().createData(anchor, new ArrayDataType(identityType, (int) references, 8));
    } catch (ghidra.program.model.util.CodeUnitInsertionException e) {
      throw new IOException("object identity table collision", e);
    }
    monitor.initialize(objects.strings.size(), "Publishing Dart string identities");
    for (var string : objects.strings) {
      monitor.checkCancelled();
      Address object = anchor.add((long) string.refId * 8);
      Address payload = snapshot.data().add(string.dataOffset);
      facts.add(object, JSON.toJson(Map.of("kind", "String", "payload", payload.toString(),
          "length", string.value.length(), "encoding", string.isOneByte ? "latin1" : "utf16le")));
      reference(program, object, payload);
      monitor.increment();
    }
    for (var cls : objects.classes) {
      facts.add(anchor.add((long) cls.refId * 8), JSON.toJson(Map.of("kind", "Class", "object", cls)));
    }
    for (var field : objects.fields) {
      monitor.checkCancelled();
      Address address = anchor.add((long) field.refId * 8);
      facts.add(address, JSON.toJson(Map.of("kind", "Field", "object", field)));
      var storage = objects.fieldStorage(field);
      detail(facts, address, "storage", storage);
      if (field.typeRefId > 0) {
        reference(program, address, anchor.add((long) field.typeRefId * 8));
      }
      if (storage.initialValueRef() != null && storage.initialValueRef() > 0) {
        reference(program, address, anchor.add(storage.initialValueRef() * 8L));
      }
    }
    for (var named : objects.namedObjects) {
      monitor.checkCancelled();
      Address address = anchor.add((long) named.refId * 8);
      detail(facts, address, "declaration", named);
      for (int ref : new int[] {named.nameRefId, named.ownerRefId, named.signatureRefId}) {
        if (ref > 0) reference(program, address, anchor.add((long) ref * 8));
      }
    }
    for (var type : objects.types) {
      monitor.checkCancelled();
      Address address = anchor.add((long) type.refId * 8);
      detail(facts, address, "type", type);
      Integer classRef = objects.classRefByCid.get(objects.typeClassId(type));
      if (classRef != null) reference(program, address, anchor.add((long) classRef * 8));
      for (int ref : type.refs) {
        if (ref > 0) reference(program, anchor.add((long) type.refId * 8), anchor.add((long) ref * 8));
      }
    }
    for (var signature : objects.funcTypes) {
      monitor.checkCancelled();
      // Logical Dart counts are metadata, never a physical ABI prototype.
      detail(facts, anchor.add((long) signature.refId * 8), "signature", signature);
    }
    for (var mint : objects.mintValues.entrySet()) {
      monitor.checkCancelled();
      detail(facts, anchor.add((long) mint.getKey() * 8), "integer", mint.getValue());
    }
    for (var code : objects.codes) {
      monitor.checkCancelled();
      Address object = anchor.add((long) code.refId * 8);
      detail(facts, object, "kind", "Code");
      detail(facts, object, "object", code);
      if (code.ownerRef > 0) reference(program, object, anchor.add((long) code.ownerRef * 8));
      Address target = codeTarget(snapshot, code);
      if (target != null) reference(program, object, target);
      if (code.exceptionRef > 0) reference(program, object, anchor.add((long) code.exceptionRef * 8));
      if (code.clusterIndex < 0) continue;
      int slot = code.clusterIndex + snapshot.table().firstEntryWithCode;
      long pc = snapshot.table().entries.get(slot).pcOffset();
      reference(program, object, snapshot.instructions().add(pc));
    }
    for (var handlers : objects.exceptionEntries.entrySet()) {
      facts.add(anchor.add((long) handlers.getKey() * 8), JSON.toJson(Map.of("kind", "ExceptionHandlers", "offsets", handlers.getValue())));
    }
    int position = 0;
    Map<Integer, Address> pools = new LinkedHashMap<>();
    for (var entry : objects.imagePoolEntries()) {
      monitor.checkCancelled();
      Address slot = anchor.add((references + position++) * 8);
      pools.putIfAbsent(entry.poolRef, slot);
      facts.add(slot, JSON.toJson(entry));
      try {
        program.getListing().createData(slot, QWordDataType.dataType);
      } catch (ghidra.program.model.util.CodeUnitInsertionException e) {
        throw new IOException("logical slot collision", e);
      }
      program.getMemory().setLong(slot, entry.kind == DartClusterParser.PoolEntryKind.IMMEDIATE ? entry.imm : entry.refId);
      if (entry.kind == DartClusterParser.PoolEntryKind.TAGGED && entry.refId > 0) {
        reference(program, slot, anchor.add((long) entry.refId * 8));
      }
    }
    for (var pool : pools.entrySet()) {
      Address object = anchor.add((long) pool.getKey() * 8);
      reference(program, object, pool.getValue());
      detail(facts, object, "kind", "ObjectPool");
      detail(facts, object, "firstSlot", pool.getValue().toString());
    }
    monitor.initialize(objects.objects.size(), "Publishing Dart serialized object fields");
    for (var object : objects.objects.values()) {
      monitor.checkCancelled();
      Address address = anchor.add((long) object.refId() * 8);
      detail(facts, address, "serialized", object);
      // Instance clusters encode their Class via CID, not a serialized reference.
      if (object.cid() >= objects.profile.cids.numPredefinedCids) {
        Integer classRef = objects.classRefByCid.get(object.cid());
        if (classRef != null) reference(program, address, anchor.add((long) classRef * 8));
      }
      for (int ref : object.references()) {
        if (ref > 0) reference(program, address, anchor.add((long) ref * 8));
      }
      if (object.dataOffset() >= 0) {
        reference(program, address, snapshot.data().add(object.dataOffset()));
      }
      monitor.increment();
    }
    if (roots != null) {
      detail(facts, anchor, "roots", roots);
      if (roots.unit() != null) {
        for (var patches : List.of(roots.unit().codeSourceMaps(), roots.unit().codeStackMaps())) {
          for (var patch : patches.entrySet()) {
            reference(program, anchor.add(patch.getKey() * 8L), anchor.add(patch.getValue() * 8L));
          }
        }
      }
      Address slot = anchor.add((references + objects.imagePoolEntries().size()) * 8);
      monitor.initialize(rootSlots, "Publishing Dart roots and dispatch table");
      for (var root : roots.references().entrySet()) {
        rootSlot(program, facts, slot, anchor, root.getKey(), root.getValue(), true);
        slot = slot.add(8);
        monitor.checkCancelled();
        monitor.increment();
      }
      int[][] fieldTables = {roots.staticFields(), roots.sharedStaticFields()};
      for (int table = 0; table < fieldTables.length; table++) {
        String name = table == 0 ? "static_fields" : "shared_static_fields";
        for (int index = 0; index < fieldTables[table].length; index++) {
          rootSlot(program, facts, slot, anchor, name + "[" + index + "]", fieldTables[table][index], true);
          slot = slot.add(8);
          monitor.checkCancelled();
          monitor.increment();
        }
      }
      long[] dispatch = roots.dispatchCodeIndices();
      Map<Long, Address> targets = dispatchTargets(snapshot);
      for (int index = 0; index < dispatch.length; index++) {
        // These are Code indices, not snapshot reference IDs or addresses.
        rootSlot(program, facts, slot, anchor, "dispatch[" + index + "]", dispatch[index], false);
        Address target = targets.get(dispatch[index]);
        if (target != null) {
          reference(program, slot, target);
          detail(facts, slot, "target", target.toString());
        }
        slot = slot.add(8);
        monitor.checkCancelled();
        monitor.increment();
      }
    }
    var renameable = new java.util.HashSet<Address>();
    for (var unit : snapshot.units()) {
      Address entry = program.getImageBase().add(unit.primaryEntry());
      var function = program.getFunctionManager().getFunctionAt(entry);
      var symbol = program.getSymbolTable().getPrimarySymbol(entry);
      if (function != null) symbol = function.getSymbol();
      if (symbol == null || symbol.getSource() == SourceType.DEFAULT) {
        renameable.add(entry);
      } else if (symbol.getSource() == SourceType.ANALYSIS
          && symbol.getName().equals("dart_" + Long.toUnsignedString(unit.primaryEntry(), 16))) {
        // L1/b4a's generated address name is ours to enrich. Preserve other
        // analyzers' names as well as imported and user-defined symbols.
        renameable.add(entry);
      }
    }
    // Keep L3-owned bodies intact. L2 may add disjoint payloads absent from the
    // export (notably VM helpers), never another owner for an existing range.
    // A null primary preserves that owner while still contributing L2 alternate
    // entry labels and bounded disassembly, hence their real string/pool references.
    var units = snapshot.units();
    if (ghidart.importer.B4aImporter.isImported(program)) {
      var merged = new java.util.ArrayList<DartCodeIndex.CodeUnit>();
      for (var unit : units) {
        monitor.checkCancelled();
        var body = new AddressSet(program.getImageBase().add(unit.start()),
            program.getImageBase().add(unit.end() - 1));
        merged.add(program.getFunctionManager().getFunctionsOverlapping(body).hasNext()
            ? new DartCodeIndex.CodeUnit(unit.start(), unit.end(), null, unit.entries()) : unit);
      }
      units = merged;
    }
    var stats = units.isEmpty() ? new DartAotAnalyzer.DiscoveryStats()
        : DartAotAnalyzer.applyBoundaries(program, units, monitor, log);
    int named = 0;
    for (int rangeIndex = 0; rangeIndex < snapshot.table().uniqueRanges.size(); rangeIndex++) {
      var range = snapshot.table().uniqueRanges.get(rangeIndex);
      monitor.checkCancelled();
      String name = objects.resolveRangeSymbol(range, snapshot.table().firstEntryWithCode);
      if (name == null) continue;
      // The primary entry may follow a monomorphic preamble. Match the same
      // canonical payload used by the shared boundary publisher.
      var unit = snapshot.units().get(rangeIndex);
      var function = program.getFunctionManager().getFunctionAt(program.getImageBase().add(unit.primaryEntry()));
      if (function == null || !renameable.contains(function.getEntryPoint())) continue;
      try {
        function.setName(ghidra.program.model.symbol.SymbolUtilities.replaceInvalidChars(name, true), SourceType.ANALYSIS);
        named++;
      } catch (ghidra.util.exception.InvalidInputException | ghidra.util.exception.DuplicateNameException e) {
        // An existing definition wins. Object facts still retain the original name.
      }
    }
    enrich(program, snapshot, monitor, log);
    program.getOptions(OWNER).setString(option, identity);
    log.appendMsg("Dart AOT Objects", snapshot.scope() + ": " + snapshot.units().size()
        + " payloads (" + objects.codes.stream().filter(code -> code.clusterIndex >= 0).count()
        + " serialized Code objects), " + stats.functionsCreated() + " new functions, " + stats.entryLabelsCreated()
        + " entry labels, " + named + " function names, " + objects.strings.size() + " string identities, "
        + objects.imagePoolEntries().size() + " scoped pool slots, " + objects.objects.size()
        + " retained object records; " + rootSlots + " root/dispatch slots."
        + (roots == null ? " Root layout is not yet adapted." : " Root stream fully consumed.")
        + (objects.opaqueObjects.isEmpty() ? "" : " " + objects.opaqueObjects.size()
            + " objects retained without role interpretation (raw fields/bytes preserved)."));
  }

  /** Independent, retryable enrichments of a fully validated structural generation. */
  private static void enrich(Program program, Snapshot snapshot, TaskMonitor monitor, MessageLog log)
      throws IOException, CancelledException {
    String option = OWNER + "." + snapshot.scope() + ".presentation";
    Address anchor = program.getMemory().getBlock("DartObjects_" + snapshot.scope()).getStart();
    for (var cls : snapshot.objects().classes) {
      monitor.checkCancelled();
      ghidart.importer.B4aImporter.annotateClass(program, anchor.add(cls.refId * 8L), cls.classId);
    }
    boolean complete = snapshot.objects().opaqueObjects.isEmpty();
    complete &= enhance(program, OWNER + "." + snapshot.scope() + ".stringData", 1,
        "string data", () -> {
          prepareSnapshotData(program, snapshot, monitor);
          int defined = 0;
          int conflicts = 0;
          Address firstConflict = null;
          monitor.initialize(snapshot.objects().strings.size(), "Defining Dart string payloads");
          for (var string : snapshot.objects().strings) {
            monitor.checkCancelled();
            Address payload = snapshot.data().add(string.dataOffset);
            int length = Math.multiplyExact(string.value.length(), string.isOneByte ? 1 : 2);
            if (length > 0) {
              boolean created;
              try {
                created = defineString(program, payload, length, string.isOneByte);
              } catch (IOException e) {
                created = false;
              }
              if (created) {
                defined++;
              } else {
                if (firstConflict == null) firstConflict = payload;
                conflicts++;
              }
            }
            monitor.increment();
          }
          log.appendMsg("Dart AOT Objects", snapshot.scope() + ": " + defined
              + " string data definitions; " + conflicts + " conflicts (existing data preserved).");
          if (conflicts > 0) {
            throw new IOException(conflicts + " string data conflicts; first at " + firstConflict);
          }
        }, log);
    String semantics = OWNER + "." + snapshot.scope() + ".semanticFacts";
    complete &= enhance(program, semantics, 2, "semantic facts", () -> {
      publishSemanticFacts(program, snapshot, anchor, monitor);
    }, log);
    complete &= enhance(program, option, 10, "symbol hierarchy", () -> {
      DartSnapshotSymbols.publish(program, snapshot, anchor, monitor, log);
    }, log);
    String typeOption = OWNER + "." + snapshot.scope() + ".classTypes";
    complete &= enhance(program, typeOption, 5, "class types", () -> {
      DartSnapshotTypes.publish(program, snapshot, monitor, log);
    }, log);
    String codeOption = OWNER + "." + snapshot.scope() + ".functionCodes";
    complete &= enhance(program, codeOption, 1, "Function/Code relationships", () -> {
      publishFunctionCodes(program, snapshot, anchor, monitor);
    }, log);
    String views = OWNER + "." + snapshot.scope() + ".slotViews";
    complete &= enhance(program, views, 2, "PP views", () -> {
      ghidart.listing.DartSlotViews.publishPools(program, snapshot, anchor, monitor);
    }, log);
    String threadOption = OWNER + "." + snapshot.scope() + ".threadReferences";
    complete &= enhance(program, threadOption, 1, "THR references", () -> {
      var ranges = new AddressSet();
      for (var payload : snapshot.table().uniqueRanges) {
        Address start = snapshot.instructions().add(payload.pcOffset);
        ranges.add(start, start.add(payload.size - 1));
      }
      int links = ghidart.listing.DartSlotViews.publishThreadAccesses(program, ranges, monitor);
      log.appendMsg("Dart AOT Objects", snapshot.scope() + ": " + links + " observed THR accesses (no layout required).");
    }, log);
    String poolOption = OWNER + "." + snapshot.scope() + ".poolReferences";
    complete &= enhance(program, poolOption, 5, "PP references", () -> {
      int links = DartPoolReferences.publish(program, snapshot, anchor, monitor);
      log.appendMsg("Dart AOT Objects", snapshot.scope() + ": " + links + " PP slot references.");
    }, log);
    program.getOptions(OWNER).setBoolean(OWNER + "." + snapshot.scope() + ".partial", !complete);
  }

  @FunctionalInterface
  private interface Enhancement {
    void publish() throws IOException, CancelledException;
  }

  /** Expected presentation conflicts must not discard unrelated, valid facts.
   * Publishers add evidence incrementally and preserve user edits. Failed steps may
   * retain valid additions, but never receive a completion stamp; reruns retry them.
   * Cancellation and unexpected programming failures still abort the transaction.
   */
  private static boolean enhance(Program program, String key, int version, String label,
      Enhancement action, MessageLog log) throws CancelledException {
    var options = program.getOptions(OWNER);
    if (options.getInt(key, 0) == version) return true;
    try {
      action.publish();
      options.setInt(key, version);
      options.removeOption(key + ".error");
      return true;
    } catch (IOException e) {
      options.setString(key + ".error", e.getMessage());
      log.appendMsg("Dart AOT Objects", label + " incomplete: " + e.getMessage()
          + "; validated facts retained; this step will retry on reanalysis.");
      return false;
    }
  }

  /** Add validated semantic facts without reallocating published object identities.
   * Parent facts use the child's logical anchor, not another file's addresses.
   * Nearest loading-unit definitions win; no native user types are rewritten.
   */
  private static void publishSemanticFacts(Program program, Snapshot snapshot, Address anchor,
      TaskMonitor monitor) throws CancelledException, IOException {
    var facts = property(program);
    var functions = new java.util.HashSet<Integer>();
    var signatures = new java.util.HashSet<Integer>();
    var instances = new java.util.HashSet<Integer>();
    var fields = new java.util.HashSet<Integer>();
    for (var scope = snapshot.objects(); scope != null;
        scope = snapshot.objects().header.isLoadingUnit ? scope.vm : null) {
      for (var opaque : scope.opaqueObjects.entrySet()) {
        monitor.checkCancelled();
        detail(facts, anchor.add(opaque.getKey() * 8L), "interpretation",
            Map.of("status", "opaque", "capability", "Function role", "reason", opaque.getValue()));
      }
      for (var function : scope.functionInfos) {
        monitor.checkCancelled();
        if (functions.add(function.refId())) {
          detail(facts, anchor.add(function.refId() * 8L), "functionInfo", function);
        }
      }
      for (var signature : scope.funcTypes) {
        monitor.checkCancelled();
        if (signatures.add(signature.refId)) {
          detail(facts, anchor.add(signature.refId * 8L), "signature", signature);
        }
      }
      for (var entry : scope.instanceSlots.entrySet()) {
        monitor.checkCancelled();
        if (!instances.add(entry.getKey())) continue;
        Address address = anchor.add(entry.getKey() * 8L);
        detail(facts, address, "instanceSlots", entry.getValue());
        detail(facts, address, "immutable", scope.immutableInstances.contains(entry.getKey()));
      }
      for (var field : scope.fields) {
        monitor.checkCancelled();
        if (!fields.add(field.refId)) continue;
        Address address = anchor.add(field.refId * 8L);
        detail(facts, address, "object", field);
        if (field.typeRefId > 0) reference(program, address, anchor.add(field.typeRefId * 8L));
      }
    }
  }

  /** Function/Code relationships also survive when no local body is available. */
  private static void publishFunctionCodes(Program program, Snapshot snapshot, Address anchor,
      TaskMonitor monitor) throws IOException, CancelledException {
    var objects = snapshot.objects();
    var targets = fileTargets(program, snapshot);
    var facts = property(program);
    for (var named : objects.namedObjects) {
      monitor.checkCancelled();
      if (named.cid != objects.profile.cids.function) continue;
      var record = objects.object(named.refId);
      if (record == null || record.scalars().length == 0) continue;
      long index = record.scalars()[0];
      Address address = anchor.add(named.refId * 8L);
      Integer code = objects.codeReference(index, snapshot.table().firstEntryWithCode);
      if (code != null) reference(program, address, anchor.add(code * 8L));
      if (!objects.profile.codeTextOffsetDelta && index == 0) {
        detail(facts, address, "codeRole", "LazyCompile");
      }
      Address target = targets.get(named.refId);
      if (target != null) reference(program, address, target);
    }
    if (objects.header.isLoadingUnit) for (var code : objects.codes) {
      monitor.checkCancelled();
      if (code.refId > objects.header.numBaseObjects) continue;
      var owner = objects.named(code.ownerRef);
      if (owner == null || owner.cid != objects.profile.cids.function) continue;
      Address address = anchor.add(owner.refId * 8L);
      reference(program, address, anchor.add(code.refId * 8L));
      Address target = targets.get(owner.refId);
      if (target != null) reference(program, address, target);
    }
  }

  /** Code has no file-backed object address; its payload is a separate image. */
  private static Address codeTarget(Snapshot snapshot, DartClusterParser.CodeEntry code) {
    if (code.clusterIndex < 0) return null; // A deferred unit must supply its own image.
    int slot = code.clusterIndex + snapshot.table().firstEntryWithCode;
    long pc = snapshot.table().entries.get(slot).pcOffset();
    return snapshot.instructions().add(pc + snapshot.objects().profile.normalEntryOffset(code.payloadInfo));
  }

  /** File-backed destinations only; serialized identities are not heap addresses.
   * Function entries and Code payloads may share a destination. A class or arbitrary
   * instance deliberately has none: its serialized fields are not an in-place object.
   */
  public static Map<Integer, Address> fileTargets(Program program, Snapshot snapshot) throws IOException {
    var targets = new LinkedHashMap<Integer, Address>();
    var objects = snapshot.objects();
    if (objects.vm != null && !objects.header.isLoadingUnit) {
      Address vmData = symbol(program, "kDartVmSnapshotData");
      if (vmData != null) for (var string : objects.vm.strings) {
        if (!string.value.isEmpty()) targets.put(string.refId, vmData.add(string.dataOffset));
      }
    }
    for (var string : objects.strings) {
      if (!string.value.isEmpty()) targets.put(string.refId, snapshot.data().add(string.dataOffset));
    }
    var codes = new LinkedHashMap<Integer, Address>();
    for (var code : objects.codes) {
      Address target = codeTarget(snapshot, code);
      if (target != null) {
        codes.put(code.refId, target);
        targets.put(code.refId, target);
        if (objects.header.isLoadingUnit && code.refId <= objects.header.numBaseObjects) {
          var owner = objects.named(code.ownerRef);
          if (owner != null && owner.cid == objects.profile.cids.function) targets.put(owner.refId, target);
        }
      }
    }
    var indices = dispatchTargets(snapshot);
    for (var named : objects.namedObjects) {
      if (named.cid != objects.profile.cids.function) continue;
      var serialized = objects.objects.get(named.refId);
      if (serialized == null || serialized.scalars().length == 0) continue;
      long index = serialized.scalars()[0];
      Integer codeRef = objects.codeReference(index, snapshot.table().firstEntryWithCode);
      Address target = codeRef == null ? null : codes.get(codeRef);
      if (target == null && !objects.profile.codeTextOffsetDelta && index > 0) {
        long localIndex = objects.header.isLoadingUnit ? index - objects.header.numBaseObjects : index;
        if (localIndex > 0) target = indices.get(localIndex);
      }
      if (target != null) targets.put(named.refId, target);
    }
    return targets;
  }

  private static Map<Long, Address> dispatchTargets(Snapshot snapshot) throws IOException {
    var objects = snapshot.objects();
    var targets = new LinkedHashMap<Long, Address>();
    boolean old = objects.profile.codeTextOffsetDelta;
    if (!old) {
      // Discarded Code entries retain their normal entry in InstructionsTable.
      for (int slot = 0; slot < snapshot.table().firstEntryWithCode; slot++) {
        targets.put((long) slot + 1,
            snapshot.instructions().add(snapshot.table().entries.get(slot).pcOffset()));
      }
    }
    Integer nullError = objects.roots.references().get("object_store.dispatch_table_null_error_stub");
    for (var code : objects.codes) {
      Address target = codeTarget(snapshot, code);
      if (target == null) continue; // Deferred Code requires its unit's image.
      long index = old ? (long) code.refId - objects.roots.firstCodeRef()
          : (long) code.clusterIndex + snapshot.table().firstEntryWithCode + 1;
      targets.put(index, target);
      if (nullError != null && code.refId == nullError) targets.put(-1L, target);
    }
    // Only merged metadata provides an explicit LazyCompile Code reference.
    if (!old) {
      Integer lazy = objects.codeReference(0, snapshot.table().firstEntryWithCode);
      if (lazy != null) for (var code : objects.codes) {
        if (code.refId == lazy) {
          Address target = codeTarget(snapshot, code);
          if (target != null) targets.put(0L, target);
          break;
        }
      }
    }
    return targets;
  }

  /** Materialize a named root or table slot without pretending it is a runtime address. */
  private static void rootSlot(Program program, StringPropertyMap facts, Address slot,
      Address anchor, String name, long value, boolean objectReference) throws IOException {
    try {
      program.getListing().createData(slot, QWordDataType.dataType);
      program.getMemory().setLong(slot, value);
    } catch (ghidra.program.model.util.CodeUnitInsertionException | MemoryAccessException e) {
      throw new IOException("logical root slot collision", e);
    }
    facts.add(slot, JSON.toJson(Map.of("kind", objectReference ? "RootReference" : "DispatchCodeIndex",
        "name", name, "value", value)));
    program.getListing().setComment(slot, ghidra.program.model.listing.CommentType.EOL, name);
    if (objectReference && value > 0) reference(program, slot, anchor.add(value * 8));
  }

  /** ELF object symbols describe storage; their undefined arrays are not object types. */
  private static void prepareSnapshotData(Program program, Snapshot snapshot, TaskMonitor monitor)
      throws CancelledException {
    var listing = program.getListing();
    var data = listing.getDefinedDataAt(snapshot.data());
    if (data == null || !ghidra.program.model.data.Undefined.isUndefinedArray(data.getDataType())) return;
    if (data.getLength() > snapshot.bytes().length) return;
    for (var symbol : program.getSymbolTable().getSymbols(snapshot.data())) {
      if (symbol.getSource() != SourceType.IMPORTED) continue;
      String name = symbol.getName().replaceFirst("^_+", "");
      if (!Set.of("kDartVmSnapshotData", "kDartIsolateSnapshotData", "kDartSnapshotData").contains(name)) continue;
      // Clear only the loader's raw placeholder, after full L2 validation and
      // inside the publication transaction. Labels, bytes and references stay.
      var references = program.getReferenceManager();
      var saved = new ArrayList<ghidra.program.model.symbol.Reference>();
      var region = new ghidra.program.model.address.AddressSet(data.getMinAddress(), data.getMaxAddress());
      for (var address : references.getReferenceSourceIterator(region, true)) {
        monitor.checkCancelled();
        java.util.Collections.addAll(saved, references.getReferencesFrom(address));
      }
      listing.clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), false, monitor);
      for (var reference : saved) references.addReference(reference);
      return;
    }
  }

  private static boolean defineString(Program program, Address payload, int length, boolean latin1)
      throws IOException {
    var listing = program.getListing();
    var existing = listing.getDefinedDataContaining(payload);
    if (existing != null) {
      return existing.getAddress().equals(payload)
          && existing.hasStringValue() && existing.getLength() == length;
    }
    if (listing.getInstructionContaining(payload) != null) return false;
    var region = new ghidra.program.model.address.AddressSet(payload, payload.add(length - 1));
    if (listing.getInstructions(region, true).hasNext() || listing.getDefinedData(region, true).hasNext()) return false;
    try {
      listing.createData(payload, latin1 ? new DartLatin1DataType() : new DartUtf16DataType(), length);
      return true;
    } catch (ghidra.program.model.util.CodeUnitInsertionException e) {
      throw new IOException("string data insertion failed", e);
    }
  }

  /** Keep complementary facts for one serialized identity instead of overwriting them. */
  private static void detail(StringPropertyMap facts, Address address, String name, Object value) {
    String existing = facts.getString(address);
    var record = existing == null ? new com.google.gson.JsonObject()
        : JSON.fromJson(existing, com.google.gson.JsonObject.class);
    record.add(name, JSON.toJsonTree(value));
    facts.add(address, JSON.toJson(record));
  }

  private static StringPropertyMap property(Program program) throws IOException {
    var manager = program.getUsrPropertyManager();
    var existing = manager.getStringPropertyMap(FACTS);
    if (existing != null) return existing;
    try {
      return manager.createStringPropertyMap(FACTS);
    } catch (ghidra.util.exception.DuplicateNameException e) {
      throw new IOException("object property conflict", e);
    }
  }

  private static void reference(Program program, Address from, Address to) {
    DartObjectGraph.link(program, from, to, RefType.DATA);
  }

  static Address symbol(Program program, String name) throws IOException {
    Address result = null;
    for (var symbol : program.getSymbolTable().getAllSymbols(false)) {
      if (!symbol.getName().replaceFirst("^_+", "").equals(name)) continue;
      if (result != null && !result.equals(symbol.getAddress())) throw new IOException("conflicting " + name);
      result = symbol.getAddress();
    }
    return result;
  }

  private static byte[] bytes(Program program, Address start, int length)
      throws IOException, MemoryAccessException {
    if (length <= 0 || !program.getMemory().getLoadedAndInitializedAddressSet()
        .contains(start, start.add(length - 1))) throw new IOException("snapshot image is not fully mapped");
    byte[] bytes = new byte[length];
    if (program.getMemory().getBytes(start, bytes) != length) throw new IOException("truncated snapshot memory");
    return bytes;
  }

  private static MessageDigest digest() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }
}
