package ghidart;

import com.google.gson.Gson;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.DWordDataType;
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
 * Optional L2 producer: validate serialized AOT facts before touching the database.
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
  private static final int FACT_GENERATION = 5;
  private static final Gson JSON = new Gson();

  record Snapshot(String scope, Address data, Address instructions, byte[] bytes,
      DartClusterParser.Result objects, DartInstructionsTable table,
      List<DartCodeIndex.CodeUnit> units, boolean vmReferences, String identity) {}

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
  public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
      throws CancelledException {
    try (var output = new DartAnalysisLog(program, log)) {
      try {
        List<Snapshot> snapshots = read(program, monitor);
        if (snapshots.isEmpty()) {
          output.messages().appendMsg(getName(), "No mapped AOT snapshot symbols; L1 remains available.");
          return true;
        }
        // Cluster decoding, reference bounds and image ranges are checked before the
        // transaction. No weak caches or partial Results escape this pass.
        int transaction = program.startTransaction("Publish Dart AOT objects");
        boolean commit = false;
        try {
          for (Snapshot snapshot : snapshots) publish(program, snapshot, monitor, output.messages());
          monitor.checkCancelled();
          commit = true;
        } finally {
          program.endTransaction(transaction, commit);
        }
        return true;
      } catch (IOException | IllegalArgumentException | MemoryAccessException e) {
        monitor.checkCancelled();
        output.messages().appendMsg(getName(), "L2 rejected: " + e.getMessage() + "; L1 is unchanged.");
        return false;
      }
    }
  }

  private static List<Snapshot> read(Program program, TaskMonitor monitor)
      throws IOException, MemoryAccessException, CancelledException {
    var result = new ArrayList<Snapshot>();
    DartClusterParser.Result vm = null;
    Address vmData = symbol(program, "kDartVmSnapshotData");
    if (vmData != null) {
      Snapshot snapshot = read(program, "vm", vmData,
          symbol(program, "kDartVmSnapshotInstructions"), null, true, monitor);
      result.add(snapshot);
      vm = snapshot.objects();
    }
    Address isolate = symbol(program, "kDartIsolateSnapshotData");
    Address instructions = symbol(program, "kDartIsolateSnapshotInstructions");
    if (isolate == null) {
      isolate = symbol(program, "kDartSnapshotData");
      instructions = symbol(program, "kDartSnapshotText");
    }
    if (isolate != null) result.add(read(program, "isolate", isolate, instructions, vm, false, monitor));
    return List.copyOf(result);
  }

  private static Snapshot read(Program program, String scope, Address data, Address instructions,
      DartClusterParser.Result vm, boolean isVm, TaskMonitor monitor)
      throws IOException, MemoryAccessException, CancelledException {
    if (instructions == null) throw new IOException("missing " + scope + " instruction image");
    monitor.setMessage("Reading Dart " + scope + " snapshot");
    byte[] prefix = bytes(program, data, 20);
    var stream = new DartStream(prefix);
    if (stream.readInt32() != DartSnapshotHeader.SNAPSHOT_MAGIC) throw new IOException("snapshot magic");
    long length = stream.readInt64();
    if (length < 49 || length > Integer.MAX_VALUE - 4L) throw new IOException("snapshot extent");
    byte[] clustered = bytes(program, data, (int) length + 4);
    var header = DartSnapshotHeader.parse(clustered, 0, isVm);
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
    return new Snapshot(scope, data, instructions, input, objects, table, units, vm != null,
        HexFormat.of().formatHex(digest.digest()));
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
        long normal = start + (mono ? 24 : 0);
        long unchecked = code.payloadInfo >>> 1;
        addEntry(roles, normal, "normal", start, end);
        addEntry(roles, normal + unchecked, "unchecked", start, end);
        // ReadInstructions initializes all four cached entries even when they
        // coincide. Preserve their roles rather than dropping aliased entries.
        long monomorphic = start + (mono ? 8 : 0);
        addEntry(roles, monomorphic, "monomorphic", start, end);
        addEntry(roles, monomorphic + unchecked, "monomorphic_unchecked", start, end);
        if (primary == null) primary = normal;
        for (int pc : objects.exceptionEntries.getOrDefault(code.exceptionRef, List.of())) {
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
    String previous = program.getOptions(OWNER).getString(option, "");
    if (identity.equals(previous)) {
      log.appendMsg("Dart AOT Objects", snapshot.scope() + ": validated facts already published.");
      return;
    }
    // Never silently overwrite a previous generation, which may have user edits.
    if (!previous.isEmpty()) throw new IOException("snapshot/schema changed; existing L2 generation preserved; use a fresh import");
    String blockName = "DartObjects_" + snapshot.scope();
    if (program.getMemory().getBlock(blockName) != null) throw new IOException("object block name conflict");
    var objects = snapshot.objects();
    long references = objects.header.numObjects + 1;
    var roots = objects.roots;
    long rootSlots = roots == null ? 0 : (long) roots.references().size()
        + roots.staticFields().length + roots.sharedStaticFields().length
        + roots.dispatchCodeIndices().length;
    long size = Math.multiplyExact(references + objects.poolEntries.size() + rootSlots, 8L);
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
    prepareSnapshotData(program, snapshot, monitor);
    int defined = 0;
    monitor.initialize(objects.strings.size(), "Defining Dart string payloads");
    for (var string : objects.strings) {
      monitor.checkCancelled();
      Address object = anchor.add((long) string.refId * 8);
      Address payload = snapshot.data().add(string.dataOffset);
      facts.add(object, JSON.toJson(Map.of("kind", "String", "payload", payload.toString(),
          "length", string.value.length(), "encoding", string.isOneByte ? "latin1" : "utf16le")));
      reference(program, object, payload);
      int byteLength = Math.multiplyExact(string.value.length(), string.isOneByte ? 1 : 2);
      if (byteLength > 0 && defineString(program, payload, byteLength, string.isOneByte)) defined++;
      monitor.increment();
    }
    for (var cls : objects.classes) {
      facts.add(anchor.add((long) cls.refId * 8), JSON.toJson(Map.of("kind", "Class", "object", cls)));
    }
    for (var field : objects.fields) {
      facts.add(anchor.add((long) field.refId * 8), JSON.toJson(Map.of("kind", "Field", "object", field)));
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
      detail(facts, anchor.add((long) type.refId * 8), "type", type);
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
      facts.add(object, JSON.toJson(Map.of("kind", "Code", "object", code)));
      if (code.ownerRef > 0) reference(program, object, anchor.add((long) code.ownerRef * 8));
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
    for (var entry : objects.poolEntries) {
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
      facts.add(object, JSON.toJson(Map.of("kind", "ObjectPool", "firstSlot", pool.getValue().toString())));
    }
    monitor.initialize(objects.objects.size(), "Publishing Dart serialized object fields");
    for (var object : objects.objects.values()) {
      monitor.checkCancelled();
      Address address = anchor.add((long) object.refId() * 8);
      detail(facts, address, "serialized", object);
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
      Address slot = anchor.add((references + objects.poolEntries.size()) * 8);
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
      for (int index = 0; index < dispatch.length; index++) {
        // These are Code indices, not snapshot reference IDs or addresses.
        rootSlot(program, facts, slot, anchor, "dispatch[" + index + "]", dispatch[index], false);
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
    var stats = DartAotAnalyzer.applyBoundaries(program, snapshot.units(), monitor, log);
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
    program.getOptions(OWNER).setString(option, identity);
    log.appendMsg("Dart AOT Objects", snapshot.scope() + ": " + snapshot.units().size()
        + " payloads (" + objects.codes.stream().filter(code -> code.clusterIndex >= 0).count()
        + " serialized Code objects), " + stats.functionsCreated + " new functions, " + stats.entryLabelsCreated
        + " entry labels, " + named + " function names, " + defined + "/" + objects.strings.size() + " string data, "
        + objects.poolEntries.size() + " scoped pool slots, " + objects.objects.size()
        + " retained object records; " + rootSlots + " root/dispatch slots."
        + (roots == null ? " Root layout is not yet adapted." : " Root stream fully consumed."));
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
    program.getReferenceManager().addMemoryReference(from, to, RefType.DATA, SourceType.ANALYSIS, 0);
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
