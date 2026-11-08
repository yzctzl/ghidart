package ghidart.analysis;

import ghidart.snapshot.DartClusterParser;
import ghidart.snapshot.DartSnapshotAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/** Resolve native PP accesses to validated L2 slots without decompiling the application.
 *
 * FullAOT's ObjectStore identifies the global pool; that identity is never inferred
 * from an offset alone. Bounded FullAOT instruction payloads with no explicit PP
 * writes are eligible, including payloads whose Code object was discarded by the
 * serializer. Small raw P-code expressions are evaluated within a straight-line block;
 * joins, calls and unresolved definitions discard scratch values. Loads are not
 * folded: a direct data xref denotes the serialized initial slot value, including
 * patchable slots, rather than a claim about its value after runtime mutation.
 */
public final class DartPoolReferences {
  private record Key(Address address, int size) {}
  private record Value(boolean pp, long offset) {}

  public static int publish(Program program, DartSnapshotAnalyzer.Snapshot snapshot, Address anchor,
      TaskMonitor monitor) throws CancelledException, IOException {
    var objects = snapshot.objects();
    Integer pool = objects.roots.references().get("object_store.global_object_pool");
    if (pool == null || objects.globalPool().isEmpty()) return 0;
    var destinations = DartSnapshotAnalyzer.fileTargets(program, snapshot);
    var slots = new HashMap<Long, Address>();
    var entries = new HashMap<Long, DartClusterParser.PoolEntry>();
    long position = objects.header.numObjects + 1L;
    for (var entry : objects.imagePoolEntries()) {
      if (entry.poolRef == pool) {
        long offset = entry.byteOffsetFromUntaggedPool();
        slots.put(offset, anchor.add(position * 8));
        entries.put(offset, entry);
      }
      position++;
    }
    var pp = program.getRegister("x27");
    var ppKey = new Key(pp.getAddress(), pp.getMinimumByteSize());
    AddressSet incomingFlow = incomingFlow(program, snapshot, monitor);
    int references = 0;
    monitor.initialize(snapshot.table().uniqueRanges.size(), "Linking Dart pool accesses");
    monitor.setIndeterminate(false);
    for (var payload : snapshot.table().uniqueRanges) {
      monitor.checkCancelled();
      monitor.increment();
      long offset = payload.pcOffset;
      Address start = snapshot.instructions().add(offset);
      Address end = start.add(payload.size - 1);
      boolean changesPp = false;
      for (var it = program.getListing().getInstructions(start, true); it.hasNext();) {
        monitor.checkCancelled();
        var instruction = it.next();
        if (instruction.getAddress().compareTo(end) > 0) break;
        for (var op : instruction.getPcode()) {
          var output = op.getOutput();
          if (output != null && output.isRegister() && overlap(key(output), ppKey)) changesPp = true;
        }
      }
      if (changesPp) continue;
      var values = new HashMap<Key, Value>();
      Address previous = null;
      for (var it = program.getListing().getInstructions(start, true); it.hasNext();) {
        var instruction = it.next();
        if (instruction.getAddress().compareTo(end) > 0) break;
        monitor.checkCancelled();
        if (!instruction.getAddress().equals(previous) || incomingFlow.contains(instruction.getAddress())) values.clear();
        values.keySet().removeIf(k -> k.address().isUniqueAddress());
        values.put(ppKey, new Value(true, 0));
        for (var op : instruction.getPcode()) {
          int opcode = op.getOpcode();
          if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
            var address = read(values, op.getInput(1));
            int width = opcode == PcodeOp.LOAD ? op.getOutput().getSize() : op.getInput(2).getSize();
            if (address != null && address.pp() && width == 8 && slots.containsKey(address.offset())) {
              var target = slots.get(address.offset());
              RefType type = opcode == PcodeOp.LOAD ? RefType.READ : RefType.WRITE;
              ghidart.snapshot.DartObjectGraph.link(program, instruction.getAddress(), target, type);
              ghidart.listing.DartSlotViews.access(program, instruction.getAddress(), target, type);
              ghidart.importer.B4aImporter.annotatePoolSlot(program,
                  instruction.getAddress(), target, address.offset());
              references++;
              var entry = entries.get(address.offset());
              if (opcode == PcodeOp.LOAD && entry.kind == DartClusterParser.PoolEntryKind.TAGGED) {
                var destination = destinations.get(entry.refId);
                if (destination != null) {
                  program.getReferenceManager().addMemoryReference(instruction.getAddress(), destination,
                      RefType.DATA, SourceType.ANALYSIS, -1);
                }
              }
            }
          }
          Value result = evaluate(values, op);
          var output = op.getOutput();
          if (output != null) {
            Key key = key(output);
            values.keySet().removeIf(k -> overlap(k, key));
            if (result != null && output.getSize() < 8) {
              result = result.pp() ? null : new Value(false,
                  result.offset() & ((1L << (output.getSize() * 8)) - 1));
            }
            if (result != null) values.put(key, result);
          }
          if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND
              || opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH
              || opcode == PcodeOp.BRANCHIND || opcode == PcodeOp.RETURN) values.clear();
        }
        previous = instruction.getFallThrough();
      }
    }
    return references;
  }

  /** Bring validated pool identity into selected-function decompiler locals.
   * Multiple LOADs/slots at one instruction are deliberately left unchanged;
   * a native reference alone does not identify which SSA output carries a value.
   */
  static void nameValues(Program program, ghidra.program.model.listing.Function function,
      ghidra.program.model.pcode.HighFunction high, TaskMonitor monitor) throws CancelledException {
    var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    if (facts == null) return;
    var loads = new HashMap<Address, java.util.List<PcodeOp>>();
    for (var it = high.getPcodeOps(); it.hasNext();) {
      monitor.checkCancelled();
      var op = it.next();
      if (op.getOpcode() == PcodeOp.LOAD && function.getBody().contains(op.getSeqnum().getTarget())) {
        loads.computeIfAbsent(op.getSeqnum().getTarget(), ignored -> new java.util.ArrayList<>()).add(op);
      }
    }
    for (var site : loads.entrySet()) {
      monitor.checkCancelled();
      if (site.getValue().size() != 1) continue;
      Long offset = null;
      Address poolSlot = null;
      boolean ambiguous = false;
      for (var reference : ghidart.snapshot.DartObjectGraph.from(program, site.getKey())) {
        if (reference.getReferenceType() != RefType.READ) continue;
        String json = facts.getString(reference.getToAddress());
        if (json == null) continue;
        var slot = com.google.gson.JsonParser.parseString(json).getAsJsonObject();
        if (!slot.has("poolRef") || !slot.has("index")) continue;
        if (offset != null) { ambiguous = true; break; }
        offset = slot.get("index").getAsLong() * 8 + 16;
        poolSlot = reference.getToAddress();
      }
      if (!ambiguous && offset != null) {
        DartValueAnalyzer.nameExpression(program, function, high,
            site.getValue().getFirst().getOutput(),
            "pp_" + Long.toHexString(offset) + valueName(program, poolSlot));
      }
    }
  }

  /** An initial-value hint, never a substitution for a mutable pool load.
   * Character bytes are reached through the already-validated slot DATA reference.
   * Base-object names live on the logical identity, not on a fabricated heap image.
   */
  private static String valueName(Program program, Address slot) {
    for (var reference : ghidart.snapshot.DartObjectGraph.from(program, slot)) {
      if (reference.getReferenceType() != RefType.DATA) continue;
      Address target = reference.getToAddress();
      var data = program.getListing().getDataAt(target);
      if (data != null && data.hasStringValue()) {
        String value = String.valueOf(data.getValue());
        var name = new StringBuilder("_str");
        value.codePoints().limit(32).forEach(character ->
            name.appendCodePoint(Character.isLetterOrDigit(character) ? character : '_'));
        return name.toString();
      }
      String name = ghidart.snapshot.DartObjectGraph.describe(program, target);
      int base = name.indexOf("BaseObjects::");
      if (base >= 0) return "_" + name.substring(base + 13);
    }
    return "";
  }

  /** Query the sparse reference index once, rather than once per instruction. */
  private static AddressSet incomingFlow(Program program, DartSnapshotAnalyzer.Snapshot snapshot,
      TaskMonitor monitor) throws CancelledException {
    var image = new AddressSet();
    for (var payload : snapshot.table().uniqueRanges) {
      monitor.checkCancelled();
      Address start = snapshot.instructions().add(payload.pcOffset);
      image.add(start, start.add(payload.size - 1));
    }
    var targets = new AddressSet();
    monitor.setMessage("Indexing Dart pool control-flow joins");
    var manager = program.getReferenceManager();
    for (var it = manager.getReferenceDestinationIterator(image, true); it.hasNext();) {
      monitor.checkCancelled();
      Address target = it.next();
      for (var ref : manager.getReferencesTo(target)) {
        if (ref.getReferenceType().isFlow()) {
          targets.add(target);
          break;
        }
      }
    }
    return targets;
  }

  private static Value evaluate(Map<Key, Value> values, PcodeOp op) {
    if (op.getOutput() == null || op.getNumInputs() == 0) return null;
    Value a = read(values, op.getInput(0));
    int opcode = op.getOpcode();
    if (a == null) return null;
    if (opcode == PcodeOp.COPY || opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.CAST) {
      return !a.pp() || op.getOutput().getSize() == 8 ? a : null;
    }
    if (op.getNumInputs() != 2) return null;
    Value b = read(values, op.getInput(1));
    if (b == null) return null;
    if (opcode == PcodeOp.INT_ADD && !(a.pp() && b.pp())) return new Value(a.pp() || b.pp(), a.offset() + b.offset());
    if (opcode == PcodeOp.INT_SUB && !b.pp()) return new Value(a.pp(), a.offset() - b.offset());
    if (a.pp() || b.pp()) return null;
    return switch (opcode) {
      case PcodeOp.INT_LEFT -> b.offset() >= 0 && b.offset() < 64 ? new Value(false, a.offset() << b.offset()) : null;
      case PcodeOp.INT_OR -> new Value(false, a.offset() | b.offset());
      case PcodeOp.INT_AND -> new Value(false, a.offset() & b.offset());
      default -> null;
    };
  }

  private static Key key(Varnode node) { return new Key(node.getAddress(), node.getSize()); }

  private static Value read(Map<Key, Value> values, Varnode node) {
    return node.isConstant() ? new Value(false, node.getOffset()) : values.get(key(node));
  }

  private static boolean overlap(Key a, Key b) {
    return a.address().getAddressSpace().equals(b.address().getAddressSpace())
        && a.address().getOffset() < b.address().getOffset() + b.size()
        && b.address().getOffset() < a.address().getOffset() + a.size();
  }
}
