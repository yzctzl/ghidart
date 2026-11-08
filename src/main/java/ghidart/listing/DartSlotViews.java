package ghidart.listing;

import ghidart.snapshot.DartObjectGraph;
import ghidart.snapshot.DartSnapshotAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/** Named THR/PP offset models with native use-site XREFs, not runtime heap images.
 *
 * Non-loaded overlays give each field a readable coordinate (THR:offset or
 * PP:offset). Bytes stay uninitialized: a snapshot reference ID is not a runtime
 * pointer or a constant value. Only proved accesses reference these models;
 * object relationships remain in DartObjectGraph. L3's global PP view is reused
 * when L2 supplies its exact pool identity, avoiding a second set of slots.
 */
public final class DartSlotViews {
  private static final String LINKS = "ghidart.slotRecords";
  private DartSlotViews() {}

  public static Address exportedStructure(Program program, String structure, long length,
      TaskMonitor monitor) throws IOException, CancelledException {
    if (!structure.equals("DartThread") && !structure.equals("DartObjectPool")) return null;
    return model(program, structure.equals("DartThread") ? "THR" : "PP", length, monitor);
  }

  private static Address model(Program program, String name, long length, TaskMonitor monitor)
      throws IOException, CancelledException {
    monitor.checkCancelled();
    String blockName = "DartSlots_" + name;
    var block = program.getMemory().getBlock(blockName);
    if (block != null && (!block.isArtificial() || block.isLoaded() || block.isInitialized()
        || !block.getStart().getAddressSpace().isOverlaySpace())) {
      throw new IOException("Unowned or modified Dart slot model: " + name);
    }
    try {
      if (block == null) {
        if (program.getAddressFactory().getAddressSpace(name) != null) {
          throw new IOException("Model address-space name already in use: " + name);
        }
        var zero = program.getAddressFactory().getAddressSpace("OTHER").getAddress(0);
        block = program.getMemory().createUninitializedBlock(name, zero, length, true);
        block.setName(blockName);
        block.setArtificial(true);
        block.setRead(true);
        block.setWrite(false);
        block.setExecute(false);
        block.setComment("Dart offset model, NOT runtime memory. No debugger mapping or constant bytes.");
      } else if (block.getSize() < length) {
        if (!block.isArtificial() || block.isInitialized()) throw new IOException("Modified Dart slot model: " + name);
        var tail = program.getMemory().createUninitializedBlock(blockName + "_tail",
            block.getEnd().add(1), length - block.getSize(), false);
        tail.setArtificial(true);
        tail.setRead(true);
        tail.setWrite(false);
        tail.setExecute(false);
        block = program.getMemory().join(block, tail);
      }
      return block.getStart();
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      throw new IOException("Cannot publish " + name + " offset model", e);
    }
  }

  public static Namespace exportedOwner(Program program, String structure) throws Exception {
    Namespace library = DartNamespaces.namespace(program, program.getGlobalNamespace(), "Library", false, SourceType.ANALYSIS);
    Namespace owner = DartNamespaces.namespace(program, library, structure.equals("DartThread") ? "THR" : "PP", false, SourceType.ANALYSIS);
    return structure.equals("DartThread") ? owner
        : DartNamespaces.namespace(program, owner, "Export", false, SourceType.ANALYSIS);
  }

  public static void slot(Program program, Address address, Namespace owner, String name,
      String description, SourceType source) throws IOException {
    try {
      if (program.getListing().getDefinedDataContaining(address) == null) {
        // Thread offsets can name byte flags inside a word. Do not invent an
        // eight-byte field extent that would conflict with an adjacent anchor.
        program.getListing().createData(address, address.getAddressSpace().getName().equals("THR")
            ? ghidra.program.model.data.Undefined1DataType.dataType : Undefined8DataType.dataType);
      }
      var primary = program.getSymbolTable().getPrimarySymbol(address);
      if (primary == null || primary.getSource() == SourceType.DEFAULT) {
        program.getSymbolTable().createLabel(address, DartNamespaces.clean(name), owner, source);
      } else if (primary.getSource() != SourceType.USER_DEFINED) {
        if (source == SourceType.IMPORTED) {
          if (!primary.getParentNamespace().getName().equals("Export")) owner = primary.getParentNamespace();
          primary.setNameAndNamespace(DartNamespaces.clean(name), owner, source);
        } else if (primary.getParentNamespace().getName().equals("Export")) {
          primary.setNamespace(owner);
        }
      }
      if (program.getListing().getComment(CommentType.EOL, address) == null) {
        program.getListing().setComment(address, CommentType.EOL,
            "Offset model; not runtime memory. " + description);
      }
    } catch (Exception e) {
      throw new IOException("Cannot describe Dart slot " + address, e);
    }
  }

  private record ThreadAccess(Address site, RefType type, int width) {}

  /** Observe fixed THR accesses without a snapshot layout or b4a export.
   * Only address arithmetic inside one decoded instruction is followed. Loads
   * are not evaluated, indexed addresses are unknown, and no field type/name is
   * guessed. One-byte anchors avoid inventing field extents or overlapping a
   * neighboring observed offset; the comment records actual access widths.
   */
  public static int publishThreadAccesses(Program program, AddressSetView region,
      TaskMonitor monitor) throws IOException, CancelledException {
    var thr = program.getRegister("x26");
    if (thr == null) return 0;
    var root = new Varnode(thr.getAddress(), thr.getMinimumByteSize());
    var accesses = new LinkedHashMap<Long, List<ThreadAccess>>();
    long length = 0;
    var instructions = program.getListing().getInstructions(region, true);
    monitor.initialize(region.getNumAddresses() / 4, "Linking observed THR offsets");
    while (instructions.hasNext()) {
      monitor.checkCancelled();
      var instruction = instructions.next();
      monitor.increment();
      var offsets = new HashMap<Varnode, Long>();
      offsets.put(root, 0L);
      for (var op : instruction.getPcode()) {
        int opcode = op.getOpcode();
        if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
          Long offset = offsets.get(op.getInput(1));
          int width = opcode == PcodeOp.LOAD ? op.getOutput().getSize() : op.getInput(2).getSize();
          if (offset != null && offset >= 0 && offset <= Integer.MAX_VALUE - width) {
            accesses.computeIfAbsent(offset, unused -> new ArrayList<>()).add(
                new ThreadAccess(instruction.getAddress(),
                    opcode == PcodeOp.LOAD ? RefType.READ : RefType.WRITE, width));
            length = Math.max(length, offset + width);
          }
        }
        var output = op.getOutput();
        if (output == null) continue;
        Long offset = null;
        if (opcode == PcodeOp.COPY) offset = offsets.get(op.getInput(0));
        else if (opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB) {
          Long left = offsets.get(op.getInput(0));
          Long right = offsets.get(op.getInput(1));
          if (left != null && op.getInput(1).isConstant()) {
            offset = opcode == PcodeOp.INT_ADD ? left + op.getInput(1).getOffset()
                : left - op.getInput(1).getOffset();
          } else if (opcode == PcodeOp.INT_ADD && right != null && op.getInput(0).isConstant()) {
            offset = right + op.getInput(0).getOffset();
          }
        }
        // Partial writes also invalidate an overlapping register expression.
        offsets.keySet().removeIf(value -> value.getAddress().getAddressSpace().equals(output.getAddress().getAddressSpace())
            && value.getOffset() < output.getOffset() + output.getSize()
            && output.getOffset() < value.getOffset() + value.getSize());
        if (offset != null && output.getSize() == 8) offsets.put(output, offset);
      }
    }
    if (accesses.isEmpty()) return 0;
    Address start = model(program, "THR", length, monitor);
    try {
      Namespace owner = exportedOwner(program, "DartThread");
      int references = 0;
      for (var entry : accesses.entrySet()) {
        monitor.checkCancelled();
        Address target = start.add(entry.getKey());
        if (program.getListing().getDefinedDataContaining(target) == null) {
          program.getListing().createData(target, ghidra.program.model.data.Undefined1DataType.dataType);
        }
        String widths = entry.getValue().stream().map(access -> access.width()).distinct().sorted()
            .map(Object::toString).collect(java.util.stream.Collectors.joining(", "));
        slot(program, target, owner, "offset_" + Long.toHexString(entry.getKey()),
            "Observed THR byte offset; access widths " + widths + ". Field layout unknown.", SourceType.ANALYSIS);
        for (var access : entry.getValue()) {
          program.getReferenceManager().addMemoryReference(access.site(), target, access.type(), SourceType.ANALYSIS, -1);
          references++;
        }
      }
      return references;
    } catch (Exception e) {
      if (e instanceof CancelledException cancelled) throw cancelled;
      throw new IOException("Cannot publish observed THR offsets", e);
    }
  }

  public static Address forRecord(Program program, Address record) {
    var map = program.getUsrPropertyManager().getStringPropertyMap(LINKS);
    String value = map == null ? null : map.getString(record);
    return value == null ? null : program.getAddressFactory().getAddress(value);
  }

  public static void publishPools(Program program, DartSnapshotAnalyzer.Snapshot snapshot,
      Address anchor, TaskMonitor monitor) throws IOException, CancelledException {
    var objects = snapshot.objects();
    Integer global = objects.roots.references().get("object_store.global_object_pool");
    var sizes = new HashMap<Integer, Long>();
    for (var entry : objects.imagePoolEntries()) {
      sizes.merge(entry.poolRef, entry.byteOffsetFromUntaggedPool() + 8, Math::max);
    }
    var bases = new HashMap<Integer, Address>();
    var owners = new HashMap<Integer, Namespace>();
    try {
      var library = DartNamespaces.namespace(program, program.getGlobalNamespace(), "Library", false, SourceType.ANALYSIS);
      if (sizes.isEmpty()) return;
      var pp = DartNamespaces.namespace(program, library, "PP", false, SourceType.ANALYSIS);
      var scope = DartNamespaces.namespace(program, pp, snapshot.scope(), false, SourceType.ANALYSIS);
      for (var pool : sizes.entrySet()) {
        String name = !snapshot.scope().equals("vm") && pool.getKey().equals(global) ? "PP" : "PP_" + snapshot.scope() + "_" + pool.getKey();
        Address start = model(program, name, pool.getValue(), monitor);
        bases.put(pool.getKey(), start);
        if (name.equals("PP")) {
          // Replace export-only PP observations with the pool-proved L2 accesses
          // rebuilt immediately after this view is published. User refs survive.
          var block = program.getMemory().getBlock(start);
          var range = new ghidra.program.model.address.AddressSet(block.getStart(), block.getEnd());
          var refs = program.getReferenceManager();
          var targets = refs.getReferenceDestinationIterator(range, true);
          while (targets.hasNext()) {
            monitor.checkCancelled();
            for (var ref : refs.getReferencesTo(targets.next())) {
              if (ref.getSource() == SourceType.ANALYSIS
                  && (ref.getReferenceType().isRead() || ref.getReferenceType().isWrite())) refs.delete(ref);
            }
          }
        }
        owners.put(pool.getKey(), DartNamespaces.namespace(program, scope, "pool_" + pool.getKey(), false, SourceType.ANALYSIS));
      }
      var map = program.getUsrPropertyManager().getStringPropertyMap(LINKS);
      if (map == null) map = program.getUsrPropertyManager().createStringPropertyMap(LINKS);
      long position = objects.header.numObjects + 1L;
      monitor.initialize(objects.imagePoolEntries().size(), "Publishing named Dart PP slots");
      for (var entry : objects.imagePoolEntries()) {
        monitor.checkCancelled();
        Address record = anchor.add(position++ * 8);
        long offset = entry.byteOffsetFromUntaggedPool();
        Address target = bases.get(entry.poolRef).add(offset);
        String description = program.getListing().getComment(CommentType.EOL, record);
        slot(program, target, owners.get(entry.poolRef), "slot_" + entry.index + "_pp_" + Long.toHexString(offset),
            description == null ? entry.kind.toString() : description, SourceType.ANALYSIS);
        map.add(record, target.toString());
        map.add(target, record.toString());
        DartObjectGraph.link(program, target, record, RefType.DATA);
        monitor.increment();
      }
      pruneExport(program);
    } catch (IOException | CancelledException e) {
      throw e;
    } catch (Exception e) {
      throw new IOException("Cannot publish named pool views", e);
    }
  }

  public static void pruneExport(Program program) {
    var table = program.getSymbolTable();
    var library = table.getNamespace("Library", program.getGlobalNamespace());
    var pp = library == null ? null : table.getNamespace("PP", library);
    var exported = pp == null ? null : table.getNamespace("Export", pp);
    if (exported != null && exported.getSymbol().getSource() != SourceType.USER_DEFINED
        && !table.getSymbols(exported).hasNext()) exported.getSymbol().delete();
  }

  public static void access(Program program, Address site, Address record, RefType type) {
    Address model = forRecord(program, record);
    if (model != null) {
      program.getReferenceManager().addMemoryReference(site, model, type, SourceType.ANALYSIS, -1);
    }
  }
}
