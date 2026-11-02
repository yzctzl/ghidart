package ghidart;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidart.DartValueAnalyzer.ObjectUse;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerTypedef;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Selected-function object provenance, without inventing a native heap image.
 *
 * <p>Seeds come from validated pool instance identities and Class allocation
 * stubs. An SSA value carries one exact Class, not a declared upper bound. Only
 * copies, constant address arithmetic and unanimous merges preserve that fact.
 * Field references denote declarations in OTHER, never physical heap storage.
 * Loads remain loads; signatures and P-code are unchanged. Whole SSA locals with
 * one proved full-width tagged Class may use native shifted-pointer types.
 * Compressed values remain integers; no runtime heap address is fabricated.
 */
final class DartObjectUses {
  record Result(List<ObjectUse> uses, Map<Varnode, String> names, Map<Varnode, DataType> types) {}
  private record ClassInfo(Address identity, int cid, long size, int word, long unboxed,
      Address parent, String typePath, Map<Long, Address> fields) {}
  // displacement is relative to the untagged object base. Runtime object values
  // carry kHeapObjectTag=1; adding an encoded field displacement removes it.
  private record ObjectValue(Address type, long displacement) {}
  private static final ObjectValue CYCLE = new ObjectValue(null, 0);
  private static final class Values extends IdentityHashMap<Varnode, ObjectValue> {
    boolean cyclic;
    int remaining = 100_000;
  }

  private final Program program;
  private final Map<Address, ClassInfo> classes = new HashMap<>();
  private final Map<Address, Address> allocations = new HashMap<>();
  private final Set<Address> conflictingAllocations = new HashSet<>();
  private final Map<Address, Address> instances = new HashMap<>();

  private DartObjectUses(Program program) {
    this.program = program;
  }

  /** Index metadata once per analysis invocation, not once per function. */
  static DartObjectUses read(Program program, TaskMonitor monitor) throws CancelledException {
    var index = new DartObjectUses(program);
    var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    if (facts == null) return index;
    monitor.setMessage("Indexing validated Dart class and field facts");
    monitor.setIndeterminate(true);
    var declarations = new HashMap<Address, JsonObject>();
    for (var it = facts.getPropertyIterator(); it.hasNext();) {
      monitor.checkCancelled();
      Address address = it.next();
      String json = facts.getString(address);
      // Avoid decoding the entire retained object graph for selected functions.
      if (!json.contains("\"kind\":\"Class\"") && !json.contains("\"kind\":\"Field\"")) continue;
      declarations.put(address, JsonParser.parseString(json).getAsJsonObject());
    }
    for (var entry : declarations.entrySet()) {
      monitor.checkCancelled();
      var json = entry.getValue();
      if (!json.get("kind").getAsString().equals("Class")) continue;
      var cls = json.getAsJsonObject("object");
      Address identity = entry.getKey();
      // Layout facts come from the validated producer, not user-editable types.
      if (!json.has("layout")) continue;
      var layout = json.getAsJsonObject("layout");
      int cid = cls.get("classId").getAsInt();
      int word = layout.get("word").getAsInt();
      long size = layout.get("size").getAsLong();
      int parentRef = layout.has("parentRef") ? layout.get("parentRef").getAsInt() : -1;
      Address parent = parentRef <= 0 ? null
          : relative(identity, parentRef, cls.get("refId").getAsInt());
      index.classes.put(identity, new ClassInfo(identity, cid, size, word,
          cls.get("unboxedFields").getAsLong(), parent,
          layout.has("typePath") ? layout.get("typePath").getAsString() : null, new HashMap<>()));
    }
    for (var entry : declarations.entrySet()) {
      monitor.checkCancelled();
      var json = entry.getValue();
      if (!json.get("kind").getAsString().equals("Field") || !json.has("storage")) continue;
      var storage = json.getAsJsonObject("storage");
      if (storage.get("isStatic").getAsBoolean() || !storage.has("offsetOrId")) continue;
      var field = json.getAsJsonObject("object");
      Address owner = relative(entry.getKey(), field.get("ownerRefId").getAsInt(), field.get("refId").getAsInt());
      var cls = index.classes.get(owner);
      long offset = storage.get("offsetOrId").getAsLong();
      if (cls != null && offset >= 8 && offset + cls.word <= cls.size) cls.fields.put(offset, entry.getKey());
    }
    // Code::IsAllocationStubCode is defined by OwnerClassId()==kClassCid.
    // Class.allocation_stub may be cleared by the precompiler; Code.owner
    // survives and is the SDK's authoritative allocation-stub relationship.
    for (var it = facts.getPropertyIterator(); it.hasNext();) {
      monitor.checkCancelled();
      Address address = it.next();
      String json = facts.getString(address);
      if (!json.contains("\"kind\":\"Code\"")) continue;
      var code = JsonParser.parseString(json).getAsJsonObject().getAsJsonObject("object");
      if (code == null) continue;
      Address owner = relative(address, code.get("ownerRef").getAsInt(), code.get("refId").getAsInt());
      if (!index.classes.containsKey(owner)) continue;
      for (var ref : program.getReferenceManager().getReferencesFrom(address)) {
        Address target = ref.getToAddress();
        if (program.getFunctionManager().getFunctionAt(target) == null) continue;
        Address old = index.allocations.putIfAbsent(target, owner);
        if (old != null && !old.equals(owner)) index.conflictingAllocations.add(target);
      }
    }
    index.conflictingAllocations.forEach(index.allocations::remove);
    // Loading units retain parent instances as raw inherited records. Their
    // CIDs have the same Class meaning, but their addresses stay in the local
    // logical identity table; never borrow an external parent's heap address.
    record ScopeCid(long scope, int cid) {}
    var classIds = new HashMap<ScopeCid, Address>();
    for (var cls : index.classes.values()) {
      classIds.put(new ScopeCid(cls.identity.getOffset() >>> 32, cls.cid), cls.identity);
    }
    for (var it = facts.getPropertyIterator(); it.hasNext();) {
      monitor.checkCancelled();
      Address address = it.next();
      String json = facts.getString(address);
      if (!json.contains("\"serialized\"") && !json.contains("\"inherited\"")) continue;
      var object = JsonParser.parseString(json).getAsJsonObject();
      var raw = object.getAsJsonObject(object.has("serialized") ? "serialized" : "inherited");
      if (raw == null || !raw.has("cid")) continue;
      Address type = classIds.get(new ScopeCid(address.getOffset() >>> 32, raw.get("cid").getAsInt()));
      if (type != null) index.instances.put(address, type);
    }
    return index;
  }

  /** Restore only the SDK allocation result, not a logical Dart signature.
   * Native recovery can otherwise combine stale x0/x1 into a 16-byte return.
   * The same Class-owned Code fact used for provenance proves result x0.
   * L1 alone has no such fact and follows its existing machine-only path.
   */
  static int allocationReturns(Program program, List<Function> functions, TaskMonitor monitor)
      throws CancelledException {
    var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    if (facts == null) return 0;
    int changed = 0;
    for (var function : functions) {
      monitor.checkCancelled();
      if (function.isExternal() || function.hasNoReturn()
          || !function.getSignatureSource().isLowerOrEqualPriorityThan(
              ghidra.program.model.symbol.SourceType.ANALYSIS)
          || !function.getReturn().getSource().isLowerOrEqualPriorityThan(
              ghidra.program.model.symbol.SourceType.ANALYSIS)) continue;
      boolean allocation = false;
      for (var ref : program.getReferenceManager().getReferencesTo(function.getEntryPoint())) {
        String json = facts.getString(ref.getFromAddress());
        if (json == null || !json.contains("\"kind\":\"Code\"")) continue;
        var code = JsonParser.parseString(json).getAsJsonObject().getAsJsonObject("object");
        if (code == null) continue;
        Address owner = relative(ref.getFromAddress(), code.get("ownerRef").getAsInt(), code.get("refId").getAsInt());
        String declaration = facts.getString(owner);
        allocation |= declaration != null && declaration.contains("\"kind\":\"Class\"");
      }
      if (!allocation) continue;
      try {
        var storage = new ghidra.program.model.listing.VariableStorage(program, program.getRegister("x0"));
        if (function.getReturnType().getLength() == 8
            && function.getReturn().getVariableStorage().equals(storage)) continue;
        function.setReturn(ghidra.program.model.data.Undefined8DataType.dataType,
            storage, ghidra.program.model.symbol.SourceType.ANALYSIS);
        changed++;
      } catch (ghidra.util.exception.InvalidInputException e) {
        throw new IllegalStateException("Cannot apply proved allocation return at " + function.getEntryPoint(), e);
      }
    }
    return changed;
  }

  private static Address relative(Address identity, int ref, int self) {
    return identity.add((ref - (long) self) * 8);
  }

  Result collect(Function function, HighFunction high, TaskMonitor monitor) throws CancelledException {
    var uses = new ArrayList<ObjectUse>();
    var names = new IdentityHashMap<Varnode, String>();
    var values = new Values();
    var active = java.util.Collections.newSetFromMap(new IdentityHashMap<Varnode, Boolean>());
    for (var it = high.getPcodeOps(); it.hasNext();) {
      monitor.checkCancelled();
      var op = it.next();
      Address site = op.getSeqnum().getTarget();
      if (!function.getBody().contains(site)) continue;
      if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) {
        var object = value(op.getInput(1), high, values, active, 0, monitor);
        if (object == null) continue;
        var cls = classes.get(object.type);
        int width = op.getOpcode() == PcodeOp.LOAD ? op.getOutput().getSize() : op.getInput(2).getSize();
        // An unboxed 64-bit value occupies two compressed words. Require both
        // bitmap bits and no intervening declaration; width alone is not a type.
        boolean fits = cls != null && width == cls.word;
        if (cls != null && cls.word == 4 && width == 8
            && object.displacement >= 8 && object.displacement % 4 == 0
            && object.displacement + 8 <= cls.size) {
          int bit = (int) (object.displacement / 4);
          fits = bit < 63 && ((cls.unboxed >>> bit) & 3) == 3
              && field(cls, object.displacement + 4) == null;
        }
        Address field = fits ? field(cls, object.displacement) : null;
        if (field == null) continue;
        String kind = op.getOpcode() == PcodeOp.LOAD ? "field-read" : "field-write";
        uses.add(new ObjectUse(site.toString(), kind, field.toString(), ""));
        if (op.getOpcode() == PcodeOp.LOAD) names.put(op.getOutput(), "field_" + name(field));
      } else if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
        var result = value(op.getOutput(), high, values, active, 0, monitor);
        if (result != null) {
          uses.add(new ObjectUse(site.toString(), "allocation", result.type.toString(), ""));
          names.put(op.getOutput(), "new_" + name(result.type));
        }
        for (int input = 1; input < op.getNumInputs(); input++) {
          var argument = value(op.getInput(input), high, values, active, 0, monitor);
          if (argument != null && argument.displacement == 1) {
            uses.add(new ObjectUse(site.toString(), "call-argument", argument.type.toString(), Integer.toString(input - 1)));
          }
        }
      } else if (op.getOpcode() == PcodeOp.RETURN) {
        for (int input = 1; input < op.getNumInputs(); input++) {
          var result = value(op.getInput(input), high, values, active, 0, monitor);
          if (result != null && result.displacement == 1) uses.add(new ObjectUse(site.toString(), "return", result.type.toString(), ""));
        }
      }
    }
    var types = new IdentityHashMap<Varnode, DataType>();
    for (var node : names.keySet()) {
      var object = value(node, high, values, active, 0, monitor);
      if (object == null || object == CYCLE || object.displacement != 1 || node.getHigh() == null) continue;
      // One HighVariable can contain several SSA definitions. Typing only the
      // allocation result would incorrectly type unrelated register reuses or
      // mixed-class merges that Ghidra grouped into the same local.
      boolean exact = true;
      for (var instance : node.getHigh().getInstances()) {
        if (!object.equals(value(instance, high, values, active, 0, monitor))) { exact = false; break; }
      }
      if (!exact) continue;
      var cls = classes.get(object.type);
      if (cls == null || cls.typePath == null) continue;
      var manager = program.getDataTypeManager();
      var layout = manager.getDataType(cls.typePath);
      if (!(layout instanceof Structure) || layout.getLength() != cls.size) continue;
      // The pointer holds the real tagged address: one byte into the untagged
      // layout. Ghidra's native pointer-relative model displays ADJ(p)->field,
      // preserving tag arithmetic instead of pretending p is an ordinary ptr.
      var pointer = new PointerTypedef("Tagged_" + layout.getName(),
          layout, 8, manager, 1L);
      var old = manager.getDataType(pointer.getCategoryPath(), pointer.getName());
      if (old != null && !old.isEquivalent(pointer)) continue; // Preserve edited types.
      types.put(node, old == null ? manager.addDataType(pointer, null) : old);
    }
    return new Result(List.copyOf(uses), names, types);
  }

  private Address field(ClassInfo cls, long offset) {
    var seen = new HashSet<Address>();
    while (cls != null && seen.add(cls.identity)) {
      Address field = cls.fields.get(offset);
      if (field != null) return field;
      cls = classes.get(cls.parent);
    }
    return null;
  }

  private String name(Address identity) {
    var symbol = program.getSymbolTable().getPrimarySymbol(identity);
    if (symbol == null) return Long.toHexString(identity.getOffset());
    String text = symbol.getName().equals("class_info") ? symbol.getParentNamespace().getName() : symbol.getName();
    text = SymbolUtilities.replaceInvalidChars(text, true);
    return text.length() > 80 ? text.substring(0, 80) : text;
  }

  private ObjectValue value(Varnode node, HighFunction high, Values cache,
      Set<Varnode> active, int depth, TaskMonitor monitor) throws CancelledException {
    monitor.checkCancelled();
    if (node == null || depth >= 64 || --cache.remaining < 0 || node.getSize() != 8) return null;
    if (cache.containsKey(node)) return cache.get(node);
    if (!active.add(node)) {
      // Intermediate answers inside a mutually recursive PHI are contextual.
      // Do not memoize them as facts before all external inputs are checked.
      cache.cyclic = true;
      return CYCLE;
    }
    ObjectValue result = null;
    try {
      var op = node.getDef();
      if (op == null) return null;
      switch (op.getOpcode()) {
        case PcodeOp.LOAD -> {
          // Native PP references identify a slot, not an arbitrary nearby load.
          int loads = 0;
          var instructions = op.getParent().getIterator();
          while (instructions.hasNext()) {
            var other = instructions.next();
            if (other.getOpcode() == PcodeOp.LOAD && other.getSeqnum().getTarget().equals(op.getSeqnum().getTarget())) loads++;
          }
          if (loads != 1) break;
          Address type = null;
          for (var ref : program.getReferenceManager().getReferencesFrom(op.getSeqnum().getTarget())) {
            if (ref.getReferenceType() != RefType.READ) continue;
            var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
            String json = facts == null ? null : facts.getString(ref.getToAddress());
            if (json == null || !json.contains("\"poolRef\"")) return null;
            var slot = JsonParser.parseString(json).getAsJsonObject();
            // The producer qualifies raw trait bits using the validated format.
            // Older SDKs use bit 7; newer ones use bit 4 plus reset behaviors.
            if (!slot.has("stableTaggedBits") || !slot.get("kind").getAsString().equals("TAGGED")
                || slot.get("bits").getAsInt() != slot.get("stableTaggedBits").getAsInt()) return null;
            Address slotType = null;
            for (var target : program.getReferenceManager().getReferencesFrom(ref.getToAddress())) {
              Address candidate = instances.get(target.getToAddress());
              if (candidate != null) {
                if (slotType != null && !slotType.equals(candidate)) return null;
                slotType = candidate;
              }
            }
            // Every possible read slot must agree. A known alternative cannot
            // justify an unknown, patchable or differently typed alternative.
            if (slotType == null || type != null && !type.equals(slotType)) return null;
            type = slotType;
          }
          if (type != null) result = new ObjectValue(type, 1);
        }
        case PcodeOp.CALL -> {
          Address type = allocations.get(op.getInput(0).getAddress());
          // A typed local may make Ghidra split the machine x0 result into a
          // unique CALL temporary followed by CAST. Verify the callee's physical
          // return storage, not the optimizer's temporary address.
          var callee = program.getFunctionManager().getFunctionAt(op.getInput(0).getAddress());
          if (type == null || callee == null) break;
          var storage = callee.getReturn().getVariableStorage().getVarnodes();
          if (storage.length == 1 && storage[0].getSize() == 8
              && storage[0].getAddress().equals(program.getRegister("x0").getAddress())) {
            result = new ObjectValue(type, 1);
          }
        }
        case PcodeOp.COPY, PcodeOp.CAST -> result = value(op.getInput(0), high, cache, active, depth + 1, monitor);
        case PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.PTRADD, PcodeOp.PTRSUB -> {
          var a = op.getInput(0);
          var b = op.getInput(1);
          if (a.isConstant() && op.getOpcode() == PcodeOp.INT_ADD) { var swap = a; a = b; b = swap; }
          if (!b.isConstant()) break;
          var base = value(a, high, cache, active, depth + 1, monitor);
          if (base != null && base != CYCLE) {
            long offset = b.getOffset();
            if (op.getOpcode() == PcodeOp.INT_SUB) offset = -offset;
            if (op.getOpcode() == PcodeOp.PTRADD) {
              if (!op.getInput(2).isConstant()) break;
              try { offset = Math.multiplyExact(offset, op.getInput(2).getOffset()); }
              catch (ArithmeticException e) { break; }
            }
            long displacement;
            try { displacement = Math.addExact(base.displacement, offset); }
            catch (ArithmeticException e) { break; }
            if (displacement >= 0 && displacement < classes.get(base.type).size) result = new ObjectValue(base.type, displacement);
          }
        }
        case PcodeOp.INDIRECT -> {
          // Only a caller-local spill across an owned helper is type-preserving.
          // Pointer bits can move during GC; arbitrary memory effects still stop.
          if (!node.getAddress().isStackAddress() || node.getOffset() >= 0
              || !op.getInput(1).isConstant()) break;
          var effect = high.getOpRef((int) op.getInput(1).getOffset());
          if (effect != null && (effect.getOpcode() == PcodeOp.CALL || effect.getOpcode() == PcodeOp.CALLIND)
              && DartThreadCalls.preservesSpilledObjectType(program, high.getFunction(), effect.getSeqnum().getTarget())) {
            result = value(op.getInput(0), high, cache, active, depth + 1, monitor);
          }
        }
        case PcodeOp.MULTIEQUAL -> {
          for (var input : op.getInputs()) {
            var incoming = value(input, high, cache, active, depth + 1, monitor);
            // A loop-carried COPY/owned-helper cycle contributes no new type.
            // Every non-cyclic input must still be known and agree. Arithmetic
            // through a cycle is rejected instead of assuming a fixed offset.
            if (incoming == CYCLE) continue;
            if (incoming == null || result != null && !result.equals(incoming)) { result = null; break; }
            result = incoming;
          }
        }
      }
    } finally {
      active.remove(node);
      if (!cache.cyclic && result != CYCLE) cache.put(node, result);
    }
    return depth == 0 && result == CYCLE ? null : result;
  }
}
