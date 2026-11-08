package ghidart.analysis;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidart.analysis.DartValueAnalyzer.ObjectUse;
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
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Selected-function object provenance, without inventing a native heap image.
 *
 * <p>Seeds come from validated pool instance identities, Class allocation
 * stubs, and proved method receiver physical entry storage. An SSA value carries
 * one known implementation layout or a bounded set of candidate layouts. Only
 * copies, constant address arithmetic and unanimous merges preserve that fact.
 * Field relationships denote retained declarations, never physical heap storage.
 * Loads remain loads; signatures and P-code are unchanged. Whole SSA locals with
 * one proved full-width tagged Class may use native shifted-pointer types.
 * Compressed values remain integers; no runtime heap address is fabricated.
 */
final class DartObjectUses {
  record Result(List<ObjectUse> uses, Map<Varnode, String> names, Map<Varnode, DataType> types) {}
  private record ClassInfo(Address identity, int cid, long size, int word, long unboxed,
      Address parent, String typePath, Map<Long, Address> fields) {}
  private record InstanceSlotFact(long byteOffset, Address targetAddress, Long unboxed) {}
  private record InstanceFact(Address type, boolean isImmutable, Map<Long, InstanceSlotFact> slots) {}

  // displacement is relative to the untagged object base. Runtime object values
  // carry kHeapObjectTag=1; adding an encoded field displacement removes it.
  private record ObjectValue(Address type, Set<Address> candidates, long displacement, Address instance,
      boolean compressed) {
    ObjectValue(Address type, Set<Address> candidates, long displacement, Address instance) {
      this(type, candidates, displacement, instance, false);
    }
    @SuppressWarnings("unused")
    ObjectValue(Address type, long displacement) {
      this(type, type == null ? Set.of() : Set.of(type), displacement, null);
    }
    ObjectValue(Address type, long displacement, Address instance) {
      this(type, type == null ? Set.of() : Set.of(type), displacement, instance);
    }
    @SuppressWarnings("unused")
    ObjectValue(Set<Address> candidates, long displacement) {
      this(candidates.size() == 1 ? candidates.iterator().next() : null, candidates, displacement, null);
    }
  }

  private static final ObjectValue CYCLE = new ObjectValue(null, Set.of(), 0, null);
  private static final class Values extends IdentityHashMap<Varnode, ObjectValue> {
    boolean cyclic;
    int remaining = 100_000;
  }

  private final Program program;
  private final Map<Address, ClassInfo> classes = new HashMap<>();
  private final Map<Address, Address> allocations = new HashMap<>();
  private final Set<Address> conflictingAllocations = new HashSet<>();
  private final Map<Address, Address> instances = new HashMap<>();
  private final Set<Address> immutableInstances = new HashSet<>();
  private final Map<Address, InstanceFact> instanceFacts = new HashMap<>();
  private final Map<Address, Address> strings = new HashMap<>();
  private record Receiver(Address owner, int parameters, boolean stackOnly) {}
  private final Map<Address, Receiver> receivers = new HashMap<>();
  private final Set<Address> conflictingReceivers = new HashSet<>();

  private DartObjectUses(Program program) {
    this.program = program;
  }

  /** Index metadata once per analysis invocation, not once per function. */
  static DartObjectUses read(Program program, TaskMonitor monitor) throws CancelledException {
    var index = new DartObjectUses(program);
    var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    if (facts == null) return index;
    monitor.setMessage("Indexing validated Dart class, field, instance and receiver facts");
    monitor.setIndeterminate(true);

    var declarations = new HashMap<Address, JsonObject>();
    var codeEntries = new HashMap<Address, JsonObject>();
    var functionFacts = new HashMap<Address, JsonObject>();

    for (var it = facts.getPropertyIterator(); it.hasNext();) {
      monitor.checkCancelled();
      Address address = it.next();
      String json = facts.getString(address);
      if (json.contains("\"kind\":\"Class\"") || json.contains("\"kind\":\"Field\"")) {
        declarations.put(address, JsonParser.parseString(json).getAsJsonObject());
      } else if (json.contains("\"functionInfo\"")) {
        functionFacts.put(address, JsonParser.parseString(json).getAsJsonObject());
      } else if (json.contains("\"kind\":\"Code\"")) {
        codeEntries.put(address, JsonParser.parseString(json).getAsJsonObject());
      } else if (json.contains("\"kind\":\"String\"")) {
        var strObj = JsonParser.parseString(json).getAsJsonObject();
        if (strObj.has("payload")) {
          Address payload = program.getAddressFactory().getAddress(strObj.get("payload").getAsString());
          if (payload != null) index.strings.put(address, payload);
        }
      }
    }

    // 1. Classes
    for (var entry : declarations.entrySet()) {
      monitor.checkCancelled();
      var json = entry.getValue();
      if (!json.get("kind").getAsString().equals("Class")) continue;
      var cls = json.getAsJsonObject("object");
      Address identity = entry.getKey();
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

    // 2. Fields
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

    // 3. Instances (CID -> Class)
    record ScopeCid(long scope, int cid) {}
    var classIds = new HashMap<ScopeCid, Address>();
    for (var cls : index.classes.values()) {
      classIds.put(new ScopeCid(cls.identity.getOffset() >>> 32, cls.cid), cls.identity);
    }
    // Stream raw records rather than retaining a second decoded copy of every
    // object. Only instance slots belonging to a known Class survive this pass.
    for (var it = facts.getPropertyIterator(); it.hasNext();) {
      monitor.checkCancelled();
      Address address = it.next();
      String json = facts.getString(address);
      if (!json.contains("\"serialized\"") && !json.contains("\"inherited\"")) continue;
      var object = JsonParser.parseString(json).getAsJsonObject();
      var raw = object.getAsJsonObject(object.has("serialized") ? "serialized" : "inherited");
      if (raw == null || !raw.has("cid")) continue;
      Address type = classIds.get(new ScopeCid(address.getOffset() >>> 32, raw.get("cid").getAsInt()));
      if (type != null) {
        index.instances.put(address, type);
        int selfRef = raw.get("refId").getAsInt();
        Address anchor = relative(address, 0, selfRef);
        boolean isImm = object.has("immutable") && object.get("immutable").getAsBoolean();
        if (isImm) index.immutableInstances.add(address);
        if (object.has("instanceSlots")) {
          var slotsArray = object.getAsJsonArray("instanceSlots");
          var slotMap = new HashMap<Long, InstanceSlotFact>();
          for (var el : slotsArray) {
            var s = el.getAsJsonObject();
            long byteOffset = s.get("byteOffset").getAsLong();
            int targetRef = s.get("targetRef").getAsInt();
            Long unboxed = s.has("unboxed") && !s.get("unboxed").isJsonNull() ? s.get("unboxed").getAsLong() : null;
            Address targetAddr = targetRef > 0 ? anchor.add((long) targetRef * 8L) : null;
            slotMap.put(byteOffset, new InstanceSlotFact(byteOffset, targetAddr, unboxed));
          }
          index.instanceFacts.put(address, new InstanceFact(type, isImm, slotMap));
        }
      }
    }

    // 4. Code-owned allocation stubs
    for (var entry : codeEntries.entrySet()) {
      monitor.checkCancelled();
      Address address = entry.getKey();
      var code = entry.getValue().getAsJsonObject("object");
      if (code == null) continue;
      int ownerRef = code.get("ownerRef").getAsInt();
      int refId = code.get("refId").getAsInt();
      Address owner = relative(address, ownerRef, refId);

      // Allocation stub: owner is a Class
      if (index.classes.containsKey(owner)) {
        for (var ref : ghidart.snapshot.DartObjectGraph.from(program, address)) {
          Address target = ref.getToAddress();
          if (program.getFunctionManager().getFunctionAt(target) == null) continue;
          Address old = index.allocations.putIfAbsent(target, owner);
          if (old != null && !old.equals(owner)) index.conflictingAllocations.add(target);
        }
      }

    }
    // DedupInstructions shares one Code between unrelated Function declarations.
    // Code.owner is only a representative; all aliases must agree on a receiver
    // contract before a shared physical entry acquires an implementation layout.
    for (var entry : functionFacts.entrySet()) {
      monitor.checkCancelled();
      Address identity = entry.getKey();
      var info = entry.getValue().getAsJsonObject("functionInfo");
      Receiver receiver = null;
      int self = info.get("refId").getAsInt();
      Address owner = relative(identity, info.get("ownerRefId").getAsInt(), self);
      int signatureRef = info.get("signatureRefId").getAsInt();
      String signatureJson = signatureRef > 0 ? facts.getString(relative(identity, signatureRef, self)) : null;
      var signature = signatureJson == null ? null
          : JsonParser.parseString(signatureJson).getAsJsonObject().getAsJsonObject("signature");
      String role = info.has("role") ? info.get("role").getAsString() : "";
      if (info.get("hasThis").getAsBoolean() && index.classes.containsKey(owner)
          && signature != null && signature.get("hasImplicit").getAsBoolean()
          && signature.get("numOptional").getAsInt() == 0 && !role.isEmpty()) {
        boolean stackOnly = Set.of("MethodExtractor", "NoSuchMethodDispatcher",
            "InvokeFieldDispatcher", "DynamicInvocationForwarder", "FieldInitializer").contains(role);
        receiver = new Receiver(owner, signature.get("numFixed").getAsInt() + 1, stackOnly);
      }
      for (var ref : ghidart.snapshot.DartObjectGraph.from(program, identity)) {
        Address target = ref.getToAddress();
        if (program.getFunctionManager().getFunctionAt(target) == null) continue;
        if (receiver == null) {
          index.conflictingReceivers.add(target);
        } else {
          Receiver old = index.receivers.putIfAbsent(target, receiver);
          if (old != null && !old.equals(receiver)) index.conflictingReceivers.add(target);
        }
      }
    }
    index.conflictingAllocations.forEach(index.allocations::remove);
    index.conflictingReceivers.forEach(index.receivers::remove);

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
              SourceType.ANALYSIS)
          || !function.getReturn().getSource().isLowerOrEqualPriorityThan(
              SourceType.ANALYSIS)) continue;
      boolean allocation = false;
      for (var ref : ghidart.snapshot.DartObjectGraph.to(program, function.getEntryPoint())) {
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
            storage, SourceType.ANALYSIS);
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

  /** Match a complete recovered physical prototype to a required-argument entry.
   * ARM64 Dart register arguments start at x1, not the result register x0.
   * Stack-only entries reverse logical arguments; this is the highest slot.
   * Missing inputs, optional copies and user/imported prototypes remain unknown.
   * The owner proves an implementation layout, not exact runtime subtype.
   */
  private Address receiverStorage(Function function, Receiver receiver) {
    if (receiver == null || receiver.parameters() < 1
        || function.getParameterCount() != receiver.parameters()
        || function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS)) return null;
    Address register = null;
    var stack = new HashSet<Long>();
    for (var parameter : function.getParameters()) {
      if (parameter.getSource().isHigherPriorityThan(SourceType.ANALYSIS)) return null;
      var storage = parameter.getVariableStorage().getVarnodes();
      if (storage.length != 1 || storage[0].getSize() != 8) return null;
      var node = storage[0];
      if (node.isRegister()) {
        var reg = program.getRegister(node.getAddress(), node.getSize());
        if (reg == null || !Set.of("x1", "x2", "x3", "x5", "x6", "x7",
            "d0", "d1", "d2", "d3", "d4", "d5").contains(reg.getName())) return null;
        if (reg.equals(program.getRegister("x1"))) register = node.getAddress();
      } else if (node.getAddress().isStackAddress() && node.getOffset() >= 0) {
        stack.add(node.getOffset());
      } else return null;
    }
    if (!receiver.stackOnly() && register != null) return register;
    if (stack.size() != receiver.parameters()) return null;
    for (int i = 0; i < receiver.parameters(); i++) if (!stack.contains(i * 8L)) return null;
    return program.getAddressFactory().getStackSpace().getAddress((receiver.parameters() - 1) * 8L);
  }

  /** COPY-only leaf summary, expressed as a physical formal-parameter index.
   * Arithmetic and loads invalidate an identity even when they read x0/x1.
   * Branching, gaps, calls and unknown exits are deliberately not summarized.
   */
  private int forwardedParameter(Function callee) {
    if (callee == null || callee.isExternal() || callee.hasNoReturn()
        || callee.getBody().getNumAddresses() > 64) return -1;
    var returned = callee.getReturn().getVariableStorage().getVarnodes();
    if (returned.length != 1 || returned[0].getSize() != 8) return -1;
    record Storage(Address address, int size) {}
    var origins = new HashMap<Storage, Integer>();
    for (var parameter : callee.getParameters()) {
      var storage = parameter.getVariableStorage().getVarnodes();
      if (storage.length == 1 && storage[0].getSize() == 8 && storage[0].isRegister()) {
        origins.put(new Storage(storage[0].getAddress(), 8), parameter.getOrdinal());
      }
    }
    Address next = callee.getEntryPoint();
    for (var it = program.getListing().getInstructions(callee.getBody(), true); it.hasNext();) {
      var instruction = it.next();
      if (!instruction.getAddress().equals(next) || instruction.getFlowType().isCall()
          || instruction.getFlowType().isJump()) return -1;
      for (var op : instruction.getPcode()) {
        if (op.getOpcode() == PcodeOp.RETURN) {
          if (it.hasNext() || !instruction.getMaxAddress().equals(callee.getBody().getMaxAddress())) return -1;
          return origins.getOrDefault(new Storage(returned[0].getAddress(), 8), -1);
        }
        if (op.getOpcode() == PcodeOp.CALLOTHER || op.getOpcode() == PcodeOp.BRANCH
            || op.getOpcode() == PcodeOp.CBRANCH || op.getOpcode() == PcodeOp.BRANCHIND
            || op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) return -1;
        var output = op.getOutput();
        if (output == null) continue;
        Integer origin = op.getOpcode() == PcodeOp.COPY && output.getSize() == 8
            ? origins.get(new Storage(op.getInput(0).getAddress(), op.getInput(0).getSize())) : null;
        // A partial write also destroys a prior full-register identity.
        origins.keySet().removeIf(key -> key.address().getAddressSpace().equals(output.getAddress().getAddressSpace())
            && key.address().getOffset() < output.getOffset() + output.getSize()
            && output.getOffset() < key.address().getOffset() + key.size());
        if (origin != null) origins.put(new Storage(output.getAddress(), output.getSize()), origin);
      }
      if (instruction.getFlowType().isTerminal()) return -1;
      next = instruction.getFallThrough();
    }
    return -1;
  }

  private boolean hasCallOverride(Function caller, Address site) {
    var space = HighFunction.findOverrideSpace(caller);
    if (space == null) return false;
    for (var symbol : program.getSymbolTable().getSymbols(space)) {
      if (symbol.getAddress().equals(site)
          && ghidra.program.model.pcode.HighFunctionDBUtil.readOverride(symbol) != null) return true;
    }
    return false;
  }

  Result collect(Function function, HighFunction high, TaskMonitor monitor) throws CancelledException {
    var uses = new ArrayList<ObjectUse>();
    var names = new IdentityHashMap<Varnode, String>();
    var values = new Values();
    var active = Collections.newSetFromMap(new IdentityHashMap<Varnode, Boolean>());
    for (var it = high.getPcodeOps(); it.hasNext();) {
      monitor.checkCancelled();
      var op = it.next();
      Address site = op.getSeqnum().getTarget();
      if (!function.getBody().contains(site)) continue;
      if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) {
        var object = value(op.getInput(1), high, values, active, 0, monitor);
        if (object == null || object.compressed || object.candidates.isEmpty()) continue;
        int width = op.getOpcode() == PcodeOp.LOAD ? op.getOutput().getSize() : op.getInput(2).getSize();

        Address commonField = null;
        boolean allMatch = true;
        for (var candidate : object.candidates) {
          var cls = classes.get(candidate);
          if (cls == null) { allMatch = false; break; }
          boolean fits = width == cls.word;
          if (cls.word == 4 && width == 8
              && object.displacement >= 8 && object.displacement % 4 == 0
              && object.displacement + 8 <= cls.size) {
            int bit = (int) (object.displacement / 4);
            fits = bit < 63 && ((cls.unboxed >>> bit) & 3) == 3
                && field(cls, object.displacement + 4) == null;
          }
          if (!fits) { allMatch = false; break; }
          Address f = field(cls, object.displacement);
          if (f == null) { allMatch = false; break; }
          if (commonField == null) {
            commonField = f;
          } else if (!commonField.equals(f)) {
            allMatch = false;
            break;
          }
        }

        if (allMatch && commonField != null) {
          String kind = op.getOpcode() == PcodeOp.LOAD ? "field-read" : "field-write";
          uses.add(new ObjectUse(site.toString(), kind, commonField.toString(), ""));
          if (op.getOpcode() == PcodeOp.LOAD) {
            names.put(op.getOutput(), "field_" + name(commonField));
            if (object.instance != null) {
              var fact = instanceFacts.get(object.instance);
              if (fact != null && fact.isImmutable()) {
                var slot = fact.slots().get(object.displacement);
                if (slot != null && slot.targetAddress() != null) {
                  Address payload = strings.get(slot.targetAddress());
                  if (payload != null) {
                    uses.add(new ObjectUse(site.toString(), "string-read", payload.toString(), ""));
                  }
                }
              }
            }
          }
        }
      } else if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
        var result = value(op.getOutput(), high, values, active, 0, monitor);
        if (result != null && result.type != null && op.getOpcode() == PcodeOp.CALL
            && allocations.containsKey(op.getInput(0).getAddress())) {
          uses.add(new ObjectUse(site.toString(), "allocation", result.type.toString(), ""));
          names.put(op.getOutput(), "new_" + name(result.type));
        }
        for (int input = 1; input < op.getNumInputs(); input++) {
          var argument = value(op.getInput(input), high, values, active, 0, monitor);
          if (argument != null && argument.displacement == 1 && !argument.compressed && argument.type != null) {
            uses.add(new ObjectUse(site.toString(), "call-argument", argument.type.toString(), Integer.toString(input - 1)));
          }
        }
      } else if (op.getOpcode() == PcodeOp.RETURN) {
        for (int input = 1; input < op.getNumInputs(); input++) {
          var result = value(op.getInput(input), high, values, active, 0, monitor);
          if (result != null && result.displacement == 1 && !result.compressed && result.type != null) {
            uses.add(new ObjectUse(site.toString(), "return", result.type.toString(), ""));
          }
        }
      }
    }
    var types = new IdentityHashMap<Varnode, DataType>();
    for (var node : names.keySet()) {
      var object = value(node, high, values, active, 0, monitor);
      if (object == null || object == CYCLE || object.displacement != 1 || object.compressed || object.type == null || node.getHigh() == null) continue;
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
    String text = ghidart.snapshot.DartObjectGraph.name(program, identity);
    if (text == null) text = ghidart.snapshot.DartObjectGraph.describe(program, identity);
    text = text.replaceFirst("^(Class|Field|Function|Code) ", "");
    int scope = text.lastIndexOf("::");
    if (scope >= 0) text = text.substring(scope + 2);
    text = SymbolUtilities.replaceInvalidChars(text, true);
    return text.length() > 80 ? text.substring(0, 80) : text;
  }

  /** Only the SDK's actual heap-base arithmetic restores a native pointer.
   * A zero-extended compressed reference alone remains a numeric tagged value.
   */
  private boolean heapBase(Varnode node, int depth) {
    if (node == null || depth > 8) return false;
    var op = node.getDef();
    if (op == null) return false;
    if (op.getOpcode() == PcodeOp.COPY || op.getOpcode() == PcodeOp.CAST) {
      return heapBase(op.getInput(0), depth + 1);
    }
    if (op.getOpcode() != PcodeOp.INT_LEFT || !op.getInput(1).isConstant()
        || op.getInput(1).getOffset() != 32) return false;
    var base = op.getInput(0);
    String name = program.getCompilerSpec().getCompilerSpecID().toString().equals("dart-r23") ? "x23" : "x28";
    var register = program.getRegister(name);
    return register != null && base.getSize() == 8 && base.getDef() == null
        && base.getAddress().equals(register.getAddress());
  }

  private ObjectValue value(Varnode node, HighFunction high, Values cache,
      Set<Varnode> active, int depth, TaskMonitor monitor) throws CancelledException {
    monitor.checkCancelled();
    if (node == null || depth >= 64 || --cache.remaining < 0 || (node.getSize() != 8 && node.getSize() != 4)) return null;
    if (cache.containsKey(node)) return cache.get(node);
    if (!active.add(node)) {
      // Intermediate answers inside a mutually recursive PHI are contextual.
      // Do not memoize them as facts before all external inputs are checked.
      cache.cyclic = true;
      return CYCLE;
    }
    ObjectValue result = null;
    try {
      if (node.isInput()) {
        var function = high.getFunction();
        var receiver = receivers.get(function.getEntryPoint());
        var storage = receiverStorage(function, receiver);
        if (storage != null && node.getSize() == 8 && node.getAddress().equals(storage)) {
          result = new ObjectValue(receiver.owner(), 1, null);
        }
      } else {
        var op = node.getDef();
        if (op != null) {
          switch (op.getOpcode()) {
            case PcodeOp.LOAD -> {
              // 1. PP slot load
              int loads = 0;
              var instructions = op.getParent().getIterator();
              while (instructions.hasNext()) {
                var other = instructions.next();
                if (other.getOpcode() == PcodeOp.LOAD && other.getSeqnum().getTarget().equals(op.getSeqnum().getTarget())) loads++;
              }
              if (loads == 1 && node.getSize() == 8) {
                Address type = null;
                Address targetInst = null;
                boolean sameInstance = true;
                boolean validPp = false;
                for (var ref : ghidart.snapshot.DartObjectGraph.from(program, op.getSeqnum().getTarget())) {
                  if (ref.getReferenceType() != RefType.READ) continue;
                  var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
                  String json = facts == null ? null : facts.getString(ref.getToAddress());
                  if (json == null || !json.contains("\"poolRef\"")) { type = null; break; }
                  var slot = JsonParser.parseString(json).getAsJsonObject();
                  // The producer qualifies raw trait bits using the validated format.
                  // Older SDKs use bit 7; newer ones use bit 4 plus reset behaviors.
                  if (!slot.has("stableTaggedBits") || !slot.get("kind").getAsString().equals("TAGGED")
                      || slot.get("bits").getAsInt() != slot.get("stableTaggedBits").getAsInt()) { type = null; break; }
                  Address slotType = null;
                  Address slotInst = null;
                  boolean sameSlotInstance = true;
                  for (var target : ghidart.snapshot.DartObjectGraph.from(program, ref.getToAddress())) {
                    Address candidate = instances.get(target.getToAddress());
                    if (candidate == null) { slotType = null; break; }
                    if (slotType != null && !slotType.equals(candidate)) { slotType = null; break; }
                    if (slotInst != null && !slotInst.equals(target.getToAddress())) sameSlotInstance = false;
                    slotType = candidate;
                    slotInst = target.getToAddress();
                  }
                  // Every possible read slot must agree. A known alternative cannot
                  // justify an unknown, patchable or differently typed alternative.
                  if (slotType == null || (type != null && !type.equals(slotType))) { type = null; break; }
                  if (!sameSlotInstance || validPp && !java.util.Objects.equals(targetInst, slotInst)) sameInstance = false;
                  type = slotType;
                  targetInst = slotInst;
                  validPp = true;
                }
                if (validPp && type != null) {
                  boolean isImm = sameInstance && targetInst != null && immutableInstances.contains(targetInst);
                  result = new ObjectValue(type, 1, isImm ? targetInst : null);
                  break;
                }
              }

              // 2. Field load on immutable instance
              var base = value(op.getInput(1), high, cache, active, depth + 1, monitor);
              if (base != null && base != CYCLE && base.instance != null
                  && !base.compressed && base.type != null && classes.get(base.type).word == node.getSize()) {
                var fact = instanceFacts.get(base.instance);
                if (fact != null && fact.isImmutable()) {
                  var slot = fact.slots().get(base.displacement);
                  if (slot != null && slot.targetAddress() != null) {
                    Address targetType = instances.get(slot.targetAddress());
                    if (targetType != null) {
                      boolean targetImm = immutableInstances.contains(slot.targetAddress());
                      result = new ObjectValue(targetType, Set.of(targetType), 1,
                          targetImm ? slot.targetAddress() : null, node.getSize() == 4);
                    }
                  }
                }
              }
            }
            case PcodeOp.CALL -> {
              if (node.getSize() != 8) break;
              if (hasCallOverride(high.getFunction(), op.getSeqnum().getTarget())) break;
              Address target = op.getInput(0).getAddress();
              Address type = allocations.get(target);
              var callee = program.getFunctionManager().getFunctionAt(target);
              if (type != null && callee != null) {
                var storage = callee.getReturn().getVariableStorage().getVarnodes();
                if (storage.length == 1 && storage[0].getSize() == 8
                    && storage[0].getAddress().equals(program.getRegister("x0").getAddress())) {
                  result = new ObjectValue(type, 1, null);
                }
              } else if (callee != null) {
                int parameter = forwardedParameter(callee);
                if (parameter >= 0 && op.getNumInputs() == callee.getParameterCount() + 1) {
                  result = value(op.getInput(parameter + 1), high, cache, active, depth + 1, monitor);
                }
              }
            }
            case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT -> {
              var input = value(op.getInput(0), high, cache, active, depth + 1, monitor);
              if (input != null && input != CYCLE
                  && (op.getInput(0).getSize() == node.getSize() || input.compressed)) result = input;
            }
            case PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.PTRADD, PcodeOp.PTRSUB -> {
              var a = op.getInput(0);
              var b = op.getInput(1);
              if (op.getOpcode() == PcodeOp.INT_ADD && node.getSize() == 8) {
                var pointer = value(a, high, cache, active, depth + 1, monitor);
                if (pointer != null && pointer != CYCLE && pointer.compressed && heapBase(b, 0)) {
                  result = new ObjectValue(pointer.type, pointer.candidates, pointer.displacement, pointer.instance);
                  break;
                }
                pointer = value(b, high, cache, active, depth + 1, monitor);
                if (pointer != null && pointer != CYCLE && pointer.compressed && heapBase(a, 0)) {
                  result = new ObjectValue(pointer.type, pointer.candidates, pointer.displacement, pointer.instance);
                  break;
                }
              }
              if (a.isConstant() && op.getOpcode() == PcodeOp.INT_ADD) { var swap = a; a = b; b = swap; }
              if (b.isConstant()) {
                var base = value(a, high, cache, active, depth + 1, monitor);
                if (base != null && base != CYCLE && !base.candidates.isEmpty()) {
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
                  boolean inBounds = true;
                  for (var cand : base.candidates) {
                    var cls = classes.get(cand);
                    if (cls == null || displacement < 0 || displacement >= cls.size) {
                      inBounds = false;
                      break;
                    }
                  }
                  if (inBounds) {
                    result = new ObjectValue(base.type, base.candidates, displacement, base.instance, base.compressed);
                  }
                }
              }
            }
            case PcodeOp.INDIRECT -> {
              // Only a caller-local spill across an owned helper is type-preserving.
              // Pointer bits can move during GC; arbitrary memory effects still stop.
              if (node.getAddress().isStackAddress() && node.getOffset() < 0
                  && op.getInput(1).isConstant()) {
                var effect = high.getOpRef((int) op.getInput(1).getOffset());
                if (effect != null && (effect.getOpcode() == PcodeOp.CALL || effect.getOpcode() == PcodeOp.CALLIND)
                    && DartThreadCalls.preservesSpilledObjectType(program, high.getFunction(), effect.getSeqnum().getTarget())) {
                  var input = value(op.getInput(0), high, cache, active, depth + 1, monitor);
                  if (input != null && input != CYCLE
                      && (node.getSize() == op.getInput(0).getSize() || input.compressed)) result = input;
                }
              }
            }
            case PcodeOp.MULTIEQUAL -> {
              long commonDisp = -1;
              Set<Address> mergedCandidates = new HashSet<>();
              Address commonInstance = null;
              boolean firstInstance = true;
              boolean valid = true;
              Boolean compressed = null;
              for (var input : op.getInputs()) {
                var incoming = value(input, high, cache, active, depth + 1, monitor);
                if (incoming == CYCLE) continue;
                if (incoming == null || incoming.candidates.isEmpty()) {
                  valid = false;
                  break;
                }
                if (compressed != null && compressed != incoming.compressed) { valid = false; break; }
                compressed = incoming.compressed;
                if (commonDisp == -1) {
                  commonDisp = incoming.displacement;
                } else if (commonDisp != incoming.displacement) {
                  valid = false;
                  break;
                }
                mergedCandidates.addAll(incoming.candidates);
                if (mergedCandidates.size() > 4) {
                  valid = false;
                  break;
                }
                if (firstInstance) {
                  commonInstance = incoming.instance;
                  firstInstance = false;
                } else if (commonInstance != null && !commonInstance.equals(incoming.instance)) {
                  commonInstance = null;
                }
              }
              if (valid && !mergedCandidates.isEmpty()) {
                if (mergedCandidates.size() == 1) {
                  result = new ObjectValue(mergedCandidates.iterator().next(), Set.copyOf(mergedCandidates),
                      commonDisp, commonInstance, Boolean.TRUE.equals(compressed));
                } else {
                  result = new ObjectValue(null, Set.copyOf(mergedCandidates), commonDisp, null,
                      Boolean.TRUE.equals(compressed));
                }
              }
            }
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
