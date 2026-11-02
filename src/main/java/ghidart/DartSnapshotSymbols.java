package ghidart;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Publish retained L2 identities as native namespaces, labels and navigable pool slots.
 *
 * Library URLs determine hierarchy, Class.library determines class ownership, and
 * Function.owner determines function scope. Dots in a pretty name are never parsed
 * back into ownership. Logical object/slot addresses remain in OTHER; only retained
 * character bytes use file-backed addresses. This layer does not invent heap addresses
 * or substitute logical signatures for the machine ABI.
 */
final class DartSnapshotSymbols {
  private final Program program;
  private final DartSnapshotAnalyzer.Snapshot snapshot;
  private final DartClusterParser.Result objects;
  private final Address anchor;
  private final Map<Integer, Namespace> owners = new HashMap<>();
  private final Map<Integer, DartClusterParser.ClassInfo> classes = new HashMap<>();
  private final TaskMonitor monitor;
  private Namespace root;

  private DartSnapshotSymbols(Program program, DartSnapshotAnalyzer.Snapshot snapshot,
      Address anchor, TaskMonitor monitor) {
    this.program = program;
    this.snapshot = snapshot;
    this.objects = snapshot.objects();
    this.anchor = anchor;
    this.monitor = monitor;
    for (var scope = objects; scope != null; scope = scope.vm) {
      for (var cls : scope.classes) classes.putIfAbsent(cls.refId, cls);
    }
  }

  static void publish(Program program, DartSnapshotAnalyzer.Snapshot snapshot,
      Address anchor, TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {
    var symbols = new DartSnapshotSymbols(program, snapshot, anchor, monitor);
    try {
      symbols.publish(log);
    } catch (InvalidInputException | DuplicateNameException | CircularDependencyException e) {
      throw new IOException("cannot publish Dart symbol hierarchy", e);
    }
  }

  private void publish(MessageLog log) throws InvalidInputException, DuplicateNameException,
      CircularDependencyException, IOException, CancelledException {
    monitor.setMessage("Organizing Dart library and class scopes");
    root = namespace(program.getGlobalNamespace(), "Dart", false);
    // Base identities keep the same indices through VM, program and loading-unit
    // reference tables. Give them names without assigning a runtime heap address.
    var baseScope = objects;
    while (baseScope.vm != null) baseScope = baseScope.vm;
    if (baseScope.roots != null) {
      var baseOwner = namespace(namespace(root, "VM", false), "BaseObjects", false);
      for (var role : baseScope.roots.references().entrySet()) {
        monitor.checkCancelled();
        if (role.getKey().startsWith("base.")) {
          label(identity(role.getValue()), role.getKey().substring(5), baseOwner);
        }
      }
    }
    int classes = 0;
    for (var cls : objects.classes) {
      monitor.checkCancelled();
      label(identity(cls.refId), "class_info", owner(cls.refId, new HashSet<>()));
      classes++;
    }
    for (var named : objects.namedObjects) {
      monitor.checkCancelled();
      if (named.cid == objects.profile.cids.library) {
        label(identity(named.refId), "library_info", owner(named.refId, new HashSet<>()));
      } else if (named.cid == objects.profile.cids.field) {
        label(identity(named.refId), string(named.nameRefId, "field_" + named.refId),
            owner(named.ownerRefId, new HashSet<>()));
      }
    }
    monitor.setMessage("Organizing Dart functions and aliases");
    int functions = 0;
    var scopedFunctions = new HashSet<Address>();
    for (var code : objects.codes) {
      monitor.checkCancelled();
      if (code.clusterIndex < 0) continue;
      var declaration = objects.named(code.ownerRef);
      int slot = code.clusterIndex + snapshot.table().firstEntryWithCode;
      long pc = snapshot.table().entries.get(slot).pcOffset();
      long normal = pc + ((code.payloadInfo & 1) != 0 ? 24 : 0);
      var function = program.getFunctionManager().getFunctionAt(snapshot.instructions().add(normal));
      if (function == null) continue;
      String old = function.getName();
      SourceType source = function.getSymbol().getSource();
      if (source == SourceType.USER_DEFINED || source == SourceType.IMPORTED) continue;
      var currentParent = function.getParentNamespace();
      if (!currentParent.isGlobal() && !currentParent.getName(true).startsWith("Dart::")) continue;
      String pretty = objects.functionNameByCodeSlot.get(code.clusterIndex);
      String generated = "dart_" + Long.toUnsignedString(function.getEntryPoint().subtract(program.getImageBase()), 16);
      Namespace parent;
      String name = clean(pretty);
      if (declaration != null && declaration.cid == objects.profile.cids.function) {
        parent = owner(declaration.ownerRefId, new HashSet<>());
        name = clean(string(declaration.nameRefId, "function_" + declaration.refId));
      } else if (declaration != null && declaration.cid == objects.profile.cids.clazz) {
        parent = owner(declaration.refId, new HashSet<>());
      } else if (declaration != null && declaration.cid == objects.profile.cids.field) {
        parent = owner(declaration.ownerRefId, new HashSet<>());
      } else {
        parent = namespace(namespace(root, "VM", false), snapshot.scope(), false);
        if (pretty == null) name = old;
      }
      if (scopedFunctions.contains(function.getEntryPoint())) {
        if (pretty != null) label(function.getEntryPoint(), name, parent);
        continue;
      }
      if (!old.equals(generated) && !old.equals(clean(pretty))
          && !(old.equals(name) && function.getParentNamespace().equals(parent))) continue;
      function.setParentNamespace(parent);
      function.setName(name, SourceType.ANALYSIS);
      scopedFunctions.add(function.getEntryPoint());
      functions++;
    }
    // Function::code_index still identifies entries whose Code object was
    // discarded. SDK FunctionDeserializationCluster + GetCodeByIndex use a
    // one-based instruction-table index, with zero reserved for LazyCompile.
    if (!objects.profile.codeTextOffsetDelta) {
      var codeBySlot = new HashMap<Integer, DartClusterParser.CodeEntry>();
      for (var code : objects.codes) if (code.clusterIndex >= 0) {
        codeBySlot.put(code.clusterIndex + snapshot.table().firstEntryWithCode, code);
      }
      for (var declaration : objects.namedObjects) {
        monitor.checkCancelled();
        if (declaration.cid != objects.profile.cids.function) continue;
        var serialized = objects.object(declaration.refId);
        if (serialized == null || serialized.scalars().length == 0) continue;
        long codeIndex = serialized.scalars()[0];
        if (codeIndex <= 0 || codeIndex > snapshot.table().length) continue; // Lazy/deferred.
        int slot = (int) codeIndex - 1;
        long pc = snapshot.table().entries.get(slot).pcOffset();
        var code = codeBySlot.get(slot);
        if (code != null && (code.payloadInfo & 1) != 0) pc += 24;
        var function = program.getFunctionManager().getFunctionAt(snapshot.instructions().add(pc));
        if (function == null || function.getSymbol().getSource() == SourceType.USER_DEFINED
            || function.getSymbol().getSource() == SourceType.IMPORTED) continue;
        Namespace parent = owner(declaration.ownerRefId, new HashSet<>());
        String name = clean(string(declaration.nameRefId, "function_" + declaration.refId));
        if (scopedFunctions.contains(function.getEntryPoint())) {
          label(function.getEntryPoint(), name, parent);
        } else if (function.getName().equals("dart_" + Long.toUnsignedString(
            function.getEntryPoint().subtract(program.getImageBase()), 16))
            && function.getParentNamespace().isGlobal()) {
          function.setParentNamespace(parent);
          function.setName(name, SourceType.ANALYSIS);
          scopedFunctions.add(function.getEntryPoint());
          functions++;
        }
      }
    }
    for (var unit : snapshot.units()) {
      var function = program.getFunctionManager().getFunctionAt(
          program.getImageBase().add(unit.primaryEntry()));
      if (function == null || scopedFunctions.contains(function.getEntryPoint())) continue;
      String generated = "dart_" + Long.toUnsignedString(unit.primaryEntry(), 16);
      if (function.getSymbol().getSource() == SourceType.ANALYSIS
          && function.getName().equals(generated) && function.getParentNamespace().isGlobal()) {
        function.setParentNamespace(namespace(namespace(root, "Unresolved", false), snapshot.scope(), false));
      }
    }
    var destinations = DartSnapshotAnalyzer.fileTargets(program, snapshot);
    // ObjectStore roots identify shared stubs even when their Code has no named
    // Function owner. Use the decoded role, never an instruction hash or address.
    for (var role : objects.roots.references().entrySet()) {
      monitor.checkCancelled();
      var record = objects.objects.get(role.getValue());
      if (record == null || record.cid() != objects.profile.cids.code) continue;
      Address target = destinations.get(role.getValue());
      if (target == null) continue;
      var function = program.getFunctionManager().getFunctionAt(target);
      if (function == null || function.getSymbol().getSource() != SourceType.ANALYSIS) continue;
      String name = clean(role.getKey().replaceFirst("^object_store\\.", ""));
      Namespace parent = namespace(namespace(root, "VM", false), snapshot.scope(), false);
      if (function.getName().equals("dart_" + Long.toUnsignedString(target.subtract(program.getImageBase()), 16))) {
        function.setParentNamespace(parent);
        function.setName(name, SourceType.ANALYSIS);
      } else {
        label(target, name, parent);
      }
    }
    // Merged Code clusters serialize these helper identities explicitly. The
    // older VM root tail does not, so no cross-version stub ordinal is guessed.
    for (var cluster : objects.clusters) {
      if (cluster.cid != objects.profile.cids.code) continue;
      for (var helper : Map.of("LazyCompile", cluster.lazyCompileRef,
          "UnknownDartCode", cluster.unknownDartCodeRef).entrySet()) {
        if (helper.getValue() <= 0) continue;
        Address target = destinations.get(helper.getValue());
        if (target != null) label(target, helper.getKey(),
            namespace(namespace(root, "VM", false), snapshot.scope(), false));
      }
    }
    // Give serialized graph nodes useful names while keeping their identity separate
    // from executable entries. Clicking an identity still exposes its retained fields.
    for (var code : objects.codes) {
      monitor.checkCancelled();
      if (code.clusterIndex < 0) continue;
      int slot = code.clusterIndex + snapshot.table().firstEntryWithCode;
      long pc = snapshot.table().entries.get(slot).pcOffset() + ((code.payloadInfo & 1) != 0 ? 24 : 0);
      var function = program.getFunctionManager().getFunctionAt(snapshot.instructions().add(pc));
      if (function == null) continue;
      label(identity(code.refId), "code_info_" + function.getName(), function.getParentNamespace());
      var declaration = objects.named(code.ownerRef);
      if (declaration != null && declaration.cid == objects.profile.cids.clazz) {
        comment(function.getEntryPoint(), "Dart class allocation stub; this is not a class method. "
            + "The payload may tail-call a shared allocator. Class metadata: " + identity(declaration.refId));
      }
    }
    for (var named : objects.namedObjects) {
      monitor.checkCancelled();
      if (named.cid == objects.profile.cids.function) {
        label(identity(named.refId), "function_info_" + string(named.nameRefId, "ref_" + named.refId),
            owner(named.ownerRefId, new HashSet<>()));
        var serialized = objects.object(named.refId);
        if (!objects.profile.codeTextOffsetDelta && serialized != null
            && serialized.scalars().length > 0 && serialized.scalars()[0] == 0) {
          comment(identity(named.refId), "Dart Function declaration has no compiled AOT body: "
              + "code_index 0 selects SDK LazyCompile, not the first instruction payload.");
        }
      }
    }
    // Serialized numeric values are useful at their logical identities too.
    // Preserve exact Double bits (including signed zero and NaN payloads), and
    // never define these artificial identity bytes as runtime numeric objects.
    for (var object : objects.objects.values()) {
      monitor.checkCancelled();
      String numeric = objects.numericValue(object.refId());
      if (numeric != null) comment(identity(object.refId()), "Dart serialized " + numeric);
    }
    collectStrings(objects, snapshot.data());
    Namespace pools = namespace(namespace(root, "ObjectPools", false), snapshot.scope(), false);
    long references = objects.header.numObjects + 1;
    var poolNamespaces = new HashMap<Integer, Namespace>();
    int position = 0;
    monitor.initialize(objects.imagePoolEntries().size(), "Describing Dart pool slots");
    for (var entry : objects.imagePoolEntries()) {
      monitor.increment();
      monitor.checkCancelled();
      Address address = anchor.add((references + position++) * 8);
      Namespace pool = poolNamespaces.get(entry.poolRef);
      if (pool == null) {
        pool = namespace(pools, "pool_" + entry.poolRef, false);
        poolNamespaces.put(entry.poolRef, pool);
        label(address, "slots", pool);
      }
      label(address, "slot_" + entry.index + "_pp_" + Long.toHexString(entry.byteOffsetFromUntaggedPool()), pool);
      String text = "PP+0x" + Long.toHexString(entry.byteOffsetFromUntaggedPool())
          + " [" + entry.index + "] " + entry.kind + " bits=0x" + Integer.toHexString(entry.bits);
      if (entry.kind == DartClusterParser.PoolEntryKind.TAGGED) {
        text += " ref #" + entry.refId;
        String value = string(entry.refId, null);
        if (value != null) text += " String " + preview(value);
        String numeric = objects.numericValue(entry.refId);
        if (numeric != null) text += " " + numeric;
        Address target = destinations.get(entry.refId);
        if (target != null) reference(address, target, RefType.DATA);
      } else if (entry.kind == DartClusterParser.PoolEntryKind.IMMEDIATE) {
        text += " = 0x" + Long.toHexString(entry.imm);
      }
      text += "; snapshot value" + (entry.isPatchable(objects.profile) ? ", patchable slot" : "");
      var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
      var slotFacts = com.google.gson.JsonParser.parseString(facts.getString(address)).getAsJsonObject();
      slotFacts.addProperty("stableTaggedBits", entry.stableTaggedBits(objects.profile));
      facts.add(address, slotFacts.toString());
      comment(address, text);
    }
    log.appendMsg("Dart AOT Objects", snapshot.scope() + ": " + classes + " class records organized, "
        + functions + " scoped functions. "
        + "Browse Symbol Tree > Namespaces/Classes > Dart and Dart::ObjectPools.");
  }

  private void collectStrings(DartClusterParser.Result result, Address data)
      throws IOException, CancelledException {
    monitor.initialize(result.strings.size(), "Linking Dart string metadata");
    for (var string : result.strings) {
      monitor.increment();
      monitor.checkCancelled();
      if (result != objects || string.headerOffset < 0) continue;
      Address header = data.add(string.headerOffset);
      if (program.getListing().getDefinedDataContaining(header) == null) {
        var type = new StructureDataType(string.objectHeader ? "DartRoStringHeader" :
            "DartStringPrefix_" + string.headerLength, 0);
        if (string.objectHeader) {
          type.add(QWordDataType.dataType, "tags", "VM object tags, not character data");
          type.add(QWordDataType.dataType, "length_smi", "Number of code units, Smi encoded");
        } else {
          type.add(new ArrayDataType(ByteDataType.dataType, string.headerLength, 1),
              objects.profile.oldStringFormat ? "length" : "length_and_encoding", "Dart variable-length unsigned encoding");
        }
        try {
          program.getListing().createData(header, type);
        } catch (ghidra.program.model.util.CodeUnitInsertionException e) {
          throw new IOException("string prefix overlaps existing data at " + header, e);
        }
      }
      comment(header, "Dart " + (string.objectHeader ? "object header" : "serialized string prefix")
          + ": " + string.value.length() + " code units, " + (string.isOneByte ? "Latin-1" : "UTF-16LE")
          + "; characters at " + data.add(string.dataOffset));
    }
  }

  private Namespace owner(int ref, Set<Integer> active)
      throws InvalidInputException, DuplicateNameException {
    if (owners.containsKey(ref)) return owners.get(ref);
    if (ref <= 0 || active.size() >= 32 || !active.add(ref)) return namespace(root, "Unresolved", false);
    var named = objects.named(ref);
    if (named == null) {
      var object = objects.object(ref);
      if (object != null && object.cid() == objects.profile.cids.patchClass) {
        int[] refs = object.references();
        if (refs.length > 0) return owner(refs[0], active);
      }
      return namespace(root, "VM", false);
    }
    Namespace parent;
    if (named.cid == objects.profile.cids.library) {
      var object = objects.object(ref);
      int[] refs = object == null ? new int[0] : object.references();
      String url = refs.length > 1 ? string(refs[1], null) : null;
      parent = root;
      if (url == null || url.isEmpty()) url = "library_" + ref;
      for (String part : url.split("[/:]+")) if (!part.isEmpty()) parent = namespace(parent, part, false);
    } else {
      var cls = classes.get(ref);
      parent = owner(cls == null ? named.ownerRefId : cls.libraryRefId, active);
      String name = string(named.nameRefId, "declaration_" + ref);
      if (!name.equals("::")) parent = namespace(parent,
          named.cid == objects.profile.cids.function ? name + "$closures" : name,
          named.cid == objects.profile.cids.clazz);
    }
    active.remove(ref);
    owners.put(ref, parent);
    return parent;
  }

  private Namespace namespace(Namespace parent, String name, boolean clazz)
      throws InvalidInputException, DuplicateNameException {
    name = clean(name);
    var table = program.getSymbolTable();
    var existing = table.getNamespace(name, parent);
    if (existing != null) return existing;
    return clazz ? table.createClass(parent, name, SourceType.ANALYSIS)
        : table.createNameSpace(parent, name, SourceType.ANALYSIS);
  }

  private void label(Address address, String name, Namespace parent) throws InvalidInputException {
    var primary = program.getSymbolTable().getPrimarySymbol(address);
    if (primary != null && primary.getSource() == SourceType.USER_DEFINED) return;
    program.getSymbolTable().createLabel(address, clean(name), parent, SourceType.ANALYSIS);
  }

  private Address identity(int ref) { return anchor.add((long) ref * 8); }

  private String string(int ref, String fallback) {
    String value = objects.string(ref);
    return value == null ? fallback : value;
  }

  private static String clean(String value) {
    return SymbolUtilities.replaceInvalidChars(value == null || value.isEmpty() ? "unnamed" : value, true);
  }

  private static String preview(String value) {
    String text = value.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace("\0", "\\0");
    return "\"" + text.substring(0, Math.min(100, text.length())) + (text.length() > 100 ? "…" : "") + "\"";
  }

  private void comment(Address address, String text) {
    String old = program.getListing().getComment(CommentType.EOL, address);
    if (old == null || old.equals(text)) program.getListing().setComment(address, CommentType.EOL, text);
  }

  private void reference(Address from, Address to, RefType type) {
    program.getReferenceManager().addMemoryReference(from, to, type, SourceType.ANALYSIS, -1);
  }
}
