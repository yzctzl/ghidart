package ghidart.snapshot;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
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
 * back into ownership. Logical object/slot keys remain private records; only retained
 * character bytes and instructions receive file-backed references. This layer does not invent heap addresses
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
    root = program.getGlobalNamespace();
    // Base identities keep the same indices through VM, program and loading-unit
    // reference tables. Give them names without assigning a runtime heap address.
    var baseScope = objects;
    while (baseScope.vm != null) baseScope = baseScope.vm;
    if (baseScope.roots != null) {

      for (var role : baseScope.roots.baseIdentities().entrySet()) {
        monitor.checkCancelled();
        if (role.getKey().startsWith("base.")) {
          DartObjectGraph.name(program, identity(role.getValue()), "BaseObjects::" + role.getKey().substring(5));
        }
      }
    }
    int classes = 0;
    for (var cls : objects.classes) {
      monitor.checkCancelled();
      Namespace clazz = owner(cls.refId, new HashSet<>());
      DartObjectGraph.name(program, identity(cls.refId), "Class " + clazz.getName(true));
      classes++;
    }
    for (var named : objects.namedObjects) {
      monitor.checkCancelled();
      if (named.cid == objects.profile.cids.library) {
        Namespace library = owner(named.refId, new HashSet<>());
        DartObjectGraph.name(program, identity(named.refId), "Library " + library.getName(true));
      } else if (named.cid == objects.profile.cids.field) {
        DartObjectGraph.name(program, identity(named.refId), "Field " + string(named.nameRefId, "field_" + named.refId));
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
      long normal = pc + objects.profile.normalEntryOffset(code.payloadInfo);
      var function = program.getFunctionManager().getFunctionAt(snapshot.instructions().add(normal));
      if (function == null) continue;
      String old = function.getName();
      SourceType source = function.getSymbol().getSource();
      if (source == SourceType.USER_DEFINED || source == SourceType.IMPORTED) continue;
      var currentParent = function.getParentNamespace();
      if (!currentParent.isGlobal() && !currentParent.getName(true).startsWith("Dart::")
          && !currentParent.getName(true).startsWith("Library::")
          && !java.util.Set.of("Packages", "SDK", "App", "Runtime", "Unresolved")
              .contains(currentParent.getName(true).split("::")[0])) continue;
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
        parent = namespace(namespace(root, "Runtime", false), snapshot.scope(), false);
        if (pretty == null) name = old;
      }
      if (scopedFunctions.contains(function.getEntryPoint())) {
        if (pretty != null) label(function.getEntryPoint(), name, parent);
        continue;
      }
      String legacyPretty = pretty == null ? null
          : ghidra.program.model.symbol.SymbolUtilities.replaceInvalidChars(pretty, true);
      if (!old.equals(generated) && !old.equals(clean(pretty)) && !old.equals(legacyPretty)
          && !(old.equals(name) && function.getParentNamespace().equals(parent))) continue;
      function.setParentNamespace(parent);
      function.setName(name, SourceType.ANALYSIS);
      scopedFunctions.add(function.getEntryPoint());
      functions++;
    }
    // The same validated targets drive graph references and declaration scopes.
    // In particular, loading-unit indices include the parent reference count;
    // interpreting them again as local table slots silently loses ownership.
    var destinations = DartSnapshotAnalyzer.fileTargets(program, snapshot);
    functions += publishRetainedFunctions(scopedFunctions, destinations);
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
      Namespace parent = namespace(namespace(root, "Runtime", false), snapshot.scope(), false);
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
            namespace(namespace(root, "Runtime", false), snapshot.scope(), false));
      }
    }
    // Give serialized graph nodes useful names while keeping their identity separate
    // from executable entries. Clicking an identity still exposes its retained fields.
    for (var code : objects.codes) {
      monitor.checkCancelled();
      if (code.clusterIndex < 0) continue;
      int slot = code.clusterIndex + snapshot.table().firstEntryWithCode;
      long pc = snapshot.table().entries.get(slot).pcOffset() + objects.profile.normalEntryOffset(code.payloadInfo);
      var function = program.getFunctionManager().getFunctionAt(snapshot.instructions().add(pc));
      if (function == null) continue;
      DartObjectGraph.name(program, identity(code.refId), "Code " + function.getName(true));
      var declaration = objects.named(code.ownerRef);
      if (declaration != null && declaration.cid == objects.profile.cids.clazz) {
        String prefix = "Dart class allocation stub; this is not a class method. "
            + "The payload may tail-call a shared allocator. ";
        String text = prefix + "Class record: " + DartObjectGraph.describe(program, identity(declaration.refId));
        String previous = program.getListing().getComment(CommentType.EOL, function.getEntryPoint());
        if ((prefix + "Class metadata: " + identity(declaration.refId)).equals(previous)) {
          program.getListing().setComment(function.getEntryPoint(), CommentType.EOL, text);
        } else comment(function.getEntryPoint(), text);
      }
    }
    for (var named : objects.namedObjects) {
      monitor.checkCancelled();
      if (named.cid == objects.profile.cids.function) {
        DartObjectGraph.name(program, identity(named.refId), "Function " + string(named.nameRefId, "function"));
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
    long references = objects.header.numObjects + 1;
    int position = 0;
    monitor.initialize(objects.imagePoolEntries().size(), "Describing Dart pool slots");
    for (var entry : objects.imagePoolEntries()) {
      monitor.increment();
      monitor.checkCancelled();
      Address address = anchor.add((references + position++) * 8);
      DartObjectGraph.name(program, address, "Pool #" + entry.poolRef + " slot " + entry.index
          + " PP+0x" + Long.toHexString(entry.byteOffsetFromUntaggedPool()));
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
        + "Browse Packages/SDK/App/Runtime for declarations; Dart records retain object and pool relationships.");
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

  /** Retained Function declarations also name entries whose Code was discarded.
   * Shared implementations keep scoped aliases. Missing declarations stay unknown;
   * a dispatch-table target alone proves neither a class nor a source library.
   */
  private int publishRetainedFunctions(Set<Address> scopedFunctions, Map<Integer, Address> destinations)
      throws InvalidInputException, DuplicateNameException, CircularDependencyException,
      CancelledException {
    int changed = 0;
    for (var declaration : objects.namedObjects) {
      monitor.checkCancelled();
      if (declaration.cid != objects.profile.cids.function) continue;
      var serialized = objects.object(declaration.refId);
      if (serialized == null || serialized.scalars().length == 0
          || !objects.profile.codeTextOffsetDelta && serialized.scalars()[0] == 0) continue;
      Address target = destinations.get(declaration.refId);
      if (target == null) continue;
      var function = program.getFunctionManager().getFunctionContaining(target);
      if (function == null || function.getSymbol().getSource() == SourceType.USER_DEFINED) continue;
      Namespace parent = owner(declaration.ownerRefId, new HashSet<>());
      String name = clean(string(declaration.nameRefId, "function_" + declaration.refId));
      // A loader or b4a may already provide the physical symbol. Keep it and
      // its ownership intact; the retained declaration remains a scoped alias.
      // A normal/unchecked entry can sit inside the one physical payload owner.
      // Label that entry without splitting the body or moving its primary symbol.
      if (!function.getEntryPoint().equals(target)
          || function.getSymbol().getSource() == SourceType.IMPORTED || scopedFunctions.contains(target)) {
        label(target, name, parent);
        continue;
      }
      String generated = "dart_" + Long.toUnsignedString(target.subtract(program.getImageBase()), 16);
      if (!function.getName().equals(generated)) {
        label(target, name, parent);
        continue;
      }
      Namespace previous = function.getParentNamespace();
      if (!previous.isGlobal()
          && !ghidart.listing.DartNamespaces.unresolvedScope(previous, snapshot.scope())) {
        label(target, name, parent);
        continue;
      }
      function.setParentNamespace(parent);
      function.setName(name, SourceType.ANALYSIS);
      scopedFunctions.add(target);
      changed++;
    }
    return changed;
  }

  private Namespace owner(int ref, Set<Integer> active)
      throws InvalidInputException, DuplicateNameException, CircularDependencyException {
    if (owners.containsKey(ref)) return owners.get(ref);
    if (ref <= 0 || active.size() >= 32 || !active.add(ref)) return namespace(root, "Unresolved", false);
    var named = objects.named(ref);
    if (named == null) {
      var object = objects.object(ref);
      if (object != null && object.cid() == objects.profile.cids.patchClass) {
        int[] refs = object.references();
        if (refs.length > 0) return owner(refs[0], active);
      }
      return namespace(root, "Runtime", false);
    }
    Namespace parent;
    if (named.cid == objects.profile.cids.library) {
      var object = objects.object(ref);
      int[] refs = object == null ? new int[0] : object.references();
      String url = refs.length > 1 ? string(refs[1], null) : null;
      if (url == null || url.isEmpty()) url = "library_" + ref;
      parent = ghidart.listing.DartNamespaces.library(program, url, SourceType.ANALYSIS);
    } else {
      var cls = classes.get(ref);
      parent = owner(cls == null ? named.ownerRefId : cls.libraryRefId, active);
      String name = string(named.nameRefId, "declaration_" + ref);
      if (!name.equals("::")) {
        parent = named.cid == objects.profile.cids.clazz && cls != null
            ? ghidart.listing.DartNamespaces.clazz(program, cls.classId, parent, name, SourceType.ANALYSIS)
            : namespace(parent, named.cid == objects.profile.cids.function ? name + "$closures" : name,
                named.cid == objects.profile.cids.clazz);
      }
    }
    active.remove(ref);
    owners.put(ref, parent);
    return parent;
  }

  private Namespace namespace(Namespace parent, String name, boolean clazz)
      throws InvalidInputException, DuplicateNameException {
    return ghidart.listing.DartNamespaces.namespace(program, parent, name, clazz, SourceType.ANALYSIS);
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
    return ghidart.listing.DartNamespaces.clean(value);
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
    DartObjectGraph.link(program, from, to, type);
  }
}
