package ghidart;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.HashMap;
import java.util.Map;

/** Native class layouts from validated L2 facts, not inferred runtime heap images.
 *
 * Offsets and sizes use target compressed words (Class::target_instance_size).
 * Tagged slots are integer typedefs: they may contain Smis or tagged/compressed
 * object references, so an ordinary Ghidra pointer would have incorrect semantics.
 * Unboxed storage stays raw until a concrete numeric representation is known.
 * Types are available for inspection and explicit application; no logical Dart
 * declaration is imposed on a function's recovered physical ABI.
 */
final class DartSnapshotTypes {
  private static final CategoryPath ROOT = new CategoryPath("/Dart/L2");

  static void publish(Program program, DartSnapshotAnalyzer.Snapshot snapshot,
      TaskMonitor monitor, MessageLog log) throws CancelledException {
    var objects = snapshot.objects();
    int word = objects.profile.compressedPointers ? 4 : 8;
    var path = new CategoryPath(ROOT, snapshot.scope());
    var tagged = new TypedefDataType(path, "DartTagged" + word * 8,
        word == 4 ? DWordDataType.dataType : QWordDataType.dataType);
    var classes = new java.util.ArrayList<DartClusterParser.ClassInfo>();
    var declarations = new java.util.ArrayList<DartClusterParser.FieldInfo>();
    var types = new HashMap<Integer, DartClusterParser.TypeInfo>();
    var classesByCid = new HashMap<Integer, DartClusterParser.ClassInfo>();
    for (var scope = objects; scope != null; scope = objects.header.isLoadingUnit ? scope.vm : null) {
      classes.addAll(scope.classes);
      declarations.addAll(scope.fields);
      for (var type : scope.types) types.putIfAbsent(type.refId, type);
      for (var cls : scope.classes) classesByCid.putIfAbsent(cls.classId, cls);
    }
    var fields = new HashMap<Integer, Map<Integer, DartClusterParser.FieldInfo>>();
    for (var field : declarations) {
      monitor.checkCancelled();
      var storage = objects.fieldStorage(field);
      if (storage.isStatic() || storage.offsetOrId() == null
          || storage.offsetOrId() > Integer.MAX_VALUE) continue;
      fields.computeIfAbsent(field.ownerRefId, ignored -> new HashMap<>())
          .putIfAbsent(storage.offsetOrId().intValue(), field);
    }
    int created = 0;
    int existing = 0;
    int skipped = 0;
    monitor.initialize(classes.size(), "Publishing Dart class layouts");
    for (var cls : classes) {
      monitor.checkCancelled();
      monitor.increment();
      // Predefined VM classes have specialized layouts; a Class instance-size
      // scalar alone does not describe their variable-length payloads.
      if (cls.classId < objects.profile.cids.numPredefinedCids
          || cls.classId >= (objects.profile.topLevelCid16 ? 1 << 16 : 1 << 20)) continue;
      long size = (long) cls.instanceSizeInWords * word;
      long end = (long) cls.nextFieldOffInWords * word;
      if (size < 8 || size > 16 * 1024 * 1024 || end < 8 || end > size) {
        skipped++;
        continue;
      }
      String name = objects.classNameByCid.getOrDefault(cls.classId, "anonymous");
      name = SymbolUtilities.replaceInvalidChars(name, true);
      if (name.length() > 120) name = name.substring(0, 120);
      name = "CID_" + cls.classId + "_" + name;
      var type = new StructureDataType(path, name, (int) size);
      type.setDescription("Dart L2 " + snapshot.scope() + " Class ref #" + cls.refId
          + "; untagged target layout, word=" + word
          + ". Tagged values are not native pointers. Allocation padding is not a field.");
      type.replaceAtOffset(0, QWordDataType.dataType, 8, "tags", "Runtime object header; absent from serialized instance fields");
      // Instance layouts include inherited storage. Recover names through the
      // retained superclass Type, not by guessing owners from matching offsets.
      // Nearest declarations win; unavailable VM bases remain unnamed slots.
      var declared = new HashMap<Integer, DartClusterParser.FieldInfo>();
      var seen = new java.util.HashSet<Integer>();
      for (var parent = cls; parent != null && seen.add(parent.refId);) {
        fields.getOrDefault(parent.refId, Map.of()).forEach(declared::putIfAbsent);
        var superType = types.get(parent.superTypeRefId);
        Integer superCid = superType == null ? null : objects.typeClassId(superType);
        parent = superCid == null ? null : classesByCid.get(superCid);
      }
      for (int offset = 8; offset < end; offset += word) {
        int index = offset / word;
        boolean unboxed = index < 64 && ((cls.unboxedFields >>> index) & 1) != 0;
        DataType storage = unboxed ? Undefined.getUndefinedDataType(word) : tagged;
        String fieldName = "slot_" + Integer.toHexString(offset);
        String description = unboxed ? "Unboxed bits; numeric type is not implied" : "Tagged value";
        var field = declared.get(offset);
        if (field != null) {
          String retained = objects.string(field.nameRefId);
          if (retained != null) {
            String clean = SymbolUtilities.replaceInvalidChars(retained, true);
            if (clean.length() > 120) clean = clean.substring(0, 120);
            fieldName = clean + "_" + Integer.toHexString(offset);
          }
          description += "; Field ref #" + field.refId;
        } else if (cls.typeArgsOffInWords == index) {
          fieldName = "type_arguments";
        }
        type.replaceAtOffset(offset, storage, word, fieldName, description);
      }
      var manager = program.getDataTypeManager();
      var old = manager.getDataType(path, name);
      if (old != null) {
        // Existing types may have user edits or attached references. Never
        // replace them or create a stream of .conflict variants on rerun.
        existing++;
      } else {
        manager.addDataType(type, null);
        created++;
      }
    }
    log.appendMsg("Dart AOT Objects", snapshot.scope() + ": " + created
        + " target class layouts, " + existing + " existing layouts preserved, " + skipped
        + " layouts without a bounded fixed extent. Browse Data Type Manager > Dart > L2.");
  }
}
