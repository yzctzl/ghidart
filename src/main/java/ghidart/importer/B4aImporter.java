/**
 * Publish b4a facts through native Ghidra symbols, data types, comments and references.
 *
 * Read one declaration at a time: real documents can exceed 250 MB. Validate the
 * original image before mutation, and publish in one rollbackable transaction.
 * OTHER records are database identities, never invented runtime heap pointers.
 * Logical signatures and printed IL remain evidence, not physical call contracts.
 */
package ghidart.importer;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.task.TaskMonitor;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class B4aImporter {
  public static final String FACTS = "ghidart.b4a";
  private static final String GENERATION = "b4aGeneration";
  private final Program program;
  private final TaskMonitor monitor;
  private final Map<Integer, JsonObject> classes = new LinkedHashMap<>();
  private final Map<Integer, Namespace> owners = new HashMap<>();
  private final Map<String, Address> slots = new HashMap<>();
  private final java.util.TreeMap<Long, DartCodeIndex.CodeUnit> ranges = new java.util.TreeMap<>();
  private final Map<String, JsonArray> structures = new LinkedHashMap<>();
  private StringPropertyMap facts;
  private Address next;
  private Namespace root;
  private int slotSize;
  private long records;
  private long declarations;
  private long names;
  private long comments;
  private long references;
  private long unresolvedOperands;

  private B4aImporter(Program program, DartCodeIndex index, TaskMonitor monitor) {
    this.program = program;
    this.monitor = monitor;
    for (var unit : index.codeUnits()) ranges.put(unit.start(), unit);
  }

  public static void importFile(Program program, Path path, TaskMonitor monitor, MessageLog log)
      throws Exception {
    if (!"AARCH64:LE:64:dart".equals(program.getLanguageID().toString())) {
      throw new IllegalArgumentException("select the Dart ARM64 language first");
    }
    String identity = hash(path, monitor);
    DartCodeIndex index = DartCodeIndex.read(path);
    DartAotAnalyzer.verifyIdentity(program, index);
    var options = program.getOptions("ghidart");
    String previous = options.getString(GENERATION, "");
    if (identity.equals(previous)) {
      log.appendMsg("Dart b4a Import", "This b4a generation is already imported; user edits preserved.");
      return;
    }
    if (!previous.isEmpty()) {
      throw new IllegalArgumentException("different b4a generation; existing data preserved, use a fresh database");
    }
    var importer = new B4aImporter(program, index, monitor);
    // Preflight parses every record before publishing; malformed trailing records
    // cannot leave half an import. Analysis bodies are not retained in Java memory.
    monitor.setIndeterminate(true);
    monitor.setMessage("Validating b4a semantic records");
    importer.scan(path, false);
    if (!identity.equals(hash(path, monitor))) throw new IllegalArgumentException("b4a file changed during validation");
    int transaction = program.startTransaction("Import b4a semantics");
    boolean committed = false;
    try {
      DartAotAnalyzer.applyBoundaries(program, index.codeUnits(), monitor, log);
      monitor.setIndeterminate(false);
      monitor.initialize(importer.records, "Publishing b4a facts");
      importer.initialize();
      importer.publishClasses();
      for (var structure : importer.structures.entrySet()) {
        importer.publishStructure(structure.getKey(), structure.getValue());
      }
      importer.scan(path, true);
      if (!identity.equals(hash(path, monitor))) throw new IllegalArgumentException("b4a file changed during import");
      options.setString(GENERATION, identity);
      options.setString("b4aPath", path.toAbsolutePath().normalize().toString());
      committed = true;
    } finally {
      program.endTransaction(transaction, committed);
    }
    log.appendMsg("Dart b4a Import", "Imported " + importer.classes.size() + " classes, "
        + importer.declarations + " declarations, " + importer.names + " names, "
        + importer.comments + " comments and " + importer.references + " operand references; "
        + importer.unresolvedOperands + " operands retained without a proved slot. Physical ABI unchanged.");
  }

  private static String hash(Path path, TaskMonitor monitor) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (InputStream input = Files.newInputStream(path)) {
      byte[] buffer = new byte[1 << 20];
      int size;
      while ((size = input.read(buffer)) != -1) {
        monitor.checkCancelled();
        digest.update(buffer, 0, size);
      }
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  private void scan(Path path, boolean publish) throws Exception {
    try (JsonReader reader = new JsonReader(Files.newBufferedReader(path))) {
      reader.beginObject();
      Set<String> seen = new HashSet<>();
      while (reader.hasNext()) {
        monitor.checkCancelled();
        String section = reader.nextName();
        if (!seen.add(section)) throw new IllegalArgumentException("duplicate section: " + section);
        monitor.setMessage((publish ? "Importing b4a " : "Validating b4a ") + section);
        switch (section) {
          case "classes", "topClasses", "functions", "analysis", "operands", "codeUnits" -> {
            reader.beginArray();
            long count = 0;
            while (reader.hasNext()) {
              monitor.checkCancelled();
              JsonElement value = JsonParser.parseReader(reader);
              if (!value.isJsonNull()) {
                if (publish) publishRecord(section, value);
                else validateRecord(section, value);
              }
              if (++count % 256 == 0) monitor.setMessage("b4a " + section + ": " + count + " records");
            }
            reader.endArray();
          }
          case "structures" -> {
            reader.beginObject();
            while (reader.hasNext()) {
              String structure = reader.nextName();
              JsonArray members = JsonParser.parseReader(reader).getAsJsonArray();
              if (!publish) {
                if (structures.putIfAbsent(structure, members) != null) {
                  throw new IllegalArgumentException("duplicate structure");
                }
                var offsets = new java.util.TreeSet<Long>();
                for (var member : members) {
                  var row = member.getAsJsonArray();
                  long offset = row.get(0).getAsLong();
                  if (row.size() != 3 || offset < 0 || offset > (1L << 28)
                      || !offsets.add(offset)) throw new IllegalArgumentException("invalid structure member");
                  row.get(1).getAsString();
                  row.get(2).getAsString();
                  records++;
                }
                long end = -1;
                for (long offset : offsets) {
                  if (offset < end) throw new IllegalArgumentException("overlapping structure members");
                  end = offset + 8;
                }
              }
            }
            reader.endObject();
          }
          default -> {
            JsonElement value = JsonParser.parseReader(reader);
            if (section.equals("target")) {
              slotSize = value.getAsJsonObject().get("slotSize").getAsInt();
              if (slotSize != 4 && slotSize != 8) throw new IllegalArgumentException("invalid slotSize");
            }
            if (!publish) records++;
            if (publish) {
              Address record = record(value);
              label(record, section, root);
            }
          }
        }
      }
      reader.endObject();
      if (reader.peek() != JsonToken.END_DOCUMENT) throw new IllegalArgumentException("trailing b4a data");
      if (!seen.containsAll(Set.of("classes", "topClasses", "analysis", "structures", "operands", "functions"))) {
        throw new IllegalArgumentException("missing b4a semantic sections");
      }
    }
  }

  private void validateRecord(String section, JsonElement value) {
    records++;
    if (section.equals("codeUnits")) return; // DartCodeIndex already validates these.
    if (section.equals("classes") || section.equals("topClasses")) {
      JsonObject cls = value.getAsJsonObject();
      int id = cls.get("id").getAsInt();
      if (id < 0 || classes.putIfAbsent(id, cls) != null) throw new IllegalArgumentException("duplicate/invalid class id");
      if (cls.has("size") && (cls.get("size").getAsInt() < 0 || cls.get("size").getAsInt() > (1 << 24))) {
        throw new IllegalArgumentException("invalid class size");
      }
    } else {
      JsonArray row = value.getAsJsonArray();
      long rva = rva(row.get(0));
      if (section.equals("analysis")) {
        if (row.size() != 2) throw new IllegalArgumentException("invalid analysis record");
        JsonObject body = row.get(1).getAsJsonObject();
        body.get("name").getAsString();
        body.get("cid").getAsInt();
        for (String key : new String[] {"il", "annotations"}) {
          if (!body.has(key)) continue;
          for (var item : body.getAsJsonArray(key)) {
            var annotation = item.getAsJsonArray();
            if (annotation.size() != (key.equals("il") ? 4 : 2)) throw new IllegalArgumentException("invalid annotation");
            rva(annotation.get(0));
            if (key.equals("il") && rva(annotation.get(1)) <= rva(annotation.get(0))) {
              throw new IllegalArgumentException("invalid IL extent");
            }
          }
        }
      } else if (section.equals("functions")) {
        if (row.size() != 3 || row.get(1).getAsLong() < 0) throw new IllegalArgumentException("invalid function record");
        row.get(2).getAsString();
      } else if (row.size() != 4 || row.get(1).getAsInt() < 0 || row.get(1).getAsInt() > 7) {
        throw new IllegalArgumentException("invalid operand record");
      }
      // Missing bodies/extra entry labels are retained, never used to invent sizes.
      if ((rva & 3) != 0) throw new IllegalArgumentException("unaligned ARM64 address");
    }
  }

  private static long rva(JsonElement value) {
    String text = value.getAsString();
    if (!text.matches("0x[0-9a-f]+")) throw new IllegalArgumentException("invalid RVA");
    long result = Long.parseLong(text.substring(2), 16);
    if (result < 0 || result > 0xffff_ffffL) throw new IllegalArgumentException("RVA outside supported image");
    return result;
  }

  private void initialize() throws Exception {
    long size = Math.multiplyExact(records + 1024, 8);
    if (size > (1L << 30)) throw new IllegalArgumentException("b4a metadata too large");
    next = program.getAddressFactory().getAddressSpace("OTHER").getAddress(0x40_0000_0000L);
    var block = program.getMemory().createInitializedBlock("B4aMetadata", next, size, (byte) 0, monitor, false);
    block.setRead(true);
    block.setWrite(false);
    block.setExecute(false);
    block.setArtificial(true);
    block.setComment("b4a exported facts; logical identities, NOT runtime heap addresses");
    facts = program.getUsrPropertyManager().createStringPropertyMap(FACTS);
    root = namespace(program.getGlobalNamespace(), "B4a", false);
  }

  private Address record(JsonElement value) throws Exception {
    monitor.checkCancelled();
    Address address = next;
    next = next.add(8);
    monitor.increment();
    program.getListing().createData(address, Undefined.getUndefinedDataType(8));
    facts.add(address, value.toString());
    return address;
  }

  private Namespace namespace(Namespace parent, String name, boolean clazz) throws Exception {
    String clean = clean(name);
    var symbols = program.getSymbolTable();
    Namespace existing = symbols.getNamespace(clean, parent);
    if (existing != null) return existing;
    return clazz ? symbols.createClass(parent, clean, SourceType.IMPORTED)
        : symbols.createNameSpace(parent, clean, SourceType.IMPORTED);
  }

  private static String clean(String name) {
    String result = SymbolUtilities.replaceInvalidChars(name.isBlank() ? "unnamed" : name, true);
    return result.length() <= 180 ? result : result.substring(0, 160) + "_" + Integer.toUnsignedString(name.hashCode(), 16);
  }

  private void label(Address address, String name, Namespace owner) throws Exception {
    if (program.getSymbolTable().getSymbol(clean(name), address, owner) == null) {
      program.getSymbolTable().createLabel(address, clean(name), owner, SourceType.IMPORTED);
    }
  }

  private void publishClasses() throws Exception {
    Namespace libraries = namespace(root, "Libraries", false);
    for (var cls : classes.values()) {
      monitor.checkCancelled();
      int id = cls.get("id").getAsInt();
      Namespace library = namespace(libraries, text(cls, "library", "SDK"), false);
      String name = text(cls, "name", "class_" + id);
      Namespace owner = name.isEmpty() ? library : namespace(library, name + "_cid" + id, true);
      owners.put(id, owner);
      Address address = record(cls);
      label(address, "class_info_" + id, owner);
      mergeComment(address, CommentType.PLATE, cls.toString());
    }
    for (var cls : classes.values()) publishLayout(cls);
  }

  private void publishLayout(JsonObject cls) throws Exception {
    if (!cls.has("size") || !cls.has("fields")) return;
    int size = cls.get("size").getAsInt();
    if (size <= 0) return;
    String name = "Class_" + cls.get("id").getAsInt() + "_" + clean(text(cls, "name", "unnamed"));
    CategoryPath category = new CategoryPath("/Dart/B4a/Classes");
    if (program.getDataTypeManager().getDataType(category, name) != null) return;
    var type = new StructureDataType(category, name, size);
    type.setDescription("b4a byte layout; tagged/compressed fields are raw storage. " + cls);
    Map<Integer, JsonObject> fields = new java.util.TreeMap<>();
    Set<Integer> seen = new HashSet<>();
    for (JsonObject parent = cls; parent != null; parent = classes.get(parent.has("sid") ? parent.get("sid").getAsInt() : -1)) {
      if (!seen.add(parent.get("id").getAsInt())) break;
      if (!parent.has("fields")) continue;
      for (var item : parent.getAsJsonArray("fields")) {
        var field = item.getAsJsonObject();
        if (!field.get("static").getAsBoolean()) fields.putIfAbsent(field.get("offset").getAsInt(), field);
      }
    }
    for (var item : fields.entrySet()) {
      int offset = item.getKey();
      if (offset < 0 || offset >= size) continue;
      int width = Math.min(slotSize, size - offset);
      type.replaceAtOffset(offset, Undefined.getUndefinedDataType(width), width,
          clean(text(item.getValue(), "name", "field")) + "_" + Integer.toHexString(offset), item.getValue().toString());
    }
    program.getDataTypeManager().resolve(type, DataTypeConflictHandler.KEEP_HANDLER);
  }

  private void publishRecord(String section, JsonElement value) throws Exception {
    if (section.equals("classes") || section.equals("topClasses")) return;
    if (section.equals("codeUnits")) {
      Address retained = record(value);
      var unit = value.getAsJsonObject();
      label(retained, "code_" + unit.get("start").getAsString(), namespace(root, "CodeUnits", false));
      return;
    }
    JsonArray row = value.getAsJsonArray();
    long offset = rva(row.get(0));
    Address address = program.getImageBase().add(offset);
    if (section.equals("functions")) {
      Address retained = record(value);
      if (codeContains(offset)) {
        label(address, row.get(2).getAsString(), namespace(root, "Entries", false));
        program.getReferenceManager().addMemoryReference(retained, address, RefType.DATA, SourceType.IMPORTED, 0);
      }
    } else if (section.equals("analysis")) {
      publishDeclaration(offset, row);
    } else {
      publishOperand(address, row);
    }
  }

  private boolean codeContains(long rva) {
    var entry = ranges.floorEntry(rva);
    return entry != null && rva < entry.getValue().end();
  }

  private void publishDeclaration(long offset, JsonArray row) throws Exception {
    JsonObject body = row.get(1).getAsJsonObject();
    Address retained = record(row);
    declarations++;
    Namespace owner = owners.getOrDefault(body.get("cid").getAsInt(), root);
    String name = body.get("name").getAsString();
    int separator = name.indexOf("::");
    if (separator >= 0) name = name.substring(separator + 2);
    name = clean(name) + "_" + Long.toHexString(offset);
    label(retained, "declaration_" + declarations + "_" + name, owner);
    JsonObject summary = body.deepCopy();
    summary.remove("il");
    summary.remove("annotations");
    mergeComment(retained, CommentType.PLATE, summary.toString());
    if (!codeContains(offset)) return;
    Address entry = program.getImageBase().add(offset);
    program.getReferenceManager().addMemoryReference(retained, entry, RefType.DATA, SourceType.IMPORTED, 0);
    program.getReferenceManager().addMemoryReference(entry, retained, RefType.DATA, SourceType.IMPORTED, -1);
    var function = program.getFunctionManager().getFunctionAt(entry);
    if (function != null && function.getSymbol().getSource() != SourceType.USER_DEFINED
        && function.getSymbol().getSource() != SourceType.IMPORTED) {
      function.setParentNamespace(owner);
      function.setName(name, SourceType.IMPORTED);
      names++;
    }
    label(entry, name, owner);
    mergeComment(entry, CommentType.PLATE, summary.toString());
    for (String key : new String[] {"il", "annotations"}) {
      if (!body.has(key)) continue;
      for (var item : body.getAsJsonArray(key)) {
        monitor.checkCancelled();
        JsonArray annotation = item.getAsJsonArray();
        long site = rva(annotation.get(0));
        if (!codeContains(site)) continue;
        if (key.equals("il") && annotation.get(2).getAsInt() == 0) continue;
        String message = key.equals("il")
            ? "IL [" + annotation.get(0).getAsString() + ", " + annotation.get(1).getAsString() + "): " + annotation.get(3).getAsString()
            : annotation.get(1).getAsString();
        mergeComment(program.getImageBase().add(site), CommentType.EOL, message);
      }
    }
  }

  private void publishStructure(String name, JsonArray members) throws Exception {
    Namespace owner = namespace(namespace(root, "Structures", false), name, false);
    var type = new StructureDataType(new CategoryPath("/Dart/B4a/Structures"), clean(name), 0);
    var sorted = new java.util.ArrayList<JsonElement>(members.asList());
    sorted.sort(java.util.Comparator.comparingInt(value -> value.getAsJsonArray().get(0).getAsInt()));
    for (var value : sorted) {
      monitor.checkCancelled();
      JsonArray member = value.getAsJsonArray();
      int offset = member.get(0).getAsInt();
      String label = member.get(1).getAsString();
      Address slot = record(value);
      slots.put(name + ":" + offset, slot);
      label(slot, label + "_" + Integer.toHexString(offset), owner);
      mergeComment(slot, CommentType.EOL, name + " + 0x" + Integer.toHexString(offset)
          + "; " + member.get(2).getAsString());
      // These are machine-word structures, never compressed object-slot arrays.
      // Unpacked append is linear. growStructure/replaceAtOffset repack all
      // previous members and become quadratic on a real 90,000-slot pool.
      if (type.getLength() < offset) {
        int gap = offset - type.getLength();
        type.add(new ghidra.program.model.data.ArrayDataType(Undefined.getUndefinedDataType(1), gap, 1),
            gap, "padding_" + type.getLength(), null);
      }
      type.add(Undefined.getUndefinedDataType(8), 8,
          clean(label) + "_" + Integer.toHexString(offset), member.get(2).getAsString());
    }
    if (program.getDataTypeManager().getDataType(type.getCategoryPath(), type.getName()) == null) {
      program.getDataTypeManager().resolve(type, DataTypeConflictHandler.KEEP_HANDLER);
    }
  }

  private void publishOperand(Address address, JsonArray row) throws Exception {
    Address retained = record(row);
    int operand = row.get(1).getAsInt();
    String structure = row.get(2).getAsString();
    long delta = row.get(3).getAsLong();
    var instruction = program.getListing().getInstructionAt(address);
    if (instruction == null || operand >= instruction.getNumOperands()) {
      unresolvedOperands++;
      return;
    }
    program.getReferenceManager().addMemoryReference(retained, address, RefType.DATA, SourceType.IMPORTED, 0);
    Scalar scalar = null;
    int count = 0;
    for (Object object : instruction.getOpObjects(operand)) {
      if (object instanceof Scalar value) { scalar = value; count++; }
    }
    Address slot = count == 1 ? slots.get(structure + ":" + (scalar.getSignedValue() + delta)) : null;
    if (slot == null) {
      unresolvedOperands++;
      mergeComment(address, CommentType.EOL, structure + ", operand " + operand + ", delta " + delta + " (unresolved slot)");
      return;
    }
    for (var reference : program.getReferenceManager().getReferencesFrom(address, operand)) {
      if (reference.getSource() == SourceType.USER_DEFINED) {
        unresolvedOperands++;
        return;
      }
    }
    program.getReferenceManager().addMemoryReference(address, slot, RefType.DATA, SourceType.IMPORTED, operand);
    mergeComment(address, CommentType.EOL, program.getListing().getComment(CommentType.EOL, slot));
    references++;
  }

  private void mergeComment(Address address, CommentType type, String text) {
    var listing = program.getListing();
    String previous = listing.getComment(type, address);
    String marked = "[b4a] " + text;
    if (previous != null && previous.contains(marked)) return;
    // Full, untruncated records live in FACTS. Keep normal views bounded.
    if (marked.length() > 8000) marked = marked.substring(0, 8000) + "… (full record in ghidart.b4a)";
    if (previous != null && previous.length() > 16000) return;
    listing.setComment(address, type, previous == null ? marked : previous + "\n" + marked);
    comments++;
  }

  private static String text(JsonObject object, String key, String fallback) {
    return object.has(key) && !object.get(key).isJsonNull() ? object.get(key).getAsString() : fallback;
  }
}
