/**
 * Publish b4a facts through native Ghidra symbols, data types, comments and references.
 *
 * Read one declaration at a time: real documents can exceed 250 MB. Validate the
 * original image before mutation, and publish in one rollbackable transaction.
 * Private facts stay in properties. Descriptions annotate proved slots, never fake objects.
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
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
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
  public static final String ANNOTATIONS = "ghidart.b4a.listing";
  private static final int PRESENTATION = 7;
  private static final String GENERATION = "b4aGeneration";
  private final Program program;
  private final TaskMonitor monitor;
  private final Map<Integer, JsonObject> classes = new LinkedHashMap<>();
  private final Map<Integer, Namespace> owners = new HashMap<>();
  private final Map<String, JsonArray> slots = new HashMap<>();
  private final java.util.TreeMap<Long, DartCodeIndex.CodeUnit> ranges = new java.util.TreeMap<>();
  private final Map<String, JsonArray> structures = new LinkedHashMap<>();
  private StringPropertyMap facts;
  private Address next;
  private StringPropertyMap annotations;
  private final Map<Long, String> fallbackNames = new LinkedHashMap<>();
  private final Set<Address> named = new HashSet<>();
  private final java.util.List<Namespace> obsoleteNamespaces = new java.util.ArrayList<>();
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
    if (identity.equals(previous) && options.getInt("b4aPresentation", 0) == PRESENTATION) {
      log.appendMsg("Dart b4a Import", "This b4a generation is already imported; user edits preserved.");
      return;
    }
    if (!previous.isEmpty() && !identity.equals(previous)) {
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
    try (var graph = ghidart.snapshot.DartObjectGraph.batch(program, monitor)) {
      if (!previous.isEmpty()) importer.removeOldPresentation();
      DartAotAnalyzer.applyBoundaries(program, index.codeUnits(), monitor, log);
      monitor.setIndeterminate(false);
      monitor.initialize(importer.records, "Publishing b4a facts");
      ghidart.snapshot.DartObjectGraph.migrate(program, monitor);
      ghidart.listing.DartNamespaces.migrate(program, monitor);
      importer.initialize();
      monitor.setMessage("Publishing b4a classes and layouts");
      importer.publishClasses();
      for (var structure : importer.structures.entrySet()) {
        monitor.setMessage("Publishing b4a " + structure.getKey());
        importer.publishStructure(structure.getKey(), structure.getValue());
      }
      importer.scan(path, true);
      if (!identity.equals(hash(path, monitor))) throw new IllegalArgumentException("b4a file changed during import");
      importer.publishFallbackNames();
      ghidart.listing.DartSlotViews.pruneExport(program);
      ghidart.listing.DartSlotViews.upgradeAnchors(program, monitor);
      importer.pruneOldNamespaces();
      options.setInt("b4aPresentation", PRESENTATION);
      options.setString(GENERATION, identity);
      options.setString("b4aPath", path.toAbsolutePath().normalize().toString());
      graph.flush();
      committed = true;
    } finally {
      program.endTransaction(transaction, committed);
    }
    log.appendMsg("Dart b4a Import", "Imported " + importer.classes.size() + " classes, "
        + importer.declarations + " declarations, " + importer.names + " names, "
        + importer.comments + " Listing annotations and " + importer.references + " existing L2 slot matches; "
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
                if (publish) {
                  publishRecord(section, value);
                  monitor.increment();
                } else validateRecord(section, value);
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
              record(value); // Export metadata is retained privately, not fake Listing data.
              monitor.increment();
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
      if (section.equals("functions")) fallbackNames.putIfAbsent(rva, row.get(2).getAsString());
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

  /** Upgrade only our prior presentation; user symbols, comments and references survive. */
  private void removeOldPresentation() throws Exception {
    var oldRoot = program.getSymbolTable().getNamespace("B4a", program.getGlobalNamespace());
    if (oldRoot != null) {
      obsoleteNamespaces.add(oldRoot);
      rememberNamespaces(oldRoot);
    }
    var old = program.getMemory().getBlock("B4aMetadata");
    if (old != null) {
      var map = program.getUsrPropertyManager().getStringPropertyMap(FACTS);
      var locations = map.getPropertyIterator();
      while (locations.hasNext()) {
        monitor.checkCancelled();
        Address address = locations.next();
        var data = program.getListing().getDataAt(address);
        if (data != null && !Undefined.isUndefined(data.getDataType())) {
          throw new IllegalArgumentException("user data types in old metadata; use a fresh database");
        }
        for (var kind : CommentType.values()) {
          String comment = program.getListing().getComment(kind, address);
          if (comment != null && comment.lines().anyMatch(line -> !line.startsWith("[b4a] "))) {
            throw new IllegalArgumentException("user comments in old metadata; use a fresh database");
          }
        }
        for (var reference : program.getReferenceManager().getReferencesTo(address)) {
          if (reference.getSource() == SourceType.USER_DEFINED) {
            throw new IllegalArgumentException("user references point to old metadata; use a fresh database");
          }
          if (reference.getSource() == SourceType.IMPORTED) program.getReferenceManager().delete(reference);
        }
        for (var reference : program.getReferenceManager().getReferencesFrom(address)) {
          if (reference.getSource() == SourceType.IMPORTED) program.getReferenceManager().delete(reference);
        }
        for (var symbol : program.getSymbolTable().getSymbols(address)) {
          if (symbol.getSource() == SourceType.USER_DEFINED) {
            throw new IllegalArgumentException("user symbols in old metadata; use a fresh database");
          }
          if (symbol.getSource() == SourceType.IMPORTED) symbol.delete();
        }
      }
      program.getMemory().removeBlock(old, monitor);
    }
    var listing = program.getListing();
    for (var kind : new CommentType[] {CommentType.PLATE, CommentType.EOL}) {
      var iterator = listing.getCommentAddressIterator(kind, program.getMemory(), true);
      while (iterator.hasNext()) {
        monitor.checkCancelled();
        Address address = iterator.next();
        String comment = listing.getComment(kind, address);
        if (comment == null || !comment.contains("[b4a] ")) continue;
        String kept = comment.lines().filter(line -> !line.startsWith("[b4a] "))
            .collect(java.util.stream.Collectors.joining("\n"));
        listing.setComment(address, kind, kept.isEmpty() ? null : kept);
      }
    }
    var entries = program.getSymbolTable().getNamespace("B4a", program.getGlobalNamespace());
    if (entries != null) {
      entries = program.getSymbolTable().getNamespace("Entries", entries);
      if (entries != null) {
        var iterator = program.getSymbolTable().getSymbols(entries);
        while (iterator.hasNext()) {
          var symbol = iterator.next();
          if (symbol.getSource() == SourceType.IMPORTED && !symbol.getSymbolType().equals(
              ghidra.program.model.symbol.SymbolType.FUNCTION)) symbol.delete();
        }
        if (!program.getSymbolTable().getSymbols(entries).hasNext()) entries.getSymbol().delete();
      }
    }
    var descriptions = program.getMemory().getBlock("B4aValues");
    if (descriptions != null) {
      // This overlay held exported text, never target bytes. Refuse to discard
      // user work; ordinary imports remove only the presentation we created.
      var oldFacts = program.getUsrPropertyManager().getStringPropertyMap(FACTS);
      var data = listing.getDefinedData(new ghidra.program.model.address.AddressSet(
          descriptions.getStart(), descriptions.getEnd()), true);
      while (data.hasNext()) {
        monitor.checkCancelled();
        var value = data.next();
        String json = oldFacts == null ? null : oldFacts.getString(value.getAddress());
        if (json == null || !value.hasStringValue()
            || !slotText(JsonParser.parseString(json).getAsJsonArray()).equals(value.getValue())) {
          throw new IllegalArgumentException("modified B4aValues data; use a fresh database");
        }
        for (var kind : CommentType.values()) {
          if (listing.getComment(kind, value.getAddress()) != null) {
            throw new IllegalArgumentException("user comments in B4aValues; use a fresh database");
          }
        }
        for (var reference : program.getReferenceManager().getReferencesFrom(value.getAddress())) {
          if (reference.getSource() == SourceType.USER_DEFINED) throw new IllegalArgumentException("user references in B4aValues; use a fresh database");
        }
      }
      for (var it = program.getSymbolTable().getSymbolIterator(descriptions.getStart(), true); it.hasNext();) {
        var symbol = it.next();
        if (!descriptions.contains(symbol.getAddress())) break;
        if (symbol.getSource() == SourceType.USER_DEFINED) throw new IllegalArgumentException("user symbols in B4aValues; use a fresh database");
      }
      for (var it = program.getReferenceManager().getReferenceDestinationIterator(
          new ghidra.program.model.address.AddressSet(descriptions.getStart(), descriptions.getEnd()), true); it.hasNext();) {
        for (var reference : program.getReferenceManager().getReferencesTo(it.next())) {
          if (reference.getSource() == SourceType.USER_DEFINED) throw new IllegalArgumentException("user references to B4aValues; use a fresh database");
          if (reference.getSource() == SourceType.IMPORTED) program.getReferenceManager().delete(reference);
        }
      }
      program.getMemory().removeBlock(descriptions, monitor);
    }
    program.getUsrPropertyManager().removePropertyMap(FACTS);
    program.getUsrPropertyManager().removePropertyMap(ANNOTATIONS);
  }

  private void initialize() throws Exception {
    // Private records need keys, not mapped zero-filled bytes or symbol-tree labels.
    next = program.getAddressFactory().getAddressSpace("OTHER").getAddress(0x40_0000_0000L);
    facts = program.getUsrPropertyManager().createStringPropertyMap(FACTS);
    annotations = program.getUsrPropertyManager().createStringPropertyMap(ANNOTATIONS);
    root = program.getGlobalNamespace();
  }

  private void record(JsonElement value) throws Exception {
    monitor.checkCancelled();
    Address address = next;
    next = next.add(8);
    facts.add(address, value.toString());
  }

  private static boolean hasContent(JsonArray row) {
    String name = row.get(1).getAsString();
    return !row.get(2).getAsString().isBlank() || (!name.isBlank() && !name.startsWith("pad_"));
  }

  private static String slotText(JsonArray row) {
    String description = row.get(2).getAsString();
    return description.isBlank() ? row.get(1).getAsString() : description;
  }

  private Namespace namespace(Namespace parent, String name, boolean clazz) throws Exception {
    return ghidart.listing.DartNamespaces.namespace(program, parent, name, clazz, SourceType.IMPORTED);
  }

  private static String clean(String name) {
    return ghidart.listing.DartNamespaces.clean(name);
  }

  private void label(Address address, String name, Namespace owner) throws Exception {
    if (program.getSymbolTable().getSymbol(clean(name), address, owner) == null) {
      program.getSymbolTable().createLabel(address, clean(name), owner, SourceType.IMPORTED);
    }
  }

  private void publishClasses() throws Exception {
    for (var cls : classes.values()) {
      monitor.checkCancelled();
      int id = cls.get("id").getAsInt();
      Namespace library = ghidart.listing.DartNamespaces.library(program, text(cls, "library", "SDK"), SourceType.IMPORTED);
      String name = text(cls, "name", "class_" + id);
      Namespace owner = (name.isEmpty() || name.equals("::")) ? library
          : ghidart.listing.DartNamespaces.clazz(program, id, library, name, SourceType.IMPORTED);
      owners.put(id, owner);
      facts.add(classKey(program, id), cls.toString());
    }
    for (var cls : classes.values()) publishLayout(cls);
    // Manual L3 import may follow an already-published L2 object graph.
    var objects = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    if (objects != null) {
      var identities = objects.getPropertyIterator();
      while (identities.hasNext()) {
        monitor.checkCancelled();
        Address address = identities.next();
        var object = JsonParser.parseString(objects.getString(address)).getAsJsonObject();
        if (object.has("kind") && object.get("kind").getAsString().equals("Class") && object.has("object")) {
          annotateClass(program, address, object.getAsJsonObject("object").get("classId").getAsInt());
        }
      }
    }
  }

  private static Address classKey(Program program, int cid) {
    return program.getAddressFactory().getAddressSpace("OTHER").getAddress(0x50_0000_0000L + cid);
  }

  /** Match Class identities by validated target CID, not by a pretty name or heap address. */
  public static void annotateClass(Program program, Address identity, int cid) {
    var facts = program.getUsrPropertyManager().getStringPropertyMap(FACTS);
    if (facts == null) return;
    String cls = facts.getString(classKey(program, cid));
    if (cls == null) return;
    String previous = facts.getString(identity);
    var record = previous == null ? new JsonObject() : JsonParser.parseString(previous).getAsJsonObject();
    record.add("class", JsonParser.parseString(cls));
    facts.add(identity, record.toString());
    enrichClassLayout(program, identity, cid, JsonParser.parseString(cls).getAsJsonObject());
  }

  /** Fill unnamed L2 slots from the validated b4a layout in either import order.
   * Keep the native Structure object so existing tagged pointers see the names.
   * Storage, retained L2 names and user edits are never replaced.
   */
  private static void enrichClassLayout(Program program, Address identity, int cid, JsonObject cls) {
    var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    String raw = facts == null ? null : facts.getString(identity);
    if (raw == null || !cls.has("size")) return;
    var object = JsonParser.parseString(raw).getAsJsonObject();
    if (!object.has("layout")) return;
    var layout = object.getAsJsonObject("layout");
    var manager = program.getDataTypeManager();
    var targetType = manager.getDataType(layout.get("typePath").getAsString());
    var sourceType = manager.getDataType(new CategoryPath("/Dart/B4a/Classes"),
        "Class_" + cid + "_" + clean(text(cls, "name", "unnamed")));
    if (!(targetType instanceof ghidra.program.model.data.Structure target)
        || !(sourceType instanceof ghidra.program.model.data.Structure source)
        || target.getLength() != cls.get("size").getAsInt()
        || source.getLength() != target.getLength()) return;
    int word = layout.get("word").getAsInt();
    var names = new java.util.HashSet<String>();
    for (var field : target.getDefinedComponents()) names.add(field.getFieldName());
    for (var field : source.getDefinedComponents()) {
      int offset = field.getOffset();
      var slot = target.getComponentAt(offset);
      if (offset < 8 || slot == null || slot.getOffset() != offset
          || slot.getLength() != word || field.getLength() != word
          || !("slot_" + Integer.toHexString(offset)).equals(slot.getFieldName())
          || field.getFieldName() == null || names.contains(field.getFieldName())) continue;
      String comment = slot.getComment();
      boolean tagged = "Tagged value".equals(comment)
          && slot.getDataType().getName().equals("DartTagged" + word * 8)
          && slot.getDataType().getCategoryPath().equals(target.getCategoryPath())
          && slot.getDataType() instanceof ghidra.program.model.data.TypeDef alias
          && alias.getDataType().isEquivalent(word == 4
              ? ghidra.program.model.data.DWordDataType.dataType
              : ghidra.program.model.data.QWordDataType.dataType);
      boolean unboxed = "Unboxed bits; numeric type is not implied".equals(comment)
          && Undefined.isUndefined(slot.getDataType());
      if (!tagged && !unboxed) continue;
      slot.setFieldName(field.getFieldName());
      slot.setComment(comment + "; b4a field name");
      names.add(field.getFieldName());
    }
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
    if (section.equals("codeUnits")) return; // Already represented by real functions/ranges.
    JsonArray row = value.getAsJsonArray();
    long offset = rva(row.get(0));
    Address address = program.getImageBase().add(offset);
    if (section.equals("functions")) {
      return; // Legacy names are fallback names, never a second parallel tree.
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
    declarations++;
    Namespace owner = owners.getOrDefault(body.get("cid").getAsInt(), root);
    String name = body.get("name").getAsString();
    int separator = name.indexOf("::");
    if (separator >= 0) name = name.substring(separator + 2);
    name = clean(name) + "_" + Long.toHexString(offset);

    if (!codeContains(offset)) { record(row); return; }
    Address entry = program.getImageBase().add(offset);
    appendFact(entry, "declarations", row);
    var function = program.getFunctionManager().getFunctionAt(entry);
    if (function != null && function.getSymbol().getSource() != SourceType.USER_DEFINED
        && (function.getSymbol().getSource() != SourceType.IMPORTED || isOurs(function.getParentNamespace()))
        && named.add(entry)) {
      // Move and rename atomically: L2 may already have a shared-code alias
      // using the old method name in this class at the same address.
      function.getSymbol().setNameAndNamespace(name, owner, SourceType.IMPORTED);
      names++;
    }
    label(entry, name, owner);

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
        saveAnnotation(program.getImageBase().add(site), message);
      }
    }
  }

  private void publishStructure(String name, JsonArray members) throws Exception {
    if (members.asList().stream().noneMatch(value -> hasContent(value.getAsJsonArray()))) return;
    var type = new StructureDataType(new CategoryPath("/Dart/B4a/Structures"), clean(name), 0);
    var sorted = new java.util.ArrayList<JsonElement>(members.asList());
    sorted.sort(java.util.Comparator.comparingInt(value -> value.getAsJsonArray().get(0).getAsInt()));
    long extent = sorted.isEmpty() ? 0 : sorted.getLast().getAsJsonArray().get(0).getAsLong() + 8;
    Address model = ghidart.listing.DartSlotViews.exportedStructure(program, name, extent, monitor);
    Namespace modelOwner = model == null ? null : ghidart.listing.DartSlotViews.exportedOwner(program, name);
    for (var value : sorted) {
      monitor.checkCancelled();
      JsonArray member = value.getAsJsonArray();
      monitor.increment();
      int offset = member.get(0).getAsInt();
      String label = member.get(1).getAsString();
      if (!hasContent(member)) continue;
      slots.put(name + ":" + offset, member);
      if (model != null) {
        Address target = model.add(offset);
        ghidart.listing.DartSlotViews.slot(program, target, modelOwner, clean(label) + "_" + Integer.toHexString(offset),
            slotText(member), SourceType.IMPORTED);
        JsonArray retained = new JsonArray();
        retained.add(name);
        retained.add(member);
        appendFact(target, "structureMembers", retained);
      }
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
    appendFact(address, "operands", row);
    int operand = row.get(1).getAsInt();
    String structure = row.get(2).getAsString();
    long delta = row.get(3).getAsLong();
    var instruction = program.getListing().getInstructionAt(address);
    if (instruction == null || operand >= instruction.getNumOperands()) {
      unresolvedOperands++;
      return;
    }
    Scalar scalar = null;
    int count = 0;
    for (Object object : instruction.getOpObjects(operand)) {
      if (object instanceof Scalar value) { scalar = value; count++; }
    }
    long offset = count == 1 ? scalar.getSignedValue() + delta : count == 0 ? delta : -1;
    JsonArray member = slots.get(structure + ":" + offset);
    if (member == null) {
      unresolvedOperands++;
      return;
    }
    saveAnnotation(address, structure + " + 0x" + Long.toHexString(offset) + ": " + slotText(member));
    publishModelAccess(program, address, row);
    if (!structure.equals("DartObjectPool")) return;
    JsonArray description = new JsonArray();
    description.add(offset);
    description.add(member);
    appendFact(address, "poolDescriptions", description);
    // L2 may already exist when L3 is imported manually. Keep its real READ/WRITE
    // and character references; an exported description is not a new destination.
    var l2 = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    if (l2 == null) return;
    for (var reference : ghidart.snapshot.DartObjectGraph.from(program, address)) {
      if (reference.getReferenceType() != RefType.READ && reference.getReferenceType() != RefType.WRITE) continue;
      String json = l2.getString(reference.getToAddress());
      if (json == null) continue;
      var slot = JsonParser.parseString(json).getAsJsonObject();
      if (slot.has("poolRef") && slot.has("index")
          && slot.get("index").getAsLong() * 8 + 16 == offset) {
        annotatePoolSlot(program, address, reference.getToAddress(), offset);
        references++;
      }
    }
  }

  /** Replay after L2 disassembles additional entries; keep retained export rows useful. */
  public static int restoreModelReferences(Program program, TaskMonitor monitor) throws CancelledException {
    var facts = program.getUsrPropertyManager().getStringPropertyMap(FACTS);
    if (facts == null) return 0;
    int linked = 0;
    monitor.setMessage("Linking exported THR/PP field accesses");
    var addresses = facts.getPropertyIterator();
    while (addresses.hasNext()) {
      monitor.checkCancelled();
      Address address = addresses.next();
      String stored = facts.getString(address);
      if (stored == null || !stored.contains("\"operands\"")) continue;
      var record = JsonParser.parseString(stored).getAsJsonObject();
      if (!record.has("operands")) continue;
      for (var value : record.getAsJsonArray("operands")) {
        linked += publishModelAccess(program, address, value.getAsJsonArray());
      }
    }
    return linked;
  }

  private static int publishModelAccess(Program program, Address address, JsonArray row) {
    String structure = row.get(2).getAsString();
    if (!structure.equals("DartThread") && !structure.equals("DartObjectPool")) return 0;
    int operand = row.get(1).getAsInt();
    var instruction = program.getListing().getInstructionAt(address);
    if (instruction == null || operand >= instruction.getNumOperands()) return 0;
    Scalar scalar = null;
    int scalars = 0, registers = 0;
    boolean matchesBase = false;
    var base = program.getRegister(structure.equals("DartThread") ? "x26" : "x27");
    for (Object object : instruction.getOpObjects(operand)) {
      if (object instanceof Scalar value) { scalar = value; scalars++; }
      if (object instanceof ghidra.program.model.lang.Register register) {
        registers++;
        matchesBase |= register.equals(base);
      }
    }
    if (scalars > 1 || registers != 1 || !matchesBase) return 0;
    long offset = (scalar == null ? 0 : scalar.getSignedValue()) + row.get(3).getAsLong();
    // Unknown register-based addresses often have only a generic DATA operand
    // type in Ghidra. The decoded LOAD/STORE effects establish read/write kind.
    boolean read = false, write = false;
    for (var op : instruction.getPcode()) {
      read |= op.getOpcode() == ghidra.program.model.pcode.PcodeOp.LOAD;
      write |= op.getOpcode() == ghidra.program.model.pcode.PcodeOp.STORE;
    }
    if (!read && !write) return 0;
    var type = read && write ? RefType.READ_WRITE : read ? RefType.READ : RefType.WRITE;
    String modelName = structure.equals("DartThread") ? "THR" : "PP";
    var block = program.getMemory().getBlock("DartSlots_" + modelName);
    if (block == null || offset < 0 || offset >= block.getSize()) return 0;
    Address target = block.getStart().add(offset);
    if (program.getListing().getDataAt(target) == null) return 0;
    if (structure.equals("DartObjectPool")
        && program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1") != null) {
      // Once L2 is available, require its pool provenance. Offset equality alone
      // cannot select the active pool when a function changes PP.
      boolean proved = ghidart.snapshot.DartObjectGraph.from(program, address).stream()
          .anyMatch(edge -> (edge.getReferenceType().isRead() || edge.getReferenceType().isWrite())
              && target.equals(ghidart.listing.DartSlotViews.forRecord(program, edge.getToAddress())));
      if (!proved) return 0;
    }
    if (program.getReferenceManager().getReference(address, target, -1) != null) return 0;
    program.getReferenceManager().addMemoryReference(address, target, type, SourceType.ANALYSIS, -1);
    return 1;
  }

  /** Attach L3 evidence to an L2-proved, pool-scoped slot. Never invent a pointer.
   * Called by L2 after its native reference is established, and by a later L3 import.
   */
  public static void annotatePoolSlot(Program program, Address site, Address slot, long offset) {
    var facts = program.getUsrPropertyManager().getStringPropertyMap(FACTS);
    if (facts == null) return;
    String json = facts.getString(site);
    if (json == null) return;
    var record = JsonParser.parseString(json).getAsJsonObject();
    if (!record.has("poolDescriptions")) return;
    var descriptions = new JsonArray();
    String previous = facts.getString(slot);
    var result = previous == null ? new JsonObject() : JsonParser.parseString(previous).getAsJsonObject();
    if (result.has("poolDescriptions")) descriptions = result.getAsJsonArray("poolDescriptions");
    for (var value : record.getAsJsonArray("poolDescriptions")) {
      var row = value.getAsJsonArray();
      if (row.get(0).getAsLong() != offset) continue;
      if (!descriptions.contains(row.get(1))) descriptions.add(row.get(1));
      appendAnnotation(program.getUsrPropertyManager().getStringPropertyMap(ANNOTATIONS),
          slot, "b4a: " + slotText(row.get(1).getAsJsonArray()));
    }
    if (descriptions.isEmpty()) return;
    result.add("poolDescriptions", descriptions);
    facts.add(slot, result.toString());
  }

  private void appendFact(Address address, String kind, JsonElement value) {
    String previous = facts.getString(address);
    JsonObject object = previous == null ? new JsonObject() : JsonParser.parseString(previous).getAsJsonObject();
    if (!object.has(kind)) object.add(kind, new JsonArray());
    object.getAsJsonArray(kind).add(value);
    facts.add(address, object.toString());
  }

  private void rememberNamespaces(Namespace owner) {
    for (var symbol : program.getSymbolTable().getSymbols(owner)) {
      if (symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.LABEL
          && symbol.getSource() == SourceType.IMPORTED) symbol.delete();
      else if (symbol.getSymbolType().isNamespace() && !symbol.getSymbolType().equals(
          ghidra.program.model.symbol.SymbolType.FUNCTION) && symbol.getObject() instanceof Namespace child) {
        obsoleteNamespaces.add(child);
        rememberNamespaces(child);
      }
    }
  }

  private void pruneOldNamespaces() {
    for (int i = obsoleteNamespaces.size() - 1; i >= 0; i--) {
      Namespace owner = obsoleteNamespaces.get(i);
      var symbol = owner.getSymbol();
      if (!symbol.isDeleted() && symbol.getSource() == SourceType.IMPORTED
          && !program.getSymbolTable().getSymbols(owner).hasNext()) symbol.delete();
    }
  }

  private void saveAnnotation(Address address, String text) {
    if (appendAnnotation(annotations, address, text)) comments++;
  }

  private static boolean appendAnnotation(StringPropertyMap map, Address address, String text) {
    if (map == null) return false;
    String previous = map.getString(address);
    if (previous != null && (previous.contains(text) || previous.length() > 8000)) return false;
    map.add(address, previous == null ? text : previous + "\n" + text);
    return true;
  }

  private boolean isOurs(Namespace owner) {
    while (!owner.isGlobal()) {
      if ((owner.getName().equals("B4a") || owner.getName().equals("Library")
          || java.util.Set.of("Packages", "SDK", "App", "Runtime", "Unresolved").contains(owner.getName()))
          && owner.getParentNamespace().isGlobal()) return true;
      owner = owner.getParentNamespace();
    }
    return false;
  }

  private void publishFallbackNames() throws Exception {
    for (var item : fallbackNames.entrySet()) {
      monitor.checkCancelled();
      if (!codeContains(item.getKey())) continue;
      Address entry = program.getImageBase().add(item.getKey());
      if (named.contains(entry)) continue;
      var function = program.getFunctionManager().getFunctionAt(entry);
      if (function == null || function.getSymbol().getSource() == SourceType.USER_DEFINED
          || (function.getSymbol().getSource() == SourceType.IMPORTED && !isOurs(function.getParentNamespace()))) continue;
      function.getSymbol().setNameAndNamespace(clean(item.getValue()),
          namespace(root, "Runtime", false), SourceType.IMPORTED);
      names++;
    }
  }

  public static boolean isImported(Program program) {
    return !program.getOptions("ghidart").getString(GENERATION, "").isEmpty();
  }

  private static String text(JsonObject object, String key, String fallback) {
    return object.has(key) && !object.get(key).isJsonNull() ? object.get(key).getAsString() : fallback;
  }
}
