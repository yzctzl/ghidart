/** Stable managed string references for Ghidra's native constant-pool operation. */
package ghidart.analysis;

import com.google.gson.JsonParser;
import ghidart.snapshot.DartObjectGraph;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;

/** A Dart String reference is a managed value, never a pointer to its file characters. */
final class DartConstantPool extends ConstantPool {
  private final Program program;

  DartConstantPool(Program program) { this.program = program; }

  static Address reference(Program program, Address site) {
    var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    if (facts == null) return null;
    Address slot = null;
    for (var edge : DartObjectGraph.from(program, site)) {
      if (edge.getReferenceType() != RefType.READ) continue;
      if (slot != null) return null;
      slot = edge.getToAddress();
    }
    return slot != null && string(program, slot) != null ? slot : null;
  }

  private static String string(Program program, Address slot) {
    var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    String raw = facts == null ? null : facts.getString(slot);
    if (raw == null) return null;
    var entry = JsonParser.parseString(raw).getAsJsonObject();
    if (!entry.has("poolRef") || !entry.has("stableTaggedBits")
        || !entry.get("kind").getAsString().equals("TAGGED")
        || entry.get("bits").getAsInt() != entry.get("stableTaggedBits").getAsInt()) return null;
    String value = null;
    for (var edge : DartObjectGraph.from(program, slot)) {
      if (edge.getReferenceType() != RefType.DATA) continue;
      var data = program.getListing().getDefinedDataAt(edge.getToAddress());
      if (data == null || !data.hasStringValue()) continue;
      // Only file-backed characters published by the validated snapshot reader.
      var block = program.getMemory().getBlock(data.getAddress());
      if (block == null || !block.isLoaded() || !block.isInitialized() || block.isArtificial()) continue;
      if (value != null || !(data.getValue() instanceof String text) || text.indexOf(0) >= 0
          || !java.nio.charset.StandardCharsets.UTF_8.newEncoder().canEncode(text)) return null;
      // Native CPOOL prints NUL-terminated UTF-8. Keep embedded NULs and
      // unpaired Dart UTF-16 units in explicit-length data and raw loads,
      // rather than truncating or silently inserting replacement characters.
      value = text;
    }
    return value;
  }

  @Override
  public Record getRecord(long[] references) {
    // RuleTransformCpool appends the record tag after its first lookup. Native
    // type propagation can query again using that decorated reference.
    if (references.length != 1
        && !(references.length == 2 && references[1] == STRING_LITERAL)) {
      throw new IllegalStateException("Invalid Dart constant reference: "
          + java.util.Arrays.toString(references));
    }
    Address slot = program.getAddressFactory().getAddressSpace("OTHER").getAddress(references[0]);
    String value = string(program, slot);
    if (value == null) throw new IllegalStateException("Dart pool evidence changed; refresh decompilation");
    var record = new Record();
    record.tag = STRING_LITERAL;
    record.setUTF8Data(value);
    record.type = new TypedefDataType(new CategoryPath("/Dart"), "DartStringRef", QWordDataType.dataType);
    return record;
  }
}
