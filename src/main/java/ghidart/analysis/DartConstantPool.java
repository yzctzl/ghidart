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
public final class DartConstantPool extends ConstantPool {
  private final Program program;

  DartConstantPool(Program program) { this.program = program; }

  /** The same evidence decision drives native lifting and the user's explanation.
   * A recorded initial value alone does not prove a slot remains constant at runtime.
   */
  public record Evidence(Address slot, String value, String explanation) {
    public boolean liftable() { return value != null; }
  }

  static Address reference(Program program, Address site) {
    var evidence = evidence(program, site);
    return evidence.liftable() ? evidence.slot() : null;
  }

  public static Evidence evidence(Program program, Address site) {
    var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    if (facts == null) return new Evidence(null, null, "No validated L2 pool records are present.");
    Address modelRecord = ghidart.listing.DartSlotViews.forRecord(program, site);
    if (modelRecord != null && facts.hasProperty(modelRecord)) site = modelRecord;
    String raw = facts.getString(site);
    if (raw != null && raw.contains("\"poolRef\"")) return string(program, site);
    Address slot = null;
    for (var edge : DartObjectGraph.from(program, site)) {
      if (edge.getReferenceType() != RefType.READ) continue;
      if (slot != null) return new Evidence(null, null,
          "Several read targets are recorded; one stable pool identity has not been established.");
      slot = edge.getToAddress();
    }
    return slot == null ? new Evidence(null, null,
        "No validated pool read is recorded here. Writes and THR calls are not constant loads.")
        : string(program, slot);
  }

  private static Evidence string(Program program, Address slot) {
    var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    String raw = facts == null ? null : facts.getString(slot);
    if (raw == null) return new Evidence(slot, null, "The read target has no validated L2 slot record.");
    var entry = JsonParser.parseString(raw).getAsJsonObject();
    if (!entry.has("poolRef") || !entry.has("kind")) {
      return new Evidence(slot, null, "The read target is not a validated object-pool slot.");
    }
    if (!entry.get("kind").getAsString().equals("TAGGED")) {
      return new Evidence(slot, null, "This slot contains " + entry.get("kind").getAsString()
          + "; native String substitution does not apply.");
    }
    if (!entry.has("stableTaggedBits") || !entry.has("bits")
        || entry.get("bits").getAsInt() != entry.get("stableTaggedBits").getAsInt()) {
      return new Evidence(slot, null,
          "The initial object is recorded, but slot traits do not prove an immutable tagged value.");
    }
    String value = null;
    for (var edge : DartObjectGraph.from(program, slot)) {
      if (edge.getReferenceType() != RefType.DATA) continue;
      var data = program.getListing().getDefinedDataAt(edge.getToAddress());
      if (data == null || !data.hasStringValue()) continue;
      // Only file-backed characters published by the validated snapshot reader.
      var block = program.getMemory().getBlock(data.getAddress());
      if (block == null || !block.isLoaded() || !block.isInitialized() || block.isArtificial()) continue;
      if (value != null) return new Evidence(slot, null, "Several character payloads are linked to this slot.");
      if (!(data.getValue() instanceof String text)) {
        return new Evidence(slot, null, "The character data has no decodable String value.");
      }
      // Native CPOOL prints NUL-terminated UTF-8. Preserve explicit-length data
      // for embedded NULs and unpaired UTF-16 units instead of silently truncating.
      if (text.indexOf(0) >= 0) return new Evidence(slot, null,
          "Embedded NUL: kept as explicit-length data; native String literals would truncate it.");
      if (!java.nio.charset.StandardCharsets.UTF_8.newEncoder().canEncode(text)) {
        return new Evidence(slot, null,
            "Unpaired UTF-16 units: kept as raw character data to preserve the exact value.");
      }
      value = text;
    }
    return new Evidence(slot, value, value == null
        ? "No unique file-backed String payload is linked; the initial object remains available in Dart Records."
        : "Stable tagged String with file-backed characters; eligible for native literal substitution.");
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
    String value = string(program, slot).value();
    if (value == null) throw new IllegalStateException("Dart pool evidence changed; refresh decompilation");
    var record = new Record();
    record.tag = STRING_LITERAL;
    record.setUTF8Data(value);
    record.type = new TypedefDataType(new CategoryPath("/Dart"), "DartStringRef", QWordDataType.dataType);
    return record;
  }
}
