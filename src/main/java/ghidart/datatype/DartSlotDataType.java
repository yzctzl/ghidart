/** Navigation anchor for a model offset, not bytes from a runtime Thread or pool.
 *
 * Values are rendered from validated database facts without reading the backing
 * bytes. In particular, a serialized object ID is never exposed as a pointer,
 * and an unknown Thread value is shown as runtime-dependent rather than zero.
 * The one-byte anchor assigns no physical field extent or executable semantics.
 */
package ghidart.datatype;

import ghidart.listing.DartSlotViews;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.BuiltIn;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.mem.MemBuffer;

public final class DartSlotDataType extends BuiltIn {
  public DartSlotDataType() { this(null); }

  public DartSlotDataType(DataTypeManager manager) {
    super(CategoryPath.ROOT, "dart_slot", manager);
  }

  @Override public int getLength() { return 1; }
  @Override public String getDescription() { return "Dart offset-model anchor; not runtime memory"; }
  @Override public Object getValue(MemBuffer buffer, Settings settings, int length) { return null; }
  @Override public Class<?> getValueClass(Settings settings) { return Object.class; }
  @Override public String getRepresentation(MemBuffer buffer, Settings settings, int length) {
    return DartSlotViews.summary(buffer.getMemory().getProgram(), buffer.getAddress());
  }
  @Override public DataType clone(DataTypeManager manager) {
    return manager == getDataTypeManager() ? this : new DartSlotDataType(manager);
  }
}
