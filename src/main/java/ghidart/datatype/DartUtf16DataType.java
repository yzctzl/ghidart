/**
 * Explicit-length little-endian UTF-16 code units, without C termination.
 *
 * A leading FEFF is a character, not a byte-order marker. Java's normal charset
 * decoder replaces unpaired surrogates; retain the original code units instead.
 * The native string renderer exposes malformed units as bytes rather than
 * inventing Unicode text. No Dart layout, length or encoding is inferred here.
 */
package ghidart.datatype;

import ghidra.docking.settings.Settings;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StringLayoutEnum;
import ghidra.program.model.data.WideChar16DataType;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.classfinder.ClassTranslator;

public final class DartUtf16DataType extends AbstractStringDataType {
  static {
    ClassTranslator.put("ghidart.DartUtf16DataType", DartUtf16DataType.class.getName());
  }

  public DartUtf16DataType() {
    this(null);
  }

  public DartUtf16DataType(DataTypeManager manager) {
    super("dart_chars16le", "chars16le", "CHARS", "CHARS", "u",
        "Explicit-length UTF-16LE code units (not a Dart object)",
        "UTF-16LE", WideChar16DataType.dataType, StringLayoutEnum.CHAR_SEQ, manager);
  }

  @Override
  public DataType clone(DataTypeManager manager) {
    return manager == getDataTypeManager() ? this : new DartUtf16DataType(manager);
  }

  // Ghidra's string editor re-encodes individual Java characters and rejects
  // surrogate code units. Expose this as a lossless view, edited in Bytes, rather
  // than claiming that its generic text editor can round-trip every Dart value.
  @Override
  public boolean isEncodable() {
    return false;
  }

  @Override
  public int getLength(MemBuffer buffer, int maximum) {
    return maximum >= 0 && (maximum & 1) == 0 ? super.getLength(buffer, maximum) : -1;
  }

  @Override
  public Object getValue(MemBuffer buffer, Settings settings, int length) {
    if (length < 0 || (length & 1) != 0) return null;
    var value = new StringBuilder();
    try {
      for (int offset = 0; offset < length; offset += 2) {
        int low = Byte.toUnsignedInt(buffer.getByte(offset));
        int high = Byte.toUnsignedInt(buffer.getByte(offset + 1));
        value.append((char) (low | high << 8));
      }
    } catch (MemoryAccessException e) {
      return null;
    }
    return value.toString();
  }
}
