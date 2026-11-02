/**
 * Explicit-length Latin-1 characters, including interior and trailing zeroes.
 *
 * Apply only to an independently identified character payload. This type reads
 * exactly the supplied byte length; it does not inspect an object header or
 * infer an encoding from printable bytes. Ghidra handles display and storage.
 */
package ghidart.datatype;

import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StringLayoutEnum;
import ghidra.util.classfinder.ClassTranslator;

public final class DartLatin1DataType extends AbstractStringDataType {
  static {
    ClassTranslator.put("ghidart.DartLatin1DataType", DartLatin1DataType.class.getName());
  }

  public DartLatin1DataType() {
    this(null);
  }

  public DartLatin1DataType(DataTypeManager manager) {
    super("dart_chars8", "chars8", "CHARS", "CHARS", "s",
        "Explicit-length Latin-1 character payload (not a Dart object)",
        "ISO-8859-1", CharDataType.dataType, StringLayoutEnum.CHAR_SEQ, manager);
  }

  @Override
  public DataType clone(DataTypeManager manager) {
    return manager == getDataTypeManager() ? this : new DartLatin1DataType(manager);
  }
}
