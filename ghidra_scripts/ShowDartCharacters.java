// Show the complete contents of an explicitly typed character payload.
// Place the cursor in dart_chars8 / dart_chars16le data, or on an instruction
// referencing it. No object layout, printable-byte heuristic or encoding guess
// is used. Unlike C literal inlining, this view preserves embedded zeroes.
// @category Dart

import ghidart.datatype.DartLatin1DataType;
import ghidart.datatype.DartUtf16DataType;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import java.util.LinkedHashSet;

public class ShowDartCharacters extends GhidraScript {
  @Override
  public void run() throws Exception {
    if (currentProgram == null || currentAddress == null) {
      println("Open a program and select a character payload or its reference.");
      return;
    }
    var payloads = new LinkedHashSet<Data>();
    add(payloads, getDataContaining(currentAddress));
    for (var reference : getReferencesFrom(currentAddress)) {
      monitor.checkCancelled();
      if (reference.isMemoryReference()) {
        add(payloads, getDataContaining(reference.getToAddress()));
      }
    }
    if (payloads.isEmpty()) {
      println("No explicitly typed Dart characters here. Apply dart_chars8 or "
          + "dart_chars16le only when payload address, length and encoding are known.");
    }
    for (var data : payloads) {
      monitor.checkCancelled();
      if (!(data.getValue() instanceof String text)) {
        println(data.getAddress() + ": character bytes could not be read.");
        continue;
      }
      println(data.getAddress() + "  " + data.getDataType().getName() + "  "
          + data.getLength() + " bytes, " + text.length() + " code units");
      // Bounded lines keep a large payload readable without truncating it.
      // Escape each UTF-16 code unit separately, including lone surrogates.
      for (int start = 0; start < text.length(); start += 64) {
        monitor.checkCancelled();
        var line = new StringBuilder();
        for (int i = start; i < Math.min(start + 64, text.length()); i++) {
          char unit = text.charAt(i);
          if (unit == '\\' || unit == '"') line.append('\\').append(unit);
          else if (unit >= 0x20 && unit <= 0x7e) line.append(unit);
          else line.append(String.format("\\u%04x", (int) unit));
        }
        println("  [" + start + "] \"" + line + "\"");
      }
    }
  }

  private void add(LinkedHashSet<Data> payloads, Data data) {
    if (data == null) return;
    var type = data.getDataType();
    if (type instanceof DartLatin1DataType || type instanceof DartUtf16DataType) {
      payloads.add(data);
    }
  }
}
