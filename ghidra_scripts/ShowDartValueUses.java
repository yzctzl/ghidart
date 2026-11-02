// Print saved PP-relative accesses and constant uses for the current function.
// Run Dart Value Uses analysis first; rerun it after changing code or signatures.
// @category Dart

import ghidart.analysis.DartValueAnalyzer;
import ghidra.app.script.GhidraScript;

public class ShowDartValueUses extends GhidraScript {
  @Override
  public void run() throws Exception {
    if (currentProgram == null || currentAddress == null) {
      println("Open a program and place the cursor inside a Dart function.");
      return;
    }
    var function = getFunctionContaining(currentAddress);
    if (function == null) {
      println("Place the cursor inside a Dart function.");
      return;
    }
    var uses = DartValueAnalyzer.uses(currentProgram, function);
    var objects = DartValueAnalyzer.objectUses(currentProgram, function);
    if (uses.isEmpty() && objects.isEmpty()) {
      println("No saved value uses. Run Dart Value Uses analysis on this function.");
      return;
    }
    println("Machine-value uses for " + function.getName()
        + "; PP offsets do not identify pool entries or objects.");
    for (var use : uses) {
      monitor.checkCancelled();
      String value = use.origin() == null ? "0x" + Long.toUnsignedString(use.value(), 16)
          : use.origin() + (use.value() < 0 ? " - 0x" : " + 0x")
              + Long.toUnsignedString(use.value() < 0 ? -use.value() : use.value(), 16);
      println(use.site() + "  " + use.kind() + "[" + use.input() + "]  "
          + use.width() + " bytes  " + value);
    }
    for (var use : objects) {
      monitor.checkCancelled();
      var address = currentProgram.getAddressFactory().getAddress(use.declaration());
      var symbol = address == null ? null : currentProgram.getSymbolTable().getPrimarySymbol(address);
      String declaration = symbol == null ? use.declaration() : symbol.getName(true);
      println(use.site() + "  " + use.kind() + "  " + declaration
          + (use.value().isEmpty() ? "" : " [physical input " + use.value() + "]"));
    }
  }
}
