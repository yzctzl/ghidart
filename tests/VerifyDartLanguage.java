// Verify the processor foundation without relying on Dart ABI or b4a metadata.
// @category Dart

import ghidra.app.script.GhidraScript;

public class VerifyDartLanguage extends GhidraScript {
  @Override
  public void run() throws Exception {
    if (!"AARCH64:LE:64:dart".equals(currentProgram.getLanguageID().toString())) {
      throw new IllegalStateException("Dart ARM64 language was not loaded");
    }
    for (String name : new String[] {"x15", "sp", "x30", "x26", "x27"}) {
      var register = currentProgram.getRegister(name);
      if (register == null) {
        throw new IllegalStateException("Missing physical register alias: " + name);
      }
    }
    for (String[] pair : new String[][] {
        {"x4", "ARGS"}, {"x15", "VMSP"}, {"x16", "TMP"}, {"x17", "TMP2"},
        {"x21", "GDT"}, {"x22", "NULL"}, {"x24", "CODE"}, {"x26", "THR"},
        {"x27", "PP"}, {"x28", "HBS"}, {"x29", "FP"}, {"x30", "LR"}}) {
      var physical = currentProgram.getRegister(pair[0]);
      if (physical == null || !pair[1].equals(physical.getName())
          || !physical.equals(currentProgram.getRegister(pair[1]))) {
        throw new IllegalStateException("Invalid register alias: " + pair[1]);
      }
    }
    println("DART LANGUAGE PASSED: ARM64 decoder loaded; Dart names and physical aliases intact");
  }
}
