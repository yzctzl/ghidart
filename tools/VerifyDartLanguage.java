// Verify the processor foundation without relying on Dart ABI or b4a metadata.
// @category Dart

import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;

public class VerifyDartLanguage extends GhidraScript {
  @Override
  public void run() throws Exception {
    if (!"AARCH64:LE:64:dart".equals(currentProgram.getLanguageID().toString())) {
      throw new IllegalStateException("Dart ARM64 language was not loaded");
    }
    for (String name : new String[] {"x15", "sp", "x30", "x26", "x27"}) {
      var register = currentProgram.getRegister(name);
      if (register == null || !name.equals(register.getName())) {
        throw new IllegalStateException("Missing or renamed physical register: " + name);
      }
    }
    for (String[] pair : new String[][] {
        {"x15", "DART_SP"}, {"x30", "DART_LR"}, {"x26", "DART_THR"}, {"x27", "DART_PP"}}) {
      if (!currentProgram.getRegister(pair[0]).equals(currentProgram.getRegister(pair[1]))) {
        throw new IllegalStateException("Invalid register alias: " + pair[1]);
      }
    }
    println("DART LANGUAGE PASSED: official decoder loaded; physical registers and aliases intact");
  }
}
