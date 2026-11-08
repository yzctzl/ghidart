/** Interpreter semantics for decoder markers; decompiler substitutions remain separate. */
package ghidart.analysis;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.exec.PcodeUseropLibraryFactory;
import ghidra.pcode.exec.SleighPcodeUseropDefinition;

/** A discoverable SDK extension point keeps the physical LOAD exact in emulation. */
@PcodeUseropLibraryFactory.UseropLibrary(id = "ghidart.pool")
public final class DartPcodeUseropLibraryFactory implements PcodeUseropLibraryFactory {
  @Override
  public <T> PcodeUseropLibrary<T> create(SleighLanguage language, PcodeArithmetic<T> arithmetic) {
    return new PoolUserops<>();
  }

  public static final class PoolUserops<T> extends AnnotatedPcodeUseropLibrary<T> {
    @PcodeUserop
    public SleighPcodeUseropDefinition dart_pool_value(SleighPcodeUseropDefinition.BuilderStage1 builder) {
      return builder.params("loaded").body(args -> "__op_output = loaded;").build();
    }
  }
}
