/** Prefer matching b4a data, enriched by L2 objects and independent L1 ABI analysis. */
package ghidart.importer;

import ghidart.analysis.DartAnalysisLog;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.nio.file.Files;

/** Use a matching sidecar by default; One Shot and saved analyzer choices remain available. */
public final class B4aImportAnalyzer extends AbstractAnalyzer {
  private final DartAotAnalyzer source = new DartAotAnalyzer();

  public B4aImportAnalyzer() {
    super("Dart b4a Import", "Import b4a names, layouts, pool/Thread observations and Listing-only annotations.",
        AnalyzerType.BYTE_ANALYZER);
    setPriority(AnalysisPriority.DISASSEMBLY.before().before().before());
    setSupportsOneTimeAnalysis();
    setDefaultEnablement(false);
  }

  @Override
  public boolean getDefaultEnablement(Program program) {
    // Ghidra preserves explicit saved choices; this only selects the initial default.
    return source.findMetadata(program).filter(Files::isRegularFile).isPresent();
  }

  @Override
  public boolean canAnalyze(Program program) {
    return source.canAnalyze(program);
  }

  @Override
  public void registerOptions(Options options, Program program) {
    source.registerOptions(options, program);
  }

  @Override
  public void optionsChanged(Options options, Program program) {
    source.optionsChanged(options, program);
  }

  @Override
  public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
      throws CancelledException {
    try (var output = new DartAnalysisLog(program, log)) {
      var path = source.findMetadata(program);
      if (path.isEmpty()) {
        output.messages().appendMsg(getName(), "No b4a.json found. Set b4a.json path or place it beside the binary.");
        return false;
      }
      try {
        B4aImporter.importFile(program, path.get(), monitor, output.messages());
        return true;
      } catch (CancelledException e) {
        throw e;
      } catch (Exception e) {
        output.messages().appendMsg(getName(), "Import rejected; changes rolled back: " + e.getMessage());
        return false;
      }
    }
  }
}
