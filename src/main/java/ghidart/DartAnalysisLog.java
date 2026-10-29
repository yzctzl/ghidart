/** Route ghidart analysis messages to the active tool's console. */
package ghidart;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/** Keep Ghidra's shared analysis log for other analyzers and headless callers. */
final class DartAnalysisLog implements AutoCloseable {
  private final MessageLog messages;
  private final ConsoleService console;
  private final boolean redirected;

  DartAnalysisLog(Program program, MessageLog original) {
    var manager = AutoAnalysisManager.hasAutoAnalysisManager(program)
        ? AutoAnalysisManager.getAnalysisManager(program) : null;
    var tool = manager == null ? null : manager.getAnalysisTool();
    redirected = tool != null;
    console = tool == null ? null : tool.getService(ConsoleService.class);
    messages = redirected ? new MessageLog() : original;
  }

  MessageLog messages() {
    return messages;
  }

  @Override
  public void close() {
    if (!redirected || !messages.hasMessages()) return;
    if (console != null) {
      console.print(messages.toString());
    } else {
      Msg.info(DartAnalysisLog.class, messages.toString());
    }
  }
}
