/** Native Console actions for saved Dart facts and explicit-length characters. */
package ghidart.listing;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidart.analysis.DartValueAnalyzer;
import ghidart.datatype.DartLatin1DataType;
import ghidart.datatype.DartUtf16DataType;
import ghidart.importer.B4aImporter;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.util.Msg;
import java.util.LinkedHashSet;

@PluginInfo(status = PluginStatus.STABLE, packageName = CorePluginPackage.NAME, category = "Analysis",
    shortDescription = "Dart fact views", description = "Show saved b4a records, value uses and full character payloads in the Console.")
public final class DartViewsPlugin extends ProgramPlugin {
  public DartViewsPlugin(PluginTool tool) {
    super(tool);
    action("Show b4a Records", this::showRecords);
    action("Show Value Uses", this::showUses);
    action("Show Characters", this::showCharacters);
  }

  private void action(String name, Runnable show) {
    var action = new DockingAction(name, getName()) {
      @Override
      public boolean isEnabledForContext(ActionContext context) {
        return currentProgram != null && currentLocation != null;
      }

      @Override
      public void actionPerformed(ActionContext context) {
        show.run();
      }
    };
    action.setMenuBarData(new MenuData(new String[] {"Dart", name}));
    action.setPopupMenuData(new MenuData(new String[] {"Dart", name}));
    action.markHelpUnnecessary();
    tool.addAction(action);
  }

  private void print(String text) {
    var console = tool.getService(ConsoleService.class);
    if (console != null) console.println(text);
    else Msg.info(this, text);
  }

  private LinkedHashSet<Address> locations() {
    var addresses = new LinkedHashSet<Address>();
    Address selected = currentLocation.getAddress();
    addresses.add(selected);
    var function = currentProgram.getFunctionManager().getFunctionContaining(selected);
    if (function != null) addresses.add(function.getEntryPoint());
    for (Address address : new LinkedHashSet<>(addresses)) {
      for (var reference : currentProgram.getReferenceManager().getReferencesFrom(address)) {
        if (reference.isMemoryReference()) addresses.add(reference.getToAddress());
      }
    }
    return addresses;
  }

  private void showRecords() {
    var facts = currentProgram.getUsrPropertyManager().getStringPropertyMap(B4aImporter.FACTS);
    boolean found = false;
    if (facts != null) {
      var json = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
      for (Address address : locations()) {
        String record = facts.getString(address);
        if (record == null) continue;
        print(address + "\n" + json.toJson(JsonParser.parseString(record)));
        found = true;
      }
    }
    if (!found) print("No b4a record here. Run Dart b4a Import, or select a B4a metadata record/reference.");
  }

  private void showUses() {
    var function = currentProgram.getFunctionManager().getFunctionContaining(currentLocation.getAddress());
    if (function == null) {
      print("Place the cursor inside a Dart function.");
      return;
    }
    var uses = DartValueAnalyzer.uses(currentProgram, function);
    var objects = DartValueAnalyzer.objectUses(currentProgram, function);
    if (uses.isEmpty() && objects.isEmpty()) print("No saved uses. Run Dart Value Uses on this function.");
    for (var use : uses) {
      String value = use.origin() == null ? "0x" + Long.toUnsignedString(use.value(), 16)
          : use.origin() + (use.value() < 0 ? " - 0x" : " + 0x")
              + Long.toUnsignedString(use.value() < 0 ? -use.value() : use.value(), 16);
      print(use.site() + "  " + use.kind() + "[" + use.input() + "]  " + use.width() + " bytes  " + value);
    }
    for (var use : objects) {
      var address = currentProgram.getAddressFactory().getAddress(use.declaration());
      var symbol = address == null ? null : currentProgram.getSymbolTable().getPrimarySymbol(address);
      print(use.site() + "  " + use.kind() + "  " + (symbol == null ? use.declaration() : symbol.getName(true))
          + (use.value().isEmpty() ? "" : " [physical input " + use.value() + "]"));
    }
  }

  private void showCharacters() {
    var payloads = new LinkedHashSet<Data>();
    for (Address address : locations()) {
      Data data = currentProgram.getListing().getDataContaining(address);
      if (data != null && (data.getDataType() instanceof DartLatin1DataType
          || data.getDataType() instanceof DartUtf16DataType)) payloads.add(data);
    }
    if (payloads.isEmpty()) print("No explicitly typed Dart character payload here or at its references.");
    for (var data : payloads) {
      if (!(data.getValue() instanceof String text)) continue;
      print(data.getAddress() + "  " + data.getDataType().getName() + "  " + data.getLength()
          + " bytes, " + text.length() + " code units");
      for (int start = 0; start < text.length(); start += 64) {
        var line = new StringBuilder();
        for (int i = start; i < Math.min(start + 64, text.length()); i++) {
          char unit = text.charAt(i);
          if (unit == '\\' || unit == '"') line.append('\\').append(unit);
          else if (unit >= 0x20 && unit <= 0x7e) line.append(unit);
          else line.append(String.format("\\u%04x", (int) unit));
        }
        print("  [" + start + "] \"" + line + "\"");
      }
    }
  }
}
