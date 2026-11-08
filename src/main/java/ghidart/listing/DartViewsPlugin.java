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
  private final DartObjectProvider objects;
  public DartViewsPlugin(PluginTool tool) {
    super(tool);
    objects = new DartObjectProvider(tool, getName());
    action("Show Analysis Status", false, this::showStatus);
    action("Browse Dart Records", () -> objects.show(currentProgram, currentLocation.getAddress()));
    action("Show Dart Records", this::showRecords);
    action("Show Value Uses", this::showUses);
    action("Explain Pool Value", this::explainPool);
    action("Show Characters", this::showCharacters);
  }

  @Override
  protected void programActivated(ghidra.program.model.listing.Program program) {
    if (!"AARCH64:LE:64:dart".equals(program.getLanguageID().toString())) return;
    var viewer = tool.getService(ghidra.app.services.CodeViewerService.class);
    if (viewer == null) return;
    var model = viewer.getFormatManager().getCodeUnitFormat();
    for (int row = 0; row < model.getNumRows(); row++) {
      for (var field : model.getFactorys(row)) {
        if (field instanceof B4aAnnotationFieldFactory) return;
      }
    }
    int row = model.getNumRows();
    model.addRow(row);
    model.addFactory(new B4aAnnotationFieldFactory(), row, 0);
    model.getFactorys(row)[0].setWidth(900);
  }

  @Override
  protected void programClosed(ghidra.program.model.listing.Program program) {
    objects.clear(program);
  }

  @Override
  protected void dispose() {
    objects.clear();
    objects.removeFromTool();
    super.dispose();
  }

  private void action(String name, Runnable show) {
    action(name, true, show);
  }

  private void action(String name, boolean needsLocation, Runnable show) {
    var action = new DockingAction(name, getName()) {
      @Override
      public boolean isEnabledForContext(ActionContext context) {
        return currentProgram != null
            && "AARCH64:LE:64:dart".equals(currentProgram.getLanguageID().toString())
            && (!needsLocation || currentLocation != null);
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

  /** Report persisted evidence, not an inferred percentage of analysis completion. */
  private void showStatus() {
    for (String line : analysisStatus(currentProgram,
        currentLocation == null ? null : currentLocation.getAddress())) print(line);
  }

  static java.util.List<String> analysisStatus(ghidra.program.model.listing.Program program, Address location) {
    var lines = new java.util.ArrayList<String>();
    var properties = program.getUsrPropertyManager();
    lines.add("Dart analysis — " + program.getDomainFile().getPathname());
    lines.add("Language: " + program.getLanguageID() + " " + program.getLanguage().getVersion()
        + "." + program.getLanguage().getMinorVersion() + "; compiler: " + program.getCompilerSpec().getCompilerSpecID());
    for (String[] entry : new String[][] {
        {"L1 boundary records", "ghidart.L1.functions"},
        {"L2 object/slot records", "ghidart.L2.objects.v1"},
        {"b4a retained records", B4aImporter.FACTS},
        {"Value-use function records", "ghidart.machineValueUses.v1"}}) {
      var map = properties.getStringPropertyMap(entry[1]);
      lines.add(entry[0] + ": " + (map == null ? "not present" : map.getSize()));
    }
    String status = program.getOptions("ghidart.L2").getString("L2.status", "not run");
    lines.add("Latest L2 attempt: " + status + ". Existing records may predate this attempt.");
    var function = location == null ? null
        : program.getFunctionManager().getFunctionContaining(location);
    if (function != null) {
      lines.add("Current function: " + function.getName(true) + " @ " + function.getEntryPoint());
      String scope = DartNamespaces.scopeDescription(function);
      if (!scope.isEmpty()) lines.add(scope);
      lines.add("Physical prototype (" + function.getSignatureSource() + "): " + function.getPrototypeString(false, false));
      var uses = properties.getStringPropertyMap("ghidart.machineValueUses.v1");
      lines.add("Saved value analysis here: " + (uses != null && uses.hasProperty(function.getEntryPoint()) ? "present" : "not present"));
      if (function.getTags().stream().anyMatch(tag -> tag.getName().equals("Dart: incomplete CFG"))) {
        lines.add("Incomplete CFG: resolve the unknown flow before relying on inferred parameters.");
      }
    }
    if (properties.getStringPropertyMap("ghidart.L2.objects.v1") == null) {
      lines.add("Next: Analysis > One Shot > Dart AOT Objects for supported snapshots. "
          + "Import matching b4a data first if available; L1 remains independent.");
    }
    lines.add("For pseudocode: select functions and run Dart Value Uses (ABI recovery is on by default). "
        + "This does not run automatically on open.");
    lines.add("Browse: Namespaces for declarations; Library > PP / THR for instruction uses; "
        + "Defined Strings for characters; Dart > Browse Dart Records for relationships.");
    return java.util.List.copyOf(lines);
  }

  private LinkedHashSet<Address> locations() {
    var addresses = new LinkedHashSet<Address>();
    Address selected = currentLocation.getAddress();
    addresses.add(selected);
    var function = currentProgram.getFunctionManager().getFunctionContaining(selected);
    if (function != null) addresses.add(function.getEntryPoint());
    for (Address address : new LinkedHashSet<>(addresses)) {
      for (var edge : ghidart.snapshot.DartObjectGraph.from(currentProgram, address)) addresses.add(edge.getToAddress());
      for (var edge : ghidart.snapshot.DartObjectGraph.to(currentProgram, address)) addresses.add(edge.getFromAddress());
      for (var reference : currentProgram.getReferenceManager().getReferencesFrom(address)) {
        if (reference.isMemoryReference()) addresses.add(reference.getToAddress());
      }
    }
    return addresses;
  }

  private void showRecords() {
    boolean found = false;
    var notes = currentProgram.getUsrPropertyManager().getStringPropertyMap(B4aImporter.ANNOTATIONS);
    String note = notes == null ? null : notes.getString(currentLocation.getAddress());
    if (note != null) { print(note); found = true; }
    var json = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    var addresses = locations();
    for (String source : new String[] {"ghidart.L2.objects.v1", B4aImporter.FACTS}) {
      var facts = currentProgram.getUsrPropertyManager().getStringPropertyMap(source);
      if (facts == null) continue;
      for (Address address : addresses) {
        String record = facts.getString(address);
        if (record == null) continue;
        print(ghidart.snapshot.DartObjectGraph.describe(currentProgram, address) + " [" + source + "]\n" + json.toJson(JsonParser.parseString(record)));
        found = true;
      }
    }
    if (!found) print("No Dart record here. Select code, an object or a pool slot after L2/L3 analysis.");
  }

  private void explainPool() {
    Address site = currentLocation.getAddress();
    var evidence = ghidart.analysis.DartConstantPool.evidence(currentProgram, site);
    print("Dart pool evidence at " + site + ": " + evidence.explanation());
    if (evidence.slot() != null) {
      print("Slot: " + ghidart.snapshot.DartObjectGraph.describe(currentProgram, evidence.slot()));
      print("Use Dart > Browse Dart Records to follow the initial object and character payload.");
    }
    if (evidence.liftable()) {
      print("The load instruction must also support the native pool fixup. "
          + "Slot eligibility alone does not prove this value survives later code.");
    }
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
      String description = address == null ? use.declaration()
          : ghidart.snapshot.DartObjectGraph.describe(currentProgram, address);
      print(use.site() + "  " + use.kind() + "  " + description
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
