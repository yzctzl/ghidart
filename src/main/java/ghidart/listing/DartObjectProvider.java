package ghidart.listing;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidart.importer.B4aImporter;
import ghidart.snapshot.DartObjectGraph;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayDeque;
import java.util.ArrayList;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.table.DefaultTableModel;

/** Browse database relationships without adding fake references to the Listing.
 *
 * Only the selected node and its immediate neighbours are loaded. Logical nodes
 * open here; file-backed nodes also navigate through Ghidra's ordinary Go To.
 * This is a view of the persistent graph, not another source of object facts.
 */
final class DartObjectProvider extends ComponentProviderAdapter {
  private final JPanel panel = new JPanel(new BorderLayout());
  private final JTextArea details = new JTextArea();
  private final DefaultTableModel model = new DefaultTableModel(new String[] {"Relation", "Object / location"}, 0) {
    @Override public boolean isCellEditable(int row, int column) { return false; }
  };
  private final JTable table = new JTable(model);
  private final ArrayList<Address> targets = new ArrayList<>();
  private final ArrayDeque<Address> history = new ArrayDeque<>();
  private Program program;
  private Address selected;

  DartObjectProvider(PluginTool tool, String owner) {
    super(tool, "Dart Records", owner);
    details.setEditable(false);
    table.setAutoCreateRowSorter(true);
    panel.add(new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(details), new JScrollPane(table)), BorderLayout.CENTER);
    var back = new JButton("Back");
    back.addActionListener(event -> {
      if (!history.isEmpty()) display(program, history.pop(), false);
    });
    panel.add(back, BorderLayout.NORTH);
    table.addMouseListener(new MouseAdapter() {
      @Override public void mouseClicked(MouseEvent event) {
        if (event.getClickCount() != 2 || table.getSelectedRow() < 0) return;
        Address target = targets.get(table.convertRowIndexToModel(table.getSelectedRow()));
        display(program, target, true);
        if (!DartObjectGraph.isIdentity(program, target)) {
          var go = tool.getService(GoToService.class);
          if (go != null) go.goTo(target);
        }
      }
    });
    addToTool();
  }

  @Override public JComponent getComponent() { return panel; }

  void show(Program program, Address address) {
    display(program, address, true);
    setVisible(true);
  }

  void clear() {
    program = null;
    selected = null;
    history.clear();
    targets.clear();
    model.setRowCount(0);
    details.setText("");
  }

  private void display(Program nextProgram, Address address, boolean remember) {
    if (nextProgram == null) return;
    if (program != nextProgram) clear();
    if (remember && selected != null && !selected.equals(address)) history.push(selected);
    program = nextProgram;
    selected = address;
    setSubTitle(DartObjectGraph.describe(program, address));
    targets.clear();
    model.setRowCount(0);
    var text = new StringBuilder(DartObjectGraph.describe(program, address)).append('\n');
    var json = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    for (String source : new String[] {"ghidart.L2.objects.v1", B4aImporter.FACTS}) {
      var facts = program.getUsrPropertyManager().getStringPropertyMap(source);
      String record = facts == null ? null : facts.getString(address);
      if (record != null) text.append('\n').append(source).append('\n').append(json.toJson(JsonParser.parseString(record))).append('\n');
    }
    details.setText(text.toString());
    details.setCaretPosition(0);
    var function = program.getFunctionManager().getFunctionContaining(address);
    if (function != null && !function.getEntryPoint().equals(address)) add("containing function", function.getEntryPoint());
    for (var edge : DartObjectGraph.from(program, address)) add(DartObjectGraph.relation(program, edge) + " →", edge.getToAddress());
    for (var edge : DartObjectGraph.to(program, address)) add(DartObjectGraph.relation(program, edge) + " ←", edge.getFromAddress());
    for (var ref : program.getReferenceManager().getReferencesFrom(address)) add("XREF → " + ref.getReferenceType(), ref.getToAddress());
    for (var ref : program.getReferenceManager().getReferencesTo(address)) add("XREF ← " + ref.getReferenceType(), ref.getFromAddress());
  }

  private void add(String relation, Address target) {
    targets.add(target);
    model.addRow(new Object[] {relation, DartObjectGraph.describe(program, target)});
  }
}
