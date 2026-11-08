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
import docking.WindowPosition;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayDeque;
import java.util.ArrayList;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.TableRowSorter;
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
  private final JCheckBox raw = new JCheckBox("Raw records");
  private final JTextField filter = new JTextField(20);
  private final JLabel count = new JLabel();
  private final JButton back = new JButton("Back");
  private final JButton previous = new JButton("Previous");
  private final JButton next = new JButton("Next");
  private final JButton classLayout = new JButton("Class Layout");
  private ghidra.program.model.data.DataType selectedLayout;
  private static final int PAGE_SIZE = 200;
  private record Relation(String label, Address target, DartObjectGraph.Link edge) {}
  private final ArrayList<Relation> relations = new ArrayList<>();
  private int page;
  private final DefaultTableModel model = new DefaultTableModel(new String[] {"Relation", "Object / location"}, 0) {
    @Override public boolean isCellEditable(int row, int column) { return false; }
  };
  private final JTable table = new JTable(model) {
    @Override public String getToolTipText(MouseEvent event) {
      int row = rowAtPoint(event.getPoint()), column = columnAtPoint(event.getPoint());
      return row < 0 || column < 0 ? null : String.valueOf(getValueAt(row, column));
    }
  };
  private final ArrayList<Address> targets = new ArrayList<>();
  private final ArrayDeque<Address> history = new ArrayDeque<>();
  private Program program;
  private Address selected;

  DartObjectProvider(PluginTool tool, String owner) {
    super(tool, "Dart Records", owner);
    setDefaultWindowPosition(WindowPosition.RIGHT);
    panel.setPreferredSize(new Dimension(720, 560));
    details.setEditable(false);
    details.setLineWrap(true);
    details.setWrapStyleWord(true);
    table.setAutoCreateRowSorter(true);
    table.getColumnModel().getColumn(0).setPreferredWidth(180);
    table.getColumnModel().getColumn(1).setPreferredWidth(700);
    var split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(details), new JScrollPane(table));
    split.setResizeWeight(0.35);
    split.setDividerLocation(180);
    panel.add(split, BorderLayout.CENTER);
    back.setEnabled(false);
    back.addActionListener(event -> {
      if (!history.isEmpty()) display(program, history.pop(), false);
    });
    raw.addActionListener(event -> { if (selected != null) showDetails(); });
    var controls = new JPanel(new BorderLayout(8, 0));
    var navigation = new JPanel();
    navigation.add(back);
    navigation.add(raw);
    navigation.add(previous);
    navigation.add(next);
    previous.addActionListener(event -> { page--; renderPage(); });
    next.addActionListener(event -> { page++; renderPage(); });
    previous.setEnabled(false);
    next.setEnabled(false);
    controls.add(navigation, BorderLayout.WEST);
    var search = new JPanel(new BorderLayout(6, 0));
    search.add(new JLabel("Filter page"), BorderLayout.WEST);
    search.add(filter, BorderLayout.CENTER);
    controls.add(search, BorderLayout.CENTER);
    filter.setToolTipText("Filter relationships and object/location names on this page");
    panel.add(controls, BorderLayout.NORTH);
    var footer = new JPanel(new BorderLayout(8, 0));
    footer.add(count, BorderLayout.CENTER);
    footer.add(classLayout, BorderLayout.EAST);
    classLayout.setEnabled(false);
    classLayout.setToolTipText("Select this Class's decoded structure in Ghidra Data Types");
    classLayout.addActionListener(event -> {
      var service = tool.getService(ghidra.app.services.DataTypeManagerService.class);
      if (service != null && selectedLayout != null) service.setDataTypeSelected(selectedLayout);
    });
    panel.add(footer, BorderLayout.SOUTH);
    filter.getDocument().addDocumentListener(new DocumentListener() {
      public void insertUpdate(DocumentEvent event) { filterRows(); }
      public void removeUpdate(DocumentEvent event) { filterRows(); }
      public void changedUpdate(DocumentEvent event) { filterRows(); }
    });
    table.addMouseListener(new MouseAdapter() {
      @Override public void mouseClicked(MouseEvent event) {
        if (event.getClickCount() != 2 || table.getSelectedRow() < 0) return;
        Address target = targets.get(table.convertRowIndexToModel(table.getSelectedRow()));
        display(program, target, true);
        if (!DartObjectGraph.isIdentity(program, target)) {
          var go = tool.getService(GoToService.class);
          if (go != null) go.goTo(target, program);
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

  void clear(Program closed) {
    if (program == closed) clear();
  }

  void clear() {
    program = null;
    selected = null;
    selectedLayout = null;
    classLayout.setEnabled(false);
    history.clear();
    targets.clear();
    relations.clear();
    model.setRowCount(0);
    details.setText("");
    previous.setEnabled(false);
    next.setEnabled(false);
    back.setEnabled(false);
    count.setText("");
    setSubTitle("");
  }

  private void display(Program nextProgram, Address address, boolean remember) {
    if (nextProgram == null) return;
    if (program != nextProgram) clear();
    if (remember && selected != null && !selected.equals(address)) {
      if (history.size() == 100) history.removeLast();
      history.push(selected);
    }
    program = nextProgram;
    selected = address;
    setSubTitle(program.getDomainFile().getPathname() + " — " + DartObjectGraph.describe(program, address));
    back.setEnabled(!history.isEmpty());
    relations.clear();
    page = 0;
    filter.setText("");
    showDetails();
    var function = program.getFunctionManager().getFunctionContaining(address);
    if (function != null && !function.getEntryPoint().equals(address)) add("containing function", function.getEntryPoint());
    for (var edge : DartObjectGraph.from(program, address)) relations.add(new Relation(" →", edge.getToAddress(), edge));
    for (var edge : DartObjectGraph.to(program, address)) relations.add(new Relation(" ←", edge.getFromAddress(), edge));
    for (var ref : program.getReferenceManager().getReferencesFrom(address)) add("XREF → " + ref.getReferenceType(), ref.getToAddress());
    for (var ref : program.getReferenceManager().getReferencesTo(address)) add("XREF ← " + ref.getReferenceType(), ref.getFromAddress());
    renderPage();
  }

  @SuppressWarnings("unchecked")
  private void filterRows() {
    var sorter = (TableRowSorter<DefaultTableModel>) table.getRowSorter();
    sorter.setRowFilter(filter.getText().isBlank() ? null
        : RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(filter.getText())));
    count.setText(table.getRowCount() + " shown on page " + (page + 1) + " / "
        + Math.max(1, (relations.size() + PAGE_SIZE - 1) / PAGE_SIZE)
        + "; " + relations.size() + " total relationships. Double-click to follow.");
  }

  /** Start with the selected value and its meaning; raw serialization remains optional. */
  private void showDetails() {
    selectedLayout = null;
    var text = new StringBuilder(DartObjectGraph.describe(program, selected)).append('\n');
    String scope = DartNamespaces.scopeDescription(program.getFunctionManager().getFunctionContaining(selected));
    if (!scope.isEmpty()) text.append(scope).append('\n');
    var data = program.getListing().getDefinedDataAt(selected);
    appendCharacters(text, data);
    String slot = DartSlotViews.summary(program, selected);
    if (!slot.isEmpty()) text.append(slot).append('\n');
    var json = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    for (String source : new String[] {"ghidart.L2.objects.v1", B4aImporter.FACTS}) {
      var facts = program.getUsrPropertyManager().getStringPropertyMap(source);
      String record = facts == null ? null : facts.getString(selected);
      if (record == null) continue;
      var node = JsonParser.parseString(record).getAsJsonObject();
      var layout = node.has("layout") && node.get("layout").isJsonObject()
          ? node.getAsJsonObject("layout") : null;
      if (layout != null && layout.has("typePath")) {
        var type = program.getDataTypeManager().getDataType(layout.get("typePath").getAsString());
        if (type instanceof ghidra.program.model.data.Structure) selectedLayout = type;
      }
      if (data == null && node.has("kind") && node.get("kind").getAsString().equals("String")) {
        int length = node.get("length").getAsInt();
        if (length == 0) text.append("Characters: \"\"; empty Dart String\n");
        else {
          Address payload = program.getAddressFactory().getAddress(node.get("payload").getAsString());
          var characters = payload == null ? null : program.getListing().getDefinedDataAt(payload);
          long expected = (long) length * (node.get("encoding").getAsString().equals("utf16le") ? 2 : 1);
          if (characters != null && characters.getLength() == expected) appendCharacters(text, characters);
        }
      }
      text.append('\n').append(source.equals(B4aImporter.FACTS) ? "b4a export" : "Decoded AOT").append('\n');
      if (raw.isSelected()) text.append(json.toJson(node)).append('\n');
      else {
        appendSummary(text, node, "");
      }
    }
    if (text.toString().indexOf("\n") == text.length() - 1) {
      text.append("Follow a relationship below for its decoded object or declaration.\n");
    }
    classLayout.setEnabled(selectedLayout != null
        && tool.getService(ghidra.app.services.DataTypeManagerService.class) != null);
    details.setText(text.toString());
    details.setCaretPosition(0);
  }

  private static void appendCharacters(StringBuilder text, ghidra.program.model.listing.Data data) {
    if (data == null || !data.hasStringValue() || !(data.getValue() instanceof String value)) return;
    int end = value.offsetByCodePoints(0, Math.min(1024, value.codePointCount(0, value.length())));
    text.append("Characters: ").append(new com.google.gson.Gson().toJson(value.substring(0, end)))
        .append(end < value.length() ? "… (Dart > Show Characters prints the full payload)" : "").append('\n');
    text.append(data.getDataType().getName()).append("; ").append(data.getLength())
        .append(" bytes; ").append(value.length()).append(" UTF-16 code units\n");
  }

  private static void appendSummary(StringBuilder text, com.google.gson.JsonObject node, String section) {
    for (var entry : node.entrySet()) {
      String key = entry.getKey();
      var value = entry.getValue();
      if (value.isJsonPrimitive()) {
        // Relationship names below resolve these identities; do not present
        // internal reference numbers as though they were runtime addresses.
        if (key.endsWith("RefId") || key.equals("refId")) continue;
        String label = (section + key).replaceAll("([a-z0-9])([A-Z])", "$1 $2");
        String shown = value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()
            ? value.getAsString() : value.toString();
        int end = shown.offsetByCodePoints(0, Math.min(240, shown.codePointCount(0, shown.length())));
        text.append(label).append(": ").append(shown, 0, end)
            .append(end < shown.length() ? "… (see Raw records)" : "").append('\n');
      } else if (java.util.Set.of("object", "layout", "declaration", "functionInfo").contains(key)
          && value.isJsonObject()) {
        appendSummary(text, value.getAsJsonObject(), key + " / ");
      }
    }
  }

  private void add(String relation, Address target) {
    relations.add(new Relation(relation, target, null));
  }

  /** Resolve only one page. Shared null/types can have over 100,000 neighbours;
   * resolving every name and growing a sorted Swing model would stall the UI.
   * All edges remain navigable; pagination never discards database relations.
   */
  private void renderPage() {
    targets.clear();
    model.setRowCount(0);
    int end = Math.min((page + 1) * PAGE_SIZE, relations.size());
    for (int i = page * PAGE_SIZE; i < end; i++) {
      var row = relations.get(i);
      Address target = row.target();
      targets.add(target);
      String description = DartObjectGraph.describe(program, target);
      var function = program.getFunctionManager().getFunctionContaining(target);
      if (function != null && !function.getEntryPoint().equals(target)) {
        description = target + " — " + function.getName(true) + " + 0x"
            + Long.toHexString(target.subtract(function.getEntryPoint()));
      }
      String label = row.edge() == null ? row.label()
          : DartObjectGraph.relation(program, row.edge()) + row.label();
      model.addRow(new Object[] {label, description});
    }
    previous.setEnabled(page > 0);
    next.setEnabled(end < relations.size());
    filterRows();
  }
}
