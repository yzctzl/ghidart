/** Show pool/Thread values and imported IL beside their actual instruction uses. */
package ghidart.listing;

import docking.widgets.fieldpanel.field.AttributedString;
import docking.widgets.fieldpanel.field.FieldElement;
import docking.widgets.fieldpanel.field.TextFieldElement;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidart.importer.B4aImporter;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.ListingColors;
import ghidra.app.util.viewer.field.ListingField;
import ghidra.app.util.viewer.field.ListingTextField;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.util.ProgramLocation;
import java.math.BigInteger;
import java.util.ArrayList;

public final class B4aAnnotationFieldFactory extends FieldFactory {
  public B4aAnnotationFieldFactory() {
    super("Dart Analysis");
  }

  private B4aAnnotationFieldFactory(FieldFormatModel model, ListingHighlightProvider highlights,
      ToolOptions display, ToolOptions fields) {
    super("Dart Analysis", model, highlights, display, fields);
  }

  @Override
  public ListingField getField(ProxyObj<?> proxy, int varWidth) {
    if (!enabled || !(proxy.getObject() instanceof CodeUnit unit)) return null;
    var map = unit.getProgram().getUsrPropertyManager().getStringPropertyMap(B4aImporter.ANNOTATIONS);
    String text = map == null ? null : map.getString(unit.getMinAddress());
    var descriptions = new java.util.LinkedHashSet<String>();
    if (unit instanceof ghidra.program.model.listing.Instruction) {
      descriptions.addAll(DartSlotViews.at(unit.getProgram(), unit.getMinAddress()));
    }
    if (text != null) descriptions.addAll(java.util.Arrays.asList(text.split("\n")));
    if (descriptions.isEmpty()) return null;
    text = String.join("\n", descriptions);
    var lines = new ArrayList<FieldElement>();
    String[] parts = text.split("\n", 9);
    for (int i = 0; i < parts.length; i++) {
      String line = i == 8 ? "… Dart → Show Dart Records for full details" : parts[i];
      var attributed = new AttributedString(line, ListingColors.CommentColors.EOL, getMetrics());
      lines.add(new TextFieldElement(attributed, i, 0));
    }
    return ListingTextField.createMultilineTextField(this, proxy, lines, startX + varWidth, width, hlProvider);
  }

  @Override
  public ProgramLocation getProgramLocation(int row, int col, ListingField field) {
    if (!(field.getProxy().getObject() instanceof CodeUnit unit)) return null;
    return new AnnotationLocation(unit.getProgram(), unit.getMinAddress(), row, col);
  }

  @Override
  public FieldLocation getFieldLocation(ListingField field, BigInteger index, int fieldNum,
      ProgramLocation location) {
    if (!(location instanceof AnnotationLocation)) return null;
    return new FieldLocation(index, fieldNum, location.getRow(), location.getCharOffset());
  }

  /** A distinct location keeps ordinary address/operand navigation on its own field. */
  public static final class AnnotationLocation extends ProgramLocation {
    public AnnotationLocation() {}

    private AnnotationLocation(ghidra.program.model.listing.Program program,
        ghidra.program.model.address.Address address, int row, int column) {
      super(program, address, row, 0, column);
    }
  }

  @Override
  public boolean acceptsType(int category, Class<?> type) {
    return category == FieldFormatModel.INSTRUCTION_OR_DATA && CodeUnit.class.isAssignableFrom(type);
  }

  @Override
  public FieldFactory newInstance(FieldFormatModel model, ListingHighlightProvider highlights,
      ToolOptions display, ToolOptions fields) {
    return new B4aAnnotationFieldFactory(model, highlights, display, fields);
  }
}
