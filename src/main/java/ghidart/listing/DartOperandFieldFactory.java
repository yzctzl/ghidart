/** Preserve existing Ghidra layouts that used the former Dart operand field. */
package ghidart.listing;

import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.OperandFieldFactory;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.framework.options.ToolOptions;
import ghidra.util.classfinder.ClassTranslator;

/** Standard operands under the old field name, for saved layout compatibility. */
public final class DartOperandFieldFactory extends OperandFieldFactory {
  static {
    ClassTranslator.put("ghidart.DartOperandFieldFactory", DartOperandFieldFactory.class.getName());
  }

  public DartOperandFieldFactory() {
    super();
  }

  private DartOperandFieldFactory(FieldFormatModel model, ListingHighlightProvider highlights,
      ToolOptions displayOptions, ToolOptions fieldOptions) {
    super(model, highlights, displayOptions, fieldOptions);
  }

  @Override
  public String getFieldName() {
    return "Dart Operands";
  }

  @Override
  public FieldFactory newInstance(FieldFormatModel model, ListingHighlightProvider highlights,
      ToolOptions displayOptions, ToolOptions fieldOptions) {
    return new DartOperandFieldFactory(model, highlights, displayOptions, fieldOptions);
  }
}
