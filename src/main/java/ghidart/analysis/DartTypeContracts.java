/** Apply proved object types to native ABI storage, with reversible ownership. */
package ghidart.analysis;

import com.google.gson.Gson;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import java.util.ArrayList;
import java.util.Map;

/** Type enrichment never adds parameters, changes storage or replaces user prototypes. */
final class DartTypeContracts {
  private static final String PROPERTY = "ghidart.objectTypeContracts.v1";
  private static final Gson JSON = new Gson();
  private record Saved(int ordinal, long original, long applied, String storage, SourceType source) {}
  private record State(SourceType signatureSource, Saved[] types) {}

  private DartTypeContracts() {}

  static void restore(Function function) {
    var program = function.getProgram();
    var facts = program.getUsrPropertyManager().getStringPropertyMap(PROPERTY);
    String raw = facts == null ? null : facts.getString(function.getEntryPoint());
    if (raw == null) return;
    var state = JSON.fromJson(raw, State.class);
    if (state == null || state.types() == null || state.signatureSource() == null) {
      throw new IllegalStateException("Invalid object type ownership at " + function.getEntryPoint());
    }
    if (function.getSignatureSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)) {
      var manager = program.getDataTypeManager();
      boolean complete = true;
      for (var saved : state.types()) {
        var parameter = saved.ordinal() < 0 ? function.getReturn() : function.getParameter(saved.ordinal());
        var original = manager.getDataType(saved.original());
        if (parameter == null || original == null
            || parameter.getSource().isHigherPriorityThan(SourceType.ANALYSIS)
            || manager.getID(parameter.getDataType()) != saved.applied()
            || !parameter.getVariableStorage().getSerializationString().equals(saved.storage())) {
          complete = false;
          continue;
        }
        try {
          parameter.setDataType(original, saved.source());
        } catch (InvalidInputException e) {
          throw new IllegalStateException("Cannot restore object type at " + function.getEntryPoint(), e);
        }
      }
      if (complete) function.setSignatureSource(state.signatureSource());
    }
    facts.remove(function.getEntryPoint());
  }

  static int apply(Function function, HighFunction high, Map<Varnode, DataType> types) {
    if (function.getSignatureSource().isHigherPriorityThan(SourceType.ANALYSIS)) return 0;
    var saved = new ArrayList<Saved>();
    SourceType source = function.getSignatureSource();
    for (var entry : types.entrySet()) {
      if (!(entry.getKey().getHigh() instanceof HighParam parameter)) continue;
      int ordinal = parameter.getSymbol().getCategoryIndex();
      var nativeParameter = function.getParameter(ordinal);
      if (nativeParameter != null && saved.stream().noneMatch(s -> s.ordinal() == ordinal)) {
        apply(function, nativeParameter, ordinal, entry.getValue(), saved);
      }
    }
    // Every reachable native RETURN must carry the same proved Class. A
    // declaration's logical return type alone does not establish physical ABI.
    DataType result = null;
    boolean agreed = true;
    int returns = 0;
    for (var it = high.getPcodeOps(); it.hasNext();) {
      var op = it.next();
      if (op.getOpcode() != PcodeOp.RETURN) continue;
      returns++;
      DataType candidate = op.getNumInputs() == 2 ? types.get(op.getInput(1)) : null;
      if (candidate == null || result != null && !result.isEquivalent(candidate)) {
        agreed = false;
        break;
      }
      result = candidate;
    }
    if (agreed && returns != 0 && result != null) apply(function, function.getReturn(), -1, result, saved);
    if (!saved.isEmpty()) {
      var program = function.getProgram();
      var facts = program.getUsrPropertyManager().getStringPropertyMap(PROPERTY);
      try {
        if (facts == null) facts = program.getUsrPropertyManager().createStringPropertyMap(PROPERTY);
      } catch (ghidra.util.exception.DuplicateNameException e) {
        throw new IllegalStateException(e);
      }
      facts.add(function.getEntryPoint(), JSON.toJson(new State(source, saved.toArray(Saved[]::new))));
    }
    return saved.size();
  }

  private static void apply(Function function, Parameter parameter, int ordinal, DataType type,
      ArrayList<Saved> saved) {
    var storage = parameter.getVariableStorage();
    if (parameter.getSource().isHigherPriorityThan(SourceType.ANALYSIS)
        || storage.isUnassignedStorage() || storage.size() != type.getLength()
        || parameter.getDataType().isEquivalent(type)) return;
    var manager = function.getProgram().getDataTypeManager();
    var old = parameter.getDataType();
    SourceType source = parameter.getSource();
    try {
      parameter.setDataType(type, SourceType.ANALYSIS);
      if (!parameter.getVariableStorage().equals(storage)) {
        parameter.setDataType(old, source);
        throw new IllegalStateException("Object type changed ABI storage at " + function.getEntryPoint());
      }
      saved.add(new Saved(ordinal, manager.getID(old), manager.getID(parameter.getDataType()),
          storage.getSerializationString(), source));
    } catch (InvalidInputException e) {
      throw new IllegalStateException("Cannot apply object type at " + function.getEntryPoint(), e);
    }
  }
}
