/**
 * Infer optional access shapes with Ghidra's native structure builder.
 *
 * A shape describes observed byte offsets through one recovered parameter, not
 * a Dart class, an object header, or a complete allocation. Mixed integer uses,
 * escapes and unknown addressing reject inference. Parameters must already
 * agree with the recovered physical prototype; this pass never adds arguments.
 * Owned type substitutions are recorded separately and revoked before ABI
 * reanalysis. User/imported prototypes and edited generated layouts are kept.
 */
package ghidart.analysis;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/** Machine-only, reversible type hints; instruction and call semantics stay native. */
final class DartMemoryShapes {
  private static final String PROPERTY = "ghidart.observedMemoryTypes.v1";
  private static final Gson JSON = new Gson();

  private record Saved(int ordinal, long originalType, SourceType source,
      long shapeType, String definition) {}

  private DartMemoryShapes() {}

  /** Restore only unchanged substitutions that this pass made previously. */
  static boolean restore(Program program, Function function, MessageLog log) {
    var notes = program.getUsrPropertyManager().getStringPropertyMap(PROPERTY);
    if (notes == null || notes.getString(function.getEntryPoint()) == null) return true;
    Saved[] saved;
    try {
      saved = JSON.fromJson(notes.getString(function.getEntryPoint()), Saved[].class);
      if (saved == null) throw new JsonParseException("Missing ownership record");
      for (var fact : saved) {
        if (fact == null || fact.ordinal() < 0 || fact.source() == null
            || fact.definition() == null) throw new JsonParseException("Invalid ownership record");
      }
    } catch (JsonParseException e) {
      log.appendMsg("Dart ABI", "Cannot read observed-type ownership at "
          + function.getEntryPoint() + "; automatic ABI recovery for this function was skipped.");
      return false;
    }
    if (function.getSignatureSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)) {
      var types = program.getDataTypeManager();
      // Editing a generated layout is an explicit type decision. Publish its
      // source priority before native parameter recovery, which otherwise may
      // discard an ANALYSIS-level pointer when the option is disabled.
      for (var fact : saved) {
        var parameter = function.getParameter(fact.ordinal());
        if (parameter != null && parameter.getDataType() instanceof Pointer pointer
            && pointer.getDataType() instanceof Structure shape
            && types.getID(shape) == fact.shapeType()
            && !shape.toString().equals(fact.definition())) {
          try {
            parameter.setDataType(parameter.getDataType(), SourceType.USER_DEFINED);
          } catch (InvalidInputException e) {
            throw new IllegalStateException("Cannot preserve an edited observed type", e);
          }
          function.setSignatureSource(SourceType.USER_DEFINED);
          log.appendMsg("Dart ABI", "Edited observed memory type preserved as a user prototype at "
              + function.getEntryPoint() + ".");
          notes.remove(function.getEntryPoint());
          return true;
        }
      }
      for (var fact : saved) {
        var parameter = function.getParameter(fact.ordinal());
        if (parameter == null || !parameter.getSource()
            .isLowerOrEqualPriorityThan(SourceType.ANALYSIS)
            || !(parameter.getDataType() instanceof Pointer pointer)
            || !(pointer.getDataType() instanceof Structure shape)
            || types.getID(shape) != fact.shapeType()
            || !shape.toString().equals(fact.definition())) continue;
        DataType original = types.getDataType(fact.originalType());
        if (original == null || original.getLength() != parameter.getLength()) continue;
        try {
          parameter.setDataType(original, fact.source());
        } catch (InvalidInputException e) {
          throw new IllegalStateException("Cannot revoke an observed parameter type", e);
        }
      }
    }
    // A different type, edited shape or stronger source is now user-owned.
    notes.remove(function.getEntryPoint());
    return true;
  }

  static int recover(Program program, List<Function> functions, TaskMonitor monitor,
      MessageLog log) throws CancelledException {
    var decompiler = new DecompInterface();
    int recovered = 0;
    try {
      if (!decompiler.openProgram(program)) return 0;
      for (var function : functions) {
        monitor.checkCancelled();
        if (function.isExternal() || function.getParameterCount() == 0
            || !function.getSignatureSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)
            || !managed(program, function)) continue;
        var result = decompiler.decompileFunction(function, 20, monitor);
        monitor.checkCancelled();
        if (!result.decompileCompleted() || result.getHighFunction() == null) continue;
        var high = result.getHighFunction();
        if (!samePrototype(function, high)) continue;
        try {
          recovered += apply(program, function, high, monitor);
        } catch (InvalidInputException | ghidra.util.exception.DuplicateNameException
            | ghidra.util.InvalidNameException e) {
          log.appendMsg("Dart ABI", "Observed memory type rejected at "
              + function.getEntryPoint() + ": " + e.getMessage());
        }
        decompiler.flushCache();
      }
    } finally {
      decompiler.dispose();
    }
    return recovered;
  }

  private static int apply(Program program, Function function, HighFunction high,
      TaskMonitor monitor) throws InvalidInputException,
      ghidra.util.exception.DuplicateNameException, ghidra.util.InvalidNameException,
      CancelledException {
    var types = program.getDataTypeManager();
    var saved = new ArrayList<Saved>();
    var symbols = high.getLocalSymbolMap().getSymbols();
    while (symbols.hasNext()) {
      monitor.checkCancelled();
      var symbol = symbols.next();
      if (!symbol.isParameter()) continue;
      var parameter = function.getParameter(symbol.getCategoryIndex());
      if (parameter == null || parameter.getLength() != 8
          || !parameter.getSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)) continue;
      DataType original = parameter.getDataType();
      if (!untyped(original)) continue;
      long originalId = types.getID(original);
      if (types.getDataType(originalId) == null || !memoryOnly(symbol.getHighVariable(), monitor)) continue;
      var builder = new FillOutStructureHelper(program, monitor);
      Structure shape = builder.processStructure(symbol.getHighVariable(), function, true, false, null);
      monitor.checkCancelled();
      if (shape == null || shape.getNumDefinedComponents() < 2) continue;
      shape.setCategoryPath(new CategoryPath("/ghidart/observed-memory/" + function.getEntryPoint()));
      shape.setName("parameter_" + parameter.getOrdinal());
      shape.setDescription("Minimum observed memory span, not a Dart class or complete object layout.");
      for (var field : shape.getDefinedComponents()) {
        field.setFieldName("offset_" + Integer.toHexString(field.getOffset()));
      }
      // Create ownership storage before changing any parameter. Keep each
      // successful substitution tracked even if a later parameter rejects.
      var notes = ownership(program);
      SourceType originalSource = parameter.getSource();
      parameter.setDataType(new PointerDataType(shape), SourceType.ANALYSIS);
      var installed = (Structure) ((Pointer) parameter.getDataType()).getDataType();
      saved.add(new Saved(parameter.getOrdinal(), originalId, originalSource,
          types.getID(installed), installed.toString()));
      notes.add(function.getEntryPoint(), JSON.toJson(saved));
    }
    return saved.size();
  }

  private static StringPropertyMap ownership(Program program)
      throws ghidra.util.exception.DuplicateNameException {
    var manager = program.getUsrPropertyManager();
    var existing = manager.getStringPropertyMap(PROPERTY);
    return existing == null ? manager.createStringPropertyMap(PROPERTY) : existing;
  }

  private static boolean untyped(DataType type) {
    if (Undefined.isUndefined(type) || type instanceof AbstractIntegerDataType) return true;
    if (!(type instanceof Pointer pointer)) return false;
    DataType target = pointer.getDataType();
    return target == null || Undefined.isUndefined(target)
        || target instanceof ghidra.program.model.data.VoidDataType;
  }

  private static boolean managed(Program program, Function function) {
    var convention = function.getCallingConvention();
    if (convention == null) convention = program.getCompilerSpec().getDefaultCallingConvention();
    return "__dart".equals(convention.getName());
  }

  private static boolean samePrototype(Function function, HighFunction high) {
    var parameters = high.getFunctionPrototype();
    if (parameters.getNumParams() != function.getParameterCount()) return false;
    for (int i = 0; i < function.getParameterCount(); i++) {
      if (!function.getParameter(i).getVariableStorage().equals(parameters.getParam(i).getStorage())) {
        return false;
      }
    }
    return true;
  }

  /** Follow only address uses. A tag test, numeric use or pointer escape rejects. */
  private static boolean memoryOnly(HighVariable variable, TaskMonitor monitor)
      throws CancelledException {
    if (variable == null) return false;
    var pending = new ArrayDeque<Varnode>();
    var seen = new HashSet<Varnode>();
    for (var instance : variable.getInstances()) pending.add(instance);
    boolean accessed = false;
    while (!pending.isEmpty()) {
      monitor.checkCancelled();
      var value = pending.remove();
      if (!seen.add(value)) continue;
      var uses = value.getDescendants();
      while (uses.hasNext()) {
        var op = uses.next();
        int code = op.getOpcode();
        if (code == PcodeOp.LOAD && op.getInput(1).equals(value)) {
          accessed = true;
        } else if (code == PcodeOp.STORE && op.getInput(1).equals(value)
            && !op.getInput(2).equals(value)) {
          accessed = true;
        } else if (code == PcodeOp.COPY || code == PcodeOp.CAST) {
          pending.add(op.getOutput());
        } else if ((code == PcodeOp.PTRSUB && op.getInput(1).isConstant())
            || (code == PcodeOp.PTRADD && op.getInput(1).isConstant()
                && op.getInput(2).isConstant())
            || (code == PcodeOp.INT_ADD
                && (op.getInput(0).isConstant() || op.getInput(1).isConstant()))) {
          pending.add(op.getOutput());
        } else {
          return false;
        }
      }
    }
    return accessed;
  }
}
