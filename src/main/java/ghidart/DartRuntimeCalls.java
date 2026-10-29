/**
 * Prove the C++ RuntimeEntry transition and preserve its parameter objects.
 *
 * Raw instruction p-code must prove the four NativeArguments fields, the x5
 * indirect target and the surrounding sp/x15 switch. A small affine evaluator
 * accepts equivalent address arithmetic; unsupported semantics reject the match.
 * NativeArguments is passed by value and lowered indirectly on ARM64. Explicit
 * stack objects prevent the official spill heuristic from deleting its fields.
 * Straight-line RuntimeStubs may be reused through an official callfixup, so a
 * caller sees argument/result-slot effects as well as the native clobber set.
 * Overlapping automatic stack views share one bounded storage allocation.
 * Dynamic objects are accepted only with four surviving field stores and an
 * immediate trap; other unknown locations and metadata conflicts reject. This is
 * not a general FFI convention or a classifier for arbitrary VM stubs.
 */
package ghidart;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Recognizes the SDK's NativeArguments lowering, not arbitrary BLR instructions. */
final class DartRuntimeCalls {
  private DartRuntimeCalls() {}

  static int recover(Program program, Function function, TaskMonitor monitor)
      throws CancelledException, InvalidInputException {
    var objects = new LinkedHashMap<Address, DataType>();
    var locals = new ArrayList<Variable>();
    SourceType source = function.getSignatureSource();
    try {
      return recoverCalls(program, function, objects, locals, monitor);
    } catch (CancelledException | InvalidInputException | RuntimeException e) {
      // Ghidra nests transactions without savepoints. Aborting an inner one
      // aborts the entire outer analysis, so undo only metadata created here.
      var space = HighFunction.findOverrideSpace(function);
      for (var address : objects.keySet()) {
        var symbols = new ArrayList<Symbol>();
        for (var symbol : program.getSymbolTable().getSymbols(address)) {
          if (symbol.getParentNamespace().equals(space)
              && symbol.getSymbolType() == SymbolType.LABEL
              && HighFunctionDBUtil.readOverride(symbol) != null) {
            symbols.add(symbol);
          }
        }
        symbols.forEach(Symbol::delete);
      }
      locals.forEach(function::removeVariable);
      function.setSignatureSource(source);
      throw e;
    }
  }

  private static int recoverCalls(Program program, Function function,
      Map<Address, DataType> objects,
      List<Variable> locals, TaskMonitor monitor)
      throws CancelledException, InvalidInputException {
    int recovered = 0;
    var instructions = program.getListing().getInstructions(function.getBody(), true);
    while (instructions.hasNext()) {
      monitor.checkCancelled();
      Instruction call = instructions.next();
      if (!isRuntimeEntry(program, function, call) && !isTrampolineCall(program, call)) {
        continue;
      }
      // Call overrides may carry user/importer knowledge. Never replace one,
      // including one installed on a previous run of this recognizer.
      var space = HighFunction.findOverrideSpace(function);
      boolean overridden = false;
      for (var symbol : program.getSymbolTable().getSymbols(call.getAddress())) {
        overridden |= symbol.getSymbolType() == SymbolType.LABEL
            && space != null && symbol.getParentNamespace().equals(space)
            && HighFunctionDBUtil.readOverride(symbol) != null;
      }
      if (overridden) {
        continue;
      }
      var signature = new FunctionDefinitionDataType("DartRuntimeEntry", program.getDataTypeManager());
      signature.setCallingConvention("__dart_runtime_entry");
      signature.setReturnType(VoidDataType.dataType);
      var arguments = new StructureDataType(
          new CategoryPath("/Dart/ABI"), "NativeArguments", 0,
          program.getDataTypeManager());
      arguments.add(new PointerDataType(VoidDataType.dataType), "thread", null);
      arguments.add(LongLongDataType.dataType, "argc_tag", null);
      arguments.add(new PointerDataType(Undefined8DataType.dataType), "argv", null);
      arguments.add(new PointerDataType(Undefined8DataType.dataType), "retval", null);
      arguments.setPackingEnabled(true);
      signature.setArguments(new ParameterDefinition[] {
          new ParameterDefinitionImpl("native_args", arguments, null)});
      objects.put(call.getAddress(), arguments);
      HighFunctionDBUtil.writeOverride(function, call.getAddress(), signature);
      recovered++;
    }
    if (!objects.isEmpty()) {
      // Reopen our own inferred prototype, never a user/importer signature.
      // Otherwise a previous incomplete recovery can keep argc locked out.
      boolean reopen = function.getSignatureSource() == SourceType.ANALYSIS
          && function.getReturn().getSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS);
      for (var parameter : function.getParameters()) {
        reopen &= parameter.getSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS);
      }
      if (reopen) {
        function.setSignatureSource(SourceType.DEFAULT);
      }
      bindArgumentObjects(program, function, objects, locals, monitor);
      if (function.getCallFixup() == null
          && function.getSignatureSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)
          && !linearRuntimeBody(program, function).isEmpty()) {
        function.setCallFixup(DartPcodeInjectLibrary.RUNTIME_STUB);
      }
    }
    return recovered;
  }

  /** Bind a proved parameter object in the official engine's recovered stack frame.
   *
   * Ghidra's saved-register heuristic mistakes the first field (copied from THR)
   * for an unused spill. A typed local prevents that range from being unmapped.
   * Use the engine's own stack-relative address, including its alignment model;
   * never guess an offset from an App, SDK version or prologue byte pattern.
   */
  private static void bindArgumentObjects(Program program, Function function,
      Map<Address, DataType> objects,
      List<Variable> locals, TaskMonitor monitor)
      throws CancelledException, InvalidInputException {
    var decompiler = new DecompInterface();
    try {
      if (!decompiler.openProgram(program)) {
        throw new InvalidInputException(decompiler.getLastMessage());
      }
      var result = decompiler.decompileFunction(function, 20, monitor);
      monitor.checkCancelled();
      if (!result.decompileCompleted()) {
        throw new InvalidInputException(result.getErrorMessage());
      }
      var offsets = new HashMap<Address, Integer>();
      for (var object : objects.entrySet()) {
        var nativeCall = nativeCall(result.getHighFunction(), object.getKey());
        Long offset = nativeCall == null ? null : stackOffset(program, nativeCall.getInput(1), 0);
        boolean dynamicObject = offset == null && nativeCall != null
            && completeDynamicObject(nativeCall);
        // A dynamic aligned stack address has no fixed DB local. For a
        // trapping caller, keep the actual pointer only when all four field
        // stores survived in the native call's block. No result is consumed.
        if (offset == null && dynamicObject && trapsAfter(program, object.getKey())) {
          continue;
        }
        bindLocal(program, function, object.getValue(), offset,
            "native_args_" + object.getKey(), locals);
        offsets.put(object.getKey(), offset.intValue());
      }
      // The initial null in a Dart result slot also resembles a saved register.
      // Read the actual retval field after object recovery; do not guess argc,
      // frame depth, or the location of a result from the CALL instruction alone.
      decompiler.flushCache();
      result = decompiler.decompileFunction(function, 20, monitor);
      monitor.checkCancelled();
      if (!result.decompileCompleted()) {
        throw new InvalidInputException(result.getErrorMessage());
      }
      for (var object : objects.entrySet()) {
        var call = program.getListing().getInstructionAt(object.getKey());
        if (!offsets.containsKey(object.getKey())) {
          var nativeCall = nativeCall(result.getHighFunction(), object.getKey());
          if (nativeCall == null || !completeDynamicObject(nativeCall)) {
            throw new InvalidInputException("Dynamic Runtime fields changed during local recovery: "
                + object.getKey());
          }
        }
        if (!isTrampolineCall(program, call) || trapsAfter(program, object.getKey())) {
          continue;
        }
        Long offset = null;
        var operations = result.getHighFunction().getPcodeOps(object.getKey());
        while (operations.hasNext()) {
          var op = operations.next();
          var output = op.getOutput();
          if (op.getOpcode() == PcodeOp.INDIRECT && output != null
              && output.getAddress().isStackAddress() && output.getSize() == 8
              && output.getOffset() == offsets.get(object.getKey()) + 24L) {
            offset = stackOffset(program, op.getInput(0), 0);
          }
        }
        bindLocal(program, function, UnsignedLongLongDataType.dataType,
            offset, "runtime_result_" + object.getKey(), locals);
      }
    } finally {
      decompiler.dispose();
    }
  }

  private static PcodeOpAST nativeCall(HighFunction function, Address address) {
    var operations = function.getPcodeOps(address);
    while (operations.hasNext()) {
      var op = operations.next();
      if (op.getOpcode() == PcodeOp.CALLIND && op.getNumInputs() == 2) {
        return op;
      }
    }
    return null;
  }

  private static boolean trapsAfter(Program program, Address address) {
    var call = program.getListing().getInstructionAt(address);
    var next = call == null || call.getFallThrough() == null ? null
        : program.getListing().getInstructionAt(call.getFallThrough());
    return next != null && next.getMnemonicString().equalsIgnoreCase("brk");
  }

  /** Dynamic objects remain memory STOREs, not fixed stack SSA variables.
   * Require each complete field in the same basic block before the native
   * call. Missing, widened or cross-call stores are not sufficient evidence.
   */
  private static boolean completeDynamicObject(PcodeOpAST call) {
    int fields = 0;
    var operations = call.getParent().getIterator();
    while (operations.hasNext()) {
      var op = operations.next();
      if (op == call) {
        return fields == 15;
      }
      if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
        fields = 0;
      } else if (op.getOpcode() == PcodeOp.STORE) {
        Long offset = displacement(op.getInput(1), call.getInput(1), 0);
        if (offset != null && offset >= 0 && offset < 32) {
          if (offset % 8 != 0 || op.getInput(2).getSize() != 8) {
            return false;
          }
          fields |= 1 << (offset.intValue() / 8);
        }
      }
    }
    return false;
  }

  private static Long displacement(Varnode node, Varnode base, int depth) {
    var address = relativeAddress(node, depth);
    var origin = relativeAddress(base, depth);
    return address != null && origin != null && address.base().equals(origin.base())
        ? address.offset() - origin.offset() : null;
  }

  private record RelativeAddress(Varnode base, long offset) {}

  // Normalize constant address arithmetic on both sides of a comparison.
  // Nonlinear/dynamic expressions remain opaque SSA roots: two unrelated
  // alignments or merged pointers never become equivalent by assumption.
  private static RelativeAddress relativeAddress(Varnode node, int depth) {
    if (depth > 16) {
      return null;
    }
    var op = node.getDef();
    if (op == null) {
      return new RelativeAddress(node, 0);
    }
    int code = op.getOpcode();
    if (code == PcodeOp.COPY || code == PcodeOp.CAST) {
      return relativeAddress(op.getInput(0), depth + 1);
    }
    if ((code != PcodeOp.INT_ADD && code != PcodeOp.INT_SUB
        && code != PcodeOp.PTRSUB && code != PcodeOp.PTRADD)
        || !op.getInput(1).isConstant()
        || code == PcodeOp.PTRADD && !op.getInput(2).isConstant()) {
      return new RelativeAddress(node, 0);
    }
    var base = relativeAddress(op.getInput(0), depth + 1);
    if (base == null) {
      return null;
    }
    long scale = code == PcodeOp.PTRADD ? op.getInput(2).getOffset()
        : code == PcodeOp.INT_SUB ? -1 : 1;
    return new RelativeAddress(base.base(), base.offset() + op.getInput(1).getOffset() * scale);
  }

  private static void bindLocal(Program program, Function function, DataType type,
      Long offset, String name, List<Variable> created)
      throws InvalidInputException {
    if (offset == null || offset >= 0 || offset % 8 != 0 || offset < Integer.MIN_VALUE
        || offset + type.getLength() > 0) {
      throw new InvalidInputException("Runtime object has no bounded local stack location: " + name);
    }
    boolean shared = false;
    for (var local : function.getAllVariables()) {
      var storage = local.getVariableStorage();
      if (!storage.isStackStorage()) {
        continue;
      }
      long start = storage.getStackOffset();
      if (start < offset + type.getLength() && offset < start + storage.size()) {
        if (start == offset && local.getDataType().isEquivalent(type)) {
          return;
        }
        if (!created.contains(local)) {
          throw new InvalidInputException("Runtime object overlaps existing local " + local.getName());
        }
        if (start <= offset && offset + type.getLength() <= start + storage.size()) {
          return;
        }
        shared = true;
      }
    }
    if (shared) {
      // A pointer into the middle of one DB local is bounded by that object's
      // extent in Ghidra's alias analysis. Separate word guards would preserve
      // names but can still lose fields beyond that bound. Merge overlapping
      // automatic storage into one allocation; the call prototype supplies
      // each NativeArguments view. Never merge user/imported locals.
      long start = offset;
      long end = offset + type.getLength();
      var overlapping = new ArrayList<Variable>();
      boolean expanded;
      do {
        expanded = false;
        for (var local : created) {
          var storage = local.getVariableStorage();
          long first = storage.getStackOffset();
          long last = first + storage.size();
          if (!overlapping.contains(local) && first < end && start < last) {
            overlapping.add(local);
            start = Math.min(start, first);
            end = Math.max(end, last);
            expanded = true;
          }
        }
      } while (expanded);
      for (var local : overlapping) {
        function.removeVariable(local);
        created.remove(local);
      }
      offset = start;
      type = new ArrayDataType(UnsignedLongLongDataType.dataType, (int) ((end - start) / 8), 8);
      name = "runtime_storage_" + Long.toHexString(-start);
    }
    try {
      created.add(function.addLocalVariable(new LocalVariableImpl(name, type, offset.intValue(),
          program), SourceType.ANALYSIS));
    } catch (DuplicateNameException e) {
      throw new InvalidInputException(e.getMessage());
    }
  }

  private static boolean isTrampolineCall(Program program, Instruction instruction) {
    if (instruction == null || !instruction.getFlowType().isCall()) {
      return false;
    }
    var targets = instruction.getFlows();
    var target = targets.length == 1
        ? program.getFunctionManager().getFunctionAt(targets[0]) : null;
    return target != null && DartPcodeInjectLibrary.RUNTIME_STUB.equals(target.getCallFixup())
        && !linearRuntimeBody(program, target).isEmpty();
  }

  static ghidra.program.model.symbol.Symbol overrideSymbol(Program program,
      Function function, Address address) {
    var space = HighFunction.findOverrideSpace(function);
    for (var symbol : program.getSymbolTable().getSymbols(address)) {
      if (space != null && symbol.getParentNamespace().equals(space)
          && symbol.getSymbolType() == SymbolType.LABEL
          && HighFunctionDBUtil.readOverride(symbol) != null) return symbol;
    }
    return null;
  }

  static FunctionSignature callSignature(Program program, Function function, Address address) {
    var symbol = overrideSymbol(program, function, address);
    var value = symbol == null ? null : HighFunctionDBUtil.readOverride(symbol);
    return value != null && value.getDataType() instanceof FunctionSignature signature
        ? signature : null;
  }

  static boolean hasOverride(Program program, Function function, Address address) {
    return overrideSymbol(program, function, address) != null;
  }

  /** Propagate a Thread load through official p-code within one bounded block. */
  static Long threadLoad(Program program, List<Instruction> block, String destination) {
    return baseLoad(program, block, destination, "x26");
  }

  static Long poolLoad(Program program, List<Instruction> block, String destination) {
    return baseLoad(program, block, destination, "x27");
  }

  private static Long baseLoad(Program program, List<Instruction> block,
      String destination, String baseRegister) {
    var values = new HashMap<Varnode, Value>();
    var loads = new HashMap<Varnode, Long>();
    var root = Value.atom(register(program, baseRegister));
    try {
      for (var instruction : block) {
        // Decoder unique temporaries are local to an instruction.
        values.keySet().removeIf(Varnode::isUnique);
        loads.keySet().removeIf(Varnode::isUnique);
        for (var op : instruction.getPcode()) {
          if (op.getOpcode() == PcodeOp.CALLOTHER) {
            return null;
          }
          var output = op.getOutput();
          if (output == null) {
            continue;
          }
          Value expression = evaluate(values, op);
          Long slot = null;
          if (op.getOpcode() == PcodeOp.COPY) {
            slot = loads.get(op.getInput(0));
          } else if (op.getOpcode() == PcodeOp.LOAD && output.getSize() == 8) {
            Value address = read(values, op.getInput(1));
            if (address != null && address.terms().equals(root.terms())) {
              slot = address.constant();
            }
          }
          for (var existing : List.copyOf(values.keySet())) {
            if (existing.getAddress().getAddressSpace().equals(output.getAddress().getAddressSpace())
                && existing.getOffset() < output.getOffset() + output.getSize()
                && output.getOffset() < existing.getOffset() + existing.getSize()) {
              values.put(existing, null);
              loads.remove(existing);
            }
          }
          values.put(output, expression);
          loads.put(output, slot);
        }
      }
      return loads.get(register(program, destination));
    } catch (ArithmeticException e) {
      return null;
    }
  }

  /** One basic-block prefix: never propagate through a call or a join. */
  static List<Instruction> blockBefore(Program program,
      ghidra.program.model.address.AddressSetView body, Instruction end) {
    var block = new ArrayList<Instruction>();
    block.add(end);
    var cursor = end;
    for (int i = 0; i < 32; i++) {
      var references = program.getReferenceManager().getReferencesTo(cursor.getAddress());
      boolean incoming = false;
      while (references.hasNext()) {
        incoming |= references.next().getReferenceType().isFlow();
      }
      if (incoming) break;
      var previous = cursor.getPrevious();
      if (previous == null || !body.contains(previous.getAddress())
          || !cursor.getAddress().equals(previous.getFallThrough())
          || previous.getFlowType().isCall() || previous.getFlowType().isJump()
          || previous.getFlowType().isTerminal()) break;
      block.addFirst(previous);
      cursor = previous;
    }
    return block;
  }

  static boolean hasNativeOverride(Program program, Function function,
      Address address) {
    var space = HighFunction.findOverrideSpace(function);
    for (var symbol : program.getSymbolTable().getSymbols(address)) {
      if (space != null && symbol.getParentNamespace().equals(space)
          && symbol.getSymbolType() == SymbolType.LABEL) {
        var override = HighFunctionDBUtil.readOverride(symbol);
        if (override == null || !(override.getDataType() instanceof FunctionSignature signature)
            || !"__dart_runtime_entry".equals(signature.getCallingConventionName())
            || !signature.getReturnType().isEquivalent(VoidDataType.dataType)
            || signature.getArguments().length != 1
            || !(signature.getArguments()[0].getDataType() instanceof ghidra.program.model.data.Structure arguments)
            || arguments.getLength() != 32 || arguments.getNumComponents() != 4) {
          continue;
        }
        boolean valid = true;
        for (int i = 0; i < 4; i++) {
          var field = arguments.getComponent(i);
          valid &= field.getOffset() == i * 8 && field.getLength() == 8;
          valid &= i == 1 ? field.getDataType().isEquivalent(LongLongDataType.dataType)
              : field.getDataType() instanceof ghidra.program.model.data.Pointer;
        }
        if (valid) {
          return true;
        }
      }
    }
    return false;
  }

  // Accept only a constant displacement from the entry value of VMSP. The
  // decompiler already resolved stack alignment; unknown/merged bases reject.
  private static Long stackOffset(Program program, Varnode node, int depth) {
    var address = relativeAddress(node, depth);
    if (address == null) {
      return null;
    }
    var base = address.base();
    var stack = program.getRegister("x15");
    return base.isInput() && base.getSize() == stack.getNumBytes()
        && base.getAddress().equals(stack.getAddress()) ? address.offset() : null;
  }

  /** Only a contiguous, single-return body with exactly one proved native call. */
  static List<Instruction> linearRuntimeBody(Program program, Function function) {
    var body = new ArrayList<Instruction>();
    var instructions = program.getListing().getInstructions(function.getBody(), true);
    instructions.forEachRemaining(body::add);
    return !body.isEmpty() && body.getFirst().getAddress().equals(function.getEntryPoint())
        && body.getLast().getMaxAddress().equals(function.getBody().getMaxAddress())
        && isRuntimeBody(program, body) ? body : List.of();
  }

  // Also accepts official pseudo-instructions, so discovery proves a complete
  // body before modifying the listing. No guessed function boundary is needed.
  static boolean isRuntimeBody(Program program, List<Instruction> body) {
    int calls = 0;
    Address next = body.isEmpty() ? null : body.getFirst().getAddress();
    for (int i = 0; i < body.size(); i++) {
      var instruction = body.get(i);
      if (!instruction.getAddress().equals(next)) {
        return false;
      }
      next = next.add(instruction.getLength());
      boolean returns = false;
      for (var op : instruction.getPcode()) {
        returns |= op.getOpcode() == PcodeOp.RETURN;
        if (op.getOpcode() == PcodeOp.CALLOTHER) {
          return false;
        }
      }
      if (returns) {
        return i == body.size() - 1 && calls == 1;
      }
      var flow = instruction.getFlowType();
      if (flow.isJump() || flow.isTerminal()) {
        return false;
      }
      if (flow.isCall()) {
        if (!isRuntimeEntry(program, body, i)) {
          return false;
        }
        calls++;
      }
    }
    return false;
  }

  private static boolean isRuntimeEntry(Program program, Function function, Instruction call) {
    if (!callsRegister(program, call, "x5")) {
      return false;
    }
    var body = new ArrayList<Instruction>();
    body.add(call);
    var cursor = call;
    for (int i = 0; i < 27; i++) {
      var previous = cursor.getPrevious();
      if (previous == null || !function.getBody().contains(previous.getAddress())
          || !cursor.getAddress().equals(previous.getFallThrough())) {
        break;
      }
      body.addFirst(previous);
      cursor = previous;
    }
    int index = body.size() - 1;
    cursor = call;
    for (int i = 0; i < 2; i++) {
      var next = cursor.getNext();
      if (next == null || !function.getBody().contains(next.getAddress())
          || !next.getAddress().equals(cursor.getFallThrough())) {
        return false;
      }
      body.add(next);
      cursor = next;
    }
    return isRuntimeEntry(program, body, index);
  }

  private static boolean callsRegister(Program program, Instruction call, String name) {
    // The official decoder copies the BLR operand to pc before CALLIND pc.
    var definitions = new HashMap<Varnode, Varnode>();
    for (var op : call.getPcode()) {
      if (op.getOpcode() == PcodeOp.CALLIND) {
        var target = op.getInput(0);
        return register(program, name).equals(definitions.getOrDefault(target, target));
      }
      if (op.getOutput() != null) {
        Varnode source = op.getOpcode() == PcodeOp.COPY ? op.getInput(0) : null;
        definitions.put(op.getOutput(), definitions.getOrDefault(source, source));
      }
    }
    return false;
  }

  private static boolean isRuntimeEntry(Program program, List<Instruction> body, int call) {
    if (call < 2 || call + 2 >= body.size()
        || !callsRegister(program, body.get(call), "x5")
        || !copy(program, body.get(call - 1), "sp", "x15")
        || !copy(program, body.get(call - 2), "x25", "sp")
        || !copy(program, body.get(call + 1), "x15", "sp")
        || !copy(program, body.get(call + 2), "sp", "x25")) {
      return false;
    }
    for (int i = call - 3; i >= Math.max(0, call - 26); i--) {
      var cursor = body.get(i);
      if (cursor.getFlowType().isCall() || cursor.getFlowType().isJump()
          || cursor.getFlowType().isTerminal()) {
        return false;
      }
      if (copy(program, cursor, "x0", "x26")) {
        var setup = body.subList(i, call - 2);
        for (int j = i; j < call + 2; j++) {
          if (!body.get(j + 1).getAddress().equals(body.get(j).getFallThrough())) {
            return false;
          }
          if (j == i) {
            continue;
          }
          var references = program.getReferenceManager().getReferencesTo(body.get(j).getAddress());
          while (references.hasNext()) {
            if (references.next().getReferenceType().isFlow()) {
              return false;
            }
          }
        }
        return argumentsMatch(program, setup);
      }
    }
    return false;
  }

  private static boolean argumentsMatch(Program program, List<Instruction> setup) {
    var values = new HashMap<Varnode, Value>();
    var stores = new HashMap<Value, Value>();
    Value stack = Value.atom(register(program, "x15"));
    Value argc = Value.atom(register(program, "x4"));
    Value argv = Value.atom(register(program, "x29")).add(argc.scale(8)).add(Value.constant(8));
    try {
      for (Instruction instruction : setup) {
        for (PcodeOp op : instruction.getPcode()) {
          if (op.getOpcode() == PcodeOp.CALLOTHER || op.getOpcode() == PcodeOp.LOAD) {
            return false;
          }
          if (op.getOpcode() == PcodeOp.STORE) {
            Value address = read(values, op.getInput(1));
            Value value = read(values, op.getInput(2));
            if (address == null || value == null || op.getInput(2).getSize() != 8) {
              return false;
            }
            stores.put(address, value);
          } else if (op.getOutput() != null) {
            Value value = evaluate(values, op);
            Varnode output = op.getOutput();
            // A 32-bit/subregister write invalidates an earlier full-register
            // expression. Unsupported operations remain unknown, never identity.
            for (Varnode existing : List.copyOf(values.keySet())) {
              if (existing.getAddress().getAddressSpace().equals(output.getAddress().getAddressSpace())
                  && existing.getOffset() < output.getOffset() + output.getSize()
                  && output.getOffset() < existing.getOffset() + existing.getSize()) {
                values.put(existing, null);
              }
            }
            values.put(output, value);
          } else {
            return false;
          }
        }
      }
      return stores.size() == 4 && stack.equals(read(values, register(program, "x0")))
          && Value.atom(register(program, "x26")).equals(stores.get(stack))
          && argc.equals(stores.get(stack.add(Value.constant(8))))
          && argv.equals(stores.get(stack.add(Value.constant(16))))
          && argv.add(Value.constant(8)).equals(stores.get(stack.add(Value.constant(24))));
    } catch (ArithmeticException e) {
      return false;
    }
  }

  private static Value evaluate(Map<Varnode, Value> values, PcodeOp op) {
    if (op.getNumInputs() == 0) {
      return null;
    }
    Value left = read(values, op.getInput(0));
    if (left == null) {
      return null;
    }
    return switch (op.getOpcode()) {
      case PcodeOp.COPY -> left;
      case PcodeOp.INT_ADD -> left.add(read(values, op.getInput(1)));
      case PcodeOp.INT_LEFT -> op.getInput(1).isConstant() && op.getInput(1).getOffset() < 63
          ? left.scale(1L << op.getInput(1).getOffset()) : null;
      default -> null;
    };
  }

  private static Value read(Map<Varnode, Value> values, Varnode node) {
    if (values.containsKey(node)) {
      return values.get(node);
    }
    if (node.isConstant()) {
      return Value.constant(node.getOffset());
    }
    if (!node.isRegister()) {
      return null;
    }
    for (Varnode written : values.keySet()) {
      if (written.getAddress().getAddressSpace().equals(node.getAddress().getAddressSpace())
          && written.getOffset() < node.getOffset() + node.getSize()
          && node.getOffset() < written.getOffset() + written.getSize()) {
        return null;
      }
    }
    return Value.atom(node);
  }

  static boolean copy(Program program, Instruction instruction, String to, String from) {
    if (instruction == null) {
      return false;
    }
    PcodeOp[] ops = instruction.getPcode();
    return ops.length == 1 && ops[0].getOpcode() == PcodeOp.COPY
        && register(program, to).equals(ops[0].getOutput())
        && register(program, from).equals(ops[0].getInput(0));
  }

  private static Varnode register(Program program, String name) {
    var reg = program.getRegister(name);
    return new Varnode(reg.getAddress(), reg.getNumBytes());
  }

  // Only affine arithmetic needed by NativeArguments lowering. This is neither
  // an emulator nor a second instruction decoder: unsupported semantics reject.
  private record Value(Map<Varnode, Long> terms, long constant) {
    static Value atom(Varnode node) {
      return new Value(Map.of(node, 1L), 0);
    }

    static Value constant(long value) {
      return new Value(Map.of(), value);
    }

    Value add(Value other) {
      if (other == null) {
        return null;
      }
      var sum = new HashMap<>(terms);
      other.terms.forEach((node, coefficient) -> sum.merge(node, coefficient, Math::addExact));
      sum.values().removeIf(coefficient -> coefficient == 0);
      return new Value(Map.copyOf(sum), Math.addExact(constant, other.constant));
    }

    Value scale(long factor) {
      var product = new HashMap<Varnode, Long>();
      terms.forEach((node, coefficient) -> product.put(node, Math.multiplyExact(coefficient, factor)));
      return new Value(Map.copyOf(product), Math.multiplyExact(constant, factor));
    }
  }
}
