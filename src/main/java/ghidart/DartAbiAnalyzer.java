/**
 * Recover managed Dart call contracts using Ghidra's decompiler.
 *
 * The compiler spec supplies candidate storage and clobber rules; Ghidra's
 * parameter-identification command recovers actual inputs across the call graph.
 * A bounded return supplement handles invariant NULL_REG and known forwarded
 * results, rejecting ambiguous paths and later writes to result registers.
 * Runtime contracts are prepared bottom-up. A narrowly scoped official
 * callfixup exposes a proved RuntimeStub's actual decoded stack side effects;
 * it does not maintain handwritten instruction semantics. Whole-program
 * recovery remains opt-in; bytes and the debugger's register view are unchanged.
 */
package ghidart;

import ghidra.app.cmd.function.DecompilerParameterIdCmd;
import ghidra.framework.options.Options;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.AcyclicCallGraphBuilder;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

/** Uses Ghidra's own call-graph recovery, without imported function signatures. */
public final class DartAbiAnalyzer extends AbstractAnalyzer {
  private static final String MEMORY_OPTION = "Infer observed memory shapes";
  private boolean inferMemoryShapes;

  public DartAbiAnalyzer() {
    super("Dart ABI", "Recover managed arguments and results in the selected call graph.",
        AnalyzerType.FUNCTION_ANALYZER);
    setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after());
    setSupportsOneTimeAnalysis();
  }

  @Override
  public boolean canAnalyze(Program program) {
    return "AARCH64:LE:64:dart".equals(program.getLanguageID().toString());
  }

  @Override
  public boolean getDefaultEnablement(Program program) {
    // A whole AOT image can contain hundreds of thousands of functions. Keep
    // whole-program decompilation explicit while the ABI is being validated.
    return false;
  }

  @Override
  public void registerOptions(Options options, Program program) {
    options.registerOption(MEMORY_OPTION, false, null,
        "Infer access shapes for recovered parameters used only as memory addresses. "
            + "These are observed offsets, not Dart class layouts.");
  }

  @Override
  public void optionsChanged(Options options, Program program) {
    inferMemoryShapes = options.getBoolean(MEMORY_OPTION, false);
  }

  @Override
  public boolean added(Program program, AddressSetView entries, TaskMonitor monitor, MessageLog log)
      throws CancelledException {
    try (var output = new DartAnalysisLog(program, log)) {
      return analyze(program, entries, monitor, output.messages());
    }
  }

  private boolean analyze(Program program, AddressSetView entries, TaskMonitor monitor,
      MessageLog log) throws CancelledException {
    var graph = new AcyclicCallGraphBuilder(program, entries, true).getDependencyGraph(monitor);
    var bottomUp = new ArrayList<Function>();
    while (!graph.isEmpty()) {
      monitor.checkCancelled();
      Address entry = graph.pop();
      Function function = entry == null ? null
          : program.getFunctionManager().getFunctionAt(entry);
      if (function != null) {
        bottomUp.add(function);
      }
    }
    // Discard only unchanged hints owned by the optional memory-shape pass.
    // This also revokes stale hints when the option is subsequently disabled.
    var unreadableTypes = new HashSet<Address>();
    for (var function : bottomUp) {
      if (!DartMemoryShapes.restore(program, function, log)) {
        unreadableTypes.add(function.getEntryPoint());
      }
    }
    // An unresolved successor makes return/parameter inference incomplete.
    // Keep its conservative ABI and warning instead of publishing a precise
    // signature inferred only from the visible subset of paths.
    var safeEntries = new AddressSet(entries);
    int incomplete = 0;
    var iterator = bottomUp.iterator();
    while (iterator.hasNext()) {
      Function function = iterator.next();
      if (unreadableTypes.contains(function.getEntryPoint())) {
        safeEntries.delete(function.getEntryPoint(), function.getEntryPoint());
        iterator.remove();
        continue;
      }
      if (incomplete(function)) {
        safeEntries.delete(function.getEntryPoint(), function.getEntryPoint());
        iterator.remove();
        incomplete++;
      }
    }
    log.appendMsg(getName(), incomplete + " incomplete CFGs left without inferred signatures.");
    if (bottomUp.isEmpty() && !unreadableTypes.isEmpty()) return true;
    // Machine-only helper contracts: no snapshot identity or Thread layout.
    int helpers = DartThreadCalls.recoverContracts(program, bottomUp, monitor, log);
    log.appendMsg(getName(), helpers + " SDK helper call contracts recovered.");
    int runtimeCalls = 0;
    for (Function function : bottomUp) {
      try {
        runtimeCalls += DartRuntimeCalls.recover(program, function, monitor);
      } catch (InvalidInputException e) {
        log.appendMsg(getName(), "Runtime contract rejected at " + function.getEntryPoint()
            + ": " + e.getMessage());
      }
    }
    // Keep unresolved Thread calls indirect. A helper's ABI evidence does not
    // establish the runtime-initialized destination address of a Thread field.
    log.appendMsg(getName(), runtimeCalls + " proved RuntimeEntry call sites recovered.");
    // Reopen automatic prototypes so a corrected helper contract can remove
    // stale inputs. Keep explicit void returns and imported or user contracts;
    // clearing at ANALYSIS level would also erase those return facts.
    for (Function function : bottomUp) {
      monitor.checkCancelled();
      boolean automatic = function.getSignatureSource() == SourceType.ANALYSIS
          && !function.getReturnType().isEquivalent(ghidra.program.model.data.VoidDataType.dataType)
          && function.getReturn().getSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS);
      for (Parameter parameter : function.getParameters()) {
        automatic &= parameter.getSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS);
      }
      if (automatic) {
        function.setSignatureSource(SourceType.DEFAULT);
        try {
          function.setReturnType(ghidra.program.model.data.DataType.DEFAULT, SourceType.DEFAULT);
        } catch (InvalidInputException e) {
          throw new IllegalStateException(e);
        }
      }
    }
    // L2 may independently prove a Class-owned allocation stub's x0 result.
    // This supplies no argument count and is absent in the L1-only path.
    DartObjectUses.allocationReturns(program, bottomUp, monitor);
    var nativeRecovery = new DecompilerParameterIdCmd(
        getName(), safeEntries, SourceType.DEFAULT, true, false, 20);
    if (!nativeRecovery.applyTo(program, monitor)) {
      log.appendMsg(getName(), nativeRecovery.getStatusMsg());
      return false;
    }
    monitor.checkCancelled();

    // Native liveness recovery can discard CALL results and invariant NULL_REG
    // values. Supplement only locally proved managed return contracts, after
    // native parameter recovery. This supplement changes only return metadata.
    int recovered = 0;
    try (var contracts = new ReturnContracts(program, monitor)) {
      for (Function function : bottomUp) {
        monitor.checkCancelled();
        Address entry = function.getEntryPoint();
        if (!eligible(function)) {
          continue;
        }
        try {
          Parameter result = managedResult(program, function, contracts, monitor);
          if (result != null) {
            function.setReturn(result.getDataType(), result.getVariableStorage(), SourceType.ANALYSIS);
            recovered++;
          }
        } catch (InvalidInputException e) {
          log.appendMsg(getName(), "Return contract rejected at " + entry + ": " + e.getMessage());
        }
      }
    }
    int allocations = DartObjectUses.allocationReturns(program, bottomUp, monitor);
    if (allocations != 0) {
      log.appendMsg(getName(), allocations + " L2-proved allocation returns restored to x0.");
    }
    if (inferMemoryShapes) {
      int shapes = DartMemoryShapes.recover(program, bottomUp, monitor, log);
      log.appendMsg(getName(), shapes + " observed parameter memory shapes recovered; "
          + "these are access types, not Dart classes.");
    }
    log.appendMsg(getName(), "Native parameter recovery completed; " + recovered
        + " managed return contracts recovered. User/imported signatures were preserved.");
    return true;
  }

  private static boolean incomplete(Function function) {
    return function.getTags().stream()
        .anyMatch(tag -> tag.getName().equals(DartFunctionAnalyzer.INCOMPLETE_TAG));
  }

  private static boolean eligible(Function function) {
    return function != null && !function.isExternal() && !function.hasNoReturn()
        && !incomplete(function) && function.getSignatureSource() == SourceType.ANALYSIS
        && function.getReturn().getVariableStorage().isUnassignedStorage()
        && function.getReturn().getSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS);
  }

  private static Parameter managedResult(Program program, Function function,
      ReturnContracts contracts, TaskMonitor monitor)
      throws CancelledException, InvalidInputException {
    Parameter result = null;
    var pending = new ArrayDeque<Address>();
    var visited = new HashSet<Address>();
    pending.add(function.getEntryPoint());
    while (!pending.isEmpty()) {
      monitor.checkCancelled();
      Address address = pending.removeFirst();
      if (!visited.add(address)) {
        continue;
      }
      if (!contracts.body(function).contains(address)) {
        return null;
      }
      Instruction instruction = program.getListing().getInstructionAt(address);
      if (instruction == null) {
        return null;
      }
      boolean returns = false;
      for (PcodeOp operation : instruction.getPcode()) {
        returns |= operation.getOpcode() == PcodeOp.RETURN;
      }
      if (returns) {
        Parameter candidate = resultAtReturn(program, function, instruction, contracts, monitor);
        if (candidate == null || (result != null
            && (!result.getVariableStorage().equals(candidate.getVariableStorage())
                || !result.getDataType().isEquivalent(candidate.getDataType())))) {
          return null;
        }
        result = candidate;
        continue;
      }
      // A payload can include an earlier dispatch entry and cold blocks. Only
      // paths reachable from the function's normal entry constrain its return.
      var flow = instruction.getFlowType();
      if (flow.isJump()) {
        Address[] targets = instruction.getFlows();
        if (targets.length == 0) {
          return null;
        }
        for (Address target : targets) {
          pending.add(target);
        }
      } else if (flow.isTerminal()) {
        return null;
      }
      if (instruction.getFallThrough() != null) {
        pending.add(instruction.getFallThrough());
      }
    }
    return result;
  }

  private static Parameter resultAtReturn(Program program, Function function, Instruction ret,
      ReturnContracts contracts, TaskMonitor monitor)
      throws CancelledException, InvalidInputException {
    return resultBefore(program, function, ret, contracts, monitor, 0,
        new HashSet<>(), new int[] {256});
  }

  /** Meet return contracts along actual predecessor edges, never address order. */
  private static Parameter resultBefore(Program program, Function function, Instruction end,
      ReturnContracts contracts, TaskMonitor monitor, int written, HashSet<Address> path, int[] budget)
      throws CancelledException, InvalidInputException {
    var block = contracts.blocks.getFirstCodeBlockContaining(end.getAddress(), monitor);
    // This is a local supplement, not a second whole-function dataflow engine.
    // A cycle or excessive predecessor depth remains unknown; Ghidra's normal
    // parameter/return analysis is still authoritative for those cases.
    if (block == null || --budget[0] < 0 || path.size() >= 64
        || !path.add(block.getMinAddress())) {
      return null;
    }
    var instructions = program.getListing().getInstructions(block, false);
    while (instructions.hasNext()) {
      monitor.checkCancelled();
      Instruction instruction = instructions.next();
      if (instruction.getAddress().compareTo(end.getAddress()) > 0) {
        continue;
      }
      if (!contracts.body(function).contains(instruction.getAddress())) {
        return null;
      }
      if (instruction.getFlowType().isCall()) {
        Parameter result;
        var override = contracts.override(function, instruction);
        if (override != null) {
          var model = program.getCompilerSpec().getCallingConvention(override.getCallingConventionName());
          if (model == null) return null;
          if (override.getReturnType().isEquivalent(ghidra.program.model.data.VoidDataType.dataType)) {
            // A void helper can preserve a result computed before the call.
            // Use its compiler model, not a second hand-maintained save list.
            written |= killedResults(program, model);
            continue;
          }
          var storage = model.getStorageLocations(program,
              new ghidra.program.model.data.DataType[] {override.getReturnType()}, true, false)[0];
          result = new ParameterImpl(Parameter.RETURN_NAME, override.getReturnType(), storage, program);
        } else {
          Address[] targets = instruction.getFlows();
          Function callee = targets.length == 1
              ? program.getFunctionManager().getFunctionAt(targets[0]) : null;
          if (callee == null || callee.isExternal() || callee.hasNoReturn()) return null;
          result = contracts.result(callee);
        }
        if (result == null) {
          return null;
        }
        var storage = result.getVariableStorage();
        // Undefined datatypes retain DEFAULT parameter source even when the
        // recovered function signature has explicit return storage.
        boolean pair = storage.equals(new VariableStorage(program,
            program.getRegister("x1"), program.getRegister("x0")));
        if (!storage.isRegisterStorage() && !pair) {
          return null;
        }
        String register = pair ? "x0:x1" : storage.getRegister().getName();
        if (!pair && !register.equals("x0") && !register.equals("d0")) {
          return null;
        }
        int mask = pair ? 5 : register.equals("d0") ? 2 : 1;
        if ((written & mask) != 0) {
          return null;
        }
        return result;
      }
      // NULL_REG is an invariant runtime value, not an ordinary parameter.
      // Native liveness recovery can discard an explicit x0 = NULL_REG return.
      // Recognize the ABI role through raw COPY semantics, not instruction text.
      PcodeOp[] operations = instruction.getPcode();
      if ((written & 1) == 0 && operations.length == 1) {
        PcodeOp copy = operations[0];
        if (copy.getOpcode() == PcodeOp.COPY
            && copy.getOutput().equals(new Varnode(program.getRegister("x0").getAddress(), 8))
            && copy.getInput(0).equals(new Varnode(program.getRegister("x22").getAddress(), 8))) {
          return new ParameterImpl(Parameter.RETURN_NAME, Undefined8DataType.dataType,
              new VariableStorage(program, program.getRegister("x0")), program);
        }
      }
      for (PcodeOp operation : operations) {
        if (operation.getOpcode() == PcodeOp.CALLOTHER) {
          return null;
        }
        Varnode value = operation.getOutput();
        if (value != null && value.isRegister()) {
          var writtenRange = new AddressSet(value.getAddress(),
              value.getAddress().add(value.getSize() - 1));
          var second = program.getRegister("x1");
          if (writtenRange.intersects(second.getAddress(),
              second.getAddress().add(second.getNumBytes() - 1))) written |= 4;
          for (String name : new String[] {"x0", "d0"}) {
            var register = program.getRegister(name);
            if (writtenRange.intersects(register.getAddress(),
                register.getAddress().add(register.getNumBytes() - 1))) {
              // An explicit result write makes forwarding an earlier call ambiguous,
              // including a write in the other result bank. Only a proved void
              // helper contract can kill one bank without producing a result.
              written |= 3;
            }
          }
        }
      }
      if (instruction.getAddress().equals(function.getEntryPoint())) {
        return null;
      }
    }
    Parameter agreed = null;
    var sources = block.getSources(monitor);
    while (sources.hasNext()) {
      monitor.checkCancelled();
      var edge = sources.next();
      if (!edge.getFlowType().isFallthrough() && !edge.getFlowType().isJump()) {
        return null;
      }
      Instruction predecessor = program.getListing().getInstructionAt(edge.getReferent());
      if (predecessor == null) {
        return null;
      }
      if (!contracts.body(function).contains(predecessor.getAddress())) {
        // A decoded shared tail has predecessors from several functions.
        // Only paths reachable from this entry constrain this function.
        continue;
      }
      Parameter candidate = resultBefore(program, function, predecessor, contracts, monitor,
          written, new HashSet<>(path), budget);
      if (candidate == null || (agreed != null
          && (!agreed.getVariableStorage().equals(candidate.getVariableStorage())
              || !agreed.getDataType().isEquivalent(candidate.getDataType())))) {
        return null;
      }
      agreed = candidate;
    }
    return agreed;
  }

  private static int killedResults(Program program, ghidra.program.model.lang.PrototypeModel model) {
    int killed = 0;
    String[] names = {"x0", "d0", "x1"};
    for (int i = 0; i < names.length; i++) {
      var register = program.getRegister(names[i]);
      boolean preserved = false;
      for (Varnode value : model.getUnaffectedList()) {
        var range = new AddressSet(value.getAddress(), value.getAddress().add(value.getSize() - 1));
        preserved |= range.contains(register.getAddress(),
            register.getAddress().add(register.getNumBytes() - 1));
      }
      if (!preserved) killed |= 1 << i;
    }
    return killed;
  }

  /** Query unselected callees without importing their inferred parameters. */
  private static final class ReturnContracts implements AutoCloseable {
    private final Program program;
    private final TaskMonitor monitor;
    private final BasicBlockModel blocks;
    private final DecompInterface decompiler = new DecompInterface();
    private final HashMap<Address, Parameter> inferred = new HashMap<>();
    private boolean opened;
    private final HashMap<Address, AddressSetView> bodies = new HashMap<>();

    ReturnContracts(Program program, TaskMonitor monitor) {
      this.program = program;
      this.monitor = monitor;
      blocks = new BasicBlockModel(program);
    }

    ghidra.program.model.listing.FunctionSignature override(Function caller, Instruction call) {
      return DartRuntimeCalls.callSignature(program, caller, call.getAddress());
    }

    AddressSetView body(Function function) throws CancelledException {
      Address entry = function.getEntryPoint();
      AddressSetView body = bodies.get(entry);
      if (body == null) {
        body = CreateFunctionCmd.getFunctionBody(program, entry, false, monitor);
        monitor.checkCancelled();
        bodies.put(entry, body);
      }
      return body;
    }

    Parameter result(Function function) throws CancelledException, InvalidInputException {
      if (incomplete(function) && function.getSignatureSource()
          .isLowerOrEqualPriorityThan(SourceType.ANALYSIS)) {
        return null;
      }
      Parameter declared = function.getReturn();
      if (function.getSignatureSource() != SourceType.DEFAULT
          || !declared.getVariableStorage().isUnassignedStorage()) {
        return declared;
      }
      Address entry = function.getEntryPoint();
      if (inferred.containsKey(entry)) {
        return inferred.get(entry);
      }
      inferred.put(entry, null);
      if (!opened) {
        var options = new DecompileOptions();
        options.grabFromProgram(program);
        decompiler.setOptions(options);
        opened = decompiler.openProgram(program);
        if (!opened) {
          return null;
        }
      }
      var result = decompiler.decompileFunction(function, 20, monitor);
      monitor.checkCancelled();
      if (!result.decompileCompleted() || result.getHighFunction() == null) {
        return null;
      }
      var prototype = result.getHighFunction().getFunctionPrototype();
      var storage = prototype.getReturnStorage();
      // Saved registers in shared stubs can look like an input/output pair.
      // Only supplement a single managed result, never a pass-through input.
      if (!storage.isRegisterStorage()) {
        return null;
      }
      for (int i = 0; i < prototype.getNumParams(); i++) {
        if (storage.intersects(prototype.getParam(i).getStorage())) {
          return null;
        }
      }
      Parameter recovered = new ParameterImpl(Parameter.RETURN_NAME,
          prototype.getReturnType(), storage, program);
      inferred.put(entry, recovered);
      return recovered;
    }

    @Override
    public void close() {
      decompiler.dispose();
    }
  }
}
