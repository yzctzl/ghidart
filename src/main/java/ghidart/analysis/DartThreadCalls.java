/**
 * Recover helper call effects from ARM64 code, independently of AOT metadata.
 *
 * Direct shared helpers must exhibit their actual saves, frame, runtime call,
 * result-slot update and restores. Indirect calls require the complete local
 * stack-check or write-barrier idiom emitted by the Dart compiler. These are
 * bounded codegen recognizers, not assumptions about a Thread field number.
 * An ABI contract never creates a destination address for an indirect call.
 * Snapshot hashes, feature strings, image headers and SDK layouts are unused.
 */
package ghidart.analysis;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.List;

/** Per-call machine evidence; no whole-VM layout selection or global scan. */
final class DartThreadCalls {
  private DartThreadCalls() {}

  private record
      Contract(String name, List<String> inputs, boolean result, boolean array, int savedFpu) {}
  private record Save(List<Register> registers, int bytes) {}

  // AddAllNonReservedRegisters in the ARM64 SDK. Roles, not Thread offsets.
  private static final int[] AVAILABLE = {
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 19, 20, 23, 24, 25};

  static int recoverContracts(Program program, List<Function> callers, TaskMonitor monitor,
      MessageLog log) throws CancelledException {
    var properties = program.getUsrPropertyManager();
    var generated = properties.getStringPropertyMap("ghidart.L1.helperCalls");
    if (generated == null) {
      try {
        generated = properties.createStringPropertyMap("ghidart.L1.helperCalls");
      } catch (ghidra.util.exception.DuplicateNameException e) {
        throw new IllegalStateException(e);
      }
    }
    int recovered = 0;
    var targets = new java.util.HashMap<Address, Contract>();
    for (Function caller : callers) {
      // Body edits and instruction removal can hide old call sites from the
      // instruction iterator. Inspect our namespace facts before visiting code.
      var space = ghidra.program.model.pcode.HighFunction.findOverrideSpace(caller);
      if (space != null) {
        var stale = new ArrayList<Address>();
        var symbols = program.getSymbolTable().getSymbols(space);
        while (symbols.hasNext()) {
          monitor.checkCancelled();
          var symbol = symbols.next();
          Address address = symbol.getAddress();
          String fingerprint = generated.getString(address);
          if (fingerprint == null) {
            continue;
          }
          var signature = DartRuntimeCalls.callSignature(program, caller, address);
          var instruction = program.getListing().getInstructionAt(address);
          if (signature != null && fingerprint.equals(signature.getPrototypeString(true))
              && (!caller.getBody().contains(address) || instruction == null)) {
            stale.add(address);
          }
        }
        for (Address address : stale) {
          clearContract(program, caller, address, generated);
        }
      }
      var instructions = program.getListing().getInstructions(caller.getBody(), true);
      while (instructions.hasNext()) {
        monitor.checkCancelled();
        Instruction call = instructions.next();
        discardShadowedContract(program, caller, call.getAddress(), generated);
        var existing = DartRuntimeCalls.callSignature(program, caller, call.getAddress());
        boolean owned = existing != null
            && existing.getPrototypeString(true).equals(generated.getString(call.getAddress()));
        if (existing != null && !owned) {
          continue;
        }
        if (!call.getFlowType().isCall()) {
          if (owned) {
            clearContract(program, caller, call.getAddress(), generated);
          }
          continue;
        }
        Contract contract = null;
        if (!call.getFlowType().isComputed() && call.getFlows().length == 1) {
          Address target = call.getFlows()[0];
          if (!targets.containsKey(target)) {
            targets.put(target, sharedAt(program, target, monitor));
          }
          contract = targets.get(target);
        }
        boolean threadCall =
            call.getFlowType().isComputed() && targetSlot(program, caller, call) != null;
        if (contract == null && (!call.getFlowType().isComputed() || threadCall)) {
          contract = barrierAt(program, caller, call);
          if (contract == null && threadCall) {
            contract = guardAt(program, caller, call, monitor);
          }
        }
        if (contract == null) {
          if (owned) {
            clearContract(program, caller, call.getAddress(), generated);
          }
          continue;
        }
        String name = contract.name();
        if (owned && name.equals(existing.getCallingConventionName())) {
          continue;
        }
        if (owned) {
          clearContract(program, caller, call.getAddress(), generated);
        }
        if (!caller.getSignatureSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)) {
          continue;
        }
        var arguments = contract.inputs();
        boolean mint = contract.result();
        try {
          String xml = prototype(name, arguments, mint, contract.array(), contract.savedFpu());
          var prior = ghidra.program.database.SpecExtension.getCompilerSpecExtension(
              program, ghidra.program.database.SpecExtension.Type.PROTOTYPE_MODEL, name);
          if (prior != null && !prior.equals(xml)) {
            log.appendMsg("Dart ABI", "Existing helper convention differs: " + name);
            continue;
          }
          if (prior == null) {
            new ghidra.program.database.SpecExtension(program).addReplaceCompilerSpecExtension(
                xml, monitor);
          }
          var signature = new ghidra.program.model.data.FunctionDefinitionDataType(
              name, program.getDataTypeManager());
          signature.setCallingConvention(name);
          signature.setReturnType(mint ? ghidra.program.model.data.Undefined8DataType.dataType
                                       : ghidra.program.model.data.VoidDataType.dataType);
          var parameters = new ArrayList<ghidra.program.model.data.ParameterDefinition>();
          for (String register : arguments) {
            parameters.add(new ghidra.program.model.data.ParameterDefinitionImpl(
                register, ghidra.program.model.data.Undefined8DataType.dataType, null));
          }
          signature.setArguments(
              parameters.toArray(ghidra.program.model.data.ParameterDefinition[] ::new));
          ghidra.program.model.pcode.HighFunctionDBUtil.writeOverride(
              caller, call.getAddress(), signature);
          var written = DartRuntimeCalls.callSignature(program, caller, call.getAddress());
          if (written != null) {
            generated.add(call.getAddress(), written.getPrototypeString(true));
          }
          recovered++;
        } catch (ghidra.util.exception.InvalidInputException | ghidra.framework.store.LockException
            | org.xml.sax.SAXException | ghidra.xml.XmlParseException e) {
          log.appendMsg("Dart ABI",
              "Helper contract rejected at " + call.getAddress() + ": " + e.getMessage());
        }
      }
    }
    return recovered;
  }

  /** Recognized guards, barriers and Mint helpers can relocate an object during
   * GC, but do not replace the caller's spilled object with another class.
   * This is a type-preservation fact, not a claim that its pointer bits or heap
   * fields stay unchanged. Only our unchanged, machine-proved call contracts
   * qualify; arbitrary calls and user-edited overrides do not.
   */
  static boolean preservesSpilledObjectType(Program program, Function caller, Address site) {
    var owned = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L1.helperCalls");
    String saved = owned == null ? null : owned.getString(site);
    if (saved == null) return false;
    var space = ghidra.program.model.pcode.HighFunction.findOverrideSpace(caller);
    int overrides = 0;
    for (var symbol : program.getSymbolTable().getSymbols(site)) {
      if (space != null && symbol.getParentNamespace().equals(space)
          && ghidra.program.model.pcode.HighFunctionDBUtil.readOverride(symbol) != null) overrides++;
    }
    if (overrides != 1) return false;
    var signature = DartRuntimeCalls.callSignature(program, caller, site);
    if (signature == null || !saved.equals(signature.getPrototypeString(true))) return false;
    String name = signature.getCallingConventionName();
    return name != null && (name.equals("__dart_stack_check")
        || name.equals("__dart_array_barrier") || name.startsWith("__dart_barrier_x")
        || name.equals("__dart_mint") || name.equals("__dart_mint_fpu")
        || name.equals("__dart_guard") || name.equals("__dart_guard_fpu"));
  }

  /**
   * Callers of Ghidra's override API may add a second symbol
   * instead of replacing the original. Withdraw only our fingerprinted fact,
   * leaving the other prototype as authoritative rather than choosing by order.
   */
  private static void discardShadowedContract(Program program, Function caller, Address address,
      ghidra.program.model.util.StringPropertyMap generated) {
    String fingerprint = generated.getString(address);
    var space = ghidra.program.model.pcode.HighFunction.findOverrideSpace(caller);
    if (fingerprint == null || space == null) {
      return;
    }
    var owned = new ArrayList<ghidra.program.model.symbol.Symbol>();
    boolean other = false;
    for (var symbol : program.getSymbolTable().getSymbols(address)) {
      if (!symbol.getParentNamespace().equals(space)) {
        continue;
      }
      var value = ghidra.program.model.pcode.HighFunctionDBUtil.readOverride(symbol);
      if (value == null
          || !(value.getDataType()
                   instanceof ghidra.program.model.listing.FunctionSignature signature)) {
        continue;
      }
      if (fingerprint.equals(signature.getPrototypeString(true))) {
        owned.add(symbol);
      } else
        other = true;
    }
    if (other) {
      owned.forEach(ghidra.program.model.symbol.Symbol::delete);
      generated.remove(address);
    }
  }

  /** Remove only our unchanged call-site fact, never a user-edited prototype. */
  private static void clearContract(Program program, Function caller, Address address,
      ghidra.program.model.util.StringPropertyMap generated) {
    var symbol = DartRuntimeCalls.overrideSymbol(program, caller, address);
    if (symbol != null) {
      symbol.delete();
    }
    generated.remove(address);
    boolean automatic = caller.getSignatureSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)
        && caller.getReturn().getSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS);
    for (var parameter : caller.getParameters()) {
      automatic &= parameter.getSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS);
    }
    if (automatic) {
      caller.setSignatureSource(SourceType.DEFAULT);
      try {
        caller.setReturnType(ghidra.program.model.data.DataType.DEFAULT, SourceType.DEFAULT);
      } catch (InvalidInputException e) {
        throw new IllegalStateException(e);
      }
    }
  }

  /**
   * Small generated compiler models, not a separate microcode lifter. The
   * shared variant saves every FPU register; barrier LeafRuntimeScope saves
   * allocatable FPUs and leaves FpuTMP (q31) volatile. Array barrier also uses
   * its slot register x25; Mint's fast path clobbers its x1 temporary.
   */
  private static String prototype(
      String name, List<String> inputs, boolean mint, boolean array, int savedFpu) {
    var xml = new StringBuilder("<prototype name=\"")
                  .append(name)
                  .append("\" extrapop=\"0\" stackshift=\"0\"><input>");
    for (String register : inputs) {
      xml.append("<pentry minsize=\"1\" maxsize=\"8\"><register name=\"")
          .append(register)
          .append("\"/></pentry>");
    }
    // A storage fallback keeps the native model usable for explicit later types.
    xml.append("<pentry minsize=\"1\" maxsize=\"500\" align=\"8\">")
        .append("<addr offset=\"0\" space=\"stack\"/></pentry></input><output>");
    if (mint) {
      xml.append("<pentry minsize=\"1\" maxsize=\"8\"><register name=\"x0\"/></pentry>");
    }
    xml.append("</output><unaffected>");
    for (int register = 0; register < 31; register ++) {
      if (register != 16 && register != 17 && !(mint && register < 2)
          && !(array && register == 25)) {
        xml.append("<register name=\"x").append(register).append("\"/>");
      }
    }
    xml.append("<register name=\"sp\"/>");
    for (int register = 0; register < savedFpu; register ++) {
      xml.append("<register name=\"q").append(register).append("\"/>");
    }
    xml.append("</unaffected><killedbycall><register name=\"x16\"/><register name=\"x17\"/>");
    if (mint) {
      xml.append("<register name=\"x0\"/><register name=\"x1\"/>");
    }
    if (array) {
      xml.append("<register name=\"x25\"/>");
    }
    for (int register = savedFpu; register < 32; register ++) {
      xml.append("<register name=\"q").append(register).append("\"/>");
    }
    return xml.append("</killedbycall></prototype>").toString();
  }

  private static Long targetSlot(Program program, Function function, Instruction call) {
    return DartRuntimeCalls.threadLoad(
        program, DartRuntimeCalls.blockBefore(program, function.getBody(), call), "pc");
  }

  /**
   * StoreBarrier / ArrayStoreBarrier in assembler_arm64.cc.
   * The tag-byte overlap test and x28 mask must guard this exact call. The
   * preceding store identifies the object and distinguishes the array slot;
   * the displacement used to fetch the helper is deliberately irrelevant.
   */
  private static Contract barrierAt(Program program, Function caller, Instruction call) {
    Instruction branch = call.getPrevious();
    for (int distance = 0; distance < 4 && branch != null; distance++) {
      if (mnemonic(branch, "b.eq")) {
        break;
      }
      if (branch.getFlowType().isCall() || branch.getFlowType().isJump()
          || branch.getFlowType().isTerminal()) {
        return null;
      }
      branch = branch.getPrevious();
    }
    if (!mnemonic(branch, "b.eq") || branch.getFlows().length != 1) {
      return null;
    }
    Address done = branch.getFlows()[0];
    // The bypass must land just after CALL (and optional LR restore).
    if (done.compareTo(call.getAddress()) <= 0 || done.subtract(call.getAddress()) > 8) {
      return null;
    }
    var test = branch.getPrevious();
    var overlap = test == null ? null : test.getPrevious();
    var valueTag = overlap == null ? null : overlap.getPrevious();
    var objectTag = valueTag == null ? null : valueTag.getPrevious();
    var store = objectTag == null ? null : objectTag.getPrevious();
    var beforeTags = store;
    Register object = tagBase(objectTag);
    if (object == null || !program.getRegister("x0").equals(tagBase(valueTag))) {
      return null;
    }
    // BranchIfSmi is optional, but must test the stored value and bypass this
    // very call. It cannot be skipped as an arbitrary intervening instruction.
    if (mnemonic(store, "tbz")) {
      if (!registerOperand(store, 0, program, "x0")
          || !Long.valueOf(0).equals(displacement(store, 1)) || store.getFlows().length != 1
          || !done.equals(store.getFlows()[0]) || hasIncoming(program, store)) {
        return null;
      }
      store = store.getPrevious();
    }
    if (store == null
        || !(store == beforeTags ? contiguous(store, objectTag)
                                 : contiguous(store, beforeTags, objectTag))
        || !contiguous(objectTag, valueTag, overlap, test, branch)
        || !caller.getBody().contains(store.getAddress())) {
      return null;
    }
    for (var instruction : List.of(objectTag, valueTag, overlap, test, branch)) {
      if (hasIncoming(program, instruction)) {
        return null;
      }
    }
    if (!mnemonic(overlap, "and") || !sameRegister(overlap, 0, objectTag, 0)
        || !sameRegister(overlap, 1, valueTag, 0) || !sameRegister(overlap, 2, objectTag, 0)
        || !rightShift(overlap, objectTag.getRegister(0).getBaseRegister(), 2)) {
      return null;
    }
    if (!mnemonic(test, "tst") || !sameRegister(test, 0, overlap, 0)
        || !barrierMask(test, program.getRegister("x28"))) {
      return null;
    }
    Register base = pointerStoreBase(program, store, object);
    if (!isStore(store) || !registerOperand(store, 0, program, "x0")
        || (base != null && writesRegister(store, base))) {
      return null;
    }
    boolean array =
        program.getRegister("x25").equals(base) && program.getRegister("x1").equals(object);
    if (array ? !program.getRegister("x1").equals(object) : !object.equals(base)) {
      return null;
    }
    // Nothing between the conditional and CALL may shuffle object/value or
    // create another entry into the slow path. Support the compiler's optional
    // LR spill, followed by the helper-address load, rather than arbitrary code.
    boolean spilledLr = false;
    boolean loadedTarget = false;
    var cursor = branch.getNext();
    while (cursor != null && !cursor.getAddress().equals(call.getAddress())) {
      if (hasIncoming(program, cursor) || !caller.getBody().contains(cursor.getAddress())) {
        return null;
      }
      boolean load = DartRuntimeCalls.threadLoad(program, List.of(cursor), "x30") != null;
      if (load) {
        loadedTarget = true;
      } else {
        if (loadedTarget || spilledLr
            || !stackSave(program, cursor, List.of(program.getRegister("x30")), true)) {
          return null;
        }
        spilledLr = true;
      }
      cursor = cursor.getNext();
    }
    if (cursor == null || hasIncoming(program, call)) {
      return null;
    }
    if (spilledLr != (done.subtract(call.getAddress()) == 8)) {
      return null;
    }
    if (spilledLr
        && !stackSave(program, call.getNext(), List.of(program.getRegister("x30")), false)) {
      return null;
    }
    int index = -1;
    for (int candidate : AVAILABLE) {
      if (program.getRegister("x" + candidate).equals(object)) {
        index = candidate;
      }
    }
    if (index <= 0) {
      return null;
    }
    var inputs = new ArrayList<String>();
    inputs.add("x0");
    if (index != 0) {
      inputs.add("x" + index);
    }
    if (array) {
      inputs.add("x25");
    }
    return new Contract(
        array ? "__dart_array_barrier" : "__dart_barrier_x" + index, inputs, false, array, 31);
  }

  /**
   * CheckStackOverflowInstr + its shared slow path in il_arm64.cc.
   * Identify the guard edge and its exact continuation, not a known THR slot.
   * The compiler chooses the FPU-saving variant whenever FPU values are live,
   * so this call-site contract preserves live FPU values for either variant.
   */
  private static Contract guardAt(Program program, Function caller, Instruction call,
      TaskMonitor monitor) throws CancelledException {
    var continuation = call.getNext();
    if (!mnemonic(continuation, "b") || continuation.getFlows().length != 1) {
      return null;
    }
    Address resume = continuation.getFlows()[0];
    if (!caller.getBody().contains(resume)) {
      return null;
    }
    var prefix = call.getPrevious();
    if (prefix == null || !contiguous(prefix, call, continuation)
        || DartRuntimeCalls.threadLoad(program, List.of(prefix), "x30") == null) {
      return null;
    }
    if (hasIncoming(program, call) || !caller.getBody().contains(prefix.getAddress())) {
      return null;
    }
    var incoming = program.getListing().getInstructions(caller.getBody(), true);
    boolean found = false;
    while (incoming.hasNext()) {
      monitor.checkCancelled();
      var branch = incoming.next();
      if (!List.of(branch.getFlows()).contains(prefix.getAddress())) {
        continue;
      }
      if (!mnemonic(branch, "b.ls") || !resume.equals(branch.getFallThrough())) {
        return null;
      }
      var compare = branch.getPrevious();
      if (!mnemonic(compare, "cmp") || !registerOperand(compare, 0, program, "x15")) {
        return null;
      }
      var limit = compare.getRegister(1);
      var load = compare.getPrevious();
      if (limit == null || !contiguous(load, compare, branch) || !limit.equals(load.getRegister(0))
          || DartRuntimeCalls.threadLoad(program, List.of(load), limit.getName()) == null) {
        return null;
      }
      found = true;
    }
    return found ? new Contract("__dart_stack_check", List.of(), false, false, 32) : null;
  }

  /**
   * GenerateSharedStubGeneric / GenerateSharedStub in stub_code_compiler_arm64.cc.
   * Match actual stack transfers, allowing register-pair order and equivalent
   * addressing encodings; never use a CODE slot to stand in for this proof.
   */
  private static Contract sharedAt(Program program, Address entry, TaskMonitor monitor)
      throws CancelledException {
    try {
      var decoder = new ghidra.app.util.PseudoDisassembler(program);
      var first = decoder.disassemble(entry);
      if (mnemonic(first, "ldp")) {
        Address slow = allocationSlowPath(program, entry, decoder, monitor);
        if (slow == null) {
          return null;
        }
        Contract contract = sharedBody(program, slow, monitor);
        return contract != null && contract.result() ? contract : null;
      }
      return sharedBody(program, entry, monitor);
    } catch (ghidra.program.model.lang.InsufficientBytesException
        | ghidra.program.model.lang.UnknownInstructionException
        | ghidra.program.model.lang.UnknownContextException | IndexOutOfBoundsException e) {
      // A truncated prefix/body is unsupported; no contract is published.
      return null;
    }
  }

  /**
   * TryAllocate followed by GenerateSharedStub. Validate both paths, including
   * the same THR top slot and tagged result. No class ID or Thread offset is
   * assumed. The combined Mint model kills x1 as well as returning x0: the
   * allocation fast path uses x1 even though the slow path restores it.
   */
  private static Address allocationSlowPath(Program program, Address entry,
      ghidra.app.util.PseudoDisassembler decoder, TaskMonitor monitor)
      throws ghidra.program.model.lang.InsufficientBytesException,
             ghidra.program.model.lang.UnknownInstructionException,
             ghidra.program.model.lang.UnknownContextException, CancelledException {
    var code = new ArrayList<Instruction>();
    var block = program.getMemory().getBlock(entry);
    Address cursor = entry;
    for (int count = 0; count < 20 && block != null && block.contains(cursor); count++) {
      monitor.checkCancelled();
      var instruction = decoder.disassemble(cursor);
      if (instruction == null) {
        return null;
      }
      code.add(instruction);
      if (mnemonic(instruction, "ret")) {
        break;
      }
      cursor = cursor.add(instruction.getLength());
    }
    if (code.size() < 9 || !returnsToLr(program, code.getLast())) {
      return null;
    }
    var load = code.get(0);
    var advance = code.get(1);
    // Older TryAllocate keeps x0 untagged until after the header store,
    // advances top in x1 and uses TMP for the limit/header. Newer code
    // advances x0 itself, then subtracts size - tag before initialization.
    boolean untagged = registerOperand(advance, 0, program, "x1");
    String limit = untagged ? "x16" : "x1";
    String top = untagged ? "x1" : "x0";
    String tags = untagged ? "x16" : "x1";
    if (!mnemonic(load, "ldp") || !registerOperand(load, 0, program, "x0")
        || !registerOperand(load, 1, program, limit)
        || !program.getRegister("x26").equals(memoryBase(load, 2))
        || !mnemonic(advance, "add") || !registerOperand(advance, 0, program, top)
        || !registerOperand(advance, 1, program, "x0")
        || advance.getOpObjects(2).length != 1
        || !(advance.getOpObjects(2)[0] instanceof Scalar sizeValue)) {
      return null;
    }
    long size = sizeValue.getSignedValue();
    if (size <= 0 || size % 8 != 0) return null;
    var compare = code.get(2);
    var branch = code.get(3);
    Address slow = code.getLast().getAddress().add(4);
    if (!mnemonic(compare, "cmp") || !registerOperand(compare, 0, program, limit)
        || !registerOperand(compare, 1, program, top) || !mnemonic(branch, "b.ls")
        || branch.getFlows().length != 1 || !slow.equals(branch.getFlows()[0])
        || !block.contains(slow)) {
      return null;
    }
    var store = code.get(4);
    if (!mnemonic(store, "str") || !registerOperand(store, 0, program, top)
        || !program.getRegister("x26").equals(memoryBase(store, 1))
        || !java.util.Objects.equals(displacement(load, 2), displacement(store, 1))) {
      return null;
    }
    for (var instruction : List.of(load, store)) {
      if (writesRegister(instruction, program.getRegister("x26"))) {
        return null;
      }
    }
    int index = 5;
    if (!untagged && !Long.valueOf(size - 1).equals(
        immediateArithmetic(program, code.get(index++), "sub", "x0"))) {
      return null;
    }
    // Header construction can use one or several MOV/MOVK immediates; the
    // particular tag word belongs to the object layout, not the ABI proof.
    if (!mnemonic(code.get(index), "mov")) {
      return null;
    }
    while (index < code.size()
        && (mnemonic(code.get(index), "mov") || mnemonic(code.get(index), "movk"))) {
      var instruction = code.get(index++);
      if (!registerOperand(instruction, 0, program, tags) || instruction.getOpObjects(1).length != 1
          || !(instruction.getOpObjects(1)[0] instanceof Scalar)) {
        return null;
      }
    }
    var header = code.get(index++);
    if (!(mnemonic(header, "str") || mnemonic(header, "stur"))
        || !registerOperand(header, 0, program, tags)
        || !program.getRegister("x0").equals(memoryBase(header, 1))
        || writesRegister(header, program.getRegister("x0"))
        || !Long.valueOf(untagged ? 0 : -1).equals(displacement(header, 1))) {
      return null;
    }
    if (mnemonic(code.get(index), "dmb")) {
      index++;
    }
    if (untagged && !Long.valueOf(1).equals(
        immediateArithmetic(program, code.get(index++), "add", "x0"))) {
      return null;
    }
    return index + 1 == code.size() ? slow : null;
  }

  private static Long immediateArithmetic(
      Program program, Instruction instruction, String operation, String register) {
    if (!mnemonic(instruction, operation) || !registerOperand(instruction, 0, program, register)
        || !registerOperand(instruction, 1, program, register)
        || instruction.getOpObjects(2).length != 1
        || !(instruction.getOpObjects(2)[0] instanceof Scalar scalar)) {
      return null;
    }
    return scalar.getSignedValue();
  }

  /** SDK large offsets and release stores materialize their address in TMP2. */
  private static Register pointerStoreBase(
      Program program, Instruction instruction, Register object) {
    Register base = memoryBase(instruction, 1);
    if (mnemonic(instruction, "stlr") && program.getRegister("x17").equals(base)) {
      var address = instruction.getPrevious();
      if (!contiguous(address, instruction) || hasIncoming(program, instruction)
          || !mnemonic(address, "add") || !registerOperand(address, 0, program, "x17")
          || !object.equals(address.getRegister(1)) || address.getOpObjects(2).length != 1
          || !(address.getOpObjects(2)[0] instanceof Scalar)) {
        return null;
      }
      return object;
    }
    if (base != null || !isStore(instruction)) {
      return base;
    }
    var registers = new ArrayList<Register>();
    for (var operand : instruction.getOpObjects(1)) {
      if (operand instanceof Register register) {
        registers.add(register);
      }
    }
    return registers.size() == 2 && program.getRegister("x17").equals(registers.get(1))
        ? registers.getFirst()
        : null;
  }

  private static Contract sharedBody(Program program, Address entry, TaskMonitor monitor)
      throws CancelledException {
    var block = program.getMemory().getBlock(entry);
    if (block == null || !block.isExecute() || !block.isInitialized()) {
      return null;
    }
    var body = new ArrayList<Instruction>();
    var decoder = new ghidra.app.util.PseudoDisassembler(program);
    Address address = entry;
    try {
      for (int count = 0; count < 128 && block.contains(address); count++) {
        monitor.checkCancelled();
        var instruction = decoder.disassemble(address);
        if (instruction == null
            || instruction.getFlowType().isJump() && !mnemonic(instruction, "ret")) {
          return null;
        }
        for (var op : instruction.getPcode()) {
          if (op.getOpcode() == PcodeOp.CALLOTHER) {
            return null;
          }
        }
        body.add(instruction);
        if (instruction.getFlowType().isTerminal()) {
          break;
        }
        address = address.add(instruction.getLength());
      }
    } catch (ghidra.program.model.lang.InsufficientBytesException
        | ghidra.program.model.lang.UnknownInstructionException
        | ghidra.program.model.lang.UnknownContextException e) {
      return null;
    }
    if (body.isEmpty() || !returnsToLr(program, body.getLast())) {
      return null;
    }
    int index = 0;
    if (!stackSave(program, body.get(index++), List.of(program.getRegister("x30")), true)) {
      return null;
    }
    var saves = new ArrayList<Save>();
    var saved = new java.util.HashSet<Register>();
    int bytes = 0;
    while (index < body.size()) {
      var instruction = body.get(index);
      // Older PushRegisters emits individual Q saves; odd CPU sets also
      // have a single leftover save. Newer SDKs pair the Q registers.
      // Keep the same exact saved set, writeback and inverse-restore proof.
      var first = instruction.getRegister(0);
      List<Register> registers;
      if (mnemonic(instruction, "str") && first != null
          && (first.getNumBytes() == 8 || first.getNumBytes() == 16)) {
        registers = List.of(first);
      } else if (mnemonic(instruction, "stp")) {
        var second = instruction.getRegister(1);
        if (first == null || second == null) return null;
        registers = List.of(first, second);
      } else {
        break;
      }
      if (!stackSave(program, instruction, registers, true)) {
        return null;
      }
      for (var register : registers) {
        if (!saved.add(register)) {
          return null;
        }
      }
      int size = registers.stream().mapToInt(Register::getNumBytes).sum();
      saves.add(new Save(registers, size));
      bytes += size;
      index++;
    }
    var expected = new java.util.HashSet<Register>();
    for (int register : AVAILABLE) {
      expected.add(program.getRegister("x" + register));
    }
    // The separate-heap-base compiler model reserves x23. Its odd CPU set
    // also accounts for the SDK's final single-register push/pop.
    if (program.getCompilerSpec().isGlobal(program.getRegister("x23").getAddress())) {
      expected.remove(program.getRegister("x23"));
    }
    boolean fpu = saved.contains(program.getRegister("q0"));
    if (fpu) {
      for (int register = 0; register < 32; register ++) {
        expected.add(program.getRegister("q" + register));
      }
    }
    if (!saved.equals(expected) || body.size() - index < 12) {
      return null;
    }
    if (DartRuntimeCalls.threadLoad(program, List.of(body.get(index++)), "x24") == null) {
      return null;
    }
    var frame = List.of(program.getRegister("x29"), program.getRegister("x30"));
    if (!stackSave(program, body.get(index++), frame, true)
        || !DartRuntimeCalls.copy(program, body.get(index++), "x29", "x15")) {
      return null;
    }
    boolean result = stackSave(program, body.get(index), List.of(program.getRegister("x22")), true);
    if (result) {
      index++;
    }
    if (DartRuntimeCalls.threadLoad(program, List.of(body.get(index++)), "x5") == null
        || !zero(program, body.get(index++), "x4")) {
      return null;
    }
    var load = body.get(index++);
    var call = body.get(index++);
    if (!call.getFlowType().isCall() || !call.getFlowType().isComputed()
        || DartRuntimeCalls.threadLoad(program, List.of(load, call), "pc") == null) {
      return null;
    }
    if (result) {
      if (!stackSave(program, body.get(index++), List.of(program.getRegister("x0")), false)) {
        return null;
      }
      var store = body.get(index++);
      // Locate saved x0 from the actual prefix order. FP is 16 bytes below it.
      int consumed = 0;
      Long resultOffset = null;
      for (var save : saves) {
        consumed += save.bytes();
        for (int i = 0; i < save.registers().size(); i++) {
          if (save.registers().get(i).equals(program.getRegister("x0"))) {
            resultOffset = (long) bytes - consumed + i * 8 + 16;
          }
        }
      }
      if (!mnemonic(store, "str") || !registerOperand(store, 0, program, "x0")
          || !program.getRegister("x29").equals(memoryBase(store, 1))
          || !java.util.Objects.equals(resultOffset, displacement(store, 1))) {
        return null;
      }
    }
    if (!DartRuntimeCalls.copy(program, body.get(index++), "x15", "x29")
        || !stackSave(program, body.get(index++), frame, false)) {
      return null;
    }
    for (int i = saves.size() - 1; i >= 0; i--) {
      if (index >= body.size()
          || !stackSave(program, body.get(index++), saves.get(i).registers(), false)) {
        return null;
      }
    }
    if (index + 2 != body.size() || !stackChange(program, body.get(index++), 8)) {
      return null;
    }
    return new Contract("__dart_" + (result ? "mint" : "guard") + (fpu ? "_fpu" : ""), List.of(),
        result, false, fpu ? 32 : 0);
  }

  private static boolean writesRegister(Instruction instruction, Register register) {
    for (var operation : instruction.getPcode()) {
      var output = operation.getOutput();
      if (output != null && output.getAddress().equals(register.getAddress())) {
        return true;
      }
    }
    return false;
  }

  private static boolean returnsToLr(Program program, Instruction instruction) {
    // The official decoder omits the implicit x30 operand of the usual RET.
    return mnemonic(instruction, "ret")
        && (instruction.getNumOperands() == 0 || registerOperand(instruction, 0, program, "x30"));
  }

  private static boolean mnemonic(Instruction instruction, String name) {
    return instruction != null && instruction.getMnemonicString().equalsIgnoreCase(name);
  }

  private static boolean registerOperand(
      Instruction instruction, int operand, Program program, String register) {
    var actual = instruction == null ? null : instruction.getRegister(operand);
    return actual != null
        && actual.getBaseRegister().equals(program.getRegister(register).getBaseRegister());
  }

  private static boolean sameRegister(Instruction left, int a, Instruction right, int b) {
    var register = memoryBase(left, a);
    var other = memoryBase(right, b);
    return register != null && other != null
        && register.getBaseRegister().equals(other.getBaseRegister());
  }

  private static Register memoryBase(Instruction instruction, int operand) {
    if (instruction == null || operand >= instruction.getNumOperands()) {
      return null;
    }
    Register base = null;
    for (var object : instruction.getOpObjects(operand)) {
      if (object instanceof Register register) {
        if (base != null) {
          return null;
        }
        base = register;
      }
    }
    return base;
  }

  private static Long displacement(Instruction instruction, int operand) {
    if (instruction == null) {
      return null;
    }
    Long value = 0L;
    for (var object : instruction.getOpObjects(operand)) {
      if (object instanceof Scalar scalar) {
        value = scalar.getSignedValue();
      }
    }
    return value;
  }

  private static Register tagBase(Instruction instruction) {
    if (!mnemonic(instruction, "ldurb") && !mnemonic(instruction, "ldrb")) {
      return null;
    }
    return Long.valueOf(-1).equals(displacement(instruction, 1)) ? memoryBase(instruction, 1)
                                                                 : null;
  }

  private static boolean isStore(Instruction instruction) {
    return mnemonic(instruction, "str") || mnemonic(instruction, "stur")
        || mnemonic(instruction, "stlr");
  }

  /**
   * With a separate barrier mask, BARRIER_MASK was the complete x28 value;
   * newer code uses its upper word in packed HEAP_BITS. Accept these actual
   * arithmetic forms independently of SDK metadata, not arbitrary shifts.
   */
  private static boolean barrierMask(Instruction test, Register mask) {
    if (rightShift(test, mask, 32)) return true;
    for (var op : test.getPcode()) {
      if (op.getOpcode() != PcodeOp.INT_AND) continue;
      for (var input : op.getInputs()) {
        if (input.isRegister() && input.getSize() == 8
            && input.getAddress().equals(mask.getAddress())) return true;
      }
    }
    return false;
  }

  private static boolean rightShift(Instruction instruction, Register register, long amount) {
    if (instruction == null) {
      return false;
    }
    for (var op : instruction.getPcode()) {
      if (op.getOpcode() == PcodeOp.INT_RIGHT && op.getInput(0).isRegister()
          && op.getInput(0).getAddress().equals(register.getAddress())
          && op.getInput(1).isConstant() && op.getInput(1).getOffset() == amount) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasIncoming(Program program, Instruction instruction) {
    var refs = program.getReferenceManager().getReferencesTo(instruction.getAddress());
    while (refs.hasNext()) {
      if (refs.next().getReferenceType().isFlow()) {
        return true;
      }
    }
    return false;
  }

  private static boolean zero(Program program, Instruction instruction, String register) {
    var ops = instruction.getPcode();
    return ops.length == 1 && ops[0].getOpcode() == PcodeOp.COPY
        && ops[0].getOutput().getAddress().equals(program.getRegister(register).getAddress())
        && ops[0].getInput(0).isConstant() && ops[0].getInput(0).getOffset() == 0;
  }

  private static boolean stackSave(
      Program program, Instruction instruction, List<Register> registers, boolean push) {
    if (instruction == null || registers.stream().anyMatch(java.util.Objects::isNull)) {
      return false;
    }
    String name = registers.size() == 2 ? (push ? "stp" : "ldp") : (push ? "str" : "ldr");
    if (!mnemonic(instruction, name)) {
      return false;
    }
    int bytes = 0;
    for (int i = 0; i < registers.size(); i++) {
      if (!registers.get(i).equals(instruction.getRegister(i))) {
        return false;
      }
      bytes += registers.get(i).getNumBytes();
    }
    if (!program.getRegister("x15").equals(memoryBase(instruction, registers.size()))) {
      return false;
    }
    return stackChange(program, instruction, push ? -bytes : bytes, registers, push);
  }

  private static boolean contiguous(Instruction... instructions) {
    for (int i = 0; i < instructions.length; i++) {
      if (instructions[i] == null) {
        return false;
      }
      if (i > 0 && !instructions[i].getAddress().equals(instructions[i - 1].getFallThrough())) {
        return false;
      }
    }
    return true;
  }

  /**
   * Interpret only the instruction's constant VMSP writeback. The official
   * p-code already distinguishes pre/post-index addressing and subregisters.
   */
  private static boolean stackChange(Program program, Instruction instruction, long expected) {
    return mnemonic(instruction, "add") && registerOperand(instruction, 0, program, "x15")
        && registerOperand(instruction, 1, program, "x15")
        && stackChange(program, instruction, expected, List.of(), false);
  }

  private static boolean stackChange(Program program, Instruction instruction, long expected,
      List<Register> registers, boolean push) {
    if (instruction == null) {
      return false;
    }
    var stack = program.getRegister("x15");
    var values = new java.util.HashMap<ghidra.program.model.pcode.Varnode, Long>();
    var root = new ghidra.program.model.pcode.Varnode(stack.getAddress(), 8);
    values.put(root, 0L);
    var sources =
        new java.util
            .HashMap<ghidra.program.model.pcode.Varnode, ghidra.program.model.pcode.Varnode>();
    boolean written = false;
    int accesses = 0;
    long offset = push ? expected : 0;
    for (var op : instruction.getPcode()) {
      if (op.getOpcode() == PcodeOp.STORE || op.getOpcode() == PcodeOp.LOAD) {
        if (accesses >= registers.size() || push != (op.getOpcode() == PcodeOp.STORE)
            || !Long.valueOf(offset).equals(values.get(op.getInput(1)))) {
          return false;
        }
        var register = registers.get(accesses++);
        var data = push ? op.getInput(2) : op.getOutput();
        if (data.getSize() != register.getNumBytes()) {
          return false;
        }
        // STORE must save the named register, not an unrelated value. LOAD
        // destinations may be decoder temporaries before their final COPY.
        if (push && !sources.getOrDefault(data, data).getAddress().equals(register.getAddress())) {
          return false;
        }
        offset += data.getSize();
      }
      var output = op.getOutput();
      if (output == null) {
        continue;
      }
      if (op.getOpcode() == PcodeOp.COPY) {
        sources.put(output, sources.getOrDefault(op.getInput(0), op.getInput(0)));
      } else {
        sources.remove(output);
      }
      Long value = null;
      if (op.getOpcode() == PcodeOp.COPY) {
        value = constantOrOffset(values, op.getInput(0));
      }
      if (op.getOpcode() == PcodeOp.INT_ADD) {
        Long base = constantOrOffset(values, op.getInput(0));
        Long delta = constantOrOffset(values, op.getInput(1));
        if (base != null && delta != null) {
          value = base + delta;
        }
      }
      values.put(output, value);
      written |= output.equals(root);
    }
    return written && accesses == registers.size()
        && Long.valueOf(expected).equals(values.get(root));
  }

  private static Long constantOrOffset(
      java.util.Map<ghidra.program.model.pcode.Varnode, Long> values,
      ghidra.program.model.pcode.Varnode node) {
    return node.isConstant() ? Long.valueOf(node.getOffset()) : values.get(node);
  }
}
