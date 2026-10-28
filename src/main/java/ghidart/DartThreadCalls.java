/**
 * Resolve SDK Thread calls and their distinct register contracts.
 *
 * Snapshot hash and build features select upstream SDK layout facts, not an
 * application address. A matching CODE_REG load and complete NativeArguments
 * proof identify the target function. Bounded p-code data flow then
 * proves a caller's indirect target came from that slot. Only an official call
 * destination reference is added; physical instructions/registers stay intact.
 * Unknown layouts, ambiguous targets and existing call metadata are preserved.
 * RuntimeEntry still requires its actual bridge-body proof. Barrier and shared
 * helper contracts use exact SDK ABI/layout facts and proved target provenance.
 * Unknown helpers/native calls keep the conservative managed fallback.
 */
package ghidart;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Keeps versioned layout facts separate from the ABI's instruction proof. */
final class DartThreadCalls {
  private DartThreadCalls() {}

  // Generated SDK AOT + PRODUCT + ARM64 offsets, selected by exact snapshot
  // hash, OS and pointer mode. Sources: AOT_Thread in compiler/runtime_api.cc and ARM64 stub/compiler ABIs.
  // No nearest-version fallback: unknown/custom SDK layouts remain unresolved.
  private record Shared(long entry, long code, boolean mint, boolean fpu) {}
  private record Layout(String hash, String os, String pointers, long entry, long code,
      long barrier, long arrayBarrier, long wrappers, List<Shared> shared) {}

  private static final List<Layout> LAYOUTS = List.of(
      new Layout("adb4292f3ec25074ca70abcd2d5c7251", "ios", "no-compressed-pointers", 0x258, 0x110,
          0x248, 0x250, 0x638, List.of(
              new Shared(0x288, 0x1c8, false, false),
              new Shared(0x290, 0x1d0, false, true),
              new Shared(0x268, 0x180, true, false),
              new Shared(0x260, 0x178, true, true))),
      new Layout("1ce86630892e2dca9a8543fdb8ed8e22", "android", "compressed-pointers", 0x208, 0xd8,
          0x1f8, 0x200, 0x570, List.of(
              new Shared(0x238, 0x188, false, false),
              new Shared(0x240, 0x190, false, true),
              new Shared(0x218, 0x158, true, false),
              new Shared(0x210, 0x150, true, true))),
      new Layout("78da37fed6bf1489361a312568249f3f", "macos", "no-compressed-pointers", 0x208, 0xd8,
          0x1f8, 0x200, 0x578, List.of(
              new Shared(0x238, 0x188, false, false),
              new Shared(0x240, 0x190, false, true),
              new Shared(0x218, 0x158, true, false),
              new Shared(0x210, 0x150, true, true))));

  /** Known SDK helpers have a different clobber contract from managed Dart.
   * Preserve the opaque CALL and use the official per-call prototype API;
   * no whole-stub inlining or handwritten instruction semantics are needed.
   */
  static int recoverContracts(Program program, List<Function> callers,
      TaskMonitor monitor, MessageLog log) throws CancelledException {
    Layout layout = layout(program);
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
    var sharedTargets = new java.util.HashMap<Address, Shared>();
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
        var existing = DartRuntimeCalls.callSignature(program, caller, call.getAddress());
        boolean owned = existing != null && existing.getPrototypeString(true)
            .equals(generated.getString(call.getAddress()));
        if (existing != null && !owned) continue;
        if (layout == null || !call.getFlowType().isCall()) {
          if (owned) clearContract(program, caller, call.getAddress(), generated);
          continue;
        }
        Long slot = call.getFlowType().isComputed() ? targetSlot(program, caller, call) : null;
        Shared shared = null;
        if (slot != null) {
          for (Shared candidate : layout.shared()) {
            if (slot == candidate.entry()) shared = candidate;
          }
        } else if (!call.getFlowType().isComputed() && call.getFlows().length == 1) {
          Address target = call.getFlows()[0];
          if (!sharedTargets.containsKey(target)) {
            sharedTargets.put(target, sharedAt(program, target, layout, monitor));
          }
          shared = sharedTargets.get(target);
        }
        int object = -1;
        boolean array = slot != null && slot == layout.arrayBarrier();
        if (slot != null && (slot == layout.barrier() || array)) object = 1;
        if (slot != null && slot >= layout.wrappers() && (slot - layout.wrappers()) % 8 == 0) {
          int[] available = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
              19, 20, 23, 24, 25};
          long ordinal = (slot - layout.wrappers()) / 8;
          if (ordinal < available.length) object = available[(int) ordinal];
        }
        if (shared == null && object < 0) {
          if (owned) clearContract(program, caller, call.getAddress(), generated);
          continue;
        }
        String name = shared != null
            ? "__dart_" + (shared.mint() ? "mint" : "guard") + (shared.fpu() ? "_fpu" : "")
            : array ? "__dart_array_barrier" : "__dart_barrier_x" + object;
        if (owned && name.equals(existing.getCallingConventionName())) continue;
        if (owned) clearContract(program, caller, call.getAddress(), generated);
        if (!caller.getSignatureSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)) continue;
        var arguments = new ArrayList<String>();
        if (shared == null) {
          arguments.add("x0");
          if (object != 0) arguments.add("x" + object);
          if (array) arguments.add("x25");
        }
        boolean mint = shared != null && shared.mint();
        int savedFpu = shared == null ? 31 : shared.fpu() ? 32 : 0;
        try {
          String xml = prototype(name, arguments, mint, array, savedFpu);
          var prior = ghidra.program.database.SpecExtension.getCompilerSpecExtension(program,
              ghidra.program.database.SpecExtension.Type.PROTOTYPE_MODEL, name);
          if (prior != null && !prior.equals(xml)) {
            log.appendMsg("Dart ABI", "Existing helper convention differs: " + name);
            continue;
          }
          if (prior == null) {
            new ghidra.program.database.SpecExtension(program)
                .addReplaceCompilerSpecExtension(xml, monitor);
          }
          var signature = new ghidra.program.model.data.FunctionDefinitionDataType(
              name, program.getDataTypeManager());
          signature.setCallingConvention(name);
          signature.setReturnType(mint ? ghidra.program.model.data.Undefined8DataType.dataType
              : ghidra.program.model.data.VoidDataType.dataType);
          var parameters = new ArrayList<ghidra.program.model.data.ParameterDefinition>();
          for (String register : arguments) {
            parameters.add(new ghidra.program.model.data.ParameterDefinitionImpl(register,
                ghidra.program.model.data.Undefined8DataType.dataType, null));
          }
          signature.setArguments(parameters.toArray(ghidra.program.model.data.ParameterDefinition[]::new));
          ghidra.program.model.pcode.HighFunctionDBUtil.writeOverride(caller, call.getAddress(), signature);
          var written = DartRuntimeCalls.callSignature(program, caller, call.getAddress());
          if (written != null) generated.add(call.getAddress(), written.getPrototypeString(true));
          recovered++;
        } catch (ghidra.util.exception.InvalidInputException | ghidra.framework.store.LockException
            | org.xml.sax.SAXException | ghidra.xml.XmlParseException e) {
          log.appendMsg("Dart ABI", "Helper contract rejected at " + call.getAddress() + ": " + e.getMessage());
        }
      }
    }
    return recovered;
  }

  /** Remove only our unchanged call-site fact, never a user-edited prototype. */
  private static void clearContract(Program program, Function caller, Address address,
      ghidra.program.model.util.StringPropertyMap generated) {
    var symbol = DartRuntimeCalls.overrideSymbol(program, caller, address);
    if (symbol != null) symbol.delete();
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

  /** CODE_REG's SDK slot identifies the shared helper; follow only reachable
   * prefix instructions in the named VM image. Fast allocation may RET before
   * a branched slow path loads CODE_REG. No app address/name is a match rule.
   */
  private static Shared sharedAt(Program program, Address entry, Layout layout,
      TaskMonitor monitor) throws CancelledException {
    Address end = null;
    try {
      for (String image : List.of("_kDartVmSnapshotInstructions", "_kDartIsolateSnapshotInstructions")) {
        var symbols = program.getSymbolTable().getGlobalSymbols(image);
        if (symbols.size() != 1 || symbols.getFirst().getSource() != SourceType.IMPORTED) continue;
        Address start = symbols.getFirst().getAddress();
        var block = program.getMemory().getBlock(start);
        long size = program.getMemory().getLong(start);
        if (block != null && block.isExecute() && size >= 64 && size % 16 == 0
            && size <= block.getEnd().subtract(start) + 1
            && entry.compareTo(start.add(64)) >= 0 && entry.compareTo(start.add(size)) < 0) {
          end = start.add(size);
          break;
        }
      }
      if (end == null) return null;
      var decoder = new ghidra.app.util.PseudoDisassembler(program);
      var pending = new java.util.ArrayDeque<Address>();
      var seen = new java.util.HashSet<Address>();
      pending.add(entry);
      Shared result = null;
      while (!pending.isEmpty() && seen.size() < 128) {
        monitor.checkCancelled();
        Address address = pending.removeFirst();
        if (!seen.add(address) || address.compareTo(entry) < 0
            || address.subtract(entry) > 2048 || address.compareTo(end) >= 0) continue;
        Instruction instruction = decoder.disassemble(address);
        if (instruction == null) return null;
        Long code = DartRuntimeCalls.threadLoad(program, List.of(instruction), "x24");
        if (code != null) {
          Shared selected = null;
          for (Shared candidate : layout.shared()) if (code == candidate.code()) selected = candidate;
          if (selected == null || result != null && !result.equals(selected)) return null;
          result = selected;
          continue;
        }
        var flow = instruction.getFlowType();
        if (flow.isCall() || flow.isComputed()) continue;
        if (flow.isJump()) for (Address target : instruction.getFlows()) pending.add(target);
        if (instruction.getFallThrough() != null) pending.add(instruction.getFallThrough());
      }
      return pending.isEmpty() ? result : null;
    } catch (ghidra.program.model.mem.MemoryAccessException
        | ghidra.program.model.lang.UnknownInstructionException
        | ghidra.program.model.lang.InsufficientBytesException
        | ghidra.program.model.lang.UnknownContextException e) {
      return null;
    }
  }

  /** Small generated compiler models, not a separate microcode lifter. The
   * shared variant saves every FPU register; barrier LeafRuntimeScope saves
   * allocatable FPUs and leaves FpuTMP (q31) volatile. Array barrier also uses
   * its slot register x25; Mint's fast path clobbers its x1 temporary.
   */
  private static String prototype(String name, List<String> inputs, boolean mint,
      boolean array, int savedFpu) {
    var xml = new StringBuilder("<prototype name=\"").append(name)
        .append("\" extrapop=\"0\" stackshift=\"0\"><input>");
    for (String register : inputs) {
      xml.append("<pentry minsize=\"1\" maxsize=\"8\"><register name=\"")
          .append(register).append("\"/></pentry>");
    }
    // A storage fallback keeps the native model usable for explicit later types.
    xml.append("<pentry minsize=\"1\" maxsize=\"500\" align=\"8\">")
        .append("<addr offset=\"0\" space=\"stack\"/></pentry></input><output>");
    if (mint) xml.append("<pentry minsize=\"1\" maxsize=\"8\"><register name=\"x0\"/></pentry>");
    xml.append("</output><unaffected>");
    for (int register = 0; register < 31; register++) {
      if (register != 16 && register != 17 && !(mint && register < 2)
          && !(array && register == 25)) xml.append("<register name=\"x").append(register).append("\"/>");
    }
    xml.append("<register name=\"sp\"/>");
    for (int register = 0; register < savedFpu; register++) {
      xml.append("<register name=\"q").append(register).append("\"/>");
    }
    xml.append("</unaffected><killedbycall><register name=\"x16\"/><register name=\"x17\"/>");
    if (mint) xml.append("<register name=\"x0\"/><register name=\"x1\"/>");
    if (array) xml.append("<register name=\"x25\"/>");
    for (int register = savedFpu; register < 32; register++) {
      xml.append("<register name=\"q").append(register).append("\"/>");
    }
    return xml.append("</killedbycall></prototype>").toString();
  }

  static List<Reference> resolve(Program program, List<Function> callers,
      TaskMonitor monitor, MessageLog log) throws CancelledException {
    Layout layout = layout(program);
    if (layout == null) {
      return List.of();
    }
    Function target = null;
    var functions = program.getFunctionManager().getFunctions(true);
    while (functions.hasNext()) {
      monitor.checkCancelled();
      var function = functions.next();
      var first = program.getListing().getInstructionAt(function.getEntryPoint());
      if (first == null || !Long.valueOf(layout.code()).equals(
          DartRuntimeCalls.threadLoad(program, List.of(first), "x24"))
          || DartRuntimeCalls.linearRuntimeBody(program, function).isEmpty()) {
        continue;
      }
      if (target != null) {
        log.appendMsg("Dart ABI", "Ambiguous RuntimeStub targets; THR calls left unresolved.");
        return List.of();
      }
      target = function;
    }
    if (target == null) {
      target = discover(program, layout, monitor, log);
      if (target == null) {
        log.appendMsg("Dart ABI", "SDK Thread layout recognized, but no unique proved RuntimeStub"
            + " is available. THR calls left unresolved.");
        return List.of();
      }
    }
    try {
      DartRuntimeCalls.recover(program, target, monitor);
    } catch (InvalidInputException e) {
      log.appendMsg("Dart ABI", "RuntimeStub preparation rejected: " + e.getMessage());
      return List.of();
    }
    if (!DartPcodeInjectLibrary.RUNTIME_STUB.equals(target.getCallFixup())) {
      return List.of();
    }
    var created = new ArrayList<Reference>();
    try {
      for (var caller : callers) {
        if (!caller.getSignatureSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)) {
          continue;
        }
        var instructions = program.getListing().getInstructions(caller.getBody(), true);
        while (instructions.hasNext()) {
          monitor.checkCancelled();
          var call = instructions.next();
          if (!call.getFlowType().isCall() || !call.getFlowType().isComputed()
              || DartRuntimeCalls.hasOverride(program, caller, call.getAddress())
              || program.getReferenceManager().getFlowReferencesFrom(call.getAddress()).length != 0
              || !Long.valueOf(layout.entry()).equals(targetSlot(program, caller, call))) {
            continue;
          }
          var reference = program.getReferenceManager().addMemoryReference(call.getAddress(),
              target.getEntryPoint(), RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.ANALYSIS, -1);
          program.getReferenceManager().setPrimary(reference, true);
          created.add(reference);
        }
      }
    } catch (CancelledException | RuntimeException e) {
      created.forEach(program.getReferenceManager()::delete);
      throw e;
    }
    log.appendMsg("Dart ABI", created.size() + " THR runtime targets proved at "
        + target.getEntryPoint() + ".");
    return created;
  }

  /** Locate only the ABI bridge, using the SDK image extent and actual semantics. */
  private static Function discover(Program program, Layout layout, TaskMonitor monitor,
      MessageLog log) throws CancelledException {
    var symbols = program.getSymbolTable().getGlobalSymbols("_kDartVmSnapshotInstructions");
    if (symbols.size() != 1 || symbols.getFirst().getSource() != SourceType.IMPORTED) {
      return null;
    }
    var start = symbols.getFirst().getAddress();
    var memory = program.getMemory();
    var block = memory.getBlock(start);
    if (block == null || !block.isInitialized() || !block.isExecute()) {
      return null;
    }
    var decoder = new ghidra.app.util.PseudoDisassembler(program);
    List<Instruction> candidate = List.of();
    try {
      // SDK Image::ImageSize is the first target word; header size is 64 for
      // all selected SDKs. Stay inside this image and the initialized block.
      long size = memory.getLong(start);
      if (size < 64 || size % 16 != 0 || size > block.getEnd().subtract(start) + 1) {
        return null;
      }
      var end = start.add(size);
      for (var address = start.add(64); address.compareTo(end) < 0; address = address.add(4)) {
        monitor.checkCancelled();
        var first = decoder.disassemble(address);
        if (first == null || !Long.valueOf(layout.code()).equals(
            DartRuntimeCalls.threadLoad(program, List.of(first), "x24"))) {
          continue;
        }
        var body = new ArrayList<Instruction>();
        var cursor = first;
        for (int i = 0; i < 256 && cursor != null
            && cursor.getMaxAddress().compareTo(end) < 0; i++) {
          body.add(cursor);
          var flow = cursor.getFlowType();
          if (flow.isTerminal()) {
            break;
          }
          if (flow.isJump()) {
            break;
          }
          cursor = decoder.disassemble(cursor.getAddress().add(cursor.getLength()));
        }
        if (!DartRuntimeCalls.isRuntimeBody(program, body)) {
          continue;
        }
        if (!candidate.isEmpty()) {
          log.appendMsg("Dart ABI", "Ambiguous VM RuntimeStub bodies; no function created.");
          return null;
        }
        candidate = body;
      }
      if (candidate.isEmpty()) {
        return null;
      }
      var range = new ghidra.program.model.address.AddressSet(
          candidate.getFirst().getAddress(), candidate.getLast().getMaxAddress());
      if (program.getFunctionManager().getFunctionsOverlapping(range).hasNext()
          || program.getListing().getInstructions(range, true).hasNext()) {
        return null;
      }
      var symbol = program.getSymbolTable().getPrimarySymbol(range.getMinAddress());
      if (symbol != null && !symbol.getSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)) {
        return null;
      }
      // Only the official loader's undefined snapshot-array placeholder may
      // be cleared. Real data definitions or user/importer types win conflicts.
      var definitions = program.getListing().getDefinedData(range, true);
      while (definitions.hasNext()) {
        var data = definitions.next();
        if (!data.getMinAddress().equals(start)
            || !ghidra.program.model.data.Undefined.isUndefinedArray(data.getDataType())) {
          return null;
        }
      }
      var data = program.getListing().getDefinedDataContaining(range.getMinAddress());
      if (data != null) {
        if (!data.getMinAddress().equals(start)
            || !ghidra.program.model.data.Undefined.isUndefinedArray(data.getDataType())) {
          return null;
        }
        program.getListing().clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), false, monitor);
      }
      var command = new ghidra.app.cmd.disassemble.DisassembleCommand(range.getMinAddress(), range, true);
      command.enableCodeAnalysis(false);
      if (!command.applyTo(program, monitor)) {
        log.appendMsg("Dart ABI", command.getStatusMsg());
        return null;
      }
      var function = program.getFunctionManager().createFunction("DartCallToRuntime",
          range.getMinAddress(), range, SourceType.ANALYSIS);
      log.appendMsg("Dart ABI", "Proved VM RuntimeStub discovered at " + range.getMinAddress() + ".");
      return function;
    } catch (ghidra.program.model.mem.MemoryAccessException
        | ghidra.program.model.lang.InsufficientBytesException
        | ghidra.program.model.lang.UnknownInstructionException
        | ghidra.program.model.lang.UnknownContextException
        | ghidra.program.model.address.AddressOutOfBoundsException
        | ghidra.util.exception.InvalidInputException
        | ghidra.program.database.function.OverlappingFunctionException e) {
      log.appendMsg("Dart ABI", "RuntimeStub discovery rejected: " + e.getMessage());
      return null;
    }
  }

  private static Long targetSlot(Program program, Function function, Instruction call) {
    return DartRuntimeCalls.threadLoad(program,
        DartRuntimeCalls.blockBefore(program, function.getBody(), call), "pc");
  }

  private static Layout layout(Program program) {
    Layout result = null;
    // Read loaded snapshot headers, not external b4a metadata or a filename.
    // Both headers must select the same SDK facts if both are available.
    for (String name : List.of("_kDartVmSnapshotData", "_kDartIsolateSnapshotData")) {
      var symbols = program.getSymbolTable().getGlobalSymbols(name);
      if (symbols.size() != 1) {
        return null;
      }
      Address start = symbols.getFirst().getAddress();
      try {
        var memory = program.getMemory();
        if (memory.getInt(start) != 0xdcdcf5f5 || memory.getLong(start.add(4)) < 52
            || memory.getLong(start.add(12)) != 3) {
          return null;
        }
        byte[] bytes = new byte[32];
        memory.getBytes(start.add(20), bytes);
        String hash = new String(bytes, StandardCharsets.US_ASCII);
        var features = new StringBuilder();
        boolean terminated = false;
        long limit = Math.min(1024, memory.getLong(start.add(4)) + 4 - 52);
        for (int i = 0; i < limit; i++) {
          int b = Byte.toUnsignedInt(memory.getByte(start.add(52 + i)));
          if (b == 0) {
            terminated = true;
            break;
          }
          if (b < 32 || b > 126) {
            return null;
          }
          features.append((char) b);
        }
        if (!terminated) {
          return null;
        }
        Set<String> flags = Set.copyOf(List.of(features.toString().split(" +")));
        if (!flags.containsAll(List.of("product", "arm64"))
            || flags.contains("tsan") || flags.contains("msan") || flags.contains("asan")) {
          return null;
        }
        Layout selected = null;
        for (var candidate : LAYOUTS) {
          if (candidate.hash().equals(hash) && flags.contains(candidate.os())
              && flags.contains(candidate.pointers())
              && !flags.contains(candidate.pointers().equals("compressed-pointers")
                  ? "no-compressed-pointers" : "compressed-pointers")) {
            selected = candidate;
          }
        }
        if (selected == null || result != null && !result.equals(selected)) {
          return null;
        }
        result = selected;
      } catch (ghidra.program.model.mem.MemoryAccessException
          | ghidra.program.model.address.AddressOutOfBoundsException e) {
        return null;
      }
    }
    return result;
  }
}
