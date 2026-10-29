/**
 * Discover Dart functions from machine code, without an AOT index.
 *
 * Confirmed entries and reachable direct calls are stronger evidence than a
 * scanned frame or post-terminator candidate. Candidates never cut a parent's
 * CFG: reachable internal frames are absorbed before ownership is assigned.
 * Ghidra supplies instruction semantics and follows unowned shared tails during
 * decompilation; those tails must not be assigned to one arbitrary function.
 */
package ghidart;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;

/** Opt-in CFG recovery; existing function definitions remain user-controlled. */
public final class DartFunctionAnalyzer extends AbstractAnalyzer {
  public static final String INCOMPLETE_TAG = "Dart: incomplete CFG";
  private static final int OUTSIDE = 1;
  private static final int OWNERSHIP = 2;
  private static final int UNDECODABLE = 4;
  private static final int INDIRECT = 8;
  private static final int BUDGET = 16;
  private static final int FALLTHROUGH_ENTRY = 32;
  private static final String ENTRY_OPTION = "Confirmed entry addresses";
  private static final String SCAN_OPTION = "Scan unreferenced entries";
  private String configuredEntries = "";
  private boolean scanEntries = true;

  public DartFunctionAnalyzer() {
    super("Dart Machine Code Functions", "Recover Dart functions from entries, calls and CFG.",
        AnalyzerType.BYTE_ANALYZER);
    setPriority(AnalysisPriority.DISASSEMBLY.after());
    setSupportsOneTimeAnalysis();
  }

  @Override
  public boolean canAnalyze(Program program) {
    return "AARCH64:LE:64:dart".equals(program.getLanguageID().toString());
  }

  @Override
  public boolean getDefaultEnablement(Program program) {
    // The image can also contain native code. Select a managed code region.
    return false;
  }

  @Override
  public void registerOptions(Options options, Program program) {
    options.registerOption(ENTRY_OPTION, "", null,
        "Optional confirmed database addresses (hex, separated by spaces or commas).");
    options.registerOption(SCAN_OPTION, true, null,
        "Find frame and post-terminator candidates inside the selected managed code region.");
  }

  @Override
  public void optionsChanged(Options options, Program program) {
    configuredEntries = options.getString(ENTRY_OPTION, "").trim();
    scanEntries = options.getBoolean(SCAN_OPTION, true);
  }

  @Override
  public boolean added(Program program, AddressSetView selection, TaskMonitor monitor,
      MessageLog log) throws CancelledException {
    try (var output = new DartAnalysisLog(program, log)) {
      return analyze(program, selection, monitor, output.messages());
    }
  }

  private boolean analyze(Program program, AddressSetView selection, TaskMonitor monitor,
      MessageLog log) throws CancelledException {
    AddressSet region = executableRegion(program, selection);
    AddressSet seeds = new AddressSet();
    if (!configuredEntries.isEmpty()) {
      for (String text : configuredEntries.split("[\\s,]+")) {
        Address entry = program.getAddressFactory().getAddress(text);
        if (entry == null || entry.getOffset() % 4 != 0 || !region.contains(entry)) {
          log.appendMsg(getName(), "Invalid confirmed entry in the selected region: " + text);
          return false;
        }
        seeds.add(entry);
      }
    }
    var functions = program.getFunctionManager().getFunctions(region, true);
    while (functions.hasNext()) {
      monitor.checkCancelled();
      seeds.add(functions.next().getEntryPoint());
    }
    recover(program, seeds, region, scanEntries, monitor, log);
    return true;
  }

  /** Explicit seeds remain useful when the caller already knows entry addresses. */
  public static void recover(Program program, AddressSetView seeds, AddressSetView selectedRegion,
      TaskMonitor monitor, MessageLog log) throws CancelledException {
    recover(program, seeds, selectedRegion, false, monitor, log);
  }

  /** Scanning supplies candidates, never authoritative function boundaries. */
  public static void recover(Program program, AddressSetView seeds, AddressSetView selectedRegion,
      boolean scan, TaskMonitor monitor, MessageLog log) throws CancelledException {
    if (!"AARCH64:LE:64:dart".equals(program.getLanguageID().toString())) {
      throw new IllegalArgumentException("Dart ARM64 language required");
    }
    AddressSet region = executableRegion(program, selectedRegion);
    prepareInstructionSnapshots(program, region, monitor);
    var discovery = new Discovery(program, region, monitor);
    AddressSet callbackBodies = new AddressSet();
    if (scan) {
      callbackBodies = prepareCallbackTables(program, discovery.region, monitor, log);
    }
    discovery.addEntries(seeds);
    if (scan) {
      discovery.candidates.add(scanCandidates(program, discovery.region, monitor));
      // Decode in one bounded official traversal instead of one command for
      // every instruction of a multi-million-instruction AOT image.
      AddressSet starts = new AddressSet(discovery.candidates);
      starts.add(seeds.intersect(discovery.region));
      var command = new DisassembleCommand(starts, discovery.region, true);
      command.enableCodeAnalysis(false);
      command.applyTo(program, monitor);
    }
    // Shared callback bodies enter through the native ABI, not __dart. Keep
    // them labeled, without promoting their prologue to a managed function.
    discovery.candidates.delete(callbackBodies);
    try {
      discovery.run(log);
    } finally {
      if (discovery.switchDecompiler != null) discovery.switchDecompiler.dispose();
    }
  }

  /** Remove only imported instruction-snapshot undefined arrays that block decoding.
   * ELF STT_OBJECT symbols describe storage, not typed data. Keep their labels
   * and bytes, and preserve all other data definitions. No snapshot parsing or
   * external index is needed; discovery remains restricted to the selected region.
   */
  static void prepareInstructionSnapshots(Program program, AddressSetView region,
      TaskMonitor monitor) throws CancelledException {
    for (String name : List.of(
        "_kDartVmSnapshotInstructions", "_kDartIsolateSnapshotInstructions",
        "_kDartSnapshotText")) {
      for (var symbol : program.getSymbolTable().getGlobalSymbols(name)) {
        monitor.checkCancelled();
        if (symbol.getSource() != SourceType.IMPORTED || !symbol.isPrimary()) continue;
        var data = program.getListing().getDefinedDataAt(symbol.getAddress());
        if (data != null && Undefined.isUndefinedArray(data.getDataType())
            && region.intersects(data.getMinAddress(), data.getMaxAddress())) {
          program.getListing().clearCodeUnits(
              data.getMinAddress(), data.getMaxAddress(), false, monitor);
        }
      }
    }
  }

  /** Recognize the SDK's PC-keyed callback table, not arbitrary indirect jumps.
   * SDK 3.9.2 and 3.13.3 both emit ADR x9,self; B shared for each entry.
   * The shared body differs between SDK versions. Its native stack prologue
   * supports identification, but does not prove its ABI or runtime target.
   */
  private static AddressSet prepareCallbackTables(Program program, AddressSet region,
      TaskMonitor monitor, MessageLog log) throws CancelledException {
    AddressSet bodies = new AddressSet();
    AddressSet tables = new AddressSet();
    int count = 0;
    long entries = 0;
    for (var range : new AddressSet(region)) {
      long first = (range.getMinAddress().getOffset() + 3) & ~3L;
      for (Address start = range.getMinAddress().getNewAddress(first);
          start.compareTo(range.getMaxAddress()) <= 0; start = start.add(4)) {
        monitor.checkCancelled();
        Address body = callbackTarget(program, region, start);
        if (body == null || body.compareTo(start) <= 0) continue;
        // Never accept a valid suffix of a damaged or partially selected table.
        // Check preceding bytes even when they lie outside the selection.
        try {
          Address previous = start.subtract(8);
          if (program.getMemory().getInt(previous) == 0x10000009) continue;
          int branch = program.getMemory().getInt(previous.add(4));
          if ((branch & 0xfc000000) == 0x14000000
              && previous.add(4).add(((long) (branch << 6) >> 6) * 4).equals(body)) continue;
        } catch (MemoryAccessException | ghidra.program.model.address.AddressOutOfBoundsException ignored) {
          // A table can begin at the first mapped address.
        }
        long length = body.subtract(start);
        // Require several independent PC keys. No page size, SDK version or
        // platform-specific number of callbacks is built into the recognizer.
        if (length < 64 || length % 8 != 0 || !region.contains(start, body.add(3))) continue;
        Address end = body.subtract(1);
        var nextData = program.getListing().getDefinedDataAfter(start);
        if (program.getListing().getDefinedDataContaining(start) != null) continue;
        if (nextData != null && nextData.getMinAddress().compareTo(end) <= 0) continue;
        if (program.getFunctionManager().getFunctionsOverlapping(
            new AddressSet(start, end)).hasNext()) continue;
        boolean valid = hasNativeCallbackPrologue(program, body);
        for (Address row = start; valid && row.compareTo(body) < 0; row = row.add(8)) {
          monitor.checkCancelled();
          valid = body.equals(callbackTarget(program, region, row));
        }
        if (!valid) continue;
        AddressSet table = new AddressSet(start, end);
        AddressSet starts = new AddressSet();
        for (Address row = start; row.compareTo(body) < 0; row = row.add(8)) {
          monitor.checkCancelled();
          starts.add(row);
          callbackLabel(program, row, "dart_ffi_callback_");
        }
        var command = new DisassembleCommand(starts, table, false);
        command.enableCodeAnalysis(false);
        command.applyTo(program, monitor);
        callbackLabel(program, body, "dart_ffi_callback_shared_");
        program.getBookmarkManager().setBookmark(start, BookmarkType.INFO, "Dart FFI callbacks",
            (length / 8) + " PC-keyed native entries; shared body at " + body
                + ". Runtime callback targets and native ABI are not inferred.");
        tables.add(table);
        bodies.add(body);
        count++;
        entries += length / 8;
        start = end.subtract(3);
      }
    }
    // Exclude table bytes from managed CFG discovery, without resolving any
    // indirect successor or assigning shared code to an arbitrary entry.
    region.delete(tables);
    if (count != 0) {
      log.appendMsg("Dart Machine Code Functions", "Structural FFI callback tables " + count
          + "; native entries " + entries + "; shared bodies " + bodies.getNumAddresses()
          + ". Labeled separately; runtime targets and shared-body CFG remain unresolved.");
    }
    return bodies;
  }

  private static Address callbackTarget(Program program, AddressSetView region, Address row) {
    if (!region.contains(row, row.add(7))) return null;
    try {
      if (program.getMemory().getInt(row) != 0x10000009) return null; // ADR x9, self.
      int branch = program.getMemory().getInt(row.add(4));
      if ((branch & 0xfc000000) != 0x14000000) return null; // B, never BL.
      Address target = row.add(4).add(((long) (branch << 6) >> 6) * 4);
      return region.contains(target) ? target : null;
    } catch (MemoryAccessException | ghidra.program.model.address.AddressOutOfBoundsException e) {
      return null;
    }
  }

  private static boolean hasNativeCallbackPrologue(Program program, Address body) {
    try {
      // SDKs save LR alongside THR or FP on the native stack. The rest of the
      // body changes across versions and is deliberately left to normal analysis.
      return (program.getMemory().getInt(body) & ~31) == (0xa9bf7bfa & ~31);
    } catch (MemoryAccessException e) {
      return false;
    }
  }

  private static void callbackLabel(Program program, Address address, String prefix) {
    try {
      program.getSymbolTable().createLabel(address, prefix + address, SourceType.ANALYSIS);
    } catch (InvalidInputException e) {
      throw new IllegalStateException(e);
    }
  }

  private record Trace(AddressSet body, AddressSet calls, int failure, boolean mayReturn) {
    boolean complete() {
      return failure == 0;
    }
  }

  /** Per-analysis graph; only output provenance persists in the database. */
  private static final class Discovery {
    private final Program program;
    private final AddressSet region;
    private final TaskMonitor monitor;
    private final boolean hasExistingFunctions;
    private final ghidra.program.model.util.StringPropertyMap generated;
    private final LinkedHashSet<Address> entries = new LinkedHashSet<>();
    private final ArrayDeque<Address> pending = new ArrayDeque<>();
    private final LinkedHashSet<Address> scheduled = new LinkedHashSet<>();
    private final LinkedHashSet<Address> noReturns = new LinkedHashSet<>();
    private final AddressSet candidates = new AddressSet();
    private final AddressSet checkedEntries = new AddressSet();
    private final AddressSet switchBranches = new AddressSet();
    private final java.util.HashSet<Address> triedSwitches = new java.util.HashSet<>();
    private ghidra.app.decompiler.DecompInterface switchDecompiler;
    private long switchNanos;
    private int recoveredSwitches;
    private final LinkedHashMap<Address, Trace> traces = new LinkedHashMap<>();

    Discovery(Program program, AddressSet region, TaskMonitor monitor) {
      this.program = program;
      this.region = region;
      this.monitor = monitor;
      hasExistingFunctions = program.getFunctionManager().getFunctionCount() != 0;
      var properties = program.getUsrPropertyManager();
      var previous = properties.getStringPropertyMap("ghidart.L1.functions");
      try {
        generated = previous != null ? previous
            : properties.createStringPropertyMap("ghidart.L1.functions");
      } catch (ghidra.util.exception.DuplicateNameException e) {
        throw new IllegalStateException(e);
      }
    }

    void addEntries(AddressSetView addresses) throws CancelledException {
      var iterator = addresses.getAddresses(true);
      while (iterator.hasNext()) {
        monitor.checkCancelled();
        Address entry = iterator.next();
        if (region.contains(entry) && entry.getOffset() % 4 == 0 && entries.add(entry)) {
          schedule(entry);
        }
      }
    }

    private void schedule(Address entry) {
      if (scheduled.add(entry)) {
        pending.add(entry);
      }
    }

    private void observe(Address entry, Trace trace) {
      traces.put(entry, trace);
      if (trace.complete() && !trace.mayReturn() && entries.contains(entry)
          && noReturns.add(entry)) {
        // A proved trap/no-return callee invalidates its callers' previous
        // fallthrough, including any false absorption of the next function.
        for (var item : traces.entrySet()) {
          if (entries.contains(item.getKey()) && item.getValue().calls().contains(entry)) {
            schedule(item.getKey());
          }
        }
      }
    }

    void run(MessageLog log) throws CancelledException {
      // SDK monomorphic entries branch back to a THR miss trampoline and
      // otherwise fall into the unchecked entry. The payload start is not
      // itself a Dart method entry. Prove the whole shape before splitting it.
      AddressSet misses = new AddressSet();
      var scanned = candidates.getAddresses(true);
      while (scanned.hasNext()) {
        monitor.checkCancelled();
        Address checked = scanned.next();
        Address normal = checkedEntry(checked);
        if (normal != null) {
          checkedEntries.add(checked);
          AddressSet pair = new AddressSet(checked);
          pair.add(normal);
          addEntries(pair);
          misses.add(checked.subtract(8));
        }
      }
      candidates.delete(misses);
      int previousEntries;
      do {
        previousEntries = entries.size();
        while (!pending.isEmpty()) {
          monitor.checkCancelled();
          Address entry = pending.removeFirst();
          scheduled.remove(entry);
          var existing = program.getFunctionManager().getFunctionAt(entry);
          if (existing != null && !canUpdate(existing)) {
            addEntries(callsIn(existing.getBody()));
          } else {
            Trace trace = resolveSwitches(entry, trace(entry));
            observe(entry, trace);
            // A confirmed entry proves reachable instructions even if a later
            // indirect edge remains unknown. Their direct calls are evidence.
            addEntries(trace.calls());
          }
        }
        for (Address noReturn : noReturns) {
          var references = program.getReferenceManager().getReferencesTo(noReturn);
          while (references.hasNext()) {
            var reference = references.next();
            if (reference.getReferenceType().isCall()) {
              Address next = reference.getFromAddress().add(4);
              if (region.contains(next, next.add(3))) {
                try {
                  int word = program.getMemory().getInt(next);
                  // A no-return sentinel is not the next function. The normal
                  // terminal scan already resumes after trap/alignment padding.
                  if (word != 0 && word != 0xd503201f
                      && (word & 0xffe0001f) != 0xd4200000) candidates.add(next);
                } catch (MemoryAccessException ignored) {
                  // The selected region may have become unreadable.
                }
              }
            }
          }
        }
        // Do not re-walk every suffix/internal frame of an already traversed
        // CFG. A later direct call still promotes that entry and reopens it.
        AddressSet covered = new AddressSet();
        for (var item : traces.entrySet()) {
          if (entries.contains(item.getKey())) {
            covered.add(item.getValue().body());
          }
        }
        var iterator = candidates.getAddresses(true);
        while (iterator.hasNext()) {
          monitor.checkCancelled();
          Address entry = iterator.next();
          if (!entries.contains(entry) && !covered.contains(entry)) {
            if (requiresCallerFrame(entry)) {
              continue;
            }
            Address tail = allocationThunk(entry);
            if (tail != null) addEntries(new AddressSet(tail));
            Trace trace = resolveSwitches(entry, trace(entry));
            traces.put(entry, trace);
            if (usable(entry, trace)) {
              covered.add(trace.body());
              addEntries(trace.calls());
            }
          }
        }
      } while (!pending.isEmpty() || previousEntries != entries.size());

      // Recompute with settled direct-call boundaries; discovery order cannot
      // make the same explicit tail jump swallow a function in one run only.
      AddressSet owned = new AddressSet();
      var existing = program.getFunctionManager().getFunctions(region, true);
      while (existing.hasNext()) {
        owned.add(existing.next().getBody());
      }
      for (Address entry : entries) {
        var function = program.getFunctionManager().getFunctionAt(entry);
        if (function == null || canUpdate(function)) {
          Trace trace = trace(entry);
          traces.put(entry, trace);
          owned.add(trace.body());
        }
      }
      AddressSet interiors = new AddressSet();
      for (var item : traces.entrySet()) {
        if (!entries.contains(item.getKey()) && usable(item.getKey(), item.getValue())
            && !owned.contains(item.getKey())) {
          AddressSet nested = item.getValue().body().intersect(candidates);
          nested.delete(item.getKey(), item.getKey());
          interiors.add(nested);
        }
      }
      var accepted = new LinkedHashMap<Address, AddressSet>();
      int unresolved = 0;
      int internal = 0;
      for (var item : traces.entrySet()) {
        Address entry = item.getKey();
        if (!entries.contains(entry) && (owned.contains(entry) || interiors.contains(entry))) {
          internal++;
          continue;
        }
        if (!usable(entry, item.getValue())) {
          unresolved++;
          continue;
        }
        accepted.put(entry, item.getValue().body());
      }
      AddressSet claimed = new AddressSet();
      AddressSet shared = new AddressSet();
      for (AddressSet body : accepted.values()) {
        shared.add(claimed.intersect(body));
        claimed.add(body);
      }
      int created = 0;
      int partial = 0;
      for (var item : accepted.entrySet()) {
        monitor.checkCancelled();
        Address entry = item.getKey();
        AddressSet body = item.getValue().subtract(shared);
        var previous = program.getFunctionManager().getFunctionAt(entry);
        boolean conflict = previous != null && !canUpdate(previous);
        var overlaps = program.getFunctionManager().getFunctionsOverlapping(body);
        while (overlaps.hasNext()) {
          conflict |= !overlaps.next().getEntryPoint().equals(entry);
        }
        if (!body.contains(entry) || conflict) {
          unresolved++;
          continue;
        }
        // Finish cancellable proof work before publishing a new function.
        boolean tailCalls = traces.get(entry).complete() && threadTails(item.getValue());
        monitor.checkCancelled();
        try {
          // Do not use CreateFunctionCmd: its thunk inference can create an
          // unvalidated target. Shared instructions stay decoded and unowned;
          // the native decompiler follows them in each caller's frame context.
          var function = previous;
          if (function == null) {
            function = program.getFunctionManager().createFunction(
                null, entry, body, SourceType.ANALYSIS);
          } else {
            function.setBody(body);
          }
          if (traces.get(entry).complete()) {
            function.setNoReturn(!traces.get(entry).mayReturn());
          }
          if (checkedEntries.contains(entry)) {
            function.addTag("Dart: checked entry");
          }
          if (tailCalls) {
            var instructions = program.getListing().getInstructions(item.getValue(), true);
            while (instructions.hasNext()) {
              var instruction = instructions.next();
              if (instruction.getFlowType().isComputed() && instruction.getFlowType().isJump()
                  && !switchBranches.contains(instruction.getAddress())
                  && instruction.getFlowOverride() == FlowOverride.NONE) {
                instruction.setFlowOverride(FlowOverride.CALL_RETURN);
              }
            }
          }
          if (!traces.get(entry).complete()) {
            function.addTag(INCOMPLETE_TAG);
            program.getBookmarkManager().setBookmark(entry, BookmarkType.WARNING, "Dart CFG",
                "Unresolved indirect successor; this function's CFG is incomplete.");
            partial++;
          } else {
            function.removeTag(INCOMPLETE_TAG);
            var bookmark = program.getBookmarkManager().getBookmark(
                entry, BookmarkType.WARNING, "Dart CFG");
            if (bookmark != null) program.getBookmarkManager().removeBookmark(bookmark);
          }
          generated.add(entry, fingerprint(function));
          if (previous == null) {
            created++;
          }
        } catch (InvalidInputException | OverlappingFunctionException e) {
          unresolved++;
        }
      }
      log.appendMsg("Dart Machine Code Functions", "Created " + created + "; internal candidates "
          + internal + "; partial CFG " + partial + "; unresolved/conflicting " + unresolved + "; shared bytes "
          + shared.getNumAddresses() + "; native switches " + recoveredSwitches + "; proved no-return " + noReturns.size() + ". No snapshot or b4a index was read.");
    }

    /** Only revise our untouched output. Names, signatures, bodies or no-return
     * edits made by the user/importer revoke ownership of that function.
     */
    private boolean canUpdate(ghidra.program.model.listing.Function function) {
      return function.getSymbol().getSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)
          && function.getSignatureSource().isLowerOrEqualPriorityThan(SourceType.ANALYSIS)
          && fingerprint(function).equals(generated.getString(function.getEntryPoint()));
    }

    private String fingerprint(ghidra.program.model.listing.Function function) {
      var value = new StringBuilder(function.getName()).append(':').append(function.hasNoReturn());
      for (var range : function.getBody()) {
        value.append(';').append(range.getMinAddress()).append('-').append(range.getMaxAddress());
      }
      return value.toString();
    }

    private AddressSet callsIn(AddressSetView body) throws CancelledException {
      AddressSet calls = new AddressSet();
      var instructions = program.getListing().getInstructions(body, true);
      while (instructions.hasNext()) {
        monitor.checkCancelled();
        Instruction instruction = instructions.next();
        if (region.contains(instruction.getAddress())) {
          collectCalls(instruction, calls);
        }
      }
      return calls;
    }

    private Trace trace(Address entry) throws CancelledException {
      AddressSet body = new AddressSet();
      AddressSet calls = new AddressSet();
      var work = new ArrayDeque<Address>();
      work.add(entry);
      int failure = 0;
      boolean mayReturn = false;
      int count = 0;
      while (!work.isEmpty()) {
        monitor.checkCancelled();
        Address address = work.removeFirst();
        if (body.contains(address)) {
          continue;
        }
        if (++count > 100000) {
          return new Trace(body, calls, failure | BUDGET, true);
        }
        if (address.getOffset() % 4 != 0 || !region.contains(address, address.add(3))) {
          failure |= OUTSIDE;
          continue;
        }
        var owner = hasExistingFunctions
            ? program.getFunctionManager().getFunctionContaining(address) : null;
        if (!address.equals(entry) && (entries.contains(address)
            || owner != null && owner.getEntryPoint().equals(address))) {
          failure |= FALLTHROUGH_ENTRY;
          mayReturn = true;
          continue;
        }
        if (owner != null && !owner.getEntryPoint().equals(entry)) {
          failure |= OWNERSHIP;
          continue;
        }
        Instruction instruction = program.getListing().getInstructionAt(address);
        if (instruction == null) {
          var command = new DisassembleCommand(address,
              new AddressSet(address, address.add(3)), false);
          command.enableCodeAnalysis(false);
          command.applyTo(program, monitor);
          instruction = program.getListing().getInstructionAt(address);
        }
        if (instruction == null) {
          failure |= UNDECODABLE;
          continue;
        }
        body.add(instruction.getMinAddress(), instruction.getMaxAddress());
        var flow = instruction.getFlowType();
        boolean trap = instruction.getMnemonicString().equalsIgnoreCase("brk");
        if (flow.isJump() && !trap) {
          if ((flow.isComputed() && !switchBranches.contains(address))
              || instruction.getFlows().length == 0) {
            failure |= INDIRECT;
          } else {
            for (Address target : instruction.getFlows()) {
              if (target.equals(entry) || (!entries.contains(target)
                  && (!hasExistingFunctions
                      || program.getFunctionManager().getFunctionAt(target) == null))) {
                work.add(target);
              } else if (!noReturns.contains(target)) {
                var callee = program.getFunctionManager().getFunctionAt(target);
                mayReturn |= callee == null || !callee.hasNoReturn();
              }
            }
          }
        }
        // SDK Stop/Breakpoint terminates generated Dart paths, including the
        // sentinel after a runtime call that must not return. Ghidra models a
        // debugger-resumable BRK with fallthrough; that is wrong for AOT CFG.
        mayReturn |= flow.isTerminal() && !flow.isJump() && !flow.isCall() && !trap;
        collectCalls(instruction, calls);
        boolean noReturn = false;
        if (flow.isCall() && instruction.getFlows().length == 1) {
          var callee = program.getFunctionManager().getFunctionAt(instruction.getFlows()[0]);
          noReturn = noReturns.contains(instruction.getFlows()[0])
              || (callee != null && callee.hasNoReturn());
        }
        if (!trap && !noReturn && instruction.getFallThrough() != null) {
          work.add(instruction.getFallThrough());
        }
      }
      if ((failure & ~(INDIRECT | FALLTHROUGH_ENTRY)) == 0) {
        // Only a stack-neutral prefix can fall into a separately known entry.
        if (frameFree(body)) {
          failure &= ~FALLTHROUGH_ENTRY;
        }
        if ((failure & INDIRECT) != 0 && threadTails(body)) {
          failure &= ~INDIRECT;
          mayReturn = true;
        }
      }
      return new Trace(body, calls, failure, mayReturn);
    }

    /** Reuse the official switch engine before weak entries acquire ownership.
     * An UndefinedFunction is a decompiler view, not a database mutation. Only
     * complete tables inside the selected code region become flow facts; no
     * pattern, object-pool layout or application addresses are duplicated here.
     */
    private Trace resolveSwitches(Address entry, Trace trace) throws CancelledException {
      if (trace.failure() != INDIRECT || !usable(entry, trace)
          || !triedSwitches.add(entry) || switchNanos >= 60_000_000_000L) {
        return trace;
      }
      if (switchDecompiler == null) {
        switchDecompiler = new ghidra.app.decompiler.DecompInterface();
        new ghidra.app.plugin.core.analysis.SwitchAnalysisDecompileConfigurer(program)
            .configure(switchDecompiler);
        if (!switchDecompiler.openProgram(program)) {
          switchNanos = Long.MAX_VALUE;
          return trace;
        }
      }
      var candidate = new ghidra.util.UndefinedFunction(program, entry);
      candidate.setBody(trace.body());
      long started = System.nanoTime();
      var result = switchDecompiler.decompileFunction(candidate, 5, monitor);
      switchNanos += System.nanoTime() - started;
      monitor.checkCancelled();
      if (!result.decompileCompleted() || result.getHighFunction() == null) {
        return trace;
      }
      boolean changed = false;
      for (var table : result.getHighFunction().getJumpTables()) {
        Address branch = table.getSwitchAddress();
        Address[] targets = table.getCases();
        if (!trace.body().contains(branch) || targets == null || targets.length == 0) {
          continue;
        }
        AddressSet destinations = new AddressSet();
        boolean valid = true;
        for (Address target : targets) {
          valid &= target.getOffset() % 4 == 0 && region.contains(target, target.add(3));
          var owner = hasExistingFunctions
              ? program.getFunctionManager().getFunctionContaining(target) : null;
          valid &= owner == null || owner.getEntryPoint().equals(entry);
          destinations.add(target);
        }
        var references = program.getReferenceManager().getFlowReferencesFrom(branch);
        for (var reference : references) {
          valid &= destinations.contains(reference.getToAddress());
        }
        if (!valid) {
          continue;
        }
        var decode = new DisassembleCommand(destinations, region, true);
        decode.enableCodeAnalysis(false);
        decode.applyTo(program, monitor);
        monitor.checkCancelled();
        for (Address target : targets) {
          valid &= program.getListing().getInstructionAt(target) != null;
        }
        if (!valid) {
          continue;
        }
        for (Address target : targets) {
          program.getReferenceManager().addMemoryReference(branch, target,
              ghidra.program.model.symbol.RefType.COMPUTED_JUMP, SourceType.ANALYSIS, -1);
        }
        switchBranches.add(branch);
        recoveredSwitches++;
        changed = true;
      }
      if (changed) {
        switchDecompiler.flushCache();
        return trace(entry);
      }
      return trace;
    }

    private boolean usable(Address entry, Trace trace) {
      // Keep known functions visible when only a successor is unresolved, but
      // never report that CFG as complete. An unreferenced partial candidate
      // additionally needs the SDK's concrete managed-frame evidence.
      return trace.complete() || (trace.failure() == INDIRECT
          && (entries.contains(entry) || isFrame(entry)));
    }

    private boolean isFrame(Address entry) {
      var range = region.getRangeContaining(entry);
      if (range == null || range.getMaxAddress().subtract(entry) < 7) {
        return false;
      }
      try {
        int next = program.getMemory().getInt(entry.add(4));
        return program.getMemory().getInt(entry) == 0xa9bf79fd
            && (next == 0xaa0f03fd || next == 0x910001fd);
      } catch (MemoryAccessException e) {
        return false;
      }
    }

    /** assembler_arm64.cc: GenerateMonomorphicCheckedEntryJIT/AOT. */
    private Address checkedEntry(Address entry) {
      var range = region.getRangeContaining(entry);
      if (range == null || entry.subtract(range.getMinAddress()) < 8
          || range.getMaxAddress().subtract(entry) < 19) {
        return null;
      }
      var listing = program.getListing();
      var loadMiss = listing.getInstructionAt(entry.subtract(8));
      var miss = listing.getInstructionAt(entry.subtract(4));
      var header = listing.getInstructionAt(entry);
      var cid = listing.getInstructionAt(entry.add(4));
      var compare = listing.getInstructionAt(entry.add(8));
      var branch = listing.getInstructionAt(entry.add(12));
      if (loadMiss == null || miss == null || header == null || cid == null
          || compare == null || branch == null) {
        return null;
      }
      if (!miss.getMnemonicString().equalsIgnoreCase("br") || !register(miss, 0, "x16")
          || DartRuntimeCalls.threadLoad(program, List.of(loadMiss), "x16") == null) {
        return null;
      }
      boolean receiver = false;
      boolean tag = false;
      for (Object object : header.getOpObjects(1)) {
        if (object instanceof ghidra.program.model.lang.Register value) {
          if (!value.getBaseRegister().equals(program.getRegister("x0"))) {
            return null;
          }
          receiver = true;
        } else if (object instanceof ghidra.program.model.scalar.Scalar value) {
          tag = value.getSignedValue() == -1;
        }
      }
      if (!header.getMnemonicString().equalsIgnoreCase("ldur")
          || !register(header, 0, "x16") || !receiver || !tag
          || !cid.getMnemonicString().equalsIgnoreCase("ubfx")
          || !register(cid, 0, "x16") || !register(cid, 1, "x16")
          || cid.getScalar(2) == null || cid.getScalar(2).getUnsignedValue() != 12
          || cid.getScalar(3) == null || cid.getScalar(3).getUnsignedValue() != 20
          || !compare.getMnemonicString().equalsIgnoreCase("cmp")
          || !register(compare, 0, "x5") || !register(compare, 1, "x16")
          || !branch.getMnemonicString().equalsIgnoreCase("b.ne")
          || branch.getFlows().length != 1
          || !branch.getFlows()[0].equals(entry.subtract(8))) {
        return null;
      }
      // The CID is tagged for comparison with the Smi cache key in x5.
      boolean tagged = false;
      for (Object object : compare.getOpObjects(1)) {
        if (object instanceof ghidra.program.model.scalar.Scalar value) {
          tagged = value.getUnsignedValue() == 1;
        }
      }
      try {
        // The shifted-register operand is composite in Ghidra (getRegister
        // and getScalar return null). ARM64 shift bits distinguish LSL/LSR.
        return tagged && (program.getMemory().getInt(compare.getAddress()) & 0x00c00000) == 0
            ? entry.add(16) : null;
      } catch (MemoryAccessException e) {
        return null;
      }
    }

    private boolean register(Instruction instruction, int operand, String name) {
      boolean found = false;
      for (Object object : instruction.getOpObjects(operand)) {
        if (object instanceof ghidra.program.model.lang.Register value) {
          if (!value.getBaseRegister().equals(program.getRegister(name))) {
            return false;
          }
          found = true;
        }
      }
      return found;
    }

    /** A cold/exception block can restore an already established FP without
     * any incoming machine-code edge. It is not an independent entry merely
     * because it follows RET/B. Explicit calls/seeds take precedence; weak
     * candidates must not consume a frame that they have not established.
     */
    private boolean requiresCallerFrame(Address entry) throws CancelledException {
      if (isFrame(entry)) {
        return false;
      }
      var frame = program.getRegister("x29");
      var pending = new ArrayDeque<Address>();
      var seen = new java.util.HashSet<Address>();
      pending.add(entry);
      while (!pending.isEmpty() && seen.size() < 256) {
        monitor.checkCancelled();
        Address cursor = pending.removeFirst();
        if (!seen.add(cursor) || !region.contains(cursor)
            || !cursor.equals(entry) && entries.contains(cursor)) continue;
        // Frameless fast paths may enter a real frame only in their cold
        // boxing/throw path. Saving FP there is not an inherited-frame read.
        if (isFrame(cursor)) continue;
        var instruction = program.getListing().getInstructionAt(cursor);
        if (instruction == null) continue;
        boolean established = false;
        for (var op : instruction.getPcode()) {
          for (int i = 0; i < op.getNumInputs(); i++) {
            // Saving the caller's FP as a value is normal EnterFrame behavior;
            // using it to address a local/restore VMSP needs an inherited frame.
            if (op.getOpcode() == PcodeOp.STORE && i == 2) continue;
            var input = op.getInput(i);
            if (input.isRegister() && input.getAddress().equals(frame.getAddress())) return true;
          }
          var output = op.getOutput();
          established |= output != null && output.isRegister()
              && output.getAddress().equals(frame.getAddress());
        }
        if (established) continue;
        if (instruction.getFlowType().isJump()) {
          for (Address target : instruction.getFlows()) pending.add(target);
        }
        if (instruction.getFallThrough() != null) pending.add(instruction.getFallThrough());
      }
      return false;
    }

    private Address allocationThunk(Address entry) throws CancelledException {
      Address cursor = entry;
      ghidra.program.model.lang.Register materialized = null;
      for (int count = 0; count < 8; count++) {
        monitor.checkCancelled();
        Instruction instruction = program.getListing().getInstructionAt(cursor);
        if (instruction == null) {
          return null;
        }
        var flow = instruction.getFlowType();
        if (flow.isJump()) {
          Address[] targets = instruction.getFlows();
          if (materialized == null || flow.isComputed() || flow.isConditional()
              || targets.length != 1 || !region.contains(targets[0])) {
            return null;
          }
          return allocationHelper(targets[0], materialized) ? targets[0] : null;
        }
        if (flow.isCall() || flow.isTerminal()) {
          return null;
        }
        for (var op : instruction.getPcode()) {
          switch (op.getOpcode()) {
            case PcodeOp.LOAD, PcodeOp.STORE, PcodeOp.CALL, PcodeOp.CALLIND,
                PcodeOp.CALLOTHER, PcodeOp.RETURN -> {
              return null;
            }
          }
          if (writesFrame(op)) {
            return null;
          }
          for (var input : op.getInputs()) {
            if (input.isRegister()) {
              var register = program.getRegister(input);
              if (register == null || materialized == null
                  || !register.getBaseRegister().equals(materialized)) {
                return null;
              }
            }
          }
          var output = op.getOutput();
          if (output != null && output.isRegister()) {
            var physical = program.getRegister(output);
            if (physical == null) {
              return null;
            }
            var register = physical.getBaseRegister();
            if (materialized != null && !materialized.equals(register)) {
              return null;
            }
            materialized = register;
          }
        }
        if (instruction.getFallThrough() == null) {
          return null;
        }
        cursor = instruction.getFallThrough();
      }
      return null;
    }

    /** Prove a constant-tag allocation wrapper, not an arbitrary branch/join.
     * SDK GenerateAllocateObjectHelper extracts size from that tag, loads
     * Thread::top into x0 and stores the advanced pointer into the same slot.
     * No Thread offset, CID, object size or app-specific immediate is assumed.
     */
    private boolean allocationHelper(Address target,
        ghidra.program.model.lang.Register tags) throws CancelledException {
      var prefix = new java.util.ArrayList<Instruction>();
      Address cursor = target;
      Long top = null;
      var tagValues = new java.util.HashSet<ghidra.program.model.lang.Register>();
      tagValues.add(tags.getBaseRegister());
      ghidra.program.model.lang.Register advanced = null;
      for (int count = 0; count < 12; count++) {
        monitor.checkCancelled();
        Instruction instruction = program.getListing().getInstructionAt(cursor);
        if (instruction == null) {
          return false;
        }
        if (count == 0 && !java.util.Arrays.asList(instruction.getInputObjects()).contains(tags)) {
          return false;
        }
        // Track size derived from the wrapper's tag register. The new top
        // must actually be x0 + that size, not an arbitrary value stored in THR.
        boolean derivesTag = false;
        for (Object input : instruction.getInputObjects()) {
          if (input instanceof ghidra.program.model.lang.Register register) {
            derivesTag |= tagValues.contains(register.getBaseRegister());
          }
        }
        var destination = instruction.getRegister(0);
        var size = instruction.getNumOperands() > 2 ? instruction.getRegister(2) : null;
        boolean advancesTop = top != null && instruction.getMnemonicString().equalsIgnoreCase("add")
            && register(instruction, 1, "x0") && size != null
            && tagValues.contains(size.getBaseRegister());
        for (Object output : instruction.getResultObjects()) {
          if (output instanceof ghidra.program.model.lang.Register register) {
            var base = register.getBaseRegister();
            tagValues.remove(base);
            if (base.equals(advanced)) advanced = null;
            if (derivesTag) tagValues.add(base);
          }
        }
        if (advancesTop && destination != null) advanced = destination.getBaseRegister();
        prefix.add(instruction);
        if (top == null) top = DartRuntimeCalls.threadLoad(program, prefix, "x0");
        if (top != null) {
          for (var op : instruction.getPcode()) {
            if (op.getOpcode() != PcodeOp.STORE || op.getInput(2).getSize() != 8) {
              continue;
            }
            var objects = instruction.getOpObjects(instruction.getNumOperands() - 1);
            Long offset = null;
            boolean thread = false;
            boolean otherRegister = false;
            for (Object object : objects) {
              if (object instanceof ghidra.program.model.lang.Register register) {
                thread |= register.equals(program.getRegister("x26"));
                otherRegister |= !register.equals(program.getRegister("x26"));
              } else if (object instanceof ghidra.program.model.scalar.Scalar scalar) {
                offset = scalar.getSignedValue();
              }
            }
            var stored = instruction.getRegister(0);
            if (thread && !otherRegister && top.equals(offset) && advanced != null
                && stored != null && stored.getBaseRegister().equals(advanced)) {
              return true;
            }
          }
        }
        if (instruction.getFallThrough() == null || instruction.getFlowType().isCall()) {
          return false;
        }
        cursor = instruction.getFallThrough();
      }
      return false;
    }

    private boolean writesFrame(PcodeOp op) {
      var output = op.getOutput();
      if (output == null || !output.isRegister()) {
        return false;
      }
      for (String name : new String[] {"x15", "x29", "x30", "sp"}) {
        var register = program.getRegister(name);
        if (new AddressSet(output.getAddress(), output.getAddress().add(output.getSize() - 1))
            .intersects(register.getAddress(), register.getAddress().add(register.getNumBytes() - 1))) {
          return true;
        }
      }
      return false;
    }

    private boolean frameFree(AddressSetView body) throws CancelledException {
      var instructions = program.getListing().getInstructions(body, true);
      while (instructions.hasNext()) {
        monitor.checkCancelled();
        for (var op : instructions.next().getPcode()) {
          if (writesFrame(op)) {
            return false;
          }
        }
      }
      return true;
    }

    private boolean threadTails(AddressSetView body) throws CancelledException {
      var instructions = program.getListing().getInstructions(body, true);
      boolean found = false;
      boolean frameless = frameFree(body);
      while (instructions.hasNext()) {
        monitor.checkCancelled();
        Instruction instruction = instructions.next();
        if (instruction.getFlowType().isJump() && instruction.getFlowType().isComputed()
            && !switchBranches.contains(instruction.getAddress())
            && !instruction.getMnemonicString().equalsIgnoreCase("brk")) {
          if (balancedTail(instruction, body)) {
            found = true;
            continue;
          }
          if (!frameless) {
            return false;
          }
          var target = instruction.getRegister(0);
          var previous = instruction.getPrevious();
          if (target == null || previous == null || !body.contains(previous.getAddress())
              || !instruction.getAddress().equals(previous.getFallThrough())) {
            return false;
          }
          var refs = program.getReferenceManager().getReferencesTo(instruction.getAddress());
          while (refs.hasNext()) {
            if (refs.next().getReferenceType().isFlow()) {
              return false;
            }
          }
          if (DartRuntimeCalls.threadLoad(program, List.of(previous), target.getName()) == null
              && !poolTail(previous, target, body)) {
            return false;
          }
          found = true;
        }
      }
      return found;
    }

    /** AOT code-object tail entry: PP -> CODE_REG -> one of Code's four
     * cached entry-point words. This proves a call role, never the callee's
     * address/signature. Normal/monomorphic/unchecked fields share this ABI;
     * pool indices and target registers are not tied to an application.
     */
    private boolean poolTail(Instruction load, ghidra.program.model.lang.Register target,
        AddressSetView body) {
      var result = load.getRegister(0);
      if (!load.getMnemonicString().equalsIgnoreCase("ldur") || result == null
          || result.getNumBytes() != 8 || !result.equals(target)) return false;
      boolean code = false;
      boolean entry = false;
      for (Object object : load.getOpObjects(1)) {
        if (object instanceof ghidra.program.model.lang.Register register) {
          if (!register.equals(program.getRegister("x24"))) return false;
          code = true;
        } else if (object instanceof ghidra.program.model.scalar.Scalar value) {
          // UntaggedCode: header then four target-word entry caches; tagged base.
          long offset = value.getSignedValue();
          entry = offset >= 7 && offset <= 31 && (offset & 7) == 7;
        }
      }
      return code && entry && DartRuntimeCalls.poolLoad(program,
          DartRuntimeCalls.blockBefore(program, body, load), "x24") != null;
    }

    /** LeaveFrame before BR proves a tail transfer, even when its target is
     * dynamic. Keep CALLIND, not an invented concrete callee or return value.
     * A jump table inside a live frame does not satisfy this epilogue proof.
     */
    private boolean balancedTail(Instruction branch, AddressSetView body) {
      if (!isFrame(body.getMinAddress())) {
        return false;
      }
      var pop = branch.getPrevious();
      var restore = pop == null ? null : pop.getPrevious();
      if (restore == null || !body.contains(restore.getAddress())
          || !branch.getAddress().equals(pop.getFallThrough())
          || !pop.getAddress().equals(restore.getFallThrough())) {
        return false;
      }
      try {
        // Official ARM64 LDP FP,LR,[VMSP],#16, paired with the SDK frame save.
        if (program.getMemory().getInt(pop.getAddress()) != 0xa8c179fd) {
          return false;
        }
      } catch (MemoryAccessException e) {
        return false;
      }
      var operations = restore.getPcode();
      if (operations.length != 1 || operations[0].getOpcode() != PcodeOp.COPY
          || !register(restore, 0, "x15") || !register(restore, 1, "x29")) {
        return false;
      }
      for (Instruction instruction : List.of(pop, branch)) {
        var references = program.getReferenceManager().getReferencesTo(instruction.getAddress());
        while (references.hasNext()) {
          if (references.next().getReferenceType().isFlow()) {
            return false;
          }
        }
      }
      return true;
    }

    private void collectCalls(Instruction instruction, AddressSet calls) {
      var flow = instruction.getFlowType();
      if (flow.isCall() && !flow.isComputed()) {
        for (Address target : instruction.getFlows()) {
          if (region.contains(target) && target.getOffset() % 4 == 0) {
            calls.add(target);
          }
        }
      }
    }
  }

  private static AddressSet scanCandidates(Program program, AddressSetView region,
      TaskMonitor monitor) throws CancelledException {
    AddressSet result = new AddressSet();
    for (var range : region) {
      long length = range.getLength();
      long offset = (4 - (range.getMinAddress().getOffset() & 3)) & 3;
      boolean afterTerminal = false;
      while (offset + 4 <= length) {
        monitor.checkCancelled();
        int size = (int) Math.min(65544, length - offset);
        byte[] bytes = new byte[size];
        try {
          program.getMemory().getBytes(range.getMinAddress().add(offset), bytes);
        } catch (MemoryAccessException e) {
          break;
        }
        var buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        int step = Math.min(65536, size - size % 4);
        for (int i = 0; i < step; i += 4) {
          int word = buffer.getInt(i);
          Address address = range.getMinAddress().add(offset + i);
          boolean padding = word == 0 || word == 0xd503201f || (word & 0xffe0001f) == 0xd4200000;
          if (afterTerminal && !padding) {
            result.add(address);
            afterTerminal = false;
          }
          // SDK Assembler::EnterFrame: stp FP,LR,[VMSP,#-16]!; mov FP,VMSP.
          // The two MOV encodings are architecture equivalents, not SDK versions.
          if (word == 0xa9bf79fd && i + 8 <= size) {
            int next = buffer.getInt(i + 4);
            if (next == 0xaa0f03fd || next == 0x910001fd) {
              result.add(address);
            }
          }
          // These encodings are only candidate anchors. The official decoder
          // supplies all subsequent control-flow and instruction semantics.
          afterTerminal |= (word & 0xfffffc1f) == 0xd65f0000
              || (word & 0xffe0001f) == 0xd4200000 || (word & 0xfc000000) == 0x14000000
              || (word & 0xfffffc1f) == 0xd61f0000;
        }
        offset += step;
      }
    }
    return result;
  }

  private static AddressSet executableRegion(Program program, AddressSetView selected) {
    return program.getMemory().getExecuteSet().intersect(selected)
        .intersect(program.getMemory().getLoadedAndInitializedAddressSet());
  }
}
