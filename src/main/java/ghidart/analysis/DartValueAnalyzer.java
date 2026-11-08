/**
 * Retain machine-value uses from Ghidra's SSA, with optional validated L2 provenance.
 *
 * PP origins are scoped to one SSA input or definition, not a global pool ID.
 * Constant-only merges retain at most eight alternatives; relative-address
 * merges require exactly the same origin and displacement on every input.
 * Loads are never evaluated from file bytes: writable pools and relocations
 * must not become invented constants. Facts live in a program property, without
 * bulk comments or fake addresses. Only complete, already-defined executable
 * call targets and bounded concrete memory accesses receive native references.
 * Reanalysis removes only owned refs and unchanged generated local names.
 */
package ghidart.analysis;

import com.google.gson.Gson;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.OpBehaviorFactory;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Selected-function SSA uses, concrete references and validated L2 declaration uses. */
public final class DartValueAnalyzer extends AbstractAnalyzer {
  private static final String PROPERTY = "ghidart.machineValueUses.v1";
  private static final Gson JSON = new Gson();
  private static final int ALTERNATIVES = 8;
  private static final String HEAP_NAMES = "Name heap-base expressions";
  private static final String POOL_NAMES = "Name L2 pool values";
  private boolean namePoolValues = true;
  private static final String THREAD_NAMES = "Name THR values";
  private boolean nameThreadValues = true;
  private static final String TIMEOUT = "Decompiler timeout (seconds)";
  private boolean nameHeapBases;
  private int timeoutSeconds = 20;

  /**
   * Null origin means a numeric constant; otherwise value is a PP byte offset.
   * Input identifies the SSA use, not a Dart source parameter. Call/return
   * indices exclude their control target. Sequence is local to this SSA result.
   */
  public record Use(String site, int sequence, String kind, int input, int width,
      String origin, long value) {}

  /** Exact receiver provenance and declaration uses; declarations are logical
   * database addresses, not runtime pointers. Value records the physical call
   * input index when kind is call-argument, not a Dart logical parameter index.
   */
  public record ObjectUse(String site, String kind, String declaration, String value) {}
  private static final String OBJECT_USES = "ghidart.L2.valueSemantics.v1";

  public static List<ObjectUse> objectUses(Program program, Function function) {
    var property = program.getUsrPropertyManager().getStringPropertyMap(OBJECT_USES);
    String json = property == null ? null : property.getString(function.getEntryPoint());
    return json == null ? List.of() : List.of(JSON.fromJson(json, ObjectUse[].class));
  }

  private record Link(String from, String to, String kind) {}
  private record Named(long symbol, String name, long type, long hash, int firstUse, String storage) {}
  private record Facts(List<Use> uses, List<Link> links, List<Named> names) {
    Facts(List<Use> uses, List<Link> links) {
      this(uses, links, List.of());
    }
  }
  private record Term(String origin, long value) {}

  public DartValueAnalyzer() {
    super("Dart Value Uses", "Index proved PP-relative accesses and constant uses from SSA.",
        AnalyzerType.FUNCTION_ANALYZER);
    setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after());
    setSupportsOneTimeAnalysis();
  }

  @Override
  public boolean canAnalyze(Program program) {
    return "AARCH64:LE:64:dart".equals(program.getLanguageID().toString());
  }

  @Override
  public boolean getDefaultEnablement(Program program) {
    return false;
  }

  @Override
  public void registerOptions(Options options, Program program) {
    options.registerOption(TIMEOUT, 20, null,
        "Maximum native decompiler time per function (1–300 seconds). "
            + "Timed-out functions are reported without inferred facts.");
    options.registerOption(POOL_NAMES, true, null,
        "Name unambiguous local pool loads using validated L2 slot references; does not fold snapshot values.");
    options.registerOption(THREAD_NAMES, true, null,
        "Name unambiguous THR loads from proved field references; no runtime values are assumed.");
    options.registerOption(HEAP_NAMES, false, null,
        "Name exact HBS << 32 expressions using native local symbols; no P-code replacement.");
  }

  @Override
  public void optionsChanged(Options options, Program program) {
    nameHeapBases = options.getBoolean(HEAP_NAMES, false);
    namePoolValues = options.getBoolean(POOL_NAMES, true);
    nameThreadValues = options.getBoolean(THREAD_NAMES, true);
    timeoutSeconds = Math.max(1, Math.min(300, options.getInt(TIMEOUT, 20)));
  }

  /** Read the saved use index; this does not trigger analysis or read a snapshot. */
  public static List<Use> uses(Program program, Function function) {
    var facts = read(program, function);
    return facts == null ? List.of() : List.copyOf(facts.uses());
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
    var objects = DartObjectUses.read(program, monitor);
    var decompiler = new DecompInterface();
    int functions = 0;
    int uses = 0;
    int links = 0;
    int objectUses = 0;
    int valueNames = 0;
    int skipped = 0;
    int failed = 0;
    int timedOut = 0;
    long started = System.nanoTime();
    // This analysis consumes HighFunction only. C token generation adds work
    // and output transfer but contributes no value-use evidence.
    decompiler.toggleCCode(false);
    decompiler.toggleSyntaxTree(true);
    try {
      monitor.setMessage(getName() + ": counting selected functions");
      long total = 0;
      var count = program.getFunctionManager().getFunctions(entries, true);
      while (count.hasNext()) {
        monitor.checkCancelled();
        count.next();
        total++;
      }
      monitor.initialize(total);
      monitor.setIndeterminate(false);
      monitor.setShowProgressValue(true);
      if (!decompiler.openProgram(program)) {
        log.appendMsg(getName(), decompiler.getLastMessage());
        return false;
      }
      var selected = program.getFunctionManager().getFunctions(entries, true);
      long visited = 0;
      while (selected.hasNext()) {
        monitor.checkCancelled();
        var function = selected.next();
        visited++;
        String current = getName() + " " + visited + "/" + total + " at "
            + function.getEntryPoint();
        monitor.setMessage(current + ": decompiling (limit " + timeoutSeconds + " s)");
        try {
          if (function.isExternal()) {
            skipped++;
            continue;
          }
          // Revoke old facts even if the new body cannot be decompiled. Never
          // delete a pre-existing or subsequently user-owned reference.
          clear(program, function);
          if (function.getTags().stream().anyMatch(t ->
              t.getName().equals(DartFunctionAnalyzer.INCOMPLETE_TAG))) {
            skipped++;
            continue;
          }
          var result = decompiler.decompileFunction(function, timeoutSeconds, monitor);
          monitor.checkCancelled();
          if (!result.decompileCompleted() || result.getHighFunction() == null) {
            failed++;
            if (result.isTimedOut()) timedOut++;
            if (failed <= 5) {
              log.appendMsg(getName(), function.getEntryPoint() + ": "
                  + (result.isTimedOut() ? "decompiler timeout" : result.getErrorMessage()));
            }
            continue;
          }
          monitor.setMessage(current + ": collecting SSA uses");
          var facts = collect(program, function, result.getHighFunction(), monitor);
          monitor.setMessage(current + ": saving references and names");
          var semantics = objects.collect(function, result.getHighFunction(), monitor);
          var semanticLinks = new ArrayList<>(facts.links());
          for (var use : semantics.uses()) {
            semanticLinks.add(new Link(use.site(), use.declaration(), "declaration"));
          }
          links += save(program, function, new Facts(facts.uses(), semanticLinks));
          var property = program.getUsrPropertyManager().getStringPropertyMap(OBJECT_USES);
          if (property == null) {
            try { property = program.getUsrPropertyManager().createStringPropertyMap(OBJECT_USES); }
            catch (DuplicateNameException e) { throw new IllegalStateException(e); }
          }
          property.add(function.getEntryPoint(), JSON.toJson(semantics.uses()));
          for (var name : semantics.names().entrySet()) {
            nameExpression(program, function, result.getHighFunction(), name.getKey(), name.getValue(), semantics.types().get(name.getKey()));
          }
          objectUses += semantics.uses().size();
          if (nameHeapBases) nameHeapBases(program, function, result.getHighFunction(), monitor);
          if (namePoolValues || nameThreadValues) valueNames += DartPoolReferences.nameValues(
              program, function, result.getHighFunction(), namePoolValues, nameThreadValues, monitor);
          functions++;
          uses += facts.uses().size();
        } finally {
          // References and native local symbols can affect subsequent SSA.
          // Flush on failures too, rather than retaining a failed function.
          decompiler.flushCache();
          monitor.setProgress(visited);
        }
      }
    } finally {
      decompiler.dispose();
    }
    long seconds = (System.nanoTime() - started) / 1_000_000_000;
    String summary = functions + " functions, " + uses + " machine-value uses, "
        + links + " references/relations, " + objectUses + " L2 object uses; " + skipped + " skipped, " + failed
        + " failed (" + timedOut + " timed out), " + valueNames + " PP/THR values named, " + seconds + " s.";
    monitor.setMessage(getName() + ": " + summary);
    log.appendMsg(getName(), summary + " PP offsets are not pool entries.");
    return true;
  }

  private static Facts collect(Program program, Function function, HighFunction high,
      TaskMonitor monitor) throws CancelledException {
    var values = new Values(program, function, monitor);
    var uses = new LinkedHashSet<Use>();
    var links = new LinkedHashSet<Link>();
    var operations = high.getPcodeOps();
    while (operations.hasNext()) {
      monitor.checkCancelled();
      var op = operations.next();
      Address site = op.getSeqnum().getTarget();
      if (!function.getBody().contains(site)) continue;
      directMemory(program, uses, links, op);
      switch (op.getOpcode()) {
        case PcodeOp.LOAD -> {
          add(uses, values, op, "read", 1, op.getOutput().getSize());
          memoryLinks(program, links, values, op, "read", op.getOutput().getSize());
        }
        case PcodeOp.STORE -> {
          add(uses, values, op, "write", 1, op.getInput(2).getSize());
          memoryLinks(program, links, values, op, "write", op.getInput(2).getSize());
          add(uses, values, op, "stored-value", 2, op.getInput(2).getSize());
        }
        case PcodeOp.CALL, PcodeOp.CALLIND -> {
          var instruction = program.getListing().getInstructionAt(site);
          if (instruction != null && instruction.getFlowType().isComputed()
              && instruction.getFlowType().isCall()) {
            var target = op.getInput(0);
            Set<Term> targets = target.isAddress()
                ? Set.of(new Term(null, target.getOffset())) : values.read(target);
            for (var term : targets) {
              uses.add(new Use(site.toString(), op.getSeqnum().getTime(),
                  "call-target", 0, target.getSize(), term.origin(), term.value()));
            }
            if (knownFunctions(program, targets)) {
              for (var term : targets) {
                var to = program.getAddressFactory().getDefaultAddressSpace().getAddress(term.value());
                links.add(new Link(site.toString(), to.toString(), "call"));
              }
            }
          }
          for (int i = 1; i < op.getNumInputs(); i++) {
            add(uses, values, op, "call-argument", i - 1, op.getInput(i).getSize(), i);
          }
        }
        case PcodeOp.BRANCHIND ->
            add(uses, values, op, "jump-target", 0, op.getInput(0).getSize());
        case PcodeOp.RETURN -> {
          for (int i = 1; i < op.getNumInputs(); i++) {
            add(uses, values, op, "return", i - 1, op.getInput(i).getSize(), i);
          }
        }
        case PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS,
            PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESS, PcodeOp.INT_SLESSEQUAL -> {
          for (int i = 0; i < 2; i++) {
            add(uses, values, op, "compare", i, op.getInput(i).getSize());
          }
        }
      }
    }
    return new Facts(List.copyOf(uses), List.copyOf(links));
  }

  /**
   * Give a transparent intermediate a native name, not an opaque userop.
   * Use the decompiler's own storage when available. Symbol-less physical
   * register results can be named at their defining instruction; symbol-less
   * unique temporaries stay inline. Ambiguous or occupied storage is skipped.
   */
  private static void nameHeapBases(Program program, Function function, HighFunction high,
      TaskMonitor monitor) throws CancelledException {
    var operations = high.getPcodeOps();
    while (operations.hasNext()) {
      monitor.checkCancelled();
      var op = operations.next();
      // Name the decoder's arithmetic intermediate, not an architectural
      // register assignment. Older SDKs build the packed barrier mask with
      // LSL HBS,HBS,#32; naming that state update "heap_base" is misleading.
      if (op.getOpcode() != PcodeOp.INT_LEFT || !op.getOutput().isUnique()
          || op.getOutput().getSize() != 8
          || !op.getInput(1).isConstant() || op.getInput(1).getOffset() != 32
          || op.getInput(0).getSize() != 8
          || !op.getInput(0).getAddress().equals(program.getRegister("x28").getAddress())
          || !function.getBody().contains(op.getSeqnum().getTarget())) continue;
      nameExpression(program, function, high, op.getOutput(), "heap_base");
    }
  }

  /** An owned native display name; neither a value substitution nor a type claim. */
  static boolean nameExpression(Program program, Function function, HighFunction high,
      Varnode value, String preferred) {
    return nameExpression(program, function, high, value, preferred, null);
  }

  /** An optional proved type is applied only when creating a new owned local. */
  private static boolean nameExpression(Program program, Function function, HighFunction high,
      Varnode value, String preferred, ghidra.program.model.data.DataType provedType) {
    if (value == null || value.isInput() || (value.getSize() != 1 && value.getSize() != 2 && value.getSize() != 4 && value.getSize() != 8)
        || value.getHigh() instanceof ghidra.program.model.pcode.HighParam
        || value.getHigh() instanceof ghidra.program.model.pcode.HighGlobal) return false;
    var facts = read(program, function);
    if (facts == null) return false;
    try {
      var variable = value.getHigh();
      if (variable == null || variable.getInstances().length != 1) return false;
      // Respect Ghidra's native storage. A register-backed implied expression
      // (HighOther) can be made explicit at its defining instruction. Unique
      // temporaries without a symbol are deliberately left inline: fabricating
      // a hash local for them can save a name that never appears in the C view.
      var symbol = variable.getSymbol();
      VariableStorage storage;
      ghidra.program.model.address.Address defined;
      if (symbol != null) {
        symbol.resolveStorage();
        storage = symbol.getStorage();
        defined = symbol.getPCAddress();
      } else {
        if (!value.isRegister() || value.getDef() == null) return false;
        storage = new VariableStorage(program, value.getAddress(), value.getSize());
        defined = value.getDef().getSeqnum().getTarget();
      }
      if (storage.isUnassignedStorage() || storage.size() != value.getSize()) return false;
      for (var local : function.getLocalVariables()) {
        if (local.getVariableStorage().equals(storage)) return false;
      }
      String name = preferred;
      for (int suffix = 1; program.getSymbolTable().getVariableSymbol(name, function) != null;
          suffix++) name = preferred + "_" + suffix;
      int firstUse = defined == null ? 0 : (int) defined.subtract(function.getEntryPoint());
      var type = provedType != null ? provedType
          : value.getHigh() == null ? null : value.getHigh().getDataType();
      if (type == null || type.getLength() != value.getSize()) {
        type = ghidra.program.model.data.Undefined.getUndefinedDataType(value.getSize());
      }
      var local = function.addLocalVariable(new LocalVariableImpl(name, firstUse,
          type, storage, program), SourceType.ANALYSIS);
      var names = new ArrayList<Named>(facts.names());
      names.add(new Named(local.getSymbol().getID(), name,
          program.getDataTypeManager().getID(local.getDataType()),
          storage.isHashStorage() ? storage.getFirstVarnode().getOffset() : 0, firstUse,
          storage.getSerializationString()));
      program.getUsrPropertyManager().getStringPropertyMap(PROPERTY).add(function.getEntryPoint(),
          JSON.toJson(new Facts(facts.uses(), facts.links(), names)));
      return true;
    } catch (InvalidInputException | DuplicateNameException e) {
      return false;
    }
  }

  /** Complete finite SSA targets for CFG discovery, before function ownership. */
  static Map<Address, Set<Address>> jumpTargets(Program program, Function function,
      HighFunction high, TaskMonitor monitor) throws CancelledException {
    var values = new Values(program, function, monitor);
    var result = new HashMap<Address, Set<Address>>();
    var operations = high.getPcodeOps();
    while (operations.hasNext()) {
      monitor.checkCancelled();
      var op = operations.next();
      // A branch out of the temporary function body is often normalized into
      // a tail CALLIND. Use its target only when the actual instruction is a
      // computed jump; never reinterpret a machine CALL as a CFG successor.
      if (op.getOpcode() != PcodeOp.BRANCHIND && op.getOpcode() != PcodeOp.CALLIND
          && op.getOpcode() != PcodeOp.CALL) continue;
      Address site = op.getSeqnum().getTarget();
      var instruction = program.getListing().getInstructionAt(site);
      if (!function.getBody().contains(site) || instruction == null
          || !instruction.getFlowType().isComputed()
          || !instruction.getFlowType().isJump()) continue;
      var target = op.getInput(0);
      var terms = target.isAddress() ? Set.of(new Term(null, target.getOffset()))
          : values.read(target);
      if (terms.isEmpty() || terms.stream().anyMatch(t -> t.origin() != null)) continue;
      var targets = new LinkedHashSet<Address>();
      for (var term : terms) {
        targets.add(program.getAddressFactory().getDefaultAddressSpace().getAddress(term.value()));
      }
      result.put(site, Set.copyOf(targets));
    }
    return result;
  }

  private static void add(Set<Use> uses, Values values, PcodeOp op, String kind,
      int input, int width) throws CancelledException {
    add(uses, values, op, kind, input, width, input);
  }

  private static void add(Set<Use> uses, Values values, PcodeOp op, String kind,
      int input, int width, int operand) throws CancelledException {
    for (var term : values.read(op.getInput(operand))) {
      uses.add(new Use(op.getSeqnum().getTarget().toString(), op.getSeqnum().getTime(),
          kind, input, width, term.origin(), term.value()));
    }
  }

  private static void directMemory(Program program, Set<Use> uses, Set<Link> links,
      PcodeOp op) {
    var instruction = program.getListing().getInstructionAt(op.getSeqnum().getTarget());
    if (instruction == null) return;
    boolean load = false;
    boolean store = false;
    for (var raw : instruction.getPcode()) {
      load |= raw.getOpcode() == PcodeOp.LOAD;
      store |= raw.getOpcode() == PcodeOp.STORE;
    }
    // High P-code represents a direct global load/store as an address-tied
    // variable, rather than LOAD/STORE. Exclude synthetic call/exit SSA copies.
    if (load) {
      for (int i = 0; i < op.getNumInputs(); i++) {
        var node = op.getInput(i);
        if (memoryNode(program, node)) {
          uses.add(new Use(instruction.getAddress().toString(), op.getSeqnum().getTime(),
              "read", i, node.getSize(), null, node.getOffset()));
          boundedLinks(program, links, op, "read", node.getSize(),
              Set.of(new Term(null, node.getOffset())));
        }
      }
    }
    var node = op.getOutput();
    if (store && node != null && memoryNode(program, node)) {
      uses.add(new Use(instruction.getAddress().toString(), op.getSeqnum().getTime(),
          "write", -1, node.getSize(), null, node.getOffset()));
      boundedLinks(program, links, op, "write", node.getSize(),
          Set.of(new Term(null, node.getOffset())));
    }
  }

  private static boolean memoryNode(Program program, Varnode node) {
    return node.isAddress() && node.isAddrTied() && node.getAddress().getAddressSpace()
        .equals(program.getAddressFactory().getDefaultAddressSpace());
  }

  private static void memoryLinks(Program program, Set<Link> links, Values values,
      PcodeOp op, String kind, int width) throws CancelledException {
    var space = program.getAddressFactory().getDefaultAddressSpace();
    if (!op.getInput(0).isConstant() || op.getInput(0).getOffset() != space.getSpaceID()) return;
    boundedLinks(program, links, op, kind, width, values.read(op.getInput(1)));
  }

  private static void boundedLinks(Program program, Set<Link> links, PcodeOp op,
      String kind, int width, Set<Term> targets) {
    var candidates = new ArrayList<Link>();
    for (var term : targets) {
      if (term.origin() != null) return;
      Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(term.value());
      var block = program.getMemory().getBlock(address);
      try {
        if (width < 1 || block == null || !block.contains(address.addNoWrap(width - 1))) return;
      } catch (AddressOverflowException e) {
        return;
      }
      candidates.add(new Link(op.getSeqnum().getTarget().toString(), address.toString(), kind));
    }
    links.addAll(candidates);
  }

  private static RefType referenceType(Link link) {
    return switch (link.kind()) {
      case "call" -> RefType.COMPUTED_CALL;
      case "read" -> RefType.READ;
      case "write" -> RefType.WRITE;
      case "declaration" -> RefType.DATA;
      default -> throw new IllegalStateException("Invalid machine-value reference kind");
    };
  }

  private static boolean knownFunctions(Program program, Set<Term> targets) {
    if (targets.isEmpty()) return false;
    for (var target : targets) {
      if (target.origin() != null) return false;
      Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(target.value());
      var block = program.getMemory().getBlock(address);
      if ((target.value() & 3) != 0 || block == null || !block.isExecute()
          || program.getFunctionManager().getFunctionAt(address) == null) return false;
    }
    return true;
  }

  private static Facts read(Program program, Function function) {
    var property = program.getUsrPropertyManager().getStringPropertyMap(PROPERTY);
    if (property == null || property.getString(function.getEntryPoint()) == null) return null;
    var facts = JSON.fromJson(property.getString(function.getEntryPoint()), Facts.class);
    if (facts == null || facts.uses() == null || facts.links() == null) {
      throw new IllegalStateException("Invalid machine-value ownership at " + function.getEntryPoint());
    }
    return facts.names() == null ? new Facts(facts.uses(), facts.links()) : facts;
  }

  private static void clear(Program program, Function function) {
    var semantics = program.getUsrPropertyManager().getStringPropertyMap(OBJECT_USES);
    if (semantics != null) semantics.remove(function.getEntryPoint());
    var facts = read(program, function);
    if (facts == null) return;
    for (var owned : facts.names()) {
      for (var local : function.getLocalVariables()) {
        if (local.getSymbol().getID() == owned.symbol()
            && local.getSymbol().getSource() == SourceType.ANALYSIS
            && local.getName().equals(owned.name())
            && program.getDataTypeManager().getID(local.getDataType()) == owned.type()
            && local.getFirstUseOffset() == owned.firstUse()
            && (owned.storage() != null
                ? owned.storage().equals(local.getVariableStorage().getSerializationString())
                : local.getVariableStorage().isHashStorage()
                    && local.getFirstStorageVarnode().getOffset() == owned.hash())) {
          function.removeVariable(local);
        }
      }
    }
    var addresses = program.getAddressFactory();
    var references = program.getReferenceManager();
    for (var link : facts.links()) {
      Address from = addresses.getAddress(link.from());
      Address to = addresses.getAddress(link.to());
      if (ghidart.snapshot.DartObjectGraph.isIdentity(program, to)) {
        ghidart.snapshot.DartObjectGraph.unlink(program, from, to, referenceType(link));
      }
      var reference = references.getReference(addresses.getAddress(link.from()),
          addresses.getAddress(link.to()), -1);
      if (reference != null && reference.getSource() == SourceType.ANALYSIS
          && reference.getReferenceType().equals(referenceType(link))) {
        references.delete(reference);
      }
    }
    program.getUsrPropertyManager().getStringPropertyMap(PROPERTY).remove(function.getEntryPoint());
  }

  private static int save(Program program, Function function, Facts facts) {
    var manager = program.getUsrPropertyManager();
    var property = manager.getStringPropertyMap(PROPERTY);
    if (property == null) {
      try {
        property = manager.createStringPropertyMap(PROPERTY);
      } catch (DuplicateNameException e) {
        throw new IllegalStateException(e);
      }
    }
    var owned = new ArrayList<Link>();
    property.add(function.getEntryPoint(), JSON.toJson(new Facts(facts.uses(), owned)));
    var references = program.getReferenceManager();
    for (var link : facts.links()) {
      Address from = program.getAddressFactory().getAddress(link.from());
      Address to = program.getAddressFactory().getAddress(link.to());
      if (ghidart.snapshot.DartObjectGraph.isIdentity(program, to)) {
        boolean exists = ghidart.snapshot.DartObjectGraph.from(program, from).stream()
            .anyMatch(edge -> edge.getToAddress().equals(to) && edge.getReferenceType() == referenceType(link));
        if (!exists) {
          ghidart.snapshot.DartObjectGraph.link(program, from, to, referenceType(link));
          owned.add(link);
          property.add(function.getEntryPoint(), JSON.toJson(new Facts(facts.uses(), owned)));
        }
        continue;
      }
      boolean existing = false;
      for (var reference : references.getReferencesFrom(from)) {
        existing |= reference.getToAddress().equals(to);
      }
      if (existing) continue;
      references.addMemoryReference(from, to, referenceType(link), SourceType.ANALYSIS, -1);
      owned.add(link);
      // Publish ownership after each change, including a partially cancelled run.
      property.add(function.getEntryPoint(), JSON.toJson(new Facts(facts.uses(), owned)));
    }
    return owned.size();
  }

  /** Evaluate the existing SSA graph, not instruction encodings or object layouts. */
  private static final class Values {
    private final Program program;
    private final Function function;
    private final TaskMonitor monitor;
    private final Map<Varnode, Set<Term>> cache = new HashMap<>();
    private final Set<Varnode> pending = new HashSet<>();

    Values(Program program, Function function, TaskMonitor monitor) {
      this.program = program;
      this.function = function;
      this.monitor = monitor;
    }

    Set<Term> read(Varnode node) throws CancelledException {
      monitor.checkCancelled();
      if (node.getSize() > 8) return Set.of();
      if (node.isConstant()) return Set.of(new Term(null, node.getOffset()));
      if (cache.containsKey(node)) return cache.get(node);
      if (pending.size() >= 64 || !pending.add(node)) return Set.of();
      Set<Term> result;
      try {
        result = evaluate(node);
      } finally {
        pending.remove(node);
      }
      cache.put(node, result);
      return result;
    }

    private Set<Term> evaluate(Varnode node) throws CancelledException {
      var op = node.getDef();
      if (node.getSize() == 8 && node.getAddress().equals(program.getRegister("x27").getAddress())
          && (op == null && node.isInput() || op != null
              && (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.INDIRECT))) {
        String source = op == null ? "input@" + function.getEntryPoint()
            : "definition@" + op.getSeqnum();
        return Set.of(new Term("PP:" + source, 0));
      }
      if (op == null) return Set.of();
      if (op.getOpcode() == PcodeOp.MULTIEQUAL) {
        Set<Term> result = null;
        for (var input : op.getInputs()) {
          var part = read(input);
          if (part.isEmpty()) return Set.of();
          if (result == null) result = new LinkedHashSet<>(part);
          else if (!result.equals(part)) {
            if (result.stream().anyMatch(t -> t.origin() != null)
                || part.stream().anyMatch(t -> t.origin() != null)) return Set.of();
            result.addAll(part);
          }
          if (result.size() > ALTERNATIVES) return Set.of();
        }
        return result == null ? Set.of() : Set.copyOf(result);
      }
      if (op.getOpcode() == PcodeOp.COPY || op.getOpcode() == PcodeOp.CAST) {
        var source = read(op.getInput(0));
        return op.getInput(0).getSize() == node.getSize() ? source : Set.of();
      }
      var left = op.getNumInputs() == 0 ? Set.<Term>of() : read(op.getInput(0));
      if (left.isEmpty()) return Set.of();
      var right = op.getNumInputs() < 2 ? Set.<Term>of() : read(op.getInput(1));
      // Do not manufacture cross-products between correlated SSA merges.
      if (left.size() > 1 && right.size() > 1) return Set.of();
      var result = new LinkedHashSet<Term>();
      for (var a : left) {
        if (op.getNumInputs() == 1) {
          var behavior = OpBehaviorFactory.getOpBehavior(op.getOpcode());
          if (a.origin() != null || !(behavior instanceof UnaryOpBehavior unary)) return Set.of();
          result.add(new Term(null, unary.evaluateUnary(
              node.getSize(), op.getInput(0).getSize(), a.value())));
        } else {
          for (var b : right) {
            Term value = binary(node, op, a, b);
            if (value == null) return Set.of();
            result.add(value);
            if (result.size() > ALTERNATIVES) return Set.of();
          }
        }
      }
      return Set.copyOf(result);
    }

    private Term binary(Varnode node, PcodeOp op, Term a, Term b) throws CancelledException {
      int code = op.getOpcode();
      if (code == PcodeOp.PTRADD) {
        var scale = read(op.getInput(2));
        if (scale.size() != 1 || scale.iterator().next().origin() != null || b.origin() != null) return null;
        b = new Term(null, b.value() * scale.iterator().next().value());
        code = PcodeOp.INT_ADD;
      } else if (code == PcodeOp.PTRSUB) code = PcodeOp.INT_ADD;
      if (a.origin() != null || b.origin() != null) {
        if (node.getSize() != 8) return null;
        if (code == PcodeOp.INT_ADD && (a.origin() == null || b.origin() == null)) {
          return new Term(a.origin() == null ? b.origin() : a.origin(), a.value() + b.value());
        }
        if (code == PcodeOp.INT_SUB && a.origin() != null && b.origin() == null) {
          return new Term(a.origin(), a.value() - b.value());
        }
        return null;
      }
      var behavior = OpBehaviorFactory.getOpBehavior(code);
      if (!(behavior instanceof BinaryOpBehavior binary)) return null;
      try {
        return new Term(null, binary.evaluateBinary(node.getSize(), op.getInput(0).getSize(),
            a.value(), b.value()));
      } catch (ArithmeticException e) {
        return null;
      }
    }
  }
}
