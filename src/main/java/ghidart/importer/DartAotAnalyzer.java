/**
 * Apply externally established Dart Code boundaries before normal disassembly.
 *
 * Only image identity, mapping checks and Code ranges are read from b4a.json;
 * no app signatures or IL are imported. Disassembly is restricted to validated
 * payloads, with one primary function owner and labels for alternate entries.
 * Existing user/imported definitions are preserved when they conflict.
 * Without a sidecar this analyzer does nothing: it is not an independent
 * snapshot parser or a heuristic prologue-based function finder.
 */
package ghidart.importer;

import ghidart.analysis.DartAnalysisLog;
import ghidart.analysis.DartFunctionAnalyzer;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/** Discovers Dart AOT functions from validated Code payload boundaries. */
public final class DartAotAnalyzer extends AbstractAnalyzer {
  private static final String METADATA_OPTION = "b4a.json path";
  private static final String PROGRAM_OPTIONS = "ghidart";
  private static final String IMPORTED_IDENTITY = "codeIndexSha256";

  private String configuredMetadataPath = "";

  public DartAotAnalyzer() {
    super(
        "Dart AOT Code Boundaries",
        "Disassembles and creates functions from validated Dart Code payload ranges.",
        AnalyzerType.BYTE_ANALYZER);
    setPriority(AnalysisPriority.DISASSEMBLY.before());
    setSupportsOneTimeAnalysis();
  }

  @Override
  public boolean getDefaultEnablement(Program program) {
    return false;
  }

  @Override
  public boolean canAnalyze(Program program) {
    return "AARCH64:LE:64:dart".equals(program.getLanguageID().toString());
  }

  @Override
  public void registerOptions(Options options, Program program) {
    options.registerOption(
        METADATA_OPTION,
        "",
        null,
        "Optional b4a.json path. If empty, ghidart looks next to the input binary.");
  }

  @Override
  public void optionsChanged(Options options, Program program) {
    configuredMetadataPath = options.getString(METADATA_OPTION, "").trim();
  }

  @Override
  public boolean added(
      Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
      throws CancelledException {
    try (var output = new DartAnalysisLog(program, log)) {
      return analyze(program, set, monitor, output.messages());
    }
  }

  private boolean analyze(
      Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
      throws CancelledException {
    if (B4aImporter.isImported(program)) return true;
    Optional<Path> metadataPath = findMetadata(program);
    if (metadataPath.isEmpty()) {
      log.appendMsg(
          getName(),
          "No b4a.json sidecar found; skipping boundary import. "
              + "Run Dart Machine Code Functions on the managed code region for independent discovery.");
      return true;
    }

    try {
      DartCodeIndex index = DartCodeIndex.read(metadataPath.get());
      String boundaryIdentity = index.boundarySha256();
      String imported = program.getOptions(PROGRAM_OPTIONS).getString(IMPORTED_IDENTITY, "");
      if (boundaryIdentity.equals(imported)
          && program.getOptions(PROGRAM_OPTIONS).getInt("boundaryVersion", 0) == 3) {
        return true;
      }

      verifyIdentity(program, index);
      DiscoveryStats stats = applyBoundaries(program, index.codeUnits(), monitor, log);
      if (stats.functionsCreated + stats.functionsExisting == 0) {
        throw new IllegalArgumentException("no Dart functions could be created; boundary import incomplete");
      }
      program.getOptions(PROGRAM_OPTIONS).setInt("boundaryVersion", 3);
      program.getOptions(PROGRAM_OPTIONS).setString(IMPORTED_IDENTITY, boundaryIdentity);
      program.getOptions(PROGRAM_OPTIONS).setString("b4aPath", metadataPath.get().toString());
      log.appendMsg(
          getName(),
          "Validated "
              + index.codeUnits().size()
              + " Code payloads; created "
              + stats.functionsCreated
              + " functions and "
              + stats.entryLabelsCreated
              + " entry labels ("
              + stats.functionsSkipped
              + " conflicts/skips).");
      return true;
    } catch (IOException | IllegalArgumentException e) {
      log.appendMsg(getName(), "Function discovery rejected: " + e.getMessage());
      return false;
    }
  }

  public Optional<Path> findMetadata(Program program) {
    if (!configuredMetadataPath.isEmpty()) {
      return Optional.of(Path.of(configuredMetadataPath).toAbsolutePath().normalize());
    }

    String executablePath = program.getExecutablePath();
    if (executablePath == null || executablePath.isBlank()) {
      return Optional.empty();
    }
    Path executable = Path.of(executablePath).toAbsolutePath().normalize();
    Path directory = executable.getParent();
    if (directory == null) {
      return Optional.empty();
    }
    Path conventional = directory.resolve("b4a.json");
    if (Files.isRegularFile(conventional)) {
      return Optional.of(conventional);
    }
    Path named = directory.resolve(executable.getFileName() + ".b4a.json");
    return Files.isRegularFile(named) ? Optional.of(named) : Optional.empty();
  }

  public static void verifyIdentity(Program program, DartCodeIndex index) throws IOException {
    String executablePath = program.getExecutablePath();
    Path executable =
        executablePath == null || executablePath.isBlank()
            ? null
            : Path.of(executablePath).toAbsolutePath().normalize();
    if (executable != null && Files.isRegularFile(executable)) {
      String binaryHash = index.verifyBinary(executable);
      if (!binaryHash.equalsIgnoreCase(program.getExecutableSHA256())) {
        throw new IllegalArgumentException("database identity differs from the input binary");
      }
    } else {
      String programSha256 = program.getExecutableSHA256();
      if (programSha256 == null || !index.imageSha256().equalsIgnoreCase(programSha256)) {
        throw new IllegalArgumentException("cannot verify the original input binary");
      }
    }
    for (DartCodeIndex.Check check : index.checks()) {
      byte[] actual = new byte[check.bytes().length];
      try {
        program.getMemory().getBytes(program.getImageBase().add(check.rva()), actual);
      } catch (ghidra.program.model.mem.MemoryAccessException e) {
        throw new IllegalArgumentException("image mapping check is not readable", e);
      }
      if (!java.util.Arrays.equals(actual, check.bytes())) {
        throw new IllegalArgumentException("b4a RVA mapping differs from the loaded image");
      }
    }
  }

  public static DiscoveryStats applyBoundaries(
      Program program, java.util.List<DartCodeIndex.CodeUnit> units, TaskMonitor monitor, MessageLog log)
      throws CancelledException {
    Address base = program.getImageBase();
    Memory memory = program.getMemory();
    AddressSet ranges = new AddressSet();
    AddressSet seeds = new AddressSet();

    for (DartCodeIndex.CodeUnit unit : units) {
      monitor.checkCancelled();
      Address start = base.add(unit.start());
      Address end = base.add(unit.end() - 1);
      if (!memory.getExecuteSet().contains(start, end)
          || !memory.getLoadedAndInitializedAddressSet().contains(start, end)) {
        throw new IllegalArgumentException(
            "Code payload is not fully mapped executable memory: " + unit.rangeString());
      }
      ranges.add(start, end);
      for (DartCodeIndex.Entry entry : unit.entries()) {
        seeds.add(base.add(entry.rva()));
      }
    }

    DartFunctionAnalyzer.prepareInstructionSnapshots(program, ranges, monitor);

    if (!seeds.isEmpty()) {
      DisassembleCommand command = new DisassembleCommand(seeds, ranges, true);
      command.enableCodeAnalysis(false);
      if (!command.applyTo(program, monitor)) {
        log.appendMsg(
            DartAotAnalyzer.class.getSimpleName(),
            "Restricted disassembly was incomplete: " + command.getStatusMsg());
      }
    }

    DiscoveryStats stats = new DiscoveryStats();
    monitor.initialize(units.size(), "Creating Dart functions");
    for (DartCodeIndex.CodeUnit unit : units) {
      monitor.checkCancelled();
      createEntryLabels(program, base, unit, stats);
      if (unit.primaryEntry() == null) {
        stats.functionsSkipped++;
        monitor.increment();
        continue;
      }

      Address entry = base.add(unit.primaryEntry());
      Function existing = program.getFunctionManager().getFunctionAt(entry);
      if (existing != null) {
        AddressSet payload = new AddressSet(base.add(unit.start()), base.add(unit.end() - 1));
        if (payload.contains(existing.getBody())) {
          // ELF debug symbols can create a one-byte placeholder, shorter than
          // one ARM64 instruction. It is not an analyzed function body. Keep
          // the imported name, but complete its validated instruction extent.
          if (existing.getBody().getNumAddresses() == 1
              && existing.getSymbol().getSource() != SourceType.USER_DEFINED
              && existing.getSignatureSource() == SourceType.DEFAULT
              && existing.getAllVariables().length == 0) {
            AddressSet body = instructionBody(program, base, unit);
            boolean overlaps = false;
            var owners = program.getFunctionManager().getFunctionsOverlapping(body);
            while (owners.hasNext()) {
              if (!owners.next().equals(existing)) overlaps = true;
            }
            if (!overlaps && body.contains(entry)) {
              try {
                existing.setBody(body);
              } catch (ghidra.program.database.function.OverlappingFunctionException e) {
                // Another function owner always wins over an inferred extent.
              }
            }
          }
          stats.functionsExisting++;
        } else {
          stats.functionsSkipped++;
        }
        monitor.increment();
        continue;
      }

      AddressSet body = instructionBody(program, base, unit);
      if (!body.contains(entry)
          || program.getFunctionManager().getFunctionContaining(entry) != null
          || program.getFunctionManager().getFunctionsOverlapping(body).hasNext()) {
        stats.functionsSkipped++;
        monitor.increment();
        continue;
      }

      Symbol entrySymbol = program.getSymbolTable().getPrimarySymbol(entry);
      String name = entrySymbol != null && (entrySymbol.getSource() == SourceType.USER_DEFINED
          || entrySymbol.getSource() == SourceType.IMPORTED)
          ? null : "dart_" + Long.toUnsignedString(unit.primaryEntry(), 16);
      CreateFunctionCmd command =
          new CreateFunctionCmd(name, entry, body, SourceType.ANALYSIS, false, false);
      if (command.applyTo(program, monitor)) {
        stats.functionsCreated++;
      } else {
        stats.functionsSkipped++;
      }
      monitor.increment();
    }
    shortenEntryLabels(program, monitor);
    return stats;
  }

  private static AddressSet instructionBody(
      Program program, Address base, DartCodeIndex.CodeUnit unit) {
    AddressSet range = new AddressSet(base.add(unit.start()), base.add(unit.end() - 1));
    AddressSet body = new AddressSet();
    InstructionIterator instructions = program.getListing().getInstructions(range, true);
    while (instructions.hasNext()) {
      Instruction instruction = instructions.next();
      body.add(instruction.getMinAddress(), instruction.getMaxAddress());
    }
    return body;
  }

  private static void createEntryLabels(
      Program program, Address base, DartCodeIndex.CodeUnit unit, DiscoveryStats stats) {
    for (DartCodeIndex.Entry entry : unit.entries()) {
      Address address = base.add(entry.rva());
      Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
      boolean generated = symbol != null && symbol.getSource() == SourceType.ANALYSIS
          && symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.LABEL
          && symbol.getName().startsWith("dart_") && symbol.getName().contains("_entry_");
      if (symbol != null && symbol.getSource() != SourceType.DEFAULT && !generated) continue;
      // One address can serve several entry roles. Keep the roles in the index,
      // not repeated in the label shown at every reference to this address.
      String role = entry.roles().contains("monomorphic") ? "monomorphic_"
          : entry.roles().contains("unchecked") ? "unchecked_" : "";
      String name = "dart_" + role + "entry_" + Long.toUnsignedString(entry.rva(), 16);
      try {
        if (generated) symbol.setName(name, SourceType.ANALYSIS);
        else program.getSymbolTable().createLabel(address, name, SourceType.ANALYSIS);
        stats.entryLabelsCreated++;
      } catch (InvalidInputException | ghidra.util.exception.DuplicateNameException ignored) {
        // A conflicting user/imported symbol is never replaced.
      }
    }
  }

  /** Upgrade only owned labels; function names and user/imported symbols survive. */
  public static void shortenEntryLabels(Program program, TaskMonitor monitor) throws CancelledException {
    var symbols = program.getSymbolTable().getAllSymbols(true);
    while (symbols.hasNext()) {
      monitor.checkCancelled();
      var symbol = symbols.next();
      if (symbol.getSource() != SourceType.ANALYSIS
          || symbol.getSymbolType() != ghidra.program.model.symbol.SymbolType.LABEL) continue;
      String name = symbol.getName();
      if (!name.startsWith("dart_") || !name.contains("_entry_")) continue;
      String suffix = name.substring(name.lastIndexOf("_entry_") + 7);
      if (!suffix.matches("[0-9a-f]+")) continue;
      String role = name.contains("monomorphic") ? "monomorphic_" : name.contains("unchecked") ? "unchecked_" : "";
      try {
        var owner = program.getFunctionManager().getFunctionContaining(symbol.getAddress());
        if (owner == null) symbol.setName("dart_" + role + "entry_" + suffix, SourceType.ANALYSIS);
        else if (symbol.getAddress().equals(owner.getEntryPoint())) symbol.delete();
        else {
          long displacement = symbol.getAddress().subtract(owner.getEntryPoint());
          String offset = (displacement < 0 ? "m" : "p") + Long.toHexString(Math.abs(displacement));
          symbol.setNameAndNamespace("entry_" + role + offset, owner, SourceType.ANALYSIS);
        }
      }
      catch (InvalidInputException | ghidra.util.exception.DuplicateNameException | ghidra.program.model.listing.CircularDependencyException ignored) {
        // A conflicting user symbol wins over a cosmetic label upgrade.
      }
    }
  }

  public static final class DiscoveryStats {
    int functionsCreated;
    int functionsExisting;
    int entryLabelsCreated;
    int functionsSkipped;

    public int functionsCreated() {
      return functionsCreated;
    }

    public int entryLabelsCreated() {
      return entryLabelsCreated;
    }
  }
}
