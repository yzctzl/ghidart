package ghidart.listing;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/** Shared library hierarchy for decoded AOT and imported analysis.
 *
 * Source provenance belongs in facts, not in parallel symbol trees. Keep package
 * and SDK URIs distinct; remove host build paths from file URIs in both sources.
 */
public final class DartNamespaces {
  private DartNamespaces() {}

  public static Namespace library(Program program, String uri, SourceType source)
      throws InvalidInputException, DuplicateNameException {
    String path = uri == null ? "" : uri;
    String category;
    if (path.startsWith("package:")) {
      category = "Packages";
      path = path.substring(8);
    } else if (path.startsWith("dart:")) {
      category = "SDK";
      path = path.substring(5);
    } else if (path.startsWith("file:") || path.startsWith("/")) {
      category = "App";
      int lib = path.lastIndexOf("/lib/");
      path = lib >= 0 ? path.substring(lib + 5) : path.substring(path.lastIndexOf('/') + 1);
    } else if (path.equals("SDK")) {
      category = "SDK";
      path = "UnknownLibrary";
    } else {
      category = "Packages";
      // Obfuscation may remove the URI. Retain the library identity without
      // pretending that a short library name proves a package name.
      path = "UnknownSource/" + (path.isBlank() ? "unknown" : path);
    }
    Namespace owner = namespace(program, program.getGlobalNamespace(), category, false, source);
    for (String part : path.split("/")) {
      if (!part.isBlank()) owner = namespace(program, owner, part, false, source);
    }
    return owner;
  }

  /** Move only extension-owned scopes; keep user-owned symbols and scope IDs.
   * Metadata labels leave the Symbol Tree entirely: they describe graph records,
   * not declarations. Empty former scaffolding is pruned bottom-up.
   */
  public static void migrate(Program program, ghidra.util.task.TaskMonitor monitor)
      throws ghidra.util.exception.CancelledException {
    if (program.getOptions("ghidart").getInt("namespacePresentation", 0) == 1) return;
    var table = program.getSymbolTable();
    var logical = new java.util.ArrayList<ghidra.program.model.symbol.Symbol>();
    for (var block : program.getMemory().getBlocks()) {
      if (!ghidart.snapshot.DartObjectGraph.isIdentity(program, block.getStart())) continue;
      var symbols = table.getSymbolIterator(block.getStart(), true);
      while (symbols.hasNext()) {
        monitor.checkCancelled();
        var symbol = symbols.next();
        if (!block.contains(symbol.getAddress())) break;
        if (symbol.getSource() == SourceType.ANALYSIS) logical.add(symbol);
      }
    }
    for (var symbol : logical) {
      ghidart.snapshot.DartObjectGraph.name(program, symbol.getAddress(), symbol.getName(true));
      symbol.delete();
    }
    try {
      Namespace old = table.getNamespace("Library", program.getGlobalNamespace());
      if (old != null) {
        var children = new java.util.ArrayList<ghidra.program.model.symbol.Symbol>();
        table.getSymbols(old).forEachRemaining(children::add);
        for (var symbol : children) {
          monitor.checkCancelled();
          if (!(symbol.getObject() instanceof Namespace child)
              || symbol.getSource() == SourceType.USER_DEFINED) continue;
          if (java.util.Set.of("THR", "PP").contains(child.getName())) continue;
          if (child.getName().equals("ObjectPools")) {
            prune(program, child, monitor);
            continue;
          }
          String category = switch (child.getName()) {
            case "package" -> "Packages";
            case "dart", "SDK" -> "SDK";
            case "app" -> "App";
            case "Runtime", "VM" -> "Runtime";
            case "Unresolved" -> "Unresolved";
            default -> "Packages";
          };
          Namespace target = namespace(program, program.getGlobalNamespace(), category, false, SourceType.ANALYSIS);
          if (child.getName().equals("SDK")) {
            target = namespace(program, target, "UnknownLibrary", false, SourceType.ANALYSIS);
          } else if (!java.util.Set.of("package", "dart", "app", "Runtime", "VM", "Unresolved").contains(child.getName())) {
            target = namespace(program, target, "UnknownSource", false, SourceType.ANALYSIS);
            target = namespace(program, target, child.getName(), false, SourceType.ANALYSIS);
          }
          moveContents(program, child, target, monitor);
        }
        prune(program, old, monitor);
      }
      Namespace objects = table.getNamespace(clean("Dart Objects"), program.getGlobalNamespace());
      if (objects != null) prune(program, objects, monitor);
    } catch (InvalidInputException | DuplicateNameException
        | ghidra.program.model.listing.CircularDependencyException e) {
      throw new IllegalStateException("Cannot migrate Dart namespace presentation", e);
    }
    program.getOptions("ghidart").setInt("namespacePresentation", 1);
  }

  private static void moveContents(Program program, Namespace from, Namespace to,
      ghidra.util.task.TaskMonitor monitor) throws InvalidInputException, DuplicateNameException,
      ghidra.program.model.listing.CircularDependencyException, ghidra.util.exception.CancelledException {
    var symbols = new java.util.ArrayList<ghidra.program.model.symbol.Symbol>();
    program.getSymbolTable().getSymbols(from).forEachRemaining(symbols::add);
    for (var symbol : symbols) {
      monitor.checkCancelled();
      if (symbol.getSource() == SourceType.USER_DEFINED) continue;
      if (symbol.getObject() instanceof Namespace child
          && !(symbol.getObject() instanceof ghidra.program.model.listing.Function)) {
        var existing = program.getSymbolTable().getNamespace(child.getName(), to);
        if (existing != null && symbol.getSymbolType() == ghidra.program.model.symbol.SymbolType.CLASS) {
          // A collision must not merge separate CID owners or lose their symbol IDs.
          symbol.setNameAndNamespace(child.getName() + "_scope" + child.getID(), to, symbol.getSource());
          continue;
        }
        if (existing != null) {
          moveContents(program, child, existing, monitor);
          prune(program, child, monitor);
          continue;
        }
      }
      symbol.setNamespace(to);
    }
  }

  private static void prune(Program program, Namespace owner, ghidra.util.task.TaskMonitor monitor)
      throws ghidra.util.exception.CancelledException {
    var symbols = new java.util.ArrayList<ghidra.program.model.symbol.Symbol>();
    program.getSymbolTable().getSymbols(owner).forEachRemaining(symbols::add);
    for (var symbol : symbols) {
      monitor.checkCancelled();
      if (symbol.getObject() instanceof Namespace child
          && !(symbol.getObject() instanceof ghidra.program.model.listing.Function)) prune(program, child, monitor);
    }
    if (owner.getSymbol().getSource() != SourceType.USER_DEFINED
        && !program.getSymbolTable().getSymbols(owner).hasNext()) owner.getSymbol().delete();
  }

  public static Namespace namespace(Program program, Namespace parent, String name,
      boolean clazz, SourceType source) throws InvalidInputException, DuplicateNameException {
    String clean = clean(name);
    var table = program.getSymbolTable();
    var existing = table.getNamespace(clean, parent);
    if (existing != null) return existing;
    return clazz ? table.createClass(parent, clean, source)
        : table.createNameSpace(parent, clean, source);
  }

  /** One target CID owns one class scope across L2 and L3. Names are not identity. */
  public static Namespace clazz(Program program, int cid, Namespace library, String name,
      SourceType source) throws InvalidInputException, DuplicateNameException,
      ghidra.program.model.listing.CircularDependencyException {
    var properties = program.getUsrPropertyManager();
    var scopes = properties.getLongPropertyMap("ghidart.classScopes");
    if (scopes == null) {
      scopes = properties.createLongPropertyMap("ghidart.classScopes");
    }
    var key = program.getAddressFactory().getAddressSpace("OTHER").getAddress(0x60_0000_0000L + cid);
    if (scopes.hasProperty(key)) {
      try {
        var symbol = program.getSymbolTable().getSymbol(scopes.getLong(key));
        if (symbol != null && symbol.getObject() instanceof Namespace owner) {
          // Imported names enrich generated scopes, never user-owned ones.
          if (source == SourceType.IMPORTED && symbol.getSource() == SourceType.ANALYSIS) {
            if (library.getName(true).equals("SDK::UnknownLibrary")) library = owner.getParentNamespace();
            symbol.setNameAndNamespace(className(program, library, name, cid, owner), library, source);
          } else if (source == SourceType.ANALYSIS && owner.getParentNamespace().getName(true).equals("SDK::UnknownLibrary")
              && symbol.getSource() == SourceType.IMPORTED) {
            // Predefined b4a classes may omit their library. Decoded Class.library
            // supplies that missing relation without changing the preferred name.
            symbol.setNameAndNamespace(className(program, library, owner.getName(), cid, owner), library, symbol.getSource());
          }
          return owner;
        }
      } catch (ghidra.util.exception.NoValueException e) {
        throw new IllegalStateException("missing Dart class scope", e);
      }
    }
    String available = clean(name);
    var existing = program.getSymbolTable().getNamespace(available, library);
    if (existing != null) {
      var reverse = classScopeKey(program, existing.getID());
      try {
        if (scopes.hasProperty(reverse) && scopes.getLong(reverse) != cid) available += "_cid" + cid;
      } catch (ghidra.util.exception.NoValueException e) {
        throw new IllegalStateException("missing Dart class identity", e);
      }
    }
    Namespace owner = namespace(program, library, available, true, source);
    scopes.add(key, owner.getID());
    scopes.add(classScopeKey(program, owner.getID()), cid);
    return owner;
  }

  private static ghidra.program.model.address.Address classScopeKey(Program program, long id) {
    return program.getAddressFactory().getAddressSpace("OTHER").getAddress(0x61_0000_0000L + id);
  }

  private static String className(Program program, Namespace library, String name, int cid, Namespace owner) {
    String clean = clean(name);
    var existing = program.getSymbolTable().getNamespace(clean, library);
    return existing == null || existing.getID() == owner.getID() ? clean : clean + "_cid" + cid;
  }

  public static String clean(String name) {
    String value = SymbolUtilities.replaceInvalidChars(name == null || name.isBlank() ? "unnamed" : name, true);
    return value.length() <= 180 ? value : value.substring(0, 160)
        + "_" + Integer.toUnsignedString(name.hashCode(), 16);
  }
}
