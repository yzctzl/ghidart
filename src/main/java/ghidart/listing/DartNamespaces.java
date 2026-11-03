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
    Namespace owner = namespace(program, program.getGlobalNamespace(), "Library", false, source);
    String path = uri;
    if (path.startsWith("file://")) {
      int lib = path.lastIndexOf("/lib/");
      path = lib >= 0 ? "app/" + path.substring(lib + 5)
          : "app/" + path.substring(path.lastIndexOf('/') + 1);
    } else path = path.replaceFirst(":", "/");
    for (String part : path.split("/")) {
      if (!part.isBlank()) owner = namespace(program, owner, part, false, source);
    }
    return owner;
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
            if (library.getName(true).equals("Library::SDK")) library = owner.getParentNamespace();
            symbol.setNameAndNamespace(className(program, library, name, cid, owner), library, source);
          } else if (source == SourceType.ANALYSIS && owner.getParentNamespace().getName(true).equals("Library::SDK")
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
