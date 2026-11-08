package ghidart.snapshot;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.List;

/** Database relationships, separate from machine-code and file-data references.
 *
 * Keys preserve the existing scope/ref identity; no address is claimed to be a heap
 * pointer. Both directions are indexed for object navigation and semantic consumers.
 * Ordinary XREFs contain only real accesses. Existing analysis-owned artificial
 * references migrate transactionally; user references and file-backed refs survive.
 */
public final class DartObjectGraph {
  private static final String OUT = "ghidart.objects.out";
  private static final String IN = "ghidart.objects.in";
  private static final String NAMES = "ghidart.objects.names";

  private static final ThreadLocal<Batch> ACTIVE = new ThreadLocal<>();

  /** Transaction-scoped write buffer: hot objects (null/types/shared Code) can have
   * thousands of incoming edges. Rewriting their growing DB strings per edge is
   * quadratic. Keep at most 4096 hot adjacency lists, deduplicate in memory and
   * write each evicted list once. No parsed application or graph cache survives.
   * The caller must flush before marking its publication transaction successful.
   */
  public static final class Batch implements AutoCloseable {
    private record Key(String map, Address address) {}
    private final Program program;
    private final TaskMonitor monitor;
    private final java.util.LinkedHashMap<Key, java.util.LinkedHashSet<String>> pending =
        new java.util.LinkedHashMap<>(4096, 0.75f, true);

    private Batch(Program program, TaskMonitor monitor) {
      this.program = program;
      this.monitor = monitor;
    }

    private void change(String map, Address address, String value, boolean remove) {
      var key = new Key(map, address);
      var values = pending.get(key);
      if (values == null) {
        if (pending.size() >= 4096) {
          var oldest = pending.entrySet().iterator().next();
          write(oldest.getKey(), oldest.getValue());
          pending.remove(oldest.getKey());
        }
        values = new java.util.LinkedHashSet<>();
        var property = program.getUsrPropertyManager().getStringPropertyMap(map);
        String previous = property == null ? null : property.getString(address);
        if (previous != null) java.util.Collections.addAll(values, previous.split("\n"));
        pending.put(key, values);
      }
      if (remove) values.remove(value);
      else values.add(value);
    }

    private void write(Key key, java.util.LinkedHashSet<String> values) {
      var map = program.getUsrPropertyManager().getStringPropertyMap(key.map());
      if (map == null) map = create(program, key.map());
      if (values.isEmpty()) map.remove(key.address());
      else map.add(key.address(), String.join("\n", values) + "\n");
    }

    public void flush() throws CancelledException {
      monitor.initialize(pending.size(), "Saving Dart object relationships");
      for (var entry : pending.entrySet()) {
        monitor.checkCancelled();
        write(entry.getKey(), entry.getValue());
        monitor.increment();
      }
      pending.clear();
    }

    @Override public void close() {
      pending.clear();
      ACTIVE.remove();
    }
  }

  public static Batch batch(Program program, TaskMonitor monitor) {
    if (ACTIVE.get() != null) throw new IllegalStateException("Nested object graph publication");
    var batch = new Batch(program, monitor);
    ACTIVE.set(batch);
    return batch;
  }

  private DartObjectGraph() {}

  public record Link(Address getFromAddress, Address getToAddress, RefType getReferenceType) {}

  public static boolean isIdentity(Program program, Address address) {
    var block = program.getMemory().getBlock(address);
    return block != null && block.isArtificial() && block.getName().startsWith("DartObjects_");
  }

  public static void link(Program program, Address from, Address to, RefType type) {
    if (from == null || to == null) return;
    String kind = type == RefType.READ ? "R" : type == RefType.WRITE ? "W" : "D";
    append(program, OUT, from, kind + " " + to);
    append(program, IN, to, kind + " " + from);
  }

  private static void append(Program program, String name, Address key, String value) {
    var batch = ACTIVE.get();
    if (batch != null && batch.program == program) {
      batch.change(name, key, value, false);
      return;
    }
    var map = program.getUsrPropertyManager().getStringPropertyMap(name);
    if (map == null) map = create(program, name);
    String previous = map.getString(key);
    String line = value + "\n";
    if (previous == null) map.add(key, line);
    else if (!previous.contains(line)) map.add(key, previous + line);
  }

  /** Revoke an unchanged analyzer-owned relation during value-use reanalysis. */
  public static void unlink(Program program, Address from, Address to, RefType type) {
    String kind = type == RefType.READ ? "R" : type == RefType.WRITE ? "W" : "D";
    remove(program, OUT, from, kind + " " + to);
    remove(program, IN, to, kind + " " + from);
  }

  private static void remove(Program program, String name, Address key, String value) {
    var batch = ACTIVE.get();
    if (batch != null && batch.program == program) {
      batch.change(name, key, value, true);
      return;
    }
    var map = program.getUsrPropertyManager().getStringPropertyMap(name);
    String previous = map == null ? null : map.getString(key);
    if (previous == null) return;
    String remaining = previous.replace(value + "\n", "");
    if (remaining.isEmpty()) map.remove(key);
    else if (!remaining.equals(previous)) map.add(key, remaining);
  }

  private static ghidra.program.model.util.StringPropertyMap create(Program program, String name) {
    try {
      return program.getUsrPropertyManager().createStringPropertyMap(name);
    } catch (ghidra.util.exception.DuplicateNameException e) {
      throw new IllegalStateException("Object relation property collision: " + name, e);
    }
  }

  public static List<Link> from(Program program, Address address) {
    return links(program, OUT, address, false);
  }

  public static List<Link> to(Program program, Address address) {
    return links(program, IN, address, true);
  }

  private static List<Link> links(Program program, String name, Address address, boolean reverse) {
    var map = program.getUsrPropertyManager().getStringPropertyMap(name);
    String stored = map == null ? null : map.getString(address);
    var batch = ACTIVE.get();
    if (batch != null && batch.program == program) {
      var pending = batch.pending.get(new Batch.Key(name, address));
      if (pending != null) stored = String.join("\n", pending);
    }
    if (stored == null || stored.isEmpty()) return List.of();
    var result = new ArrayList<Link>();
    for (String line : stored.split("\n")) {
      Address other = program.getAddressFactory().getAddress(line.substring(2));
      if (other == null) continue;
      RefType type = line.charAt(0) == 'R' ? RefType.READ : line.charAt(0) == 'W' ? RefType.WRITE : RefType.DATA;
      result.add(new Link(reverse ? other : address, reverse ? address : other, type));
    }
    return result;
  }

  public static void name(Program program, Address address, String value) {
    var map = program.getUsrPropertyManager().getStringPropertyMap(NAMES);
    if (map == null) map = create(program, NAMES);
    map.add(address, value);
  }

  public static String name(Program program, Address address) {
    var map = program.getUsrPropertyManager().getStringPropertyMap(NAMES);
    return map == null ? null : map.getString(address);
  }

  public static String describe(Program program, Address address) {
    if (!isIdentity(program, address)) {
      var symbol = program.getSymbolTable().getPrimarySymbol(address);
      var block = program.getMemory().getBlock(address);
      return (symbol == null ? "" : symbol.getName(true) + " @ ") + address
          + (block != null && block.getName().startsWith("DartSlots_") ? " (offset model)" : "");
    }
    String name = name(program, address);
    var block = program.getMemory().getBlock(address);
    if (name == null) {
      var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
      String record = facts == null ? null : facts.getString(address);
      if (record != null) {
        var object = com.google.gson.JsonParser.parseString(record).getAsJsonObject();
        if (object.has("name") && object.get("name").isJsonPrimitive()) name = object.get("name").getAsString();
        else if (object.has("kind")) name = object.get("kind").getAsString();
        else if (object.has("serialized")) name = "Serialized object";
      }
    }
    long index = address.subtract(block.getStart()) / 8;
    return block.getName().substring("DartObjects_".length()) + " record #" + index
        + (name == null ? "" : " — " + name);
  }

  /** Derive edge labels from the retained facts, not a second semantic schema. */
  public static String relation(Program program, Link edge) {
    if (edge.getReferenceType() == RefType.READ) return "PP read";
    if (edge.getReferenceType() == RefType.WRITE) return "PP write";
    if (!isIdentity(program, edge.getFromAddress()) && isIdentity(program, edge.getToAddress())) {
      var block = program.getMemory().getBlock(edge.getFromAddress());
      return block != null && block.getName().startsWith("DartSlots_") ? "slot record" : "declaration";
    }
    var facts = program.getUsrPropertyManager().getStringPropertyMap("ghidart.L2.objects.v1");
    String stored = facts == null ? null : facts.getString(edge.getFromAddress());
    if (stored == null) return "object relation";
    var node = com.google.gson.JsonParser.parseString(stored).getAsJsonObject();
    if (!isIdentity(program, edge.getToAddress())) {
      if (program.getFunctionManager().getFunctionAt(edge.getToAddress()) != null) return "code entry";
      return node.has("kind") && node.get("kind").getAsString().equals("String")
          ? "characters" : "serialized payload";
    }
    if (node.has("poolRef")) return "initial pool value";
    var source = program.getMemory().getBlock(edge.getFromAddress());
    var target = program.getMemory().getBlock(edge.getToAddress());
    if (source == null || target == null) return "object relation";
    if (!source.equals(target)) return "inherited identity";
    long ref = edge.getToAddress().subtract(target.getStart()) / 8;
    for (String section : new String[] {"object", "declaration", "functionInfo"}) {
      if (!node.has(section) || !node.get(section).isJsonObject()) continue;
      for (var field : node.getAsJsonObject(section).entrySet()) {
        String key = field.getKey();
        if (key.equals("refId") || !(key.endsWith("RefId") || key.endsWith("Ref"))) continue;
        var value = field.getValue();
        if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber() && value.getAsLong() == ref) {
          return key.replaceFirst("RefId$|Ref$", "");
        }
      }
    }
    return "object relation";
  }

  /** Called inside the L2 publication transaction, including existing generations. */
  public static void migrate(Program program, TaskMonitor monitor) throws CancelledException {
    var options = program.getOptions("ghidart.L2");
    if (options.getBoolean("objectGraphSeparated", false)) return;
    var manager = program.getReferenceManager();
    var identities = new AddressSet();
    for (var block : program.getMemory().getBlocks()) {
      if (isIdentity(program, block.getStart())) identities.add(block.getStart(), block.getEnd());
    }
    var sites = new AddressSet(identities);
    var destinations = manager.getReferenceDestinationIterator(identities, true);
    while (destinations.hasNext()) {
      monitor.checkCancelled();
      for (var ref : manager.getReferencesTo(destinations.next())) sites.add(ref.getFromAddress());
    }
    var sources = manager.getReferenceSourceIterator(sites, true);
    while (sources.hasNext()) {
      monitor.checkCancelled();
      for (var ref : manager.getReferencesFrom(sources.next())) {
        if (ref.getSource() != SourceType.ANALYSIS || !ref.isMemoryReference()
            || (!isIdentity(program, ref.getFromAddress()) && !isIdentity(program, ref.getToAddress()))) continue;
        link(program, ref.getFromAddress(), ref.getToAddress(), ref.getReferenceType());
        manager.delete(ref);
      }
    }
    options.setBoolean("objectGraphSeparated", true);
  }
}
