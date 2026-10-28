/**
 * Read the analysis-independent boundary subset of the b4a interface.
 *
 * Streaming skips unrelated semantic data. Validation rejects wrong targets,
 * invalid image identities, misaligned/overlapping ranges and out-of-range
 * entries before the caller changes a Ghidra database. Hashing supports the
 * selected slice of a universal binary; mapped-byte checks belong to the caller.
 * This immutable index describes supplied evidence, not discovered functions.
 */
package ghidart;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Validated, analysis-independent Dart Code payload and entry-point index. */
public final class DartCodeIndex {
  private static final Set<String> ENTRY_ROLES =
      Set.of("normal", "monomorphic", "unchecked", "monomorphic_unchecked");

  private final List<CodeUnit> codeUnits;
  private final String imageSha256;
  private final long imageFileSize;
  private final long imageSliceOffset;
  private final List<Check> checks;

  private DartCodeIndex(
      List<CodeUnit> codeUnits,
      String imageSha256,
      long imageFileSize,
      long imageSliceOffset, List<Check> checks) {
    this.codeUnits = List.copyOf(codeUnits);
    this.imageSha256 = imageSha256;
    this.imageFileSize = imageFileSize;
    this.imageSliceOffset = imageSliceOffset;
    this.checks = List.copyOf(checks);
  }

  public static DartCodeIndex read(Path path) throws IOException {
    String format = null;
    Integer version = null;
    Target target = null;
    Image image = null;
    List<CodeUnit> units = null;

    try (JsonReader reader =
        new JsonReader(Files.newBufferedReader(path, StandardCharsets.UTF_8))) {
      reader.beginObject();
      Set<String> fields = new LinkedHashSet<>();
      while (reader.hasNext()) {
        String field = reader.nextName();
        if (!fields.add(field)) {
          throw new IllegalArgumentException("duplicate b4a field: " + field);
        }
        switch (field) {
          case "format" -> format = reader.nextString();
          case "version" -> version = reader.nextInt();
          case "target" -> target = readTarget(reader);
          case "image" -> image = readImage(reader);
          case "codeUnits" -> units = readCodeUnits(reader);
          default -> reader.skipValue();
        }
      }
      reader.endObject();
      if (reader.peek() != JsonToken.END_DOCUMENT) {
        throw new IllegalArgumentException("trailing data after b4a document");
      }
    }

    if (!"b4a".equals(format) || version == null || version != 1) {
      throw new IllegalArgumentException("unsupported b4a format/version");
    }
    if (target == null
        || !"arm64".equals(target.arch)
        || !"little".equals(target.endian)
        || target.wordSize != 8) {
      throw new IllegalArgumentException("ghidart requires little-endian ARM64 b4a data");
    }
    if (image == null || units == null || units.isEmpty()) {
      throw new IllegalArgumentException("b4a image/codeUnits section is missing");
    }
    if (!"0x0".equals(image.preferredBase)) {
      throw new IllegalArgumentException("nonzero b4a preferred base is unsupported");
    }
    if (image.sha256 == null || !image.sha256.matches("[0-9a-f]{64}") || image.fileSize <= 0) {
      throw new IllegalArgumentException("invalid b4a image identity");
    }
    if (image.checks.isEmpty()) {
      throw new IllegalArgumentException("image mapping checks are missing");
    }
    return new DartCodeIndex(units, image.sha256, image.fileSize, image.sliceOffset, image.checks);
  }

  public List<CodeUnit> codeUnits() {
    return codeUnits;
  }

  public String imageSha256() {
    return imageSha256;
  }

  public String boundarySha256() {
    MessageDigest digest = sha256();
    digest.update(imageSha256.getBytes(StandardCharsets.UTF_8));
    for (Check check : checks) {
      String mapping = check.rva() + ":" + HexFormat.of().formatHex(check.bytes()) + ";";
      digest.update(mapping.getBytes(StandardCharsets.UTF_8));
    }
    for (CodeUnit unit : codeUnits) {
      String payload = unit.start() + ":" + unit.end() + ":" + unit.primaryEntry() + ";";
      digest.update(payload.getBytes(StandardCharsets.UTF_8));
      for (Entry entry : unit.entries()) {
        String roles = String.join(",", entry.roles().stream().sorted().toList());
        digest.update((entry.rva() + ":" + roles + ";").getBytes(StandardCharsets.UTF_8));
      }
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  public List<Check> checks() {
    return checks;
  }

  public String verifyBinary(Path path) throws IOException {
    long binarySize = Files.size(path);
    long offset = binarySize == imageFileSize ? 0 : imageSliceOffset;
    if (offset < 0 || imageFileSize > binarySize || offset > binarySize - imageFileSize) {
      throw new IllegalArgumentException("b4a image slice is outside the original binary");
    }
    String actual = hashRange(path, offset, imageFileSize);
    if (!imageSha256.equals(actual)) {
      throw new IllegalArgumentException("b4a.json does not match the original input binary");
    }
    return offset == 0 && binarySize == imageFileSize
        ? actual : hashRange(path, 0, binarySize);
  }

  private static Target readTarget(JsonReader reader) throws IOException {
    String arch = null;
    String endian = null;
    int wordSize = 0;
    reader.beginObject();
    while (reader.hasNext()) {
      switch (reader.nextName()) {
        case "arch" -> arch = reader.nextString();
        case "endian" -> endian = reader.nextString();
        case "wordSize" -> wordSize = reader.nextInt();
        default -> reader.skipValue();
      }
    }
    reader.endObject();
    return new Target(arch, endian, wordSize);
  }

  private static Image readImage(JsonReader reader) throws IOException {
    String sha256 = null;
    String preferredBase = null;
    long fileSize = 0;
    long sliceOffset = 0;
    List<Check> checks = new ArrayList<>();
    reader.beginObject();
    while (reader.hasNext()) {
      switch (reader.nextName()) {
        case "sha256" -> sha256 = reader.nextString();
        case "preferredBase" -> preferredBase = reader.nextString();
        case "fileSize" -> fileSize = reader.nextLong();
        case "sliceOffset" -> sliceOffset = parseAddress(reader.nextString());
        case "checks" -> {
          reader.beginArray();
          while (reader.hasNext()) {
            reader.beginArray();
            long rva = parseAddress(reader.nextString());
            byte[] bytes = HexFormat.of().parseHex(reader.nextString());
            if (bytes.length == 0 || bytes.length > 64) {
              throw new IllegalArgumentException("invalid image mapping check length");
            }
            reader.endArray();
            checks.add(new Check(rva, bytes));
          }
          reader.endArray();
        }
        default -> reader.skipValue();
      }
    }
    reader.endObject();
    return new Image(sha256, preferredBase, fileSize, sliceOffset, checks);
  }

  private static List<CodeUnit> readCodeUnits(JsonReader reader) throws IOException {
    List<CodeUnit> units = new ArrayList<>();
    long previousEnd = 0;
    reader.beginArray();
    while (reader.hasNext()) {
      CodeUnit unit = readCodeUnit(reader);
      if (unit.start < previousEnd) {
        throw new IllegalArgumentException("overlapping or unsorted b4a Code payloads");
      }
      previousEnd = unit.end;
      units.add(unit);
    }
    reader.endArray();
    return units;
  }

  private static CodeUnit readCodeUnit(JsonReader reader) throws IOException {
    Long start = null;
    Long end = null;
    Long primary = null;
    boolean sawPrimary = false;
    List<EntryObservation> observations = null;

    reader.beginObject();
    while (reader.hasNext()) {
      switch (reader.nextName()) {
        case "start" -> start = parseAddress(reader.nextString());
        case "end" -> end = parseAddress(reader.nextString());
        case "primaryEntry" -> {
          sawPrimary = true;
          primary =
              reader.peek() == JsonToken.NULL ? readNull(reader) : parseAddress(reader.nextString());
        }
        case "entries" -> observations = readEntries(reader);
        default -> reader.skipValue();
      }
    }
    reader.endObject();

    if (start == null || end == null || !sawPrimary || observations == null) {
      throw new IllegalArgumentException("incomplete b4a Code payload");
    }
    if (end <= start || (start & 3) != 0 || (end & 3) != 0) {
      throw new IllegalArgumentException("invalid ARM64 Code payload range");
    }

    Map<Long, Set<String>> grouped = new LinkedHashMap<>();
    for (EntryObservation observation : observations) {
      if (observation.rva < start || observation.rva >= end || (observation.rva & 3) != 0) {
        throw new IllegalArgumentException("entry lies outside its b4a Code payload");
      }
      grouped
          .computeIfAbsent(observation.rva, ignored -> new LinkedHashSet<>())
          .add(observation.role);
    }
    if (primary != null && (!grouped.containsKey(primary)
        || !grouped.get(primary).contains("normal"))) {
      throw new IllegalArgumentException("primaryEntry is not a known normal Code entry");
    }

    List<Entry> entries = new ArrayList<>();
    grouped.forEach((rva, roles) -> entries.add(new Entry(rva, Set.copyOf(roles))));
    entries.sort(Comparator.comparingLong(Entry::rva));
    return new CodeUnit(start, end, primary, List.copyOf(entries));
  }

  private static List<EntryObservation> readEntries(JsonReader reader) throws IOException {
    List<EntryObservation> entries = new ArrayList<>();
    reader.beginArray();
    while (reader.hasNext()) {
      Long rva = null;
      String role = null;
      reader.beginObject();
      while (reader.hasNext()) {
        switch (reader.nextName()) {
          case "rva" -> rva = parseAddress(reader.nextString());
          case "kind" -> role = reader.nextString();
          default -> reader.skipValue();
        }
      }
      reader.endObject();
      if (rva == null || role == null || !ENTRY_ROLES.contains(role)) {
        throw new IllegalArgumentException("invalid b4a Code entry");
      }
      entries.add(new EntryObservation(rva, role));
    }
    reader.endArray();
    return entries;
  }

  private static Long readNull(JsonReader reader) throws IOException {
    reader.nextNull();
    return null;
  }

  private static long parseAddress(String text) {
    if (text == null || !text.matches("0x[0-9a-f]+")) {
      throw new IllegalArgumentException("invalid b4a address: " + text);
    }
    long value = Long.parseUnsignedLong(text.substring(2), 16);
    if (value < 0) {
      throw new IllegalArgumentException("b4a address exceeds signed 64-bit range: " + text);
    }
    return value;
  }

  private static String hashRange(Path path, long offset, long size) throws IOException {
    MessageDigest digest = sha256();
    try (InputStream input = Files.newInputStream(path)) {
      input.skipNBytes(offset);
      byte[] buffer = new byte[1 << 20];
      while (size > 0) {
        int count = input.read(buffer, 0, (int) Math.min(size, buffer.length));
        if (count < 0) {
          throw new IOException("truncated binary while hashing b4a image slice");
        }
        digest.update(buffer, 0, count);
        size -= count;
      }
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  private static MessageDigest sha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError("SHA-256 is required by Java", e);
    }
  }

  public record CodeUnit(long start, long end, Long primaryEntry, List<Entry> entries) {
    public String rangeString() {
      return "[0x" + Long.toUnsignedString(start, 16)
          + ",0x" + Long.toUnsignedString(end, 16) + ")";
    }
  }

  public record Entry(long rva, Set<String> roles) {}

  public record Check(long rva, byte[] bytes) {}

  private record Target(String arch, String endian, int wordSize) {}

  private record Image(String sha256, String preferredBase, long fileSize, long sliceOffset, List<Check> checks) {}

  private record EntryObservation(long rva, String role) {}
}
