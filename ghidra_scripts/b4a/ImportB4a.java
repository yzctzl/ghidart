// Validate b4a.json and import its ARM64 code-entry labels and range bookmarks.
// ABI and function-body analysis remain the responsibility of ghidart.
// @category Dart

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;

public class ImportB4a extends GhidraScript {
  // Stream past large semantic sections. The full shared document remains
  // available for later type/analysis import; no script-specific JSON is needed.
  public static JsonObject readFoundation(Path path) throws Exception {
    Set<String> fields = Set.of(
        "format", "version", "target", "image", "registers", "codeUnits");
    JsonObject data = new JsonObject();
    try (JsonReader reader = new JsonReader(Files.newBufferedReader(path, StandardCharsets.UTF_8))) {
      reader.beginObject();
      while (reader.hasNext()) {
        String key = reader.nextName();
        if (fields.contains(key)) {
          if (data.has(key)) {
            throw new IllegalArgumentException("Duplicate b4a section: " + key);
          }
          data.add(key, JsonParser.parseReader(reader));
        } else {
          reader.skipValue();
        }
      }
      reader.endObject();
      if (reader.peek() != com.google.gson.stream.JsonToken.END_DOCUMENT) {
        throw new IllegalArgumentException("Trailing b4a data");
      }
    }
    if (!data.has("format") || !data.has("version")
        || !"b4a".equals(data.get("format").getAsString())
        || !data.get("version").isJsonPrimitive()
        || !data.get("version").getAsJsonPrimitive().isNumber()
        || !"1".equals(data.get("version").getAsString())) {
      throw new IllegalArgumentException("Unsupported b4a format/version");
    }
    return data;
  }

  private static long address(JsonElement value) {
    String text = value.getAsString();
    if (!text.matches("0x[0-9a-f]+")) {
      throw new IllegalArgumentException("Invalid b4a address: " + text);
    }
    // Current b4a input images are zero-based and limited to 1 GiB.
    long result = Long.parseLong(text.substring(2), 16);
    if (result < 0 || result >= (1L << 30)) {
      throw new IllegalArgumentException("Unsupported image address: " + text);
    }
    return result;
  }

  public static String hashRange(Path path, long offset, long size) throws Exception {
    if (offset < 0 || size <= 0 || offset > Files.size(path) - size) {
      throw new IllegalArgumentException("Invalid original image slice");
    }
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (InputStream stream = Files.newInputStream(path)) {
      stream.skipNBytes(offset);
      byte[] buffer = new byte[1 << 20];
      while (size > 0) {
        int count = stream.read(buffer, 0, (int) Math.min(size, buffer.length));
        if (count < 0) {
          throw new IllegalArgumentException("Truncated original image");
        }
        digest.update(buffer, 0, count);
        size -= count;
      }
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  @Override
  public void run() throws Exception {
    if (currentProgram == null) {
      throw new IllegalStateException("Open the original ARM64 binary first");
    }
    String[] args = getScriptArgs();
    Path path = args.length > 0 ? Path.of(args[0]) : askFile("Select b4a.json", "Open").toPath();
    JsonObject data = readFoundation(path);
    JsonObject target = data.getAsJsonObject("target");
    if (!"arm64".equals(target.get("arch").getAsString())
        || !"little".equals(target.get("endian").getAsString())
        || target.get("wordSize").getAsInt() != 8
        || !"AARCH64".equals(currentProgram.getLanguage().getProcessor().toString())
        || currentProgram.getLanguage().isBigEndian()) {
      throw new IllegalArgumentException("ghidart currently requires little-endian ARM64");
    }
    Path binary = args.length > 1 ? Path.of(args[1])
        : askFile("Select the original binary (thin slice or original container)", "Open").toPath();
    JsonObject image = data.getAsJsonObject("image");
    long size = image.get("fileSize").getAsLong();
    long offset = Files.size(binary) == size ? 0
        : Long.parseLong(image.get("sliceOffset").getAsString().substring(2), 16);
    String sha = image.get("sha256").getAsString();
    String programSha = currentProgram.getExecutableSHA256();
    if (!sha.matches("[0-9a-f]{64}") || !sha.equals(hashRange(binary, offset, size))
        || programSha == null
        || !(programSha.equalsIgnoreCase(sha)
            || programSha.equalsIgnoreCase(hashRange(binary, 0, Files.size(binary))))) {
      throw new IllegalArgumentException("b4a/original binary/Ghidra input identity mismatch");
    }
    if (!"0x0".equals(image.get("preferredBase").getAsString())) {
      throw new IllegalArgumentException("Nonzero preferred image base is unsupported");
    }
    Address base = currentProgram.getImageBase();
    JsonArray units = data.getAsJsonArray("codeUnits");
    long previousEnd = 0;
    // Validate ranges and entries before writing. This first importer deliberately
    // rejects overlapping groups rather than guessing their function ownership.
    for (JsonElement element : units) {
      monitor.checkCancelled();
      JsonObject unit = element.getAsJsonObject();
      long start = address(unit.get("start"));
      long end = address(unit.get("end"));
      if (start < previousEnd || end <= start || (start % 4) != 0 || (end % 4) != 0
          || !currentProgram.getMemory().contains(base.add(start), base.add(end - 1))) {
        throw new IllegalArgumentException("Invalid/overlapping/unmapped b4a code range");
      }
      previousEnd = end;
      for (JsonElement item : unit.getAsJsonArray("entries")) {
        long entry = address(item.getAsJsonObject().get("rva"));
        MemoryBlock block = currentProgram.getMemory().getBlock(base.add(entry));
        if (entry < start || entry >= end || entry % 4 != 0 || block == null || !block.isExecute()) {
          throw new IllegalArgumentException("Invalid or non-executable b4a entry");
        }
      }
    }
    int transaction = currentProgram.startTransaction("Import b4a foundation");
    boolean committed = false;
    int labels = 0;
    try {
      Set<Long> seen = new HashSet<>();
      for (JsonElement element : units) {
        monitor.checkCancelled();
        JsonObject unit = element.getAsJsonObject();
        long start = address(unit.get("start"));
        currentProgram.getBookmarkManager().setBookmark(base.add(start), BookmarkType.INFO,
            "b4a", "Code [" + unit.get("start").getAsString() + ", "
                + unit.get("end").getAsString() + "); source=" + unit.get("source").getAsString());
        for (JsonElement item : unit.getAsJsonArray("entries")) {
          long entry = address(item.getAsJsonObject().get("rva"));
          if (!seen.add(entry)) {
            continue;
          }
          Address ea = base.add(entry);
          Symbol existing = currentProgram.getSymbolTable().getPrimarySymbol(ea);
          if (existing == null || existing.getSource() == SourceType.DEFAULT) {
            currentProgram.getSymbolTable().createLabel(ea, "b4a_entry_" + Long.toHexString(entry),
                SourceType.IMPORTED);
            labels++;
          }
        }
      }
      currentProgram.getOptions("b4a").setString("imageSha256", sha);
      committed = true;
    } finally {
      currentProgram.endTransaction(transaction, committed);
    }
    println("b4a: validated " + units.size() + " code units, added " + labels
        + " labels. Function-body/ABI and semantic import are separate ghidart work.");
  }
}
