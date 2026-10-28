// Offline identity check. Uses the same reader/hash routines as the Ghidra importer.
import com.google.gson.JsonObject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class VerifyB4a {
  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      throw new IllegalArgumentException("Usage: VerifyB4a <samples-directory>");
    }
    Path root = Path.of(args[0]);
    List<Path> samples;
    try (var paths = Files.list(root)) {
      samples = paths.filter(Files::isDirectory)
          .filter(path -> Files.isRegularFile(path.resolve("b4a.json")))
          .sorted().toList();
    }
    if (samples.isEmpty()) {
      throw new IllegalArgumentException("No sample pairs in " + root);
    }
    for (Path sample : samples) {
      JsonObject data = ImportB4a.readFoundation(sample.resolve("b4a.json"));
      JsonObject target = data.getAsJsonObject("target");
      if (!"arm64".equals(target.get("arch").getAsString())) {
        throw new IllegalArgumentException("Expected ARM64 sample: " + sample);
      }
      JsonObject image = data.getAsJsonObject("image");
      String format = image.get("format").getAsString();
      Path binary = sample.resolve("elf".equals(format) ? "libapp.so" : "App");
      long size = image.get("fileSize").getAsLong();
      long offset = Files.size(binary) == size ? 0
          : Long.parseLong(image.get("sliceOffset").getAsString().substring(2), 16);
      String sha = ImportB4a.hashRange(binary, offset, size);
      if (!sha.equals(image.get("sha256").getAsString())) {
        throw new IllegalArgumentException("Binary/JSON identity mismatch: " + sample);
      }
      System.out.printf("%s: %s/%s, %d Code ranges, SHA-256 OK%n",
          sample.getFileName(), target.get("os").getAsString(), format,
          data.getAsJsonArray("codeUnits").size());
    }
    System.out.println("Offline identity checks passed; no Ghidra analysis was run.");
  }
}
