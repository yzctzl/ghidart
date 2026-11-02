package ghidart.snapshot;

import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.IOException;
import java.util.List;

/** Read an external unit against its parent, using the official binary loaders.
 *
 * Parent images are opened temporarily for their reference table, never mapped
 * over the child's executable addresses or saved as hidden project programs.
 * The snapshot's program identity and full parent reference count must agree;
 * a matching filename alone is not evidence. Missing parents leave L1 available.
 */
final class DartLoadingUnits {
  static boolean isUnit(Program program, String explicitParent) throws IOException {
    if (DartSnapshotAnalyzer.symbol(program, "kDartVmSnapshotData") != null) return false;
    return !explicitParent.isBlank()
        || program.getExecutablePath().matches(".*-[0-9]+\\.part\\.(so|dylib)$");
  }

  static List<DartSnapshotAnalyzer.Snapshot> read(Program program, String explicitParent,
      TaskMonitor monitor) throws IOException, MemoryAccessException, CancelledException {
    return read(program, explicitParent, monitor, 0);
  }

  private static List<DartSnapshotAnalyzer.Snapshot> read(Program program, String explicitParent,
      TaskMonitor monitor, int depth) throws IOException, MemoryAccessException, CancelledException {
    if (depth >= 16) throw new IOException("loading-unit parent chain exceeds 16 images");
    String path = explicitParent.isBlank()
        ? program.getExecutablePath().replaceFirst("-[0-9]+\\.part\\.(so|dylib)$", "") : explicitParent;
    File parent = new File(path);
    if (!parent.isFile()
        || parent.getCanonicalPath().equals(new File(program.getExecutablePath()).getCanonicalPath())) {
      throw new IOException("loading unit needs its parent binary; set Dart AOT Objects > Parent AOT file");
    }
    monitor.setMessage("Reading loading-unit parent " + parent.getName());
    try (var loaded = ProgramLoader.builder().source(parent).language(program.getLanguage())
        .compiler(program.getCompilerSpec()).log(new MessageLog()).monitor(monitor).load()) {
      if (loaded == null) throw new IOException("parent binary loader rejected input");
      Object consumer = new Object();
      Program image = loaded.getPrimary().getDomainObject(consumer);
      try {
        var snapshots = isUnit(image, "") ? read(image, "", monitor, depth + 1)
            : DartSnapshotAnalyzer.read(image, monitor);
        if (snapshots.isEmpty()) throw new IOException("parent has no validated AOT reference table");
        var objects = snapshots.getLast().objects();
        // Standard filenames locate the root, whose LoadingUnit.parent edge
        // identifies a nested unit's actual parent. Do not assume all units
        // inherit the root reference table. The reader validates the full chain.
        if (explicitParent.isBlank() && !objects.header.isLoadingUnit) {
          Integer parentId = parentUnitId(objects, new File(program.getExecutablePath()).getName());
          if (parentId != null && parentId > 1) {
            String extension = program.getExecutablePath().endsWith(".dylib") ? ".dylib" : ".so";
            File ancestor = new File(parent.getPath() + "-" + parentId + ".part" + extension);
            return read(program, ancestor.getPath(), monitor, depth + 1);
          }
        }
        String identity = snapshots.stream().map(DartSnapshotAnalyzer.Snapshot::identity)
            .collect(java.util.stream.Collectors.joining(":"));
        return List.of(DartSnapshotAnalyzer.readUnit(program, objects, identity, monitor));
      } finally {
        image.release(consumer);
      }
    } catch (CancelledException | IOException | MemoryAccessException e) {
      throw e;
    } catch (ghidra.util.exception.VersionException e) {
      throw new IOException("cannot open loading-unit parent", e);
    }
  }

  private static Integer parentUnitId(DartClusterParser.Result root, String filename)
      throws IOException {
    var match = java.util.regex.Pattern.compile(".*-([0-9]+)\\.part\\.(so|dylib)$").matcher(filename);
    if (!match.matches()) return null;
    long id;
    try {
      id = Long.parseLong(match.group(1));
    } catch (NumberFormatException e) {
      throw new IOException("invalid loading-unit filename ID", e);
    }
    for (var unit : root.objects.values()) {
      if (unit.cid() != root.profile.cids.loadingUnit || unit.scalars().length == 0
          || unit.scalars()[0] != id || unit.references().length != 1) continue;
      var parent = root.object(unit.references()[0]);
      if (parent != null && parent.cid() == root.profile.cids.loadingUnit
          && parent.scalars().length == 1 && parent.scalars()[0] >= 1
          && parent.scalars()[0] <= Integer.MAX_VALUE) return (int) parent.scalars()[0];
      throw new IOException("loading unit has no valid parent identity");
    }
    throw new IOException("loading-unit filename ID is absent from parent metadata");
  }
}
