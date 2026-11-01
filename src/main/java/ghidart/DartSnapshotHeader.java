package ghidart;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Parsed Dart AOT Snapshot header and Clustered section metadata.
 *
 * Encapsulates:
 * <ul>
 *   <li>Snapshot Data Header:
 *     <ul>
 *       <li>Magic: {@code 0xdcdcf5f5} (4 bytes)</li>
 *       <li>Length: {@code int64} (excludes magic)</li>
 *       <li>Kind: {@code int64} (FullAOT value is selected by the serialization profile)</li>
 *       <li>SnapshotHash: 32 ASCII hex chars</li>
 *       <li>Features: null-terminated ASCII/UTF-8 string</li>
 *     </ul>
 *   </li>
 *   <li>Clustered Section Header:
 *     <ul>
 *       <li>{@code numBaseObjects}, {@code numObjects}, {@code numClusters}</li>
 *       <li>Version-specific fields ({@code numCanonicalClusters}, {@code initialFieldTableLen},
 *           {@code instructionsTableLen}, {@code instructionTableDataOffset})</li>
 *     </ul>
 *   </li>
 * </ul>
 */
public final class DartSnapshotHeader {
  public static final int SNAPSHOT_MAGIC = 0xdcdcf5f5;

  // Snapshot Data Header fields
  public final long length;
  public final long totalSize;
  public final int kind;
  public final String snapshotHash;
  public final String features;
  public final Set<String> featureFlags;
  public final int snapshotOffset;
  public final int clusterDataStart;
  public final DartVersionProfile profile;
  public final boolean isVm;

  // Clustered Snapshot Header fields
  public final long numBaseObjects;
  public final long numObjects;
  public final long numCanonicalClusters;
  public final long numClusters;
  public final long initialFieldTableLen;
  public final long instructionsTableLen;
  public final long instructionTableDataOffset;
  public final int firstClusterOffset;

  private DartSnapshotHeader(Builder b) {
    this.length = b.length;
    this.totalSize = b.totalSize;
    this.kind = b.kind;
    this.snapshotHash = b.snapshotHash;
    this.features = b.features;
    this.featureFlags = Collections.unmodifiableSet(b.featureFlags);
    this.snapshotOffset = b.snapshotOffset;
    this.clusterDataStart = b.clusterDataStart;
    this.profile = b.profile;
    this.isVm = b.isVm;

    this.numBaseObjects = b.numBaseObjects;
    this.numObjects = b.numObjects;
    this.numCanonicalClusters = b.numCanonicalClusters;
    this.numClusters = b.numClusters;
    this.initialFieldTableLen = b.initialFieldTableLen;
    this.instructionsTableLen = b.instructionsTableLen;
    this.instructionTableDataOffset = b.instructionTableDataOffset;
    this.firstClusterOffset = b.firstClusterOffset;
  }

  public boolean isCompressedPointers() {
    return featureFlags.contains("compressed-pointers");
  }

  public boolean isNullSafety() {
    return featureFlags.contains("null-safety") || !featureFlags.contains("no-null-safety");
  }

  public boolean usesBareInstructions() {
    return featureFlags.contains("use_bare_instructions")
        || !featureFlags.contains("no-use_bare_instructions");
  }

  public boolean isAot() {
    return profile != null && kind == profile.aotKind();
  }

  public boolean isVmSnapshot() {
    return isVm;
  }

  public long totalClusters() {
    return numCanonicalClusters + numClusters;
  }

  public static DartSnapshotHeader parse(byte[] data, int offset) throws IOException {
    return parse(data, offset, null, false);
  }

  public static DartSnapshotHeader parse(byte[] data, int offset, boolean isVm) throws IOException {
    return parse(data, offset, null, isVm);
  }

  public static DartSnapshotHeader parse(byte[] data, int offset, DartVersionProfile profile)
      throws IOException {
    return parse(data, offset, profile, false);
  }

  public static DartSnapshotHeader parse(
      byte[] data, int offset, DartVersionProfile profile, boolean isVm) throws IOException {
    if (data == null || offset < 0 || offset > data.length - 0x35) {
      throw new IllegalArgumentException("Invalid snapshot data or offset: " + offset);
    }

    DartStream s = new DartStream(data, offset);

    // 1. Verify Magic
    int magic = s.readInt32();
    if (magic != SNAPSHOT_MAGIC) {
      throw new IOException(
          String.format(
              "Invalid Dart snapshot magic: 0x%08x at offset 0x%x (expected 0x%08x)",
              magic, offset, SNAPSHOT_MAGIC));
    }

    Builder b = new Builder();
    b.snapshotOffset = offset;
    b.isVm = isVm;
    b.length = s.readInt64();
    if (b.length < 0x31 || b.length > data.length - offset - 4L) {
      throw new IOException("snapshot declared extent is outside input");
    }
    b.totalSize = b.length + 4;
    long kind = s.readInt64();
    if (kind < 0 || kind > Integer.MAX_VALUE) throw new IOException("invalid snapshot kind");
    b.kind = (int) kind;
    s = new DartStream(data, s.position(), (int) (offset + b.totalSize - s.position()));

    byte[] hashBytes = s.readBytes(32);
    b.snapshotHash = new String(hashBytes, StandardCharsets.US_ASCII);
    if (!b.snapshotHash.matches("[0-9a-f]{32}")) throw new IOException("invalid snapshot hash");
    b.features = s.readCString();

    Set<String> flags = new HashSet<>();
    if (b.features != null && !b.features.isEmpty()) {
      for (String flag : b.features.split("\\s+")) {
        if (!flag.isEmpty()) {
          flags.add(flag);
        }
      }
    }
    b.featureFlags = flags;
    b.clusterDataStart = s.position();

    // Read numBaseObjects peek for header validation
    int savedPos = s.position();
    b.numBaseObjects = s.readUnsigned();
    s.setPosition(savedPos);

    if (profile == null) {
      DartSnapshotHeader prelim = b.build();
      profile = DartVersionProfile.detect(prelim, data);
    } else {
      profile = profile.withCompressedPointers(flags.contains("compressed-pointers"));
    }

    if (b.kind != profile.aotKind()) throw new IOException("not FullAOT for this format: " + b.kind);
    return parseClusteredHeader(data, b, profile);
  }

  /** Re-parses the clustered header counts using a specific {@link DartVersionProfile}. */
  public DartSnapshotHeader withClusteredCounts(byte[] data, DartVersionProfile newProfile)
      throws IOException {
    Builder b = new Builder();
    b.snapshotOffset = this.snapshotOffset;
    b.isVm = this.isVm;
    b.length = this.length;
    b.totalSize = this.totalSize;
    b.kind = this.kind;
    b.snapshotHash = this.snapshotHash;
    b.features = this.features;
    b.featureFlags = new HashSet<>(this.featureFlags);
    b.clusterDataStart = this.clusterDataStart;
    return parseClusteredHeader(data, b, newProfile.withCompressedPointers(isCompressedPointers()));
  }

  private static DartSnapshotHeader parseClusteredHeader(
      byte[] data, Builder b, DartVersionProfile profile) throws IOException {
    DartStream s = new DartStream(data, b.clusterDataStart, (int) (b.snapshotOffset + b.totalSize - b.clusterDataStart));
    b.numBaseObjects = s.readUnsigned();
    b.numObjects = s.readUnsigned();

    if (profile.splitCanonical) {
      b.numCanonicalClusters = s.readUnsigned();
      b.numClusters = s.readUnsigned();
    } else {
      b.numCanonicalClusters = 0;
      b.numClusters = s.readUnsigned();
    }

    if (profile.fillRefUnsigned) {
      b.initialFieldTableLen = s.readUnsigned();
    } else {
      b.initialFieldTableLen = 0;
    }

    if (profile.headerFields >= 5 && !profile.splitCanonical) {
      b.instructionsTableLen = s.readUnsigned();
    } else {
      b.instructionsTableLen = 0;
    }

    if ((profile.headerFields >= 6 || !profile.fillRefUnsigned)
        && !profile.splitCanonical
        && !profile.preCanonicalSplit) {
      b.instructionTableDataOffset = s.readUnsigned();
    } else {
      b.instructionTableDataOffset = 0;
    }

    if (b.numBaseObjects < 0 || b.numObjects < b.numBaseObjects
        || b.numObjects > 2_000_000L || b.numCanonicalClusters < 0
        || b.numClusters < 0 || b.numClusters > 2_000_000L
        || b.numCanonicalClusters > 2_000_000L - b.numClusters) {
      throw new IOException("invalid clustered snapshot counts");
    }
    b.firstClusterOffset = s.position();
    b.profile = profile;
    return b.build();
  }

  public static final class Builder {
    int snapshotOffset;
    boolean isVm;
    long length;
    long totalSize;
    int kind;
    String snapshotHash;
    String features;
    Set<String> featureFlags = new HashSet<>();
    int clusterDataStart;
    DartVersionProfile profile;

    long numBaseObjects;
    long numObjects;
    long numCanonicalClusters;
    long numClusters;
    long initialFieldTableLen;
    long instructionsTableLen;
    long instructionTableDataOffset;
    int firstClusterOffset;

    public DartSnapshotHeader build() {
      return new DartSnapshotHeader(this);
    }
  }

  @Override
  public String toString() {
    return String.format(
        "DartSnapshotHeader[kind=%d, hash=%s, len=%d, base=%d, objs=%d, clusters=%d (canonical=%d), instrLen=%d, instrOff=0x%x]",
        kind,
        snapshotHash,
        length,
        numBaseObjects,
        numObjects,
        numClusters,
        numCanonicalClusters,
        instructionsTableLen,
        instructionTableDataOffset);
  }
}
