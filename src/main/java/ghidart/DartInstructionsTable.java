package ghidart;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Canonical payload ranges for the two AOT instruction encodings.
 *
 * <p>Older Code objects carry cumulative text offsets; newer snapshots carry a
 * read-only InstructionsTable. Both paths produce the same immutable ranges.
 * Stub/code projections never recalculate endpoints or mutate shared objects.
 * The last endpoint must come from the instruction image, not a section guess.
 */
public final class DartInstructionsTable {
  public record Entry(int slot, long pcOffset, long stackMapOffset) {}

  public static final class CodeRange {
    public final int slot;
    public final List<Integer> slots;
    public final long pcOffset;
    public final long size;
    public final boolean isStub;

    private CodeRange(List<Integer> slots, long pcOffset, long size, boolean isStub) {
      this.slots = List.copyOf(slots);
      this.slot = slots.getFirst();
      this.pcOffset = pcOffset;
      this.size = size;
      this.isStub = isStub;
    }
  }

  public final int length;
  public final int firstEntryWithCode;
  public final List<Entry> entries;
  public final List<CodeRange> allRanges;
  public final List<CodeRange> uniqueRanges;
  public final List<CodeRange> codeRanges;
  public final List<CodeRange> stubRanges;

  private DartInstructionsTable(List<Entry> entries, int firstCode, long limit) {
    this.entries = List.copyOf(entries);
    this.length = entries.size();
    this.firstEntryWithCode = firstCode;
    var sorted = new ArrayList<>(entries);
    sorted.sort(Comparator.comparingLong(Entry::pcOffset));
    var ranges = new ArrayList<CodeRange>();
    for (int i = 0; i < sorted.size();) {
      long pc = sorted.get(i).pcOffset();
      var slots = new ArrayList<Integer>();
      boolean stub = true;
      do {
        int slot = sorted.get(i++).slot();
        slots.add(slot);
        stub &= slot < firstCode;
      } while (i < sorted.size() && sorted.get(i).pcOffset() == pc);
      long end = i < sorted.size() ? sorted.get(i).pcOffset() : limit;
      ranges.add(new CodeRange(slots, pc, end > pc ? end - pc : 0, stub));
    }
    uniqueRanges = List.copyOf(ranges);
    // Keep each table slot available for identity comparisons, with exactly
    // the same endpoints as its canonical payload.
    var slots = new ArrayList<CodeRange>();
    for (var range : ranges) {
      for (int slot : range.slots) {
        slots.add(new CodeRange(List.of(slot), range.pcOffset, range.size, slot < firstCode));
      }
    }
    allRanges = List.copyOf(slots);
    codeRanges = slots.stream().filter(r -> !r.isStub).toList();
    stubRanges = slots.stream().filter(r -> r.isStub).toList();
  }

  public DartInstructionsTable withInstructionLimit(long limit) throws IOException {
    for (var entry : entries) {
      if (entry.pcOffset() <= 0 || (entry.pcOffset() & 3) != 0 || entry.pcOffset() >= limit) {
        throw new IOException(String.format(
            "instruction table slot %d offset 0x%x outside aligned image payload [0, 0x%x)",
            entry.slot(), entry.pcOffset(), limit));
      }
    }
    if ((limit & 3) != 0) throw new IOException("unaligned instruction image end");
    return new DartInstructionsTable(entries, firstEntryWithCode, limit);
  }

  public static long roundUp(long value, long alignment) {
    if (value < 0 || alignment <= 0 || (alignment & (alignment - 1)) != 0
        || value > Long.MAX_VALUE - alignment + 1) {
      throw new IllegalArgumentException("invalid aligned extent");
    }
    return (value + alignment - 1) & -alignment;
  }

  public static DartInstructionsTable parse(byte[] data, DartSnapshotHeader header,
      DartVersionProfile profile) throws IOException {
    if (profile.codeTextOffsetDelta) return fromCodeEntries(List.of());
    if (header.instructionTableDataOffset == 0) {
      if (header.instructionsTableLen != 0) throw new IOException("missing instruction table");
      return fromCodeEntries(List.of());
    }
    long image = header.snapshotOffset + roundUp(header.totalSize, profile.topLevelCid16 ? 16 : 64);
    if (header.instructionTableDataOffset < 0
        || header.instructionTableDataOffset > data.length - image - 32) {
      throw new IOException("instruction table outside data image");
    }
    var imageHeader = new DartStream(data, (int) image);
    long imageSize = imageHeader.readInt64();
    if (imageSize < 16 || imageSize > data.length - image) {
      throw new IOException("read-only image outside input");
    }
    long position = image + header.instructionTableDataOffset;
    if (position > image + imageSize - 16) throw new IOException("truncated table object");
    var object = new DartStream(data, (int) position, (int) (image + imageSize - position));
    long tags = object.readInt64();
    int cid = profile.topLevelCid16 ? (int) ((tags >>> 16) & 0xffff)
        : (int) ((tags >>> 12) & 0xfffff);
    long length = object.readInt64();
    if (cid != profile.cids.oneByteString || length < 0 || (length & 1) != 0
        || (length >>> 1) < 16 || (length >>> 1) > object.remaining()) {
      throw new IOException("invalid instruction table byte container");
    }
    var stream = new DartStream(data, object.position(), (int) (length >>> 1));
    stream.readUint32(); // Canonical stack-map offset.
    long count = stream.readUint32();
    long first = stream.readUint32();
    stream.readUint32(); // Padding.
    if (first > count || count > stream.remaining() / 8) {
      throw new IOException("invalid instruction table cardinality");
    }
    var entries = new ArrayList<Entry>((int) count);
    for (int i = 0; i < count; i++) {
      entries.add(new Entry(i, stream.readUint32(), stream.readUint32()));
    }
    return new DartInstructionsTable(entries, (int) first, 0);
  }

  public static DartInstructionsTable fromCodeEntries(List<DartClusterParser.CodeEntry> codes) {
    return fromCodeEntries(codes, 0);
  }

  public static DartInstructionsTable fromCodeEntries(List<DartClusterParser.CodeEntry> codes,
      long initialTextOffset) {
    var entries = new ArrayList<Entry>();
    for (var code : codes) {
      if (code.clusterIndex >= 0) {
        entries.add(new Entry(code.clusterIndex, initialTextOffset + code.textOffset, 0));
      }
    }
    return new DartInstructionsTable(entries, 0, 0);
  }

  /** Instruction image header and InstructionsSection payload, SDK image_snapshot.h. */
  public static long readInstructionPayloadEnd(byte[] bytes, int offset,
      DartVersionProfile profile) {
    try {
      var stream = new DartStream(bytes, offset);
      long imageSize = stream.readInt64();
      long section = stream.readInt64();
      if (imageSize <= 0) return -1;
      if (section == 0 || (section < 0 && (section & 1) != 0)) {
        stream.skip(8);
        long size = stream.readInt64();
        return size > 0 && size <= imageSize - 0x20 ? 0x20 + size : -1;
      }
      if (section < 16 || section > bytes.length - offset - 16L) return -1;
      stream.setPosition(offset + (int) section + 8);
      long size = stream.readInt64();
      // The five serialized words occupy 40 bytes, but HeaderSize includes
      // payload alignment. SDK 3.5+ rounds them to 64 bytes (object.h and
      // ImageWriter::WriteText); using 40 truncates the last VM stub.
      long start = section + roundUp(5 * Long.BYTES, profile.instructionSectionPayloadAlignment);
      return size > 0 && size <= imageSize - start ? start + size : -1;
    } catch (IOException | IllegalArgumentException e) {
      return -1;
    }
  }
}
