package ghidart.snapshot;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Version identification library and format profile matrix for Dart AOT snapshots
 * for explicitly identified Dart SDK serialization layouts.
 *
 * Encapsulates all version-specific structural constants:
 * <ul>
 *   <li>Cluster tag encoding ({@link TagStyle})</li>
 *   <li>Header count layout (4, 5, or 6 VLE fields)</li>
 *   <li>Reference encoding in fill phase ({@code readUnsigned} vs {@code readRefId})</li>
 *   <li>ObjectPool entry encoding (v2 7-bit type vs v3 4-bit type + 3-bit behavior)</li>
 *   <li>Predefined Class ID tables ({@link DartClassId.Table})</li>
 *   <li>Per-cluster reference counts and scalar layout flags across Dart 2.10..3.13+</li>
 * </ul>
 */
public final class DartVersionProfile {

  /** How cluster headers (CID + canonical/immutable flags) are encoded in the Alloc section. */
  public enum TagStyle {
    /** Dart 2.10–2.13: {@code Write<int32_t>(cid)}. Canonical determined by cluster index. */
    CID_INT32,

    /** Dart 2.14–3.3: {@code Write<uint64_t>((cid << 1) | canonical)}. */
    CID_SHIFT_1,

    /** Dart 3.4+: {@code Write<uint32_t>(ClassIdTag::encode(cid) | CanonicalBit | ImmutableBit)}. */
    OBJECT_HEADER
  }

  /** Changes to Code framing are explicit; ordinary releases share a reader. */
  public enum CodeFormat { BARE_OFFSETS, INSTRUCTIONS_TABLE, MERGED_TABLE }
  public final CodeFormat codeEncoding;

  /** Class::from()..to_snapshot(FullAOT), product layouts in SDK raw_object.h. */
  public record ClassLayout(int library, int declarationType, int allocationStub, int superType) {}
  public final ClassLayout classLayout;

  /** SDK InstructionsSection::HeaderSize rounds its five ARM64 words to this alignment. */
  public final int instructionSectionPayloadAlignment;

  public CodeFormat codeFormat() {
    return codeEncoding;
  }

  /** SDK Instructions::kPolymorphicEntryOffsetAOT on ARM64.
   * Before the 2.19 class-id expansion, LoadClassId is one halfword load;
   * newer SDKs use a load plus extraction. The miss/compare prefix grows by 4.
   */
  public int normalEntryOffset(long payloadInfo) {
    return (payloadInfo & 1) == 0 ? 0 : topLevelCid16 ? 20 : 24;
  }

  public int aotKind() {
    return preCanonicalSplit || codeFormat() == CodeFormat.MERGED_TABLE ? 2 : 3;
  }

  public final String dartVersion;
  public final boolean supported;
  public final int headerFields;
  public final TagStyle tagStyle;
  public final DartClassId.Table cids;
  public final boolean compressedPointers;
  public final boolean fillRefUnsigned;
  public final boolean preV32Format;
  public final boolean hasTypeParamClassId;
  public final boolean typeParamByteScalars;
  public final boolean oldTypeScalars;
  public final int typeClassIdShift;
  public final int fieldSharedBit;
  public final boolean topLevelCid16;
  public final boolean oldPoolFormat;
  public final boolean poolTypeSwapped;
  public final boolean oldStringFormat;
  public final boolean oldTypeArgsFill;
  public final boolean oldArrayFill;
  public final boolean serializedCanonicalSets;
  public final boolean splitCanonical;
  public final boolean preCanonicalSplit;

  // Fine-grained per-version cluster layout overrides
  public final int classNumRefs;
  public final boolean classHasTokenPos;
  public final int funcNumRefs;
  public final int funcSignatureRef;
  public final int typeNumRefs;
  public final boolean typeClassIdIsRef;
  public final boolean typeHasTokenPos;
  public final int funcTypeNumRefs;
  public final boolean funcTypeOldScalars;
  public final int typeParamNumRefs;
  public final boolean typeParamWideScalars;
  public final int typeRefNumRefs;
  public final int codeNumRefs;
  public final boolean codeTextOffsetDelta;
  public final int codeStateBitsAfterRef;
  public final boolean codeStateBitsAtEnd;
  public final int closureDataNumRefs;
  public final int namespaceNumRefs;
  public final boolean unitPoolPatches;
  public final boolean scriptHasLineCol;
  public final boolean scriptHasFlags;

  private DartVersionProfile(Builder b) {
    this.dartVersion = b.dartVersion;
    this.codeEncoding = b.codeEncoding;
    this.classLayout = b.classLayout;
    this.instructionSectionPayloadAlignment = b.instructionSectionPayloadAlignment;
    this.supported = b.supported;
    this.headerFields = b.headerFields;
    this.tagStyle = b.tagStyle;
    this.cids = b.cids;
    this.compressedPointers = b.compressedPointers;
    this.fillRefUnsigned = b.fillRefUnsigned;
    this.preV32Format = b.preV32Format;
    this.hasTypeParamClassId = b.hasTypeParamClassId;
    this.typeParamByteScalars = b.typeParamByteScalars;
    this.oldTypeScalars = b.oldTypeScalars;
    this.typeClassIdShift = b.typeClassIdShift;
    this.fieldSharedBit = b.fieldSharedBit;
    this.topLevelCid16 = b.topLevelCid16;
    this.oldPoolFormat = b.oldPoolFormat;
    this.poolTypeSwapped = b.poolTypeSwapped;
    this.oldStringFormat = b.oldStringFormat;
    this.oldTypeArgsFill = b.oldTypeArgsFill;
    this.oldArrayFill = b.oldArrayFill;
    this.serializedCanonicalSets = b.serializedCanonicalSets;
    this.splitCanonical = b.splitCanonical;
    this.preCanonicalSplit = b.preCanonicalSplit;
    this.classNumRefs = b.classNumRefs;
    this.classHasTokenPos = b.classHasTokenPos;
    this.funcNumRefs = b.funcNumRefs;
    this.funcSignatureRef = b.funcSignatureRef;
    this.typeNumRefs = b.typeNumRefs;
    this.typeClassIdIsRef = b.typeClassIdIsRef;
    this.typeHasTokenPos = b.typeHasTokenPos;
    this.funcTypeNumRefs = b.funcTypeNumRefs;
    this.funcTypeOldScalars = b.funcTypeOldScalars;
    this.typeParamNumRefs = b.typeParamNumRefs;
    this.typeParamWideScalars = b.typeParamWideScalars;
    this.typeRefNumRefs = b.typeRefNumRefs;
    this.codeNumRefs = b.codeNumRefs;
    this.codeTextOffsetDelta = b.codeTextOffsetDelta;
    this.codeStateBitsAfterRef = b.codeStateBitsAfterRef;
    this.codeStateBitsAtEnd = b.codeStateBitsAtEnd;
    this.closureDataNumRefs = b.closureDataNumRefs;
    this.namespaceNumRefs = b.namespaceNumRefs;
    this.unitPoolPatches = b.unitPoolPatches;
    this.scriptHasLineCol = b.scriptHasLineCol;
    this.scriptHasFlags = b.scriptHasFlags;
  }

  public DartVersionProfile withCompressedPointers(boolean compressed) {
    if (this.compressedPointers == compressed) {
      return this;
    }
    Builder copy = toBuilder();
    copy.compressedPointers = compressed;
    return copy.build();
  }

  private Builder toBuilder() {
    Builder b = new Builder();
    b.dartVersion = this.dartVersion;
    b.codeEncoding = this.codeEncoding;
    b.classLayout = this.classLayout;
    b.instructionSectionPayloadAlignment = this.instructionSectionPayloadAlignment;
    b.supported = this.supported;
    b.headerFields = this.headerFields;
    b.tagStyle = this.tagStyle;
    b.cids = this.cids;
    b.compressedPointers = this.compressedPointers;
    b.fillRefUnsigned = this.fillRefUnsigned;
    b.preV32Format = this.preV32Format;
    b.hasTypeParamClassId = this.hasTypeParamClassId;
    b.typeParamByteScalars = this.typeParamByteScalars;
    b.oldTypeScalars = this.oldTypeScalars;
    b.typeClassIdShift = this.typeClassIdShift;
    b.fieldSharedBit = this.fieldSharedBit;
    b.topLevelCid16 = this.topLevelCid16;
    b.oldPoolFormat = this.oldPoolFormat;
    b.poolTypeSwapped = this.poolTypeSwapped;
    b.oldStringFormat = this.oldStringFormat;
    b.oldTypeArgsFill = this.oldTypeArgsFill;
    b.oldArrayFill = this.oldArrayFill;
    b.serializedCanonicalSets = this.serializedCanonicalSets;
    b.splitCanonical = this.splitCanonical;
    b.preCanonicalSplit = this.preCanonicalSplit;
    b.classNumRefs = this.classNumRefs;
    b.classHasTokenPos = this.classHasTokenPos;
    b.funcNumRefs = this.funcNumRefs;
    b.funcSignatureRef = this.funcSignatureRef;
    b.typeNumRefs = this.typeNumRefs;
    b.typeClassIdIsRef = this.typeClassIdIsRef;
    b.typeHasTokenPos = this.typeHasTokenPos;
    b.funcTypeNumRefs = this.funcTypeNumRefs;
    b.funcTypeOldScalars = this.funcTypeOldScalars;
    b.typeParamNumRefs = this.typeParamNumRefs;
    b.typeParamWideScalars = this.typeParamWideScalars;
    b.typeRefNumRefs = this.typeRefNumRefs;
    b.codeNumRefs = this.codeNumRefs;
    b.codeTextOffsetDelta = this.codeTextOffsetDelta;
    b.codeStateBitsAfterRef = this.codeStateBitsAfterRef;
    b.codeStateBitsAtEnd = this.codeStateBitsAtEnd;
    b.closureDataNumRefs = this.closureDataNumRefs;
    b.namespaceNumRefs = this.namespaceNumRefs;
    b.unitPoolPatches = this.unitPoolPatches;
    b.scriptHasLineCol = this.scriptHasLineCol;
    b.scriptHasFlags = this.scriptHasFlags;
    return b;
  }

  private static final class Builder {
    String dartVersion;
    CodeFormat codeEncoding = CodeFormat.INSTRUCTIONS_TABLE;
    ClassLayout classLayout = new ClassLayout(7, 11, -1, 9);
    int instructionSectionPayloadAlignment = 4;
    boolean supported = true;
    int headerFields = 5;
    TagStyle tagStyle = TagStyle.OBJECT_HEADER;
    DartClassId.Table cids = DartClassId.CIDS_V3_9;
    boolean compressedPointers = true;
    boolean fillRefUnsigned = false;
    boolean preV32Format = false;
    boolean hasTypeParamClassId = false;
    boolean typeParamByteScalars = false;
    boolean oldTypeScalars = false;
    int typeClassIdShift = 4;
    int fieldSharedBit = -1;
    boolean topLevelCid16 = false;
    boolean oldPoolFormat = false;
    boolean poolTypeSwapped = false;
    boolean oldStringFormat = false;
    boolean oldTypeArgsFill = false;
    boolean oldArrayFill = false;
    boolean serializedCanonicalSets = true;
    boolean splitCanonical = false;
    boolean preCanonicalSplit = false;

    int classNumRefs = 13;
    boolean classHasTokenPos = false;
    int funcNumRefs = 4;
    int funcSignatureRef = 2;
    int typeNumRefs = 3;
    boolean typeClassIdIsRef = false;
    boolean typeHasTokenPos = false;
    int funcTypeNumRefs = 6;
    boolean funcTypeOldScalars = false;
    int typeParamNumRefs = 3;
    boolean typeParamWideScalars = false;
    int typeRefNumRefs = 2;
    int codeNumRefs = 6;
    boolean codeTextOffsetDelta = false;
    int codeStateBitsAfterRef = 0;
    boolean codeStateBitsAtEnd = false;
    int closureDataNumRefs = 2;
    int namespaceNumRefs = 4;
    boolean unitPoolPatches = false;
    boolean scriptHasLineCol = false;
    boolean scriptHasFlags = false;

    public DartVersionProfile build() {
      return new DartVersionProfile(this);
    }
  }

  /** Known 32-char MD5 snapshot hashes mapped to canonical version profile keys. */
  private static final Map<String, String> KNOWN_HASHES = new HashMap<>();

  /** Canonical version profiles from 2.10.0 to 3.13.x+. */
  private static final Map<String, DartVersionProfile> PROFILES = new java.util.LinkedHashMap<>();

  static {
    // Dart 2.10–2.13
    KNOWN_HASHES.put("8ee4ef7a67df9845fba331734198a953", "2.10.0");
    KNOWN_HASHES.put("e4a09dbf2bb120fe4674e0576617a0dc", "2.13.0");
    KNOWN_HASHES.put("34f6eec64e9371856eaaa278ccf56538", "2.13.0");
    KNOWN_HASHES.put("7a5b240780941844bae88eca5dbaa7b8", "2.13.0");

    // Dart 2.14–2.19
    KNOWN_HASHES.put("9cf77f4405212c45daf608e1cd646852", "2.14.0");
    KNOWN_HASHES.put("659a72e41e3276e882709901c27de33d", "2.14.0");
    KNOWN_HASHES.put("f10776149bf76be288def3c2ca73bdc1", "2.15.0");
    KNOWN_HASHES.put("24d9d411c2f90c8fbe8907f99e89d4b0", "2.15.0");
    KNOWN_HASHES.put("d56742caf7b3b3f4bd2df93a9bbb5503", "2.16.0");
    KNOWN_HASHES.put("3318fe66091c0ffbb64faec39976cb7d", "2.16.0");
    KNOWN_HASHES.put("adf563436d12ba0d50ea5beb7f3be1bb", "2.16.0");
    KNOWN_HASHES.put("1441d6b13b8623fa7fbf61433abebd31", "2.17.6");
    KNOWN_HASHES.put("a0cb0c928b23bc17a26e062b351dc44d", "2.17.6");
    KNOWN_HASHES.put("ded6ef11c73fdc638d6ff6d3ad22a67b", "2.17.6");
    KNOWN_HASHES.put("b0e899ec5a90e4661501f0b69e9dd70f", "2.18.0");
    KNOWN_HASHES.put("b6d0a1f034d158b0d37b51d559379697", "2.18.0");
    KNOWN_HASHES.put("8e50e448b241be23b9e990094f4dca39", "2.18.0");
    KNOWN_HASHES.put("6a9b5a03a7e784a4558b10c769f188d9", "2.18.0");
    KNOWN_HASHES.put("adb4292f3ec25074ca70abcd2d5c7251", "2.19.0");
    KNOWN_HASHES.put("501ef5cbd64ca70b6b42672346af6a8a", "2.19.0");

    // Dart 3.0–3.13+
    KNOWN_HASHES.put("90b56a561f70cd55e972cb49b79b3d8b", "3.0.5");
    KNOWN_HASHES.put("aa64af18e7d086041ac127cc4bc50c5e", "3.0.5");
    KNOWN_HASHES.put("36b0375d284ee2af0d0fffc6e6e48fde", "3.0.5");
    KNOWN_HASHES.put("16ad76edd19b537bf6ea64fdd31977a7", "3.0.5");
    KNOWN_HASHES.put("7dbbeeb8ef7b91338640dca3927636de", "3.1.0");
    KNOWN_HASHES.put("f71c76320d35b65f1164dbaa6d95fe09", "3.2.5");
    KNOWN_HASHES.put("ee1eb666c76a5cb7746faf39d0b97547", "3.3.0");
    KNOWN_HASHES.put("d20a1be77c3d3c41b2a5accaee1ce549", "3.4.3");
    KNOWN_HASHES.put("80a49c7111088100a233b2ae788e1f48", "3.5.0");
    KNOWN_HASHES.put("cda356e9bae476c70de33809fd92e009", "3.5.0");
    KNOWN_HASHES.put("2858c2c0920495f00b9bce9edf6a8cd9", "3.6.2");
    KNOWN_HASHES.put("f956f595844a2f845a55707faaaa51e4", "3.6.2");
    KNOWN_HASHES.put("d91c0e6f35f0eb2e44124e8f42aa44a7", "3.7.0");
    KNOWN_HASHES.put("830f4f59e7969c70b595182826435c19", "3.8.1");
    KNOWN_HASHES.put("97ff04a728735e6b6b098bdf983faaba", "3.9.2");
    KNOWN_HASHES.put("1ce86630892e2dca9a8543fdb8ed8e22", "3.10.7");
    KNOWN_HASHES.put("78da37fed6bf1489361a312568249f3f", "3.11.0");
    KNOWN_HASHES.put("7d8fb82a698d78184f7d1e3bbc00540a", "3.11.5");
    KNOWN_HASHES.put("bf2a89a0870c9457c268c1bc89403fe1", "3.12.0");
    KNOWN_HASHES.put("0451907c2eaa8467e848c0067bfe8ed4", "3.13.3");

    initProfiles();
  }

  private static void initProfiles() {
    // Each registration records only the serialization changes from the previous
    // layout. Published profiles are immutable copies, not mutable parent chains.
    Builder layout = new Builder();

    // SDK 2.10.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.headerFields = 4;
    layout.tagStyle = TagStyle.CID_INT32;
    layout.cids = DartClassId.CIDS_V2_10;
    layout.compressedPointers = false;
    layout.fillRefUnsigned = true;
    layout.preV32Format = true;
    layout.hasTypeParamClassId = true;
    layout.typeParamByteScalars = true;
    layout.oldTypeScalars = true;
    layout.topLevelCid16 = true;
    layout.oldPoolFormat = true;
    layout.oldStringFormat = true;
    layout.preCanonicalSplit = true;
    layout.classNumRefs = 16;
    layout.classLayout = new ClassLayout(8, 13, 15, 10);
    layout.classHasTokenPos = true;
    layout.funcNumRefs = 7;
    layout.funcSignatureRef = -1; // Result type and parameter types are separate objects.
    layout.typeNumRefs = 5;
    layout.typeClassIdIsRef = true;
    layout.typeHasTokenPos = true;
    layout.typeParamNumRefs = 5;
    layout.codeNumRefs = 7;
    layout.codeTextOffsetDelta = true;
    layout.codeStateBitsAtEnd = true;
    layout.scriptHasLineCol = true;
    layout.scriptHasFlags = true;
    layout.codeEncoding = CodeFormat.BARE_OFFSETS;
    register("2.10.0", layout);

    // SDK 2.12.0: vm/clustered_snapshot.cc.
    layout.headerFields = 5;
    layout.cids = DartClassId.CIDS_V2_12;
    layout.splitCanonical = true;
    layout.preCanonicalSplit = false;
    layout.classNumRefs = 15;
    layout.classLayout = new ClassLayout(8, 12, 14, 10);
    layout.funcNumRefs = 5;
    layout.funcSignatureRef = 3; // parameter_names precedes signature in 2.12 and 2.13.
    layout.typeNumRefs = 4;
    layout.typeHasTokenPos = false;
    layout.funcTypeOldScalars = true;
    layout.typeParamWideScalars = true;
    layout.codeStateBitsAfterRef = 0;
    layout.codeStateBitsAtEnd = true;
    layout.closureDataNumRefs = 4;
    layout.scriptHasFlags = false;
    // SDK 2.12 has split canonical clusters but rebuilds canonical sets after loading.
    layout.serializedCanonicalSets = false;
    register("2.12.0", layout);

    // 2.13 moves Code state_bits after compressed_stackmaps, packs ClosureData
    // metadata, narrows Namespace to target_ and adds deferred pool patches.
    layout.codeStateBitsAfterRef = 1;
    layout.codeStateBitsAtEnd = false;
    layout.closureDataNumRefs = 3;
    layout.namespaceNumRefs = 1;
    layout.unitPoolPatches = true;
    layout.cids = DartClassId.CIDS_V2_13;
    layout.serializedCanonicalSets = true;
    register("2.13.0", layout);

    // SDK 2.14.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.tagStyle = TagStyle.CID_SHIFT_1;
    layout.cids = DartClassId.CIDS_V2_14;
    layout.compressedPointers = true;
    layout.splitCanonical = false;
    layout.classNumRefs = 13;
    layout.classLayout = new ClassLayout(7, 11, -1, 9);
    layout.classHasTokenPos = false;
    layout.funcNumRefs = 4;
    layout.funcSignatureRef = 2;
    layout.funcTypeOldScalars = false;
    layout.typeParamNumRefs = 3;
    layout.typeParamWideScalars = false;
    layout.codeStateBitsAfterRef = 0;
    layout.closureDataNumRefs = 2;
    layout.scriptHasLineCol = false;
    register("2.14.0", layout);

    // SDK 2.15.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.cids = DartClassId.CIDS_V2_15;
    // StringSerializationCluster already combines width and length in 2.15.
    layout.oldStringFormat = false;
    layout.typeNumRefs = 3;
    layout.typeClassIdIsRef = false;
    register("2.15.0", layout);

    // SDK 2.16.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.headerFields = 6;
    layout.cids = DartClassId.CIDS_V2_16;
    layout.codeNumRefs = 6;
    layout.codeTextOffsetDelta = false;
    layout.codeEncoding = CodeFormat.INSTRUCTIONS_TABLE;
    register("2.16.0", layout);

    // SDK 2.17.6: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.cids = DartClassId.CIDS_V2_17;
    register("2.17.6", layout);

    // SDK 2.18.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.headerFields = 5;
    layout.cids = DartClassId.CIDS_V2_18;
    layout.fillRefUnsigned = false;
    register("2.18.0", layout);

    // SDK 2.19.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.cids = DartClassId.CIDS_V2_19;
    layout.oldTypeScalars = false;
    layout.topLevelCid16 = false;
    register("2.19.0", layout);

    // SDK 3.0.5: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.cids = DartClassId.CIDS_V3_0;
    layout.typeParamByteScalars = false;
    register("3.0.5", layout);

    // SDK 3.1.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.cids = DartClassId.CIDS_V3_1;
    layout.hasTypeParamClassId = false;
    register("3.1.0", layout);

    // SDK 3.2.5: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.preV32Format = false;
    layout.poolTypeSwapped = true;
    register("3.2.5", layout);

    // SDK 3.3.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.oldPoolFormat = false;
    layout.poolTypeSwapped = false;
    register("3.3.0", layout);

    // SDK 3.4.3: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.tagStyle = TagStyle.OBJECT_HEADER;
    layout.cids = DartClassId.CIDS_V3_4;
    register("3.4.3", layout);

    // SDK 3.5.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    // SDK object.h: kPayloadAlignment = 32 replaces kBarePayloadAlignment = 4.
    layout.instructionSectionPayloadAlignment = 32;
    // raw_object.h: NullabilityBits shrinks from two bits to one, below TypeStateBits.
    layout.typeClassIdShift = 3;
    // object.h Field::kSharedBit selects the second serialized field table.
    layout.fieldSharedBit = 15;
    register("3.5.0", layout);

    // SDK 3.6.2: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.cids = DartClassId.CIDS_V3_6;
    register("3.6.2", layout);

    // SDK 3.7.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    register("3.7.0", layout);

    // SDK 3.8.1: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    register("3.8.1", layout);

    // SDK 3.9.2: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.cids = DartClassId.CIDS_V3_9;
    register("3.9.2", layout);

    // SDK 3.10.7: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    register("3.10.7", layout);

    // SDK 3.11.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    register("3.11.0", layout);

    // SDK 3.11.5: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    register("3.11.5", layout);

    // SDK 3.12.0: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    register("3.12.0", layout);

    // SDK 3.13.3: vm/app_snapshot.cc (older SDKs: clustered_snapshot.cc).
    layout.cids = DartClassId.CIDS_V3_13;
    layout.codeEncoding = CodeFormat.MERGED_TABLE;
    register("3.13.3", layout);
  }

  private static void register(String version, Builder layout) {
    layout.dartVersion = version;
    PROFILES.put(version, layout.build());
  }

  /** Returns the map of known 32-char snapshot hashes to canonical version keys. */
  public static Map<String, String> knownHashes() {
    return java.util.Collections.unmodifiableMap(KNOWN_HASHES);
  }

  /** Returns a predefined profile by version key (e.g., "3.10.7", "2.19.0", "2.10.0"). */
  public static DartVersionProfile forVersion(String version) {
    DartVersionProfile p = PROFILES.get(version);
    if (p == null) throw new IllegalArgumentException("unsupported Dart format: " + version);
    return p;
  }

  /** Select a known serialization layout. A hash selects a reader, not proof of validity. */
  public static DartVersionProfile detect(DartSnapshotHeader header, byte[] snapshotData) {
    boolean compressed = header.isCompressedPointers();
    String hash = header.snapshotHash;
    if (hash != null) {
      String exact = KNOWN_HASHES.get(hash);
      if (exact != null) {
        return forVersion(exact).withCompressedPointers(compressed);
      }
    }
    throw new IllegalArgumentException("unknown snapshot format hash: " + hash);
  }

  /** A hash is only a hint. Every candidate still has to decode the complete snapshot pair. */
  public static List<DartVersionProfile> candidates(DartSnapshotHeader envelope) {
    var candidates = new java.util.LinkedHashMap<String, DartVersionProfile>();
    String hint = KNOWN_HASHES.get(envelope.snapshotHash);
    if (hint != null) candidates.put(hint, forVersion(hint));
    candidates.putAll(PROFILES);
    return candidates.values().stream()
        .filter(profile -> profile.aotKind() == envelope.kind)
        .map(profile -> profile.withCompressedPointers(envelope.isCompressedPointers()))
        .toList();
  }

  public static boolean isHashHint(DartSnapshotHeader envelope, DartVersionProfile profile) {
    return profile.dartVersion.equals(KNOWN_HASHES.get(envelope.snapshotHash));
  }

  /** Decoded cluster header tag. */
  public static final class DecodedTag {
    public final int cid;
    public final boolean canonical;
    public final boolean immutable;

    public DecodedTag(int cid, boolean canonical, boolean immutable) {
      this.cid = cid;
      this.canonical = canonical;
      this.immutable = immutable;
    }
  }

  /**
   * Decodes one cluster tag from the stream according to {@link #tagStyle}.
   *
   * In Dart 3.4+ ({@link TagStyle#OBJECT_HEADER}):
   * <ul>
   *   <li>{@code kCanonicalBit = 1} ({@code (raw & (1 << 1)) != 0})</li>
   *   <li>{@code kImmutableBit = 6} ({@code (raw & (1 << 6)) != 0})</li>
   *   <li>{@code kClassIdTagPos = 12}, {@code kClassIdTagSize = 20}</li>
   * </ul>
   */
  public static DecodedTag decodeClusterTag(
      DartStream s, DartVersionProfile profile, int clusterIndex, long numCanonicalClusters)
      throws IOException {
    switch (profile.tagStyle) {
      case OBJECT_HEADER: {
        int raw = s.readTagged32();
        int cid = (raw >>> 12) & 0xfffff;
        boolean canonical = (raw & (1 << 1)) != 0;
        boolean immutable = (raw & (1 << 6)) != 0;
        return new DecodedTag(cid, canonical, immutable);
      }
      case CID_SHIFT_1: {
        long raw = s.readTagged64();
        int cid = (int) (raw >>> 1);
        boolean canonical = (raw & 1L) != 0;
        return new DecodedTag(cid, canonical, false);
      }
      case CID_INT32: {
        int cid = (int) s.readTagged64();
        boolean canonical = profile.splitCanonical && (clusterIndex < numCanonicalClusters);
        return new DecodedTag(cid, canonical, false);
      }
      default:
        throw new IllegalStateException("Unexpected tagStyle: " + profile.tagStyle);
    }
  }
}
