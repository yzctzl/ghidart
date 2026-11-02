package ghidart;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Clustered Dart AOT Snapshot Deserializer (Layer 2).
 *
 * Parses the Clustered Snapshot Alloc and Fill streams for both VM and Isolate
 * snapshots for explicitly identified SDK layouts, recovering:
 * <ul>
 *   <li>All allocated cluster metadata ({@link ClusterMeta}) with self-validation
 *       ({@code totalAllocatedRefs == numObjects})</li>
 *   <li>String literals (inline Fill strings and ROData image strings)</li>
 *   <li>Mint integer constants (for field offset and pool resolution)</li>
 *   <li>Named objects (Function, Class, Field, Script, Library, LibraryPrefix, UnlinkedCall, UserTag)</li>
 *   <li>FunctionType parameter counts ({@link FuncTypeInfo})</li>
 *   <li>Class and Field layouts ({@link ClassInfo}, {@link FieldInfo})</li>
 *   <li>Code entries and owner Function/Closure links ({@link CodeEntry})</li>
 *   <li>ObjectPool entries (tagged object refs, immediates, native functions) ({@link PoolEntry})</li>
 * </ul>
 */
public final class DartClusterParser {

  /** Root references are scoped snapshot IDs; dispatch entries remain Code indices. */
  public record RootData(Map<String, Integer> references, int[] staticFields,
      int[] sharedStaticFields, int firstCodeRef, long[] dispatchCodeIndices,
      int endOffset, UnitData unit, Map<String, Integer> baseIdentities) {
    public RootData(Map<String, Integer> references, int[] staticFields,
        int[] sharedStaticFields, int firstCodeRef, long[] dispatchCodeIndices, int endOffset) {
      this(references, staticFields, sharedStaticFields, firstCodeRef, dispatchCodeIndices, endOffset, null);
    }
    public RootData(Map<String, Integer> references, int[] staticFields,
        int[] sharedStaticFields, int firstCodeRef, long[] dispatchCodeIndices,
        int endOffset, UnitData unit) {
      this(references, staticFields, sharedStaticFields, firstCodeRef, dispatchCodeIndices,
          endOffset, unit, Map.of());
    }
    public RootData {
      baseIdentities = Map.copyOf(baseIdentities);
      references = Collections.unmodifiableMap(new java.util.LinkedHashMap<>(references));
      staticFields = staticFields.clone();
      sharedStaticFields = sharedStaticFields.clone();
      dispatchCodeIndices = dispatchCodeIndices.clone();
    }
    @Override public int[] staticFields() { return staticFields.clone(); }
    @Override public int[] sharedStaticFields() { return sharedStaticFields.clone(); }
    @Override public long[] dispatchCodeIndices() { return dispatchCodeIndices.clone(); }
  }

  /** Updates to inherited identities, not newly allocated objects in this unit. */
  public record UnitData(int firstCodeRef, int codeCount, Map<Integer, Integer> poolUpdates,
      Map<Integer, Integer> codeSourceMaps, Map<Integer, Integer> codeStackMaps) {
    public UnitData {
      poolUpdates = Map.copyOf(poolUpdates);
      codeSourceMaps = Map.copyOf(codeSourceMaps);
      codeStackMaps = Map.copyOf(codeStackMaps);
    }
  }

  public enum AllocKind {
    SIMPLE,
    CANONICAL_SET,
    STRING,
    MINT,
    ARRAY,
    WEAK_ARRAY,
    TYPE_ARGUMENTS,
    CLASS,
    CODE,
    OBJECT_POOL,
    RODATA,
    EXCEPTION_HANDLERS,
    LOCAL_VARIABLES,
    VARIABLE_CLOSURE,
    CONTEXT,
    CONTEXT_SCOPE,
    RECORD,
    TYPED_DATA,
    INSTANCE,
    EMPTY,
    UNKNOWN
  }

  public enum FillKind {
    REFS,
    STRING,
    NONE,
    DOUBLE,
    CODE,
    OBJECT_POOL,
    ARRAY,
    WEAK_ARRAY,
    TYPED_DATA,
    EXTERNAL_TYPED_DATA,
    EXCEPTION_HANDLERS,
    LOCAL_VARIABLES,
    VARIABLE_CLOSURE,
    CONTEXT,
    TYPE_ARGUMENTS,
    RODATA,
    INSTANCE,
    RECORD,
    CONTEXT_SCOPE,
    SENTINEL,
    INSTRUCTIONS_TABLE,
    CLASS,
    FIELD,
    INLINE_BYTES,
    UNKNOWN
  }

  public enum ScalarOp {
    TAGGED_32,
    TAGGED_64,
    UNSIGNED,
    BOOL,
    UINT8,
    UINT16,
    INT16,
    INT8,
    REF_ID
  }

  /** Serialized canonical hash-table layout; gaps are not object reference IDs. */
  public record CanonicalSet(long tableLength, long firstElement, long[] gaps) {
    public CanonicalSet { gaps = gaps.clone(); }
    @Override public long[] gaps() { return gaps.clone(); }
  }

  public static final class ClusterMeta {
    public final int index;
    public final int cid;
    public final boolean isCanonical;
    public final boolean isImmutable;
    public long count;
    public final int startRef;
    public int stopRef;
    public final int startOffset;
    public int endOffset;

    public int nextFieldOffsetInWords;
    public int instanceSizeInWords;
    public long mainCount;
    public Set<Long> discardedCodes;
    public int[] codeStateBits;
    public long[] lengths;
    public long[] predefCids;
    public long canonicalCount = -1;
    public long[] mintCanonical;
    public CanonicalSet canonicalSet;
    public int lazyCompileRef;
    public int unknownDartCodeRef;

    public ClusterMeta(
        int index, int cid, boolean isCanonical, boolean isImmutable, int startRef, int startOffset) {
      this.index = index;
      this.cid = cid;
      this.isCanonical = isCanonical;
      this.isImmutable = isImmutable;
      this.startRef = startRef;
      this.startOffset = startOffset;
    }
  }

  /**
   * Lossless fields retained in serialization order. These are object references,
   * not addresses; byte spans point into the original snapshot input. Typed views
   * below interpret these same facts without losing unlabelled fields.
   */
  public record ObjectData(int refId, int cid, int[] references, long[] scalars,
      int dataOffset, int dataLength) {
    public ObjectData {
      references = references.clone();
      scalars = scalars.clone();
    }

    @Override public int[] references() { return references.clone(); }
    @Override public long[] scalars() { return scalars.clone(); }
  }

  public static final class ParsedString {
    public final int refId;
    public final String value;
    public final boolean isOneByte;
    public final int dataOffset;
    public final int headerOffset;
    public final int headerLength;
    public final boolean objectHeader;

    public ParsedString(int refId, String value, boolean isOneByte, int dataOffset) {
      this(refId, value, isOneByte, dataOffset, -1, 0, false);
    }

    public ParsedString(int refId, String value, boolean isOneByte, int dataOffset,
        int headerOffset, int headerLength, boolean objectHeader) {
      this.refId = refId;
      this.value = value;
      this.isOneByte = isOneByte;
      this.dataOffset = dataOffset;
      this.headerOffset = headerOffset;
      this.headerLength = headerLength;
      this.objectHeader = objectHeader;
    }
  }

  public static final class NamedObject {
    public final int cid;
    public final int refId;
    public final int nameRefId;
    public final int ownerRefId;
    public final int signatureRefId;

    public NamedObject(int cid, int refId, int nameRefId, int ownerRefId, int signatureRefId) {
      this.cid = cid;
      this.refId = refId;
      this.nameRefId = nameRefId;
      this.ownerRefId = ownerRefId;
      this.signatureRefId = signatureRefId;
    }
  }

  public static final class FuncTypeInfo {
    public final int refId;
    public final int numFixed;
    public final int numOptional;
    public final boolean hasImplicit;

    public FuncTypeInfo(int refId, int numFixed, int numOptional, boolean hasImplicit) {
      this.refId = refId;
      this.numFixed = numFixed;
      this.numOptional = numOptional;
      this.hasImplicit = hasImplicit;
    }
  }

  public static final class ClassInfo {
    public final int refId;
    public final int nameRefId;
    public final int libraryRefId;
    public final int superTypeRefId;
    public final int declarationTypeRefId;
    public final int allocationStubRefId;
    public final int classId;
    public final int instanceSizeInWords;
    public final int nextFieldOffInWords;
    public final int typeArgsOffInWords;
    public final long unboxedFields;

    public ClassInfo(
        int refId,
        int nameRefId,
        int libraryRefId,
        int superTypeRefId,
        int declarationTypeRefId,
        int allocationStubRefId,
        int classId,
        int instanceSizeInWords,
        int nextFieldOffInWords,
        int typeArgsOffInWords, long unboxedFields) {
      this.refId = refId;
      this.nameRefId = nameRefId;
      this.libraryRefId = libraryRefId;
      this.superTypeRefId = superTypeRefId;
      this.declarationTypeRefId = declarationTypeRefId;
      this.allocationStubRefId = allocationStubRefId;
      this.classId = classId;
      this.instanceSizeInWords = instanceSizeInWords;
      this.nextFieldOffInWords = nextFieldOffInWords;
      this.typeArgsOffInWords = typeArgsOffInWords;
      this.unboxedFields = unboxedFields;
    }
  }

  public static final class TypeInfo {
    public final int refId;
    public final int cid;
    public final int[] refs;
    public final long[] scalars;

    public TypeInfo(int refId, int cid, int[] refs, long[] scalars) {
      this.refId = refId;
      this.cid = cid;
      this.refs = refs;
      this.scalars = scalars;
    }
  }

  public static final class FieldInfo {
    public final int refId;
    public final int nameRefId;
    public final int ownerRefId;
    public final int kindBits;
    public final int hostOffsetOrRef;
    /** Legacy initial value, or a Smi carrying an offset/static field ID; not a byte offset. */
    public final int valueOrOffsetRefId;
    /** Inline field ID in older formats; -1 when absent or carried by the Smi reference. */
    public final long staticFieldId;

    public FieldInfo(int refId, int nameRefId, int ownerRefId, int kindBits,
        int valueOrOffsetRefId, long staticFieldId) {
      this.refId = refId;
      this.nameRefId = nameRefId;
      this.ownerRefId = ownerRefId;
      this.kindBits = kindBits;
      this.hostOffsetOrRef = ((kindBits >>> 1) & 1) != 0 ? -1 : valueOrOffsetRefId;
      this.valueOrOffsetRefId = valueOrOffsetRefId;
      this.staticFieldId = staticFieldId;
    }
  }

  /** Snapshot storage only: a static initial value can change after loading. */
  public record FieldStorage(boolean isStatic, boolean shared, Long offsetOrId,
      Integer initialValueRef) {}

  public static final class CodeEntry {
    public final int refId;
    public final int ownerRef;
    public final int clusterIndex;
    public final long payloadInfo;
    public final long textOffset;
    public final int exceptionRef;

    public CodeEntry(int refId, int ownerRef, int clusterIndex, long payloadInfo, long textOffset, int exceptionRef) {
      this.refId = refId;
      this.ownerRef = ownerRef;
      this.clusterIndex = clusterIndex;
      this.payloadInfo = payloadInfo;
      this.textOffset = textOffset;
      this.exceptionRef = exceptionRef;
    }
  }

  public enum PoolEntryKind {
    TAGGED,
    IMMEDIATE,
    NATIVE,
    EMPTY
  }

  public static final class PoolEntry {
    public final int poolRef;
    public final int index;
    public final int bits;
    public final PoolEntryKind kind;
    public final int refId;
    public final long imm;

    public PoolEntry(int poolRef, int index, int bits, PoolEntryKind kind, int refId, long imm) {
      this.poolRef = poolRef;
      this.bits = bits;
      this.index = index;
      this.kind = kind;
      this.refId = refId;
      this.imm = imm;
    }

    /** ObjectPoolBuilderEntry used a 7-bit type / bit-7 patchability before
     * SnapshotBehavior introduced 4-bit types / bit-4 patchability. In both
     * eras kPatchable=0 and kNotPatchable=1. Trait decoding belongs to the
     * selected format, not to consumers of an unqualified raw bits byte.
     */
    public boolean isPatchable(DartVersionProfile profile) {
      return (bits & (profile.oldPoolFormat ? 0x80 : 0x10)) == 0;
    }

    public int stableTaggedBits(DartVersionProfile profile) {
      return profile.oldPoolFormat ? 0x80 | (profile.poolTypeSwapped ? 1 : 0) : 0x11;
    }

    /** Byte offset relative to the untagged ObjectPool pointer: {@code index * 8 + 16}. */
    public long byteOffsetFromUntaggedPool() {
      return (long) index * 8L + 16L;
    }

    /**
     * Byte offset relative to a tagged ObjectPool object, not ARM64 PP.
     * ARM64 PP is untagged (Assembler::LoadPoolPointer); machine-code accesses
     * use {@link #byteOffsetFromUntaggedPool()}.
     */
    public long byteOffsetFromTaggedPp() {
      return (long) index * 8L + 15L;
    }
  }

  public static final class FillSpec {
    public final FillKind kind;
    public final int numRefs;
    public final ScalarOp[] scalars;
    public final int nameIdx;
    public final int ownerIdx;
    public final int signatureIdx;
    public final boolean leadingBool;
    public final boolean isFuncType;
    public final boolean isField;

    public FillSpec(
        FillKind kind,
        int numRefs,
        ScalarOp[] scalars,
        int nameIdx,
        int ownerIdx,
        int signatureIdx,
        boolean leadingBool,
        boolean isFuncType,
        boolean isField) {
      this.kind = kind;
      this.numRefs = numRefs;
      this.scalars = scalars != null ? scalars : new ScalarOp[0];
      this.nameIdx = nameIdx;
      this.ownerIdx = ownerIdx;
      this.signatureIdx = signatureIdx;
      this.leadingBool = leadingBool;
      this.isFuncType = isFuncType;
      this.isField = isField;
    }

    public FillSpec(FillKind kind) {
      this(kind, 0, null, -1, -1, -1, false, false, false);
    }

    public FillSpec(FillKind kind, int numRefs, ScalarOp[] scalars, int nameIdx, int ownerIdx) {
      this(kind, numRefs, scalars, nameIdx, ownerIdx, -1, false, false, false);
    }

    public FillSpec withLeadingBool(boolean b) {
      if (this.leadingBool == b) {
        return this;
      }
      return new FillSpec(
          kind, numRefs, scalars, nameIdx, ownerIdx, signatureIdx, b, isFuncType, isField);
    }
  }

  public static final class Result {
    public final Result vm;
    public final DartSnapshotHeader header;
    public final DartVersionProfile profile;
    public final List<ClusterMeta> clusters;
    public final Map<Integer, ObjectData> objects;
    public final Map<Integer, List<Integer>> exceptionEntries;
    public final List<ParsedString> strings;
    public final List<NamedObject> namedObjects;
    public final List<FuncTypeInfo> funcTypes;
    public final List<TypeInfo> types;
    public final List<ClassInfo> classes;
    public final List<FieldInfo> fields;
    public final List<CodeEntry> codes;
    public final List<PoolEntry> poolEntries;
    public final Map<Integer, Long> mintValues;
    public final int fillStartOffset;
    public final int fillEndOffset;
    public final RootData roots;
    public final int totalAllocatedRefs;
    public final List<String> diagnostics;

    // Resolved lookup tables
    public final Map<Integer, String> stringByRef;
    public final Map<Integer, NamedObject> namedByRef;
    public final Map<Integer, Integer> cidByRef;
    public final Map<Integer, String> classNameByCid;
    public final Map<Integer, Integer> classRefByCid;
    public final Map<Integer, String> typeNameByRef;
    public final Map<Integer, String> functionNameByCodeSlot;
    public final Map<Integer, String> ownerKindByCodeSlot;
    public final Map<Integer, Integer> paramCountByCodeSlot;
    public final Map<Long, String> functionNameByTextOffset;
    public final Map<Long, Integer> paramCountByTextOffset;
    public final Map<Integer, List<PoolEntry>> pools;

    public Result(
        DartSnapshotHeader header,
        DartVersionProfile profile,
        List<ClusterMeta> clusters,
        List<ObjectData> objects,
        Map<Integer, List<Integer>> exceptionEntries,
        List<ParsedString> strings,
        List<NamedObject> namedObjects,
        List<FuncTypeInfo> funcTypes,
        List<TypeInfo> types,
        List<ClassInfo> classes,
        List<FieldInfo> fields,
        List<CodeEntry> codes,
        List<PoolEntry> poolEntries,
        Map<Integer, Long> mintValues,
        int fillStartOffset,
        int fillEndOffset,
        RootData roots,
        int totalAllocatedRefs,
        List<String> diagnostics,
        Result vmResult) {
      this.vm = vmResult;
      this.header = header;
      this.profile = profile;
      this.clusters = List.copyOf(clusters);
      var objectMap = new HashMap<Integer, ObjectData>();
      for (var object : objects) {
        if (objectMap.put(object.refId(), object) != null) {
          throw new IllegalArgumentException("duplicate serialized object " + object.refId());
        }
      }
      if (objectMap.size() != header.numObjects - header.numBaseObjects) {
        throw new IllegalArgumentException("serialized object records omit local allocations");
      }
      for (var cluster : clusters) {
        for (int ref = cluster.startRef; ref < cluster.stopRef; ref++) {
          var object = objectMap.get(ref);
          if (object == null || object.cid() != cluster.cid) {
            throw new IllegalArgumentException("serialized identity differs from allocation: " + ref);
          }
        }
      }
      this.objects = Map.copyOf(objectMap);
      this.exceptionEntries = Map.copyOf(exceptionEntries);
      this.strings = Collections.unmodifiableList(strings);
      this.namedObjects = Collections.unmodifiableList(namedObjects);
      this.funcTypes = Collections.unmodifiableList(funcTypes);
      this.types = Collections.unmodifiableList(types);
      this.classes = Collections.unmodifiableList(classes);
      this.fields = Collections.unmodifiableList(fields);
      this.codes = Collections.unmodifiableList(codes);
      this.poolEntries = Collections.unmodifiableList(poolEntries);
      this.mintValues = Collections.unmodifiableMap(mintValues);
      this.fillStartOffset = fillStartOffset;
      this.fillEndOffset = fillEndOffset;
      this.roots = roots;
      this.totalAllocatedRefs = totalAllocatedRefs;
      this.diagnostics = Collections.unmodifiableList(diagnostics);

      Map<Integer, String> sMap = new HashMap<>(strings.size() * 2);
      for (ParsedString ps : strings) {
        sMap.put(ps.refId, ps.value);
      }
      this.stringByRef = Collections.unmodifiableMap(sMap);

      Map<Integer, NamedObject> nMap = new HashMap<>(namedObjects.size() * 2);
      for (NamedObject no : namedObjects) {
        nMap.put(no.refId, no);
      }
      this.namedByRef = Collections.unmodifiableMap(nMap);

      Map<Integer, Integer> cMap = new HashMap<>();
      for (ClusterMeta cm : clusters) {
        for (int r = cm.startRef; r < cm.stopRef; r++) {
          cMap.put(r, cm.cid);
        }
      }
      this.cidByRef = Collections.unmodifiableMap(cMap);

      DartClassId.Table ct = profile.cids;
      Map<Integer, String> cidNames = new HashMap<>();
      Map<Integer, Integer> classRefs = new HashMap<>();
      for (int c = 1; c < ct.numPredefinedCids; c++) {
        String cn = ct.nameOf(c);
        if (!cn.startsWith("CID_")) {
          cidNames.put(c, cn);
        }
      }
      if (vmResult != null) {
        cidNames.putAll(vmResult.classNameByCid);
        classRefs.putAll(vmResult.classRefByCid);
      }
      Map<Integer, String> tNameMap = new HashMap<>();
      if (vmResult != null) {
        tNameMap.putAll(vmResult.typeNameByRef);
      }
      Map<Integer, String> allocStubClassByCodeRef = new HashMap<>();
      for (ClassInfo ci : classes) {
        classRefs.put(ci.classId, ci.refId);
        String cn = resolveString(ci.nameRefId, sMap, vmResult);
        if (cn != null && !cn.isEmpty()) {
          cidNames.put(ci.classId, cn);
          if (ci.declarationTypeRefId > 0) {
            tNameMap.put(ci.declarationTypeRefId, cn);
          }
          if (ci.allocationStubRefId > 0) {
            allocStubClassByCodeRef.put(ci.allocationStubRefId, cn);
          }
        }
      }
      this.classNameByCid = Collections.unmodifiableMap(cidNames);
      this.classRefByCid = Collections.unmodifiableMap(classRefs);

      for (TypeInfo ti : types) {
        if (tNameMap.containsKey(ti.refId)) {
          continue;
        }
        String resolvedType = cidNames.get(typeClassId(ti, profile, mintValues, vmResult));
        if (resolvedType != null && !resolvedType.isEmpty()) {
          tNameMap.put(ti.refId, resolvedType);
        }
      }
      this.typeNameByRef = Collections.unmodifiableMap(tNameMap);

      Map<Integer, FuncTypeInfo> ftByRef = new HashMap<>(funcTypes.size() * 2);
      for (FuncTypeInfo ft : funcTypes) {
        ftByRef.put(ft.refId, ft);
      }

      Map<Integer, String> fnBySlot = new HashMap<>();
      Map<Integer, String> kindBySlot = new HashMap<>();
      Map<Integer, Integer> pcBySlot = new HashMap<>();
      Map<Long, String> fnByTextOff = new HashMap<>();
      Map<Long, Integer> pcByTextOff = new HashMap<>();
      Map<Integer, String> codeRefDisplay = new HashMap<>();

      for (CodeEntry ce : codes) {
        String fnName = null;
        String ownerKind = "Null";
        int paramCount = 0;

        if (ce.ownerRef > 1) {
          NamedObject owner = nMap.get(ce.ownerRef);
          if (owner == null && vmResult != null) {
            owner = vmResult.named(ce.ownerRef);
          }
          Integer ownerCid = cMap.get(ce.ownerRef);
          if (ownerCid == null && vmResult != null) {
            ownerCid = vmResult.cidByRef.get(ce.ownerRef);
          }

          if (owner != null) {
            String rawName = resolveQualifiedName(owner, sMap, nMap, vmResult);
            if (owner.cid == ct.clazz) {
              ownerKind = "Class";
              fnName = (rawName != null && !rawName.isEmpty())
                  ? ("AllocationStub_" + rawName)
                  : ("AllocationStub_ref_" + ce.ownerRef);
            } else {
              ownerKind = "Function";
              fnName = rawName;
              if (owner.signatureRefId > 0) {
                FuncTypeInfo ft = ftByRef.get(owner.signatureRefId);
                if (ft != null) {
                  paramCount = ft.numFixed + ft.numOptional;
                }
              }
            }
          } else if (ownerCid != null && ownerCid == ct.type) {
            ownerKind = "Type";
            String tName = tNameMap.get(ce.ownerRef);
            fnName = (tName != null && !tName.isEmpty())
                ? ("TypeTestingStub_" + tName)
                : ("TypeTestingStub_ref_" + ce.ownerRef);
          } else if (ownerCid != null
              && (ownerCid == ct.functionType
                  || ownerCid == ct.recordType
                  || ownerCid == ct.typeParameter)) {
            ownerKind = "Type";
            fnName = "TypeTestingStub_" + ct.nameOf(ownerCid) + "_" + ce.ownerRef;
          } else if ((ownerCid != null && ownerCid == ct.mint)
              || mintValues.containsKey(ce.ownerRef)
              || (vmResult != null && vmResult.integer(ce.ownerRef) != null)) {
            ownerKind = "Mint";
            Long mv = mintValues.get(ce.ownerRef);
            if (mv == null && vmResult != null) {
              mv = vmResult.integer(ce.ownerRef);
            }
            if (mv != null) {
              String mintClass = cidNames.get(mv.intValue());
              if (mintClass != null && !mintClass.isEmpty()) {
                fnName = mintClass + "_mint_0x" + Long.toHexString(mv);
              } else {
                fnName = "fn_mint_0x" + Long.toHexString(mv);
              }
            }
          } else if (ownerCid != null) {
            ownerKind = ct.nameOf(ownerCid);
            fnName = "Stub_" + ownerKind + "_" + ce.ownerRef;
          }
        } else if (allocStubClassByCodeRef.containsKey(ce.refId)) {
          ownerKind = "Class";
          fnName = "AllocationStub_" + allocStubClassByCodeRef.get(ce.refId);
        }

        if (ce.clusterIndex >= 0) {
          kindBySlot.put(ce.clusterIndex, ownerKind);
        }
        if (fnName != null && !fnName.isEmpty()) {
          codeRefDisplay.put(ce.refId, fnName);
          if (ce.clusterIndex >= 0) {
            fnBySlot.put(ce.clusterIndex, fnName);
            pcBySlot.put(ce.clusterIndex, paramCount);
          }
          if (ce.textOffset > 0) {
            fnByTextOff.putIfAbsent(ce.textOffset, fnName);
            pcByTextOff.putIfAbsent(ce.textOffset, paramCount);
          }
        }
      }
      this.functionNameByCodeSlot = Collections.unmodifiableMap(fnBySlot);
      this.ownerKindByCodeSlot = Collections.unmodifiableMap(kindBySlot);
      this.paramCountByCodeSlot = Collections.unmodifiableMap(pcBySlot);
      this.functionNameByTextOffset = Collections.unmodifiableMap(fnByTextOff);
      this.paramCountByTextOffset = Collections.unmodifiableMap(pcByTextOff);

      var poolGroups = new HashMap<Integer, List<PoolEntry>>();
      for (var object : objects) {
        if (object.cid() == ct.objectPool) poolGroups.put(object.refId(), new ArrayList<>());
      }
      for (var entry : poolEntries) poolGroups.computeIfAbsent(entry.poolRef, ignored -> new ArrayList<>()).add(entry);
      var immutablePools = new HashMap<Integer, List<PoolEntry>>();
      poolGroups.forEach((ref, entries) -> immutablePools.put(ref, List.copyOf(entries)));
      pools = Map.copyOf(immutablePools);
    }

    /** Returns true if the Alloc phase satisfied {@code totalAllocatedRefs == header.numObjects}. */
    public boolean isAllocSelfValid() {
      return clusters.size() == header.totalClusters()
          && (long) totalAllocatedRefs == header.numObjects;
    }

    /** A pool identity and the ARM64 untagged base convention are required. */
    public PoolEntry poolEntry(int poolRef, long byteOffset) {
      var entries = pools.get(poolRef);
      if (entries == null || byteOffset < 16 || (byteOffset & 7) != 0) return null;
      long index = (byteOffset - 16) / 8;
      return index < entries.size() ? entries.get((int) index) : null;
    }

    /**
     * Resolves the highest-priority symbol name across all {@link DartInstructionsTable} slots
     * sharing a consolidated {@link DartInstructionsTable.CodeRange}
     * ({@code Function} &gt; {@code Class} &gt; {@code Type} &gt; {@code Mint} &gt; {@code Stub}).
     */
    public String resolveRangeSymbol(
        DartInstructionsTable.CodeRange range, int firstEntryWithCode) {
      if (range == null) {
        return null;
      }
      String bestName = null;
      int bestPrio = -1;
      for (int slot : range.slots) {
        int codeSlot = slot - firstEntryWithCode;
        if (codeSlot >= 0) {
          String name = functionNameByCodeSlot.get(codeSlot);
          if (name != null && !name.isEmpty()) {
            String kind = ownerKindByCodeSlot.getOrDefault(codeSlot, "Null");
            int prio = ownerKindPriority(kind);
            if (prio > bestPrio) {
              bestPrio = prio;
              bestName = name;
            }
          }
        }
      }
      if (bestName == null) {
        bestName = functionNameByTextOffset.get(range.pcOffset);
      }
      return bestName;
    }

    /**
     * Resolves the highest-priority owner kind ({@code "Function"}, {@code "Class"},
     * {@code "Type"}, {@code "Mint"}, {@code "Null"}, or {@code "Stub"}) across all slots
     * sharing a consolidated {@link DartInstructionsTable.CodeRange}.
     */
    public String resolveRangeOwnerKind(
        DartInstructionsTable.CodeRange range, int firstEntryWithCode) {
      if (range == null) {
        return "Null";
      }
      String bestKind = range.isStub ? "Stub" : "Null";
      int bestPrio = -1;
      for (int slot : range.slots) {
        int codeSlot = slot - firstEntryWithCode;
        if (codeSlot >= 0) {
          String kind = ownerKindByCodeSlot.getOrDefault(codeSlot, "Null");
          int prio = ownerKindPriority(kind);
          if (prio > bestPrio) {
            bestPrio = prio;
            bestKind = kind;
          }
        }
      }
      return bestKind;
    }

    private static int ownerKindPriority(String kind) {
      if (kind == null) {
        return 0;
      }
      return switch (kind) {
        case "Function" -> 4;
        case "Class" -> 3;
        case "Type" -> 2;
        case "Mint" -> 1;
        default -> 0;
      };
    }

    /** Resolve an inherited identity through the loading-unit parent chain. */
    public ObjectData object(int ref) {
      for (Result scope = this; scope != null; scope = scope.vm) {
        var value = scope.objects.get(ref);
        if (value != null) return value;
      }
      return null;
    }

    public List<Integer> exceptionEntries(int ref) {
      for (Result scope = this; scope != null; scope = scope.vm) {
        var entries = scope.exceptionEntries.get(ref);
        if (entries != null) return entries;
      }
      return List.of();
    }

    public NamedObject named(int ref) {
      for (Result scope = this; scope != null; scope = scope.vm) {
        var value = scope.namedByRef.get(ref);
        if (value != null) return value;
      }
      return null;
    }

    public Long integer(int ref) {
      for (Result scope = this; scope != null; scope = scope.vm) {
        var value = scope.mintValues.get(ref);
        if (value != null) return value;
      }
      return null;
    }

    /** Readable primitive value; the retained scalar bits remain authoritative.
     * A tagged slot still holds an object/Smi reference, not this native number.
     */
    public String numericValue(int ref) {
      Long integer = integer(ref);
      if (integer != null) return "int " + integer;
      var value = object(ref);
      if (value != null && value.cid() == profile.cids.doubleCid
          && value.scalars().length > 0) {
        long bits = value.scalars()[0];
        return "double " + Double.longBitsToDouble(bits) + " (bits=0x"
            + Long.toHexString(bits) + ")";
      }
      return null;
    }

    public String string(int ref) {
      return resolveString(ref, stringByRef, vm);
    }

    /** Local pools plus the inherited global pool as patched for this image. */
    public List<PoolEntry> imagePoolEntries() {
      if (!header.isLoadingUnit) return poolEntries;
      var entries = new ArrayList<>(poolEntries);
      Integer global = roots.references().get("object_store.global_object_pool");
      if (global != null && !pools.containsKey(global)) entries.addAll(globalPool());
      return List.copyOf(entries);
    }

    /** The effective global pool includes parent slots and this unit's patches. */
    public List<PoolEntry> globalPool() {
      Integer ref = roots == null ? null : roots.references().get("object_store.global_object_pool");
      if (ref == null) return List.of();
      var local = pools.get(ref);
      if (local != null) return local;
      if (vm == null || roots.unit() == null) return List.of();
      var result = new ArrayList<>(vm.globalPool());
      for (var update : roots.unit().poolUpdates().entrySet()) {
        var old = result.get(update.getKey());
        result.set(update.getKey(), new PoolEntry(old.poolRef, old.index, old.bits,
            old.kind, update.getValue(), old.imm));
      }
      return List.copyOf(result);
    }

    /** Resolves Field storage without treating serialized reference IDs as offsets. */
    public FieldStorage fieldStorage(FieldInfo field) {
      boolean isStatic = (field.kindBits & 2) != 0;
      boolean shared = isStatic && profile.fieldSharedBit >= 0
          && (field.kindBits & (1 << profile.fieldSharedBit)) != 0;
      Long offsetOrId = field.staticFieldId >= 0 ? Long.valueOf(field.staticFieldId)
          : mintValues.get(field.valueOrOffsetRefId);
      if (offsetOrId == null && vm != null) {
        offsetOrId = vm.integer(field.valueOrOffsetRefId);
      }
      Integer initialValue = null;
      if (isStatic && field.staticFieldId >= 0) {
        // Older Field Fill stores the initial value directly, then the field ID.
        initialValue = field.valueOrOffsetRefId;
      } else if (isStatic && roots != null && offsetOrId != null) {
        int[] values = shared ? roots.sharedStaticFields : roots.staticFields;
        if (offsetOrId >= 0 && offsetOrId < values.length) {
          initialValue = values[offsetOrId.intValue()];
        }
      }
      // Field::TargetOffsetOf serializes words, not bytes (also in SDK 2.10
      // RawField::target_offset_). Static values are field-table IDs instead.
      if (!isStatic && offsetOrId != null) {
        try {
          offsetOrId = Math.multiplyExact(offsetOrId, profile.compressedPointers ? 4L : 8L);
        } catch (ArithmeticException e) {
          throw new IllegalArgumentException("Field target byte offset overflows: " + field.refId, e);
        }
      }
      return new FieldStorage(isStatic, shared, offsetOrId, initialValue);
    }

    /** SDK GetCodeByIndex: retained Code identity, or null for a discarded entry.
     * Deferred Codes still have identities even though their instructions are external.
     * Non-root units bias local indices by the complete parent reference count.
     */
    public Integer codeReference(long index, int firstEntryWithCode) throws IOException {
      if (profile.codeTextOffsetDelta) {
        var code = index > 0 && index <= Integer.MAX_VALUE ? object((int) index) : null;
        if (code == null || code.cid() != profile.cids.code) {
          throw new IOException("Function Code reference is not a Code: " + index);
        }
        return (int) index;
      }
      if (index < 0) throw new IOException("negative Function code index");
      if (index == 0) {
        // Merged snapshots explicitly serialize the LazyCompile identity.
        // Earlier formats provide only the role; do not guess a VM stub slot.
        for (var scope = this; scope != null; scope = scope.vm) {
          for (var cluster : scope.clusters) {
            if (cluster.cid == profile.cids.code && cluster.lazyCompileRef > 0) {
              return cluster.lazyCompileRef;
            }
          }
        }
        return null;
      }
      long ordinal = index - 1;
      if (header.isLoadingUnit) {
        if (ordinal < header.numBaseObjects) {
          var code = ordinal > 0 ? object((int) ordinal) : null;
          if (code == null || code.cid() != profile.cids.code) {
            throw new IOException("inherited Function code index is not a Code: " + index);
          }
          return (int) ordinal;
        }
        ordinal -= header.numBaseObjects;
      }
      if (ordinal < firstEntryWithCode) return null;
      ordinal -= firstEntryWithCode;
      for (var cluster : clusters) {
        if (cluster.cid != profile.cids.code) continue;
        if (ordinal < cluster.count) return cluster.startRef + (int) ordinal;
        break;
      }
      throw new IOException("Function code index outside Code cluster: " + index);
    }

    /** Returns the serialized Type's class ID, not its object-reference ID. */
    public Integer typeClassId(TypeInfo type) {
      return typeClassId(type, profile, mintValues, vm);
    }

    private static Integer typeClassId(
        TypeInfo type,
        DartVersionProfile profile,
        Map<Integer, Long> mintValues,
        Result vmResult) {
      long value;
      if (profile.typeClassIdIsRef) {
        // Older Type objects serialize type_class_id_ as a Smi reference.
        if (type.refs == null || type.refs.length < 2) {
          return null;
        }
        int ref = type.refs[1];
        Long classId = mintValues.get(ref);
        if (classId == null && vmResult != null) {
          classId = vmResult.integer(ref);
        }
        if (classId == null) {
          return null;
        }
        value = classId;
      } else {
        if (type.scalars == null || type.scalars.length == 0) {
          return null;
        }
        value = type.scalars[0];
        if (!profile.oldTypeScalars) {
          value >>>= profile.typeClassIdShift;
        }
      }
      return value >= 0 && value <= Integer.MAX_VALUE ? (int) value : null;
    }

    private static String resolveString(
        int refId, Map<Integer, String> sMap, Result vmResult) {
      if (refId <= 0) {
        return null;
      }
      String s = sMap.get(refId);
      if (s != null) {
        return s;
      }
      if (vmResult != null) {
        return vmResult.string(refId);
      }
      return null;
    }

    private static String resolveQualifiedName(
        NamedObject no,
        Map<Integer, String> sMap,
        Map<Integer, NamedObject> nMap,
        Result vmResult) {
      String name = resolveString(no.nameRefId, sMap, vmResult);
      if (name == null || name.isEmpty()) {
        return "";
      }
      if (no.ownerRefId > 0) {
        NamedObject owner = nMap.get(no.ownerRefId);
        if (owner == null && vmResult != null) {
          owner = vmResult.named(no.ownerRefId);
        }
        if (owner != null) {
          String ownerName = resolveString(owner.nameRefId, sMap, vmResult);
          if (ownerName != null && !ownerName.isEmpty() && !"::".equals(ownerName)) {
            return ownerName + "." + name;
          }
        }
      }
      return name;
    }

  }

  /** Check the extent before multiplying an untrusted element count. */
  private static int payloadBytes(DartStream stream, long length, int width) throws IOException {
    if (length < 0 || width <= 0 || length > stream.remaining() / width) {
      throw new IOException("typed data payload outside serialized stream");
    }
    return (int) (length * width);
  }

  /** RO deltas are in 16-byte units; shifting first would discard high bits. */
  private static long advanceRoOffset(long offset, long delta, long imageSize) throws IOException {
    if (offset < 0 || offset > imageSize || delta < 0 || delta > (imageSize - offset) / 16) {
      throw new IOException("RO object delta outside image: offset=" + offset
          + ", delta=" + delta + ", image size=" + imageSize);
    }
    return offset + delta * 16;
  }

  private static long advanceTextOffset(long offset, long delta) throws IOException {
    if (delta < 0 || offset < 0 || delta > Long.MAX_VALUE - offset) {
      throw new IOException("instruction offset overflow");
    }
    return offset + delta;
  }

  private static int checkedLength(long value) throws IOException {
    if (value < 0 || value > Integer.MAX_VALUE) throw new IOException("invalid byte length: " + value);
    return (int) value;
  }

  private static final int MAX_STEPS = 2_000_000;

  /** Parses a single snapshot (VM or Isolate) without external VM base-object lookups. */
  public static Result parseSnapshot(
      byte[] data, DartSnapshotHeader header, DartVersionProfile profile) throws IOException {
    return parseSnapshot(data, header, profile, null);
  }

  /**
   * Parses a snapshot (VM or Isolate), optionally resolving base object references
   * ({@code refId <= numBaseObjects}) against a parsed {@code vmResult}.
   */
  public static Result parseSnapshot(
      byte[] data, DartSnapshotHeader header, DartVersionProfile profile, Result vmResult)
      throws IOException {
    return parseSnapshot(data, header, profile, vmResult, () -> false);
  }

  public static Result parseSnapshot(byte[] data, DartSnapshotHeader header,
      DartVersionProfile profile, Result vmResult, java.util.function.BooleanSupplier cancelled)
      throws IOException {
    if (header.firstClusterOffset <= header.clusterDataStart
        || header.profile == null
        || header.profile != profile) {
      header = header.withClusteredCounts(data, profile);
    }
    if (!header.isAot()) throw new IOException("not an AOT snapshot");
    if (header.isLoadingUnit && (vmResult == null || vmResult.roots == null
        || header.numBaseObjects != vmResult.header.numObjects)) {
      throw new IOException("loading unit requires its exact parent reference table");
    }
    if (header.isLoadingUnit) {
      if (profile.compressedPointers != vmResult.profile.compressedPointers
          || header.usesBareInstructions() != vmResult.header.usesBareInstructions()) {
        throw new IOException("loading unit target layout differs from parent");
      }
      Integer unitsRef = vmResult.roots.references().get("object_store.loading_units");
      var units = unitsRef == null ? null : vmResult.object(unitsRef);
      int[] refs = units == null ? new int[0] : units.references();
      var hashObject = refs.length < 2 ? null : vmResult.object(refs[1]);
      if (hashObject == null || hashObject.cid() != profile.cids.mint || hashObject.scalars().length == 0
          || (hashObject.scalars()[0] & 0xffffffffL) != header.programHash) {
        throw new IOException("loading unit program identity differs from parent");
      }
    }
    int snapshotEnd = Math.toIntExact(header.snapshotOffset + header.totalSize);
    DartStream s = new DartStream(data, header.firstClusterOffset, snapshotEnd - header.firstClusterOffset);

    s.setCancellation(cancelled);
    int nc = (int) header.totalClusters();
    if (nc < 0 || nc > MAX_STEPS) {
      throw new IOException("Cluster count out of bounds: " + nc);
    }

    List<ClusterMeta> clusters = new ArrayList<>(nc);
    Map<Integer, Long> mintValues = new HashMap<>();
    List<String> diags = new ArrayList<>();

    int nextRef = (int) header.numBaseObjects + 1;
    boolean isVm = header.isVmSnapshot();

    // 1. Alloc Phase
    for (int i = 0; i < nc; i++) {
      int tagPos = s.position();
      DartVersionProfile.DecodedTag tag;
      try {
        tag = DartVersionProfile.decodeClusterTag(s, profile, i, header.numCanonicalClusters);
      } catch (IOException e) {
        diags.add(String.format("Alloc cluster %d tag error at 0x%x: %s", i, tagPos, e.getMessage()));
        break;
      }

      ClusterMeta cm = new ClusterMeta(i, tag.cid, tag.canonical, tag.immutable, nextRef, tagPos);
      try {
        long count = readAllocCluster(s, cm, profile, isVm, !header.isLoadingUnit, mintValues);
        if (count < 0 || count > header.numObjects - nextRef + 1) {
          throw new IOException("cluster allocations exceed declared reference table");
        }
        cm.count = count;
        cm.stopRef = nextRef + (int) count;
        cm.endOffset = s.position();
        nextRef = cm.stopRef;
        clusters.add(cm);
      } catch (IOException e) {
        diags.add(
            String.format(
                "Alloc cluster %d (CID %d %s) error at 0x%x: %s",
                i, tag.cid, profile.cids.nameOf(tag.cid), s.position(), e.getMessage()));
        cm.endOffset = s.position();
        cm.stopRef = nextRef + (int) cm.count;
        clusters.add(cm);
        break;
      }
    }

    int fillStart = s.position();
    int totalAllocatedRefs = nextRef - 1;
    if ((long) totalAllocatedRefs != header.numObjects) {
      diags.add(
          String.format(
              "Alloc ref count mismatch: allocated=%d vs expected=%d (diff=%d)",
              totalAllocatedRefs, header.numObjects, header.numObjects - totalAllocatedRefs));
    }

    // 2. Fill Phase
    List<ObjectData> objects = new ArrayList<>();
    List<ParsedString> strings = new ArrayList<>();
    List<NamedObject> namedObjects = new ArrayList<>();
    List<FuncTypeInfo> funcTypes = new ArrayList<>();
    List<TypeInfo> types = new ArrayList<>();
    List<ClassInfo> classes = new ArrayList<>();
    List<FieldInfo> fields = new ArrayList<>();
    List<CodeEntry> codes = new ArrayList<>();
    List<PoolEntry> poolEntries = new ArrayList<>();
    Map<Integer, List<Integer>> exceptionEntries = new HashMap<>();

    int fillEnd = fillStart;
    RootData roots = null;
    if (fillStart > 0 && fillStart < data.length && diags.isEmpty()) {
      DartStream fs = new DartStream(data, fillStart, snapshotEnd - fillStart);
      fs.limitReferences(header.numObjects);
      fs.setCancellation(cancelled);
      int[] instrIdx = new int[] {0};
      long[] runningTextOffset = new long[] {0L};
      for (int i = 0; i < clusters.size(); i++) {
        ClusterMeta cm = clusters.get(i);
        FillSpec spec = getFillSpec(cm.cid, cm, profile);
        // SDK non-root units serialize strings inline, even without pointer compression.
        if (header.isLoadingUnit && profile.cids.isString(cm.cid)) {
          spec = new FillSpec(FillKind.STRING);
        }
        try {
          fillOneCluster(
              data,
              fs,
              header,
              cm,
              spec,
              profile,
              instrIdx,
              runningTextOffset,
              strings,
              namedObjects,
              funcTypes,
              types,
              classes,
              fields,
              codes,
              poolEntries,
              exceptionEntries,
              objects);
        } catch (IOException e) {
          diags.add(
              String.format(
                  "Fill cluster %d (CID %d %s, kind %s) error at 0x%x: %s",
                  i, cm.cid, profile.cids.nameOf(cm.cid), spec.kind, fs.position(), e.getMessage()));
          break;
        }
      }
      fillEnd = fs.position();
      if (diags.isEmpty()) roots = header.isLoadingUnit
          ? readUnitRoots(fs, header, profile, codes, vmResult, runningTextOffset)
          : readRoots(data, fs, header, profile, clusters, codes, vmResult);
    }

    if (!diags.isEmpty()) throw new IOException(String.join("; ", diags));
    for (var cluster : clusters) {
      if (cluster.cid != profile.cids.mint) continue;
      for (int ref = cluster.startRef; ref < cluster.stopRef; ref++) {
        objects.add(new ObjectData(ref, cluster.cid, new int[0],
            new long[] {mintValues.get(ref), cluster.mintCanonical[ref - cluster.startRef]}, -1, 0));
      }
    }
    return new Result(
        header,
        profile,
        clusters,
        objects,
        exceptionEntries,
        strings,
        namedObjects,
        funcTypes,
        types,
        classes,
        fields,
        codes,
        poolEntries,
        mintValues,
        fillStart,
        fillEnd,
        roots,
        totalAllocatedRefs,
        diags,
        vmResult);
  }

  /**
   * Program/VM root order is generated from the SDK macros. Reading starts at
   * the exact end of Fill; searching for a plausible ObjectPool CID loses scope
   * and can silently choose a different object. Unadapted root layouts remain
   * explicit while their Alloc/Fill readers are under development.
   */
  private static RootData readRoots(byte[] data, DartStream s, DartSnapshotHeader header,
      DartVersionProfile profile, List<ClusterMeta> clusters, List<CodeEntry> codes,
      Result vmResult) throws IOException {
    com.google.gson.JsonObject layout;
    com.google.gson.JsonArray names;
    com.google.gson.JsonArray basePrefix;
    com.google.gson.JsonArray baseSuffix;
    try (var input = DartClusterParser.class.getResourceAsStream("/ghidart/snapshot-roots.json")) {
      if (input == null) throw new IOException("missing SDK root descriptors");
      var layouts = com.google.gson.JsonParser.parseReader(
          new java.io.InputStreamReader(input, StandardCharsets.UTF_8)).getAsJsonObject();
      layout = layouts.getAsJsonObject("layouts").getAsJsonObject(profile.dartVersion);
      if (layout == null) return null;
      String group = layout.get(header.isVm ? "vm" : "program").getAsString();
      names = layouts.getAsJsonObject("groups").getAsJsonArray(group);
      basePrefix = layouts.getAsJsonObject("groups").getAsJsonArray(
          layout.get("basePrefix").getAsString());
      baseSuffix = layouts.getAsJsonObject("groups").getAsJsonArray(
          layout.get("baseSuffix").getAsString());
    }
    var refs = new java.util.LinkedHashMap<String, Integer>();
    var baseIdentities = new java.util.LinkedHashMap<String, Integer>();
    for (var name : names) {
      int ref = (int) s.readRef(profile.fillRefUnsigned);
      if (ref == 0) throw new IOException("root references illegal snapshot identity 0");
      refs.put(name.getAsString(), ref);
    }
    if (header.isVm) {
      // VM roots end with the stub Code table. SDKs can add stubs without
      // changing the snapshot hash. Preserve actual slot identities rather
      // than assigning SDK names by count or assuming a fixed tail length.
      var codeRefs = new HashSet<Integer>();
      for (var code : codes) codeRefs.add(code.refId);
      var seen = new HashSet<Integer>();
      int slot = 0;
      while (s.hasRemaining()) {
        int ref = (int) s.readRef(profile.fillRefUnsigned);
        if (!codeRefs.contains(ref)) {
          throw new IOException("VM stub root does not identify a local Code object");
        }
        seen.add(ref);
        refs.put("stub[" + slot++ + "]", ref);
      }
      if (!seen.equals(codeRefs)) throw new IOException("VM stub roots omit local Code objects");
    }
    // These identities are created by Object::InitOnce, not serialized clusters.
    // The SDK prefix is data shared by layout families. Do not infer bool/null
    // positions from a recent SDK: their order changed in merged snapshots.
    if (header.isVm || (!header.isLoadingUnit
        && profile.codeFormat() == DartVersionProfile.CodeFormat.MERGED_TABLE)) {
      if (basePrefix.size() > header.numBaseObjects) {
        throw new IOException("VM base object prefix exceeds reference table");
      }
      int ref = 1;
      for (var role : basePrefix) {
        refs.put("base." + role.getAsString(), ref);
        baseIdentities.put("base." + role.getAsString(), ref++);
      }
      // FullAOT split snapshots end their base table with internal Class
      // objects, then dynamic/void. SDK-generated names are anchored at the
      // end: variable cached-argument/ICData arrays do not shift this suffix.
      // These are identities only; their absent runtime fields are not invented.
      if (!baseSuffix.isEmpty()) {
        if (baseSuffix.size() != profile.cids.instance - profile.cids.clazz
            || basePrefix.size() + baseSuffix.size() > header.numBaseObjects) {
          throw new IOException("VM base Class suffix disagrees with CID table or extent");
        }
        int first = Math.toIntExact(header.numBaseObjects - baseSuffix.size() + 1);
        for (int cached = 0; ref < first; ref++, cached++) {
          baseIdentities.put("base.cached_vm_object[" + cached + "]", ref);
        }
        for (var role : baseSuffix) baseIdentities.put("base." + role.getAsString(), ref++);
      }
    }
    for (var root : refs.entrySet()) {
      if (!root.getKey().equals("object_store.global_object_pool")) continue;
      int ref = root.getValue();
      Integer cid = vmResult == null ? null : vmResult.cidByRef.get(ref);
      for (var cluster : clusters) {
        if (cluster.startRef <= ref && ref < cluster.stopRef) { cid = cluster.cid; break; }
      }
      if (cid == null || cid != profile.cids.objectPool) {
        throw new IOException("global_object_pool root does not identify an ObjectPool");
      }
    }
    int[] fields = new int[0];
    int[] shared = new int[0];
    int firstCode = 0;
    long[] dispatch = new long[0];
    if (!header.isVm) {
      int tables = layout.get("fieldTables").getAsInt();
      if (tables >= 1) fields = readReferences(s, s.readUnsigned(), profile.fillRefUnsigned);
      if (tables >= 2) shared = readReferences(s, s.readUnsigned(), profile.fillRefUnsigned);
      long length = s.readUnsigned();
      if (length < 0 || length > MAX_STEPS) throw new IOException("dispatch table exceeds configured resource limit");
      dispatch = new long[(int) length];
      if (length != 0) {
        long first = s.readUnsigned();
        if (first <= 0 || first > header.numObjects) {
          throw new IOException("dispatch first Code reference outside snapshot");
        }
        ClusterMeta codeCluster = null;
        for (var cluster : clusters) {
          if (cluster.cid == profile.cids.code && cluster.startRef == first) codeCluster = cluster;
        }
        if (codeCluster == null) {
          throw new IOException("dispatch first Code reference is not the Code cluster start");
        }
        // The header counts non-discarded instructions only. The RO table
        // also contains discarded entries and is the actual index space.
        long maximumCodeIndex = profile.codeTextOffsetDelta ? codeCluster.count - 1
            : DartInstructionsTable.parse(data, header, profile).length
                + codeCluster.count - codeCluster.mainCount;
        firstCode = (int) first;
        long[] recent = new long[64];
        java.util.Arrays.fill(recent, -1);
        boolean[] initialized = new boolean[64];
        int recentIndex = 0;
        long value = -1; // Null-error stub, not a serialized Code reference.
        for (int i = 0; i < dispatch.length;) {
          long encoded = s.readTagged64();
          if (encoded == 0) {
            value = -1;
          } else if (encoded < 0) {
            long index = ~encoded;
            if (index >= recent.length || !initialized[(int) index]) {
              throw new IOException("dispatch table references an uninitialized recent entry");
            }
            value = recent[(int) index];
          } else if (encoded <= 63) {
            if (encoded > dispatch.length - i) throw new IOException("dispatch repeat exceeds table");
            java.util.Arrays.fill(dispatch, i, i + (int) encoded, value);
            i += (int) encoded;
            continue;
          } else {
            value = encoded - 64;
            if (value > maximumCodeIndex) throw new IOException("dispatch Code index outside snapshot");
            recent[recentIndex] = value;
            initialized[recentIndex] = true;
            recentIndex = (recentIndex + 1) & 63;
          }
          dispatch[i++] = value;
        }
      }
    }
    int end = s.position();
    // Snapshot::SetupFromBuffer reports the serialized stream size, excluding
    // the separate aligned data image. No unread root bytes may be accepted.
    if (s.remaining() != 0) throw new IOException("unconsumed root data: " + s.remaining()
        + " bytes after " + profile.dartVersion + (header.isVm ? " VM" : " program"));
    return new RootData(refs, fields, shared, firstCode, dispatch, end, null, baseIdentities);
  }

  /** SDK UnitDeserializationRoots: patch parent Code entries and global pool slots. */
  private static RootData readUnitRoots(DartStream s, DartSnapshotHeader header,
      DartVersionProfile profile, List<CodeEntry> codes, Result parent, long[] textOffset)
      throws IOException {
    long first = s.readUnsigned();
    long count = s.readUnsigned();
    if (first < 0 || count < 0 || (count == 0 && first != 0) || count > header.numBaseObjects
        || (count != 0 && (first == 0 || first > header.numBaseObjects - count + 1))) {
      throw new IOException("deferred Code range outside parent references");
    }
    var sourceMaps = new java.util.LinkedHashMap<Integer, Integer>();
    var stackMaps = new java.util.LinkedHashMap<Integer, Integer>();
    var inherited = new HashMap<Integer, CodeEntry>();
    for (Result scope = parent; scope != null; scope = scope.vm) {
      for (var code : scope.codes) inherited.putIfAbsent(code.refId, code);
    }
    int index = (int) codes.stream().filter(code -> code.clusterIndex >= 0).count();
    for (int i = 0; i < count; i++) {
      int ref = (int) first + i;
      var old = inherited.get(ref);
      if (old == null || old.clusterIndex >= 0) throw new IOException("unit updates non-deferred Code " + ref);
      if (profile.codeTextOffsetDelta) textOffset[0] = advanceTextOffset(textOffset[0], s.readUnsigned());
      long payload = s.readUnsigned();
      // code_source_map is retained separately; the Code object itself remains
      // owned by its original parent reference table.
      if (profile.codeTextOffsetDelta) {
        stackMaps.put(ref, (int) s.readRef(profile.fillRefUnsigned));
      }
      int sourceMap = (int) s.readRef(profile.fillRefUnsigned);
      codes.add(new CodeEntry(ref, old.ownerRef, index++, payload, textOffset[0], old.exceptionRef));
      // sourceMap belongs to a per-unit patch and must not disappear from facts.
      sourceMaps.put(ref, sourceMap);
    }
    Integer poolRef = parent.roots.references().get("object_store.global_object_pool");
    var pool = parent.globalPool();
    if (poolRef == null || parent.object(poolRef) == null
        || parent.object(poolRef).cid() != profile.cids.objectPool) {
      throw new IOException("loading unit parent has no global ObjectPool");
    }
    var updates = new java.util.LinkedHashMap<Integer, Integer>();
    // SDK 2.10 keeps deferred literals in the root pool; later writers patch them.
    long position = profile.preCanonicalSplit ? pool.size() : s.readUnsigned();
    if (position < 0 || position > pool.size()) {
      throw new IOException("deferred pool start outside parent pool");
    }
    while (position < pool.size()) {
      if (position < 0 || pool.get((int) position).kind != PoolEntryKind.TAGGED) {
        throw new IOException("deferred update targets a non-tagged pool slot");
      }
      updates.put((int) position, (int) s.readRef(profile.fillRefUnsigned));
      long skip = s.readUnsigned();
      if (skip <= 0 || skip > pool.size() - position) throw new IOException("invalid deferred pool delta");
      position += skip;
    }
    if (position != pool.size() || s.remaining() != 0) throw new IOException("incomplete loading-unit roots");
    return new RootData(parent.roots.references(), parent.roots.staticFields(),
        parent.roots.sharedStaticFields(), parent.roots.firstCodeRef(), new long[0], s.position(),
        new UnitData((int) first, (int) count, updates, sourceMaps, stackMaps), parent.roots.baseIdentities());
  }

  public static AllocKind classifyAlloc(int cid, DartClassId.Table ct) {
    if (ct.isString(cid)) {
      return AllocKind.STRING;
    }
    if (cid == ct.mint) {
      return AllocKind.MINT;
    }
    if (cid == ct.doubleCid
        || cid == ct.float32x4
        || cid == ct.int32x4
        || cid == ct.float64x2) {
      return AllocKind.SIMPLE;
    }
    if (cid == ct.array || cid == ct.immutableArray) {
      return AllocKind.ARRAY;
    }
    if (ct.weakArray != 0 && cid == ct.weakArray) {
      return AllocKind.WEAK_ARRAY;
    }
    if (cid == ct.typeArguments) {
      return AllocKind.TYPE_ARGUMENTS;
    }
    if (cid == ct.type
        || (ct.functionType != 0 && cid == ct.functionType)
        || cid == ct.typeParameter
        || (ct.recordType != 0 && cid == ct.recordType)) {
      return AllocKind.CANONICAL_SET;
    }
    if (cid == ct.clazz) {
      return AllocKind.CLASS;
    }
    if (cid == ct.code) {
      return AllocKind.CODE;
    }
    if (cid == ct.objectPool) {
      return AllocKind.OBJECT_POOL;
    }
    if (cid == ct.pcDescriptors || cid == ct.codeSourceMap || cid == ct.compressedStackMaps) {
      return AllocKind.RODATA;
    }
    if (cid == ct.localVarDescriptors) return AllocKind.LOCAL_VARIABLES;
    if (cid == ct.exceptionHandlers) {
      return AllocKind.EXCEPTION_HANDLERS;
    }
    if (cid == ct.context) {
      return AllocKind.CONTEXT;
    }
    if (cid == ct.contextScope) {
      return AllocKind.CONTEXT_SCOPE;
    }
    if (cid == ct.map || cid == ct.constMap || cid == ct.set || cid == ct.constSet) {
      return AllocKind.SIMPLE;
    }
    if (ct.typedData != 0 && cid == ct.typedData) {
      return AllocKind.TYPED_DATA;
    }
    if (cid == ct.typedDataView || ct.isTypedDataViewInternal(cid)
        || cid == ct.externalTypedData || cid == ct.growableObjectArray) {
      return AllocKind.SIMPLE;
    }
    if (ct.record != 0 && cid == ct.record) {
      return AllocKind.RECORD;
    }
    if (ct.weakSerializationReference != 0 && cid == ct.weakSerializationReference) {
      return AllocKind.EMPTY;
    }

    int[] simples = {
      ct.function,
      ct.closureData,
      ct.field,
      ct.script,
      ct.library,
      ct.namespace,
      ct.kernelProgramInfo,
      ct.closure,
      ct.unlinkedCall,
      ct.icData,
      ct.megamorphicCache,
      ct.subtypeTestCache,
      ct.loadingUnit,
      ct.weakProperty,
      ct.weakReference,
      ct.libraryPrefix,
      ct.languageError,
      ct.unhandledException,
      ct.regExp,
      ct.patchClass,
      ct.ffiTrampolineData,
      ct.typeParameters,
      ct.sentinel,
      ct.signatureData,
      ct.singleTargetCache,
      ct.monomorphicSmiableCall,
      ct.callSiteData,
      ct.sendPort,
      ct.stackTrace,
      ct.capability,
      ct.receivePort,
      ct.futureOr,
      ct.transferableTypedData,
      ct.userTag,
      ct.suspendState,
      ct.typeRef
    };
    for (int sc : simples) {
      if (sc != 0 && cid == sc) {
        return AllocKind.SIMPLE;
      }
    }

    if (ct.nativePointerCid != 0 && cid == ct.nativePointerCid) {
      return AllocKind.TYPED_DATA;
    }
    if (ct.isTypedDataInternal(cid)) return AllocKind.TYPED_DATA;
    if (ct.isTypedDataAnyRange(cid)) return AllocKind.SIMPLE;
    if (cid == ct.instance || cid >= ct.numPredefinedCids) {
      return AllocKind.INSTANCE;
    }
    if (ct.numPredefinedCids != 0 && cid > 0 && cid < ct.numPredefinedCids) {
      return AllocKind.SIMPLE;
    }
    return AllocKind.UNKNOWN;
  }

  private static long readAllocCluster(
      DartStream s,
      ClusterMeta cm,
      DartVersionProfile profile,
      boolean isVm, boolean rootUnit,
      Map<Integer, Long> mintValues)
      throws IOException {
    DartClassId.Table ct = profile.cids;
    AllocKind kind = classifyAlloc(cm.cid, ct);
    if (cm.cid == ct.closure && profile.codeFormat() == DartVersionProfile.CodeFormat.MERGED_TABLE) {
      kind = AllocKind.VARIABLE_CLOSURE;
    }
    switch (kind) {
      case SIMPLE:
        return readCount(s);
      case CANONICAL_SET: {
        if (profile.preCanonicalSplit) {
          long canonical = readCount(s);
          long nonCanonical = readCount(s);
          cm.canonicalCount = canonical;
          return canonical + nonCanonical;
        }
        long count = readCount(s);
        if (rootUnit && cm.isCanonical && profile.serializedCanonicalSets) {
          boolean readFirst = !profile.splitCanonical || (cm.cid == ct.type);
          cm.canonicalSet = readCanonicalSet(s, (int) count, readFirst);
        }
        return count;
      }
      case STRING: {
        if (rootUnit && (profile.splitCanonical || !profile.compressedPointers)) {
          boolean hasCanonicalSet = rootUnit && profile.serializedCanonicalSets
              && cm.isCanonical && cm.cid == ct.string;
          return skipRoDataAlloc(s, cm, hasCanonicalSet, !profile.splitCanonical);
        }
        long count = readCount(s);
        cm.lengths = new long[(int) count];
        for (int i = 0; i < count; i++) cm.lengths[i] = s.readUnsigned();
        if (rootUnit && cm.isCanonical && !isVm) {
          cm.canonicalSet = readCanonicalSet(s, (int) count, true);
        }
        return count;
      }
      case MINT: {
        long count = readCount(s);
        cm.mintCanonical = new long[(int) count];
        java.util.Arrays.fill(cm.mintCanonical, -1);
        for (int i = 0; i < count; i++) {
          if (profile.preCanonicalSplit) cm.mintCanonical[i] = s.readUint8();
          long val = s.readTagged64();
          if (mintValues != null) {
            mintValues.put(cm.startRef + i, val);
          }
        }
        return count;
      }
      case ARRAY:
      case WEAK_ARRAY:
      case OBJECT_POOL:
      case EXCEPTION_HANDLERS:
      case LOCAL_VARIABLES:
      case VARIABLE_CLOSURE:
      case CONTEXT:
      case CONTEXT_SCOPE:
      case RECORD:
      case TYPED_DATA: {
        long count = readCount(s);
        cm.lengths = new long[(int) count];
        for (int i = 0; i < count; i++) {
          cm.lengths[i] = s.readUnsigned();
        }
        return count;
      }
      case TYPE_ARGUMENTS: {
        long count = readCount(s);
        cm.lengths = new long[(int) count];
        for (int i = 0; i < count; i++) {
          cm.lengths[i] = s.readUnsigned();
        }
        if (rootUnit && cm.isCanonical && profile.serializedCanonicalSets) {
          cm.canonicalSet = readCanonicalSet(s, (int) count, !profile.splitCanonical);
        }
        return count;
      }
      case CLASS: {
        if (profile.codeFormat() == DartVersionProfile.CodeFormat.MERGED_TABLE) return readCount(s);
        long predefined = s.readUnsigned();
        if (predefined > ct.numPredefinedCids) {
          predefined = s.readUnsigned();
        }
        if (predefined < 0 || predefined > MAX_STEPS) {
          throw new IOException("Invalid predefined class count: " + predefined);
        }
        cm.predefCids = new long[(int) predefined];
        for (int i = 0; i < predefined; i++) {
          cm.predefCids[i] = s.readTagged32();
        }
        long newCount = readCount(s);
        cm.mainCount = predefined;
        return predefined + newCount;
      }
      case CODE: {
        long count = readCount(s);
        boolean stateBitsInAlloc = profile.tagStyle != DartVersionProfile.TagStyle.CID_INT32;
        if (stateBitsInAlloc) {
          cm.codeStateBits = new int[(int) count];
          for (int i = 0; i < count; i++) {
            int sb = s.readTagged32();
            cm.codeStateBits[i] = sb;
            if (((sb >>> 3) & 1) != 0) {
              if (cm.discardedCodes == null) {
                cm.discardedCodes = new HashSet<>();
              }
              cm.discardedCodes.add((long) i);
            }
          }
        }
        cm.mainCount = count;
        long deferred = readCount(s);
        if (stateBitsInAlloc) {
          if (count + deferred > MAX_STEPS) throw new IOException("too many Code objects");
          cm.codeStateBits = java.util.Arrays.copyOf(cm.codeStateBits, (int) (count + deferred));
          for (int i = 0; i < deferred; i++) {
            int sb = s.readTagged32();
            cm.codeStateBits[(int) count + i] = sb;
            if (((sb >>> 3) & 1) != 0) {
              if (cm.discardedCodes == null) {
                cm.discardedCodes = new HashSet<>();
              }
              cm.discardedCodes.add(count + i);
            }
          }
        }
        return count + deferred;
      }
      case RODATA:
        return skipRoDataAlloc(s, cm,
            rootUnit && cm.isCanonical && profile.serializedCanonicalSets, !profile.splitCanonical);
      case INSTANCE: {
        long count = readCount(s);
        cm.nextFieldOffsetInWords = s.readTagged32();
        cm.instanceSizeInWords = s.readTagged32();
        return count;
      }
      case EMPTY: {
        if (profile.preCanonicalSplit) {
          return readCount(s);
        }
        return 0;
      }
      default:
        throw new IOException("Unrecognized AllocKind for CID " + cm.cid);
    }
  }

  private static long readCount(DartStream s) throws IOException {
    long count = s.readUnsigned();
    if (count < 0 || count > MAX_STEPS) {
      throw new IOException("Cluster object count out of bounds: " + count);
    }
    return count;
  }

  private static CanonicalSet readCanonicalSet(DartStream s, int count, boolean readFirstElement)
      throws IOException {
    long tableLen = s.readUnsigned();
    if (tableLen < 0 || tableLen > (long) MAX_STEPS * 16L) {
      throw new IOException("Canonical tableLen out of bounds: " + tableLen);
    }
    long firstElement = 0;
    if (readFirstElement) {
      firstElement = s.readUnsigned();
      if (firstElement < 0 || firstElement > count) {
        throw new IOException("Canonical firstElement out of bounds: " + firstElement);
      }
    }
    int numGaps = count - (int) firstElement;
    long[] gaps = new long[numGaps];
    for (int i = 0; i < numGaps; i++) gaps[i] = s.readUnsigned();
    return new CanonicalSet(tableLen, firstElement, gaps);
  }

  private static long skipRoDataAlloc(
      DartStream s, ClusterMeta cm, boolean isCanonical, boolean readFirstElement)
      throws IOException {
    long count = readCount(s);
    if (cm != null) {
      cm.lengths = new long[(int) count];
    }
    for (int i = 0; i < count; i++) {
      long delta = s.readUnsigned();
      if (cm != null) {
        cm.lengths[i] = delta;
      }
    }
    if (isCanonical) {
      if (cm == null) throw new IOException("missing canonical cluster metadata");
      cm.canonicalSet = readCanonicalSet(s, (int) count, readFirstElement);
    }
    return count;
  }

  public static FillSpec getFillSpec(int cid, ClusterMeta cm, DartVersionProfile profile) {
    DartClassId.Table ct = profile.cids;
    boolean u = profile.fillRefUnsigned;
    boolean preV32 = profile.preV32Format;
    if (cid == ct.apiError) return new FillSpec(FillKind.REFS, 1, null, -1, -1);
    if (cid == ct.unwindError) return new FillSpec(FillKind.REFS, 1, new ScalarOp[] {ScalarOp.BOOL}, -1, -1);
    if (cid == ct.closure && profile.codeFormat() == DartVersionProfile.CodeFormat.MERGED_TABLE) {
      return new FillSpec(FillKind.VARIABLE_CLOSURE);
    }

    if (cid == ct.function) {
      int numRefs = profile.funcNumRefs > 0 ? profile.funcNumRefs : 4;
      ScalarOp[] scalars =
          u
              ? new ScalarOp[] {ScalarOp.UNSIGNED, ScalarOp.TAGGED_32, ScalarOp.TAGGED_32}
              : new ScalarOp[] {ScalarOp.UNSIGNED, ScalarOp.TAGGED_32};
      return new FillSpec(FillKind.REFS, numRefs, scalars, 0, 1, 2, false, false, false);
    }
    if (cid == ct.clazz) {
      int numRefs = profile.classNumRefs > 0 ? profile.classNumRefs : 13;
      return new FillSpec(FillKind.CLASS, numRefs, null, 0, -1);
    }
    if (cid == ct.patchClass) {
      return new FillSpec(FillKind.REFS, preV32 ? 3 : 2, null, -1, -1);
    }
    if (cid == ct.closureData) {
      // Before the canonical-cluster split, closure_ is the third reference,
      // not the packed/default-type-arguments scalar introduced afterwards.
      if (profile.preCanonicalSplit) return new FillSpec(FillKind.REFS, 3, null, -1, -1);
      int numRefs = profile.closureDataNumRefs > 0 ? profile.closureDataNumRefs : 2;
      return new FillSpec(FillKind.REFS, numRefs, new ScalarOp[] {ScalarOp.UNSIGNED}, -1, -1);
    }
    if (cid == ct.field) {
      if (u) {
        return new FillSpec(FillKind.FIELD, 4, null, 0, 1);
      }
      return new FillSpec(
          FillKind.REFS,
          4,
          new ScalarOp[] {ScalarOp.TAGGED_32, ScalarOp.REF_ID},
          0,
          1,
          -1,
          false,
          false,
          true);
    }
    if (cid == ct.script) {
      List<ScalarOp> sc = new ArrayList<>(4);
      if (profile.scriptHasLineCol) {
        sc.add(ScalarOp.TAGGED_32);
        sc.add(ScalarOp.TAGGED_32);
      }
      if (profile.scriptHasFlags) {
        sc.add(ScalarOp.UINT8);
      }
      sc.add(ScalarOp.TAGGED_32);
      return new FillSpec(FillKind.REFS, 1, sc.toArray(new ScalarOp[0]), 0, -1);
    }
    if (cid == ct.library) {
      return new FillSpec(
          FillKind.REFS,
          10,
          new ScalarOp[] {ScalarOp.TAGGED_32, ScalarOp.TAGGED_32, ScalarOp.INT8, ScalarOp.UINT8},
          0,
          -1);
    }
    if (cid == ct.namespace) {
      // Before Namespace::to_snapshot(FullAOT) narrowed to target_, all four
      // references were retained, including show/hide filters and metadata.
      return new FillSpec(FillKind.REFS, profile.preCanonicalSplit ? 4 : 1, null, -1, -1);
    }
    if (cid == ct.closure) {
      return new FillSpec(FillKind.REFS, 6, null, -1, -1)
          .withLeadingBool(profile.preCanonicalSplit);
    }
    if (cid == ct.unlinkedCall) {
      return new FillSpec(FillKind.REFS, 2, new ScalarOp[] {ScalarOp.BOOL}, 0, -1);
    }
    if (cid == ct.subtypeTestCache) {
      ScalarOp[] sc =
          (!u && !profile.hasTypeParamClassId)
              ? new ScalarOp[] {ScalarOp.TAGGED_32, ScalarOp.TAGGED_32}
              : null;
      return new FillSpec(FillKind.REFS, 1, sc, -1, -1);
    }
    if (cid == ct.loadingUnit) {
      return new FillSpec(FillKind.REFS, 1, new ScalarOp[] {ScalarOp.TAGGED_32}, -1, -1);
    }
    if (cid == ct.type) {
      int numRefs = profile.typeNumRefs > 0 ? profile.typeNumRefs : 3;
      ScalarOp[] sc;
      if (profile.typeClassIdIsRef && profile.typeHasTokenPos) {
        sc = new ScalarOp[] {ScalarOp.TAGGED_32, ScalarOp.UINT8};
      } else if (profile.typeClassIdIsRef) {
        sc = new ScalarOp[] {ScalarOp.UINT8};
      } else if (profile.oldTypeScalars) {
        sc = new ScalarOp[] {ScalarOp.UNSIGNED, ScalarOp.UINT8};
      } else {
        sc = new ScalarOp[] {ScalarOp.UNSIGNED};
      }
      return new FillSpec(FillKind.REFS, numRefs, sc, -1, -1);
    }
    if (ct.functionType != 0 && cid == ct.functionType) {
      int numRefs = profile.funcTypeNumRefs > 0 ? profile.funcTypeNumRefs : 6;
      ScalarOp[] sc =
          profile.funcTypeOldScalars
              ? new ScalarOp[] {ScalarOp.UINT8, ScalarOp.TAGGED_32}
              : new ScalarOp[] {ScalarOp.UINT8, ScalarOp.TAGGED_32, ScalarOp.TAGGED_32};
      return new FillSpec(FillKind.REFS, numRefs, sc, -1, -1, -1, false, true, false);
    }
    if (ct.recordType != 0 && cid == ct.recordType) {
      return new FillSpec(FillKind.REFS, 4, new ScalarOp[] {ScalarOp.UINT8}, -1, -1);
    }
    if (cid == ct.typeParameter) {
      int numRefs = profile.typeParamNumRefs > 0 ? profile.typeParamNumRefs : 3;
      ScalarOp[] sc;
      if (profile.typeHasTokenPos) {
        sc =
            new ScalarOp[] {
              ScalarOp.TAGGED_32, ScalarOp.TAGGED_32, ScalarOp.INT16, ScalarOp.UINT8
            };
      } else if (profile.typeParamWideScalars) {
        sc =
            new ScalarOp[] {
              ScalarOp.TAGGED_32, ScalarOp.TAGGED_32, ScalarOp.TAGGED_32, ScalarOp.UINT8
            };
      } else if (profile.hasTypeParamClassId && profile.typeParamByteScalars) {
        sc =
            new ScalarOp[] {ScalarOp.TAGGED_32, ScalarOp.UINT8, ScalarOp.UINT8, ScalarOp.UINT8};
      } else if (profile.hasTypeParamClassId) {
        sc =
            new ScalarOp[] {
              ScalarOp.TAGGED_32, ScalarOp.TAGGED_32, ScalarOp.TAGGED_32, ScalarOp.UINT8
            };
      } else {
        sc = new ScalarOp[] {ScalarOp.TAGGED_32, ScalarOp.TAGGED_32, ScalarOp.UINT8};
      }
      return new FillSpec(FillKind.REFS, numRefs, sc, -1, -1);
    }
    if (ct.typeRef != 0 && cid == ct.typeRef) {
      int numRefs = profile.typeRefNumRefs > 0 ? profile.typeRefNumRefs : 2;
      return new FillSpec(FillKind.REFS, numRefs, null, -1, -1);
    }
    if (cid == ct.growableObjectArray) {
      return new FillSpec(FillKind.REFS, 3, null, -1, -1)
          .withLeadingBool(profile.preCanonicalSplit);
    }
    if (cid == ct.map || cid == ct.constMap || cid == ct.set || cid == ct.constSet) {
      return new FillSpec(FillKind.REFS, 5, null, -1, -1)
          .withLeadingBool(profile.preCanonicalSplit);
    }
    if (cid == ct.regExp) {
      int numRefs = profile.tagStyle == DartVersionProfile.TagStyle.CID_SHIFT_1 ? 10 : 6;
      return new FillSpec(
          FillKind.REFS,
          numRefs,
          new ScalarOp[] {ScalarOp.TAGGED_32, ScalarOp.TAGGED_32, ScalarOp.INT8},
          -1,
          -1);
    }
    if (cid == ct.weakProperty) {
      return new FillSpec(FillKind.REFS, 2, null, -1, -1);
    }
    if (ct.weakReference != 0 && cid == ct.weakReference) {
      return new FillSpec(FillKind.REFS, 2, null, -1, -1);
    }
    if (cid == ct.libraryPrefix) {
      return new FillSpec(
          FillKind.REFS, 2, new ScalarOp[] {ScalarOp.TAGGED_32, ScalarOp.BOOL}, 0, -1);
    }
    if (cid == ct.languageError) {
      return new FillSpec(
          FillKind.REFS,
          4,
          new ScalarOp[] {ScalarOp.TAGGED_32, ScalarOp.BOOL, ScalarOp.INT8},
          -1,
          -1);
    }
    if (cid == ct.unhandledException) {
      return new FillSpec(FillKind.REFS, 2, null, -1, -1);
    }
    if (cid == ct.icData) {
      return new FillSpec(FillKind.REFS, 3, new ScalarOp[] {ScalarOp.TAGGED_32}, -1, -1);
    }
    if (cid == ct.megamorphicCache) {
      return new FillSpec(FillKind.REFS, 4, new ScalarOp[] {ScalarOp.TAGGED_32}, -1, -1);
    }
    if (cid == ct.singleTargetCache) {
      return new FillSpec(
          FillKind.REFS, 1, new ScalarOp[] {ScalarOp.TAGGED_64, ScalarOp.TAGGED_64}, -1, -1);
    }
    if (ct.monomorphicSmiableCall != 0 && cid == ct.monomorphicSmiableCall) {
      return new FillSpec(
          FillKind.REFS, 0, new ScalarOp[] {ScalarOp.TAGGED_64, ScalarOp.TAGGED_64}, -1, -1);
    }
    if (cid == ct.kernelProgramInfo) {
      return new FillSpec(FillKind.REFS, 9, null, -1, -1);
    }
    if (ct.ffiTrampolineData != 0 && cid == ct.ffiTrampolineData) {
      ScalarOp[] sc;
      if (u) {
        sc = new ScalarOp[] {ScalarOp.UNSIGNED};
      } else if (profile.hasTypeParamClassId) {
        sc = new ScalarOp[] {ScalarOp.TAGGED_32};
      } else {
        sc = new ScalarOp[] {ScalarOp.TAGGED_32, ScalarOp.UINT8};
      }
      return new FillSpec(FillKind.REFS, 4, sc, -1, -1);
    }
    if (ct.signatureData != 0 && cid == ct.signatureData) {
      return new FillSpec(FillKind.REFS, 2, null, -1, -1);
    }
    if (ct.typeParameters != 0 && cid == ct.typeParameters) {
      return new FillSpec(FillKind.REFS, 4, null, -1, -1);
    }
    if (cid == ct.typedDataView || ct.isTypedDataViewInternal(cid)) {
      return new FillSpec(FillKind.REFS, 3, null, -1, -1)
          .withLeadingBool(profile.preCanonicalSplit);
    }
    if (cid == ct.externalTypedData) {
      // The abstract base class is not serialized as an external-data payload.
      return new FillSpec(FillKind.UNKNOWN);
    }
    if (cid == ct.stackTrace) {
      return new FillSpec(FillKind.REFS, 2, null, -1, -1);
    }
    if (cid == ct.sendPort) {
      return new FillSpec(
          FillKind.REFS, 0, new ScalarOp[] {ScalarOp.TAGGED_64, ScalarOp.TAGGED_64}, -1, -1);
    }
    if (ct.capability != 0 && cid == ct.capability) {
      return new FillSpec(FillKind.REFS, 0, new ScalarOp[] {ScalarOp.TAGGED_64}, -1, -1);
    }
    if (ct.receivePort != 0 && cid == ct.receivePort) {
      return new FillSpec(FillKind.REFS, 1, new ScalarOp[] {ScalarOp.TAGGED_64}, -1, -1);
    }
    if (ct.suspendState != 0 && cid == ct.suspendState) {
      return new FillSpec(FillKind.REFS, 2, new ScalarOp[] {ScalarOp.TAGGED_32}, -1, -1);
    }
    if (ct.transferableTypedData != 0 && cid == ct.transferableTypedData) {
      return new FillSpec(FillKind.NONE);
    }
    if (ct.userTag != 0 && cid == ct.userTag) {
      return new FillSpec(FillKind.REFS, 1, new ScalarOp[] {ScalarOp.TAGGED_64}, 0, -1);
    }
    if (ct.futureOr != 0 && cid == ct.futureOr) {
      return new FillSpec(FillKind.REFS, 2, null, -1, -1);
    }
    if (ct.weakSerializationReference != 0 && cid == ct.weakSerializationReference) {
      return new FillSpec(FillKind.REFS, 1, null, -1, -1);
    }
    if (ct.sentinel != 0 && cid == ct.sentinel) {
      return new FillSpec(FillKind.SENTINEL);
    }

    // Special non-REFS fill kinds
    if (ct.isString(cid)) {
      if (profile.splitCanonical || !profile.compressedPointers) {
        return new FillSpec(FillKind.RODATA);
      }
      return new FillSpec(FillKind.STRING);
    }
    if (cid == ct.mint) {
      return new FillSpec(FillKind.NONE);
    }
    if (cid == ct.doubleCid) {
      return new FillSpec(FillKind.DOUBLE);
    }
    if (cid == ct.float32x4 || cid == ct.int32x4) {
      return new FillSpec(
          FillKind.REFS,
          0,
          new ScalarOp[] {
            ScalarOp.TAGGED_32, ScalarOp.TAGGED_32, ScalarOp.TAGGED_32, ScalarOp.TAGGED_32
          },
          -1,
          -1);
    }
    if (cid == ct.float64x2) {
      return new FillSpec(
          FillKind.REFS, 0, new ScalarOp[] {ScalarOp.TAGGED_64, ScalarOp.TAGGED_64}, -1, -1);
    }
    if (cid == ct.code) {
      return new FillSpec(FillKind.CODE);
    }
    if (cid == ct.objectPool) {
      return new FillSpec(FillKind.OBJECT_POOL);
    }
    if (cid == ct.array || cid == ct.immutableArray) {
      return new FillSpec(FillKind.ARRAY);
    }
    if (ct.weakArray != 0 && cid == ct.weakArray) {
      return new FillSpec(FillKind.WEAK_ARRAY);
    }
    if (cid == ct.typeArguments) {
      return new FillSpec(FillKind.TYPE_ARGUMENTS);
    }
    if (cid == ct.localVarDescriptors) return new FillSpec(FillKind.LOCAL_VARIABLES);
    if (cid == ct.exceptionHandlers) {
      return new FillSpec(FillKind.EXCEPTION_HANDLERS);
    }
    if (cid == ct.context) {
      return new FillSpec(FillKind.CONTEXT);
    }
    if (cid == ct.contextScope) {
      return new FillSpec(FillKind.CONTEXT_SCOPE);
    }
    if (cid == ct.pcDescriptors || cid == ct.codeSourceMap || cid == ct.compressedStackMaps) {
      return new FillSpec(profile.compressedPointers ? FillKind.INLINE_BYTES : FillKind.RODATA);
    }
    if (ct.typedData != 0 && cid == ct.typedData) {
      return new FillSpec(FillKind.TYPED_DATA);
    }
    if (ct.record != 0 && cid == ct.record) {
      return new FillSpec(FillKind.RECORD);
    }
    if (ct.isTypedDataAnyRange(cid)) {
      if (ct.isTypedDataInternal(cid)) {
        return new FillSpec(FillKind.TYPED_DATA);
      }
      if (ct.isTypedDataViewInternal(cid)) {
        return new FillSpec(FillKind.REFS, 3, null, -1, -1)
            .withLeadingBool(profile.preCanonicalSplit);
      }
      int familyMember = (cid - ct.typedDataInt8ArrayCid) % ct.typedDataCidStride;
      return new FillSpec(familyMember == 2 ? FillKind.EXTERNAL_TYPED_DATA : FillKind.UNKNOWN);
    }
    if (ct.nativePointerCid != 0 && cid == ct.nativePointerCid) {
      return new FillSpec(FillKind.TYPED_DATA);
    }
    if (cid == ct.instance || cid >= ct.numPredefinedCids) {
      return new FillSpec(FillKind.INSTANCE);
    }
    return new FillSpec(FillKind.UNKNOWN);
  }

  private static void fillOneCluster(
      byte[] fullData,
      DartStream s,
      DartSnapshotHeader header,
      ClusterMeta cm,
      FillSpec spec,
      DartVersionProfile profile,
      int[] instrIdx,
      long[] runningTextOffset,
      List<ParsedString> strings,
      List<NamedObject> namedObjects,
      List<FuncTypeInfo> funcTypes,
      List<TypeInfo> types,
      List<ClassInfo> classes,
      List<FieldInfo> fields,
      List<CodeEntry> codes,
      List<PoolEntry> poolEntries,
      Map<Integer, List<Integer>> exceptionEntries,
      List<ObjectData> objects)
      throws IOException {
    boolean u = profile.fillRefUnsigned;
    switch (spec.kind) {
      case STRING:
        readFillStrings(s, cm, profile.oldStringFormat, profile.cids, strings, objects);
        break;
      case NONE:
      case SENTINEL:
      case INSTRUCTIONS_TABLE:
        break;
      case RODATA:
        if (profile.cids.isString(cm.cid) && cm.lengths != null && cm.lengths.length > 0) {
          int first = strings.size();
          extractRoDataStrings(fullData, header, cm, profile, strings);
          for (int i = first; i < strings.size(); i++) {
            var string = strings.get(i);
            objects.add(new ObjectData(string.refId, cm.cid, new int[0],
                new long[] {string.value.length()}, string.dataOffset,
                Math.multiplyExact(string.value.length(), string.isOneByte ? 1 : 2)));
          }
        } else {
          readRoDataBytes(fullData, header, cm, profile, objects);
        }
        break;
      case INLINE_BYTES:
        for (long i = 0; i < cm.count; i++) {
          long len = s.readUnsigned();
          int offset = s.position();
          int length = checkedLength(len);
          s.skip(length);
          objects.add(new ObjectData(cm.startRef + (int) i, cm.cid, new int[0],
              new long[] {len}, offset, length));
        }
        break;
      case REFS:
        readFillRefs(s, cm, spec, u, profile, namedObjects, funcTypes, types, fields, objects);
        break;
      case DOUBLE:
        for (long i = 0; i < cm.count; i++) {
          int canonical = profile.preCanonicalSplit ? s.readUint8() : -1;
          long bits = s.readTagged64();
          objects.add(new ObjectData(cm.startRef + (int) i, cm.cid, new int[0],
              new long[] {bits, canonical}, -1, 0));
        }
        break;
      case CODE:
        readFillCode(s, cm, profile, instrIdx[0], runningTextOffset, codes, objects);
        instrIdx[0] += (int) cm.mainCount;
        break;
      case OBJECT_POOL:
        readFillObjectPool(s, cm, profile, poolEntries, objects);
        break;
      case ARRAY:
        readFillArray(s, cm, u, profile, objects);
        break;
      case WEAK_ARRAY:
        for (long i = 0; i < cm.count; i++) {
          long len = s.readUnsigned();
          objects.add(new ObjectData(cm.startRef + (int) i, cm.cid,
              readReferences(s, len, u), new long[] {len}, -1, 0));
        }
        break;
      case TYPED_DATA: {
        int elemSize = typedDataElementSize(cm.cid, profile.cids);
        for (long i = 0; i < cm.count; i++) {
          long len = s.readUnsigned();
          int canonical = profile.preCanonicalSplit ? s.readUint8() : -1;
          int offset = s.position();
          int bytes = payloadBytes(s, len, elemSize);
          s.skip(bytes);
          objects.add(new ObjectData(cm.startRef + (int) i, cm.cid, new int[0],
              new long[] {len, elemSize, canonical}, offset, bytes));
        }
        break;
      }
      case EXTERNAL_TYPED_DATA: {
        // ExternalTypedDataSerializationCluster::WriteFill: length, 8-byte
        // alignment, raw elements. These bytes are not object references.
        int elementSize = typedDataElementSize(cm.cid, profile.cids);
        for (long i = 0; i < cm.count; i++) {
          long length = s.readUnsigned();
          s.align(8);
          int offset = s.position();
          int bytes = payloadBytes(s, length, elementSize);
          s.skip(bytes);
          objects.add(new ObjectData(cm.startRef + (int) i, cm.cid, new int[0],
              new long[] {length, elementSize}, offset, bytes));
        }
        break;
      }
      case VARIABLE_CLOSURE:
        for (long i = 0; i < cm.count; i++) {
          long length = readCount(s);
          objects.add(new ObjectData(cm.startRef + (int) i, cm.cid,
              readReferences(s, length + 3, u), new long[] {length}, -1, 0));
        }
        break;
      case LOCAL_VARIABLES:
        for (long i = 0; i < cm.count; i++) {
          long length = readCount(s);
          int[] refs = readReferences(s, length, u);
          if (length > s.remaining() / 5) throw new IOException("truncated local variable descriptors");
          long[] scalars = new long[Math.toIntExact(1 + 5 * length)];
          scalars[0] = length;
          for (int j = 0; j < length; j++) {
            for (int field = 0; field < 4; field++) scalars[1 + j * 5 + field] = s.readTagged32();
            scalars[1 + j * 5 + 4] = s.readTagged64();
          }
          objects.add(new ObjectData(cm.startRef + (int) i, cm.cid, refs, scalars, -1, 0));
        }
        break;
      case EXCEPTION_HANDLERS:
        for (long i = 0; i < cm.count; i++) {
          long raw = s.readUnsigned();
          long len = u ? raw : (raw >>> 1);
          int handledTypes = (int) s.readRef(u);
          if (raw < 0 || len > s.remaining() / 5) throw new IOException("invalid exception handler length");
          long[] scalars = new long[Math.toIntExact(1 + len * 5)];
          scalars[0] = raw;
          List<Integer> handlers = new ArrayList<>();
          for (int j = 0; j < len; j++) {
            int pc = s.readTagged32();
            if (pc >= 0) handlers.add(pc);
            scalars[1 + j * 5] = pc;
            scalars[1 + j * 5 + 1] = s.readTagged32();
            scalars[1 + j * 5 + 2] = s.readUint8();
            scalars[1 + j * 5 + 3] = s.readUint8();
            scalars[1 + j * 5 + 4] = s.readUint8();
          }
          objects.add(new ObjectData(cm.startRef + (int) i, cm.cid,
              new int[] {handledTypes}, scalars, -1, 0));
          exceptionEntries.put(cm.startRef + (int) i, List.copyOf(handlers));
        }
        break;
      case CONTEXT:
        for (long i = 0; i < cm.count; i++) {
          long len = s.readUnsigned();
          objects.add(new ObjectData(cm.startRef + (int) i, cm.cid,
              readReferences(s, len + 1, u), new long[] {len}, -1, 0));
        }
        break;
      case TYPE_ARGUMENTS:
        readFillTypeArguments(s, cm, u, profile, objects);
        break;
      case CLASS:
        readFillClass(s, cm, spec, u, profile, namedObjects, classes, objects);
        break;
      case FIELD:
        readFillField(s, cm, spec, u, namedObjects, fields, objects);
        break;
      case INSTANCE:
        readFillInstance(s, cm, u, profile.compressedPointers, profile.preCanonicalSplit,
            classes, objects);
        break;
      case RECORD:
        for (long i = 0; i < cm.count; i++) {
          long shape = s.readUnsigned();
          long numFields = shape & 0xffffL;
          objects.add(new ObjectData(cm.startRef + (int) i, cm.cid,
              readReferences(s, numFields, u), new long[] {shape}, -1, 0));
        }
        break;
      case CONTEXT_SCOPE:
        for (long i = 0; i < cm.count; i++) {
          long len = s.readUnsigned();
          int implicit = s.readUint8();
          objects.add(new ObjectData(cm.startRef + (int) i, cm.cid,
              readReferences(s, 7L * len, u), new long[] {len, implicit}, -1, 0));
        }
        break;
      default:
        throw new IOException("Unknown FillKind for CID " + cm.cid);
    }
  }

  private static void readFillStrings(
      DartStream s,
      ClusterMeta cm,
      boolean oldFormat,
      DartClassId.Table ct,
      List<ParsedString> out,
      List<ObjectData> objects)
      throws IOException {
    boolean cidIsTwoByte = oldFormat && ct.isTwoByteString(cm.cid);
    int ref = cm.startRef;
    for (int i = 0; i < cm.count; i++) {
      int prefixOffset = s.position();
      long encoded = s.readUnsigned();
      int length;
      boolean isTwoByte;
      if (oldFormat) {
        length = checkedLength(encoded);
        isTwoByte = cidIsTwoByte;
      } else {
        length = checkedLength(encoded >>> 1);
        isTwoByte = (encoded & 1L) != 0;
      }
      int dataOffset = s.position();
      String val;
      if (isTwoByte) {
        byte[] raw = s.readBytes(checkedLength((long) length * 2));
        char[] chars = new char[length];
        for (int j = 0; j < length; j++) {
          chars[j] = (char) ((raw[j * 2] & 0xff) | ((raw[j * 2 + 1] & 0xff) << 8));
        }
        val = new String(chars);
      } else {
        byte[] raw = s.readBytes(length);
        val = new String(raw, StandardCharsets.ISO_8859_1);
      }
      objects.add(new ObjectData(ref, cm.cid, new int[0], new long[] {encoded},
          dataOffset, checkedLength((long) length * (isTwoByte ? 2 : 1))));
      out.add(new ParsedString(ref++, val, !isTwoByte, dataOffset,
          prefixOffset, dataOffset - prefixOffset, false));
    }
  }

  /**
   * Extracts ROData strings from the data image region of a non-compressed-pointer snapshot.
   *
   * Directly implements {@code RODataDeserializationCluster::ReadAlloc} and
   * {@code ImageReader::GetObjectAt}:
   * <ul>
   *   <li>{@code data_image_} starts at {@code roundUp(totalSize, align)} (no extra {@code + align} skip).</li>
   *   <li>Each object offset is accumulated via {@code runningOffset += delta[i] << 4}
   *       ({@code kObjectAlignmentLog2 = 4} on 64-bit ARM64 without compressed pointers).</li>
   *   <li>Tag CID is at bits 16..31 in Dart <= 2.18 ({@code topLevelCid16}) and bits 12..31 in Dart >= 2.19.</li>
   * </ul>
   */
  private static void extractRoDataStrings(
      byte[] data,
      DartSnapshotHeader header,
      ClusterMeta cm,
      DartVersionProfile profile,
      List<ParsedString> out) throws IOException {
    if (profile.compressedPointers || header.totalSize <= 0 || cm.lengths == null) {
      throw new IOException("unsupported read-only string layout");
    }
    long align = profile.topLevelCid16 ? 16L : 64L;
    long diStart = header.snapshotOffset + DartInstructionsTable.roundUp(header.totalSize, align);
    if (diStart <= 0 || diStart > data.length - 16L) {
      throw new IOException("missing read-only string image");
    }

    DartClassId.Table ct = profile.cids;
    long imageSize = readLe64(data, (int) diStart);
    if (imageSize < 16 || imageSize > data.length - diStart) {
      throw new IOException("truncated read-only string image");
    }
    long imageEnd = diStart + imageSize;
    long runningOffset = 0;
    int ref = cm.startRef;
    for (int i = 0; i < cm.lengths.length; i++) {
      runningOffset = advanceRoOffset(runningOffset, cm.lengths[i], imageSize);
      long objPos = diStart + runningOffset;
      if (objPos > imageEnd - 16) throw new IOException("RO string outside image");
      long tags = readLe64(data, (int) objPos);
      int cid =
          profile.topLevelCid16
              ? (int) ((tags >>> 16) & 0xffffL)
              : (int) ((tags >>> 12) & 0xfffffL);
      boolean isOneByte = (cid == ct.oneByteString);
      boolean isTwoByte = (ct.twoByteString != 0 && cid == ct.twoByteString);
      if (!isOneByte && !isTwoByte) throw new IOException("invalid RO string CID: " + cid);
      long lenSmi = readLe64(data, (int) objPos + 8);
      if ((lenSmi & 1) != 0) throw new IOException("invalid string Smi length");
      int strLen = checkedLength(lenSmi >> 1);
      long byteLength = (long) strLen * (isTwoByte ? 2 : 1);
      if (byteLength > imageEnd - objPos - 16) throw new IOException("truncated RO string");
      int dataStart = (int) objPos + 16;
      if (isTwoByte) {
        if (dataStart + strLen * 2 <= data.length) {
          char[] chars = new char[strLen];
          for (int j = 0; j < strLen; j++) {
            int off = dataStart + j * 2;
            chars[j] = (char) ((data[off] & 0xff) | ((data[off + 1] & 0xff) << 8));
          }
          out.add(new ParsedString(ref, new String(chars), false, dataStart, (int) objPos, 16, true));
        }
      } else {
        if (dataStart + strLen <= data.length) {
          out.add(
              new ParsedString(
                  ref, new String(data, dataStart, strLen, StandardCharsets.ISO_8859_1), true, dataStart,
                  (int) objPos, 16, true));
        }
      }
      ref++;
    }
  }

  /** Explicit SDK length headers, not distances to the next RO object. */
  private static void readRoDataBytes(byte[] data, DartSnapshotHeader header,
      ClusterMeta cluster, DartVersionProfile profile, List<ObjectData> objects) throws IOException {
    int image = Math.toIntExact(header.snapshotOffset
        + DartInstructionsTable.roundUp(header.totalSize, profile.topLevelCid16 ? 16 : 64));
    if (image > data.length - 16) throw new IOException("missing read-only data image");
    long size = readLe64(data, image);
    if (size < 16 || size > data.length - image) throw new IOException("truncated read-only data image");
    long end = image + size;
    long offset = 0;
    boolean stackMaps = cluster.cid == profile.cids.compressedStackMaps;
    for (int i = 0; i < cluster.count; i++) {
      offset = advanceRoOffset(offset, cluster.lengths[i], size);
      long object = image + offset;
      if (object < image || object > end - 16) throw new IOException("RO metadata outside image");
      long tags = readLe64(data, (int) object);
      int cid = profile.topLevelCid16 ? (int) ((tags >>> 16) & 0xffff)
          : (int) ((tags >>> 12) & 0xfffff);
      if (cid != cluster.cid) throw new IOException("RO metadata CID differs from cluster");
      long encoded = readLe64(data, (int) object + 8);
      if (stackMaps) encoded &= 0xffffffffL;
      long length = stackMaps ? encoded >>> 2 : encoded;
      long payload = object + (stackMaps ? 12 : 16);
      if (length < 0 || length > end - payload) throw new IOException("RO metadata payload outside image");
      objects.add(new ObjectData(cluster.startRef + i, cluster.cid, new int[0],
          new long[] {encoded}, Math.toIntExact(payload), checkedLength(length)));
    }
  }

  private static long readLe64(byte[] data, int off) {
    return (data[off] & 0xffL)
        | ((data[off + 1] & 0xffL) << 8)
        | ((data[off + 2] & 0xffL) << 16)
        | ((data[off + 3] & 0xffL) << 24)
        | ((data[off + 4] & 0xffL) << 32)
        | ((data[off + 5] & 0xffL) << 40)
        | ((data[off + 6] & 0xffL) << 48)
        | ((data[off + 7] & 0xffL) << 56);
  }

  private static void readFillRefs(
      DartStream s,
      ClusterMeta cm,
      FillSpec spec,
      boolean u,
      DartVersionProfile profile,
      List<NamedObject> namedOut,
      List<FuncTypeInfo> funcTypesOut,
      List<TypeInfo> typesOut,
      List<FieldInfo> fieldsOut,
      List<ObjectData> objects)
      throws IOException {
    boolean isTypeCluster = (cm.cid == profile.cids.type);
    int ref = cm.startRef;
    for (int i = 0; i < cm.count; i++) {
      int canonical = spec.leadingBool ? s.readUint8() : -1;
      int nameRef = -1;
      int ownerRef = -1;
      int sigRef = -1;
      int[] capturedRefs = new int[spec.numRefs];
      for (int j = 0; j < spec.numRefs; j++) {
        int r = (int) s.readRef(u);
        capturedRefs[j] = r;
        if (j == spec.nameIdx) {
          nameRef = r;
        }
        if (j == spec.ownerIdx) {
          ownerRef = r;
        }
        if (spec.signatureIdx > 0 && j == spec.signatureIdx) {
          sigRef = r;
        }
      }
      int fieldKindBits = 0;
      long[] capturedScalars = new long[spec.scalars.length];
      for (int si = 0; si < spec.scalars.length; si++) {
        ScalarOp op = spec.scalars[si];
        if (spec.isFuncType && si == 1) {
          int packed = s.readTagged32();
          capturedScalars[si] = packed;
          boolean hasImplicit = (packed & 1) != 0;
          int numFixed = (packed >>> 2) & 0x3fff;
          int numOptional = (packed >>> 16) & 0x3fff;
          if (hasImplicit && numFixed > 0) {
            numFixed--;
          }
          funcTypesOut.add(new FuncTypeInfo(ref, numFixed, numOptional, hasImplicit));
        } else if (spec.isField && si == 0) {
          fieldKindBits = s.readTagged32();
          capturedScalars[si] = fieldKindBits;
        } else if (spec.isField && si == 1) {
          int hostOff = (int) s.readRef(u);
          capturedScalars[si] = hostOff;
          capturedRefs = java.util.Arrays.copyOf(capturedRefs, capturedRefs.length + 1);
          capturedRefs[capturedRefs.length - 1] = hostOff;
          fieldsOut.add(
              new FieldInfo(ref, nameRef, ownerRef, fieldKindBits, hostOff, -1));
        } else if (cm.cid == profile.cids.function && si == 0
            && profile.codeTextOffsetDelta) {
          // Legacy Function serializes a Code reference here. InstructionsTable
          // formats replace it with a numeric code_index; those are not refs.
          int codeRef = (int) s.readRef(u);
          capturedScalars[si] = codeRef;
          capturedRefs = java.util.Arrays.copyOf(capturedRefs, capturedRefs.length + 1);
          capturedRefs[capturedRefs.length - 1] = codeRef;
        } else {
          long val = readScalar(s, op);
          capturedScalars[si] = val;
        }
      }
      long[] rawScalars = capturedScalars;
      if (spec.leadingBool) {
        rawScalars = new long[capturedScalars.length + 1];
        rawScalars[0] = canonical;
        System.arraycopy(capturedScalars, 0, rawScalars, 1, capturedScalars.length);
      }
      objects.add(new ObjectData(ref, cm.cid, capturedRefs, rawScalars, -1, 0));
      if (isTypeCluster) {
        typesOut.add(new TypeInfo(ref, cm.cid, capturedRefs, capturedScalars));
      }
      if (spec.nameIdx >= 0) {
        namedOut.add(new NamedObject(cm.cid, ref, nameRef, ownerRef, sigRef));
      }
      ref++;
    }
  }

  private static long readScalar(DartStream s, ScalarOp op) throws IOException {
    switch (op) {
      case TAGGED_32:
      case UINT16:
      case INT16:
        return s.readTagged32();
      case TAGGED_64:
        return s.readTagged64();
      case UNSIGNED:
        return s.readUnsigned();
      case BOOL:
      case UINT8:
        return s.readUint8();
      case INT8:
        return s.readByte();
      case REF_ID:
        return s.readRefId();
      default:
        throw new IOException("unsupported scalar encoding: " + op);
    }
  }

  private static void readFillClass(
      DartStream s,
      ClusterMeta cm,
      FillSpec spec,
      boolean u,
      DartVersionProfile profile,
      List<NamedObject> namedOut,
      List<ClassInfo> classesOut,
      List<ObjectData> objects)
      throws IOException {
    long topLevelOffset = profile.topLevelCid16 ? (1L << 16) : (1L << 20);
    int ref = cm.startRef;
    for (int i = 0; i < cm.count; i++) {
      int[] refs = readReferences(s, spec.numRefs, u);
      int nameRef = refs[spec.nameIdx];
      var layout = profile.classLayout;
      int libraryRef = refs[layout.library()];
      int declTypeRef = refs[layout.declarationType()];
      int allocStubRef = layout.allocationStub() < 0 ? -1 : refs[layout.allocationStub()];
      int classId = s.readTagged32();
      int instanceSize = s.readTagged32();
      int nextFieldOff = s.readTagged32();
      int typeArgsOff = s.readTagged32();
      int numTypeArguments = s.readTagged32();
      int numNativeFields = s.readTagged32();
      int tokenPos = 0;
      int endTokenPos = 0;
      if (profile.classHasTokenPos) {
        tokenPos = s.readTagged32();
        endTokenPos = s.readTagged32();
      }
      int stateBits = s.readTagged32();

      boolean isPredefined = i < cm.mainCount;
      boolean isTopLevel = (long) classId >= topLevelOffset;
      long unboxedFields = isPredefined || !isTopLevel ? s.readUnsigned() : 0;
      var scalars = new ArrayList<Long>();
      for (long scalar : new long[] {classId, instanceSize, nextFieldOff, typeArgsOff,
          numTypeArguments, numNativeFields}) scalars.add(scalar);
      if (profile.classHasTokenPos) {
        scalars.add((long) tokenPos);
        scalars.add((long) endTokenPos);
      }
      scalars.add((long) stateBits);
      if (isPredefined || !isTopLevel) scalars.add(unboxedFields);
      objects.add(new ObjectData(ref, cm.cid, refs,
          scalars.stream().mapToLong(Long::longValue).toArray(), -1, 0));
      namedOut.add(new NamedObject(cm.cid, ref, nameRef, -1, -1));
      classesOut.add(
          new ClassInfo(
              ref,
              nameRef,
              libraryRef,
              refs[layout.superType()],
              declTypeRef,
              allocStubRef,
              classId,
              instanceSize,
              nextFieldOff,
              typeArgsOff, unboxedFields));
      ref++;
    }
  }

  private static void readFillField(
      DartStream s,
      ClusterMeta cm,
      FillSpec spec,
      boolean u,
      List<NamedObject> namedOut,
      List<FieldInfo> fieldsOut,
      List<ObjectData> objects)
      throws IOException {
    int ref = cm.startRef;
    for (int i = 0; i < cm.count; i++) {
      int nameRef = -1;
      int ownerRef = -1;
      int[] refs = new int[spec.numRefs];
      for (int j = 0; j < spec.numRefs; j++) {
        int r = (int) s.readRef(u);
        refs[j] = r;
        if (j == spec.nameIdx) {
          nameRef = r;
        }
        if (j == spec.ownerIdx) {
          ownerRef = r;
        }
      }
      int kindBits = s.readTagged32();
      int valOrOff = (int) s.readRef(u);
      boolean isStatic = ((kindBits >>> 1) & 1) != 0;
      long fieldId = isStatic ? s.readUnsigned() : -1;
      // The last serialized reference is an initial static value or an offset Smi.
      // Keep it in the reference graph as well as its interpreted scalar position.
      int[] allRefs = java.util.Arrays.copyOf(refs, refs.length + 1);
      allRefs[refs.length] = valOrOff;
      objects.add(new ObjectData(ref, cm.cid, allRefs,
          new long[] {kindBits, valOrOff, fieldId}, -1, 0));
      namedOut.add(new NamedObject(cm.cid, ref, nameRef, ownerRef, -1));
      fieldsOut.add(new FieldInfo(ref, nameRef, ownerRef, kindBits, valOrOff, fieldId));
      ref++;
    }
  }

  private static void readFillCode(
      DartStream s,
      ClusterMeta cm,
      DartVersionProfile profile,
      int instrIdxBase,
      long[] runningTextOffset,
      List<CodeEntry> out,
      List<ObjectData> objects)
      throws IOException {
    boolean u = profile.fillRefUnsigned;
    int numRefs = profile.codeNumRefs > 0 ? profile.codeNumRefs : 6;
    int stateBitsAfterRef = profile.codeStateBitsAfterRef;
    int ref = cm.startRef;
    int instrIdx = instrIdxBase;
    if (profile.codeFormat() == DartVersionProfile.CodeFormat.MERGED_TABLE) {
      // CodeSerializationCluster::WriteFill writes reference IDs here, not
      // instruction-table indices. Retain them once for the whole cluster.
      cm.lazyCompileRef = (int) s.readRef(false);
      cm.unknownDartCodeRef = (int) s.readRef(false);
      if (cm.lazyCompileRef < cm.startRef || cm.lazyCompileRef >= cm.stopRef
          || cm.unknownDartCodeRef < cm.startRef || cm.unknownDartCodeRef >= cm.stopRef) {
        throw new IOException("merged helper references outside the Code cluster");
      }
    }

    for (long i = 0; i < cm.count; i++) {
      long payloadInfo = 0;
      long textOff = 0;
      int clusterIndex = -1;
      boolean discarded = cm.discardedCodes != null && cm.discardedCodes.contains(i);
      int stateBits = cm.codeStateBits == null ? 0 : cm.codeStateBits[(int) i];
      var references = new ArrayList<Integer>(numRefs);

      if (i < cm.mainCount) {
        if (profile.codeTextOffsetDelta) {
          long delta = s.readUnsigned();
          runningTextOffset[0] = advanceTextOffset(runningTextOffset[0], delta);
          textOff = runningTextOffset[0];
        }
        payloadInfo = s.readUnsigned();
        clusterIndex = instrIdx++;
        if (discarded && stateBitsAfterRef == 0) {
          references.add((int) s.readRef(u)); // compressed_stackmaps inside ReadInstructions
        }
      }

      int ownerRef = 0;
      int exceptionRef = 0;
      if (stateBitsAfterRef > 0) {
        // Dart 2.13: first N refs -> state_bits -> [if !discarded: remaining refs]
        for (int j = 0; j < stateBitsAfterRef; j++) {
          references.add((int) s.readRef(u));
        }
        stateBits = s.readTagged32();
        discarded = ((stateBits >>> 3) & 1) != 0;
        if (!discarded) {
          for (int j = stateBitsAfterRef; j < numRefs; j++) {
            int r = (int) s.readRef(u);
            references.add(r);
            if (j == stateBitsAfterRef) {
              ownerRef = r;
            } else if (j == stateBitsAfterRef + 1) {
              exceptionRef = r;
            }
          }
        }
      } else if (!discarded) {
        for (int j = 0; j < numRefs; j++) {
          int r = (int) s.readRef(u);
          references.add(r);
          if (j == 0) {
            ownerRef = r;
          } else if (j == 1) {
            exceptionRef = r;
          }
        }
      }

      if (profile.codeStateBitsAtEnd) {
        stateBits = s.readTagged32();
      }
      objects.add(new ObjectData(ref, cm.cid,
          references.stream().mapToInt(Integer::intValue).toArray(),
          new long[] {stateBits}, -1, 0));
      out.add(new CodeEntry(ref++, ownerRef, clusterIndex, payloadInfo, textOff, exceptionRef));
    }
  }

  private static void readFillObjectPool(
      DartStream s, ClusterMeta cm, DartVersionProfile profile, List<PoolEntry> out,
      List<ObjectData> objects) throws IOException {
    boolean u = profile.fillRefUnsigned;
    for (long i = 0; i < cm.count; i++) {
      int idx = 0;
      int poolRef = cm.startRef + (int) i;
      long length = readCount(s);
      objects.add(new ObjectData(poolRef, cm.cid, new int[0], new long[] {length}, -1, 0));
      for (long j = 0; j < length; j++) {
        int entryBits = s.readUint8();
        if (profile.oldPoolFormat) {
          int typeBits = entryBits & 0x7f;
          if (profile.poolTypeSwapped && typeBits <= 1) {
            typeBits ^= 1;
          }
          switch (typeBits) {
            case 0:
            case 4: {
              int r = (int) s.readRef(u);
              out.add(new PoolEntry(poolRef, idx++, entryBits, PoolEntryKind.TAGGED, r, 0));
              break;
            }
            case 1: {
              long imm = s.readTagged64();
              out.add(new PoolEntry(poolRef, idx++, entryBits, PoolEntryKind.IMMEDIATE, 0, imm));
              break;
            }
            case 2:
            case 3:
              out.add(new PoolEntry(poolRef, idx++, entryBits, PoolEntryKind.NATIVE, 0, 0));
              break;
            default:
              throw new IOException("Unknown v2 ObjectPool entry type: " + typeBits
                  + " at pool " + poolRef + " slot " + idx
                  + " after bits=" + (out.isEmpty() ? -1 : out.get(out.size()-1).bits)
                  + " kind=" + (out.isEmpty() ? "" : out.get(out.size()-1).kind));
          }
        } else {
          int behaviorBits = entryBits >>> 5;
          int typeBits = entryBits & 0x0f;
          if (behaviorBits == 0) {
            switch (typeBits) {
              case 0: {
                long imm = s.readTagged64();
                out.add(new PoolEntry(poolRef, idx++, entryBits, PoolEntryKind.IMMEDIATE, 0, imm));
                break;
              }
              case 1: {
                int r = (int) s.readRef(u);
                out.add(new PoolEntry(poolRef, idx++, entryBits, PoolEntryKind.TAGGED, r, 0));
                break;
              }
              case 2:
                out.add(new PoolEntry(poolRef, idx++, entryBits, PoolEntryKind.NATIVE, 0, 0));
                break;
              default:
                throw new IOException("Unknown v3 ObjectPool entry type: " + typeBits);
            }
          } else {
            out.add(new PoolEntry(poolRef, idx++, entryBits, PoolEntryKind.EMPTY, 0, 0));
          }
        }
      }
    }
  }

  /** Arrays retain their type-arguments reference followed by all element references. */
  private static void readFillArray(DartStream s, ClusterMeta cm, boolean u,
      DartVersionProfile profile, List<ObjectData> objects) throws IOException {
    for (int i = 0; i < cm.count; i++) {
      long length = profile.oldArrayFill ? cm.lengths[i] : s.readUnsigned();
      int canonical = profile.preCanonicalSplit && !profile.oldArrayFill ? s.readUint8() : -1;
      int[] refs = readReferences(s, length + 1, u);
      objects.add(new ObjectData(cm.startRef + i, cm.cid, refs,
          new long[] {length, canonical}, -1, 0));
    }
  }

  private static int[] readReferences(DartStream s, long length, boolean unsigned)
      throws IOException {
    if (length < 0 || length > Integer.MAX_VALUE || length > s.remaining()) {
      throw new IOException("object reference sequence exceeds snapshot bounds: " + length);
    }
    int[] refs = new int[(int) length];
    for (int i = 0; i < refs.length; i++) refs[i] = (int) s.readRef(unsigned);
    return refs;
  }

  private static void readFillTypeArguments(DartStream s, ClusterMeta cm, boolean u,
      DartVersionProfile profile, List<ObjectData> objects) throws IOException {
    for (int i = 0; i < cm.count; i++) {
      long length = profile.oldTypeArgsFill ? cm.lengths[i] : s.readUnsigned();
      if (profile.oldTypeArgsFill) {
        int[] refs = readReferences(s, length + 1, u);
        objects.add(new ObjectData(cm.startRef + i, cm.cid, refs,
            new long[] {length, s.readTagged32()}, -1, 0));
        continue;
      }
      int canonical = profile.preCanonicalSplit ? s.readUint8() : -1;
      int hash = s.readTagged32();
      long nullability = s.readUnsigned();
      objects.add(new ObjectData(cm.startRef + i, cm.cid,
          readReferences(s, length + 1, u), new long[] {length, canonical, hash, nullability}, -1, 0));
    }
  }

  /** Preserve pointer fields and unboxed word pairs using the SDK field bitmap. */
  private static void readFillInstance(DartStream s, ClusterMeta cm, boolean u,
      boolean compressedPointers, boolean preCanonicalSplit, List<ClassInfo> classes,
      List<ObjectData> objects) throws IOException {
    long bitmap = 0;
    if (preCanonicalSplit) {
      boolean found = false;
      for (var cls : classes) {
        if (cls.classId == cm.cid) { bitmap = cls.unboxedFields; found = true; break; }
      }
      if (!found) throw new IOException("missing Class bitmap for legacy instance CID " + cm.cid);
    } else {
      bitmap = s.readUnsigned();
    }
    int headerWords = compressedPointers ? 2 : 1;
    int fields = cm.nextFieldOffsetInWords - headerWords;
    if (fields < 0 || fields > MAX_STEPS) throw new IOException("invalid instance field extent");
    for (int i = 0; i < cm.count; i++) {
      int canonical = preCanonicalSplit ? s.readUint8() : -1;
      var refs = new ArrayList<Integer>();
      var scalars = new ArrayList<Long>();
      scalars.add(bitmap);
      scalars.add((long) cm.nextFieldOffsetInWords);
      scalars.add((long) cm.instanceSizeInWords);
      if (preCanonicalSplit) scalars.add((long) canonical);
      for (int j = 0; j < fields; j++) {
        int word = headerWords + j;
        if (word < 64 && ((bitmap >>> word) & 1) != 0) {
          scalars.add((long) s.readTagged32());
          scalars.add((long) s.readTagged32());
        } else {
          refs.add((int) s.readRef(u));
        }
      }
      objects.add(new ObjectData(cm.startRef + i, cm.cid,
          refs.stream().mapToInt(Integer::intValue).toArray(),
          scalars.stream().mapToLong(Long::longValue).toArray(), -1, 0));
    }
  }

  private static int typedDataElementSize(int cid, DartClassId.Table ct) {
    if (ct.nativePointerCid != 0 && cid == ct.nativePointerCid) {
      return 1;
    }
    if (ct.typedData != 0 && cid == ct.typedData) {
      return 1;
    }
    if (ct.typedDataInt8ArrayCid <= 0 || ct.typedDataCidStride <= 0) {
      return 1;
    }
    int idx = (cid - ct.typedDataInt8ArrayCid) / ct.typedDataCidStride;
    int[] sizes = {1, 1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 16, 16, 16};
    return (idx >= 0 && idx < sizes.length) ? sizes[idx] : 1;
  }
}
