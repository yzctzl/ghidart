/**
 * Select the Dart ARM64 language for recognized AOT ELF images.
 *
 * Detection checks the snapshot symbols and data magic through ELF load
 * segments, since a symbol value is a virtual address rather than a file offset.
 * Mapping, relocation and ordinary ELF behavior stay in Ghidra's ElfLoader.
 * This loader neither parses Dart objects nor discovers function boundaries;
 * Mach-O continues to use the official loader with explicit language selection.
 */
package ghidart;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.app.util.opinion.QueryOpinionService;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Selects the Dart language; all ELF loading stays in Ghidra's ELF loader. */
public final class DartElfLoader extends ElfLoader {
  private static final List<String> SPLIT_SNAPSHOT = List.of(
      "_kDartVmSnapshotInstructions", "_kDartVmSnapshotData",
      "_kDartIsolateSnapshotInstructions", "_kDartIsolateSnapshotData");
  private static final List<String> UNIT_SNAPSHOT = List.of(
      "_kDartIsolateSnapshotInstructions", "_kDartIsolateSnapshotData");
  private static final List<String> SINGLE_SNAPSHOT = List.of(
      "_kDartSnapshotText", "_kDartSnapshotData");
  private static final byte[] SNAPSHOT_MAGIC = {
      (byte) 0xf5, (byte) 0xf5, (byte) 0xdc, (byte) 0xdc
  };

  @Override
  public String getName() {
    return "Dart AOT ELF";
  }

  @Override
  public int getTierPriority() {
    return super.getTierPriority() - 10;
  }

  @Override
  public LoaderTier getTier() {
    return LoaderTier.GENERIC_TARGET_LOADER;
  }

  @Override
  public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
    List<LoadSpec> specs = new ArrayList<>();
    try {
      ElfHeader elf = new ElfHeader(provider, null);
      elf.parse();
      if (!elf.is64Bit() || !elf.isLittleEndian() || !hasSnapshots(provider, elf)) {
        return specs;
      }
      for (var result : QueryOpinionService.query(getName(), elf.getMachineName(), elf.getFlags())) {
        specs.add(new LoadSpec(this, 0, result));
      }
    } catch (ElfException e) {
      // A different loader handles files that are not ELF.
    }
    return specs;
  }

  private static boolean hasSnapshots(ByteProvider provider, ElfHeader elf) throws IOException {
    Map<String, ElfSymbol> symbols = new HashMap<>();
    for (var table : elf.getSymbolTables()) {
      for (var symbol : table.getSymbols()) {
        String name = symbol.getNameAsString();
        if (symbol.getSectionHeaderIndex() != 0
            && (SPLIT_SNAPSHOT.contains(name) || SINGLE_SNAPSHOT.contains(name))
            && elf.getProgramLoadHeaderContaining(symbol.getValue()) != null) {
          ElfSymbol existing = symbols.putIfAbsent(name, symbol);
          if (existing != null && existing.getValue() != symbol.getValue()) {
            return false;
          }
        }
      }
    }
    // SDKs export either two separate images or one combined image.
    // Incomplete or mixed layouts do not establish a Dart snapshot.
    boolean split = SPLIT_SNAPSHOT.stream().allMatch(symbols::containsKey);
    boolean single = SINGLE_SNAPSHOT.stream().allMatch(symbols::containsKey);
    boolean unit = symbols.size() == UNIT_SNAPSHOT.size()
        && UNIT_SNAPSHOT.stream().allMatch(symbols::containsKey);
    if ((split ? 1 : 0) + (single ? 1 : 0) + (unit ? 1 : 0) != 1
        || symbols.size() != (split ? SPLIT_SNAPSHOT.size() : SINGLE_SNAPSHOT.size())) {
      return false;
    }
    for (String name : split ? SPLIT_SNAPSHOT : unit ? UNIT_SNAPSHOT : SINGLE_SNAPSHOT) {
      ElfSymbol symbol = symbols.get(name);
      if (symbol == null) {
        return false;
      }
      // Symbol values are virtual addresses, not file offsets. Section names
      // and the total number of exported symbols are irrelevant to Dart AOT.
      var segment = elf.getProgramLoadHeaderContaining(symbol.getValue());
      if (segment == null) {
        return false;
      }
      long relative = symbol.getValue() - segment.getVirtualAddress();
      long requiredBytes = name.endsWith("Data") ? SNAPSHOT_MAGIC.length : 4;
      if (relative < 0 || relative > segment.getFileSize() - requiredBytes) {
        return false;
      }
      if (name.endsWith("Data") && !Arrays.equals(SNAPSHOT_MAGIC,
          provider.readBytes(segment.getOffset() + relative, SNAPSHOT_MAGIC.length))) {
        return false;
      }
    }
    return true;
  }
}
