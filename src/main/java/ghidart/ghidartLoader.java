/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidart;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.ElfSectionHeader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.program.model.lang.Endian;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Dart ELF file demo loader
 */
public class ghidartLoader extends ElfLoader {
    List<String> dynsyms = List.of("_kDartVmSnapshotInstructions", "_kDartVmSnapshotData",
            "_kDartIsolateSnapshotInstructions", "_kDartIsolateSnapshotData");
    List<ElfSymbol> elfsyms = new ArrayList<>();

    // https://github.com/dart-lang/sdk/commit/3989d09c9578fe6d5ae51146b058e039755d1722
    byte[] kMagicValue = {(byte) 0xF5, (byte) 0xF5, (byte) 0xDC, (byte) 0xDC};

    @Override
    public String getName() {
        return "Dart ELF Loader Demo";
    }

    @Override
    public int getTierPriority() {
        return super.getTierPriority() + 10;
    }

    @Override
    public LoaderTier getTier() {
        return LoaderTier.GENERIC_TARGET_LOADER;
    }

    // match symbol name and SnapshotData magic value
    private boolean matchDynSymbols(ByteProvider provider, ElfHeader elf, ElfSymbol[] symbols) throws IOException {
        for (String dynsym : dynsyms) {
            elfsyms.add(getSymbolbyName(provider, dynsym, symbols));
        }

        return  !elfsyms.contains(null) &&
                alignDynSymbols(elf.getSection(".text"), elfsyms.get(0), elfsyms.get(2)) &&
                alignDynSymbols(elf.getSection(".rodata"), elfsyms.get(1), elfsyms.get(3));
    }

    // get dart snapshot elfsymbol by name and check magic number(0xF5F5DCDC) if necessary
    private ElfSymbol getSymbolbyName(ByteProvider provider, String symName, ElfSymbol[] symbols) throws IOException {
        for (ElfSymbol symbol : symbols) {
            if (symbol.getNameAsString().equals(symName)) {
                if (symName.endsWith("Data")) {
                    byte[] first4bytes = provider.readBytes(symbol.getValue(), kMagicValue.length);
                    if (Arrays.equals(first4bytes, kMagicValue))
                        return symbol;
                } else {
                    return symbol;
                }
            }
        }
        return null;
    }

    // .text = _kDartVmSnapshotInstructions + _kDartIsolateSnapshotInstructions
    // .rodata = _kDartVmSnapshotData + _kDartIsolateSnapshotData
    private boolean alignDynSymbols(ElfSectionHeader sct, ElfSymbol sym1, ElfSymbol sym2) {
        return (sct.getAddress() == sym1.getValue()) ||
                (sym1.getValue() + sym1.getSize() == sym2.getValue()) ||
                (sym2.getValue() + sym2.getSize() == sct.getAddress() + sct.getSize());
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        try {
            ElfHeader elf = new ElfHeader(provider, null);

            elf.parse();
            ElfSymbol[] symbols = elf.getSymbolTable(elf.getSection(".dynsym")).getSymbols();
            // https://github.com/dart-lang/sdk/blob/3.1.5/runtime/include/dart_api.h#L3980-L3987
            // dart elf aot snapshot contains 8 symbols: dartDynsyms, "", _kDartSnapshotBuildId,
            // _kDartVmSnapshotBss and _kDartIsolateSnapshotBss, and Bss may not exist
            if (symbols.length > 10 || !matchDynSymbols(provider, elf, symbols)) {
                return loadSpecs;
            }

            List<QueryResult> results =
                    QueryOpinionService.query(getName(), elf.getMachineName(), elf.getFlags());
            for (QueryResult result : results) {
                // this loader workes for aarch64 LE now
                if (!elf.is64Bit() || !elf.isLittleEndian() ||
                        (result.pair.getLanguageDescription().getSize() <= 32) ||
                        (result.pair.getLanguageDescription().getEndian() != Endian.LITTLE)) {
                    continue;
                }
                // link this loader with result language pair
                loadSpecs.add(new LoadSpec(this, 0, result));
            }
        }
        catch (ElfException e) {
            // not a problem, it's not an elf
        }

        return loadSpecs;
    }

    @Override
    public void load(Program program, ImporterSettings settings)
            throws CancelledException, IOException {
        super.load(program, settings);
        // clear code block before analysis
        for (Symbol symbol : program.getSymbolTable().getDefinedSymbols()) {
            if (dynsyms.contains(symbol.getName())) {
                program.getListing().clearCodeUnits(symbol.getAddress(), symbol.getAddress(), false, settings.monitor());
            }
        }
    }

//	@Override
//	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
//			DomainObject domainObject, boolean isLoadIntoProgram) {
//		List<Option> list =
//			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
//
//		// TODO: If this loader has custom options, add them to 'list'
//		list.add(new Option("Option name goes here", "Default option value goes here"));
//
//		return list;
//	}
//
//	@Override
//	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
//
//		// TODO: If this loader has custom options, validate them here.  Not all options require
//		// validation.
//
//		return super.validateOptions(provider, loadSpec, options, program);
//	}
}
