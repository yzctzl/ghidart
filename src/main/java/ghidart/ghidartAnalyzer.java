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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
//import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.flatapi.FlatProgramAPI;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class ghidartAnalyzer extends AbstractAnalyzer {

    private FlatProgramAPI fp;

    public ghidartAnalyzer() {
        // Name the analyzer and give it a description.
        super("DartFuncFounder", "Find functions from snapshot Instructions.", AnalyzerType.BYTE_ANALYZER);
    }

    @Override
    public boolean getDefaultEnablement(Program program) {
        // Return true if analyzer should be enabled by default
        return true;
    }

    @Override
    public boolean canAnalyze(Program program) {
        // Examine 'program' to determine of this analyzer should analyze it.  Return true
        // if it can.
        return program.getLanguageID().toString().equals("AARCH64:LE:64:dart");
    }

    @Override
    public void registerOptions(Options options, Program program) {
        // If this analyzer has custom options, register them here
        options.registerOption("Option_name_01", false, null,
                "Option description goes here");
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        // Perform analysis when things get added to the 'program'.  Return true if the
        // analysis succeeded.

        long byte_width = 0x8;
        // UntaggedInstructionsSection size is fixed from dart sdk version v2.8.0
        // https://github.com/dart-lang/sdk/blob/2.15.0/runtime/vm/image_snapshot.h#L37-L44
        long ins_header_length = byte_width * 5;

        fp = new FlatProgramAPI(program);
//		Listing listing = program.getListing();

        // disassemble functions in SnapshotInstructions one by one
        SymbolIterator si = program.getSymbolTable().getSymbolIterator();
        MemoryBlock mb = program.getMemory().getBlock(".text");
        // set monitor size to .text section size
        monitor.setMaximum(mb.getSize());
        // set VmSnapshotInstructions and IsolateSnapshotInstructions start and end address
        Address vmAddr = null, isoAddr = null, vmEnd = null, isoEnd;
        isoEnd = mb.getEnd();
        while (si.hasNext()) {
            Symbol symbol = si.next();
            if (symbol.getName().equals("_kDartVmSnapshotInstructions")) {
                vmAddr = symbol.getAddress();
            } else if (symbol.getName().equals("_kDartIsolateSnapshotInstructions")) {
                vmEnd = symbol.getAddress();
                isoAddr = symbol.getAddress();
            }
        }
        if (vmAddr == null || vmEnd == null) {
            return false;
        }
        // get SnapshotInstructions Offset and let addr point to first function
        try {
            long offset = program.getMemory().getLong(vmAddr.add(byte_width)) + ins_header_length;
            vmAddr = vmAddr.add(offset);
            isoAddr = isoAddr.add(offset);
        } catch (AddressOutOfBoundsException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return false;
        } catch (MemoryAccessException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return false;
        }
        // process _kDartVmSnapshotInstructions
        while (vmAddr.getOffset() < vmEnd.getOffset()) {
            fp.disassemble(vmAddr);
            long old = vmAddr.getOffset();
            Function vmFunc = fp.createFunction(vmAddr, "VmFunc_" + Long.toHexString(vmAddr.getOffset()));
            if (vmFunc != null) {
                vmAddr = vmFunc.getBody().getFirstRange().getMaxAddress().add(1);
                monitor.increment(vmAddr.getOffset() - old);
            } else {
                vmAddr = vmEnd;
            }
        }
        // process _kDartIsolateSnapshotInstructions
        while (isoAddr.getOffset() < isoEnd.getOffset()) {
            fp.disassemble(isoAddr);
            long old = isoAddr.getOffset();
            Function isoFunc = fp.createFunction(isoAddr, "IsoFunc_" + Long.toHexString(isoAddr.getOffset()));
            if (isoFunc != null) {
                isoAddr = isoFunc.getBody().getFirstRange().getMaxAddress().add(1);
                monitor.increment(isoAddr.getOffset() - old);
            } else {
                isoAddr = isoEnd;
            }
        }

        return true;
    }
}
