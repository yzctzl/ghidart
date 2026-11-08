/**
 * Expose a proved RuntimeStub's stack side effects to the calling function.
 *
 * A normal prototype cannot express its argc-dependent stack return slot. The
 * official callfixup interface instead reuses the stub's decoded instructions,
 * including its native CALL and register effects. Only the final RET is omitted.
 * This is a decompiler view: bytes, disassembly, function ranges and debugger
 * registers remain unchanged. Control flow or incomplete bodies reject inlining.
 */
package ghidart.analysis;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.InjectPayloadCallfixup;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.NotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeMap;

/** Uses the official decoder instead of maintaining a handwritten stub summary. */
public final class DartPcodeInjectLibrary extends PcodeInjectLibrary {
  public static final String RUNTIME_STUB = "dart_runtime_stub";

  public DartPcodeInjectLibrary(SleighLanguage language) {
    super(language);
  }

  private DartPcodeInjectLibrary(DartPcodeInjectLibrary source) { super(source); }

  @Override
  public PcodeInjectLibrary clone() { return new DartPcodeInjectLibrary(this); }

  @Override
  public InjectPayload allocateInject(String source, String name, int type) {
    if (type == InjectPayload.CALLOTHERFIXUP_TYPE && "dart_pool_value".equals(name)) {
      return new PoolValue(source);
    }
    if (type != InjectPayload.CALLFIXUP_TYPE || !RUNTIME_STUB.equals(name)) {
      return super.allocateInject(source, name, type);
    }
    long base = uniqueBase;
    uniqueBase += RuntimeStub.TEMPORARY_CAPACITY;
    return new RuntimeStub(source, base);
  }

  /** The decoder marker is an identity for all machine-only consumers. */
  static boolean isPoolIdentity(Program program, PcodeOp op) {
    return op.getOpcode() == PcodeOp.CALLOTHER && op.getNumInputs() == 2
        && op.getOutput() != null && op.getOutput().equals(op.getInput(1))
        && "dart_pool_value".equals(program.getLanguage().getUserDefinedOpName((int) op.getInput(0).getOffset()));
  }

  @Override
  public ghidra.program.model.lang.ConstantPool getConstantPool(Program program) {
    return new DartConstantPool(program);
  }

  private static final class PoolValue extends ghidra.program.model.lang.InjectPayloadCallother {
    PoolValue(String source) { super(source); }

    @Override
    public PcodeOp[] getPcode(Program program, InjectContext context) {
      var slot = DartConstantPool.reference(program, context.baseAddr);
      var output = context.output.getFirst();
      if (slot == null) return new PcodeOp[] {new PcodeOp(context.baseAddr, 0,
          PcodeOp.COPY, new Varnode[] {context.inputlist.getFirst()}, output)};
      var constants = program.getAddressFactory().getConstantSpace();
      return new PcodeOp[] {new PcodeOp(context.baseAddr, 0, PcodeOp.CPOOLREF,
          new Varnode[] {new Varnode(constants.getAddress(0), 8),
              new Varnode(constants.getAddress(slot.getOffset()), 8)}, output)};
    }
  }

  private static final class RuntimeStub extends InjectPayloadCallfixup {
    // A bounded allocation in the official injection namespace, shared by
    // instances of this one snippet. Reject oversized bodies, never collide.
    static final long TEMPORARY_CAPACITY = 1 << 16;
    private final long temporaryBase;

    RuntimeStub(String source, long temporaryBase) {
      super(source);
      this.temporaryBase = temporaryBase;
    }

    @Override
    public boolean isFallThru() {
      return true;
    }

    @Override
    public PcodeOp[] getPcode(Program program, InjectContext context) throws NotFoundException {
      var function = program.getFunctionManager().getFunctionAt(context.callAddr);
      var body = function == null ? List.<Instruction>of()
          : DartRuntimeCalls.linearRuntimeBody(program, function);
      var caller = program.getFunctionManager().getFunctionContaining(context.baseAddr);
      if (caller == null
          || !DartRuntimeCalls.hasNativeOverride(program, caller, context.baseAddr)) {
        // A callfixup is attached to the callee, but preparation is per caller.
        // The official recursion guard cancels this fixup on the original CALL.
        return new PcodeOp[] {new PcodeOp(context.baseAddr, 0, PcodeOp.CALL,
            new Varnode[] {new Varnode(context.callAddr, 8)})};
      }
      if (body.isEmpty()) {
        throw new NotFoundException("Prepared RuntimeStub body changed; rerun ABI analysis");
      }
      var result = new ArrayList<PcodeOp>();
      long base = temporaryBase;
      for (var instruction : body.subList(0, body.size() - 1)) {
        var ranges = new AddressSet();
        for (var op : instruction.getPcode()) {
          var nodes = new ArrayList<>(Arrays.asList(op.getInputs()));
          if (op.getOutput() != null) {
            nodes.add(op.getOutput());
          }
          for (var node : nodes) {
            if (node.isUnique()) {
              ranges.add(node.getAddress(), node.getAddress().add(node.getSize() - 1));
            }
          }
        }
        var translations = new TreeMap<Long, Long>();
        for (var range : ranges) {
          translations.put(range.getMinAddress().getOffset(), base);
          base += (range.getLength() + 15) & ~15L;
        }
        if (base > temporaryBase + TEMPORARY_CAPACITY) {
          throw new NotFoundException("RuntimeStub exceeds its temporary allocation");
        }
        for (var op : instruction.getPcode()) {
          var inputs = op.getInputs().clone();
          for (int i = 0; i < inputs.length; i++) {
            inputs[i] = temporary(program, inputs[i], translations);
          }
          Varnode output = op.getOutput() == null ? null
              : temporary(program, op.getOutput(), translations);
          result.add(new PcodeOp(context.baseAddr, result.size(), op.getOpcode(), inputs, output));
        }
      }
      return result.toArray(PcodeOp[]::new);
    }

    private Varnode temporary(Program program, Varnode node,
        TreeMap<Long, Long> translations) {
      if (!node.isUnique()) {
        return node;
      }
      var mapping = translations.floorEntry(node.getOffset());
      return new Varnode(program.getAddressFactory().getUniqueSpace()
          .getAddress(mapping.getValue() + node.getOffset() - mapping.getKey()), node.getSize());
    }
  }
}
