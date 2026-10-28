/** Bounded instruction data flow for Dart runtime register roles. */
package ghidart;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SymbolType;

final class DartRuntimeCalls {
  private DartRuntimeCalls() {}

  static ghidra.program.model.symbol.Symbol overrideSymbol(Program program,
      Function function, Address address) {
    var space = HighFunction.findOverrideSpace(function);
    for (var symbol : program.getSymbolTable().getSymbols(address)) {
      if (space != null && symbol.getParentNamespace().equals(space)
          && symbol.getSymbolType() == SymbolType.LABEL
          && HighFunctionDBUtil.readOverride(symbol) != null) return symbol;
    }
    return null;
  }

  static FunctionSignature callSignature(Program program, Function function, Address address) {
    var symbol = overrideSymbol(program, function, address);
    var value = symbol == null ? null : HighFunctionDBUtil.readOverride(symbol);
    return value != null && value.getDataType() instanceof FunctionSignature signature
        ? signature : null;
  }

  /** Propagate a Thread load through official p-code within one bounded block. */
  static Long threadLoad(Program program, List<Instruction> block, String destination) {
    return baseLoad(program, block, destination, "x26");
  }

  static Long poolLoad(Program program, List<Instruction> block, String destination) {
    return baseLoad(program, block, destination, "x27");
  }

  private static Long baseLoad(Program program, List<Instruction> block,
      String destination, String baseRegister) {
    var values = new HashMap<Varnode, Value>();
    var loads = new HashMap<Varnode, Long>();
    var root = Value.atom(register(program, baseRegister));
    try {
      for (var instruction : block) {
        // Decoder unique temporaries are local to an instruction.
        values.keySet().removeIf(Varnode::isUnique);
        loads.keySet().removeIf(Varnode::isUnique);
        for (var op : instruction.getPcode()) {
          if (op.getOpcode() == PcodeOp.CALLOTHER) {
            return null;
          }
          var output = op.getOutput();
          if (output == null) {
            continue;
          }
          Value expression = evaluate(values, op);
          Long slot = null;
          if (op.getOpcode() == PcodeOp.COPY) {
            slot = loads.get(op.getInput(0));
          } else if (op.getOpcode() == PcodeOp.LOAD && output.getSize() == 8) {
            Value address = read(values, op.getInput(1));
            if (address != null && address.terms().equals(root.terms())) {
              slot = address.constant();
            }
          }
          for (var existing : List.copyOf(values.keySet())) {
            if (existing.getAddress().getAddressSpace().equals(output.getAddress().getAddressSpace())
                && existing.getOffset() < output.getOffset() + output.getSize()
                && output.getOffset() < existing.getOffset() + existing.getSize()) {
              values.put(existing, null);
              loads.remove(existing);
            }
          }
          values.put(output, expression);
          loads.put(output, slot);
        }
      }
      return loads.get(register(program, destination));
    } catch (ArithmeticException e) {
      return null;
    }
  }

  /** One basic-block prefix: never propagate through a call or a join. */
  static List<Instruction> blockBefore(Program program,
      ghidra.program.model.address.AddressSetView body, Instruction end) {
    var block = new ArrayList<Instruction>();
    block.add(end);
    var cursor = end;
    for (int i = 0; i < 32; i++) {
      var references = program.getReferenceManager().getReferencesTo(cursor.getAddress());
      boolean incoming = false;
      while (references.hasNext()) {
        incoming |= references.next().getReferenceType().isFlow();
      }
      if (incoming) break;
      var previous = cursor.getPrevious();
      if (previous == null || !body.contains(previous.getAddress())
          || !cursor.getAddress().equals(previous.getFallThrough())
          || previous.getFlowType().isCall() || previous.getFlowType().isJump()
          || previous.getFlowType().isTerminal()) break;
      block.addFirst(previous);
      cursor = previous;
    }
    return block;
  }

  private static Value evaluate(Map<Varnode, Value> values, PcodeOp op) {
    if (op.getNumInputs() == 0) {
      return null;
    }
    Value left = read(values, op.getInput(0));
    if (left == null) {
      return null;
    }
    return switch (op.getOpcode()) {
      case PcodeOp.COPY -> left;
      case PcodeOp.INT_ADD -> left.add(read(values, op.getInput(1)));
      case PcodeOp.INT_LEFT -> op.getInput(1).isConstant() && op.getInput(1).getOffset() < 63
          ? left.scale(1L << op.getInput(1).getOffset()) : null;
      default -> null;
    };
  }

  private static Value read(Map<Varnode, Value> values, Varnode node) {
    if (values.containsKey(node)) {
      return values.get(node);
    }
    if (node.isConstant()) {
      return Value.constant(node.getOffset());
    }
    if (!node.isRegister()) {
      return null;
    }
    for (Varnode written : values.keySet()) {
      if (written.getAddress().getAddressSpace().equals(node.getAddress().getAddressSpace())
          && written.getOffset() < node.getOffset() + node.getSize()
          && node.getOffset() < written.getOffset() + written.getSize()) {
        return null;
      }
    }
    return Value.atom(node);
  }

  private static Varnode register(Program program, String name) {
    var reg = program.getRegister(name);
    return new Varnode(reg.getAddress(), reg.getNumBytes());
  }

  // Only affine arithmetic needed by NativeArguments lowering. This is neither
  // an emulator nor a second instruction decoder: unsupported semantics reject.
  private record Value(Map<Varnode, Long> terms, long constant) {
    static Value atom(Varnode node) {
      return new Value(Map.of(node, 1L), 0);
    }

    static Value constant(long value) {
      return new Value(Map.of(), value);
    }

    Value add(Value other) {
      if (other == null) {
        return null;
      }
      var sum = new HashMap<>(terms);
      other.terms.forEach((node, coefficient) -> sum.merge(node, coefficient, Math::addExact));
      sum.values().removeIf(coefficient -> coefficient == 0);
      return new Value(Map.copyOf(sum), Math.addExact(constant, other.constant));
    }

    Value scale(long factor) {
      var product = new HashMap<Varnode, Long>();
      terms.forEach((node, coefficient) -> product.put(node, Math.multiplyExact(coefficient, factor)));
      return new Value(Map.copyOf(product), Math.multiplyExact(constant, factor));
    }
  }
}
