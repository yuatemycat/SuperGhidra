"""
smt_pcode_verifier.py
=====================
SuperGhidra SMT-Backed Decompilation Equivalence Verifier.

Frontier 2 of SuperGhidra Reformation:
- Translates P-Code basic blocks into symbolic Z3 bitvector expressions (BitVec 32/64)
  and byte-level memory arrays (Array('mem', BitVecSort(64), BitVecSort(8))).
- Translates core P-code opcodes:
    COPY, INT_ADD, INT_SUB, INT_AND, INT_OR, INT_XOR, INT_LEFT, INT_RIGHT,
    INT_SRIGHT, INT_MULT, INT_DIV, INT_SDIV, INT_REM, INT_SREM, INT_NEGATE,
    INT_2COMP, INT_ZEXT, INT_SEXT, INT_EQUAL, INT_NOTEQUAL, INT_LESS,
    INT_LESSEQUAL, INT_SLESS, INT_SLESSEQUAL, LOAD, STORE.
- Parses decompiled C-like statements and ASTs (arithmetic, bitwise, field dereferences,
  pointer arithmetic, assignments, and returns).
- Formulates formal equivalence queries in Z3:
    Not(symbolic_pcode_state == symbolic_c_state)
- Returns structured VerificationResult (UNSAT = proven equivalent, SAT = counterexample).
- Seamlessly integrates with ReconstructionObligationLedger (FUNCTION_HOOK and
  STRUCT_FIELD_RENAME obligations).
"""

from __future__ import annotations

import ast
import dataclasses
import enum
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import z3

# Import P-Code lifter and ledger models
try:
    from pcode_lifter_bridge import (
        ARM64PcodeLifter,
        AddressSpace,
        PcodeOp,
        PcodeOpcode,
        Varnode,
    )
    from evidence_ledger import (
        CheckResult,
        ObligationStatus,
        ObligationType,
        ProofObligation,
        ReconstructionObligationLedger,
    )
except ImportError:
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from pcode_lifter_bridge import (  # type: ignore
        ARM64PcodeLifter,
        AddressSpace,
        PcodeOp,
        PcodeOpcode,
        Varnode,
    )
    from evidence_ledger import (  # type: ignore
        CheckResult,
        ObligationStatus,
        ObligationType,
        ProofObligation,
        ReconstructionObligationLedger,
    )


# ==============================================================================
# Verification Result Data Model
# ==============================================================================

@dataclasses.dataclass
class VerificationResult:
    """Outcome of SMT formal equivalence verification."""
    obligation_id: Optional[str]
    equivalent: bool
    status: str  # "UNSAT" (proven equivalent), "SAT" (counterexample found), "UNKNOWN", "ERROR"
    details: str
    counterexample: Optional[Dict[str, Any]] = None
    model_inputs: Optional[Dict[str, Any]] = None
    pcode_out: Optional[str] = None
    c_out: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "equivalent": self.equivalent,
            "status": self.status,
            "details": self.details,
            "counterexample": self.counterexample,
            "model_inputs": self.model_inputs,
            "pcode_out": self.pcode_out,
            "c_out": self.c_out,
        }


# ==============================================================================
# Symbolic Memory & State
# ==============================================================================

def read_symbolic_memory(mem: z3.ArrayRef, addr: z3.BitVecRef, size: int) -> z3.BitVecRef:
    """Reads a little-endian bitvector of `size` bytes from symbolic byte array."""
    if addr.size() != 64:
        addr = z3.ZeroExt(64 - addr.size(), addr) if addr.size() < 64 else z3.Extract(63, 0, addr)

    if size == 1:
        return mem[addr]
    elif size == 2:
        return z3.Concat(mem[addr + 1], mem[addr])
    elif size == 4:
        return z3.Concat(mem[addr + 3], mem[addr + 2], mem[addr + 1], mem[addr])
    elif size == 8:
        return z3.Concat(
            mem[addr + 7], mem[addr + 6], mem[addr + 5], mem[addr + 4],
            mem[addr + 3], mem[addr + 2], mem[addr + 1], mem[addr]
        )
    else:
        # Generic variable size reader
        chunks = [mem[addr + i] for i in reversed(range(size))]
        res = chunks[0]
        for c in chunks[1:]:
            res = z3.Concat(res, c)
        return res


def write_symbolic_memory(mem: z3.ArrayRef, addr: z3.BitVecRef, val: z3.BitVecRef, size: int) -> z3.ArrayRef:
    """Writes a little-endian bitvector of `size` bytes into symbolic byte array."""
    if addr.size() != 64:
        addr = z3.ZeroExt(64 - addr.size(), addr) if addr.size() < 64 else z3.Extract(63, 0, addr)

    target_bits = size * 8
    if val.size() < target_bits:
        val = z3.ZeroExt(target_bits - val.size(), val)
    elif val.size() > target_bits:
        val = z3.Extract(target_bits - 1, 0, val)

    for i in range(size):
        byte_i = z3.Extract((i + 1) * 8 - 1, i * 8, val)
        mem = z3.Store(mem, addr + i, byte_i)
    return mem


class SymbolicState:
    """
    Tracks registers, unique scratchpad Varnodes, named variables, and byte-addressed RAM.
    """

    def __init__(self, name_prefix: str = "", initial_mem: Optional[z3.ArrayRef] = None):
        self.prefix = name_prefix
        # Register mapping: offset (e.g. reg_idx * 8) -> 64-bit BitVecRef
        self.regs: Dict[int, z3.BitVecRef] = {}
        # Unique scratchpad mapping: offset -> BitVecRef
        self.uniques: Dict[int, z3.BitVecRef] = {}
        # Named C variables: name -> BitVecRef
        self.vars: Dict[str, z3.BitVecRef] = {}
        # Byte memory array: Array('mem', BitVecSort(64), BitVecSort(8))
        self.mem = (
            initial_mem
            if initial_mem is not None
            else z3.Array(f"{name_prefix}mem", z3.BitVecSort(64), z3.BitVecSort(8))
        )
        # Parameter bindings: {"player": "x0", "damage": "w2"}
        self.param_map: Dict[str, str] = {}
        # Return value expression
        self.return_val: Optional[z3.BitVecRef] = None

    def clone(self, new_prefix: Optional[str] = None) -> SymbolicState:
        """Creates a copy of the symbolic state sharing base memory and registers."""
        st = SymbolicState(new_prefix or self.prefix, initial_mem=self.mem)
        st.regs = dict(self.regs)
        st.uniques = dict(self.uniques)
        st.vars = dict(self.vars)
        st.param_map = dict(self.param_map)
        st.return_val = self.return_val
        return st

    def get_register(self, reg_offset: int, size: int = 8) -> z3.BitVecRef:
        """Gets or lazily creates a symbolic register."""
        if reg_offset not in self.regs:
            reg_idx = reg_offset // 8
            reg_name = f"{self.prefix}x{reg_idx}" if self.prefix else f"x{reg_idx}"
            self.regs[reg_offset] = z3.BitVec(reg_name, 64)

        val64 = self.regs[reg_offset]
        if size == 8:
            return val64
        elif size < 8:
            return z3.Extract(size * 8 - 1, 0, val64)
        else:
            return z3.ZeroExt((size - 8) * 8, val64)

    def set_register(self, reg_offset: int, val: z3.BitVecRef, size: int = 8) -> None:
        """Sets a register, with 32-bit writes automatically zero-extended to 64-bit."""
        if val.size() < size * 8:
            val = z3.ZeroExt(size * 8 - val.size(), val)
        elif val.size() > size * 8:
            val = z3.Extract(size * 8 - 1, 0, val)

        if size == 8:
            self.regs[reg_offset] = val
        elif size == 4:
            # In 64-bit architectures (ARM64/x86_64), 32-bit register write clears upper 32 bits
            self.regs[reg_offset] = z3.ZeroExt(32, val)
        else:
            # Partial byte/half-word update
            curr = self.get_register(reg_offset, 8)
            upper = z3.Extract(63, size * 8, curr)
            self.regs[reg_offset] = z3.Concat(upper, val)

    def get_varnode_value(self, vn: Varnode) -> z3.BitVecRef:
        """Retrieves symbolic expression for a Varnode."""
        if vn.space == AddressSpace.CONST:
            return z3.BitVecVal(vn.offset, vn.size * 8)
        elif vn.space == AddressSpace.REGISTER:
            return self.get_register(vn.offset, vn.size)
        elif vn.space == AddressSpace.UNIQUE:
            if vn.offset not in self.uniques:
                name = f"{self.prefix}u_{vn.offset:x}" if self.prefix else f"u_{vn.offset:x}"
                self.uniques[vn.offset] = z3.BitVec(name, vn.size * 8)
            val = self.uniques[vn.offset]
            if val.size() != vn.size * 8:
                if val.size() < vn.size * 8:
                    val = z3.ZeroExt(vn.size * 8 - val.size(), val)
                else:
                    val = z3.Extract(vn.size * 8 - 1, 0, val)
            return val
        elif vn.space == AddressSpace.RAM:
            addr = z3.BitVecVal(vn.offset, 64)
            return read_symbolic_memory(self.mem, addr, vn.size)
        else:
            name = f"{self.prefix}unk_{vn.space.value}_{vn.offset:x}"
            return z3.BitVec(name, vn.size * 8)

    def set_varnode_value(self, vn: Varnode, val: z3.BitVecRef) -> None:
        """Assigns symbolic expression to a Varnode."""
        target_bits = vn.size * 8
        if val.size() < target_bits:
            val = z3.ZeroExt(target_bits - val.size(), val)
        elif val.size() > target_bits:
            val = z3.Extract(target_bits - 1, 0, val)

        if vn.space == AddressSpace.REGISTER:
            self.set_register(vn.offset, val, vn.size)
        elif vn.space == AddressSpace.UNIQUE:
            self.uniques[vn.offset] = val
        elif vn.space == AddressSpace.RAM:
            addr = z3.BitVecVal(vn.offset, 64)
            self.mem = write_symbolic_memory(self.mem, addr, val, vn.size)


# ==============================================================================
# P-Code Symbolic Simulator
# ==============================================================================

class PcodeSymbolicSimulator:
    """Executes P-Code IR operations symbolically using Z3 bitvectors and arrays."""

    @staticmethod
    def _match_widths(a: z3.BitVecRef, b: z3.BitVecRef) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        """Ensures two bitvectors have equal bit width by zero-extending the narrower."""
        if a.size() == b.size():
            return a, b
        elif a.size() < b.size():
            return z3.ZeroExt(b.size() - a.size(), a), b
        else:
            return a, z3.ZeroExt(a.size() - b.size(), b)

    def step(self, state: SymbolicState, op: PcodeOp) -> None:
        """Executes a single PcodeOp against symbolic state."""
        opcode = op.opcode
        inputs = op.inputs
        output = op.output

        # 1. Unary & Data Movement
        if opcode == PcodeOpcode.COPY:
            if output:
                val = state.get_varnode_value(inputs[0])
                state.set_varnode_value(output, val)

        elif opcode == PcodeOpcode.RETURN:
            if inputs:
                state.return_val = state.get_varnode_value(inputs[0])
            else:
                state.return_val = state.get_register(0, 8)  # default x0 / rax

        # 2. Arithmetic Operations
        elif opcode == PcodeOpcode.INT_ADD:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 + v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SUB:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 - v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_MULT:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 * v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_DIV:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = z3.UDiv(v0, v1)
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SDIV:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 / v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_REM:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = z3.URem(v0, v1)
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SREM:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = z3.SRem(v0, v1)
            if output:
                state.set_varnode_value(output, res)

        # 3. Bitwise & Logic Operations
        elif opcode == PcodeOpcode.INT_AND:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 & v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_OR:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 | v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_XOR:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 ^ v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_LEFT:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 << v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_RIGHT:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = z3.LShR(v0, v1)
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SRIGHT:
            v0 = state.get_varnode_value(inputs[0])
            v1 = state.get_varnode_value(inputs[1])
            v0, v1 = self._match_widths(v0, v1)
            res = v0 >> v1
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_NEGATE:
            v0 = state.get_varnode_value(inputs[0])
            res = ~v0
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_2COMP:
            v0 = state.get_varnode_value(inputs[0])
            res = -v0
            if output:
                state.set_varnode_value(output, res)

        # 4. Extension Operations
        elif opcode == PcodeOpcode.INT_ZEXT:
            v0 = state.get_varnode_value(inputs[0])
            if output:
                out_bits = output.size * 8
                res = z3.ZeroExt(out_bits - v0.size(), v0) if out_bits > v0.size() else v0
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SEXT:
            v0 = state.get_varnode_value(inputs[0])
            if output:
                out_bits = output.size * 8
                res = z3.SignExt(out_bits - v0.size(), v0) if out_bits > v0.size() else v0
                state.set_varnode_value(output, res)

        # 5. Comparisons
        elif opcode == PcodeOpcode.INT_EQUAL:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(v0 == v1, z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_NOTEQUAL:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(v0 != v1, z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_LESS:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(z3.ULT(v0, v1), z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_LESSEQUAL:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(z3.ULE(v0, v1), z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SLESS:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(v0 < v1, z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        elif opcode == PcodeOpcode.INT_SLESSEQUAL:
            v0, v1 = self._match_widths(state.get_varnode_value(inputs[0]), state.get_varnode_value(inputs[1]))
            out_sz = output.size * 8 if output else 8
            res = z3.If(v0 <= v1, z3.BitVecVal(1, out_sz), z3.BitVecVal(0, out_sz))
            if output:
                state.set_varnode_value(output, res)

        # 6. Memory Load & Store
        elif opcode == PcodeOpcode.LOAD:
            addr_val = state.get_varnode_value(inputs[1])
            if output:
                val = read_symbolic_memory(state.mem, addr_val, output.size)
                state.set_varnode_value(output, val)

        elif opcode == PcodeOpcode.STORE:
            addr_val = state.get_varnode_value(inputs[1])
            data_val = state.get_varnode_value(inputs[2])
            state.mem = write_symbolic_memory(state.mem, addr_val, data_val, inputs[2].size)

    def execute_block(self, state: SymbolicState, ops: List[PcodeOp]) -> None:
        """Executes a linear sequence of PcodeOps on state."""
        for op in ops:
            self.step(state, op)


# ==============================================================================
# Decompiled C Expression & AST Parser
# ==============================================================================

class CASTNode:
    """Base class for parsed C AST nodes."""
    pass


@dataclasses.dataclass
class CVar(CASTNode):
    name: str
    size: int = 8


@dataclasses.dataclass
class CConst(CASTNode):
    val: int
    size: int = 8


@dataclasses.dataclass
class CBinary(CASTNode):
    op: str  # '+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '==', '!=', '<', '<=', '>', '>='
    left: CASTNode
    right: CASTNode


@dataclasses.dataclass
class CUnary(CASTNode):
    op: str  # '~', '-', '!'
    operand: CASTNode


@dataclasses.dataclass
class CDeref(CASTNode):
    ptr_expr: CASTNode
    size: int = 4  # bytes


@dataclasses.dataclass
class CFieldAccess(CASTNode):
    base_expr: CASTNode
    field_name: str
    offset: Optional[int] = None
    size: int = 4


@dataclasses.dataclass
class CAssignment(CASTNode):
    target: CASTNode  # CVar, CDeref, or CFieldAccess
    value: CASTNode


@dataclasses.dataclass
class CReturn(CASTNode):
    value: CASTNode


@dataclasses.dataclass
class CBlock(CASTNode):
    statements: List[CASTNode] = dataclasses.field(default_factory=list)


class CCodeParser:
    """
    Parses decompiled C function bodies, statements, or expressions into symbolic AST nodes.
    Supports pointer arithmetic (`*(int*)(p + 0x24)`), field dereferences (`p->m_health`),
    and standard C operators.
    """

    def __init__(self, struct_schemas: Optional[Dict[str, Dict[str, Tuple[int, int]]]] = None):
        self.struct_schemas = struct_schemas or {}
        self.flat_fields: Dict[str, Tuple[int, int]] = {}
        for st_name, fields in self.struct_schemas.items():
            for f_name, f_info in fields.items():
                self.flat_fields[f_name] = f_info

    def register_field(self, field_name: str, offset: int, size: int = 4) -> None:
        """Registers a struct field offset and access size."""
        self.flat_fields[field_name] = (offset, size)

    def parse(self, text: str) -> CBlock:
        """Parses a multi-statement C code block."""
        statements: List[CASTNode] = []
        # Strip comments
        clean_text = re.sub(r"//.*", "", text)
        clean_text = re.sub(r"/\*.*?\*/", "", clean_text, flags=re.DOTALL)

        # Split into statements by semicolon
        raw_stmts = [s.strip() for s in clean_text.split(";") if s.strip()]

        for s in raw_stmts:
            if s.startswith("return"):
                expr_str = s[len("return"):].strip()
                statements.append(CReturn(self._parse_expr(expr_str)))
            elif "=" in s:
                parts = s.split("=", 1)
                lhs_str = parts[0].strip()
                rhs_str = parts[1].strip()
                # Remove type declarators if present (e.g. `int x = ...`, `uint32_t v = ...`)
                lhs_tokens = lhs_str.split()
                if len(lhs_tokens) > 1 and not lhs_str.startswith("*") and "->" not in lhs_str and "." not in lhs_str:
                    lhs_str = lhs_tokens[-1]
                lhs_node = self._parse_target(lhs_str)
                rhs_node = self._parse_expr(rhs_str)
                statements.append(CAssignment(target=lhs_node, value=rhs_node))
            else:
                statements.append(self._parse_expr(s))

        return CBlock(statements=statements)

    def _parse_target(self, target_str: str) -> CASTNode:
        """Parses assignment target (variable, dereference, or field access)."""
        node = self._parse_expr(target_str)
        if isinstance(node, (CVar, CDeref, CFieldAccess)):
            return node
        return CVar(name=target_str)

    def _normalize_c_syntax(self, s: str) -> str:
        """Normalizes C syntax (-> to ., *(cast*)(ptr) to __derefN(ptr)) for python AST parsing."""
        # 1. Normalize arrow operator -> to dot .
        s = s.replace("->", ".")

        # 2. Normalize *(type*)(expr) casts
        s = re.sub(r"\*\s*\(\s*(?:uint64_t|int64_t|uint64|int64|long\s+long|size_t)\s*\*\s*\)\s*\(([^)]+)\)", r"__deref8(\1)", s)
        s = re.sub(r"\*\s*\(\s*(?:uint32_t|int32_t|uint32|int32|int|unsigned\s+int)\s*\*\s*\)\s*\(([^)]+)\)", r"__deref4(\1)", s)
        s = re.sub(r"\*\s*\(\s*(?:uint16_t|int16_t|uint16|int16|short|unsigned\s+short)\s*\*\s*\)\s*\(([^)]+)\)", r"__deref2(\1)", s)
        s = re.sub(r"\*\s*\(\s*(?:uint8_t|int8_t|uint8|int8|char|unsigned\s+char)\s*\*\s*\)\s*\(([^)]+)\)", r"__deref1(\1)", s)

        # 3. Simple *(expr)
        s = re.sub(r"\*\s*\(([^)]+)\)", r"__deref4(\1)", s)
        return s

    def _parse_expr(self, expr_str: str) -> CASTNode:
        """Parses an algebraic/pointer expression into AST."""
        expr_str = expr_str.strip()
        norm_str = self._normalize_c_syntax(expr_str)

        try:
            tree = ast.parse(norm_str, mode="eval")
            return self._from_ast(tree.body)
        except Exception:
            # Fallback identifier or integer literal
            if expr_str.startswith("0x") or expr_str.startswith("0X"):
                return CConst(int(expr_str, 16))
            elif expr_str.isdigit():
                return CConst(int(expr_str))
            return CVar(name=expr_str)

    def _from_ast(self, node: ast.AST) -> CASTNode:
        """Transforms Python AST expression node to CASTNode."""
        if isinstance(node, ast.Constant):
            return CConst(val=int(node.value))
        elif isinstance(node, ast.Name):
            return CVar(name=node.id)
        elif isinstance(node, ast.Attribute):
            base = self._from_ast(node.value)
            f_name = node.attr
            offset, size = self.flat_fields.get(f_name, (None, 4))
            return CFieldAccess(base_expr=base, field_name=f_name, offset=offset, size=size)
        elif isinstance(node, ast.Call):
            # Function call or synthetic __derefN
            fn_name = node.func.id if isinstance(node.func, ast.Name) else ""
            if fn_name.startswith("__deref") and node.args:
                sz = 4
                if fn_name == "__deref8":
                    sz = 8
                elif fn_name == "__deref2":
                    sz = 2
                elif fn_name == "__deref1":
                    sz = 1
                inner_ptr = self._from_ast(node.args[0])
                return CDeref(ptr_expr=inner_ptr, size=sz)
            return CVar(name=ast.unparse(node))
        elif isinstance(node, ast.BinOp):
            op_map = {
                ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.FloorDiv: "/",
                ast.Div: "/", ast.Mod: "%", ast.BitAnd: "&", ast.BitOr: "|",
                ast.BitXor: "^", ast.LShift: "<<", ast.RShift: ">>"
            }
            op_str = op_map.get(type(node.op), "+")
            return CBinary(op=op_str, left=self._from_ast(node.left), right=self._from_ast(node.right))
        elif isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
            cmp_map = {
                ast.Eq: "==", ast.NotEq: "!=", ast.Lt: "<", ast.LtE: "<=",
                ast.Gt: ">", ast.GtE: ">="
            }
            op_str = cmp_map.get(type(node.ops[0]), "==")
            return CBinary(op=op_str, left=self._from_ast(node.left), right=self._from_ast(node.comparators[0]))
        elif isinstance(node, ast.UnaryOp):
            op_map = {ast.Invert: "~", ast.USub: "-", ast.Not: "!"}
            op_str = op_map.get(type(node.op), "~")
            return CUnary(op=op_str, operand=self._from_ast(node.operand))
        return CVar(name=ast.unparse(node))


# ==============================================================================
# C Symbolic Evaluator
# ==============================================================================

class CSymbolicEvaluator:
    """Evaluates CASTNodes symbolically against SymbolicState."""

    @staticmethod
    def _match_widths(a: z3.BitVecRef, b: z3.BitVecRef) -> Tuple[z3.BitVecRef, z3.BitVecRef]:
        if a.size() == b.size():
            return a, b
        elif a.size() < b.size():
            return z3.ZeroExt(b.size() - a.size(), a), b
        else:
            return a, z3.ZeroExt(a.size() - b.size(), b)

    def _resolve_var_target(self, state: SymbolicState, name: str) -> Optional[Tuple[int, int]]:
        """Resolves variable name to (reg_offset, size) if it is a register or mapped param."""
        # 1. Direct param_map lookup
        if name in state.param_map:
            name = state.param_map[name]

        # 2. Register name regex: x0..x30, w0..w30, r0..r15
        arm_m = re.match(r"^([xw])(\d+)$", name.lower())
        if arm_m:
            kind, idx_str = arm_m.group(1), arm_m.group(2)
            reg_idx = int(idx_str)
            size = 8 if kind == "x" else 4
            return (reg_idx * 8, size)
        return None

    def eval_expr(self, state: SymbolicState, node: CASTNode) -> z3.BitVecRef:
        """Evaluates an expression node to a Z3 bitvector."""
        if isinstance(node, CConst):
            return z3.BitVecVal(node.val, node.size * 8)

        elif isinstance(node, CVar):
            name = node.name
            reg_info = self._resolve_var_target(state, name)
            if reg_info is not None:
                reg_off, sz = reg_info
                return state.get_register(reg_off, sz)

            if name not in state.vars:
                prefix_name = f"{state.prefix}{name}" if state.prefix else name
                state.vars[name] = z3.BitVec(prefix_name, node.size * 8)
            return state.vars[name]

        elif isinstance(node, CBinary):
            l = self.eval_expr(state, node.left)
            r = self.eval_expr(state, node.right)
            l, r = self._match_widths(l, r)
            op = node.op
            if op == "+":
                return l + r
            elif op == "-":
                return l - r
            elif op == "*":
                return l * r
            elif op == "/":
                return l / r
            elif op == "%":
                return z3.SRem(l, r)
            elif op == "&":
                return l & r
            elif op == "|":
                return l | r
            elif op == "^":
                return l ^ r
            elif op == "<<":
                return l << r
            elif op == ">>":
                return l >> r
            elif op == "==":
                return z3.If(l == r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == "!=":
                return z3.If(l != r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == "<":
                return z3.If(l < r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == "<=":
                return z3.If(l <= r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == ">":
                return z3.If(l > r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            elif op == ">=":
                return z3.If(l >= r, z3.BitVecVal(1, l.size()), z3.BitVecVal(0, l.size()))
            return l + r

        elif isinstance(node, CUnary):
            val = self.eval_expr(state, node.operand)
            if node.op == "~":
                return ~val
            elif node.op == "-":
                return -val
            elif node.op == "!":
                return z3.If(val == 0, z3.BitVecVal(1, val.size()), z3.BitVecVal(0, val.size()))
            return val

        elif isinstance(node, CDeref):
            ptr_val = self.eval_expr(state, node.ptr_expr)
            return read_symbolic_memory(state.mem, ptr_val, node.size)

        elif isinstance(node, CFieldAccess):
            base_ptr = self.eval_expr(state, node.base_expr)
            offset = node.offset if node.offset is not None else 0
            if base_ptr.size() != 64:
                base_ptr = z3.ZeroExt(64 - base_ptr.size(), base_ptr)
            addr = base_ptr + z3.BitVecVal(offset, 64)
            return read_symbolic_memory(state.mem, addr, node.size)

        prefix_unk = f"{state.prefix}unk" if state.prefix else "unk"
        return z3.BitVec(prefix_unk, 64)

    def execute_statement(self, state: SymbolicState, stmt: CASTNode) -> None:
        """Executes an assignment or return statement on state."""
        if isinstance(stmt, CAssignment):
            val = self.eval_expr(state, stmt.value)
            tgt = stmt.target
            if isinstance(tgt, CVar):
                reg_info = self._resolve_var_target(state, tgt.name)
                if reg_info is not None:
                    reg_off, sz = reg_info
                    state.set_register(reg_off, val, sz)
                else:
                    state.vars[tgt.name] = val

            elif isinstance(tgt, CDeref):
                ptr_val = self.eval_expr(state, tgt.ptr_expr)
                state.mem = write_symbolic_memory(state.mem, ptr_val, val, tgt.size)

            elif isinstance(tgt, CFieldAccess):
                base_ptr = self.eval_expr(state, tgt.base_expr)
                offset = tgt.offset if tgt.offset is not None else 0
                if base_ptr.size() != 64:
                    base_ptr = z3.ZeroExt(64 - base_ptr.size(), base_ptr)
                addr = base_ptr + z3.BitVecVal(offset, 64)
                state.mem = write_symbolic_memory(state.mem, addr, val, tgt.size)

        elif isinstance(stmt, CReturn):
            state.return_val = self.eval_expr(state, stmt.value)

    def execute_block(self, state: SymbolicState, block: CBlock) -> None:
        """Executes a list of C statements."""
        for stmt in block.statements:
            self.execute_statement(state, stmt)


# ==============================================================================
# SMT P-Code Equivalence Verifier Engine
# ==============================================================================

class SMTPcodeVerifier:
    """
    Formal SMT Verifier for P-Code vs Decompiled C Equivalence.
    Queries Z3 for counterexamples: Not(symbolic_pcode == symbolic_c).
    UNSAT = Formally Proven Equivalent.
    SAT = Divergent (Counterexample extracted with model inputs).
    """

    def __init__(self, timeout_ms: int = 10000):
        self.timeout_ms = timeout_ms
        self.pcode_sim = PcodeSymbolicSimulator()
        self.c_eval = CSymbolicEvaluator()
        self.lifter = ARM64PcodeLifter()

    def verify_equivalence(
        self,
        pcode_ops: List[PcodeOp],
        c_code_or_ast: Union[str, CASTNode],
        struct_fields: Optional[Dict[str, Tuple[int, int]]] = None,
        param_map: Optional[Dict[str, str]] = None,
        obligation_id: Optional[str] = None,
        check_memory: bool = True,
        tracked_registers: Optional[List[int]] = None,
    ) -> VerificationResult:
        """
        Formally verifies equivalence between a sequence of P-Code ops and a decompiled C snippet.

        Args:
            pcode_ops: Sequence of PcodeOps to verify.
            c_code_or_ast: Decompiled C snippet string or CASTNode.
            struct_fields: Struct field offset mappings for C field resolution: {"m_health": (0x24, 4)}.
            param_map: Variable-to-register parameter mapping: {"player": "x0", "damage": "w2"}.
            obligation_id: Optional obligation ID being verified.
            check_memory: Whether to verify memory state equivalence.
            tracked_registers: Specific register offsets (e.g. [0 for x0]) to verify.
        """
        if tracked_registers is None:
            # Default to return register x0 (offset 0)
            tracked_registers = [0]

        # 1. Parse C code into AST
        parser = CCodeParser()
        if struct_fields:
            for fn, (foff, fsz) in struct_fields.items():
                parser.register_field(fn, foff, fsz)

        if isinstance(c_code_or_ast, str):
            c_ast = parser.parse(c_code_or_ast)
        elif isinstance(c_code_or_ast, CBlock):
            c_ast = c_code_or_ast
        else:
            c_ast = CBlock(statements=[c_code_or_ast])

        # 2. Initialize Shared Base Symbolic State
        base_state = SymbolicState(name_prefix="")
        # Pre-populate common ARM64 parameter registers x0..x7
        for i in range(8):
            base_state.get_register(i * 8, 8)

        # Apply parameter mappings
        if param_map:
            base_state.param_map = dict(param_map)

        # 3. Simulate P-Code on state clone
        pcode_state = base_state.clone()
        self.pcode_sim.execute_block(pcode_state, pcode_ops)

        # 4. Simulate C code on state clone
        c_state = base_state.clone()
        self.c_eval.execute_block(c_state, c_ast)

        # 5. Formulate Equivalence Conditions
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)

        equiv_conditions: List[z3.BoolRef] = []

        # Check return value / tracked registers
        for reg_off in tracked_registers:
            p_val = pcode_state.get_register(reg_off, 8)
            # If C explicitly returned a value and reg_off is 0, compare with C return_val
            if reg_off == 0 and c_state.return_val is not None:
                c_val = c_state.return_val
                if c_val.size() != 64:
                    c_val = z3.ZeroExt(64 - c_val.size(), c_val) if c_val.size() < 64 else z3.Extract(63, 0, c_val)
            else:
                c_val = c_state.get_register(reg_off, 8)
            equiv_conditions.append(p_val == c_val)

        # Check memory equality if requested
        if check_memory:
            equiv_conditions.append(pcode_state.mem == c_state.mem)

        # Formulate query: Not(And(equiv_conditions))
        query = z3.Not(z3.And(*equiv_conditions))
        solver.add(query)

        # 6. Solve with Z3
        check_res = solver.check()
        c_val_out = c_state.return_val if c_state.return_val is not None else c_state.get_register(0, 8)

        if check_res == z3.unsat:
            return VerificationResult(
                obligation_id=obligation_id,
                equivalent=True,
                status="UNSAT",
                details="Formally proven equivalent: no input exists where native P-code diverges from decompiled C.",
                pcode_out=str(pcode_state.get_register(0, 8)),
                c_out=str(c_val_out),
            )

        elif check_res == z3.sat:
            model = solver.model()
            cex: Dict[str, Any] = {}
            for d in model.decls():
                cex[d.name()] = str(model[d])

            return VerificationResult(
                obligation_id=obligation_id,
                equivalent=False,
                status="SAT",
                details="SMT Divergence Detected: Found counterexample inputs producing non-equivalent outputs.",
                counterexample=cex,
                model_inputs=cex,
                pcode_out=str(pcode_state.get_register(0, 8)),
                c_out=str(c_val_out),
            )

        else:
            reason = solver.reason_unknown()
            return VerificationResult(
                obligation_id=obligation_id,
                equivalent=False,
                status="UNKNOWN",
                details=f"SMT Solver returned UNKNOWN (timeout or non-linear constraint: {reason})",
            )

    def verify_obligation(self, obligation: ProofObligation) -> VerificationResult:
        """
        Formally verifies an EvidenceLedger obligation.
        Supports FUNCTION_HOOK and STRUCT_FIELD_RENAME obligations.
        """
        obl_id = obligation.obligation_id
        obl_type = obligation.obligation_type
        evidence = obligation.evidence

        # 1. FUNCTION_HOOK Equivalence Verification
        if obl_type in (ObligationType.FUNCTION_HOOK, ObligationType.FUNCTION_RENAME):
            decompiled_c = evidence.get("decompiled_c") or evidence.get("c_code")
            machine_bytes = evidence.get("machine_bytes")
            pcode_ops = evidence.get("pcode_ops")
            struct_fields = evidence.get("struct_fields", {})
            param_map = evidence.get("param_map", {})

            if not decompiled_c:
                return VerificationResult(
                    obligation_id=obl_id,
                    equivalent=False,
                    status="ERROR",
                    details="Missing decompiled_c in obligation evidence.",
                )

            # Lift machine bytes to P-code if raw bytes provided
            if pcode_ops is None and machine_bytes is not None:
                if isinstance(machine_bytes, str):
                    machine_bytes = bytes.fromhex(machine_bytes.replace(" ", "").replace("0x", ""))
                base_pc = obligation.target_address or 0x1000
                pcode_ops = self.lifter.lift_block(base_pc, machine_bytes)

            if not pcode_ops:
                return VerificationResult(
                    obligation_id=obl_id,
                    equivalent=False,
                    status="ERROR",
                    details="Missing machine_bytes or pcode_ops in obligation evidence.",
                )

            # Ensure pcode_ops contains PcodeOp instances even if deserialized from JSON
            deserialized_ops: List[PcodeOp] = []
            for item in pcode_ops:
                if isinstance(item, PcodeOp):
                    deserialized_ops.append(item)
                elif isinstance(item, dict):
                    op_name = item.get("opcode", "COPY")
                    opcode = PcodeOpcode[op_name] if isinstance(op_name, str) else PcodeOpcode(op_name)
                    inputs = []
                    for v in item.get("inputs", []):
                        if isinstance(v, Varnode):
                            inputs.append(v)
                        else:
                            sp_val = v.get("space", "ram")
                            space = AddressSpace(sp_val) if isinstance(sp_val, str) else sp_val
                            off = v.get("offset", 0)
                            if isinstance(off, str) and off.startswith("0x"):
                                off = int(off, 16)
                            inputs.append(Varnode(space=space, offset=int(off), size=int(v.get("size", 8))))
                    out = None
                    if item.get("output"):
                        o_val = item["output"]
                        if isinstance(o_val, Varnode):
                            out = o_val
                        else:
                            sp_val = o_val.get("space", "ram")
                            space = AddressSpace(sp_val) if isinstance(sp_val, str) else sp_val
                            off = o_val.get("offset", 0)
                            if isinstance(off, str) and off.startswith("0x"):
                                off = int(off, 16)
                            out = Varnode(space=space, offset=int(off), size=int(o_val.get("size", 8)))
                    pc_val = item.get("pc", 0)
                    if isinstance(pc_val, str) and pc_val.startswith("0x"):
                        pc_val = int(pc_val, 16)
                    deserialized_ops.append(PcodeOp(opcode=opcode, inputs=inputs, output=out, pc=int(pc_val)))
            pcode_ops = deserialized_ops

            # Extract struct field displacements from evidence if present
            if not struct_fields and "field_displacements" in evidence:
                struct_fields = {
                    f["name"]: (f["offset"], f.get("access_size", 4))
                    for f in evidence["field_displacements"]
                    if "name" in f and "offset" in f
                }

            # If param_map not provided, check param_names in evidence
            if not param_map and "param_names" in evidence:
                p_names = evidence["param_names"]
                # Default calling convention: param 0 -> x0, param 1 -> w1 or w2, etc.
                param_map = {name: f"x{i}" for i, name in enumerate(p_names)}

            res = self.verify_equivalence(
                pcode_ops=pcode_ops,
                c_code_or_ast=decompiled_c,
                struct_fields=struct_fields,
                param_map=param_map,
                obligation_id=obl_id,
            )

            # Update obligation status and record check result
            chk = CheckResult(
                check_name="SMTPcodeEquivalenceCheck",
                passed=res.equivalent,
                message=res.details,
                details=res.to_dict(),
            )
            obligation.verification_results.append(chk.to_dict())
            if res.equivalent:
                obligation.status = ObligationStatus.VERIFIED
            else:
                obligation.status = ObligationStatus.REJECTED

            return res

        # 2. STRUCT_FIELD_RENAME Equivalence Verification
        elif obl_type in (ObligationType.STRUCT_FIELD_RENAME, ObligationType.STRUCT_DEFINITION):
            field_name = obligation.proposed_name
            offset = evidence.get("offset")
            access_size = evidence.get("access_size", 4)
            c_expr = evidence.get("c_expression") or f"player->{field_name}"

            if offset is None and "field_displacements" in evidence:
                for f in evidence["field_displacements"]:
                    if f.get("name") == field_name:
                        offset = f.get("offset")
                        access_size = f.get("access_size", 4)
                        break

            if offset is None:
                res = VerificationResult(
                    obligation_id=obl_id,
                    equivalent=False,
                    status="ERROR",
                    details=f"Missing displacement offset for struct field '{field_name}'",
                )
                return res

            # Construct synthetic P-Code load: [x0, #offset] -> w1
            pcode_ops = [
                PcodeOp(
                    opcode=PcodeOpcode.INT_ADD,
                    inputs=[
                        Varnode(AddressSpace.REGISTER, 0, 8),
                        Varnode(AddressSpace.CONST, offset, 8),
                    ],
                    output=Varnode(AddressSpace.UNIQUE, 0, 8),
                ),
                PcodeOp(
                    opcode=PcodeOpcode.LOAD,
                    inputs=[
                        Varnode(AddressSpace.RAM, 0, access_size),
                        Varnode(AddressSpace.UNIQUE, 0, 8),
                    ],
                    output=Varnode(AddressSpace.REGISTER, 8, access_size),  # x1 / w1
                ),
            ]

            struct_fields = {field_name: (offset, access_size)}
            param_map = {"player": "x0"}
            c_stmt = f"w1 = {c_expr};"

            res = self.verify_equivalence(
                pcode_ops=pcode_ops,
                c_code_or_ast=c_stmt,
                struct_fields=struct_fields,
                param_map=param_map,
                obligation_id=obl_id,
                tracked_registers=[8],  # register x1
                check_memory=False,
            )

            chk = CheckResult(
                check_name="SMTStructFieldEquivalenceCheck",
                passed=res.equivalent,
                message=res.details,
                details=res.to_dict(),
            )
            obligation.verification_results.append(chk.to_dict())
            if res.equivalent:
                obligation.status = ObligationStatus.VERIFIED
            else:
                obligation.status = ObligationStatus.REJECTED

            return res

        else:
            return VerificationResult(
                obligation_id=obl_id,
                equivalent=True,
                status="UNSAT",
                details=f"Obligation type '{obl_type}' does not require SMT decompilation equivalence check.",
            )

    def verify_ledger(
        self,
        ledger: ReconstructionObligationLedger,
        status_filter: Optional[Set[ObligationStatus]] = None,
    ) -> Dict[str, VerificationResult]:
        """Verifies all pending obligations in ledger with SMT evidence."""
        if status_filter is None:
            status_filter = {ObligationStatus.PENDING}

        results: Dict[str, VerificationResult] = {}
        for obl in ledger.list_obligations():
            if obl.status in status_filter:
                res = self.verify_obligation(obl)
                results[obl.obligation_id] = res

        ledger.save()
        return results


# ==============================================================================
# Standalone CLI / Demo
# ==============================================================================

if __name__ == "__main__":
    print("=== SuperGhidra SMT P-Code Equivalence Verifier ===")
    verifier = SMTPcodeVerifier()

    # Demo 1: TakeDamage function:
    # Machine instructions (ARM64):
    #   ldr w1, [x0, #0x24]   (load health)
    #   sub w1, w1, w2        (health - damage)
    #   str w1, [x0, #0x24]   (store health back)
    #   ret
    ops = [
        # u0 = x0 + 0x24
        PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.CONST, 0x24, 8)], Varnode(AddressSpace.UNIQUE, 0, 8)),
        # w1 = mem[u0] (4 bytes)
        PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8)], Varnode(AddressSpace.REGISTER, 8, 4)),
        # w1 = w1 - w2 (reg 8 - reg 16)
        PcodeOp(PcodeOpcode.INT_SUB, [Varnode(AddressSpace.REGISTER, 8, 4), Varnode(AddressSpace.REGISTER, 16, 4)], Varnode(AddressSpace.REGISTER, 8, 4)),
        # mem[u0] = w1
        PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8), Varnode(AddressSpace.REGISTER, 8, 4)]),
    ]

    c_code_equiv = "player->m_health = player->m_health - damage;"
    fields = {"m_health": (0x24, 4)}
    params = {"player": "x0", "damage": "w2"}

    print("\n1. Verifying provably equivalent TakeDamage hook:")
    res_pass = verifier.verify_equivalence(
        pcode_ops=ops,
        c_code_or_ast=c_code_equiv,
        struct_fields=fields,
        param_map=params,
        check_memory=True,
    )
    print(f"Result: {res_pass.status} (Equivalent: {res_pass.equivalent})")
    print(f"Details: {res_pass.details}")

    print("\n2. Verifying divergent / buggy TakeDamage mutation (+ instead of -):")
    c_code_buggy = "player->m_health = player->m_health + damage;"
    res_fail = verifier.verify_equivalence(
        pcode_ops=ops,
        c_code_or_ast=c_code_buggy,
        struct_fields=fields,
        param_map=params,
        check_memory=True,
    )
    print(f"Result: {res_fail.status} (Equivalent: {res_fail.equivalent})")
    print(f"Details: {res_fail.details}")
    print(f"Counterexample found by Z3: {res_fail.counterexample}")
