"""
pcode_lifter_bridge.py
======================
SuperGhidra Zero-JVM Python P-Code IR Lifter & SSA Graph Generator.

Implements Sections 6 & 7 of GHIDRA_REFORMATION_ARCHITECTURAL_SPEC.md:
- Direct lifting of native machine code (ARM64 / x86_64) into Ghidra P-Code IR.
- Standalone native Python P-Code lifter without pypcode or JVM dependencies.
- Contains high-performance standalone fallback disassembler/lifter for ARM64 and x86_64,
  guaranteeing zero JVM boot and zero external native dependencies.
- Generates structured P-Code operations:
    COPY, LOAD, STORE, BRANCH, CBRANCH, CALL, INT_ADD, INT_SUB, INT_MUL, etc.
- Emits fixed-shape Varnode adjacency matrices and CFG edge tensors
  for graph neural networks / TPU systolic array inference.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import socket
import struct
from typing import Any, Callable, Dict, List, Tuple

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None  # type: ignore
    HAS_NUMPY = False

try:
    import pypcode  # type: ignore
    HAS_PYPCODE = True
except ImportError:
    pypcode = None  # type: ignore
    HAS_PYPCODE = False

from superghidra.lifters import x86_decode

# ==============================================================================
# P-Code Opcode Definitions (Standard Ghidra P-Code Set)
# ==============================================================================

class PcodeOpcode(enum.IntEnum):
    UNIMPLEMENTED = 0
    COPY = 1
    LOAD = 2
    STORE = 3
    BRANCH = 4
    CBRANCH = 5
    BRANCHIND = 6
    CALL = 7
    CALLIND = 8
    RETURN = 9
    INT_EQUAL = 10
    INT_NOTEQUAL = 11
    INT_SLESS = 12
    INT_SLESSEQUAL = 13
    INT_LESS = 14
    INT_LESSEQUAL = 15
    INT_ZEXT = 16
    INT_SEXT = 17
    INT_ADD = 18
    INT_SUB = 19
    INT_CARRY = 20
    INT_SCARRY = 21
    INT_SBORROW = 22
    INT_2COMP = 23
    INT_NEGATE = 24
    INT_XOR = 25
    INT_AND = 26
    INT_OR = 27
    INT_LEFT = 28
    INT_RIGHT = 29
    INT_SRIGHT = 30
    INT_MULT = 31
    INT_DIV = 32
    INT_SDIV = 33
    INT_REM = 34
    INT_SREM = 35
    BOOL_NEGATE = 36
    BOOL_XOR = 37
    BOOL_AND = 38
    BOOL_OR = 39
    SUBPIECE = 40
    PIECE = 41
    FLOAT_EQUAL = 42
    FLOAT_NOTEQUAL = 43
    FLOAT_LESS = 44
    FLOAT_LESSEQUAL = 45
    FLOAT_ADD = 46
    FLOAT_SUB = 47
    FLOAT_MULT = 48
    FLOAT_DIV = 49
    FLOAT_NEG = 50
    FLOAT_ABS = 51
    FLOAT_SQRT = 52
    FLOAT_INT2FLOAT = 53
    FLOAT_FLOAT2FLOAT = 54
    FLOAT_TRUNC = 55
    CALLOTHER = 56
    POPCOUNT = 57
    MULTIEQUAL = 60
    INDIRECT = 61
    PTRADD = 62
    PTRSUB = 63


class AddressSpace(enum.Enum):
    RAM = "ram"
    REGISTER = "register"
    UNIQUE = "unique"      # Temporary SSA scratchpad
    CONST = "const"
    CONSTANT = "const"     # Alias for CONST


AddrSpace = AddressSpace


@dataclasses.dataclass
class Varnode:
    """Represents a P-Code Varnode (AddressSpace, offset, size in bytes)."""
    space: AddressSpace
    offset: Any
    size: int = 8
    reg_name: str | None = dataclasses.field(default=None, compare=False)

    @property
    def name(self) -> str | None:
        if self.reg_name is not None:
            return self.reg_name
        if self.space == AddressSpace.REGISTER and isinstance(self.offset, str):
            return self.offset
        return None

    def __repr__(self) -> str:
        if self.space == AddressSpace.CONST:
            if isinstance(self.offset, int):
                return f"#0x{self.offset:x}:{self.size}"
            return f"#{self.offset}:{self.size}"
        elif self.space == AddressSpace.REGISTER:
            if isinstance(self.offset, int):
                return f"r[0x{self.offset:x}]:{self.size}"
            return f"r[{self.offset}]:{self.size}"
        elif self.space == AddressSpace.UNIQUE:
            if isinstance(self.offset, int):
                return f"u[0x{self.offset:x}]:{self.size}"
            return f"u[{self.offset}]:{self.size}"
        if isinstance(self.offset, int):
            return f"ram[0x{self.offset:x}]:{self.size}"
        return f"ram[{self.offset}]:{self.size}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "space": self.space.value,
            "offset": hex(self.offset) if isinstance(self.offset, int) else str(self.offset),
            "size": self.size,
        }


@dataclasses.dataclass
class PcodeOp:
    """Represents a single P-Code instruction."""
    opcode: PcodeOpcode
    inputs: List[Varnode] = dataclasses.field(default_factory=list)
    output: Varnode | None = None
    pc: int = 0

    def __repr__(self) -> str:
        out_str = f"{self.output} = " if self.output else ""
        in_str = ", ".join(str(v) for v in self.inputs)
        return f"0x{self.pc:x}: {out_str}{self.opcode.name}({in_str})"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pc": hex(self.pc),
            "opcode": self.opcode.name,
            "output": self.output.to_dict() if self.output else None,
            "inputs": [v.to_dict() for v in self.inputs],
        }


# ==============================================================================
# Standalone ARM64 Zero-JVM P-Code Lifter Engine
# ==============================================================================

FLAG_N_OFFSET: int = 0x700
FLAG_Z_OFFSET: int = 0x701
FLAG_C_OFFSET: int = 0x702
FLAG_V_OFFSET: int = 0x703


class ARM64PcodeLifter:
    """
    Directly lifts ARM64 machine instructions into P-code operations without JVM or Sleigh binary.
    Covers primary instruction classes:
      - MOV / MOVZ / MOVK / MOVN
      - ADD / SUB (immediate and register)
      - LDR / STR (immediate displacement)
      - B / BL / B.cond / CBZ / CBNZ
      - RET / BR / BLR
      - ADRP / ADR
    """

    @staticmethod
    def _reg_varnode(reg_idx: int, size: int = 8) -> Varnode:
        """Maps ARM64 register index (0..30, SP=31) to register Varnode space."""
        # Standard offset mapping: x0..x31 at offset = reg_idx * 8
        return Varnode(space=AddressSpace.REGISTER, offset=reg_idx * 8, size=size)

    @staticmethod
    def _const_varnode(val: int, size: int = 8) -> Varnode:
        return Varnode(space=AddressSpace.CONST, offset=val, size=size)

    @staticmethod
    def _unique_varnode(idx: int, size: int = 8) -> Varnode:
        return Varnode(space=AddressSpace.UNIQUE, offset=idx * 8, size=size)

    def _gpr_varnode(self, reg_idx: int, size: int = 8, allow_sp: bool = False, is_dest: bool = False) -> Varnode:
        """
        Maps ARM64 register index (0..30, SP/XZR=31) to appropriate Varnode.
        - reg_idx 0..30: register varnode (offset = reg_idx * 8).
        - reg_idx 31:
            - If allow_sp is True: register varnode (offset = 31 * 8, representing SP).
            - If allow_sp is False and is_dest is True: discard unique varnode (offset = 0xFFF * 8).
            - If allow_sp is False and is_dest is False: const varnode with value 0 (representing XZR/WZR = 0).
        """
        if reg_idx == 31:
            if allow_sp:
                return self._reg_varnode(31, size)
            if is_dest:
                return Varnode(space=AddressSpace.UNIQUE, offset=0xFFF * 8, size=size)
            return self._const_varnode(0, size)
        return self._reg_varnode(reg_idx, size)

    FLAG_N_OFFSET: int = 0x700
    FLAG_Z_OFFSET: int = 0x701
    FLAG_C_OFFSET: int = 0x702
    FLAG_V_OFFSET: int = 0x703

    @staticmethod
    def _fp_varnode(reg_idx: int, size: int = 8) -> Varnode:
        """Maps ARM64 SIMD/FP register index (0..31) to REGISTER Varnode space at offset 0x400 + reg_idx * 16."""
        return Varnode(space=AddressSpace.REGISTER, offset=0x400 + reg_idx * 16, size=size)

    @staticmethod
    def fp_reg_index(vn: Varnode) -> int:
        """Extracts ARM64 FP/SIMD register index (0..31) from a register Varnode."""
        return (vn.offset - 0x400) // 16

    def _flag_varnode(self, offset: int) -> Varnode:
        return Varnode(space=AddressSpace.REGISTER, offset=offset, size=1)

    def _emit_nzcv_flag_writes(self, pc: int, lhs: Varnode, rhs: Varnode, res: Varnode, is_sub: bool) -> List[PcodeOp]:
        """
        Emits explicit P-code writes to architectural NZCV flag Varnodes:
          - FLAG_Z: INT_EQUAL(res, 0)
          - FLAG_N: INT_SLESS(res, 0)
          - FLAG_C: INT_LESSEQUAL(rhs, lhs) if is_sub else INT_CARRY(lhs, rhs)
          - FLAG_V: INT_SBORROW(lhs, rhs) if is_sub else INT_SCARRY(lhs, rhs)
        """
        ops: List[PcodeOp] = []
        zero_node = self._const_varnode(0, res.size)
        ops.append(PcodeOp(PcodeOpcode.INT_EQUAL, [res, zero_node], self._flag_varnode(self.FLAG_Z_OFFSET), pc=pc))
        ops.append(PcodeOp(PcodeOpcode.INT_SLESS, [res, zero_node], self._flag_varnode(self.FLAG_N_OFFSET), pc=pc))
        if is_sub:
            ops.append(PcodeOp(PcodeOpcode.INT_LESSEQUAL, [rhs, lhs], self._flag_varnode(self.FLAG_C_OFFSET), pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_SBORROW, [lhs, rhs], self._flag_varnode(self.FLAG_V_OFFSET), pc=pc))
        else:
            ops.append(PcodeOp(PcodeOpcode.INT_CARRY, [lhs, rhs], self._flag_varnode(self.FLAG_C_OFFSET), pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_SCARRY, [lhs, rhs], self._flag_varnode(self.FLAG_V_OFFSET), pc=pc))
        return ops

    def __init__(self):
        self._last_cmp_operands: Any | None = None

    @staticmethod
    def _eval_nzcv_condition(cond: int, n: int, z: int, c: int, v: int) -> bool:
        if cond == 0x0: return z == 1       # EQ
        elif cond == 0x1: return z == 0     # NE
        elif cond == 0x2: return c == 1     # CS/HS
        elif cond == 0x3: return c == 0     # CC/LO
        elif cond == 0x4: return n == 1     # MI
        elif cond == 0x5: return n == 0     # PL
        elif cond == 0x6: return v == 1     # VS
        elif cond == 0x7: return v == 0     # VC
        elif cond == 0x8: return c == 1 and z == 0  # HI
        elif cond == 0x9: return c == 0 or z == 1   # LS
        elif cond == 0xA: return n == v     # GE
        elif cond == 0xB: return n != v     # LT
        elif cond == 0xC: return z == 0 and n == v  # GT
        elif cond == 0xD: return z == 1 or n != v   # LE
        return True

    def _emit_single_cond(self, pc: int, cond: int, lhs: Varnode, rhs: Varnode, u_cond: Varnode) -> List[PcodeOp]:
        ops: List[PcodeOp] = []
        if cond == 0x0:  # EQ
            ops.append(PcodeOp(PcodeOpcode.INT_EQUAL, [lhs, rhs], u_cond, pc=pc))
        elif cond == 0x1:  # NE
            ops.append(PcodeOp(PcodeOpcode.INT_NOTEQUAL, [lhs, rhs], u_cond, pc=pc))
        elif cond == 0x2:  # CS / HS (lhs >= rhs -> rhs <= lhs)
            ops.append(PcodeOp(PcodeOpcode.INT_LESSEQUAL, [rhs, lhs], u_cond, pc=pc))
        elif cond == 0x3:  # CC / LO (lhs < rhs)
            ops.append(PcodeOp(PcodeOpcode.INT_LESS, [lhs, rhs], u_cond, pc=pc))
        elif cond == 0x4:  # MI
            ops.append(PcodeOp(PcodeOpcode.INT_SLESS, [lhs, rhs], u_cond, pc=pc))
        elif cond == 0x5:  # PL
            u_tmp = self._unique_varnode(10, 1)
            ops.append(PcodeOp(PcodeOpcode.INT_SLESS, [lhs, rhs], u_tmp, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_EQUAL, [u_tmp, self._const_varnode(0, 1)], u_cond, pc=pc))
        elif cond == 0x8:  # HI (lhs > rhs -> rhs < lhs)
            ops.append(PcodeOp(PcodeOpcode.INT_LESS, [rhs, lhs], u_cond, pc=pc))
        elif cond == 0x9:  # LS (lhs <= rhs)
            ops.append(PcodeOp(PcodeOpcode.INT_LESSEQUAL, [lhs, rhs], u_cond, pc=pc))
        elif cond == 0xA:  # GE (lhs >= rhs -> rhs <= lhs)
            ops.append(PcodeOp(PcodeOpcode.INT_SLESSEQUAL, [rhs, lhs], u_cond, pc=pc))
        elif cond == 0xB:  # LT (lhs < rhs)
            ops.append(PcodeOp(PcodeOpcode.INT_SLESS, [lhs, rhs], u_cond, pc=pc))
        elif cond == 0xC:  # GT (lhs > rhs -> rhs < lhs)
            ops.append(PcodeOp(PcodeOpcode.INT_SLESS, [rhs, lhs], u_cond, pc=pc))
        elif cond == 0xD:  # LE (lhs <= rhs)
            ops.append(PcodeOp(PcodeOpcode.INT_SLESSEQUAL, [lhs, rhs], u_cond, pc=pc))
        else:  # AL / NV
            ops.append(PcodeOp(PcodeOpcode.COPY, [self._const_varnode(1, 1)], u_cond, pc=pc))
        return ops

    def _emit_condition_check(self, pc: int, cond: int, u_cond: Varnode) -> List[PcodeOp]:
        """Emits P-code comparison operation for ARM64 condition code (0x0..0xF)."""
        ops: List[PcodeOp] = []
        if self._last_cmp_operands is None:
            # Fallback to reading explicit architectural NZCV flag varnodes
            flag_z = self._flag_varnode(self.FLAG_Z_OFFSET)
            flag_n = self._flag_varnode(self.FLAG_N_OFFSET)
            flag_c = self._flag_varnode(self.FLAG_C_OFFSET)
            flag_v = self._flag_varnode(self.FLAG_V_OFFSET)
            if cond == 0x0:  # EQ
                ops.append(PcodeOp(PcodeOpcode.COPY, [flag_z], u_cond, pc=pc))
            elif cond == 0x1:  # NE
                ops.append(PcodeOp(PcodeOpcode.INT_XOR, [flag_z, self._const_varnode(1, 1)], u_cond, pc=pc))
            elif cond == 0x2:  # CS / HS
                ops.append(PcodeOp(PcodeOpcode.COPY, [flag_c], u_cond, pc=pc))
            elif cond == 0x3:  # CC / LO
                ops.append(PcodeOp(PcodeOpcode.INT_XOR, [flag_c, self._const_varnode(1, 1)], u_cond, pc=pc))
            elif cond == 0x4:  # MI
                ops.append(PcodeOp(PcodeOpcode.COPY, [flag_n], u_cond, pc=pc))
            elif cond == 0x5:  # PL
                ops.append(PcodeOp(PcodeOpcode.INT_XOR, [flag_n, self._const_varnode(1, 1)], u_cond, pc=pc))
            elif cond == 0x6:  # VS
                ops.append(PcodeOp(PcodeOpcode.COPY, [flag_v], u_cond, pc=pc))
            elif cond == 0x7:  # VC
                ops.append(PcodeOp(PcodeOpcode.INT_XOR, [flag_v, self._const_varnode(1, 1)], u_cond, pc=pc))
            elif cond == 0x8:  # HI (C == 1 and Z == 0)
                u_not_z = self._unique_varnode(20, 1)
                ops.append(PcodeOp(PcodeOpcode.INT_XOR, [flag_z, self._const_varnode(1, 1)], u_not_z, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [flag_c, u_not_z], u_cond, pc=pc))
            elif cond == 0x9:  # LS (C == 0 or Z == 1)
                u_not_c = self._unique_varnode(21, 1)
                ops.append(PcodeOp(PcodeOpcode.INT_XOR, [flag_c, self._const_varnode(1, 1)], u_not_c, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_OR, [flag_z, u_not_c], u_cond, pc=pc))
            elif cond == 0xA:  # GE (N == V)
                ops.append(PcodeOp(PcodeOpcode.INT_EQUAL, [flag_n, flag_v], u_cond, pc=pc))
            elif cond == 0xB:  # LT (N != V)
                ops.append(PcodeOp(PcodeOpcode.INT_NOTEQUAL, [flag_n, flag_v], u_cond, pc=pc))
            elif cond == 0xC:  # GT (Z == 0 and N == V)
                u_ge = self._unique_varnode(22, 1)
                u_not_z = self._unique_varnode(23, 1)
                ops.append(PcodeOp(PcodeOpcode.INT_EQUAL, [flag_n, flag_v], u_ge, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_XOR, [flag_z, self._const_varnode(1, 1)], u_not_z, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [u_ge, u_not_z], u_cond, pc=pc))
            elif cond == 0xD:  # LE (Z == 1 or N != V)
                u_lt = self._unique_varnode(24, 1)
                ops.append(PcodeOp(PcodeOpcode.INT_NOTEQUAL, [flag_n, flag_v], u_lt, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_OR, [flag_z, u_lt], u_cond, pc=pc))
            else:  # AL / NV
                ops.append(PcodeOp(PcodeOpcode.COPY, [self._const_varnode(1, 1)], u_cond, pc=pc))
            return ops

        if isinstance(self._last_cmp_operands, tuple) and len(self._last_cmp_operands) == 7 and self._last_cmp_operands[0] == "CCMP":
            _, u_outer, rn_node, rhs_node, size, is_sub, nzcv = self._last_cmp_operands
            u_inner = self._unique_varnode(30, 1)
            ops.extend(self._emit_single_cond(pc, cond, rn_node, rhs_node, u_inner))
            n = (nzcv >> 3) & 1
            z = (nzcv >> 2) & 1
            c = (nzcv >> 1) & 1
            v = nzcv & 1
            fallback = self._eval_nzcv_condition(cond, n, z, c, v)
            if fallback:
                u_not_outer = self._unique_varnode(31, 1)
                ops.append(PcodeOp(PcodeOpcode.INT_XOR, [u_outer, self._const_varnode(1, 1)], u_not_outer, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_inner, u_not_outer], u_cond, pc=pc))
            else:
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [u_outer, u_inner], u_cond, pc=pc))
            return ops

        if isinstance(self._last_cmp_operands, tuple) and len(self._last_cmp_operands) >= 5 and self._last_cmp_operands[0] == "FCMP":
            _, lhs, rhs, size, _ = self._last_cmp_operands
            if cond == 0x0:
                ops.append(PcodeOp(PcodeOpcode.FLOAT_EQUAL, [lhs, rhs], u_cond, pc=pc))
            elif cond == 0x1:
                ops.append(PcodeOp(PcodeOpcode.FLOAT_NOTEQUAL, [lhs, rhs], u_cond, pc=pc))
            elif cond in (0x2, 0xA):  # CS/HS or GE (rhs <= lhs)
                ops.append(PcodeOp(PcodeOpcode.FLOAT_LESSEQUAL, [rhs, lhs], u_cond, pc=pc))
            elif cond in (0x3, 0x4, 0xB):  # CC/LO, MI, LT (lhs < rhs)
                ops.append(PcodeOp(PcodeOpcode.FLOAT_LESS, [lhs, rhs], u_cond, pc=pc))
            elif cond == 0xC:  # GT (rhs < lhs)
                ops.append(PcodeOp(PcodeOpcode.FLOAT_LESS, [rhs, lhs], u_cond, pc=pc))
            elif cond == 0xD:  # LE (lhs <= rhs)
                ops.append(PcodeOp(PcodeOpcode.FLOAT_LESSEQUAL, [lhs, rhs], u_cond, pc=pc))
            else:
                ops.append(PcodeOp(PcodeOpcode.COPY, [self._const_varnode(1, 1)], u_cond, pc=pc))
            return ops

        lhs, rhs, size, is_sub = self._last_cmp_operands
        return self._emit_single_cond(pc, cond, lhs, rhs, u_cond)


    def lift_instruction(self, pc: int, insn: int) -> List[PcodeOp]:
        """Lifts a single 32-bit ARM64 machine word at PC into 1 or more PcodeOps."""
        ops: List[PcodeOp] = []

        # 1. RET: 0xD65F03C0 (or RET xN: bits [31:10] == 0x3597C0)
        if (insn & 0xFFFFFC1F) == 0xD65F0000:
            rn = (insn >> 5) & 0x1F
            ops.append(PcodeOp(
                opcode=PcodeOpcode.RETURN,
                inputs=[self._gpr_varnode(rn, 8, allow_sp=False)],
                pc=pc
            ))
            return ops

        # 2. Indirect Branch with Link: BLR (bits [31:10] == 0x359F00)
        if (insn & 0xFFFFFC1F) == 0xD63F0000:
            rn = (insn >> 5) & 0x1F
            ops.append(PcodeOp(
                opcode=PcodeOpcode.COPY,
                inputs=[self._const_varnode(pc + 4, 8)],
                output=self._reg_varnode(30, 8),
                pc=pc
            ))
            ops.append(PcodeOp(
                opcode=PcodeOpcode.CALLIND,
                inputs=[self._gpr_varnode(rn, 8, allow_sp=False)],
                pc=pc
            ))
            return ops

        # 3. Indirect Branch: BR (bits [31:10] == 0x358F00)
        if (insn & 0xFFFFFC1F) == 0xD61F0000:
            rn = (insn >> 5) & 0x1F
            ops.append(PcodeOp(
                opcode=PcodeOpcode.BRANCHIND,
                inputs=[self._gpr_varnode(rn, 8, allow_sp=False)],
                pc=pc
            ))
            return ops

        # 4. BL (Branch with Link): (insn & 0xFC000000) == 0x94000000
        if (insn & 0xFC000000) == 0x94000000:
            imm26 = insn & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 -= 0x04000000
            target_pc = pc + (imm26 << 2)
            # x30 (LR) = pc + 4
            ops.append(PcodeOp(
                opcode=PcodeOpcode.COPY,
                inputs=[self._const_varnode(pc + 4, 8)],
                output=self._reg_varnode(30, 8),
                pc=pc
            ))
            # CALL target
            ops.append(PcodeOp(
                opcode=PcodeOpcode.CALL,
                inputs=[self._const_varnode(target_pc, 8)],
                pc=pc
            ))
            return ops

        # 5. B (Unconditional Branch): (insn & 0xFC000000) == 0x14000000
        if (insn & 0xFC000000) == 0x14000000:
            imm26 = insn & 0x03FFFFFF
            if imm26 & 0x02000000:
                imm26 -= 0x04000000
            target_pc = pc + (imm26 << 2)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.BRANCH,
                inputs=[self._const_varnode(target_pc, 8)],
                pc=pc
            ))
            return ops

        # 6. B.cond: (insn & 0xFF000010) == 0x54000000
        if (insn & 0xFF000010) == 0x54000000:
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 -= 0x80000
            target_pc = pc + (imm19 << 2)
            cond = insn & 0xF
            u_cond = self._unique_varnode(0, 1)
            ops.extend(self._emit_condition_check(pc, cond, u_cond))
            ops.append(PcodeOp(
                opcode=PcodeOpcode.CBRANCH,
                inputs=[self._const_varnode(target_pc, 8), u_cond],
                pc=pc
            ))
            return ops

        # 7. CBZ / CBNZ: (insn & 0x7E000000) == 0x34000000
        if (insn & 0x7E000000) == 0x34000000:
            sf = (insn >> 31) & 1
            size = 8 if sf else 4
            is_cbnz = (insn >> 24) & 1
            imm19 = (insn >> 5) & 0x7FFFF
            if imm19 & 0x40000:
                imm19 -= 0x80000
            target_pc = pc + (imm19 << 2)
            rt = insn & 0x1F
            rt_node = self._gpr_varnode(rt, size, allow_sp=False)
            u_cond = self._unique_varnode(0, 1)
            cmp_opcode = PcodeOpcode.INT_NOTEQUAL if is_cbnz else PcodeOpcode.INT_EQUAL
            ops.append(PcodeOp(
                opcode=cmp_opcode,
                inputs=[rt_node, self._const_varnode(0, size)],
                output=u_cond,
                pc=pc
            ))
            ops.append(PcodeOp(
                opcode=PcodeOpcode.CBRANCH,
                inputs=[self._const_varnode(target_pc, 8), u_cond],
                pc=pc
            ))
            return ops

        # 7b. TBZ / TBNZ (Test Bit and Branch): (insn & 0x7E000000) == 0x36000000
        if (insn & 0x7E000000) == 0x36000000:
            b5 = (insn >> 31) & 1
            op = (insn >> 24) & 1
            b40 = (insn >> 19) & 0x1F
            bit_pos = (b5 << 5) | b40
            size = 8 if b5 else 4
            imm14 = (insn >> 5) & 0x3FFF
            if imm14 & 0x2000:
                imm14 -= 0x4000
            target_pc = pc + (imm14 << 2)
            rt = insn & 0x1F
            rt_node = self._gpr_varnode(rt, size, allow_sp=False)
            u_masked = self._unique_varnode(0, size)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.INT_AND,
                inputs=[rt_node, self._const_varnode(1 << bit_pos, size)],
                output=u_masked,
                pc=pc
            ))
            u_cond = self._unique_varnode(1, 1)
            cmp_opcode = PcodeOpcode.INT_EQUAL if op == 0 else PcodeOpcode.INT_NOTEQUAL
            ops.append(PcodeOp(
                opcode=cmp_opcode,
                inputs=[u_masked, self._const_varnode(0, size)],
                output=u_cond,
                pc=pc
            ))
            ops.append(PcodeOp(
                opcode=PcodeOpcode.CBRANCH,
                inputs=[self._const_varnode(target_pc, 8), u_cond],
                pc=pc
            ))
            return ops

        # 8. MOVZ (64-bit / 32-bit): (insn & 0x7F800000) == 0x52800000
        if (insn & 0x7F800000) == 0x52800000:
            sf = (insn >> 31) & 1
            size = 8 if sf else 4
            rd = insn & 0x1F
            hw = (insn >> 21) & 3
            imm16 = (insn >> 5) & 0xFFFF
            val = imm16 << (hw * 16)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.COPY,
                inputs=[self._const_varnode(val, size)],
                output=self._gpr_varnode(rd, size, allow_sp=False, is_dest=True),
                pc=pc
            ))
            return ops

        # 9. MOVN (Move Wide with NOT): (insn & 0x7F800000) == 0x12800000
        if (insn & 0x7F800000) == 0x12800000:
            sf = (insn >> 31) & 1
            size = 8 if sf else 4
            bits = 64 if sf else 32
            rd = insn & 0x1F
            hw = (insn >> 21) & 3
            imm16 = (insn >> 5) & 0xFFFF
            val = imm16 << (hw * 16)
            val_not = (~val) & ((1 << bits) - 1)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.COPY,
                inputs=[self._const_varnode(val_not, size)],
                output=self._gpr_varnode(rd, size, allow_sp=False, is_dest=True),
                pc=pc
            ))
            return ops

        # 10. MOVK (Move Wide with Keep): (insn & 0x7F800000) == 0x72800000
        if (insn & 0x7F800000) == 0x72800000:
            sf = (insn >> 31) & 1
            size = 8 if sf else 4
            bits = 64 if sf else 32
            rd = insn & 0x1F
            hw = (insn >> 21) & 3
            shift = hw * 16
            imm16 = (insn >> 5) & 0xFFFF
            lane_mask = (~(0xFFFF << shift)) & ((1 << bits) - 1)
            insert_val = imm16 << shift
            u_temp = self._unique_varnode(0, size)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.INT_AND,
                inputs=[self._gpr_varnode(rd, size, allow_sp=False), self._const_varnode(lane_mask, size)],
                output=u_temp,
                pc=pc
            ))
            ops.append(PcodeOp(
                opcode=PcodeOpcode.INT_OR,
                inputs=[u_temp, self._const_varnode(insert_val, size)],
                output=self._gpr_varnode(rd, size, allow_sp=False, is_dest=True),
                pc=pc
            ))
            return ops

        # 11. ADRP: (insn & 0x9F000000) == 0x90000000
        if (insn & 0x9F000000) == 0x90000000:
            rd = insn & 0x1F
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7FFFF
            imm21 = (immhi << 2) | immlo
            if imm21 & 0x100000:
                imm21 -= 0x200000
            target_page = (pc & ~0xFFF) + (imm21 << 12)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.COPY,
                inputs=[self._const_varnode(target_page, 8)],
                output=self._gpr_varnode(rd, 8, allow_sp=False, is_dest=True),
                pc=pc
            ))
            return ops

        # ADR: (insn & 0x9F000000) == 0x10000000
        if (insn & 0x9F000000) == 0x10000000:
            rd = insn & 0x1F
            immlo = (insn >> 29) & 3
            immhi = (insn >> 5) & 0x7FFFF
            imm21 = (immhi << 2) | immlo
            if imm21 & 0x100000:
                imm21 -= 0x200000
            target = pc + imm21
            ops.append(PcodeOp(
                opcode=PcodeOpcode.COPY,
                inputs=[self._const_varnode(target, 8)],
                output=self._gpr_varnode(rd, 8, allow_sp=False, is_dest=True),
                pc=pc
            ))
            return ops

        # 12. ADD / ADDS (immediate): (insn & 0x5F000000) == 0x11000000
        if (insn & 0x5F000000) == 0x11000000:
            sf = (insn >> 31) & 1
            s_bit = (insn >> 29) & 1
            size = 8 if sf else 4
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            sh = (insn >> 22) & 1
            val = imm12 << (12 if sh else 0)
            rn_node = self._gpr_varnode(rn, size, allow_sp=True)
            const_node = self._const_varnode(val, size)
            if s_bit:
                self._last_cmp_operands = (rn_node, const_node, size, False)
                rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)
            else:
                rd_dest = self._gpr_varnode(rd, size, allow_sp=True, is_dest=True)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.INT_ADD,
                inputs=[rn_node, const_node],
                output=rd_dest,
                pc=pc
            ))
            return ops

        # 13. SUB / SUBS (immediate, CMP): (insn & 0x5F000000) == 0x51000000
        if (insn & 0x5F000000) == 0x51000000:
            sf = (insn >> 31) & 1
            s_bit = (insn >> 29) & 1
            size = 8 if sf else 4
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            sh = (insn >> 22) & 1
            val = imm12 << (12 if sh else 0)
            rn_node = self._gpr_varnode(rn, size, allow_sp=True)
            const_node = self._const_varnode(val, size)
            if s_bit:
                self._last_cmp_operands = (rn_node, const_node, size, True)
                rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)
            else:
                rd_dest = self._gpr_varnode(rd, size, allow_sp=True, is_dest=True)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.INT_SUB,
                inputs=[rn_node, const_node],
                output=rd_dest,
                pc=pc
            ))
            return ops

        # 14. Logical Shifted Register (AND, ORR/MOV, EOR, ANDS): (insn & 0x1F000000) == 0x0A000000
        if (insn & 0x1F000000) == 0x0A000000:
            sf = (insn >> 31) & 1
            opc = (insn >> 29) & 3
            shift_type = (insn >> 22) & 3
            n_bit = (insn >> 21) & 1
            rm = (insn >> 16) & 0x1F
            imm6 = (insn >> 10) & 0x3F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            size = 8 if sf else 4

            # Special fast-path: ORR (opc==1, n_bit==0, imm6==0, rn==31) is MOV Xd, Xm
            if opc == 1 and n_bit == 0 and imm6 == 0 and rn == 31:
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.COPY,
                    inputs=[self._gpr_varnode(rm, size, allow_sp=False)],
                    output=self._gpr_varnode(rd, size, allow_sp=False, is_dest=True),
                    pc=pc
                ))
                return ops

            cur_rm = self._gpr_varnode(rm, size, allow_sp=False)
            if imm6 > 0:
                u_shifted = self._unique_varnode(0, size)
                if shift_type == 0:  # LSL
                    ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [cur_rm, self._const_varnode(imm6, size)], u_shifted, pc=pc))
                elif shift_type == 1:  # LSR
                    ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [cur_rm, self._const_varnode(imm6, size)], u_shifted, pc=pc))
                elif shift_type == 2:  # ASR
                    ops.append(PcodeOp(PcodeOpcode.INT_SRIGHT, [cur_rm, self._const_varnode(imm6, size)], u_shifted, pc=pc))
                elif shift_type == 3:  # ROR
                    bits = 64 if sf else 32
                    u_r = self._unique_varnode(1, size)
                    u_l = self._unique_varnode(2, size)
                    ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [cur_rm, self._const_varnode(imm6, size)], u_r, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [cur_rm, self._const_varnode(bits - imm6, size)], u_l, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_r, u_l], u_shifted, pc=pc))
                cur_rm = u_shifted

            if n_bit == 1:
                u_inv = self._unique_varnode(3, size)
                ops.append(PcodeOp(PcodeOpcode.INT_NEGATE, [cur_rm], u_inv, pc=pc))
                cur_rm = u_inv

            rn_node = self._gpr_varnode(rn, size, allow_sp=False)
            rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)
            if opc in (0, 3):
                log_opcode = PcodeOpcode.INT_AND
            elif opc == 1:
                log_opcode = PcodeOpcode.INT_OR
            else:
                log_opcode = PcodeOpcode.INT_XOR

            if opc == 3:  # ANDS / TST
                self._last_cmp_operands = (rd_dest, self._const_varnode(0, size), size, True)

            ops.append(PcodeOp(
                opcode=log_opcode,
                inputs=[rn_node, cur_rm],
                output=rd_dest,
                pc=pc
            ))
            return ops

        # 15. Add/Subtract Shifted Register: (insn & 0x1F200000) == 0x0B000000
        if (insn & 0x1F200000) == 0x0B000000:
            sf = (insn >> 31) & 1
            op = (insn >> 30) & 1
            s_bit = (insn >> 29) & 1
            shift_type = (insn >> 22) & 3
            rm = (insn >> 16) & 0x1F
            imm6 = (insn >> 10) & 0x3F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            size = 8 if sf else 4

            cur_rm = self._gpr_varnode(rm, size, allow_sp=False)
            if imm6 > 0:
                u_shifted = self._unique_varnode(0, size)
                if shift_type == 0:
                    ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [cur_rm, self._const_varnode(imm6, size)], u_shifted, pc=pc))
                elif shift_type == 1:
                    ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [cur_rm, self._const_varnode(imm6, size)], u_shifted, pc=pc))
                elif shift_type == 2:
                    ops.append(PcodeOp(PcodeOpcode.INT_SRIGHT, [cur_rm, self._const_varnode(imm6, size)], u_shifted, pc=pc))
                cur_rm = u_shifted

            rn_node = self._gpr_varnode(rn, size, allow_sp=False)
            if s_bit:
                self._last_cmp_operands = (rn_node, cur_rm, size, op == 1)
                rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)
            else:
                rd_dest = self._gpr_varnode(rd, size, allow_sp=True, is_dest=True)
            arith_opcode = PcodeOpcode.INT_ADD if op == 0 else PcodeOpcode.INT_SUB
            ops.append(PcodeOp(
                opcode=arith_opcode,
                inputs=[rn_node, cur_rm],
                output=rd_dest,
                pc=pc
            ))
            return ops

        # 16. Bitfield Immediate: UBFM (LSL, LSR, UXTB, UXTH): (insn & 0x7F800000) == 0x53000000
        if (insn & 0x7F800000) == 0x53000000:
            sf = (insn >> 31) & 1
            size = 8 if sf else 4
            bits = 64 if sf else 32
            immr = (insn >> 16) & 0x3F
            imms = (insn >> 10) & 0x3F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            rn_node = self._gpr_varnode(rn, size, allow_sp=False)
            rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)

            # LSL alias: imms != 0x1F and imms != 0x3F and (imms + 1) == immr
            if imms != 0x1F and imms != 0x3F and (imms + 1) == immr:
                shift_amt = (bits - immr) % bits
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.INT_LEFT,
                    inputs=[rn_node, self._const_varnode(shift_amt, size)],
                    output=rd_dest,
                    pc=pc
                ))
                return ops

            # LSR alias: imms == (63 if sf else 31)
            if imms == (63 if sf else 31):
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.INT_RIGHT,
                    inputs=[rn_node, self._const_varnode(immr, size)],
                    output=rd_dest,
                    pc=pc
                ))
                return ops

            # UXTB alias: immr == 0 and imms == 7
            if immr == 0 and imms == 7:
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.INT_AND,
                    inputs=[rn_node, self._const_varnode(0xFF, size)],
                    output=rd_dest,
                    pc=pc
                ))
                return ops

            # UXTH alias: immr == 0 and imms == 15
            if immr == 0 and imms == 15:
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.INT_AND,
                    inputs=[rn_node, self._const_varnode(0xFFFF, size)],
                    output=rd_dest,
                    pc=pc
                ))
                return ops

            # General UBFM extract (UBFX alias when imms >= immr)
            if imms >= immr:
                mask = (1 << (imms - immr + 1)) - 1
                if immr > 0:
                    u_sh = self._unique_varnode(0, size)
                    ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [rn_node, self._const_varnode(immr, size)], u_sh, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [u_sh, self._const_varnode(mask, size)], rd_dest, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(mask, size)], rd_dest, pc=pc))
                return ops
            else:
                # General UBFM insert (UBFIZ alias when imms < immr)
                lsb = bits - immr
                width = imms + 1
                mask = (1 << width) - 1
                u_masked = self._unique_varnode(0, size)
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(mask, size)], u_masked, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [u_masked, self._const_varnode(lsb, size)], rd_dest, pc=pc))
                return ops

        # 17. Bitfield Immediate: SBFM (ASR, SXTW, SBFX, SBFIZ): (insn & 0x7F800000) == 0x13000000
        if (insn & 0x7F800000) == 0x13000000:
            sf = (insn >> 31) & 1
            size = 8 if sf else 4
            bits = 64 if sf else 32
            immr = (insn >> 16) & 0x3F
            imms = (insn >> 10) & 0x3F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            rn_node = self._gpr_varnode(rn, size, allow_sp=False)
            rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)

            # ASR alias: imms == (63 if sf else 31)
            if imms == (63 if sf else 31):
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.INT_SRIGHT,
                    inputs=[rn_node, self._const_varnode(immr, size)],
                    output=rd_dest,
                    pc=pc
                ))
                return ops

            # SXTW alias: immr == 0, imms == 31, sf == 1
            if immr == 0 and imms == 31 and sf == 1:
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.INT_SEXT,
                    inputs=[self._gpr_varnode(rn, 4, allow_sp=False)],
                    output=rd_dest,
                    pc=pc
                ))
                return ops

            if imms >= immr:
                # SBFX alias: signed bitfield extract
                width = imms - immr + 1
                shift_l = bits - 1 - imms
                if shift_l > 0:
                    u_l = self._unique_varnode(0, size)
                    ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [rn_node, self._const_varnode(shift_l, size)], u_l, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_SRIGHT, [u_l, self._const_varnode(shift_l + immr, size)], rd_dest, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.INT_SRIGHT, [rn_node, self._const_varnode(immr, size)], rd_dest, pc=pc))
                return ops
            else:
                # SBFIZ alias: signed bitfield insert in zero
                width = imms + 1
                lsb = bits - immr
                shift_l = bits - width
                u_l = self._unique_varnode(0, size)
                u_r = self._unique_varnode(1, size)
                ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [rn_node, self._const_varnode(shift_l, size)], u_l, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_SRIGHT, [u_l, self._const_varnode(shift_l, size)], u_r, pc=pc))
                if lsb > 0:
                    ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [u_r, self._const_varnode(lsb, size)], rd_dest, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.COPY, [u_r], rd_dest, pc=pc))
                return ops

        # 17b. Bitfield Move: BFM (BFI, BFXIL): (insn & 0x7F800000) == 0x33000000
        if (insn & 0x7F800000) == 0x33000000:
            sf = (insn >> 31) & 1
            size = 8 if sf else 4
            bits = 64 if sf else 32
            immr = (insn >> 16) & 0x3F
            imms = (insn >> 10) & 0x3F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            rn_node = self._gpr_varnode(rn, size, allow_sp=False)
            rd_node = self._gpr_varnode(rd, size, allow_sp=False)
            rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)

            if imms >= immr:
                # BFXIL: Bitfield extract and insert at low end
                width = imms - immr + 1
                mask = (1 << width) - 1
                inv_mask = ((1 << bits) - 1) ^ mask
                u_sh = self._unique_varnode(0, size)
                u_part = self._unique_varnode(1, size)
                u_kept = self._unique_varnode(2, size)
                if immr > 0:
                    ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [rn_node, self._const_varnode(immr, size)], u_sh, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [u_sh, self._const_varnode(mask, size)], u_part, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(mask, size)], u_part, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [rd_node, self._const_varnode(inv_mask, size)], u_kept, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_kept, u_part], rd_dest, pc=pc))
                return ops
            else:
                # BFI: Bitfield insert
                width = imms + 1
                lsb = bits - immr
                mask0 = (1 << width) - 1
                mask = (mask0 << lsb) & ((1 << bits) - 1)
                inv_mask = ((1 << bits) - 1) ^ mask
                u_masked = self._unique_varnode(0, size)
                u_part = self._unique_varnode(1, size)
                u_kept = self._unique_varnode(2, size)
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(mask0, size)], u_masked, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [u_masked, self._const_varnode(lsb, size)], u_part, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [rd_node, self._const_varnode(inv_mask, size)], u_kept, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_kept, u_part], rd_dest, pc=pc))
                return ops

        # 18. Data-Processing 3-Source (MADD / MSUB / MUL): (insn & 0x7FE00000) == 0x1B000000
        if (insn & 0x7FE00000) == 0x1B000000:
            sf = (insn >> 31) & 1
            size = 8 if sf else 4
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            rm = (insn >> 16) & 0x1F
            ra = (insn >> 10) & 0x1F
            o0 = (insn >> 15) & 1
            rn_node = self._gpr_varnode(rn, size, allow_sp=False)
            rm_node = self._gpr_varnode(rm, size, allow_sp=False)
            rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)

            # MUL alias: ra == 31 and o0 == 0
            if ra == 31 and o0 == 0:
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.INT_MULT,
                    inputs=[rn_node, rm_node],
                    output=rd_dest,
                    pc=pc
                ))
                return ops

            u_mul = self._unique_varnode(0, size)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.INT_MULT,
                inputs=[rn_node, rm_node],
                output=u_mul,
                pc=pc
            ))
            ra_node = self._gpr_varnode(ra, size, allow_sp=False)
            post_opcode = PcodeOpcode.INT_ADD if o0 == 0 else PcodeOpcode.INT_SUB
            ops.append(PcodeOp(
                opcode=post_opcode,
                inputs=[ra_node, u_mul],
                output=rd_dest,
                pc=pc
            ))
            return ops

        # 18-w1. Widening Signed Multiply-Add / Long (SMADDL / SMULL / SMSUBL): (insn & 0xFFA00000) == 0x9B200000
        if (insn & 0xFFA00000) == 0x9B200000:
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            ra = (insn >> 10) & 0x1F
            o0 = (insn >> 15) & 1
            rm = (insn >> 16) & 0x1F

            wn_node = self._gpr_varnode(rn, 4, allow_sp=False)
            wm_node = self._gpr_varnode(rm, 4, allow_sp=False)
            rd_dest = self._gpr_varnode(rd, 8, allow_sp=False, is_dest=True)

            u_xn = self._unique_varnode(0, 8)
            u_xm = self._unique_varnode(1, 8)
            u_mul = self._unique_varnode(2, 8)
            ops.append(PcodeOp(PcodeOpcode.INT_SEXT, [wn_node], u_xn, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_SEXT, [wm_node], u_xm, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_MULT, [u_xn, u_xm], u_mul, pc=pc))

            if ra == 31 and o0 == 0:
                ops.append(PcodeOp(PcodeOpcode.COPY, [u_mul], rd_dest, pc=pc))
            else:
                ra_node = self._gpr_varnode(ra, 8, allow_sp=False)
                post_op = PcodeOpcode.INT_ADD if o0 == 0 else PcodeOpcode.INT_SUB
                ops.append(PcodeOp(post_op, [ra_node, u_mul], rd_dest, pc=pc))
            return ops

        # 18-w2. Widening Unsigned Multiply-Add / Long (UMADDL / UMULL / UMSUBL): (insn & 0xFFA00000) == 0x9BA00000
        if (insn & 0xFFA00000) == 0x9BA00000:
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            ra = (insn >> 10) & 0x1F
            o0 = (insn >> 15) & 1
            rm = (insn >> 16) & 0x1F

            wn_node = self._gpr_varnode(rn, 4, allow_sp=False)
            wm_node = self._gpr_varnode(rm, 4, allow_sp=False)
            rd_dest = self._gpr_varnode(rd, 8, allow_sp=False, is_dest=True)

            u_xn = self._unique_varnode(0, 8)
            u_xm = self._unique_varnode(1, 8)
            u_mul = self._unique_varnode(2, 8)
            ops.append(PcodeOp(PcodeOpcode.INT_ZEXT, [wn_node], u_xn, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_ZEXT, [wm_node], u_xm, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_MULT, [u_xn, u_xm], u_mul, pc=pc))

            if ra == 31 and o0 == 0:
                ops.append(PcodeOp(PcodeOpcode.COPY, [u_mul], rd_dest, pc=pc))
            else:
                ra_node = self._gpr_varnode(ra, 8, allow_sp=False)
                post_op = PcodeOpcode.INT_ADD if o0 == 0 else PcodeOpcode.INT_SUB
                ops.append(PcodeOp(post_op, [ra_node, u_mul], rd_dest, pc=pc))
            return ops

        # 18-w3. High Multiply 64x64->128 (SMULH / UMULH): (insn & 0xFF60FC00) == 0x9B407C00
        if (insn & 0xFF60FC00) == 0x9B407C00:
            is_signed = ((insn >> 23) & 1) == 0
            rm = (insn >> 16) & 0x1F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F

            rn_node = self._gpr_varnode(rn, 8, allow_sp=False)
            rm_node = self._gpr_varnode(rm, 8, allow_sp=False)
            rd_dest = self._gpr_varnode(rd, 8, allow_sp=False, is_dest=True)

            u_n16 = self._unique_varnode(0, 16)
            u_m16 = self._unique_varnode(1, 16)
            u_prod16 = self._unique_varnode(2, 16)

            ext_op = PcodeOpcode.INT_SEXT if is_signed else PcodeOpcode.INT_ZEXT
            ops.append(PcodeOp(ext_op, [rn_node], u_n16, pc=pc))
            ops.append(PcodeOp(ext_op, [rm_node], u_m16, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_MULT, [u_n16, u_m16], u_prod16, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [u_prod16, self._const_varnode(8, 4)], rd_dest, pc=pc))
            return ops

        # 18-cc. Conditional Compare (CCMP / CCMN - register and immediate): (insn & 0x3FE00810) == 0x3A400000
        if (insn & 0x3FE00810) == 0x3A400000:
            sf = (insn >> 31) & 1
            op = (insn >> 30) & 1
            cond = (insn >> 12) & 0xF
            is_imm = (insn >> 11) & 1
            rn = (insn >> 5) & 0x1F
            nzcv = insn & 0xF
            size = 8 if sf else 4
            rn_node = self._gpr_varnode(rn, size, allow_sp=False)
            if is_imm:
                imm5 = (insn >> 16) & 0x1F
                rhs_node = self._const_varnode(imm5, size)
            else:
                rm = (insn >> 16) & 0x1F
                rhs_node = self._gpr_varnode(rm, size, allow_sp=False)

            u_outer = self._unique_varnode(0, 1)
            ops.extend(self._emit_condition_check(pc, cond, u_outer))
            self._last_cmp_operands = ("CCMP", u_outer, rn_node, rhs_node, size, op == 0, nzcv)
            return ops

        # 18b. Conditional Select (CSEL, CSINC, CSINV, CSNEG): (insn & 0x3FE00000) == 0x1A800000
        if (insn & 0x3FE00000) == 0x1A800000 and (insn & 0x00000800) == 0:
            sf = (insn >> 31) & 1
            size = 8 if sf else 4
            op = (insn >> 30) & 1
            rm = (insn >> 16) & 0x1F
            cond = (insn >> 12) & 0xF
            op2 = (insn >> 10) & 1
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F

            rn_node = self._gpr_varnode(rn, size, allow_sp=False)
            rm_node = self._gpr_varnode(rm, size, allow_sp=False)

            if op == 0 and op2 == 0:
                false_node = rm_node  # CSEL
            elif op == 0 and op2 == 1:
                u_inc = self._unique_varnode(1, size)
                ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rm_node, self._const_varnode(1, size)], u_inc, pc=pc))
                false_node = u_inc  # CSINC
            elif op == 1 and op2 == 0:
                u_inv = self._unique_varnode(1, size)
                ops.append(PcodeOp(PcodeOpcode.INT_NEGATE, [rm_node], u_inv, pc=pc))
                false_node = u_inv  # CSINV
            else:
                u_neg = self._unique_varnode(1, size)
                ops.append(PcodeOp(PcodeOpcode.INT_2COMP, [rm_node], u_neg, pc=pc))
                false_node = u_neg  # CSNEG

            u_cond = self._unique_varnode(2, 1)
            ops.extend(self._emit_condition_check(pc, cond, u_cond))

            u_cond_sz = self._unique_varnode(3, size)
            ops.append(PcodeOp(PcodeOpcode.INT_ZEXT, [u_cond], u_cond_sz, pc=pc))
            u_mask = self._unique_varnode(4, size)
            ops.append(PcodeOp(PcodeOpcode.INT_2COMP, [u_cond_sz], u_mask, pc=pc))
            u_not_mask = self._unique_varnode(5, size)
            ops.append(PcodeOp(PcodeOpcode.INT_NEGATE, [u_mask], u_not_mask, pc=pc))

            u_t = self._unique_varnode(6, size)
            ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, u_mask], u_t, pc=pc))
            u_f = self._unique_varnode(7, size)
            ops.append(PcodeOp(PcodeOpcode.INT_AND, [false_node, u_not_mask], u_f, pc=pc))

            rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)
            ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_t, u_f], rd_dest, pc=pc))
            return ops

        # 18c. Integer Divide (UDIV / SDIV): (insn & 0x7FE0F800) == 0x1AC00800
        if (insn & 0x7FE0F800) == 0x1AC00800:
            sf = (insn >> 31) & 1
            size = 8 if sf else 4
            rm = (insn >> 16) & 0x1F
            is_sdiv = (insn >> 10) & 1
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F

            rn_node = self._gpr_varnode(rn, size, allow_sp=False)
            rm_node = self._gpr_varnode(rm, size, allow_sp=False)
            rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)
            div_op = PcodeOpcode.INT_SDIV if is_sdiv else PcodeOpcode.INT_DIV
            ops.append(PcodeOp(
                opcode=div_op,
                inputs=[rn_node, rm_node],
                output=rd_dest,
                pc=pc
            ))
            return ops

        # 18d. Extract / Rotate Right (EXTR / ROR): (insn & 0x7FA00000) == 0x13800000
        if (insn & 0x7FA00000) == 0x13800000:
            sf = (insn >> 31) & 1
            n = (insn >> 22) & 1
            if sf == n:
                size = 8 if sf else 4
                bits = 64 if sf else 32
                rm = (insn >> 16) & 0x1F
                imms = (insn >> 10) & 0x3F
                rn = (insn >> 5) & 0x1F
                rd = insn & 0x1F

                rn_node = self._gpr_varnode(rn, size, allow_sp=False)
                rm_node = self._gpr_varnode(rm, size, allow_sp=False)
                rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)

                if imms == 0:
                    ops.append(PcodeOp(PcodeOpcode.COPY, [rm_node], rd_dest, pc=pc))
                else:
                    u_r = self._unique_varnode(0, size)
                    u_l = self._unique_varnode(1, size)
                    ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [rm_node, self._const_varnode(imms, size)], u_r, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [rn_node, self._const_varnode(bits - imms, size)], u_l, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_r, u_l], rd_dest, pc=pc))
                return ops

        # 18e. Byte Reverse (REV16, REV32, REV): (insn & 0x5FFFF000) == 0x5AC00000
        if (insn & 0x5FFFF000) == 0x5AC00000:
            sf = (insn >> 31) & 1
            size = 8 if sf else 4
            opc = (insn >> 10) & 3  # 1: REV16, 2: REV / REV32, 3: REV (64-bit)
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            rn_node = self._gpr_varnode(rn, size, allow_sp=False)
            rd_dest = self._gpr_varnode(rd, size, allow_sp=False, is_dest=True)

            if opc == 1:  # REV16 (reverse bytes in 16-bit halfwords)
                mask_lo = 0x00FF00FF00FF00FF if sf else 0x00FF00FF
                mask_hi = 0xFF00FF00FF00FF00 if sf else 0xFF00FF00
                u_lo = self._unique_varnode(0, size)
                u_hi = self._unique_varnode(1, size)
                u_sh_lo = self._unique_varnode(2, size)
                u_sh_hi = self._unique_varnode(3, size)
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(mask_lo, size)], u_lo, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [u_lo, self._const_varnode(8, size)], u_sh_lo, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(mask_hi, size)], u_hi, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [u_hi, self._const_varnode(8, size)], u_sh_hi, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_sh_lo, u_sh_hi], rd_dest, pc=pc))
                return ops

            elif opc == 2 and sf == 1:  # REV32 (64-bit: reverse bytes in 32-bit words)
                u_b0 = self._unique_varnode(0, 8)
                u_b1 = self._unique_varnode(1, 8)
                u_b2 = self._unique_varnode(2, 8)
                u_b3 = self._unique_varnode(3, 8)
                u_s0 = self._unique_varnode(4, 8)
                u_s1 = self._unique_varnode(5, 8)
                u_s2 = self._unique_varnode(6, 8)
                u_s3 = self._unique_varnode(7, 8)
                u_or01 = self._unique_varnode(8, 8)
                u_or23 = self._unique_varnode(9, 8)
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(0x000000FF000000FF, 8)], u_b0, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [u_b0, self._const_varnode(24, 8)], u_s0, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(0x0000FF000000FF00, 8)], u_b1, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [u_b1, self._const_varnode(8, 8)], u_s1, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(0x00FF000000FF0000, 8)], u_b2, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [u_b2, self._const_varnode(8, 8)], u_s2, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(0xFF000000FF000000, 8)], u_b3, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [u_b3, self._const_varnode(24, 8)], u_s3, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_s0, u_s1], u_or01, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_s2, u_s3], u_or23, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_or01, u_or23], rd_dest, pc=pc))
                return ops

            elif (opc == 2 and sf == 0) or (opc == 3 and sf == 1):  # REV (32-bit or 64-bit)
                if sf == 0:  # 32-bit REV
                    u_b0 = self._unique_varnode(0, 4)
                    u_b1 = self._unique_varnode(1, 4)
                    u_b2 = self._unique_varnode(2, 4)
                    u_b3 = self._unique_varnode(3, 4)
                    u_s0 = self._unique_varnode(4, 4)
                    u_s1 = self._unique_varnode(5, 4)
                    u_s2 = self._unique_varnode(6, 4)
                    u_s3 = self._unique_varnode(7, 4)
                    u_or01 = self._unique_varnode(8, 4)
                    u_or23 = self._unique_varnode(9, 4)
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(0x000000FF, 4)], u_b0, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [u_b0, self._const_varnode(24, 4)], u_s0, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(0x0000FF00, 4)], u_b1, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [u_b1, self._const_varnode(8, 4)], u_s1, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(0x00FF0000, 4)], u_b2, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [u_b2, self._const_varnode(8, 4)], u_s2, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(0xFF000000, 4)], u_b3, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [u_b3, self._const_varnode(24, 4)], u_s3, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_s0, u_s1], u_or01, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_s2, u_s3], u_or23, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_or01, u_or23], rd_dest, pc=pc))
                    return ops
                else:  # 64-bit REV
                    shifts = [(0, 56, True), (1, 40, True), (2, 24, True), (3, 8, True),
                              (4, 8, False), (5, 24, False), (6, 40, False), (7, 56, False)]
                    shifted_nodes = []
                    for idx_b, amt, is_left in shifts:
                        mask = 0xFF << (idx_b * 8)
                        u_m = self._unique_varnode(idx_b * 2, 8)
                        u_s = self._unique_varnode(idx_b * 2 + 1, 8)
                        ops.append(PcodeOp(PcodeOpcode.INT_AND, [rn_node, self._const_varnode(mask, 8)], u_m, pc=pc))
                        shift_op = PcodeOpcode.INT_LEFT if is_left else PcodeOpcode.INT_RIGHT
                        ops.append(PcodeOp(shift_op, [u_m, self._const_varnode(amt, 8)], u_s, pc=pc))
                        shifted_nodes.append(u_s)

                    cur = shifted_nodes[0]
                    for j in range(1, 7):
                        u_accum = self._unique_varnode(16 + j, 8)
                        ops.append(PcodeOp(PcodeOpcode.INT_OR, [cur, shifted_nodes[j]], u_accum, pc=pc))
                        cur = u_accum
                    ops.append(PcodeOp(PcodeOpcode.INT_OR, [cur, shifted_nodes[7]], rd_dest, pc=pc))
                    return ops

        # 19. Load/Store Pair (LDP / STP): (insn & 0x3E000000) == 0x28000000
        if (insn & 0x3E000000) == 0x28000000:
            opc = (insn >> 30) & 3
            v_bit = (insn >> 26) & 1
            mode = (insn >> 23) & 3  # 00: non-temporal, 01: post-index, 10: signed offset, 11: pre-index
            is_load = (insn >> 22) & 1
            imm7 = (insn >> 15) & 0x7F
            if imm7 & 0x40:
                imm7 -= 0x80
            rt2 = (insn >> 10) & 0x1F
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F

            if v_bit:
                # SIMD regs: opc 00=4 (S), 01=8 (D), 10=16 (Q)
                scale = 4 if opc == 0 else (8 if opc == 1 else 16)
                is_ldpsw = False
                rt_dest = self._fp_varnode(rt, scale)
                rt2_dest = self._fp_varnode(rt2, scale)
                rt_src = self._fp_varnode(rt, scale)
                rt2_src = self._fp_varnode(rt2, scale)
            else:
                scale = 8 if (opc & 2) else 4
                is_ldpsw = (opc == 1 and is_load == 1)
                rt_dest = self._gpr_varnode(rt, scale, allow_sp=False, is_dest=True)
                rt2_dest = self._gpr_varnode(rt2, scale, allow_sp=False, is_dest=True)
                rt_src = self._gpr_varnode(rt, scale, allow_sp=False)
                rt2_src = self._gpr_varnode(rt2, scale, allow_sp=False)

            offset = imm7 * scale
            rn_node = self._gpr_varnode(rn, 8, allow_sp=True)
            rn_dest = self._gpr_varnode(rn, 8, allow_sp=True, is_dest=True)

            ops: List[PcodeOp] = []

            if mode == 3:  # 11: Pre-index (rn += offset, then access)
                u_ptr1 = self._unique_varnode(0, 8)
                u_ptr2 = self._unique_varnode(1, 8)
                if offset >= 0:
                    ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rn_node, self._const_varnode(offset, 8)], u_ptr1, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.INT_SUB, [rn_node, self._const_varnode(-offset, 8)], u_ptr1, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_ADD, [u_ptr1, self._const_varnode(scale, 8)], u_ptr2, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.COPY, [u_ptr1], rn_dest, pc=pc))
                if is_load:
                    if is_ldpsw:
                        u_l1 = self._unique_varnode(2, 4)
                        u_l2 = self._unique_varnode(3, 4)
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), u_ptr1], u_l1, pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.INT_SEXT, [u_l1], self._gpr_varnode(rt, 8, allow_sp=False, is_dest=True), pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), u_ptr2], u_l2, pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.INT_SEXT, [u_l2], self._gpr_varnode(rt2, 8, allow_sp=False, is_dest=True), pc=pc))
                    else:
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, scale), u_ptr1], rt_dest, pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, scale), u_ptr2], rt2_dest, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, scale), u_ptr1, rt_src], pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, scale), u_ptr2, rt2_src], pc=pc))
                return ops

            elif mode == 1:  # 01: Post-index (access at rn, then rn += offset)
                u_ptr1 = rn_node
                u_ptr2 = self._unique_varnode(1, 8)
                ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rn_node, self._const_varnode(scale, 8)], u_ptr2, pc=pc))
                u_wb = self._unique_varnode(0, 8)
                if offset >= 0:
                    ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rn_node, self._const_varnode(offset, 8)], u_wb, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.INT_SUB, [rn_node, self._const_varnode(-offset, 8)], u_wb, pc=pc))
                if is_load:
                    if is_ldpsw:
                        u_l1 = self._unique_varnode(2, 4)
                        u_l2 = self._unique_varnode(3, 4)
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), u_ptr1], u_l1, pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.INT_SEXT, [u_l1], self._gpr_varnode(rt, 8, allow_sp=False, is_dest=True), pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), u_ptr2], u_l2, pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.INT_SEXT, [u_l2], self._gpr_varnode(rt2, 8, allow_sp=False, is_dest=True), pc=pc))
                    else:
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, scale), u_ptr1], rt_dest, pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, scale), u_ptr2], rt2_dest, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, scale), u_ptr1, rt_src], pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, scale), u_ptr2, rt2_src], pc=pc))
                ops.append(PcodeOp(PcodeOpcode.COPY, [u_wb], rn_dest, pc=pc))
                return ops

            else:  # 00 non-temporal, 10 signed offset (no writeback)
                u_ptr1 = self._unique_varnode(0, 8)
                u_ptr2 = self._unique_varnode(1, 8)
                if offset >= 0:
                    ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rn_node, self._const_varnode(offset, 8)], u_ptr1, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.INT_SUB, [rn_node, self._const_varnode(-offset, 8)], u_ptr1, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_ADD, [u_ptr1, self._const_varnode(scale, 8)], u_ptr2, pc=pc))
                if is_load:
                    if is_ldpsw:
                        u_l1 = self._unique_varnode(2, 4)
                        u_l2 = self._unique_varnode(3, 4)
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), u_ptr1], u_l1, pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.INT_SEXT, [u_l1], self._gpr_varnode(rt, 8, allow_sp=False, is_dest=True), pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), u_ptr2], u_l2, pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.INT_SEXT, [u_l2], self._gpr_varnode(rt2, 8, allow_sp=False, is_dest=True), pc=pc))
                    else:
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, scale), u_ptr1], rt_dest, pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, scale), u_ptr2], rt2_dest, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, scale), u_ptr1, rt_src], pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, scale), u_ptr2, rt2_src], pc=pc))
                return ops

        # 20. Unscaled Immediate Load/Store (LDUR / STUR / LDURSW / LDURSH / LDURSB): (insn & 0x3B200C00) == 0x38000000
        if (insn & 0x3B200C00) == 0x38000000:
            size_code = (insn >> 30) & 3
            v_bit = (insn >> 26) & 1
            opc = (insn >> 22) & 3
            imm9 = (insn >> 12) & 0x1FF
            if imm9 & 0x100:
                imm9 -= 0x200
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F

            # PRFM (unscaled): size=3, opc=2, v_bit=0 => NOP
            if not v_bit and size_code == 3 and opc == 2:
                return []

            if v_bit:
                size = 16 if (opc & 2) else (1 << size_code)
            else:
                size = 1 << size_code

            rn_node = self._gpr_varnode(rn, 8, allow_sp=True)
            u_ptr = self._unique_varnode(0, 8)
            if imm9 >= 0:
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.INT_ADD,
                    inputs=[rn_node, self._const_varnode(imm9, 8)],
                    output=u_ptr,
                    pc=pc
                ))
            else:
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.INT_SUB,
                    inputs=[rn_node, self._const_varnode(-imm9, 8)],
                    output=u_ptr,
                    pc=pc
                ))

            if v_bit:
                if (opc & 1) == 0:  # STUR (SIMD)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.STORE,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr, self._fp_varnode(rt, size)],
                        pc=pc
                    ))
                else:  # LDUR (SIMD)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                        output=self._fp_varnode(rt, size),
                        pc=pc
                    ))
            else:
                if opc == 0:  # STUR
                    rt_src = self._gpr_varnode(rt, size, allow_sp=False)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.STORE,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr, rt_src],
                        pc=pc
                    ))
                elif opc == 1:  # LDUR
                    rt_dest = self._gpr_varnode(rt, size, allow_sp=False, is_dest=True)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                        output=rt_dest,
                        pc=pc
                    ))
                elif opc == 2:  # LDURSW / LDURSH / LDURSB (sign-extend to 64-bit)
                    u_load = self._unique_varnode(1, size)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                        output=u_load,
                        pc=pc
                    ))
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.INT_SEXT,
                        inputs=[u_load],
                        output=self._gpr_varnode(rt, 8, allow_sp=False, is_dest=True),
                        pc=pc
                    ))
                elif opc == 3:  # LDURSH / LDURSB (sign-extend to 32-bit)
                    u_load = self._unique_varnode(1, size)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                        output=u_load,
                        pc=pc
                    ))
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.INT_SEXT,
                        inputs=[u_load],
                        output=self._gpr_varnode(rt, 4, allow_sp=False, is_dest=True),
                        pc=pc
                    ))
            return ops

        # 20b. Pre/Post-Indexed Immediate Load/Store: (insn & 0x3B200400) == 0x38000400
        if (insn & 0x3B200400) == 0x38000400:
            size_code = (insn >> 30) & 3
            v_bit = (insn >> 26) & 1
            opc = (insn >> 22) & 3
            imm9 = (insn >> 12) & 0x1FF
            if imm9 & 0x100:
                imm9 -= 0x200
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            is_pre = (insn & 0x00000800) != 0

            # PRFM: size=3, opc=2, v_bit=0 => NOP
            if not v_bit and size_code == 3 and opc == 2:
                return []

            if v_bit:
                size = 16 if (opc & 2) else (1 << size_code)
            else:
                size = 1 << size_code

            rn_node = self._gpr_varnode(rn, 8, allow_sp=True)
            rn_dest = self._gpr_varnode(rn, 8, allow_sp=True, is_dest=True)

            ops: List[PcodeOp] = []

            if is_pre:
                u_ptr = self._unique_varnode(0, 8)
                if imm9 >= 0:
                    ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rn_node, self._const_varnode(imm9, 8)], u_ptr, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.INT_SUB, [rn_node, self._const_varnode(-imm9, 8)], u_ptr, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.COPY, [u_ptr], rn_dest, pc=pc))
                target_ptr = u_ptr
            else:
                target_ptr = rn_node

            if v_bit:
                if (opc & 1) == 0:  # STR
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.STORE,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), target_ptr, self._fp_varnode(rt, size)],
                        pc=pc
                    ))
                else:  # LDR
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), target_ptr],
                        output=self._fp_varnode(rt, size),
                        pc=pc
                    ))
            else:
                if opc == 0:  # STR
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.STORE,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), target_ptr, self._gpr_varnode(rt, size, allow_sp=False)],
                        pc=pc
                    ))
                elif opc == 1:  # LDR
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), target_ptr],
                        output=self._gpr_varnode(rt, size, allow_sp=False, is_dest=True),
                        pc=pc
                    ))
                elif opc == 2:  # LDRSW / LDRSH / LDRSB (sign-extend to 64-bit)
                    u_load = self._unique_varnode(1, size)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), target_ptr],
                        output=u_load,
                        pc=pc
                    ))
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.INT_SEXT,
                        inputs=[u_load],
                        output=self._gpr_varnode(rt, 8, allow_sp=False, is_dest=True),
                        pc=pc
                    ))
                elif opc == 3:  # LDRSH / LDRSB (sign-extend to 32-bit)
                    u_load = self._unique_varnode(1, size)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), target_ptr],
                        output=u_load,
                        pc=pc
                    ))
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.INT_SEXT,
                        inputs=[u_load],
                        output=self._gpr_varnode(rt, 4, allow_sp=False, is_dest=True),
                        pc=pc
                    ))

            # Post-index Writeback
            if not is_pre:
                if imm9 >= 0:
                    ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rn_node, self._const_varnode(imm9, 8)], rn_dest, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.INT_SUB, [rn_node, self._const_varnode(-imm9, 8)], rn_dest, pc=pc))

            return ops

        # 21. LDR (unsigned immediate / LDRSW / LDRSH / LDRSB, V=0): (insn & 0x3F000000) == 0x39000000
        if (insn & 0x3F000000) == 0x39000000:
            size_code = (insn >> 30) & 3
            size = 1 << size_code  # 1, 2, 4, 8 bytes
            opc = (insn >> 22) & 3

            # PRFM (unsigned immediate): size=3, opc=2 => NOP
            if size_code == 3 and opc == 2:
                return []

            rt = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            imm12 = (insn >> 10) & 0xFFF
            offset = imm12 * size
            # Temporary ptr = rn + offset
            u_ptr = self._unique_varnode(0, 8)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.INT_ADD,
                inputs=[self._gpr_varnode(rn, 8, allow_sp=True), self._const_varnode(offset, 8)],
                output=u_ptr,
                pc=pc
            ))
            if opc == 0:
                # STR (unsigned immediate, V=0, opc=0)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.STORE,
                    inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr, self._gpr_varnode(rt, size, allow_sp=False)],
                    pc=pc
                ))
            elif opc == 1:
                # LOAD rt = ram[u_ptr]
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.LOAD,
                    inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                    output=self._gpr_varnode(rt, size, allow_sp=False, is_dest=True),
                    pc=pc
                ))
            elif opc == 2:  # LDRSW / LDRSH / LDRSB (sign-extend to 64-bit)
                u_load = self._unique_varnode(1, size)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.LOAD,
                    inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                    output=u_load,
                    pc=pc
                ))
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.INT_SEXT,
                    inputs=[u_load],
                    output=self._gpr_varnode(rt, 8, allow_sp=False, is_dest=True),
                    pc=pc
                ))
            elif opc == 3:  # LDRSH / LDRSB (sign-extend to 32-bit)
                u_load = self._unique_varnode(1, size)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.LOAD,
                    inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                    output=u_load,
                    pc=pc
                ))
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.INT_SEXT,
                    inputs=[u_load],
                    output=self._gpr_varnode(rt, 4, allow_sp=False, is_dest=True),
                    pc=pc
                ))
            return ops

        # 22. Load/Store Register (register offset) & Atomic Memory Operations:
        if (insn & 0x3F000000) == 0x38000000:
            is_reg_offset = (((insn >> 21) & 1) == 1) and (((insn >> 10) & 3) == 2)
            is_atomic_op = (((insn >> 21) & 1) == 1) and (((insn >> 10) & 3) == 0) and (insn != 0x38200000)
            if not is_reg_offset and not is_atomic_op:
                return [PcodeOp(PcodeOpcode.UNIMPLEMENTED, [], None, pc=pc)]

            if is_atomic_op:
                size_code = (insn >> 30) & 3
                size = 1 << size_code  # 1, 2, 4, or 8 bytes
                rs = (insn >> 16) & 0x1F  # Operand register
                opc = (insn >> 12) & 0xF
                rn = (insn >> 5) & 0x1F   # Base address
                rt = insn & 0x1F          # Destination for loaded old value
                rn_node = self._gpr_varnode(rn, 8, allow_sp=True)
                u_old = self._unique_varnode(0, size)
                ops: List[PcodeOp] = []
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.LOAD,
                    inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), rn_node],
                    output=u_old,
                    pc=pc
                ))
                if opc == 8:  # SWP: atomic swap
                    u_res = self._gpr_varnode(rs, size, allow_sp=False)
                elif opc == 0:  # LDADD: atomic add
                    u_res = self._unique_varnode(1, size)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.INT_ADD,
                        inputs=[u_old, self._gpr_varnode(rs, size, allow_sp=False)],
                        output=u_res,
                        pc=pc
                    ))
                elif opc == 1:  # LDCLR: atomic bit clear ([rn] & ~rs)
                    u_inv = self._unique_varnode(1, size)
                    u_res = self._unique_varnode(2, size)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.INT_NEGATE,
                        inputs=[self._gpr_varnode(rs, size, allow_sp=False)],
                        output=u_inv,
                        pc=pc
                    ))
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.INT_AND,
                        inputs=[u_old, u_inv],
                        output=u_res,
                        pc=pc
                    ))
                elif opc == 2:  # LDEOR: atomic bitwise exclusive-or
                    u_res = self._unique_varnode(1, size)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.INT_XOR,
                        inputs=[u_old, self._gpr_varnode(rs, size, allow_sp=False)],
                        output=u_res,
                        pc=pc
                    ))
                elif opc == 3:  # LDSET: atomic bitwise inclusive-or
                    u_res = self._unique_varnode(1, size)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.INT_OR,
                        inputs=[u_old, self._gpr_varnode(rs, size, allow_sp=False)],
                        output=u_res,
                        pc=pc
                    ))
                else:
                    u_res = self._gpr_varnode(rs, size, allow_sp=False)

                ops.append(PcodeOp(
                    opcode=PcodeOpcode.STORE,
                    inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), rn_node, u_res],
                    pc=pc
                ))
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.COPY,
                    inputs=[u_old],
                    output=self._gpr_varnode(rt, size, allow_sp=False, is_dest=True),
                    pc=pc
                ))
                return ops

            size_code = (insn >> 30) & 3
            v_bit = (insn >> 26) & 1
            opc = (insn >> 22) & 3
            rm = (insn >> 16) & 0x1F
            option = (insn >> 13) & 7
            s_bit = (insn >> 12) & 1
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F

            # PRFM (register offset): size=3, opc=2, v_bit=0 => NOP
            if not v_bit and size_code == 3 and opc == 2:
                return []

            if v_bit:
                size = 16 if (opc & 2) else (1 << size_code)
                shift = 4 if (opc & 2) else size_code
            else:
                size = 1 << size_code
                shift = size_code

            ops: List[PcodeOp] = []

            # Decode Rm extension
            # 010: UXTW (32-bit zero extended)
            # 011: LSL / UXTX (64-bit)
            # 110: SXTW (32-bit sign extended)
            # 111: SXTX (64-bit)
            if option == 2:  # UXTW
                u_ext = self._unique_varnode(0, 8)
                ops.append(PcodeOp(PcodeOpcode.INT_ZEXT, [self._gpr_varnode(rm, 4)], u_ext, pc=pc))
                rm_val = u_ext
            elif option == 6:  # SXTW
                u_ext = self._unique_varnode(0, 8)
                ops.append(PcodeOp(PcodeOpcode.INT_SEXT, [self._gpr_varnode(rm, 4)], u_ext, pc=pc))
                rm_val = u_ext
            else:  # 3 (LSL/UXTX) or 7 (SXTX) or default
                rm_val = self._gpr_varnode(rm, 8)

            shift_amt = shift if s_bit else 0
            if shift_amt > 0:
                u_shifted = self._unique_varnode(1, 8)
                ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [rm_val, self._const_varnode(shift_amt, 8)], u_shifted, pc=pc))
                offset_val = u_shifted
            else:
                offset_val = rm_val

            rn_node = self._gpr_varnode(rn, 8, allow_sp=True)
            u_ptr = self._unique_varnode(2, 8)
            ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rn_node, offset_val], u_ptr, pc=pc))

            if v_bit:
                if (opc & 1) == 0:  # STR (SIMD)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.STORE,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr, self._fp_varnode(rt, size)],
                        pc=pc
                    ))
                else:  # LDR (SIMD)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                        output=self._fp_varnode(rt, size),
                        pc=pc
                    ))
            else:
                if opc == 0:  # STR
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.STORE,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr, self._gpr_varnode(rt, size, allow_sp=False)],
                        pc=pc
                    ))
                elif opc == 1:  # LDR
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                        output=self._gpr_varnode(rt, size, allow_sp=False, is_dest=True),
                        pc=pc
                    ))
                elif opc == 2:  # LDRS* (sign-extend to 64-bit)
                    u_load = self._unique_varnode(3, size)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                        output=u_load,
                        pc=pc
                    ))
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.INT_SEXT,
                        inputs=[u_load],
                        output=self._gpr_varnode(rt, 8, allow_sp=False, is_dest=True),
                        pc=pc
                    ))
                elif opc == 3:  # LDRS* (sign-extend to 32-bit)
                    u_load = self._unique_varnode(3, size)
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.LOAD,
                        inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                        output=u_load,
                        pc=pc
                    ))
                    ops.append(PcodeOp(
                        opcode=PcodeOpcode.INT_SEXT,
                        inputs=[u_load],
                        output=self._gpr_varnode(rt, 4, allow_sp=False, is_dest=True),
                        pc=pc
                    ))
            return ops

        # 23. Scalar Floating-Point Data-Processing (2-source: FMUL, FDIV, FADD, FSUB): (insn & 0x5F200C00) == 0x1E200800
        if (insn & 0x5F200C00) == 0x1E200800:
            ftype = (insn >> 22) & 3
            size = 4 if ftype == 0 else (8 if ftype == 1 else 2)
            rm = (insn >> 16) & 0x1F
            fp_opc = (insn >> 12) & 0xF
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            op_map = {
                0: PcodeOpcode.FLOAT_MULT,
                1: PcodeOpcode.FLOAT_DIV,
                2: PcodeOpcode.FLOAT_ADD,
                3: PcodeOpcode.FLOAT_SUB,
            }
            if fp_opc in op_map:
                ops.append(PcodeOp(
                    opcode=op_map[fp_opc],
                    inputs=[self._fp_varnode(rn, size), self._fp_varnode(rm, size)],
                    output=self._fp_varnode(rd, size),
                    pc=pc
                ))
                return ops

        # 24. Scalar Floating-Point Unary (FMOV reg, FABS, FNEG, FSQRT, FCVT): (insn & 0x5F207C00) == 0x1E204000
        if (insn & 0x5F207C00) == 0x1E204000:
            ftype = (insn >> 22) & 3
            size = 4 if ftype == 0 else (8 if ftype == 1 else 2)
            opc = (insn >> 15) & 0x3F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            if opc == 0:
                ops.append(PcodeOp(PcodeOpcode.COPY, [self._fp_varnode(rn, size)], self._fp_varnode(rd, size), pc=pc))
                return ops
            elif opc == 1:
                ops.append(PcodeOp(PcodeOpcode.FLOAT_ABS, [self._fp_varnode(rn, size)], self._fp_varnode(rd, size), pc=pc))
                return ops
            elif opc == 2:
                ops.append(PcodeOp(PcodeOpcode.FLOAT_NEG, [self._fp_varnode(rn, size)], self._fp_varnode(rd, size), pc=pc))
                return ops
            elif opc == 3:
                ops.append(PcodeOp(PcodeOpcode.FLOAT_SQRT, [self._fp_varnode(rn, size)], self._fp_varnode(rd, size), pc=pc))
                return ops
            elif opc in (4, 5, 7):
                dst_size = 4 if opc == 4 else (8 if opc == 5 else 2)
                ops.append(PcodeOp(PcodeOpcode.FLOAT_FLOAT2FLOAT, [self._fp_varnode(rn, size)], self._fp_varnode(rd, dst_size), pc=pc))
                return ops

        # 25. Scalar Floating-Point Compare (FCMP / FCMPE): (insn & 0x5F203C00) == 0x1E202000
        if (insn & 0x5F203C00) == 0x1E202000:
            ftype = (insn >> 22) & 3
            size = 4 if ftype == 0 else (8 if ftype == 1 else 2)
            rm = (insn >> 16) & 0x1F
            rn = (insn >> 5) & 0x1F
            opc2 = insn & 0x1F
            lhs = self._fp_varnode(rn, size)
            rhs = self._const_varnode(0, size) if (opc2 & 8) else self._fp_varnode(rm, size)
            self._last_cmp_operands = ("FCMP", lhs, rhs, size, True)
            ops.append(PcodeOp(PcodeOpcode.FLOAT_EQUAL, [lhs, rhs], self._flag_varnode(self.FLAG_Z_OFFSET), pc=pc))
            ops.append(PcodeOp(PcodeOpcode.FLOAT_LESS, [lhs, rhs], self._flag_varnode(self.FLAG_N_OFFSET), pc=pc))
            return ops

        # 26. Scalar Floating-Point Conditional Select (FCSEL): (insn & 0x5F200C00) == 0x1E200C00
        if (insn & 0x5F200C00) == 0x1E200C00:
            ftype = (insn >> 22) & 3
            size = 4 if ftype == 0 else (8 if ftype == 1 else 2)
            rm = (insn >> 16) & 0x1F
            cond = (insn >> 12) & 0xF
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            u_cond = self._unique_varnode(0, 1)
            ops.extend(self._emit_condition_check(pc, cond, u_cond))
            u_zext = self._unique_varnode(1, size)
            u_mask = self._unique_varnode(2, size)
            u_not_mask = self._unique_varnode(3, size)
            u_t = self._unique_varnode(4, size)
            u_f = self._unique_varnode(5, size)
            ops.append(PcodeOp(PcodeOpcode.INT_ZEXT, [u_cond], u_zext, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_2COMP, [u_zext], u_mask, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_NEGATE, [u_mask], u_not_mask, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_AND, [self._fp_varnode(rn, size), u_mask], u_t, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_AND, [self._fp_varnode(rm, size), u_not_mask], u_f, pc=pc))
            ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_t, u_f], self._fp_varnode(rd, size), pc=pc))
            return ops

        # 27. Floating-Point <-> Integer Conversions & General FMOV (SCVTF, UCVTF, FCVTZS, FCVTZU, FMOV): (insn & 0x5F20FC00) == 0x1E200000
        if (insn & 0x5F20FC00) == 0x1E200000:
            sf = (insn >> 31) & 1
            int_size = 8 if sf else 4
            ftype = (insn >> 22) & 3
            fp_size = 4 if ftype == 0 else (8 if ftype == 1 else 2)
            rmode = (insn >> 19) & 3
            conv_opc = (insn >> 16) & 7
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            if conv_opc in (2, 3) and rmode == 0:  # SCVTF / UCVTF
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.FLOAT_INT2FLOAT,
                    inputs=[self._gpr_varnode(rn, int_size, allow_sp=False)],
                    output=self._fp_varnode(rd, fp_size),
                    pc=pc
                ))
                return ops
            elif conv_opc in (0, 1) and rmode == 3:  # FCVTZS / FCVTZU
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.FLOAT_TRUNC,
                    inputs=[self._fp_varnode(rn, fp_size)],
                    output=self._gpr_varnode(rd, int_size, allow_sp=False, is_dest=True),
                    pc=pc
                ))
                return ops
            elif conv_opc == 6 and rmode == 0:  # FMOV GPR, FP
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.COPY,
                    inputs=[self._fp_varnode(rn, fp_size)],
                    output=self._gpr_varnode(rd, int_size, allow_sp=False, is_dest=True),
                    pc=pc
                ))
                return ops
            elif conv_opc == 7 and rmode == 0:  # FMOV FP, GPR
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.COPY,
                    inputs=[self._gpr_varnode(rn, int_size, allow_sp=False)],
                    output=self._fp_varnode(rd, fp_size),
                    pc=pc
                ))
                return ops

        # 28. SIMD & FP Load/Store Unsigned Immediate (LDR/STR B/H/S/D/Q): (insn & 0x3F000000) == 0x3D000000
        if (insn & 0x3F000000) == 0x3D000000:
            size_code = (insn >> 30) & 3
            opc = (insn >> 22) & 3
            scale = 4 if (size_code == 0 and (opc & 2)) else size_code
            size = 1 << scale  # 1, 2, 4, 8, or 16 bytes
            imm12 = (insn >> 10) & 0xFFF
            offset = imm12 * size
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            u_ptr = self._unique_varnode(0, 8)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.INT_ADD,
                inputs=[self._gpr_varnode(rn, 8, allow_sp=True), self._const_varnode(offset, 8)],
                output=u_ptr,
                pc=pc
            ))
            if (opc & 1) == 1:  # LDR (SIMD&FP)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.LOAD,
                    inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr],
                    output=self._fp_varnode(rt, size),
                    pc=pc
                ))
            else:  # STR (SIMD&FP)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.STORE,
                    inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), u_ptr, self._fp_varnode(rt, size)],
                    pc=pc
                ))
            return ops

        # 29. ARM64 Load/Store Exclusive / Atomic Ops (LDXR, STXR, LDAR, STLR): (insn & 0x3F200000) == 0x08000000
        if (insn & 0x3F200000) == 0x08000000:
            size_code = (insn >> 30) & 3
            size = 1 << size_code  # 1, 2, 4, or 8 bytes
            l_bit = (insn >> 22) & 1  # 1=Load (LDXR/LDAR), 0=Store (STXR/STLR)
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            rn_node = self._gpr_varnode(rn, 8, allow_sp=True)
            if l_bit == 1:
                # LDXR / LDAR: rt = [rn]
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.LOAD,
                    inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), rn_node],
                    output=self._gpr_varnode(rt, size, allow_sp=False, is_dest=True),
                    pc=pc
                ))
                return ops
            else:
                # STXR / STLR: [rn] = rt, rs = 0
                rs = (insn >> 16) & 0x1F
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.STORE,
                    inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), rn_node, self._gpr_varnode(rt, size, allow_sp=False)],
                    pc=pc
                ))
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.COPY,
                    inputs=[self._const_varnode(0, 4)],
                    output=self._gpr_varnode(rs, 4, allow_sp=False, is_dest=True),
                    pc=pc
                ))
                return ops

        # 30. ARMv8.1-A Compare and Swap (CAS, CASA, CASL, CASAL): (insn & 0x3FA07C00) == 0x08A07C00
        if (insn & 0x3FA07C00) == 0x08A07C00:
            size_code = (insn >> 30) & 3
            size = 1 << size_code  # 1, 2, 4, or 8 bytes
            rs = (insn >> 16) & 0x1F  # Expected value / comparand
            rn = (insn >> 5) & 0x1F   # Memory base address
            rt = insn & 0x1F          # Desired new value
            rn_node = self._gpr_varnode(rn, 8, allow_sp=True)
            u_old = self._unique_varnode(0, size)
            ops.append(PcodeOp(
                opcode=PcodeOpcode.LOAD,
                inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), rn_node],
                output=u_old,
                pc=pc
            ))
            ops.append(PcodeOp(
                opcode=PcodeOpcode.STORE,
                inputs=[Varnode(space=AddressSpace.RAM, offset=0, size=size), rn_node, self._gpr_varnode(rt, size, allow_sp=False)],
                pc=pc
            ))
            ops.append(PcodeOp(
                opcode=PcodeOpcode.COPY,
                inputs=[u_old],
                output=self._gpr_varnode(rs, size, allow_sp=False, is_dest=True),
                pc=pc
            ))
            return ops



        # 32. SIMD 3-Same Vector Bitwise (AND, BIC, ORR, ORN, EOR, BSL, BIT, BIF): (insn & 0xBF20F400) == 0x0E201C00
        if (insn & 0x9F20F400) == 0x0E201400:
            q_bit = (insn >> 30) & 1
            u_bit = (insn >> 29) & 1
            size_code = (insn >> 22) & 3
            vec_size = 16 if q_bit else 8
            rm = (insn >> 16) & 0x1F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F
            v_rn = self._fp_varnode(rn, vec_size)
            v_rm = self._fp_varnode(rm, vec_size)
            v_rd = self._fp_varnode(rd, vec_size)

            if u_bit == 0:
                if size_code == 0:  # AND
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [v_rn, v_rm], v_rd, pc=pc))
                    return ops
                elif size_code == 1:  # BIC (rn AND NOT rm)
                    u_not = self._unique_varnode(0, vec_size)
                    ops.append(PcodeOp(PcodeOpcode.INT_NEGATE, [v_rm], u_not, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [v_rn, u_not], v_rd, pc=pc))
                    return ops
                elif size_code == 2:  # ORR
                    ops.append(PcodeOp(PcodeOpcode.INT_OR, [v_rn, v_rm], v_rd, pc=pc))
                    return ops
                elif size_code == 3:  # ORN (rn OR NOT rm)
                    u_not = self._unique_varnode(0, vec_size)
                    ops.append(PcodeOp(PcodeOpcode.INT_NEGATE, [v_rm], u_not, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_OR, [v_rn, u_not], v_rd, pc=pc))
                    return ops
            else:
                if size_code == 0:  # EOR
                    ops.append(PcodeOp(PcodeOpcode.INT_XOR, [v_rn, v_rm], v_rd, pc=pc))
                    return ops
                elif size_code == 1:  # BSL: rd = (rd & rn) | (~rd & rm)
                    u_t = self._unique_varnode(0, vec_size)
                    u_f = self._unique_varnode(1, vec_size)
                    u_not_rd = self._unique_varnode(2, vec_size)
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [v_rd, v_rn], u_t, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_NEGATE, [v_rd], u_not_rd, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [u_not_rd, v_rm], u_f, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_t, u_f], v_rd, pc=pc))
                    return ops
                elif size_code == 2:  # BIT: rd = (rm & rn) | (~rm & rd)
                    u_t = self._unique_varnode(0, vec_size)
                    u_f = self._unique_varnode(1, vec_size)
                    u_not_rm = self._unique_varnode(2, vec_size)
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [v_rm, v_rn], u_t, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_NEGATE, [v_rm], u_not_rm, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [u_not_rm, v_rd], u_f, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_t, u_f], v_rd, pc=pc))
                    return ops
                elif size_code == 3:  # BIF: rd = (~rm & rn) | (rm & rd)
                    u_t = self._unique_varnode(0, vec_size)
                    u_f = self._unique_varnode(1, vec_size)
                    u_not_rm = self._unique_varnode(2, vec_size)
                    ops.append(PcodeOp(PcodeOpcode.INT_NEGATE, [v_rm], u_not_rm, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [u_not_rm, v_rn], u_t, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_AND, [v_rm, v_rd], u_f, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_t, u_f], v_rd, pc=pc))
                    return ops

        # 33. SIMD Vector Integer Arithmetic & Pairwise (ADD, SUB, ADDP, MUL): (insn & 0xBF200400) == 0x0E200400
        if (insn & 0x9F200400) == 0x0E200400:
            q_bit = (insn >> 30) & 1
            u_bit = (insn >> 29) & 1
            size_code = (insn >> 22) & 3
            elem_size = 1 << size_code  # 1, 2, 4, or 8 bytes
            vec_size = 16 if q_bit else 8
            rm = (insn >> 16) & 0x1F
            sub_opc = (insn >> 11) & 0x1F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F

            if sub_opc == 0x10 and u_bit == 0:  # ADD (vector)
                num_lanes = vec_size // elem_size
                for lane in range(num_lanes):
                    lane_offset = lane * elem_size
                    u_a = self._unique_varnode(lane * 3, elem_size)
                    u_b = self._unique_varnode(lane * 3 + 1, elem_size)
                    u_res = self._unique_varnode(lane * 3 + 2, elem_size)
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rn, vec_size), self._const_varnode(lane_offset, 4)], u_a, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rm, vec_size), self._const_varnode(lane_offset, 4)], u_b, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_ADD, [u_a, u_b], u_res, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_ADD, [self._fp_varnode(rn, vec_size), self._fp_varnode(rm, vec_size)], self._fp_varnode(rd, vec_size), pc=pc))
                return ops
            elif sub_opc == 0x10 and u_bit == 1:  # SUB (vector)
                num_lanes = vec_size // elem_size
                for lane in range(num_lanes):
                    lane_offset = lane * elem_size
                    u_a = self._unique_varnode(lane * 3, elem_size)
                    u_b = self._unique_varnode(lane * 3 + 1, elem_size)
                    u_res = self._unique_varnode(lane * 3 + 2, elem_size)
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rn, vec_size), self._const_varnode(lane_offset, 4)], u_a, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rm, vec_size), self._const_varnode(lane_offset, 4)], u_b, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_SUB, [u_a, u_b], u_res, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_SUB, [self._fp_varnode(rn, vec_size), self._fp_varnode(rm, vec_size)], self._fp_varnode(rd, vec_size), pc=pc))
                return ops
            elif sub_opc == 0x17 and u_bit == 0:  # ADDP (pairwise add vector)
                num_lanes = vec_size // elem_size
                half_lanes = num_lanes // 2
                for i in range(half_lanes):
                    u_a0 = self._unique_varnode(1 + i * 3, elem_size)
                    u_a1 = self._unique_varnode(1 + i * 3 + 1, elem_size)
                    u_s = self._unique_varnode(1 + i * 3 + 2, elem_size)
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rn, vec_size), self._const_varnode(2 * i * elem_size, 4)], u_a0, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rn, vec_size), self._const_varnode((2 * i + 1) * elem_size, 4)], u_a1, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_ADD, [u_a0, u_a1], u_s, pc=pc))
                for i in range(half_lanes):
                    u_b0 = self._unique_varnode(100 + i * 3, elem_size)
                    u_b1 = self._unique_varnode(100 + i * 3 + 1, elem_size)
                    u_s = self._unique_varnode(100 + i * 3 + 2, elem_size)
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rm, vec_size), self._const_varnode(2 * i * elem_size, 4)], u_b0, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rm, vec_size), self._const_varnode((2 * i + 1) * elem_size, 4)], u_b1, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_ADD, [u_b0, u_b1], u_s, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_ADD, [self._fp_varnode(rn, vec_size), self._fp_varnode(rm, vec_size)], self._fp_varnode(rd, vec_size), pc=pc))
                return ops
            elif sub_opc == 0x13 and u_bit == 0:  # MUL (vector)
                num_lanes = vec_size // elem_size
                for lane in range(num_lanes):
                    lane_offset = lane * elem_size
                    u_a = self._unique_varnode(lane * 3, elem_size)
                    u_b = self._unique_varnode(lane * 3 + 1, elem_size)
                    u_res = self._unique_varnode(lane * 3 + 2, elem_size)
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rn, vec_size), self._const_varnode(lane_offset, 4)], u_a, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rm, vec_size), self._const_varnode(lane_offset, 4)], u_b, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.INT_MULT, [u_a, u_b], u_res, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_MULT, [self._fp_varnode(rn, vec_size), self._fp_varnode(rm, vec_size)], self._fp_varnode(rd, vec_size), pc=pc))
                return ops

        # 34. SIMD Vector Floating-Point 3-Same & Pairwise (FADD, FSUB, FMUL, FDIV, FADDP): (insn & 0x9F200400) == 0x0E200400
        if (insn & 0x9F200400) == 0x0E200400:
            q_bit = (insn >> 30) & 1
            u_bit = (insn >> 29) & 1
            sz_raw = (insn >> 22) & 3
            # sz bit 22: 0=Single (4 bytes), 1=Double (8 bytes)
            # sz bit 23: for sub_opc=0x1A, bit 23 determines FADD (0) vs FSUB (1)
            fp_elem_size = 8 if (sz_raw & 1) else 4
            vec_size = 16 if q_bit else 8
            rm = (insn >> 16) & 0x1F
            sub_opc = (insn >> 11) & 0x1F
            rn = (insn >> 5) & 0x1F
            rd = insn & 0x1F

            op_type = None
            if sub_opc == 0x1A:
                if (sz_raw & 2) == 0:
                    # FADD (u_bit=0) or FADDP (u_bit=1)
                    op_type = PcodeOpcode.FLOAT_ADD
                else:
                    # FSUB (u_bit=0)
                    if u_bit == 0:
                        op_type = PcodeOpcode.FLOAT_SUB
            elif sub_opc == 0x1B and u_bit == 1:
                # FMUL
                op_type = PcodeOpcode.FLOAT_MULT
            elif sub_opc == 0x1F and u_bit == 1:
                # FDIV
                op_type = PcodeOpcode.FLOAT_DIV

            if op_type is not None:
                num_lanes = vec_size // fp_elem_size
                for lane in range(num_lanes):
                    lane_offset = lane * fp_elem_size
                    u_a = self._unique_varnode(lane * 3, fp_elem_size)
                    u_b = self._unique_varnode(lane * 3 + 1, fp_elem_size)
                    u_res = self._unique_varnode(lane * 3 + 2, fp_elem_size)
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rn, vec_size), self._const_varnode(lane_offset, 4)], u_a, pc=pc))
                    ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [self._fp_varnode(rm, vec_size), self._const_varnode(lane_offset, 4)], u_b, pc=pc))
                    ops.append(PcodeOp(op_type, [u_a, u_b], u_res, pc=pc))
                ops.append(PcodeOp(op_type, [self._fp_varnode(rn, vec_size), self._fp_varnode(rm, vec_size)], self._fp_varnode(rd, vec_size), pc=pc))
                return ops

        # 35. ARM64 Cryptographic Extension Instructions
        # (a) AES single-round encryption/decryption & mix columns (2-register)
        # Format: 0100 1110 0010 1000 01xx 10[Rn:5][Rd:5]
        # Mask: 0xFFFF0C00 == 0x4E280800
        if (insn & 0xFFFF0C00) == 0x4E280800:
            sub_op = (insn >> 12) & 0xF
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            vd = self._fp_varnode(rd, 16)
            vn = self._fp_varnode(rn, 16)
            if sub_op == 0x4:  # AESE: Vd = AESE(Vd, Vn)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.CALLOTHER,
                    inputs=[Varnode(AddressSpace.CONST, "arm64_aese"), vd, vn],
                    output=vd,
                    pc=pc
                ))
                return ops
            elif sub_op == 0x5:  # AESD: Vd = AESD(Vd, Vn)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.CALLOTHER,
                    inputs=[Varnode(AddressSpace.CONST, "arm64_aesd"), vd, vn],
                    output=vd,
                    pc=pc
                ))
                return ops
            elif sub_op == 0x6:  # AESMC: Vd = AESMC(Vn)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.CALLOTHER,
                    inputs=[Varnode(AddressSpace.CONST, "arm64_aesmc"), vn],
                    output=vd,
                    pc=pc
                ))
                return ops
            elif sub_op == 0x7:  # AESIMC: Vd = AESIMC(Vn)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.CALLOTHER,
                    inputs=[Varnode(AddressSpace.CONST, "arm64_aesimc"), vn],
                    output=vd,
                    pc=pc
                ))
                return ops

        # (b) SHA-1 & SHA-256 3-register extension
        # Format: 0101 1110 000 [Rm:5] [opcode:4] 00 [Rn:5] [Rd:5]
        # Mask: 0xFFE0FC00
        if (insn & 0xFFE00000) == 0x5E000000 and (insn & 0x00000C00) == 0:
            sub_op = (insn >> 12) & 0xF
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            rm = (insn >> 16) & 0x1F
            vd = self._fp_varnode(rd, 16)
            vn = self._fp_varnode(rn, 16)
            vm = self._fp_varnode(rm, 16)
            sha_3reg_map = {
                0x0: "arm64_sha1c",
                0x1: "arm64_sha1p",
                0x2: "arm64_sha1m",
                0x3: "arm64_sha1su0",
                0x4: "arm64_sha256h",
                0x5: "arm64_sha256h2",
                0x6: "arm64_sha256su1",
            }
            if sub_op in sha_3reg_map:
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.CALLOTHER,
                    inputs=[Varnode(AddressSpace.CONST, sha_3reg_map[sub_op]), vd, vn, vm],
                    output=vd,
                    pc=pc
                ))
                return ops

        # (c) SHA-1 & SHA-256 2-register extension
        # Format: 0101 1110 0010 1000 00xx 10 [Rn:5] [Rd:5]
        # Mask: 0xFFFF0C00 == 0x5E280800
        if (insn & 0xFFFF0C00) == 0x5E280800:
            sub_op = (insn >> 12) & 0xF
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            vd = self._fp_varnode(rd, 16)
            vn = self._fp_varnode(rn, 16)
            if sub_op == 0x0:  # SHA1H: Sd = SHA1H(Sn)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.CALLOTHER,
                    inputs=[Varnode(AddressSpace.CONST, "arm64_sha1h"), vn],
                    output=vd,
                    pc=pc
                ))
                return ops
            elif sub_op == 0x1:  # SHA1SU1: Vd = SHA1SU1(Vd, Vn)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.CALLOTHER,
                    inputs=[Varnode(AddressSpace.CONST, "arm64_sha1su1"), vd, vn],
                    output=vd,
                    pc=pc
                ))
                return ops
            elif sub_op == 0x2:  # SHA256SU0: Vd = SHA256SU0(Vd, Vn)
                ops.append(PcodeOp(
                    opcode=PcodeOpcode.CALLOTHER,
                    inputs=[Varnode(AddressSpace.CONST, "arm64_sha256su0"), vd, vn],
                    output=vd,
                    pc=pc
                ))
                return ops

        # Generic / Fallback Unimplemented Op
        ops.append(PcodeOp(
            opcode=PcodeOpcode.UNIMPLEMENTED,
            inputs=[self._const_varnode(insn, 4)],
            pc=pc
        ))
        return ops

    def lift_block(self, base_pc: int, machine_bytes: bytes) -> List[PcodeOp]:
        """Lifts a block of contiguous 4-byte ARM64 instructions."""
        all_ops: List[PcodeOp] = []
        for i in range(0, len(machine_bytes) - 3, 4):
            insn, = struct.unpack("<I", machine_bytes[i:i + 4])
            pc = base_pc + i
            all_ops.extend(self.lift_instruction(pc, insn))
        return all_ops

    def lift_bytes(
        self,
        code: bytes,
        base_addr: int = 0x1000,
        max_insns: int | None = None,
    ) -> List[PcodeOp]:
        """Lifts ARM64 bytes starting at `base_addr`, up to `max_insns` instructions."""
        if max_insns is not None and max_insns >= 0:
            code = code[: max_insns * 4]
        return self.lift_block(base_addr, code)


# ==============================================================================
# Canonical Register Offset Tables (Shared across Builtin, pypcode & Daemon)
# ==============================================================================

_X86_REG_NAME_TO_IDX: Dict[str, int] = {}
for _idx, _names in enumerate(zip(x86_decode.REG64, x86_decode.REG32, x86_decode.REG16, x86_decode.REG8)):
    for _nm in _names:
        _X86_REG_NAME_TO_IDX[_nm] = _idx
for _idx, _nm in enumerate(("al", "cl", "dl", "bl", "ah", "ch", "dh", "bh")):
    if _nm not in _X86_REG_NAME_TO_IDX:
        _X86_REG_NAME_TO_IDX[_nm] = _idx & 3

CANONICAL_REG_OFFSETS: Dict[str, int] = {
    name: idx * 8 for name, idx in _X86_REG_NAME_TO_IDX.items()
}
for _i in range(31):
    CANONICAL_REG_OFFSETS[f"x{_i}"] = _i * 8
    CANONICAL_REG_OFFSETS[f"w{_i}"] = _i * 8
    CANONICAL_REG_OFFSETS[f"r{_i}"] = CANONICAL_REG_OFFSETS.get(f"r{_i}", _i * 8)
CANONICAL_REG_OFFSETS["sp"] = 31 * 8
CANONICAL_REG_OFFSETS["wsp"] = 31 * 8
CANONICAL_REG_OFFSETS["lr"] = 30 * 8
CANONICAL_REG_OFFSETS["fp"] = 29 * 8
for _i in range(32):
    CANONICAL_REG_OFFSETS[f"d{_i}"] = 0x400 + _i * 16
    CANONICAL_REG_OFFSETS[f"s{_i}"] = 0x400 + _i * 16
    CANONICAL_REG_OFFSETS[f"v{_i}"] = 0x400 + _i * 16
    CANONICAL_REG_OFFSETS[f"q{_i}"] = 0x400 + _i * 16
    if _i < 16:
        CANONICAL_REG_OFFSETS[f"xmm{_i}"] = 0x400 + _i * 16
        CANONICAL_REG_OFFSETS[f"ymm{_i}"] = 0x400 + _i * 16
CANONICAL_REG_OFFSETS.update({
    "flag_n": FLAG_N_OFFSET, "nf": FLAG_N_OFFSET, "ng": FLAG_N_OFFSET, "sf": FLAG_N_OFFSET,
    "flag_z": FLAG_Z_OFFSET, "zf": FLAG_Z_OFFSET, "zr": FLAG_Z_OFFSET,
    "flag_c": FLAG_C_OFFSET, "cf": FLAG_C_OFFSET, "cy": FLAG_C_OFFSET,
    "flag_v": FLAG_V_OFFSET, "of": FLAG_V_OFFSET, "vf": FLAG_V_OFFSET, "ov": FLAG_V_OFFSET,
    "pf": 0x704, "af": 0x705, "df": 0x706, "tf": 0x707, "if": 0x708,
    "rip": 0x780, "eip": 0x780, "pc": 0x780,
})


# ==============================================================================
# Standalone x86_64 / x86 Zero-JVM P-Code Lifter Engine (backed by x86_decode)
# ==============================================================================

class X86_64PcodeLifter:
    """
    Directly lifts variable-length x86_64 and x86 machine instructions into Ghidra P-Code IR
    without JVM or SLEIGH binary dependencies, using `superghidra.lifters.x86_decode`
    to decode prefixes, ModRM/SIB addressing, displacements, and immediates.
    Register mapping (8-byte intervals in AddressSpace.REGISTER):
      0: RAX (0x00), 1: RCX (0x08), 2: RDX (0x10), 3: RBX (0x18),
      4: RSP (0x20), 5: RBP (0x28), 6: RSI (0x30), 7: RDI (0x38),
      8..15: R8..R15 (0x40..0x78)
    """

    FLAG_N_OFFSET: int = 0x700
    FLAG_Z_OFFSET: int = 0x701
    FLAG_C_OFFSET: int = 0x702
    FLAG_V_OFFSET: int = 0x703

    def __init__(self, mode: int = 64):
        self.mode = mode
        self._last_cmp_operands: Tuple[Varnode, Varnode, int, bool] | None = None

    @staticmethod
    def _reg_varnode(reg_idx: int, size: int = 8) -> Varnode:
        reg_name = None
        if 0 <= reg_idx < 16:
            if size == 8:
                reg_name = x86_decode.REG64[reg_idx]
            elif size == 4:
                reg_name = x86_decode.REG32[reg_idx]
            elif size == 2:
                reg_name = x86_decode.REG16[reg_idx]
            elif size == 1:
                reg_name = x86_decode.REG8[reg_idx]
        return Varnode(space=AddressSpace.REGISTER, offset=reg_idx * 8, size=size, reg_name=reg_name)

    @staticmethod
    def _const_varnode(val: int, size: int = 8) -> Varnode:
        return Varnode(space=AddressSpace.CONST, offset=val & ((1 << (size * 8)) - 1), size=size)

    @staticmethod
    def _unique_varnode(idx: int, size: int = 8) -> Varnode:
        return Varnode(space=AddressSpace.UNIQUE, offset=idx * 8, size=size)

    def _emit_jcc_cond(self, pc: int, cc: int, u_cond: Varnode) -> List[PcodeOp]:
        ops: List[PcodeOp] = []
        if self._last_cmp_operands is not None:
            lhs, rhs, _, _ = self._last_cmp_operands
            if cc == 0x4:    # JE / JZ
                ops.append(PcodeOp(PcodeOpcode.INT_EQUAL, [lhs, rhs], u_cond, pc=pc))
            elif cc == 0x5:  # JNE / JNZ
                ops.append(PcodeOp(PcodeOpcode.INT_NOTEQUAL, [lhs, rhs], u_cond, pc=pc))
            elif cc == 0x2:  # JB / JC
                ops.append(PcodeOp(PcodeOpcode.INT_LESS, [lhs, rhs], u_cond, pc=pc))
            elif cc == 0x3:  # JAE / JNB
                ops.append(PcodeOp(PcodeOpcode.INT_LESSEQUAL, [rhs, lhs], u_cond, pc=pc))
            elif cc == 0x6:  # JBE / JNA
                ops.append(PcodeOp(PcodeOpcode.INT_LESSEQUAL, [lhs, rhs], u_cond, pc=pc))
            elif cc == 0x7:  # JA / JNBE
                ops.append(PcodeOp(PcodeOpcode.INT_LESS, [rhs, lhs], u_cond, pc=pc))
            elif cc == 0x8:  # JS
                ops.append(PcodeOp(PcodeOpcode.INT_SLESS, [lhs, rhs], u_cond, pc=pc))
            elif cc == 0x9:  # JNS
                ops.append(PcodeOp(PcodeOpcode.INT_SLESSEQUAL, [rhs, lhs], u_cond, pc=pc))
            elif cc == 0xC:  # JL / JNGE
                ops.append(PcodeOp(PcodeOpcode.INT_SLESS, [lhs, rhs], u_cond, pc=pc))
            elif cc == 0xD:  # JGE / JNL
                ops.append(PcodeOp(PcodeOpcode.INT_SLESSEQUAL, [rhs, lhs], u_cond, pc=pc))
            elif cc == 0xE:  # JLE / JNG
                ops.append(PcodeOp(PcodeOpcode.INT_SLESSEQUAL, [lhs, rhs], u_cond, pc=pc))
            elif cc == 0xF:  # JG / JNLE
                ops.append(PcodeOp(PcodeOpcode.INT_SLESS, [rhs, lhs], u_cond, pc=pc))
            else:
                ops.append(PcodeOp(PcodeOpcode.COPY, [self._const_varnode(1, 1)], u_cond, pc=pc))
        else:
            flag_z = Varnode(AddressSpace.REGISTER, self.FLAG_Z_OFFSET, 1, reg_name="zf")
            if cc == 0x5:
                ops.append(PcodeOp(PcodeOpcode.INT_XOR, [flag_z, self._const_varnode(1, 1)], u_cond, pc=pc))
            else:
                ops.append(PcodeOp(PcodeOpcode.COPY, [flag_z], u_cond, pc=pc))
        return ops

    def _emit_mem_address(self, pc: int, insn: x86_decode.X86Insn, u_addr: Varnode) -> List[PcodeOp]:
        """Emits P-Code ops computing effective address of `insn.mem` into `u_addr` (size 8)."""
        ops: List[PcodeOp] = []
        mem = insn.mem
        if mem is None:
            ops.append(PcodeOp(PcodeOpcode.COPY, [self._const_varnode(0, 8)], u_addr, pc=pc))
            return ops

        if mem.rip_relative:
            eff_addr = (pc + insn.length + mem.disp) & 0xFFFFFFFFFFFFFFFF
            ops.append(PcodeOp(PcodeOpcode.COPY, [self._const_varnode(eff_addr, 8)], u_addr, pc=pc))
            return ops

        cur_addr: Varnode | None = None
        if mem.base is not None:
            base_idx = _X86_REG_NAME_TO_IDX.get(mem.base.lower(), 0)
            cur_addr = self._reg_varnode(base_idx, 8)

        if mem.index is not None:
            idx_reg = _X86_REG_NAME_TO_IDX.get(mem.index.lower(), 0)
            idx_vn = self._reg_varnode(idx_reg, 8)
            if mem.scale > 1:
                u_scaled = self._unique_varnode(10, 8)
                ops.append(PcodeOp(PcodeOpcode.INT_MULT, [idx_vn, self._const_varnode(mem.scale, 8)], u_scaled, pc=pc))
                idx_term = u_scaled
            else:
                idx_term = idx_vn

            if cur_addr is None:
                cur_addr = idx_term
            else:
                u_sum = self._unique_varnode(11, 8)
                ops.append(PcodeOp(PcodeOpcode.INT_ADD, [cur_addr, idx_term], u_sum, pc=pc))
                cur_addr = u_sum

        disp = mem.disp
        if cur_addr is None:
            ops.append(PcodeOp(PcodeOpcode.COPY, [self._const_varnode(disp & 0xFFFFFFFFFFFFFFFF, 8)], u_addr, pc=pc))
        else:
            if disp == 0 and cur_addr.space == AddressSpace.UNIQUE:
                ops.append(PcodeOp(PcodeOpcode.COPY, [cur_addr], u_addr, pc=pc))
            elif disp >= 0:
                ops.append(PcodeOp(PcodeOpcode.INT_ADD, [cur_addr, self._const_varnode(disp, 8)], u_addr, pc=pc))
            else:
                ops.append(PcodeOp(PcodeOpcode.INT_SUB, [cur_addr, self._const_varnode(-disp, 8)], u_addr, pc=pc))
        return ops

    def lift_instruction(self, pc: int, code: bytes) -> Tuple[int, List[PcodeOp]]:
        """
        Decodes a single x86_64 / x86 instruction at `code[0:]` using `x86_decode`
        and returns `(insn_len, pcode_ops)`.
        """
        if not code:
            return 0, []

        # 1. ENDBR64: F3 0F 1E FA / ENDBR32: F3 0F 1E FB
        if len(code) >= 4 and code[:4] in (b"\xf3\x0f\x1e\xfa", b"\xf3\x0f\x1e\xfb"):
            return 4, []

        insn = x86_decode.decode(code, offset=0, address=pc, mode=self.mode)
        idx = max(1, insn.length)
        if insn.invalid:
            return idx, [PcodeOp(PcodeOpcode.UNIMPLEMENTED, [self._const_varnode(insn.opcode, 1)], pc=pc)]

        ops: List[PcodeOp] = []
        opc = insn.opcode
        op_size = 1 if insn.is_byte_op else insn.operand_size
        reg = insn.reg
        rm = insn.rm
        reg_field = (insn.modrm >> 3) & 7 if insn.modrm is not None else 0
        mod = (insn.modrm >> 6) & 3 if insn.modrm is not None else 3
        stack_size = 8 if self.mode == 64 else 4

        # Map 0 (1-byte opcodes)
        if insn.map == 0 and not insn.vex:
            # NOP (0x90) or PAUSE (F3 90)
            if opc == 0x90 and rm == 0:
                return idx, []

            # XCHG eax/rax, r (0x90..0x97 when rm != 0)
            if 0x90 <= opc <= 0x97:
                r_other = (opc - 0x90) | ((insn.rex & 1) << 3)
                r0_vn = self._reg_varnode(0, op_size)
                ro_vn = self._reg_varnode(r_other, op_size)
                u_tmp = self._unique_varnode(0, op_size)
                ops.append(PcodeOp(PcodeOpcode.COPY, [r0_vn], u_tmp, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.COPY, [ro_vn], r0_vn, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.COPY, [u_tmp], ro_vn, pc=pc))
                return idx, ops

            # 32-bit mode INC / DEC r32 (0x40..0x4F when mode == 32)
            if self.mode == 32 and 0x40 <= opc <= 0x4F:
                r_idx = opc & 7
                r_vn = self._reg_varnode(r_idx, op_size)
                p_op = PcodeOpcode.INT_ADD if opc < 0x48 else PcodeOpcode.INT_SUB
                ops.append(PcodeOp(p_op, [r_vn, self._const_varnode(1, op_size)], r_vn, pc=pc))
                return idx, ops

            # CBW / CWDE / CDQE (0x98)
            if opc == 0x98:
                src_sz = op_size // 2
                ops.append(PcodeOp(PcodeOpcode.INT_SEXT, [self._reg_varnode(0, src_sz)], self._reg_varnode(0, op_size), pc=pc))
                return idx, ops

            # CWD / CDQ / CQO (0x99)
            if opc == 0x99:
                ops.append(PcodeOp(
                    PcodeOpcode.INT_SRIGHT,
                    [self._reg_varnode(0, op_size), self._const_varnode(op_size * 8 - 1, op_size)],
                    self._reg_varnode(2, op_size),
                    pc=pc,
                ))
                return idx, ops

            # LEAVE (0xC9): mov rsp, rbp; pop rbp
            if opc == 0xC9:
                rsp = self._reg_varnode(4, stack_size)
                rbp = self._reg_varnode(5, stack_size)
                ops.append(PcodeOp(PcodeOpcode.COPY, [rbp], rsp, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, stack_size), rsp], rbp, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rsp, self._const_varnode(stack_size, stack_size)], rsp, pc=pc))
                return idx, ops

            # RET (0xC3) or RET imm16 (0xC2)
            if opc in (0xC3, 0xC2):
                rsp = self._reg_varnode(4, stack_size)
                u_ret = self._unique_varnode(0, stack_size)
                pop_bytes = stack_size + (insn.imm if opc == 0xC2 and insn.imm is not None else 0)
                ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, stack_size), rsp], u_ret, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rsp, self._const_varnode(pop_bytes, stack_size)], rsp, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.RETURN, [self._reg_varnode(0, stack_size)], pc=pc))
                return idx, ops

            # PUSH r (0x50..0x57)
            if 0x50 <= opc <= 0x57:
                r_idx = (opc - 0x50) | ((insn.rex & 1) << 3)
                rsp = self._reg_varnode(4, stack_size)
                ops.append(PcodeOp(PcodeOpcode.INT_SUB, [rsp, self._const_varnode(stack_size, stack_size)], rsp, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, stack_size), rsp, self._reg_varnode(r_idx, stack_size)], pc=pc))
                return idx, ops

            # PUSH imm8/imm32 (0x6A, 0x68)
            if opc in (0x6A, 0x68) and insn.imm is not None:
                rsp = self._reg_varnode(4, stack_size)
                ops.append(PcodeOp(PcodeOpcode.INT_SUB, [rsp, self._const_varnode(stack_size, stack_size)], rsp, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, stack_size), rsp, self._const_varnode(insn.imm, stack_size)], pc=pc))
                return idx, ops

            # POP r (0x58..0x5F)
            if 0x58 <= opc <= 0x5F:
                r_idx = (opc - 0x58) | ((insn.rex & 1) << 3)
                rsp = self._reg_varnode(4, stack_size)
                ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, stack_size), rsp], self._reg_varnode(r_idx, stack_size), pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rsp, self._const_varnode(stack_size, stack_size)], rsp, pc=pc))
                return idx, ops

            # MOV r8, imm8 (0xB0..0xB7)
            if 0xB0 <= opc <= 0xB7 and insn.imm is not None:
                r_idx = (opc - 0xB0) | ((insn.rex & 1) << 3)
                ops.append(PcodeOp(PcodeOpcode.COPY, [self._const_varnode(insn.imm, 1)], self._reg_varnode(r_idx, 1), pc=pc))
                return idx, ops

            # MOV r16/r32/r64, imm (0xB8..0xBF)
            if 0xB8 <= opc <= 0xBF and insn.imm is not None:
                r_idx = (opc - 0xB8) | ((insn.rex & 1) << 3)
                ops.append(PcodeOp(PcodeOpcode.COPY, [self._const_varnode(insn.imm, op_size)], self._reg_varnode(r_idx, op_size), pc=pc))
                return idx, ops

            # CALL rel32 (0xE8) or JMP rel32/rel8 (0xE9, 0xEB)
            if opc in (0xE8, 0xE9, 0xEB) and insn.target is not None:
                p_op = PcodeOpcode.CALL if opc == 0xE8 else PcodeOpcode.BRANCH
                ops.append(PcodeOp(p_op, [self._const_varnode(insn.target, 8)], pc=pc))
                return idx, ops

            # Jcc rel8 (0x70..0x7F)
            if 0x70 <= opc <= 0x7F and insn.target is not None:
                cc = opc & 0xF
                u_cond = self._unique_varnode(0, 1)
                ops.extend(self._emit_jcc_cond(pc, cc, u_cond))
                ops.append(PcodeOp(PcodeOpcode.CBRANCH, [self._const_varnode(insn.target, 8), u_cond], pc=pc))
                return idx, ops

            # Accumulator immediate ALU: ADD/OR/AND/SUB/XOR/CMP AL/AX/EAX/RAX, imm
            if opc in (0x04, 0x05, 0x0C, 0x0D, 0x24, 0x25, 0x2C, 0x2D, 0x34, 0x35, 0x3C, 0x3D) and insn.imm is not None:
                acc_vn = self._reg_varnode(0, op_size)
                c_vn = self._const_varnode(insn.imm, op_size)
                alu_grp = (opc >> 3) & 7
                if alu_grp == 7:  # CMP
                    self._last_cmp_operands = (acc_vn, c_vn, op_size, True)
                    u_cmp = self._unique_varnode(0, op_size)
                    ops.append(PcodeOp(PcodeOpcode.INT_SUB, [acc_vn, c_vn], u_cmp, pc=pc))
                    return idx, ops
                acc_map = {
                    0: PcodeOpcode.INT_ADD,
                    1: PcodeOpcode.INT_OR,
                    4: PcodeOpcode.INT_AND,
                    5: PcodeOpcode.INT_SUB,
                    6: PcodeOpcode.INT_XOR,
                }
                if alu_grp in acc_map:
                    ops.append(PcodeOp(acc_map[alu_grp], [acc_vn, c_vn], acc_vn, pc=pc))
                    return idx, ops

            # TEST AL/EAX/RAX, imm (0xA8, 0xA9)
            if opc in (0xA8, 0xA9) and insn.imm is not None:
                acc_vn = self._reg_varnode(0, op_size)
                c_vn = self._const_varnode(insn.imm, op_size)
                u_test = self._unique_varnode(0, op_size)
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [acc_vn, c_vn], u_test, pc=pc))
                self._last_cmp_operands = (u_test, self._const_varnode(0, op_size), op_size, True)
                return idx, ops

            # 3-operand IMUL r, r/m, imm (0x69, 0x6B)
            if opc in (0x69, 0x6B) and insn.imm is not None:
                reg_vn = self._reg_varnode(reg, op_size)
                c_vn = self._const_varnode(insn.imm, op_size)
                if mod == 3:
                    src_vn = self._reg_varnode(rm, op_size)
                else:
                    u_addr = self._unique_varnode(0, 8)
                    ops.extend(self._emit_mem_address(pc, insn, u_addr))
                    src_vn = self._unique_varnode(1, op_size)
                    ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, op_size), u_addr], src_vn, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_MULT, [src_vn, c_vn], reg_vn, pc=pc))
                return idx, ops

            # MOVSXD r64, r/m32 (0x63 in 64-bit mode)
            if opc == 0x63 and self.mode == 64:
                reg_vn = self._reg_varnode(reg, op_size)
                if mod == 3:
                    src_vn = self._reg_varnode(rm, 4)
                else:
                    u_addr = self._unique_varnode(0, 8)
                    ops.extend(self._emit_mem_address(pc, insn, u_addr))
                    src_vn = self._unique_varnode(1, 4)
                    ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), u_addr], src_vn, pc=pc))
                if op_size > 4:
                    ops.append(PcodeOp(PcodeOpcode.INT_SEXT, [src_vn], reg_vn, pc=pc))
                else:
                    ops.append(PcodeOp(PcodeOpcode.COPY, [src_vn], reg_vn, pc=pc))
                return idx, ops

            # ModR/M instructions in Map 0
            if insn.modrm is not None:
                imm_val = insn.imm if insn.imm is not None else 0
                if mod == 3:
                    rm_vn = self._reg_varnode(rm, op_size)
                    reg_vn = self._reg_varnode(reg, op_size)
                    if opc in (0x88, 0x89):  # MOV r/m, r
                        ops.append(PcodeOp(PcodeOpcode.COPY, [reg_vn], rm_vn, pc=pc))
                        return idx, ops
                    elif opc in (0x8A, 0x8B):  # MOV r, r/m
                        ops.append(PcodeOp(PcodeOpcode.COPY, [rm_vn], reg_vn, pc=pc))
                        return idx, ops
                    elif opc in (0x86, 0x87):  # XCHG r/m, r
                        u_tmp = self._unique_varnode(0, op_size)
                        ops.append(PcodeOp(PcodeOpcode.COPY, [rm_vn], u_tmp, pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.COPY, [reg_vn], rm_vn, pc=pc))
                        ops.append(PcodeOp(PcodeOpcode.COPY, [u_tmp], reg_vn, pc=pc))
                        return idx, ops
                    elif opc in (0xC6, 0xC7) and reg_field == 0:  # MOV r/m, imm
                        ops.append(PcodeOp(PcodeOpcode.COPY, [self._const_varnode(imm_val, op_size)], rm_vn, pc=pc))
                        return idx, ops
                    elif opc in (0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B,
                                 0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B,
                                 0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3A, 0x3B):
                        is_rm_dst = (opc & 2) == 0
                        lhs = rm_vn if is_rm_dst else reg_vn
                        rhs = reg_vn if is_rm_dst else rm_vn
                        dst = lhs
                        if (opc & 0x38) in (0x30, 0x28) and reg == rm and op_size in (4, 8):
                            # xor reg, reg or sub reg, reg -> zero-idiom
                            if (opc & 0x38) == 0x30:
                                ops.append(PcodeOp(PcodeOpcode.COPY, [self._const_varnode(0, op_size)], self._reg_varnode(reg, 8), pc=pc))
                                return idx, ops
                        if (opc & 0x38) == 0x38:  # CMP
                            self._last_cmp_operands = (lhs, rhs, op_size, True)
                            u_cmp = self._unique_varnode(0, op_size)
                            ops.append(PcodeOp(PcodeOpcode.INT_SUB, [lhs, rhs], u_cmp, pc=pc))
                            return idx, ops
                        alu_map = {
                            0x00: PcodeOpcode.INT_ADD,
                            0x08: PcodeOpcode.INT_OR,
                            0x20: PcodeOpcode.INT_AND,
                            0x28: PcodeOpcode.INT_SUB,
                            0x30: PcodeOpcode.INT_XOR,
                        }
                        ops.append(PcodeOp(alu_map[opc & 0x38], [lhs, rhs], dst, pc=pc))
                        return idx, ops
                    elif opc in (0x84, 0x85):  # TEST r/m, r
                        u_test = self._unique_varnode(0, op_size)
                        ops.append(PcodeOp(PcodeOpcode.INT_AND, [rm_vn, reg_vn], u_test, pc=pc))
                        self._last_cmp_operands = (u_test, self._const_varnode(0, op_size), op_size, True)
                        return idx, ops
                    elif opc in (0x80, 0x81, 0x82, 0x83):  # Group 1 immediate ALU
                        c_vn = self._const_varnode(imm_val, op_size)
                        if reg_field == 0:  # ADD
                            ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rm_vn, c_vn], rm_vn, pc=pc))
                            return idx, ops
                        elif reg_field == 1:  # OR
                            ops.append(PcodeOp(PcodeOpcode.INT_OR, [rm_vn, c_vn], rm_vn, pc=pc))
                            return idx, ops
                        elif reg_field == 4:  # AND
                            ops.append(PcodeOp(PcodeOpcode.INT_AND, [rm_vn, c_vn], rm_vn, pc=pc))
                            return idx, ops
                        elif reg_field == 5:  # SUB
                            ops.append(PcodeOp(PcodeOpcode.INT_SUB, [rm_vn, c_vn], rm_vn, pc=pc))
                            return idx, ops
                        elif reg_field == 6:  # XOR
                            ops.append(PcodeOp(PcodeOpcode.INT_XOR, [rm_vn, c_vn], rm_vn, pc=pc))
                            return idx, ops
                        elif reg_field == 7:  # CMP
                            self._last_cmp_operands = (rm_vn, c_vn, op_size, True)
                            u_cmp = self._unique_varnode(0, op_size)
                            ops.append(PcodeOp(PcodeOpcode.INT_SUB, [rm_vn, c_vn], u_cmp, pc=pc))
                            return idx, ops
                    elif opc in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):  # Shift by imm8, 1, or CL
                        if opc in (0xD0, 0xD1):
                            sh_vn = self._const_varnode(1, op_size)
                        elif opc in (0xC0, 0xC1):
                            sh_vn = self._const_varnode(imm_val & 0x3F, op_size)
                        else:
                            sh_vn = self._reg_varnode(1, 1)
                        if reg_field == 4:  # SHL
                            ops.append(PcodeOp(PcodeOpcode.INT_LEFT, [rm_vn, sh_vn], rm_vn, pc=pc))
                            return idx, ops
                        elif reg_field == 5:  # SHR
                            ops.append(PcodeOp(PcodeOpcode.INT_RIGHT, [rm_vn, sh_vn], rm_vn, pc=pc))
                            return idx, ops
                        elif reg_field == 7:  # SAR
                            ops.append(PcodeOp(PcodeOpcode.INT_SRIGHT, [rm_vn, sh_vn], rm_vn, pc=pc))
                            return idx, ops
                    elif opc in (0xF6, 0xF7):  # Group 3: TEST, NOT, NEG, MUL, IMUL
                        if reg_field in (0, 1):  # TEST r, imm
                            u_test = self._unique_varnode(0, op_size)
                            ops.append(PcodeOp(PcodeOpcode.INT_AND, [rm_vn, self._const_varnode(imm_val, op_size)], u_test, pc=pc))
                            self._last_cmp_operands = (u_test, self._const_varnode(0, op_size), op_size, True)
                            return idx, ops
                        elif reg_field == 2:  # NOT r
                            ops.append(PcodeOp(PcodeOpcode.INT_NEGATE, [rm_vn], rm_vn, pc=pc))
                            return idx, ops
                        elif reg_field == 3:  # NEG r
                            self._last_cmp_operands = (self._const_varnode(0, op_size), rm_vn, op_size, True)
                            ops.append(PcodeOp(PcodeOpcode.INT_2COMP, [rm_vn], rm_vn, pc=pc))
                            return idx, ops
                        elif reg_field in (4, 5):  # MUL / IMUL r
                            acc_vn = self._reg_varnode(0, op_size)
                            ops.append(PcodeOp(PcodeOpcode.INT_MULT, [acc_vn, rm_vn], acc_vn, pc=pc))
                            return idx, ops
                    elif opc in (0xFE, 0xFF):  # INC, DEC, CALL rm, JMP rm, PUSH rm
                        if reg_field == 0:  # INC
                            ops.append(PcodeOp(PcodeOpcode.INT_ADD, [rm_vn, self._const_varnode(1, op_size)], rm_vn, pc=pc))
                            return idx, ops
                        elif reg_field == 1:  # DEC
                            ops.append(PcodeOp(PcodeOpcode.INT_SUB, [rm_vn, self._const_varnode(1, op_size)], rm_vn, pc=pc))
                            return idx, ops
                        elif reg_field == 2 and opc == 0xFF:  # CALLIND
                            ops.append(PcodeOp(PcodeOpcode.CALLIND, [self._reg_varnode(rm, 8)], pc=pc))
                            return idx, ops
                        elif reg_field == 4 and opc == 0xFF:  # BRANCHIND
                            ops.append(PcodeOp(PcodeOpcode.BRANCHIND, [self._reg_varnode(rm, 8)], pc=pc))
                            return idx, ops
                else:
                    # Memory operand: compute effective address using x86_decode SIB + disp + RIP
                    u_addr = self._unique_varnode(0, 8)
                    ops.extend(self._emit_mem_address(pc, insn, u_addr))
                    reg_vn = self._reg_varnode(reg, op_size)
                    ram_vn = Varnode(AddressSpace.RAM, 0, op_size)

                    if opc == 0x8D:  # LEA r, [addr]
                        if op_size == 8:
                            ops.append(PcodeOp(PcodeOpcode.COPY, [u_addr], reg_vn, pc=pc))
                        else:
                            ops.append(PcodeOp(PcodeOpcode.SUBPIECE, [u_addr, self._const_varnode(0, 4)], reg_vn, pc=pc))
                        return idx, ops
                    elif opc in (0x8A, 0x8B):  # MOV r, [addr]
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [ram_vn, u_addr], reg_vn, pc=pc))
                        return idx, ops
                    elif opc in (0x88, 0x89):  # MOV [addr], r
                        ops.append(PcodeOp(PcodeOpcode.STORE, [ram_vn, u_addr, reg_vn], pc=pc))
                        return idx, ops
                    elif opc in (0xC6, 0xC7) and reg_field == 0:  # MOV [addr], imm
                        ops.append(PcodeOp(PcodeOpcode.STORE, [ram_vn, u_addr, self._const_varnode(imm_val, op_size)], pc=pc))
                        return idx, ops
                    elif opc in (0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B,
                                 0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B,
                                 0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3A, 0x3B):
                        u_mem = self._unique_varnode(1, op_size)
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [ram_vn, u_addr], u_mem, pc=pc))
                        is_mem_dst = (opc & 2) == 0
                        lhs = u_mem if is_mem_dst else reg_vn
                        rhs = reg_vn if is_mem_dst else u_mem
                        if (opc & 0x38) == 0x38:  # CMP
                            self._last_cmp_operands = (lhs, rhs, op_size, True)
                            u_cmp = self._unique_varnode(2, op_size)
                            ops.append(PcodeOp(PcodeOpcode.INT_SUB, [lhs, rhs], u_cmp, pc=pc))
                            return idx, ops
                        alu_map = {
                            0x00: PcodeOpcode.INT_ADD,
                            0x08: PcodeOpcode.INT_OR,
                            0x20: PcodeOpcode.INT_AND,
                            0x28: PcodeOpcode.INT_SUB,
                            0x30: PcodeOpcode.INT_XOR,
                        }
                        if is_mem_dst:
                            u_res = self._unique_varnode(2, op_size)
                            ops.append(PcodeOp(alu_map[opc & 0x38], [lhs, rhs], u_res, pc=pc))
                            ops.append(PcodeOp(PcodeOpcode.STORE, [ram_vn, u_addr, u_res], pc=pc))
                        else:
                            ops.append(PcodeOp(alu_map[opc & 0x38], [lhs, rhs], reg_vn, pc=pc))
                        return idx, ops
                    elif opc in (0x80, 0x81, 0x82, 0x83):  # Group 1 ALU [addr], imm
                        u_mem = self._unique_varnode(1, op_size)
                        ops.append(PcodeOp(PcodeOpcode.LOAD, [ram_vn, u_addr], u_mem, pc=pc))
                        c_vn = self._const_varnode(imm_val, op_size)
                        if reg_field == 7:  # CMP [addr], imm
                            self._last_cmp_operands = (u_mem, c_vn, op_size, True)
                            u_cmp = self._unique_varnode(2, op_size)
                            ops.append(PcodeOp(PcodeOpcode.INT_SUB, [u_mem, c_vn], u_cmp, pc=pc))
                            return idx, ops
                        grp1_map = {
                            0: PcodeOpcode.INT_ADD,
                            1: PcodeOpcode.INT_OR,
                            4: PcodeOpcode.INT_AND,
                            5: PcodeOpcode.INT_SUB,
                            6: PcodeOpcode.INT_XOR,
                        }
                        if reg_field in grp1_map:
                            u_res = self._unique_varnode(2, op_size)
                            ops.append(PcodeOp(grp1_map[reg_field], [u_mem, c_vn], u_res, pc=pc))
                            ops.append(PcodeOp(PcodeOpcode.STORE, [ram_vn, u_addr, u_res], pc=pc))
                            return idx, ops

        # Map 1 (0x0F two-byte opcodes)
        elif insn.map == 1 and not insn.vex:
            # Jcc rel32 (0x0F 0x80..0x8F)
            if 0x80 <= opc <= 0x8F and insn.target is not None:
                cc = opc & 0xF
                u_cond = self._unique_varnode(0, 1)
                ops.extend(self._emit_jcc_cond(pc, cc, u_cond))
                ops.append(PcodeOp(PcodeOpcode.CBRANCH, [self._const_varnode(insn.target, 8), u_cond], pc=pc))
                return idx, ops

            # SETcc r/m8 (0x0F 0x90..0x9F)
            if 0x90 <= opc <= 0x9F and insn.modrm is not None:
                cc = opc & 0xF
                u_cond = self._unique_varnode(0, 1)
                ops.extend(self._emit_jcc_cond(pc, cc, u_cond))
                if mod == 3:
                    ops.append(PcodeOp(PcodeOpcode.COPY, [u_cond], self._reg_varnode(rm, 1), pc=pc))
                else:
                    u_addr = self._unique_varnode(1, 8)
                    ops.extend(self._emit_mem_address(pc, insn, u_addr))
                    ops.append(PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, 1), u_addr, u_cond], pc=pc))
                return idx, ops

            # CMOVcc r, r/m (0x0F 0x40..0x4F)
            if 0x40 <= opc <= 0x4F and insn.modrm is not None:
                cc = opc & 0xF
                u_cond = self._unique_varnode(0, 1)
                ops.extend(self._emit_jcc_cond(pc, cc, u_cond))
                reg_vn = self._reg_varnode(reg, op_size)
                if mod == 3:
                    src_vn = self._reg_varnode(rm, op_size)
                else:
                    u_addr = self._unique_varnode(1, 8)
                    ops.extend(self._emit_mem_address(pc, insn, u_addr))
                    src_vn = self._unique_varnode(2, op_size)
                    ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, op_size), u_addr], src_vn, pc=pc))
                u_zext = self._unique_varnode(3, op_size)
                u_mask = self._unique_varnode(4, op_size)
                u_not_mask = self._unique_varnode(5, op_size)
                u_t = self._unique_varnode(6, op_size)
                u_f = self._unique_varnode(7, op_size)
                ops.append(PcodeOp(PcodeOpcode.INT_ZEXT, [u_cond], u_zext, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_2COMP, [u_zext], u_mask, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_NEGATE, [u_mask], u_not_mask, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [src_vn, u_mask], u_t, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_AND, [reg_vn, u_not_mask], u_f, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_OR, [u_t, u_f], reg_vn, pc=pc))
                return idx, ops

            # IMUL r, r/m (0x0F 0xAF)
            if opc == 0xAF and insn.modrm is not None:
                reg_vn = self._reg_varnode(reg, op_size)
                if mod == 3:
                    src_vn = self._reg_varnode(rm, op_size)
                else:
                    u_addr = self._unique_varnode(0, 8)
                    ops.extend(self._emit_mem_address(pc, insn, u_addr))
                    src_vn = self._unique_varnode(1, op_size)
                    ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, op_size), u_addr], src_vn, pc=pc))
                ops.append(PcodeOp(PcodeOpcode.INT_MULT, [reg_vn, src_vn], reg_vn, pc=pc))
                return idx, ops

            # MOVZX (0x0F 0xB6, 0x0F 0xB7) and MOVSX (0x0F 0xBE, 0x0F 0xBF)
            if opc in (0xB6, 0xB7, 0xBE, 0xBF) and insn.modrm is not None:
                src_sz = 1 if opc in (0xB6, 0xBE) else 2
                ext_op = PcodeOpcode.INT_ZEXT if opc in (0xB6, 0xB7) else PcodeOpcode.INT_SEXT
                reg_vn = self._reg_varnode(reg, op_size)
                if mod == 3:
                    src_vn = self._reg_varnode(rm, src_sz)
                else:
                    u_addr = self._unique_varnode(0, 8)
                    ops.extend(self._emit_mem_address(pc, insn, u_addr))
                    src_vn = self._unique_varnode(1, src_sz)
                    ops.append(PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, src_sz), u_addr], src_vn, pc=pc))
                ops.append(PcodeOp(ext_op, [src_vn], reg_vn, pc=pc))
                return idx, ops

            # Multi-byte NOP (0x0F 0x1F /0)
            if opc == 0x1F:
                return idx, []

        ops.append(PcodeOp(PcodeOpcode.UNIMPLEMENTED, [self._const_varnode(opc, 1)], pc=pc))
        return idx, ops

    def lift_block(self, base_pc: int, machine_bytes: bytes) -> List[PcodeOp]:
        """Lifts a contiguous byte slice of variable-length x86_64 instructions."""
        all_ops: List[PcodeOp] = []
        offset = 0
        n = len(machine_bytes)
        while offset < n:
            consumed, insn_ops = self.lift_instruction(base_pc + offset, machine_bytes[offset:])
            if consumed <= 0:
                break
            all_ops.extend(insn_ops)
            offset += consumed
        return all_ops

    def lift_bytes(
        self,
        code: bytes,
        base_addr: int = 0x1000,
        max_insns: int | None = None,
    ) -> List[PcodeOp]:
        """Lifts x86_64 / x86 bytes starting at `base_addr`, up to `max_insns` instructions."""
        all_ops: List[PcodeOp] = []
        offset = 0
        n = len(code)
        count = 0
        while offset < n:
            if max_insns is not None and count >= max_insns:
                break
            consumed, insn_ops = self.lift_instruction(base_addr + offset, code[offset:])
            if consumed <= 0:
                break
            all_ops.extend(insn_ops)
            offset += consumed
            count += 1
        return all_ops


# ==============================================================================
# Pypcode SLEIGH Backend
# ==============================================================================

class PypcodeSleighBackend:
    """
    Lifts raw machine code bytes into SuperGhidra `PcodeOp`s using `pypcode` SLEIGH bindings.
    Supports full SLEIGH language IDs (`"x86:LE:64:default"`, `"x86:LE:32:default"`,
    `"AArch64:LE:64:v8A"`, `"ARM:LE:32:v8"`) and short architecture aliases
    (`"x86_64"`, `"x86"`, `"arm64"`, `"arm"`).
    """

    LANGUAGE_ALIASES: Dict[str, str] = {
        "x86_64": "x86:LE:64:default",
        "amd64": "x86:LE:64:default",
        "x64": "x86:LE:64:default",
        "x86": "x86:LE:32:default",
        "i386": "x86:LE:32:default",
        "x86_32": "x86:LE:32:default",
        "arm64": "AArch64:LE:64:v8A",
        "aarch64": "AArch64:LE:64:v8A",
        "arm": "ARM:LE:32:v8",
        "arm32": "ARM:LE:32:v8",
    }

    _SLEIGH_X86_OFFSET_TO_NAME: Dict[Tuple[int, int], str] = {
        (0x00, 8): "rax", (0x00, 4): "eax", (0x00, 2): "ax", (0x00, 1): "al",
        (0x08, 8): "rcx", (0x08, 4): "ecx", (0x08, 2): "cx", (0x08, 1): "cl",
        (0x10, 8): "rdx", (0x10, 4): "edx", (0x10, 2): "dx", (0x10, 1): "dl",
        (0x18, 8): "rbx", (0x18, 4): "ebx", (0x18, 2): "bx", (0x18, 1): "bl",
        (0x20, 8): "rsp", (0x20, 4): "esp", (0x20, 2): "sp", (0x20, 1): "spl",
        (0x28, 8): "rbp", (0x28, 4): "ebp", (0x28, 2): "bp", (0x28, 1): "bpl",
        (0x30, 8): "rsi", (0x30, 4): "esi", (0x30, 2): "si", (0x30, 1): "sil",
        (0x38, 8): "rdi", (0x38, 4): "edi", (0x38, 2): "di", (0x38, 1): "dil",
        (0x80, 8): "r8",  (0x80, 4): "r8d", (0x80, 2): "r8w", (0x80, 1): "r8b",
        (0x88, 8): "r9",  (0x88, 4): "r9d", (0x88, 2): "r9w", (0x88, 1): "r9b",
        (0x90, 8): "r10", (0x90, 4): "r10d", (0x90, 2): "r10w", (0x90, 1): "r10b",
        (0x98, 8): "r11", (0x98, 4): "r11d", (0x98, 2): "r11w", (0x98, 1): "r11b",
        (0xA0, 8): "r12", (0xA0, 4): "r12d", (0xA0, 2): "r12w", (0xA0, 1): "r12b",
        (0xA8, 8): "r13", (0xA8, 4): "r13d", (0xA8, 2): "r13w", (0xA8, 1): "r13b",
        (0xB0, 8): "r14", (0xB0, 4): "r14d", (0xB0, 2): "r14w", (0xB0, 1): "r14b",
        (0xB8, 8): "r15", (0xB8, 4): "r15d", (0xB8, 2): "r15w", (0xB8, 1): "r15b",
        (0x200, 1): "cf", (0x202, 1): "pf", (0x204, 1): "af",
        (0x206, 1): "zf", (0x207, 1): "sf", (0x20b, 1): "of",
    }

    _SLEIGH_ARM64_OFFSET_TO_NAME: Dict[Tuple[int, int], str] = {
        **{(0x4000 + i * 8, 8): f"x{i}" for i in range(31)},
        **{(0x4000 + i * 8, 4): f"w{i}" for i in range(31)},
        **{(i * 8, 8): f"x{i}" for i in range(31)},
        **{(i * 8, 4): f"w{i}" for i in range(31)},
        (0x08, 8): "sp", (31 * 8, 8): "sp",
        (0x200, 1): "ng", (0x201, 1): "zr", (0x202, 1): "cy", (0x203, 1): "ov",
    }

    def __init__(self, lang_id: str = "x86_64", context: Any | None = None):
        self.lang_id = lang_id
        self.language_id = self.resolve_language_id(lang_id)
        if context is not None:
            self.ctx = context
        else:
            pp = pypcode
            if pp is None:
                try:
                    import pypcode as _pp  # type: ignore
                    pp = _pp
                except ImportError as exc:
                    raise ImportError("pypcode is not installed; install pypcode to use PypcodeSleighBackend") from exc
            self.ctx = pp.Context(self.language_id)

        self._reg_exact: Dict[Tuple[int, int], str] = {}
        self._reg_by_offset: Dict[int, str] = {}
        self._build_register_maps()

    @classmethod
    def resolve_language_id(cls, lang_or_arch: str) -> str:
        key = lang_or_arch.strip()
        return cls.LANGUAGE_ALIASES.get(key.lower(), key)

    @classmethod
    def is_available(cls) -> bool:
        if pypcode is not None:
            return True
        try:
            import pypcode as _pp  # type: ignore
            return _pp is not None
        except ImportError:
            return False

    def _build_register_maps(self) -> None:
        regs = getattr(self.ctx, "registers", None)
        if isinstance(regs, dict):
            for r_name, r_vn in regs.items():
                low_name = str(r_name).lower()
                off = int(getattr(r_vn, "offset", 0))
                sz = int(getattr(r_vn, "size", 8))
                if (off, sz) not in self._reg_exact or low_name in CANONICAL_REG_OFFSETS:
                    self._reg_exact[(off, sz)] = low_name
                if off not in self._reg_by_offset or low_name in CANONICAL_REG_OFFSETS:
                    self._reg_by_offset[off] = low_name

    def _resolve_register_name(self, vn: Any) -> str | None:
        off = getattr(vn, "offset", 0)
        sz = int(getattr(vn, "size", 8))
        if isinstance(off, str):
            return off.lower()
        off_int = int(off)
        if (off_int, sz) in self._reg_exact:
            return self._reg_exact[(off_int, sz)]
        get_reg_fn = getattr(vn, "getRegisterName", None)
        if callable(get_reg_fn):
            try:
                rn = get_reg_fn()
                if rn:
                    return str(rn).lower()
            except Exception:
                pass
        if off_int in self._reg_by_offset:
            return self._reg_by_offset[off_int]
        if "aarch64" in self.language_id.lower() or "arm" in self.language_id.lower():
            if (off_int, sz) in self._SLEIGH_ARM64_OFFSET_TO_NAME:
                return self._SLEIGH_ARM64_OFFSET_TO_NAME[(off_int, sz)]
        else:
            if (off_int, sz) in self._SLEIGH_X86_OFFSET_TO_NAME:
                return self._SLEIGH_X86_OFFSET_TO_NAME[(off_int, sz)]
        return None

    def _translate_varnode(self, vn: Any) -> Varnode:
        raw_space = getattr(vn, "space", None)
        if isinstance(raw_space, AddressSpace):
            space_name = raw_space.value
        elif isinstance(raw_space, str):
            space_name = raw_space.lower()
        else:
            space_name = str(getattr(raw_space, "name", "ram")).lower()

        size = int(getattr(vn, "size", 8))
        raw_offset = getattr(vn, "offset", 0)

        if space_name in ("const", "constant"):
            off_val = int(raw_offset, 16) if isinstance(raw_offset, str) and raw_offset.startswith("0x") else int(raw_offset)
            return Varnode(space=AddrSpace.CONSTANT, offset=off_val, size=size)
        elif space_name in ("unique", "uniq"):
            off_val = int(raw_offset, 16) if isinstance(raw_offset, str) and raw_offset.startswith("0x") else int(raw_offset)
            return Varnode(space=AddrSpace.UNIQUE, offset=off_val, size=size)
        elif space_name in ("register", "reg"):
            reg_name = self._resolve_register_name(vn)
            if reg_name is not None and reg_name in CANONICAL_REG_OFFSETS:
                canon_off = CANONICAL_REG_OFFSETS[reg_name]
            elif isinstance(raw_offset, int):
                canon_off = raw_offset if raw_offset >= 0x700 else (0x800 + raw_offset)
            else:
                canon_off = 0x800
            return Varnode(space=AddrSpace.REGISTER, offset=canon_off, size=size, reg_name=reg_name)
        else:
            off_val = int(raw_offset, 16) if isinstance(raw_offset, str) and raw_offset.startswith("0x") else int(raw_offset)
            return Varnode(space=AddrSpace.RAM, offset=off_val, size=size)

    @staticmethod
    def _translate_opcode(raw_opcode: Any) -> PcodeOpcode | None:
        if isinstance(raw_opcode, PcodeOpcode):
            return raw_opcode
        op_name = getattr(raw_opcode, "name", None) or str(raw_opcode)
        if "." in op_name:
            op_name = op_name.split(".")[-1]
        op_name = op_name.upper()
        if op_name == "IMARK":
            return None
        if hasattr(PcodeOpcode, op_name):
            return PcodeOpcode[op_name]
        return PcodeOpcode.UNIMPLEMENTED

    def lift_bytes(
        self,
        code: bytes,
        base_addr: int = 0x1000,
        max_insns: int | None = None,
    ) -> List[PcodeOp]:
        """Lifts `code` at `base_addr` via `pypcode` into canonical `PcodeOp`s."""
        if not code:
            return []
        try:
            tx = self.ctx.translate(code, base_address=base_addr, max_instructions=max_insns or 0)
        except TypeError:
            tx = self.ctx.translate(code, base_addr, max_insns or 0)

        raw_ops = getattr(tx, "ops", tx)
        ops: List[PcodeOp] = []
        current_pc = base_addr

        for raw_op in raw_ops:
            raw_opc = getattr(raw_op, "opcode", None)
            opc_name = (getattr(raw_opc, "name", None) or str(raw_opc)).split(".")[-1].upper()
            raw_inputs = list(getattr(raw_op, "inputs", []))

            if opc_name == "IMARK":
                if raw_inputs:
                    current_pc = int(getattr(raw_inputs[0], "offset", current_pc))
                continue

            opcode = self._translate_opcode(raw_opc)
            if opcode is None:
                continue

            op_pc = getattr(raw_op, "pc", None)
            if op_pc is None:
                seq = getattr(raw_op, "seq", None)
                if seq is not None:
                    target = getattr(seq, "target", None) or getattr(seq, "pc", None)
                    if target is not None:
                        op_pc = int(getattr(target, "offset", target))
            if op_pc is None:
                op_pc = current_pc

            inputs = [self._translate_varnode(v) for v in raw_inputs]
            raw_out = getattr(raw_op, "output", None)
            output = self._translate_varnode(raw_out) if raw_out is not None else None
            ops.append(PcodeOp(opcode=opcode, inputs=inputs, output=output, pc=int(op_pc)))

        return ops


# ==============================================================================
# Persistent SuperGhidra Oracle Daemon P-Code RPC Backend
# ==============================================================================

class _DualAvailableDescriptor:
    """Allows `DaemonPcodeBackend.is_available()` to be called on class or instance."""

    def __init__(self, func: Callable[..., bool]):
        self.func = func

    def __get__(self, instance: DaemonPcodeBackend | None, owner: Any = None) -> Callable[..., bool]:
        if instance is None:
            def _cls_check(host: str = "127.0.0.1", port: int = 5073, timeout: float = 0.25) -> bool:
                return self.func(None, host=host, port=port, timeout=timeout)
            return _cls_check

        def _inst_check() -> bool:
            return self.func(instance, host=instance.host, port=instance.port, timeout=instance.timeout)
        return _inst_check


class DaemonPcodeBackend:
    """
    Connects to the persistent SuperGhidra Oracle Daemon over TCP JSON RPC
    (`host="127.0.0.1"`, `port=5073`) and translates daemon P-code op dicts
    into canonical `List[PcodeOp]`.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5073,
        timeout: float = 2.0,
        arch: str = "x86_64",
        rpc_client: Callable[[Dict[str, Any]], Any] | None = None,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.arch = arch
        self.rpc_client = rpc_client

    @_DualAvailableDescriptor
    def is_available(
        self: DaemonPcodeBackend | None,
        host: str = "127.0.0.1",
        port: int = 5073,
        timeout: float = 0.25,
    ) -> bool:
        if self is not None and self.rpc_client is not None:
            return True
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    @staticmethod
    def parse_varnode_dict(vn_data: Dict[str, Any] | Varnode) -> Varnode:
        if isinstance(vn_data, Varnode):
            return vn_data
        raw_space = str(vn_data.get("space", "ram")).lower()
        size = int(vn_data.get("size", 8))
        raw_off = vn_data.get("offset", vn_data.get("value", 0))
        reg_name = vn_data.get("reg_name") or vn_data.get("name")
        if isinstance(reg_name, str):
            reg_name = reg_name.lower()

        if raw_space in ("const", "constant"):
            off = int(raw_off, 16) if isinstance(raw_off, str) and raw_off.startswith("0x") else int(raw_off)
            return Varnode(space=AddrSpace.CONSTANT, offset=off, size=size)
        elif raw_space in ("unique", "uniq"):
            off = int(raw_off, 16) if isinstance(raw_off, str) and raw_off.startswith("0x") else int(raw_off)
            return Varnode(space=AddrSpace.UNIQUE, offset=off, size=size)
        elif raw_space in ("register", "reg"):
            if isinstance(raw_off, str) and not raw_off.startswith("0x") and not raw_off.isdigit():
                reg_name = raw_off.lower()
            if reg_name and reg_name in CANONICAL_REG_OFFSETS:
                off = CANONICAL_REG_OFFSETS[reg_name]
            elif isinstance(raw_off, str) and raw_off.startswith("0x"):
                off = int(raw_off, 16)
            else:
                off = int(raw_off)
            return Varnode(space=AddrSpace.REGISTER, offset=off, size=size, reg_name=reg_name)
        else:
            off = int(raw_off, 16) if isinstance(raw_off, str) and raw_off.startswith("0x") else int(raw_off)
            return Varnode(space=AddrSpace.RAM, offset=off, size=size)

    @classmethod
    def parse_pcode_ops(cls, raw_ops: List[Dict[str, Any]], default_pc: int = 0x1000) -> List[PcodeOp]:
        ops: List[PcodeOp] = []
        for item in raw_ops:
            if isinstance(item, PcodeOp):
                ops.append(item)
                continue
            raw_opc = item.get("opcode") or item.get("mnemonic") or "UNIMPLEMENTED"
            if isinstance(raw_opc, PcodeOpcode):
                opcode = raw_opc
            elif isinstance(raw_opc, int):
                opcode = PcodeOpcode(raw_opc)
            else:
                opc_str = str(raw_opc).split(".")[-1].upper()
                opcode = PcodeOpcode[opc_str] if hasattr(PcodeOpcode, opc_str) else PcodeOpcode.UNIMPLEMENTED

            raw_pc = item.get("seq_addr", item.get("pc", item.get("address", default_pc)))
            if isinstance(raw_pc, str):
                pc_val = int(raw_pc, 16) if raw_pc.startswith("0x") else int(raw_pc)
            else:
                pc_val = int(raw_pc)

            raw_out = item.get("output")
            output = cls.parse_varnode_dict(raw_out) if raw_out is not None else None
            inputs = [cls.parse_varnode_dict(v) for v in item.get("inputs", [])]

            if opcode == PcodeOpcode.LOAD and len(inputs) == 1:
                inputs.insert(0, Varnode(AddrSpace.RAM, 0, output.size if output else 8))
            elif opcode == PcodeOpcode.STORE and len(inputs) == 2:
                inputs.insert(0, Varnode(AddrSpace.RAM, 0, inputs[1].size))

            ops.append(PcodeOp(opcode=opcode, inputs=inputs, output=output, pc=pc_val))
        return ops

    def _send_rpc(self, payload: Dict[str, Any]) -> Any:
        if self.rpc_client is not None:
            return self.rpc_client(payload)

        msg = (json.dumps(payload) + "\n").encode("utf-8")
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
            sock.sendall(msg)
            chunks: List[bytes] = []
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if b"\n" in data:
                    break
        raw_text = b"".join(chunks).decode("utf-8").strip()
        if not raw_text:
            raise RuntimeError("Empty response from SuperGhidra Oracle Daemon")
        return json.loads(raw_text.splitlines()[0])

    def lift_bytes(
        self,
        code: bytes,
        base_addr: int = 0x1000,
        max_insns: int | None = None,
    ) -> List[PcodeOp]:
        """Requests P-Code operations from the persistent SuperGhidra daemon over TCP JSON RPC."""
        req: Dict[str, Any] = {
            "cmd": "pcode",
            "address": hex(base_addr),
            "max_insns": max_insns,
            "arch": self.arch,
            "bytes": code.hex() if code else "",
        }
        resp = self._send_rpc(req)
        if isinstance(resp, list):
            raw_ops = resp
        elif isinstance(resp, dict):
            if resp.get("status") == "error" or "error" in resp:
                raise RuntimeError(f"Daemon P-code RPC error: {resp.get('error', resp)}")
            raw_ops = resp.get("ops") or resp.get("pcode") or resp.get("result") or []
        else:
            raw_ops = []
        return self.parse_pcode_ops(raw_ops, default_pc=base_addr)


# ==============================================================================
# Unified Multi-Tier P-Code Lifter (pypcode -> daemon -> builtin)
# ==============================================================================

class UnifiedPcodeLifter:
    """
    Multi-tier P-Code lifter supporting `arch="arm64" | "x86_64" | "x86"`.
    Backend resolution order for `backend="auto"`:
      1. `PypcodeSleighBackend` (if `pypcode` is installed or injected)
      2. `DaemonPcodeBackend` (if daemon is reachable or injected)
      3. Built-in pure-Python lifters (`ARM64PcodeLifter` or `X86_64PcodeLifter`)
    """

    def __init__(
        self,
        arch: str = "arm64",
        backend: str = "auto",
        daemon_host: str = "127.0.0.1",
        daemon_port: int = 5073,
        daemon_timeout: float = 0.5,
        daemon_backend: DaemonPcodeBackend | None = None,
        pypcode_backend: PypcodeSleighBackend | None = None,
    ):
        self.arch = self._normalize_arch(arch)
        self.backend = backend.lower()
        self.daemon_host = daemon_host
        self.daemon_port = daemon_port
        self.daemon_timeout = daemon_timeout
        self.daemon_backend = daemon_backend
        self.pypcode_backend = pypcode_backend

        if self.arch == "arm64":
            self.builtin_lifter: ARM64PcodeLifter | X86_64PcodeLifter = ARM64PcodeLifter()
        elif self.arch == "x86_64":
            self.builtin_lifter = X86_64PcodeLifter(mode=64)
        else:
            self.builtin_lifter = X86_64PcodeLifter(mode=32)

    @staticmethod
    def _normalize_arch(arch: str) -> str:
        low = arch.strip().lower()
        if low in ("arm64", "aarch64", "aarch64:le:64:v8a"):
            return "arm64"
        if low in ("x86_64", "amd64", "x64", "x86:le:64:default"):
            return "x86_64"
        if low in ("x86", "i386", "x86_32", "x86:le:32:default"):
            return "x86"
        raise ValueError(f"Unsupported architecture '{arch}'; expected 'arm64', 'x86_64', or 'x86'")

    def lift_with_provenance(
        self,
        code: bytes,
        base_addr: int = 0x1000,
        max_insns: int | None = None,
        backend: str | None = None,
    ) -> Tuple[List[PcodeOp], str]:
        """Lifts `code` and returns `(ops, backend_used)` where `backend_used` is `'pypcode' | 'daemon' | 'builtin'`."""
        choice = (backend or self.backend).strip().lower()
        if choice not in ("auto", "pypcode", "daemon", "builtin"):
            raise ValueError(f"Unknown backend '{choice}'; expected 'auto', 'pypcode', 'daemon', or 'builtin'")

        if choice == "pypcode":
            pp_backend = self.pypcode_backend or PypcodeSleighBackend(self.arch)
            return pp_backend.lift_bytes(code, base_addr=base_addr, max_insns=max_insns), "pypcode"

        if choice == "daemon":
            dm_backend = self.daemon_backend or DaemonPcodeBackend(
                host=self.daemon_host,
                port=self.daemon_port,
                timeout=self.daemon_timeout,
                arch=self.arch,
            )
            if not dm_backend.is_available():
                raise RuntimeError(f"Daemon backend not reachable at {dm_backend.host}:{dm_backend.port}")
            return dm_backend.lift_bytes(code, base_addr=base_addr, max_insns=max_insns), "daemon"

        if choice == "builtin":
            return self.builtin_lifter.lift_bytes(code, base_addr=base_addr, max_insns=max_insns), "builtin"

        # choice == "auto"
        if self.pypcode_backend is not None or PypcodeSleighBackend.is_available():
            try:
                pp_backend = self.pypcode_backend or PypcodeSleighBackend(self.arch)
                ops = pp_backend.lift_bytes(code, base_addr=base_addr, max_insns=max_insns)
                return ops, "pypcode"
            except Exception:
                pass

        if self.daemon_backend is not None and self.daemon_backend.is_available():
            try:
                ops = self.daemon_backend.lift_bytes(code, base_addr=base_addr, max_insns=max_insns)
                return ops, "daemon"
            except Exception:
                pass
        elif self.daemon_port != 5073 and DaemonPcodeBackend.is_available(self.daemon_host, self.daemon_port, self.daemon_timeout):
            try:
                dm_backend = DaemonPcodeBackend(
                    host=self.daemon_host,
                    port=self.daemon_port,
                    timeout=self.daemon_timeout,
                    arch=self.arch,
                )
                ops = dm_backend.lift_bytes(code, base_addr=base_addr, max_insns=max_insns)
                return ops, "daemon"
            except Exception:
                pass

        return self.builtin_lifter.lift_bytes(code, base_addr=base_addr, max_insns=max_insns), "builtin"

    def lift_bytes(
        self,
        code: bytes,
        base_addr: int = 0x1000,
        max_insns: int | None = None,
        backend: str | None = None,
    ) -> List[PcodeOp]:
        """Lifts `code` into `List[PcodeOp]` using configured backend resolution order."""
        ops, _ = self.lift_with_provenance(code, base_addr=base_addr, max_insns=max_insns, backend=backend)
        return ops

    def lift_block(self, base_pc: int, machine_bytes: bytes) -> List[PcodeOp]:
        """Compatibility alias for `lift_bytes(machine_bytes, base_addr=base_pc)`."""
        return self.lift_bytes(machine_bytes, base_addr=base_pc)


# ==============================================================================
# P-Code SSA & Graph Representation
# ==============================================================================

class PcodeGraphBuilder:
    """Constructs CFG adjacency matrices and Varnode feature tensors from P-Code ops."""

    @staticmethod
    def build_adjacency_matrix(ops: List[PcodeOp], max_nodes: int = 128) -> Tuple[Any, Dict[str, Any]]:
        """
        Builds a fixed-shape binary adjacency matrix (max_nodes, max_nodes)
        for TPU systolic arrays or GNN inference (Section 7).
        """
        num_ops = min(len(ops), max_nodes)
        if HAS_NUMPY:
            adj = np.zeros((max_nodes, max_nodes), dtype=np.float32)
        else:
            adj = [[0.0] * max_nodes for _ in range(max_nodes)]

        # Map PC to operation index
        pc_to_idx = {op.pc: idx for idx, op in enumerate(ops[:num_ops])}

        for i, op in enumerate(ops[:num_ops]):
            # Fallthrough sequential edge
            if i + 1 < num_ops and op.opcode != PcodeOpcode.RETURN and op.opcode != PcodeOpcode.BRANCH:
                if HAS_NUMPY:
                    adj[i, i + 1] = 1.0
                else:
                    adj[i][i + 1] = 1.0

            # Direct branch target edge
            if op.opcode in (PcodeOpcode.BRANCH, PcodeOpcode.CBRANCH, PcodeOpcode.CALL):
                if op.inputs and op.inputs[0].space == AddressSpace.CONST:
                    target_pc = op.inputs[0].offset
                    if target_pc in pc_to_idx:
                        target_idx = pc_to_idx[target_pc]
                        if HAS_NUMPY:
                            adj[i, target_idx] = 1.0
                        else:
                            adj[i][target_idx] = 1.0

        meta = {
            "total_ops": len(ops),
            "matrix_size": max_nodes,
            "connected_nodes": num_ops
        }
        return adj, meta


