"""
SuperGhidra Cross-Version Automated Struct Shift Migrator Tool
(struct_shift_migrator.py)

Frontier 6: Cross-Version Automated Struct Shift Migrator Tool.
Features:
1. Analyzes two binary versions (e.g. libg.so v1 vs v2).
2. Extracts memory access instructions (LDR/STR/LDP/STP in ARM64, MOV in x86-64).
3. Matches functions across versions (by symbol name, export, or anchor access patterns).
4. Discovers struct field displacement shifts (e.g. offset 0x20 -> 0x24).
5. Detects:
   - Insertion points (e.g. 4-byte insertion at 0x14).
   - Field expansions (e.g. 32-bit field expanded to 64-bit).
   - Alignment adjustments (compiler padding / reordering).
6. Generates C++ header patch (guest_hook.h diff / updated header with shifted offsets).
7. Emits detailed JSON struct migration report with shift deltas.
"""

from __future__ import annotations

import dataclasses
import difflib
import json
import os
import re
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:  # package import or flat module import
    from . import binary_loader, x86_decode
except ImportError:
    import binary_loader
    import x86_decode

# -----------------------------------------------------------------------------
# 1. Memory Access Instruction Model & ARM64/x86 Instruction Decoder
# -----------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class MemoryAccess:
    """Represents a decoded memory load/store instruction referencing a struct offset."""
    pc: int
    mnemonic: str  # e.g. "LDR", "STR", "LDRB", "LDP", "MOV"
    base_reg: str  # e.g. "x0", "x19", "rdi"
    target_reg: str  # e.g. "w1", "x0", "eax"
    displacement: int  # immediate offset from base pointer (e.g. 0x20)
    access_size: int  # size in bytes: 1, 2, 4, 8, 16
    is_write: bool
    raw_insn: int = 0
    instruction_text: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pc": f"0x{self.pc:08X}",
            "mnemonic": self.mnemonic,
            "base_reg": self.base_reg,
            "target_reg": self.target_reg,
            "displacement": f"0x{self.displacement:04X}",
            "displacement_int": self.displacement,
            "access_size": self.access_size,
            "is_write": self.is_write,
            "instruction_text": self.instruction_text,
        }


def decode_arm64_memory_access(pc: int, insn: int) -> Optional[MemoryAccess]:
    """
    Decodes ARM64 memory instructions with immediate displacement:
    - LDR / STR (unsigned immediate, V==0 general-purpose 8/16/32/64-bit, V==1 SIMD/FP 8/16/32/64/128-bit)
    - LDUR / STUR (unscaled immediate)
    - LDP / STP (pair load/store, general-purpose and SIMD/FP)
    """
    # 1a. General-purpose Unsigned immediate LDR / STR (V == 0):
    # Pattern: (insn & 0x3F000000) == 0x39000000
    if (insn & 0x3F000000) == 0x39000000:
        size = (insn >> 30) & 0x03
        is_load = bool((insn >> 22) & 0x01)
        imm12 = (insn >> 10) & 0xFFF
        offset = imm12 << size
        rn = (insn >> 5) & 0x1F
        rt = insn & 0x1F

        access_size = 1 << size
        mnemonic = "LDR" if is_load else "STR"
        if size == 0:
            mnemonic += "B"
            t_reg = f"w{rt}"
        elif size == 1:
            mnemonic += "H"
            t_reg = f"w{rt}"
        elif size == 2:
            t_reg = f"w{rt}"
        else:
            t_reg = f"x{rt}"

        b_reg = "sp" if rn == 31 else f"x{rn}"
        insn_text = f"{mnemonic} {t_reg}, [{b_reg}, #0x{offset:X}]"

        return MemoryAccess(
            pc=pc,
            mnemonic=mnemonic,
            base_reg=b_reg,
            target_reg=t_reg,
            displacement=offset,
            access_size=access_size,
            is_write=not is_load,
            raw_insn=insn,
            instruction_text=insn_text,
        )

    # 1b. SIMD/FP Unsigned immediate LDR / STR (V == 1):
    # Pattern: (insn & 0x3F000000) == 0x3D000000
    if (insn & 0x3F000000) == 0x3D000000:
        size_code = (insn >> 30) & 0x03
        opc = (insn >> 22) & 0x03
        is_load = bool(opc & 0x01)
        scale = 4 if (size_code == 0 and (opc & 0x02)) else size_code
        access_size = 1 << scale
        imm12 = (insn >> 10) & 0xFFF
        offset = imm12 << scale
        rn = (insn >> 5) & 0x1F
        rt = insn & 0x1F

        reg_prefix = {0: "b", 1: "h", 2: "s", 3: "d", 4: "q"}[scale]
        t_reg = f"{reg_prefix}{rt}"
        mnemonic = "LDR" if is_load else "STR"
        b_reg = "sp" if rn == 31 else f"x{rn}"
        insn_text = f"{mnemonic} {t_reg}, [{b_reg}, #0x{offset:X}]"

        return MemoryAccess(
            pc=pc,
            mnemonic=mnemonic,
            base_reg=b_reg,
            target_reg=t_reg,
            displacement=offset,
            access_size=access_size,
            is_write=not is_load,
            raw_insn=insn,
            instruction_text=insn_text,
        )

    # 2. LDUR / STUR (unscaled immediate, signed 9-bit):
    # Pattern: (insn & 0x3B200C00) == 0x38000000
    if (insn & 0x3B200C00) == 0x38000000:
        size_code = (insn >> 30) & 0x03
        opc = (insn >> 22) & 0x03
        is_load = bool(opc & 0x01)
        is_simd = bool((insn >> 26) & 0x01)
        imm9 = (insn >> 12) & 0x1FF
        if imm9 >= 0x100:
            imm9 -= 0x200
        rn = (insn >> 5) & 0x1F
        rt = insn & 0x1F

        if is_simd:
            scale = 4 if (size_code == 0 and (opc & 0x02)) else size_code
            access_size = 1 << scale
            reg_prefix = {0: "b", 1: "h", 2: "s", 3: "d", 4: "q"}[scale]
            t_reg = f"{reg_prefix}{rt}"
        else:
            access_size = 1 << size_code
            t_reg = f"x{rt}" if size_code == 3 else f"w{rt}"

        mnemonic = "LDUR" if is_load else "STUR"
        b_reg = "sp" if rn == 31 else f"x{rn}"
        insn_text = f"{mnemonic} {t_reg}, [{b_reg}, #0x{imm9:X}]"

        return MemoryAccess(
            pc=pc,
            mnemonic=mnemonic,
            base_reg=b_reg,
            target_reg=t_reg,
            displacement=imm9,
            access_size=access_size,
            is_write=not is_load,
            raw_insn=insn,
            instruction_text=insn_text,
        )

    # 3a. General-purpose LDP / STP (Load/Store Pair, V == 0):
    # Pattern: (insn & 0x7E000000) in (0x28000000, 0x29000000)
    if (insn & 0x7E000000) in (0x28000000, 0x29000000):
        opc = (insn >> 30) & 0x03
        is_load = bool((insn >> 22) & 0x01)
        scale = 2 + ((insn >> 31) & 0x01)  # 2 for 32-bit (4 bytes), 3 for 64-bit (8 bytes)
        imm7 = (insn >> 15) & 0x7F
        if imm7 >= 0x40:
            imm7 -= 0x80
        offset = imm7 << scale
        rn = (insn >> 5) & 0x1F
        rt = insn & 0x1F
        rt2 = (insn >> 10) & 0x1F

        access_size = 1 << scale
        mnemonic = "LDP" if is_load else "STP"
        prefix = "x" if scale == 3 else "w"
        t_reg = f"{prefix}{rt}"
        b_reg = "sp" if rn == 31 else f"x{rn}"
        insn_text = f"{mnemonic} {prefix}{rt}, {prefix}{rt2}, [{b_reg}, #0x{offset:X}]"

        return MemoryAccess(
            pc=pc,
            mnemonic=mnemonic,
            base_reg=b_reg,
            target_reg=t_reg,
            displacement=offset,
            access_size=access_size,
            is_write=not is_load,
            raw_insn=insn,
            instruction_text=insn_text,
        )

    # 3b. SIMD/FP LDP / STP (Load/Store Pair, V == 1):
    # Pattern: (insn & 0x7E000000) in (0x2C000000, 0x2D000000) or (insn & 0x3E000000) in (0x2C000000, 0x2D000000)
    if (insn & 0x7E000000) in (0x2C000000, 0x2D000000) or (insn & 0x3E000000) in (0x2C000000, 0x2D000000):
        opc = (insn >> 30) & 0x03
        if opc <= 2:
            is_load = bool((insn >> 22) & 0x01)
            scale = 2 + opc  # 2 -> 4B ('s'), 3 -> 8B ('d'), 4 -> 16B ('q')
            imm7 = (insn >> 15) & 0x7F
            if imm7 >= 0x40:
                imm7 -= 0x80
            offset = imm7 << scale
            rn = (insn >> 5) & 0x1F
            rt = insn & 0x1F
            rt2 = (insn >> 10) & 0x1F

            access_size = 1 << scale
            mnemonic = "LDP" if is_load else "STP"
            prefix = {2: "s", 3: "d", 4: "q"}[scale]
            t_reg = f"{prefix}{rt}"
            b_reg = "sp" if rn == 31 else f"x{rn}"
            insn_text = f"{mnemonic} {prefix}{rt}, {prefix}{rt2}, [{b_reg}, #0x{offset:X}]"

            return MemoryAccess(
                pc=pc,
                mnemonic=mnemonic,
                base_reg=b_reg,
                target_reg=t_reg,
                displacement=offset,
                access_size=access_size,
                is_write=not is_load,
                raw_insn=insn,
                instruction_text=insn_text,
            )

    return None


_X86_64_REGS_64 = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
_X86_64_REGS_32 = (
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
)
_X86_64_REGS_16 = (
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
)


_X86_MEM_MNEMONICS_MAP0 = {
    0x8B: "MOV", 0x8A: "MOV", 0x89: "MOV", 0x88: "MOV", 0xC7: "MOV", 0xC6: "MOV",
    0x8D: "LEA", 0x63: "MOVSXD",
    0x03: "ADD", 0x02: "ADD", 0x01: "ADD", 0x00: "ADD",
    0x2B: "SUB", 0x2A: "SUB", 0x29: "SUB", 0x28: "SUB",
    0x3B: "CMP", 0x3A: "CMP", 0x39: "CMP", 0x38: "CMP",
    0x33: "XOR", 0x31: "XOR", 0x23: "AND", 0x21: "AND", 0x0B: "OR", 0x09: "OR",
    0x85: "TEST", 0x84: "TEST", 0x87: "XCHG", 0x86: "XCHG", 0x69: "IMUL", 0x6B: "IMUL",
}
_X86_GRP1_NAMES = ("ADD", "OR", "ADC", "SBB", "AND", "SUB", "XOR", "CMP")
_SSE_SUFFIX = {None: "PS", 0x66: "PD", 0xF3: "SS", 0xF2: "SD"}
_SSE_ARITH = {0x51: "SQRT", 0x58: "ADD", 0x59: "MUL", 0x5C: "SUB", 0x5D: "MIN", 0x5E: "DIV", 0x5F: "MAX",
              0x54: "AND", 0x55: "ANDN", 0x56: "OR", 0x57: "XOR"}


def _x86_mem_mnemonic(insn: "x86_decode.X86Insn") -> Optional[str]:
    """Mnemonic for an instruction whose ModRM memory operand is a data access we track."""
    op, mp = insn.opcode, insn.map
    if mp == 0 and not insn.vex:
        if op in _X86_MEM_MNEMONICS_MAP0:
            return _X86_MEM_MNEMONICS_MAP0[op]
        if op in (0x80, 0x81, 0x83):
            return _X86_GRP1_NAMES[insn.reg & 7]
        if op in (0xF6, 0xF7) and (insn.reg & 7) in (0, 1):
            return "TEST"
        if op in (0xFE, 0xFF) and (insn.reg & 7) in (0, 1):
            return "INC" if (insn.reg & 7) == 0 else "DEC"
        if op == 0xFF and (insn.reg & 7) == 2:
            return "CALL"  # indirect call through a vtable slot: [vptr + slot*8]
        return None
    if mp != 1:
        return None
    pfx = insn.mandatory_prefix
    v = "V" if insn.vex else ""
    if op in (0xB6, 0xB7):
        return "MOVZX"
    if op in (0xBE, 0xBF):
        return "MOVSX"
    if op in (0x10, 0x11):
        return v + ("MOVSS" if pfx == 0xF3 else "MOVSD" if pfx == 0xF2 else "MOVUPD" if pfx == 0x66 else "MOVUPS")
    if op in (0x28, 0x29):
        return v + ("MOVAPD" if pfx == 0x66 else "MOVAPS")
    if op in (0x6F, 0x7F):
        return v + ("MOVDQA" if pfx == 0x66 else "MOVDQU" if pfx == 0xF3 else "MOVQ")
    if op in (0x6E, 0x7E, 0xD6):
        return v + ("MOVQ" if (insn.rex_w or op == 0xD6 or (op == 0x7E and pfx == 0xF3)) else "MOVD")
    if op in (0x12, 0x13):
        return v + ("MOVLPD" if pfx == 0x66 else "MOVLPS")
    if op in (0x16, 0x17):
        return v + ("MOVHPD" if pfx == 0x66 else "MOVHPS")
    if op in (0x2E, 0x2F):
        return v + ("UCOMI" if op == 0x2E else "COMI") + ("SD" if pfx == 0x66 else "SS")
    if op in _SSE_ARITH:
        return v + _SSE_ARITH[op] + _SSE_SUFFIX.get(pfx, "PS")
    if op == 0x5A:
        return v + "CVT"
    if op in (0x2A, 0x2C, 0x2D):
        return v + "CVT"
    if 0x40 <= op <= 0x4F:
        return "CMOV"
    if op == 0xAF:
        return "IMUL"
    return None


def decode_x86_64_memory_accesses(
    code_bytes: bytes,
    base_pc: int = 0x401000,
    mode: int = 64,
) -> List[MemoryAccess]:
    """
    Decodes struct-style memory accesses `[base_reg + disp]` from x86 / x86-64 code
    (mode 64 or 32) using the table-driven x86_decode module, so the sweep stays in sync
    through any instruction mix (SSE/AVX included).

    Reported: MOV loads/stores (incl. immediate stores), MOVZX/MOVSX/MOVSXD, LEA, ALU ops
    with a memory operand (ADD/SUB/CMP/AND/OR/XOR/TEST/...), SSE/AVX scalar and vector
    moves and arithmetic (MOVSS/MOVSD/MOVUPS/...), CMOVcc and indirect vtable calls.
    Skipped: register-only forms, RIP-relative/absolute addresses and indexed [base+idx*s]
    operands, which are not single struct fields.
    """
    accesses: List[MemoryAccess] = []
    for insn in x86_decode.iter_decode(code_bytes, base_pc, mode):
        if insn.invalid or insn.modrm is None or insn.mem is None:
            continue
        mem = insn.mem
        if mem.rip_relative or mem.base is None or mem.index is not None:
            continue
        mnemonic = _x86_mem_mnemonic(insn)
        if mnemonic is None:
            continue
        is_simd = insn.map == 1 and mnemonic not in ("MOVZX", "MOVSX", "CMOV", "IMUL")
        if mnemonic == "LEA":
            access_size = insn.operand_size
        elif mnemonic == "CALL":
            access_size = 8 if mode == 64 else 4
        else:
            access_size = insn.memory_access_size() or insn.operand_size
        if is_simd:
            target = ("ymm" if insn.vex_l else "xmm") + str(insn.reg)
        elif mnemonic == "CALL":
            target = "pc"
        else:
            reg_size = insn.operand_size if mnemonic in ("MOVZX", "MOVSX", "MOVSXD") else (
                1 if insn.is_byte_op else insn.operand_size)
            if mode == 32 and reg_size == 8:
                reg_size = 4
            target = insn.reg_name(insn.reg, reg_size)
        disp = mem.disp
        sign = f"+ 0x{disp:X}" if disp >= 0 else f"- 0x{-disp:X}"
        is_write = insn.is_memory_write()
        if is_write:
            text = f"{mnemonic} [{mem.base} {sign}], {target}"
        else:
            text = f"{mnemonic} {target}, [{mem.base} {sign}]"
        start = insn.address - base_pc
        accesses.append(MemoryAccess(
            pc=insn.address,
            mnemonic=mnemonic,
            base_reg=mem.base,
            target_reg=target,
            displacement=disp,
            access_size=access_size,
            is_write=is_write,
            raw_insn=int.from_bytes(code_bytes[start : start + insn.length], "little"),
            instruction_text=text,
        ))
    return accesses


def parse_disassembly_line(line: str, default_pc: int = 0) -> Optional[MemoryAccess]:
    """
    Parses a single textual disassembly line (from Ghidra, objdump, IDA, etc.):
    e.g. "0x00010040: LDR W0, [X19, #0x24]" or "MOV [RDI + 0x28], EAX"
    """
    cleaned = line.strip()
    if not cleaned or cleaned.startswith("//") or cleaned.startswith(";"):
        return None

    pc = default_pc
    pc_match = re.match(r"^(?:0x)?([0-9a-fA-F]+)\s*[:]\s*(.*)$", cleaned)
    if pc_match:
        try:
            pc = int(pc_match.group(1), 16)
            cleaned = pc_match.group(2).strip()
        except Exception:
            pass

    # ARM64: LDR/STR reg, [base, #offset]
    arm_match = re.search(
        r"\b(LDR|STR|LDRB|STRB|LDRH|STRH|LDUR|STUR)\s+([a-zA-Z0-9]+)\s*,\s*\[\s*([a-zA-Z0-9]+)\s*,\s*#?([+-]?(?:0x[0-9a-fA-F]+|\d+))\s*\]",
        cleaned,
        re.IGNORECASE,
    )
    if arm_match:
        mnemonic = arm_match.group(1).upper()
        target_reg = arm_match.group(2).lower()
        base_reg = arm_match.group(3).lower()
        raw_disp = arm_match.group(4)
        disp = int(raw_disp, 16) if "0x" in raw_disp.lower() else int(raw_disp)
        is_write = mnemonic.startswith("ST")
        if target_reg.startswith("q"):
            size = 16
        elif target_reg.startswith("x") or target_reg.startswith("d"):
            size = 8
        elif target_reg.startswith("h"):
            size = 2
        elif target_reg.startswith("b"):
            size = 1
        else:
            size = 4
        if "B" in mnemonic:
            size = 1
        elif "H" in mnemonic:
            size = 2

        return MemoryAccess(
            pc=pc,
            mnemonic=mnemonic,
            base_reg=base_reg,
            target_reg=target_reg,
            displacement=disp,
            access_size=size,
            is_write=is_write,
            instruction_text=cleaned,
        )

    # x86-64: MOV/LEA/ADD/CMP [base + disp], reg OR MOV/LEA/ADD/CMP reg, [base + disp]
    x86_load = re.search(
        r"\b(MOV(?:Q|L|W|B)?|LEA|ADD|CMP)\s+([a-zA-Z0-9]+)\s*,\s*\[\s*([a-zA-Z0-9]+)\s*\+\s*#?([+-]?(?:0x[0-9a-fA-F]+|\d+))\s*\]",
        cleaned,
        re.IGNORECASE,
    )
    if x86_load:
        raw_mnem = x86_load.group(1).upper()
        mnem = "MOV" if raw_mnem.startswith("MOV") else raw_mnem
        target_reg = x86_load.group(2).lower()
        base_reg = x86_load.group(3).lower()
        raw_disp = x86_load.group(4)
        disp = int(raw_disp, 16) if "0x" in raw_disp.lower() else int(raw_disp)
        return MemoryAccess(
            pc=pc,
            mnemonic=mnem,
            base_reg=base_reg,
            target_reg=target_reg,
            displacement=disp,
            access_size=8 if (target_reg.startswith("r") and not target_reg.endswith(("d", "w", "b"))) else 4,
            is_write=False,
            instruction_text=cleaned,
        )

    x86_store = re.search(
        r"\b(MOV(?:Q|L|W|B)?|ADD|CMP)\s+\[\s*([a-zA-Z0-9]+)\s*\+\s*#?([+-]?(?:0x[0-9a-fA-F]+|\d+))\s*\]\s*,\s*([a-zA-Z0-9]+)",
        cleaned,
        re.IGNORECASE,
    )
    if x86_store:
        raw_mnem = x86_store.group(1).upper()
        mnem = "MOV" if raw_mnem.startswith("MOV") else raw_mnem
        base_reg = x86_store.group(2).lower()
        raw_disp = x86_store.group(3)
        target_reg = x86_store.group(4).lower()
        disp = int(raw_disp, 16) if "0x" in raw_disp.lower() else int(raw_disp)
        return MemoryAccess(
            pc=pc,
            mnemonic=mnem,
            base_reg=base_reg,
            target_reg=target_reg,
            displacement=disp,
            access_size=8 if (target_reg.startswith("r") and not target_reg.endswith(("d", "w", "b"))) else 4,
            is_write=(mnem != "CMP"),
            instruction_text=cleaned,
        )

    return None


# -----------------------------------------------------------------------------
# 2. Shift Discovery Models & Classifications
# -----------------------------------------------------------------------------

class ShiftType:
    IDENTICAL = "identical"
    INSERTION_SHIFT = "insertion_shift"
    EXPANSION_SHIFT = "expansion_shift"
    ALIGNMENT_ADJUSTMENT = "alignment_adjustment"
    DELETION_SHIFT = "deletion_shift"


@dataclasses.dataclass
class FieldMigration:
    """Represents a discovered struct field offset migration across binary versions."""
    field_name: str
    old_offset: int
    new_offset: int
    delta: int  # new_offset - old_offset
    shift_type: str
    confidence: float
    access_size: int
    sample_v1_insn: str = ""
    sample_v2_insn: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field_name": self.field_name,
            "old_offset": f"0x{self.old_offset:X}",
            "new_offset": f"0x{self.new_offset:X}",
            "old_offset_int": self.old_offset,
            "new_offset_int": self.new_offset,
            "delta": self.delta,
            "shift_type": self.shift_type,
            "confidence": round(self.confidence, 4),
            "access_size": self.access_size,
            "sample_v1_insn": self.sample_v1_insn,
            "sample_v2_insn": self.sample_v2_insn,
        }


@dataclasses.dataclass
class StructInsertion:
    """Represents a detected newly inserted field prior to a shift boundary."""
    offset: int
    size: int
    probable_type: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": f"0x{self.offset:X}",
            "offset_int": self.offset,
            "size": self.size,
            "probable_type": self.probable_type,
        }


@dataclasses.dataclass
class MigrationReport:
    """Comprehensive Cross-Version Struct Shift Migration Report."""
    struct_name: str
    old_binary: str
    new_binary: str
    matched_functions: int
    total_shifts_detected: int
    max_delta: int
    field_migrations: List[FieldMigration]
    insertions: List[StructInsertion]
    cpp_header_patch: str
    updated_header: str
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "struct_name": self.struct_name,
            "old_binary": self.old_binary,
            "new_binary": self.new_binary,
            "matched_functions": self.matched_functions,
            "total_shifts_detected": self.total_shifts_detected,
            "max_delta": self.max_delta,
            "field_migrations": [m.to_dict() for m in self.field_migrations],
            "insertions": [ins.to_dict() for ins in self.insertions],
            "cpp_header_patch": self.cpp_header_patch,
            "updated_header": self.updated_header,
            "summary": self.summary,
        }


# -----------------------------------------------------------------------------
# 3. Struct Shift Migrator Engine
# -----------------------------------------------------------------------------

class StructShiftMigrator:
    """
    Analyzes two binary versions to discover struct displacement shifts,
    detect field insertions and expansions, and generate C++ header patches.
    """

    def __init__(self):
        self._v1_functions: Dict[str, List[MemoryAccess]] = {}
        self._v2_functions: Dict[str, List[MemoryAccess]] = {}

    def load_functions_from_instructions(
        self,
        v1_data: Dict[str, List[Union[str, MemoryAccess, int]]],
        v2_data: Dict[str, List[Union[str, MemoryAccess, int]]],
    ) -> None:
        """Loads function memory accesses from text disassembly or pre-decoded accesses."""
        self._v1_functions = self._normalize_function_data(v1_data)
        self._v2_functions = self._normalize_function_data(v2_data)

    def _normalize_function_data(
        self,
        data: Dict[str, Union[bytes, bytearray, List[Union[str, MemoryAccess, int, bytes, bytearray]]]],
    ) -> Dict[str, List[MemoryAccess]]:
        normalized: Dict[str, List[MemoryAccess]] = {}
        for func_name, items in data.items():
            if isinstance(items, (bytes, bytearray)):
                normalized[func_name] = decode_x86_64_memory_accesses(bytes(items))
                continue
            accesses: List[MemoryAccess] = []
            for item in items:
                if isinstance(item, MemoryAccess):
                    accesses.append(item)
                elif isinstance(item, str):
                    acc = parse_disassembly_line(item)
                    if acc:
                        accesses.append(acc)
                elif isinstance(item, int):
                    acc = decode_arm64_memory_access(0, item)
                    if acc:
                        accesses.append(acc)
                elif isinstance(item, (bytes, bytearray)):
                    accesses.extend(decode_x86_64_memory_accesses(bytes(item)))
            normalized[func_name] = accesses
        return normalized

    def load_from_x86_64_bytes(
        self,
        v1_bytes: bytes,
        v2_bytes: bytes,
        base_pc: int = 0x401000,
    ) -> None:
        """Loads function memory accesses directly from raw x86_64 code bytes."""
        self._v1_functions = self._sweep_x86_64_functions(v1_bytes, base_pc)
        self._v2_functions = self._sweep_x86_64_functions(v2_bytes, base_pc)

    def load_from_elf_binaries(
        self,
        old_binary_path: str,
        new_binary_path: str,
    ) -> None:
        """
        Parses raw ELF/PE binary files, extracting instructions from executable sections.
        """
        self._v1_functions = self._extract_binary_accesses(old_binary_path)
        self._v2_functions = self._extract_binary_accesses(new_binary_path)

    def _extract_binary_accesses(self, path: str) -> Dict[str, List[MemoryAccess]]:
        """Reads executable instructions from binary and groups by candidate function blocks."""
        functions: Dict[str, List[MemoryAccess]] = {}
        if not os.path.exists(path):
            return functions

        with open(path, "rb") as f:
            raw = f.read()

        # Real ELF / PE / Mach-O images go through the shared loader (any bitness/endianness).
        if binary_loader.detect_format(raw) != "raw":
            try:
                image = binary_loader.load_binary(raw)
            except binary_loader.BinaryFormatError:
                image = None
            if image is not None and image.executable_sections():
                return self._extract_image_accesses(image)

        # Legacy: minimal/synthetic headers.  Check if ELF
        if raw.startswith(b"\x7fELF"):
            is_x86_64 = False
            if len(raw) >= 20:
                e_machine = struct.unpack_from("<H", raw, 18)[0]
                is_x86_64 = e_machine == 0x3E

            # Minimal pure-Python ELF section parser for .text
            # e_shoff at offset 40 (64-bit ELF)
            try:
                e_shoff = struct.unpack_from("<Q", raw, 40)[0]
                e_shentsize = struct.unpack_from("<H", raw, 58)[0]
                e_shnum = struct.unpack_from("<H", raw, 60)[0]
                e_shstrndx = struct.unpack_from("<H", raw, 62)[0]

                shstr_hdr = e_shoff + (e_shstrndx * e_shentsize)
                shstr_offset = struct.unpack_from("<Q", raw, shstr_hdr + 24)[0]

                text_offset = 0
                text_size = 0
                text_vaddr = 0

                for i in range(e_shnum):
                    sh_entry = e_shoff + (i * e_shentsize)
                    sh_name_idx = struct.unpack_from("<I", raw, sh_entry)[0]
                    # Read name from strtab
                    name_end = raw.find(b"\x00", shstr_offset + sh_name_idx)
                    sec_name = raw[shstr_offset + sh_name_idx : name_end].decode("latin-1")
                    if sec_name == ".text":
                        text_vaddr = struct.unpack_from("<Q", raw, sh_entry + 16)[0]
                        text_offset = struct.unpack_from("<Q", raw, sh_entry + 24)[0]
                        text_size = struct.unpack_from("<Q", raw, sh_entry + 32)[0]
                        break

                if text_size > 0:
                    text_bytes = raw[text_offset : text_offset + text_size]
                    if is_x86_64:
                        return self._sweep_x86_64_functions(text_bytes, text_vaddr or 0x401000, default_name="text_section")
                    return self._sweep_arm64_functions(text_bytes, text_vaddr, default_name="text_section")
            except Exception:
                pass

            if len(raw) > 16:
                hdr_len = 64 if (len(raw) > 64 and raw[20:64] == b"\x00" * 44) else (20 if is_x86_64 and len(raw) > 20 else 16)
                if is_x86_64:
                    return self._sweep_x86_64_functions(raw[hdr_len:], 0x401000, default_name="text_section")
                return self._sweep_arm64_functions(raw[16:], 0x1000, default_name="text_section")

        # Check if PE32+/PE64 ("MZ")
        if raw.startswith(b"MZ") and len(raw) >= 0x40:
            try:
                e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
                if e_lfanew + 24 <= len(raw) and raw[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                    machine, num_sections = struct.unpack_from("<HH", raw, e_lfanew + 4)
                    size_opt_hdr = struct.unpack_from("<H", raw, e_lfanew + 20)[0]
                    sec_table_off = e_lfanew + 24 + size_opt_hdr
                    for i in range(num_sections):
                        sh_off = sec_table_off + i * 40
                        if sh_off + 40 > len(raw):
                            break
                        sec_name = raw[sh_off : sh_off + 8].rstrip(b"\x00").decode("latin-1", errors="ignore")
                        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", raw, sh_off + 8)
                        if sec_name == ".text" and raw_size > 0:
                            text_bytes = raw[raw_ptr : raw_ptr + raw_size]
                            if machine == 0xAA64:
                                return self._sweep_arm64_functions(text_bytes, vaddr or 0x1000, default_name="text_section")
                            return self._sweep_x86_64_functions(text_bytes, vaddr or 0x401000, default_name="text_section")
            except Exception:
                pass

        # Fallback: scan whole buffer as instructions
        chunk = raw[: min(len(raw), 1024 * 1024)]
        arm_res = self._sweep_arm64_functions(chunk, 0x1000, default_name="binary_stream")
        if not any(arm_res.values()):
            x86_res = self._sweep_x86_64_functions(chunk, 0x401000, default_name="binary_stream")
            if any(x86_res.values()):
                return x86_res
        return arm_res

    def _sweep_x86_64_functions(
        self,
        code_bytes: bytes,
        base_pc: int = 0x401000,
        default_name: str = "text_section",
        mode: int = 64,
    ) -> Dict[str, List[MemoryAccess]]:
        """
        Sweeps x86 instructions (mode 64 or 32) and partitions functions after each decoded
        RET instruction (not every 0xC3 byte, which also occurs inside other instructions).
        Retains default_name when only 1 function is present.
        """
        if not code_bytes:
            return {default_name: []}

        all_accs = decode_x86_64_memory_accesses(code_bytes, base_pc=base_pc, mode=mode)
        ret_pcs = [i.address for i in x86_decode.iter_decode(code_bytes, base_pc, mode) if i.flow == "ret"]
        if len(ret_pcs) <= 1:
            return {default_name: all_accs}

        functions_list: List[List[MemoryAccess]] = []
        k = 0
        for r_pc in ret_pcs:
            accs = []
            while k < len(all_accs) and all_accs[k].pc <= r_pc:
                accs.append(all_accs[k])
                k += 1
            if accs:
                functions_list.append(accs)
        if k < len(all_accs):
            functions_list.append(all_accs[k:])

        if len(functions_list) <= 1:
            return {default_name: all_accs}

        return {f"func_{idx}": accs for idx, accs in enumerate(functions_list)}

    def _extract_image_accesses(self, image: "binary_loader.BinaryImage") -> Dict[str, List[MemoryAccess]]:
        """Per-function struct accesses for a loaded ELF / PE / Mach-O image.

        Functions are delimited by the image's known function starts (PE .pdata, exports,
        symbols, LC_FUNCTION_STARTS) and named by export/symbol where available, so the same
        function can be matched across versions by name.
        """
        import bisect

        if image.arch == "arm64":
            decode_region = self._sweep_arm64_instructions
        elif image.arch in ("x86_64", "x86"):
            mode = 64 if image.arch == "x86_64" else 32
            decode_region = lambda code, base: decode_x86_64_memory_accesses(code, base, mode)  # noqa: E731
        else:
            raise ValueError(f"struct shift analysis does not support {image.arch} binaries yet")

        names: Dict[int, str] = {s.address: s.name for s in image.symbols if s.kind == "func" and s.name}
        names.update({e.address: e.name for e in image.exports if e.name and e.forwarder is None})
        starts = sorted(set(image.function_starts) | set(names))
        functions: Dict[str, List[MemoryAccess]] = {}
        for region_va, code in image.code_regions():
            accs = decode_region(code, region_va)
            region_starts = [s for s in starts if region_va <= s < region_va + len(code)] or [region_va]
            pcs = [a.pc for a in accs]
            for idx, fs in enumerate(region_starts):
                end = region_starts[idx + 1] if idx + 1 < len(region_starts) else region_va + len(code)
                chunk = accs[bisect.bisect_left(pcs, fs) : bisect.bisect_left(pcs, end)]
                if chunk:
                    functions[names.get(fs, f"sub_{fs:x}")] = chunk
        return functions

    def _sweep_arm64_instructions(self, code_bytes: bytes, base_pc: int) -> List[MemoryAccess]:
        """Linear sweep of ARM64 machine instructions into a single list of memory accesses."""
        accesses: List[MemoryAccess] = []
        num_insns = len(code_bytes) // 4
        for i in range(num_insns):
            pc = base_pc + (i * 4)
            insn = struct.unpack_from("<I", code_bytes, i * 4)[0]
            acc = decode_arm64_memory_access(pc, insn)
            if acc:
                accesses.append(acc)
        return accesses

    def _sweep_arm64_functions(
        self,
        code_bytes: bytes,
        base_pc: int,
        default_name: str = "text_section",
    ) -> Dict[str, List[MemoryAccess]]:
        """
        Sweeps ARM64 instructions and partitions functions at RET (0xD65F03C0) boundaries.
        Retains default_name ("text_section" / "binary_stream") when only 1 function is present.
        """
        num_insns = len(code_bytes) // 4
        if num_insns == 0:
            return {default_name: []}

        functions_list: List[List[MemoryAccess]] = []
        current_accs: List[MemoryAccess] = []

        for i in range(num_insns):
            pc = base_pc + (i * 4)
            insn = struct.unpack_from("<I", code_bytes, i * 4)[0]
            acc = decode_arm64_memory_access(pc, insn)
            if acc:
                current_accs.append(acc)

            # Check if RET instruction (0xD65F03C0 or (insn & 0xFFFFFC1F) == 0xD65F0000)
            if (insn & 0xFFFFFC1F) == 0xD65F0000 or insn == 0xD65F03C0:
                functions_list.append(current_accs)
                current_accs = []

        if current_accs:
            functions_list.append(current_accs)

        # Filter out empty blocks if multiple functions exist
        non_empty = [f for f in functions_list if f]

        if len(non_empty) <= 1:
            accs = non_empty[0] if non_empty else (functions_list[0] if functions_list else [])
            return {default_name: accs}

        # Multi-function partitioning: "func_0", "func_1", ...
        return {f"func_{idx}": accs for idx, accs in enumerate(non_empty)}

    def analyze_shifts(
        self,
        struct_name: str = "TargetStruct",
        original_header: Optional[str] = None,
        old_binary_name: str = "binary_v1.so",
        new_binary_name: str = "binary_v2.so",
    ) -> MigrationReport:
        """
        Executes cross-version struct shift analysis:
        1. Correlates matched functions and extract displacement pairs.
        2. Discovers shift deltas and identifies insertion points.
        3. Generates C++ header patch and updated header definition.
        4. Compiles detailed JSON migration report.
        """
        # 1. Match functions across versions
        # Step 1a: Exact name matches
        matched_pairs: List[Tuple[str, str]] = []
        v1_matched: Set[str] = set()
        v2_matched: Set[str] = set()

        for fname in self._v1_functions:
            if fname in self._v2_functions:
                matched_pairs.append((fname, fname))
                v1_matched.add(fname)
                v2_matched.add(fname)

        # Step 1b: Access profile similarity for unmatched functions
        unmatched_v1 = [f for f in self._v1_functions if f not in v1_matched and self._v1_functions[f]]
        unmatched_v2 = [f for f in self._v2_functions if f not in v2_matched and self._v2_functions[f]]

        if unmatched_v1 and unmatched_v2:
            candidate_pairs = []
            for f1 in unmatched_v1:
                sig1 = [(a.base_reg, a.is_write, a.access_size) for a in self._v1_functions[f1]]
                for f2 in unmatched_v2:
                    sig2 = [(a.base_reg, a.is_write, a.access_size) for a in self._v2_functions[f2]]
                    sim = difflib.SequenceMatcher(None, sig1, sig2).ratio()
                    candidate_pairs.append((sim, f1, f2))

            candidate_pairs.sort(key=lambda x: x[0], reverse=True)
            for sim, f1, f2 in candidate_pairs:
                if f1 not in v1_matched and f2 not in v2_matched:
                    if sim >= 0.3:
                        matched_pairs.append((f1, f2))
                        v1_matched.add(f1)
                        v2_matched.add(f2)

        matched_funcs = 0
        displacement_pairs: List[Tuple[int, int, int, int, str, str]] = []  # (old_disp, new_disp, old_size, new_size, v1_text, v2_text)

        for f1, f2 in matched_pairs:
            v1_accs = self._v1_functions.get(f1, [])
            v2_accs = self._v2_functions.get(f2, [])
            if not v1_accs or not v2_accs:
                continue

            matched_funcs += 1

            if len(v1_accs) == len(v2_accs):
                # Check if base registers match directly by position
                all_base_match = all(a1.base_reg.lower() == a2.base_reg.lower() for a1, a2 in zip(v1_accs, v2_accs))
                if all_base_match:
                    for a1, a2 in zip(v1_accs, v2_accs):
                        displacement_pairs.append(
                            (a1.displacement, a2.displacement, a1.access_size, a2.access_size, a1.instruction_text, a2.instruction_text)
                        )
                else:
                    # Base registers differ across positions: match by (base_reg, access_size, ordinal)
                    v1_groups: Dict[Tuple[str, int], List[Any]] = {}
                    for a in v1_accs:
                        v1_groups.setdefault((a.base_reg.lower(), a.access_size), []).append(a)
                    v2_groups: Dict[Tuple[str, int], List[Any]] = {}
                    for a in v2_accs:
                        v2_groups.setdefault((a.base_reg.lower(), a.access_size), []).append(a)

                    for key, a1_list in v1_groups.items():
                        if key in v2_groups:
                            a2_list = v2_groups[key]
                            paired_count = min(len(a1_list), len(a2_list))
                            for ord_idx in range(paired_count):
                                a1 = a1_list[ord_idx]
                                a2 = a2_list[ord_idx]
                                displacement_pairs.append(
                                    (a1.displacement, a2.displacement, a1.access_size, a2.access_size, a1.instruction_text, a2.instruction_text)
                                )
                    # Ambiguous / unmatched registers are left unmatched
            else:
                # Sequence-aligned pairing using SequenceMatcher when lengths differ
                sig1 = [(a.base_reg.lower(), a.is_write, a.access_size) for a in v1_accs]
                sig2 = [(a.base_reg.lower(), a.is_write, a.access_size) for a in v2_accs]

                sm = difflib.SequenceMatcher(None, sig1, sig2)
                if sm.ratio() < 0.4:
                    sig1_rel = [(a.base_reg.lower(), a.is_write) for a in v1_accs]
                    sig2_rel = [(a.base_reg.lower(), a.is_write) for a in v2_accs]
                    sm = difflib.SequenceMatcher(None, sig1_rel, sig2_rel)

                for tag, i1, i2, j1, j2 in sm.get_opcodes():
                    if tag == "equal":
                        for k in range(i2 - i1):
                            a1 = v1_accs[i1 + k]
                            a2 = v2_accs[j1 + k]
                            if a1.base_reg.lower() == a2.base_reg.lower():
                                displacement_pairs.append(
                                    (a1.displacement, a2.displacement, a1.access_size, a2.access_size, a1.instruction_text, a2.instruction_text)
                                )
                    elif tag == "replace":
                        min_k = min(i2 - i1, j2 - j1)
                        for k in range(min_k):
                            a1 = v1_accs[i1 + k]
                            a2 = v2_accs[j1 + k]
                            if a1.base_reg.lower() == a2.base_reg.lower():
                                displacement_pairs.append(
                                    (a1.displacement, a2.displacement, a1.access_size, a2.access_size, a1.instruction_text, a2.instruction_text)
                                )

        # Deduplicate and aggregate displacement transitions
        # Map old_offset -> List of (new_offset, old_size, new_size, v1_text, v2_text)
        offset_map: Dict[int, List[Tuple[int, int, int, str, str]]] = {}
        for old_d, new_d, old_s, new_s, t1, t2 in displacement_pairs:
            offset_map.setdefault(old_d, []).append((new_d, old_s, new_s, t1, t2))

        sorted_old_offsets = sorted(offset_map.keys())

        field_migrations: List[FieldMigration] = []
        shifts_detected = 0
        max_delta = 0
        deltas: List[Tuple[int, int]] = []  # (old_offset, delta)

        prev_was_expansion = False
        prev_expansion_delta = 0

        for old_off in sorted_old_offsets:
            entries = offset_map[old_off]
            # Vote on most frequent new_offset
            new_counts: Dict[int, int] = {}
            for new_off, _, _, _, _ in entries:
                new_counts[new_off] = new_counts.get(new_off, 0) + 1

            best_new_off = max(new_counts.keys(), key=lambda k: new_counts[k])
            confidence = new_counts[best_new_off] / len(entries)
            delta = best_new_off - old_off

            sample_entry = entries[0]
            old_size = sample_entry[1]
            new_size = sample_entry[2]
            t1 = sample_entry[3]
            t2 = sample_entry[4]
            access_size = max(old_size, new_size)

            if delta != 0:
                shifts_detected += 1
                if abs(delta) > abs(max_delta):
                    max_delta = delta

            # Determine shift type
            if delta == 0:
                if old_size < new_size:
                    stype = ShiftType.EXPANSION_SHIFT
                    prev_was_expansion = True
                    prev_expansion_delta = new_size - old_size
                else:
                    stype = ShiftType.IDENTICAL
                    prev_was_expansion = False
                    prev_expansion_delta = 0
            elif delta < 0:
                stype = ShiftType.DELETION_SHIFT
                prev_was_expansion = False
                prev_expansion_delta = 0
            else:  # delta > 0
                if old_size < new_size:
                    stype = ShiftType.EXPANSION_SHIFT
                    prev_was_expansion = True
                    prev_expansion_delta = delta
                elif old_size > 1 and (old_off % old_size != 0) and (best_new_off % old_size == 0):
                    stype = ShiftType.ALIGNMENT_ADJUSTMENT
                    prev_was_expansion = False
                    prev_expansion_delta = 0
                elif new_size == 8 and (old_off % 8 != 0) and (best_new_off % 8 == 0) and (delta == (8 - (old_off % 8))):
                    stype = ShiftType.ALIGNMENT_ADJUSTMENT
                    prev_was_expansion = False
                    prev_expansion_delta = 0
                elif prev_was_expansion and (delta == prev_expansion_delta):
                    stype = ShiftType.EXPANSION_SHIFT
                else:
                    stype = ShiftType.INSERTION_SHIFT
                    prev_was_expansion = False
                    prev_expansion_delta = 0

            deltas.append((old_off, delta))
            field_name = f"field_0x{old_off:X}"

            field_migrations.append(
                FieldMigration(
                    field_name=field_name,
                    old_offset=old_off,
                    new_offset=best_new_off,
                    delta=delta,
                    shift_type=stype,
                    confidence=confidence,
                    access_size=access_size,
                    sample_v1_insn=t1,
                    sample_v2_insn=t2,
                )
            )

        # Detect insertion points: points where delta increased
        insertions: List[StructInsertion] = []
        for i in range(len(deltas)):
            cur_off, cur_delta = deltas[i]
            prev_delta = deltas[i - 1][1] if i > 0 else 0
            if cur_delta > prev_delta:
                insertion_size = cur_delta - prev_delta
                # Insertion happened at offset cur_off
                ptype = (
                    "uint8_t" if insertion_size == 1
                    else "uint16_t" if insertion_size == 2
                    else "uint32_t" if insertion_size == 4
                    else "uint64_t" if insertion_size == 8
                    else f"uint8_t[{insertion_size}]"
                )
                insertions.append(
                    StructInsertion(
                        offset=cur_off,
                        size=insertion_size,
                        probable_type=ptype,
                    )
                )

        # Generate C++ Header Patch
        cpp_patch, updated_header = self._generate_cpp_patch_and_header(
            struct_name=struct_name,
            original_header=original_header,
            field_migrations=field_migrations,
            insertions=insertions,
        )

        summary = (
            f"Analyzed {matched_funcs} matched functions across {old_binary_name} and {new_binary_name}. "
            f"Detected {shifts_detected} shifted struct field displacements (max delta: {max_delta:+d} bytes) "
            f"and {len(insertions)} insertion boundaries."
        )

        return MigrationReport(
            struct_name=struct_name,
            old_binary=old_binary_name,
            new_binary=new_binary_name,
            matched_functions=matched_funcs,
            total_shifts_detected=shifts_detected,
            max_delta=max_delta,
            field_migrations=field_migrations,
            insertions=insertions,
            cpp_header_patch=cpp_patch,
            updated_header=updated_header,
            summary=summary,
        )

    def _generate_cpp_patch_and_header(
        self,
        struct_name: str,
        original_header: Optional[str],
        field_migrations: List[FieldMigration],
        insertions: List[StructInsertion],
    ) -> Tuple[str, str]:
        """Synthesizes updated C++ struct definition and diff patch."""
        # If original header is provided, parse and adjust its lines
        if original_header and original_header.strip():
            old_header_lines = original_header.splitlines()
            new_header_lines: List[str] = []

            # Map old_offset -> FieldMigration
            mig_map = {m.old_offset: m for m in field_migrations}
            ins_map = {ins.offset: ins for ins in insertions}

            for line in old_header_lines:
                # Check for offset comment e.g. /* 0x0020 */ or // 0x20
                off_match = re.search(r"(?:\/\*|\/\/)\s*(?:0x)?([0-9a-fA-F]+)\s*(?:\*\/)?", line)
                if off_match:
                    try:
                        off_val = int(off_match.group(1), 16)
                        # Check if an insertion precedes this offset
                        if off_val in ins_map:
                            ins = ins_map[off_val]
                            new_header_lines.append(
                                f"    /* 0x{ins.offset:04X} (NEW INSERTION, size: 0x{ins.size:X}) */ {ins.probable_type} unk_field_0x{ins.offset:X};"
                            )

                        if off_val in mig_map:
                            m = mig_map[off_val]
                            if m.delta != 0:
                                # Replace line with updated offset
                                shifted_line = re.sub(
                                    r"(?:\/\*|\/\/)\s*(?:0x)?[0-9a-fA-F]+\s*(?:\*\/)?",
                                    f"/* 0x{m.new_offset:04X} (shifted {m.delta:+d}, old: 0x{m.old_offset:04X}) */",
                                    line,
                                )
                                new_header_lines.append(shifted_line)
                                continue
                    except Exception:
                        pass
                new_header_lines.append(line)

            updated_code = "\n".join(new_header_lines) + "\n"
            diff_lines = list(
                difflib.unified_diff(
                    old_header_lines,
                    new_header_lines,
                    fromfile=f"old_{struct_name.lower()}.h",
                    tofile=f"new_{struct_name.lower()}.h",
                    lineterm="",
                )
            )
            patch_text = "\n".join(diff_lines)
            return patch_text, updated_code

        # Otherwise synthesize canonical C++ header
        lines: List[str] = [
            f"// Auto-generated cross-version migration patch for {struct_name}",
            f"struct {struct_name} {{",
        ]
        old_lines: List[str] = [
            f"struct {struct_name} {{",
        ]

        ins_map = {ins.offset: ins for ins in insertions}

        for m in field_migrations:
            old_type = "uint64_t" if m.access_size == 8 else "uint32_t" if m.access_size == 4 else "uint8_t"
            old_lines.append(f"    /* 0x{m.old_offset:04X} */ {old_type} {m.field_name};")

            if m.old_offset in ins_map:
                ins = ins_map[m.old_offset]
                lines.append(
                    f"    /* 0x{ins.offset:04X} (NEW INSERTION, size: 0x{ins.size:X}) */ {ins.probable_type} unk_field_0x{ins.offset:X};"
                )

            if m.delta != 0:
                lines.append(
                    f"    /* 0x{m.new_offset:04X} (shifted {m.delta:+d}, old: 0x{m.old_offset:04X}) */ {old_type} {m.field_name};"
                )
            else:
                lines.append(f"    /* 0x{m.new_offset:04X} */ {old_type} {m.field_name};")

        lines.append("};")
        old_lines.append("};")

        old_str = "\n".join(old_lines) + "\n"
        new_str = "\n".join(lines) + "\n"

        diff = list(
            difflib.unified_diff(
                old_lines,
                lines,
                fromfile=f"old_{struct_name.lower()}.h",
                tofile=f"new_{struct_name.lower()}.h",
                lineterm="",
            )
        )
        return "\n".join(diff), new_str


# -----------------------------------------------------------------------------
# 4. Standalone Tool Entrypoint for MCP and CLI
# -----------------------------------------------------------------------------

def migrate_struct_shifts(
    old_binary_path: str,
    new_binary_path: str,
    struct_name: Optional[str] = None,
    original_header: Optional[str] = None,
) -> MigrationReport:
    """
    Analyzes two binary versions to discover struct displacement shifts and generate C++ header patches.
    Arguments:
        old_binary_path: Path to v1 binary or disassembly file.
        new_binary_path: Path to v2 binary or disassembly file.
        struct_name: Name of target struct (default: 'TargetStruct').
        original_header: Optional existing C++ header source to patch.
    """
    migrator = StructShiftMigrator()
    name = struct_name or "TargetStruct"

    # Check if paths are text disassembly files or binary files
    if os.path.exists(old_binary_path) and os.path.exists(new_binary_path):
        is_old_text = False
        try:
            with open(old_binary_path, "r", encoding="utf-8") as f:
                content = f.read(2048)
                if any(x in content for x in ("LDR", "STR", "MOV", "struct", "void")):
                    is_old_text = True
        except Exception:
            pass

        if is_old_text:
            with open(old_binary_path, "r", encoding="utf-8") as f1, open(new_binary_path, "r", encoding="utf-8") as f2:
                v1_lines = f1.readlines()
                v2_lines = f2.readlines()
            migrator.load_functions_from_instructions(
                {"main": v1_lines},
                {"main": v2_lines},
            )
        else:
            migrator.load_from_elf_binaries(old_binary_path, new_binary_path)
    else:
        # Fallback if virtual/mock names passed
        migrator.load_from_elf_binaries(old_binary_path, new_binary_path)

    return migrator.analyze_shifts(
        struct_name=name,
        original_header=original_header,
        old_binary_name=os.path.basename(old_binary_path),
        new_binary_name=os.path.basename(new_binary_path),
    )
