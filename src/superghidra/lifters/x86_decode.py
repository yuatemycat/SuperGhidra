"""
x86_decode.py - table-driven x86 / x86-64 instruction length & operand decoder.

Decodes enough of every instruction to step through real compiler output without
losing sync (MSVC, GCC, Clang; SSE/AVX/AVX-512 included):

  * modes: 16, 32 and 64-bit
  * legacy prefixes, REX, VEX (C4/C5), EVEX (62), XOP (8F)
  * opcode maps: 1-byte, 0F, 0F38, 0F3A (+ 3DNow! 0F 0F)
  * ModRM / SIB / displacement (16-bit and 32/64-bit addressing, RIP-relative)
  * immediates, relative branch targets, near/far returns

It is not a full disassembler: it gives lengths, the memory operand, immediates,
branch targets and a coarse operation class, which is what CFG extraction, struct
offset analysis and function seeding need.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

__all__ = ["MemOperand", "X86Insn", "decode", "iter_decode", "REG64", "REG32", "REG16", "REG8"]

REG64 = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
REG32 = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
         "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d")
REG16 = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
         "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w")
REG8 = ("al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b")
_REG8_LEGACY = ("al", "cl", "dl", "bl", "ah", "ch", "dh", "bh")
_ADDR16 = (("bx", "si"), ("bx", "di"), ("bp", "si"), ("bp", "di"), ("si", None), ("di", None), ("bp", None), ("bx", None))

_PREFIXES = {0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67}


@dataclass
class MemOperand:
    base: str | None
    index: str | None
    scale: int
    disp: int
    rip_relative: bool = False
    segment: str | None = None
    addr_bits: int = 64

    def effective_address(self, next_ip: int) -> int | None:
        """Absolute address for RIP-relative or base-less operands, else None."""
        if self.rip_relative:
            return (next_ip + self.disp) & ((1 << self.addr_bits) - 1)
        if self.base is None and self.index is None:
            return self.disp & ((1 << self.addr_bits) - 1)
        return None


@dataclass
class X86Insn:
    address: int
    length: int
    mode: int
    map: int  # 0 = 1-byte, 1 = 0F, 2 = 0F38, 3 = 0F3A, 8..10 = XOP
    opcode: int
    prefix66: bool = False
    prefix67: bool = False
    rep: int | None = None  # 0xF2 / 0xF3 (also SSE mandatory prefixes)
    lock: bool = False
    rex: int = 0
    vex: str | None = None  # "vex" | "evex" | "xop"
    vex_l: int = 0
    vex_w: bool = False
    vex_pp: int = 0
    modrm: int | None = None
    reg: int = 0  # ModRM.reg with REX.R/VEX.R extension
    rm: int = 0  # ModRM.rm with REX.B extension (register form)
    mem: MemOperand | None = None
    imm: int | None = None
    imm_size: int = 0
    flow: str | None = None  # ret | jmp | jcc | call | jmp_ind | call_ind | int | loop | halt
    target: int | None = None
    invalid: bool = False

    # ---- derived helpers ----

    @property
    def end(self) -> int:
        return self.address + self.length

    @property
    def rex_w(self) -> bool:
        return bool(self.rex & 8) or (self.vex is not None and self.vex_w)

    @property
    def mandatory_prefix(self) -> int | None:
        """SSE mandatory prefix: 0x66, 0xF3, 0xF2 (VEX pp encodes the same)."""
        if self.vex:
            return {0: None, 1: 0x66, 2: 0xF3, 3: 0xF2}[self.vex_pp]
        if self.rep:
            return self.rep
        return 0x66 if self.prefix66 else None

    @property
    def operand_size(self) -> int:
        if self.rex_w:
            return 8
        if self.prefix66:
            return 2
        return 4

    def reg_name(self, idx: int, size: int) -> str:
        if size == 8:
            return REG64[idx]
        if size == 2:
            return REG16[idx]
        if size == 1:
            return REG8[idx] if (self.rex or idx >= 8) else _REG8_LEGACY[idx & 7]
        return REG32[idx]

    @property
    def is_byte_op(self) -> bool:
        if self.map != 0 or self.vex:
            return False
        op = self.opcode
        if op < 0x40 and (op & 7) in (0, 2, 4):
            return True
        return op in (0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE,
                      0xC0, 0xC6, 0xD0, 0xD2, 0xF6, 0xFE) or 0xB0 <= op <= 0xB7

    def memory_access_size(self) -> int | None:
        """Bytes read/written through `mem`, or None when not a data access / unknown."""
        if self.mem is None:
            return None
        op, mp, pfx = self.opcode, self.map, self.mandatory_prefix
        if mp == 0:
            if op == 0x8D:
                return None  # LEA computes an address; no access
            if 0xD8 <= op <= 0xDF:
                return None  # x87: size depends on sub-opcode
            if op == 0xFF and self.reg in (2, 4):
                return 8 if self.mode == 64 else 4
            if op == 0xFF and self.reg in (3, 5):
                return None
            if self.is_byte_op:
                return 1
            if op in (0x8C, 0x8E):
                return 2
            return self.operand_size
        if mp == 1:
            if op in (0xB6, 0xBE):
                return 1
            if op in (0xB7, 0xBF):
                return 2
            if 0x90 <= op <= 0x9F:
                return 1  # SETcc
            if op in (0x10, 0x11, 0x51, 0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F, 0x2A, 0x2C, 0x2D, 0xC2):
                if pfx == 0xF3:
                    return 4
                if pfx == 0xF2:
                    return 8
                return 32 if self.vex_l else 16
            if op in (0x2E, 0x2F):
                return 8 if pfx == 0x66 else 4
            if op in (0x12, 0x13, 0x16, 0x17, 0xD6):
                return 8
            if op in (0x6E, 0x7E):
                if op == 0x7E and pfx == 0xF3:
                    return 8  # movq xmm, m64
                return 8 if self.rex_w else 4
            if op in (0x28, 0x29, 0x2B, 0x6F, 0x7F, 0xE7, 0x14, 0x15, 0x54, 0x55, 0x56, 0x57,
                      0x5B, 0xE6, 0xEF, 0xEB, 0xDB, 0xDF, 0xFE, 0xFA, 0xD4, 0xFB, 0x70):
                return 32 if self.vex_l else 16
            if op == 0x5A:
                return 4 if pfx == 0xF3 else 8 if pfx == 0xF2 else (16 if pfx == 0x66 else 8)
            if op == 0xC3:
                return self.operand_size  # movnti
            if op in (0xAF, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B,
                      0x4C, 0x4D, 0x4E, 0x4F, 0xA3, 0xAB, 0xB3, 0xBB, 0xBC, 0xBD, 0xC0, 0xC1, 0xB0, 0xB1):
                return 1 if op in (0xC0, 0xB0) else self.operand_size
            return None
        return None

    def is_memory_write(self) -> bool:
        if self.mem is None:
            return False
        op, mp = self.opcode, self.map
        if mp == 0:
            if op < 0x40 and (op & 7) in (0, 1) and (op & 0x38) != 0x38:
                return True  # ALU r/m, r (not CMP)
            if op in (0x88, 0x89, 0x8C, 0xC6, 0xC7, 0x86, 0x87, 0x8F):
                return True
            if op in (0x80, 0x81, 0x82, 0x83) and self.reg != 7:
                return True
            if op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
                return True
            if op in (0xF6, 0xF7) and self.reg in (2, 3):
                return True
            if op in (0xFE, 0xFF) and self.reg in (0, 1):
                return True
            return False
        if mp == 1:
            return op in (0x11, 0x13, 0x17, 0x29, 0x2B, 0x7F, 0xD6, 0xE7, 0xC3, 0xAB, 0xB3, 0xBB,
                          0xC0, 0xC1, 0xB0, 0xB1) or 0x90 <= op <= 0x9F or (op == 0x7E and self.mandatory_prefix != 0xF3)
        if mp == 3:
            return op in (0x14, 0x15, 0x16, 0x17, 0x19, 0x1D, 0x39, 0x3B, 0x7D)
        return False


# --------------------------------------------------------------------------------------
# Opcode property tables
# --------------------------------------------------------------------------------------


def _set(*ranges) -> frozenset:
    out = set()
    for r in ranges:
        if isinstance(r, tuple):
            out.update(range(r[0], r[1] + 1))
        else:
            out.add(r)
    return frozenset(out)


# 1-byte map: opcodes that take a ModRM byte (62/C4/C5/8F handled separately for EVEX/VEX/XOP).
_MODRM1 = _set((0x00, 0x03), (0x08, 0x0B), (0x10, 0x13), (0x18, 0x1B), (0x20, 0x23), (0x28, 0x2B),
               (0x30, 0x33), (0x38, 0x3B), 0x62, 0x63, 0x69, 0x6B, (0x80, 0x8F), 0xC0, 0xC1, 0xC4, 0xC5,
               0xC6, 0xC7, (0xD0, 0xD3), (0xD8, 0xDF), 0xF6, 0xF7, 0xFE, 0xFF)
_IMM8_1 = _set(0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34, 0x3C, 0x6A, 0x6B, 0x80, 0x82, 0x83, 0xA8,
               (0xB0, 0xB7), 0xC0, 0xC1, 0xC6, 0xCD, 0xD4, 0xD5, (0xE4, 0xE7))
_IMMZ_1 = _set(0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D, 0x68, 0x69, 0x81, 0xA9, 0xC7)
_REL8_1 = _set((0x70, 0x7F), (0xE0, 0xE3), 0xEB)
_INVALID64_1 = _set(0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x27, 0x2F, 0x37, 0x3F, 0x60, 0x61,
                    0x82, 0x9A, 0xD4, 0xD5, 0xD6, 0xEA)

# 0F map: opcodes WITHOUT ModRM.
_NO_MODRM_0F = _set(0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0E, (0x30, 0x37), 0x39,
                    (0x3B, 0x3F), 0x77, (0x80, 0x8F), 0xA0, 0xA1, 0xA2, 0xA8, 0xA9, 0xAA, (0xC8, 0xCF))
_IMM8_0F = _set((0x70, 0x73), 0xA4, 0xAC, 0xBA, 0xC2, 0xC4, 0xC5, 0xC6)
_VEX_IMM8_MAP1 = _set((0x70, 0x73), 0xC2, 0xC4, 0xC5, 0xC6)


def _u(code: bytes, pos: int, size: int, signed: bool) -> int:
    fmt = {1: "b", 2: "h", 4: "i", 8: "q"}[size]
    return struct.unpack_from("<" + (fmt if signed else fmt.upper()), code, pos)[0]


# --------------------------------------------------------------------------------------
# Decoder
# --------------------------------------------------------------------------------------


def decode(code: bytes, offset: int = 0, address: int = 0, mode: int = 64) -> X86Insn:
    """Decode one instruction at code[offset]; `address` is its virtual address.

    Never raises: undecodable or truncated bytes yield a 1-byte X86Insn with invalid=True.
    """
    n = len(code)
    start = offset
    pos = offset
    p66 = p67 = lock = False
    rep = None
    segment = None

    def bad() -> X86Insn:
        return X86Insn(address, 1, mode, 0, code[start] if start < n else 0, invalid=True)

    # Legacy prefixes.
    while pos < n and code[pos] in _PREFIXES and pos - start < 14:
        b = code[pos]
        if b == 0x66:
            p66 = True
        elif b == 0x67:
            p67 = True
        elif b == 0xF0:
            lock = True
        elif b in (0xF2, 0xF3):
            rep = b
        else:
            segment = {0x2E: "cs", 0x36: "ss", 0x3E: "ds", 0x26: "es", 0x64: "fs", 0x65: "gs"}[b]
        pos += 1
    if pos >= n:
        return bad()

    rex = 0
    if mode == 64 and 0x40 <= code[pos] <= 0x4F:
        rex = code[pos]
        pos += 1
        if pos >= n:
            return bad()

    insn = X86Insn(address, 0, mode, 0, 0, prefix66=p66, prefix67=p67, rep=rep, lock=lock, rex=rex)
    addr_bits = (32 if p67 else 64) if mode == 64 else ((16 if p67 else 32) if mode == 32 else (32 if p67 else 16))
    opsize = 8 if (rex & 8) else (2 if p66 else 4)
    if mode == 16:
        opsize = 4 if p66 else 2

    op = code[pos]
    has_modrm = False
    imm_sizes = []  # list of (size, signed)
    rel_size = 0
    vex_r = vex_x = vex_b = 0

    def need(k: int) -> bool:
        return pos + k <= n

    # ---- VEX / EVEX / XOP ----
    is_vex2 = op == 0xC5 and need(2) and (mode == 64 or code[pos + 1] >= 0xC0)
    is_vex3 = op == 0xC4 and need(3) and (mode == 64 or code[pos + 1] >= 0xC0)
    is_evex = op == 0x62 and need(4) and (mode == 64 or code[pos + 1] >= 0xC0)
    is_xop = op == 0x8F and need(3) and (code[pos + 1] & 0x1F) >= 8
    if is_vex2:
        b1 = code[pos + 1]
        vex_r = 0 if b1 & 0x80 else 1
        insn.vex, insn.vex_l, insn.vex_pp, insn.map = "vex", (b1 >> 2) & 1, b1 & 3, 1
        pos += 2
    elif is_vex3 or is_xop:
        b1, b2 = code[pos + 1], code[pos + 2]
        vex_r, vex_x, vex_b = (0 if b1 & 0x80 else 1), (0 if b1 & 0x40 else 1), (0 if b1 & 0x20 else 1)
        insn.vex = "xop" if is_xop else "vex"
        insn.map = b1 & 0x1F
        insn.vex_w, insn.vex_l, insn.vex_pp = bool(b2 & 0x80), (b2 >> 2) & 1, b2 & 3
        pos += 3
    elif is_evex:
        p0, p1, p2 = code[pos + 1], code[pos + 2], code[pos + 3]
        vex_r, vex_x, vex_b = (0 if p0 & 0x80 else 1), (0 if p0 & 0x40 else 1), (0 if p0 & 0x20 else 1)
        insn.vex, insn.map = "evex", p0 & 0x07
        insn.vex_w, insn.vex_pp, insn.vex_l = bool(p1 & 0x80), p1 & 3, (p2 >> 5) & 3
        pos += 4
    if insn.vex:
        if not need(1):
            return bad()
        op = code[pos]
        pos += 1
        mp = insn.map
        if insn.vex == "xop":
            has_modrm = True
            if mp == 8:
                imm_sizes.append((1, False))
            elif mp == 0xA:
                imm_sizes.append((4, False))
        else:
            if mp not in (1, 2, 3, 5, 6):
                return bad()
            has_modrm = not (mp == 1 and op == 0x77)
            if mp == 3 or (mp == 1 and op in _VEX_IMM8_MAP1):
                imm_sizes.append((1, False))
        if insn.vex_w:
            opsize = 8
    else:
        pos += 1
        if op == 0x0F:
            if not need(1):
                return bad()
            op = code[pos]
            pos += 1
            if op == 0x38 or op == 0x3A:
                if not need(1):
                    return bad()
                insn.map = 2 if op == 0x38 else 3
                op = code[pos]
                pos += 1
                has_modrm = True
                if insn.map == 3:
                    imm_sizes.append((1, False))
            else:
                insn.map = 1
                if op == 0x0F:  # 3DNow!: ModRM then an opcode byte acting as imm8
                    has_modrm = True
                    imm_sizes.append((1, False))
                else:
                    has_modrm = op not in _NO_MODRM_0F
                    if op in _IMM8_0F:
                        imm_sizes.append((1, False))
                    if 0x80 <= op <= 0x8F:
                        rel_size = 2 if (mode != 64 and opsize == 2) else 4
                        insn.flow = "jcc"
                    elif op == 0x05 or op == 0x34:
                        insn.flow = "int"  # syscall / sysenter
                    elif op in (0x07, 0x35):
                        insn.flow = "ret"  # sysret / sysexit
                    elif op == 0x0B:
                        insn.flow = "halt"  # ud2
        else:
            insn.map = 0
            if mode == 64 and op in _INVALID64_1:
                insn.invalid = True
            has_modrm = op in _MODRM1
            if op in _IMM8_1:
                imm_sizes.append((1, op not in (0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xCD, 0xE4, 0xE5, 0xE6, 0xE7, 0xA8)))
            if op in _IMMZ_1:
                imm_sizes.append((2 if opsize == 2 else 4, True))
            if 0xB8 <= op <= 0xBF:
                imm_sizes.append((8 if opsize == 8 else (2 if opsize == 2 else 4), False))
            if op in (0xC2, 0xCA):
                imm_sizes.append((2, False))
            if op == 0xC8:
                imm_sizes += [(2, False), (1, False)]
            if op in (0x9A, 0xEA) and mode != 64:
                imm_sizes += [(2 if opsize == 2 else 4, False), (2, False)]
            if 0xA0 <= op <= 0xA3:
                imm_sizes.append((addr_bits // 8, False))
            if op in _REL8_1:
                rel_size = 1
                insn.flow = "jcc" if (0x70 <= op <= 0x7F) else ("loop" if 0xE0 <= op <= 0xE3 else "jmp")
            elif op in (0xE8, 0xE9):
                rel_size = 4 if (mode == 64 or opsize != 2) else 2
                insn.flow = "call" if op == 0xE8 else "jmp"
            elif op in (0xC2, 0xC3, 0xCA, 0xCB, 0xCF):
                insn.flow = "ret"
            elif op in (0xCC, 0xCD, 0xCE, 0xF1):
                insn.flow = "int"
            elif op == 0xF4:
                insn.flow = "halt"

    insn.opcode = op

    # ---- ModRM / SIB / displacement ----
    if has_modrm:
        if not need(1):
            return bad()
        modrm = code[pos]
        pos += 1
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        r_ext = (rex >> 2) & 1 if not insn.vex else vex_r
        x_ext = (rex >> 1) & 1 if not insn.vex else vex_x
        b_ext = rex & 1 if not insn.vex else vex_b
        insn.modrm = modrm
        insn.reg = reg | (r_ext << 3)
        insn.rm = rm | (b_ext << 3)

        # Group-specific immediates that depend on ModRM.reg.
        if insn.map == 0 and op in (0xF6, 0xF7) and reg in (0, 1):
            imm_sizes.append((1, True) if op == 0xF6 else (2 if opsize == 2 else 4, True))
        if insn.map == 0 and op == 0xC7 and modrm == 0xF8:  # xbegin rel
            imm_sizes = []
            rel_size = 2 if opsize == 2 else 4
            insn.flow = "jcc"
        if insn.map == 0 and op == 0xFF:
            if reg == 2:
                insn.flow = "call_ind"
            elif reg == 4:
                insn.flow = "jmp_ind"
            elif reg in (3, 5):
                insn.flow = "call_ind" if reg == 3 else "jmp_ind"

        if mod != 3:
            if addr_bits == 16:
                disp_size = 2 if (mod == 2 or (mod == 0 and rm == 6)) else (1 if mod == 1 else 0)
                base, index = (None, None) if (mod == 0 and rm == 6) else _ADDR16[rm]
                if not need(disp_size):
                    return bad()
                disp = _u(code, pos, disp_size, True) if disp_size else 0
                pos += disp_size
                insn.mem = MemOperand(base, index, 1, disp, False, segment, 16)
            else:
                regs = REG64 if addr_bits == 64 else REG32
                base_i: int | None = rm | (b_ext << 3)
                index_i: int | None = None
                scale = 1
                rip = False
                disp_size = 1 if mod == 1 else (4 if mod == 2 else 0)
                if rm == 4:
                    if not need(1):
                        return bad()
                    sib = code[pos]
                    pos += 1
                    ss, idx, bse = sib >> 6, (sib >> 3) & 7, sib & 7
                    scale = 1 << ss
                    idx_full = idx | (x_ext << 3)
                    index_i = None if idx_full == 4 else idx_full
                    base_i = bse | (b_ext << 3)
                    if bse == 5 and mod == 0:
                        base_i = None
                        disp_size = 4
                elif rm == 5 and mod == 0:
                    base_i = None
                    disp_size = 4
                    rip = mode == 64
                if not need(disp_size):
                    return bad()
                disp = _u(code, pos, disp_size, True) if disp_size else 0
                pos += disp_size
                insn.mem = MemOperand(
                    regs[base_i] if base_i is not None else None,
                    regs[index_i] if index_i is not None else None,
                    scale, disp, rip, segment, addr_bits,
                )

    # ---- immediates / relative targets ----
    for size, signed in imm_sizes:
        if not need(size):
            return bad()
        val = _u(code, pos, size, signed)
        pos += size
        if insn.imm is None:
            insn.imm, insn.imm_size = val, size
    if rel_size:
        if not need(rel_size):
            return bad()
        rel = _u(code, pos, rel_size, True)
        pos += rel_size
        insn.target = (address + (pos - start) + rel) & ((1 << (64 if mode == 64 else 32)) - 1)

    # ---- implicit memory operands (no ModRM) ----
    if insn.map == 0 and not insn.vex and insn.mem is None:
        regs = REG64 if addr_bits == 64 else (REG32 if addr_bits == 32 else REG16)
        if 0xA0 <= op <= 0xA3 and insn.imm is not None:  # mov acc, [moffs] / mov [moffs], acc
            insn.mem = MemOperand(None, None, 1, insn.imm, False, segment, addr_bits)
        elif op in (0xA4, 0xA5, 0xA6, 0xA7, 0xAC, 0xAD, 0x6E, 0x6F):  # movs/cmps/lods/outs read [rsi]
            insn.mem = MemOperand(regs[6], None, 1, 0, False, segment, addr_bits)
        elif op in (0xAA, 0xAB, 0xAE, 0xAF, 0x6C, 0x6D):  # stos/scas/ins use es:[rdi]
            insn.mem = MemOperand(regs[7], None, 1, 0, False, "es", addr_bits)

    length = pos - start
    if length > 15:
        return bad()
    insn.length = length
    return insn


def iter_decode(code: bytes, address: int = 0, mode: int = 64, start: int = 0,
                end: int | None = None) -> Iterator[X86Insn]:
    """Linear sweep over code[start:end]. `address` is the VA of code[0].

    Invalid bytes are emitted as 1-byte invalid instructions so the sweep always advances.
    """
    pos = start
    stop = len(code) if end is None else min(end, len(code))
    while pos < stop:
        insn = decode(code, pos, address + pos, mode)
        yield insn
        pos += max(1, insn.length)
