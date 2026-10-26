"""
arm_thumb_decode.py - ARM32 (A32) and Thumb / Thumb-2 (T32) instruction decoder.

Zero-dependency decoder designed for:
  - Instruction length determination: ARM32 (4 bytes), Thumb-16 (2 bytes), Thumb-32 (4 bytes).
  - Memory access displacement extraction: LDR, STR, LDRB, STRB, LDRH, STRH, LDRD, STRD
    with immediate displacement [Rn, #imm].
  - Branch and call instruction classification:
      * ARM32: B, BL, BX, BLX.
      * Thumb-16: B<cond>, B<uncond>, BLX <Rm>, BX <Rm>, CBZ, CBNZ.
      * Thumb-32: BL, BLX <imm>, B.W, B<cond>.W, TBB, TBH.
  - Function prologue and epilogue detection:
      * Prologues: PUSH {..., lr}, STMDB sp!, {..., lr}, SUB sp, sp, #imm.
      * Epilogues: POP {..., pc}, LDMIA sp!, {..., pc}, BX lr.
  - Linear iteration and struct displacement extraction for cross-version migration.
"""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass
from typing import Any, Iterator, List

__all__ = [
    "InsnCategory",
    "ArmMemOperand",
    "ArmInsn",
    "REG_NAMES",
    "COND_NAMES",
    "is_thumb32",
    "get_insn_length",
    "decode_arm",
    "decode_thumb",
    "decode",
    "iter_decode",
    "decode_arm_thumb_memory_accesses",
]

REG_NAMES = (
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
)

COND_NAMES = (
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
)


class InsnCategory(str, enum.Enum):
    ARITHMETIC = "ARITHMETIC"
    LOGICAL = "LOGICAL"
    MEMORY_LOAD = "MEMORY_LOAD"
    MEMORY_STORE = "MEMORY_STORE"
    BRANCH_COND = "BRANCH_COND"
    BRANCH_UNCOND = "BRANCH_UNCOND"
    CALL = "CALL"
    RETURN = "RETURN"
    COMPARE = "COMPARE"
    VECTOR_FP = "VECTOR_FP"
    SYSTEM = "SYSTEM"
    OTHER = "OTHER"


@dataclass
class ArmMemOperand:
    """Represents a decoded memory address operand [base, #displacement]."""
    base: str
    disp: int
    index: str | None = None
    scale: int = 1
    wback: bool = False
    is_post_index: bool = False
    is_literal: bool = False

    def effective_address(self, pc: int) -> int | None:
        if self.base == "pc" or self.is_literal:
            return (pc + self.disp) & 0xFFFFFFFF
        return None


@dataclass
class ArmInsn:
    """Represents a decoded ARM32 or Thumb-16/32 instruction."""
    address: int
    length: int
    thumb: bool
    mnemonic: str
    op_str: str = ""
    category: InsnCategory = InsnCategory.OTHER
    mem: ArmMemOperand | None = None
    target_reg: str | None = None
    imm: int | None = None
    flow: str | None = None  # "call" | "ret" | "jmp" | "jcc" | "call_ind" | "jmp_ind" | None
    target: int | None = None
    is_cond: bool = False
    cond: str | None = None
    is_prologue: bool = False
    is_epilogue: bool = False
    access_size: int | None = None
    is_write: bool = False
    raw_bytes: bytes = b""
    invalid: bool = False

    @property
    def end(self) -> int:
        return self.address + self.length

    def is_memory_write(self) -> bool:
        return self.is_write

    def memory_access_size(self) -> int | None:
        return self.access_size


def is_thumb32(hw: int) -> bool:
    """
    Returns True if the 16-bit halfword is the first half of a 32-bit Thumb-2 instruction.
    Thumb-2 prefix: (hw >> 11) in (0b11101, 0b11110, 0b11111).
    """
    return (hw >> 11) in (0b11101, 0b11110, 0b11111)


def get_insn_length(code: bytes, offset: int = 0, thumb: bool = False) -> int:
    """Determines the instruction length (2 or 4 bytes) at the given offset."""
    if not thumb:
        return 4
    if offset + 2 > len(code):
        return 2
    hw = struct.unpack_from("<H", code, offset)[0]
    return 4 if is_thumb32(hw) else 2


# -----------------------------------------------------------------------------
# ARM32 (A32) Instruction Decoder
# -----------------------------------------------------------------------------

def decode_arm(code: bytes, offset: int = 0, address: int = 0) -> ArmInsn:
    """Decodes a single 4-byte ARM32 instruction."""
    if offset + 4 > len(code):
        return ArmInsn(
            address=address,
            length=max(1, len(code) - offset),
            thumb=False,
            mnemonic="invalid",
            category=InsnCategory.OTHER,
            invalid=True,
            raw_bytes=code[offset:],
        )

    insn = struct.unpack_from("<I", code, offset)[0]
    raw = code[offset : offset + 4]

    cond = (insn >> 28) & 0x0F
    cond_str = COND_NAMES[cond] if cond < 14 else ""
    is_cond = (cond < 14)

    # 1. Branch / Branch with Link (B, BL, BLX imm)
    if (insn & 0x0E000000) == 0x0A000000:
        if cond == 0x0F:
            # BLX immediate (ARM -> Thumb branch with link)
            h = (insn >> 24) & 1
            imm24 = insn & 0x00FFFFFF
            signed_imm24 = imm24 - 0x1000000 if (imm24 & 0x800000) else imm24
            target = ((address + 8 + (signed_imm24 << 2) + (h << 1)) | 1) & 0xFFFFFFFF
            return ArmInsn(
                address=address,
                length=4,
                thumb=False,
                mnemonic="blx",
                op_str=f"#{hex(target)}",
                category=InsnCategory.CALL,
                flow="call",
                target=target,
                is_cond=False,
                raw_bytes=raw,
            )
        else:
            is_link = bool(insn & (1 << 24))
            imm24 = insn & 0x00FFFFFF
            signed_imm24 = imm24 - 0x1000000 if (imm24 & 0x800000) else imm24
            target = (address + 8 + (signed_imm24 << 2)) & 0xFFFFFFFF
            if is_link:
                return ArmInsn(
                    address=address,
                    length=4,
                    thumb=False,
                    mnemonic="bl" + cond_str,
                    op_str=f"#{hex(target)}",
                    category=InsnCategory.CALL,
                    flow="call",
                    target=target,
                    is_cond=is_cond,
                    cond=cond_str if is_cond else None,
                    raw_bytes=raw,
                )
            else:
                cat = InsnCategory.BRANCH_COND if is_cond else InsnCategory.BRANCH_UNCOND
                flow = "jcc" if is_cond else "jmp"
                return ArmInsn(
                    address=address,
                    length=4,
                    thumb=False,
                    mnemonic="b" + cond_str,
                    op_str=f"#{hex(target)}",
                    category=cat,
                    flow=flow,
                    target=target,
                    is_cond=is_cond,
                    cond=cond_str if is_cond else None,
                    raw_bytes=raw,
                )

    # 2. Register Branch: BX Rm and BLX Rm
    if (insn & 0x0FFFFFF0) == 0x012FFF10:
        rm = insn & 0x0F
        rm_name = REG_NAMES[rm]
        if rm == 14:  # lr -> return
            return ArmInsn(
                address=address,
                length=4,
                thumb=False,
                mnemonic="bx" + cond_str,
                op_str=rm_name,
                category=InsnCategory.RETURN,
                flow="ret",
                is_cond=is_cond,
                cond=cond_str if is_cond else None,
                is_epilogue=True,
                raw_bytes=raw,
            )
        else:
            return ArmInsn(
                address=address,
                length=4,
                thumb=False,
                mnemonic="bx" + cond_str,
                op_str=rm_name,
                category=InsnCategory.BRANCH_UNCOND,
                flow="jmp_ind",
                is_cond=is_cond,
                cond=cond_str if is_cond else None,
                raw_bytes=raw,
            )

    if (insn & 0x0FFFFFF0) == 0x012FFF30:
        rm = insn & 0x0F
        rm_name = REG_NAMES[rm]
        return ArmInsn(
            address=address,
            length=4,
            thumb=False,
            mnemonic="blx" + cond_str,
            op_str=rm_name,
            category=InsnCategory.CALL,
            flow="call_ind",
            is_cond=is_cond,
            cond=cond_str if is_cond else None,
            raw_bytes=raw,
        )

    # 3. Prologue / Epilogue Block Data Transfers:
    # STMDB sp!, {..., lr} (PUSH) and LDMIA sp!, {..., pc} (POP)
    if (insn & 0x0FFF0000) == 0x092D0000:
        # STMDB sp!, {reglist}
        reglist = insn & 0xFFFF
        has_lr = bool(reglist & (1 << 14))
        return ArmInsn(
            address=address,
            length=4,
            thumb=False,
            mnemonic="stmdb" + cond_str,
            op_str=f"sp!, {hex(reglist)}",
            category=InsnCategory.MEMORY_STORE,
            is_cond=is_cond,
            cond=cond_str if is_cond else None,
            is_prologue=has_lr,
            raw_bytes=raw,
        )

    if (insn & 0x0FFF0000) == 0x08BD0000:
        # LDMIA sp!, {reglist}
        reglist = insn & 0xFFFF
        has_pc = bool(reglist & (1 << 15))
        return ArmInsn(
            address=address,
            length=4,
            thumb=False,
            mnemonic="ldmia" + cond_str,
            op_str=f"sp!, {hex(reglist)}",
            category=InsnCategory.RETURN if has_pc else InsnCategory.MEMORY_LOAD,
            flow="ret" if has_pc else None,
            is_cond=is_cond,
            cond=cond_str if is_cond else None,
            is_epilogue=has_pc,
            raw_bytes=raw,
        )

    # 4. SUB sp, sp, #imm (Stack frame reservation in prologue)
    # Pattern: cond 0010 0100 1101 1101 [rotate imm8]
    if (insn & 0x0FFF0000) == 0x024D0000:
        imm8 = insn & 0xFF
        rot = ((insn >> 8) & 0x0F) * 2
        imm_val = ((imm8 >> rot) | (imm8 << (32 - rot))) & 0xFFFFFFFF if rot else imm8
        return ArmInsn(
            address=address,
            length=4,
            thumb=False,
            mnemonic="sub" + cond_str,
            op_str=f"sp, sp, #0x{imm_val:x}",
            category=InsnCategory.ARITHMETIC,
            imm=imm_val,
            is_cond=is_cond,
            cond=cond_str if is_cond else None,
            is_prologue=True,
            raw_bytes=raw,
        )

    # 5. Miscellaneous Load/Store (LDRH, STRH, LDRD, STRD, LDRSB, LDRSH with immediate)
    # Pattern: (insn & 0x0E000090) == 0x00000090 and bit 22 (I) == 1
    if (insn & 0x0E000090) == 0x00000090 and (insn & (1 << 22)):
        u = bool(insn & (1 << 23))  # 1 = add, 0 = subtract
        l = bool(insn & (1 << 20))  # load / store
        rn = (insn >> 16) & 0x0F
        rt = (insn >> 12) & 0x0F
        imm4h = (insn >> 8) & 0x0F
        imm4l = insn & 0x0F
        imm = (imm4h << 4) | imm4l
        disp = imm if u else -imm
        b_reg = REG_NAMES[rn]
        t_reg = REG_NAMES[rt]

        op_code = (insn >> 4) & 0x0F  # bits [7:4]
        if op_code == 0x0B:
            # STRH (L=0) or LDRH (L=1)
            mnem = "ldrh" if l else "strh"
            cat = InsnCategory.MEMORY_LOAD if l else InsnCategory.MEMORY_STORE
            size = 2
            mem_op = ArmMemOperand(base=b_reg, disp=disp, is_literal=(b_reg == "pc"))
            return ArmInsn(
                address=address,
                length=4,
                thumb=False,
                mnemonic=mnem + cond_str,
                op_str=f"{t_reg}, [{b_reg}, #0x{disp:x}]",
                category=cat,
                mem=mem_op,
                target_reg=t_reg,
                imm=disp,
                access_size=size,
                is_write=not l,
                is_cond=is_cond,
                cond=cond_str if is_cond else None,
                raw_bytes=raw,
            )
        elif op_code == 0x0D:
            # LDRD (L=0) or LDRSB (L=1)
            if l:
                mnem, size = "ldrsb", 1
                cat = InsnCategory.MEMORY_LOAD
                is_w = False
                t_str = t_reg
            else:
                mnem, size = "ldrd", 8
                cat = InsnCategory.MEMORY_LOAD
                is_w = False
                t_str = f"{t_reg}, {REG_NAMES[rt + 1 if rt < 15 else 0]}"
            mem_op = ArmMemOperand(base=b_reg, disp=disp, is_literal=(b_reg == "pc"))
            return ArmInsn(
                address=address,
                length=4,
                thumb=False,
                mnemonic=mnem + cond_str,
                op_str=f"{t_str}, [{b_reg}, #0x{disp:x}]",
                category=cat,
                mem=mem_op,
                target_reg=t_reg,
                imm=disp,
                access_size=size,
                is_write=is_w,
                is_cond=is_cond,
                cond=cond_str if is_cond else None,
                raw_bytes=raw,
            )
        elif op_code == 0x0F:
            # STRD (L=0) or LDRSH (L=1)
            if l:
                mnem, size = "ldrsh", 2
                cat = InsnCategory.MEMORY_LOAD
                is_w = False
                t_str = t_reg
            else:
                mnem, size = "strd", 8
                cat = InsnCategory.MEMORY_STORE
                is_w = True
                t_str = f"{t_reg}, {REG_NAMES[rt + 1 if rt < 15 else 0]}"
            mem_op = ArmMemOperand(base=b_reg, disp=disp, is_literal=(b_reg == "pc"))
            return ArmInsn(
                address=address,
                length=4,
                thumb=False,
                mnemonic=mnem + cond_str,
                op_str=f"{t_str}, [{b_reg}, #0x{disp:x}]",
                category=cat,
                mem=mem_op,
                target_reg=t_reg,
                imm=disp,
                access_size=size,
                is_write=is_w,
                is_cond=is_cond,
                cond=cond_str if is_cond else None,
                raw_bytes=raw,
            )

    # 6. Standard LDR / STR / LDRB / STRB with immediate displacement
    # Pattern: (insn & 0x0C000000) == 0x04000000 and bit 25 (I) == 0
    if (insn & 0x0C000000) == 0x04000000 and ((insn & (1 << 25)) == 0):
        u = bool(insn & (1 << 23))  # 1 = add, 0 = subtract
        b = bool(insn & (1 << 22))  # 1 = byte, 0 = word
        l = bool(insn & (1 << 20))  # 1 = load, 0 = store
        rn = (insn >> 16) & 0x0F
        rt = (insn >> 12) & 0x0F
        imm12 = insn & 0x0FFF
        disp = imm12 if u else -imm12
        b_reg = REG_NAMES[rn]
        t_reg = REG_NAMES[rt]

        mnem_base = "ldr" if l else "str"
        if b:
            mnem_base += "b"
        size = 1 if b else 4
        cat = InsnCategory.MEMORY_LOAD if l else InsnCategory.MEMORY_STORE
        mem_op = ArmMemOperand(base=b_reg, disp=disp, is_literal=(b_reg == "pc"))

        return ArmInsn(
            address=address,
            length=4,
            thumb=False,
            mnemonic=mnem_base + cond_str,
            op_str=f"{t_reg}, [{b_reg}, #0x{disp:x}]",
            category=cat,
            mem=mem_op,
            target_reg=t_reg,
            imm=disp,
            access_size=size,
            is_write=not l,
            is_cond=is_cond,
            cond=cond_str if is_cond else None,
            raw_bytes=raw,
        )

    # 7. Common Data Processing: MOV, ADD, SUB, CMP, AND, ORR, EOR, BIC, etc.
    if (insn & 0x0C000000) == 0x00000000:
        opcode = (insn >> 21) & 0x0F
        rn = (insn >> 16) & 0x0F
        rd = (insn >> 12) & 0x0F
        is_imm = bool(insn & (1 << 25))
        imm_val = None
        if is_imm:
            imm8 = insn & 0xFF
            rot = ((insn >> 8) & 0x0F) * 2
            imm_val = ((imm8 >> rot) | (imm8 << (32 - rot))) & 0xFFFFFFFF if rot else imm8

        dp_map = {
            0x0: ("and", InsnCategory.LOGICAL),
            0x1: ("eor", InsnCategory.LOGICAL),
            0x2: ("sub", InsnCategory.ARITHMETIC),
            0x3: ("rsb", InsnCategory.ARITHMETIC),
            0x4: ("add", InsnCategory.ARITHMETIC),
            0x5: ("adc", InsnCategory.ARITHMETIC),
            0x6: ("sbc", InsnCategory.ARITHMETIC),
            0x7: ("rsc", InsnCategory.ARITHMETIC),
            0x8: ("tst", InsnCategory.COMPARE),
            0x9: ("teq", InsnCategory.COMPARE),
            0xA: ("cmp", InsnCategory.COMPARE),
            0xB: ("cmn", InsnCategory.COMPARE),
            0xC: ("orr", InsnCategory.LOGICAL),
            0xD: ("mov", InsnCategory.ARITHMETIC),
            0xE: ("bic", InsnCategory.LOGICAL),
            0xF: ("mvn", InsnCategory.LOGICAL),
        }
        mnem, cat = dp_map.get(opcode, ("other", InsnCategory.OTHER))
        op_s = f"{REG_NAMES[rd]}" if opcode == 0xD else f"{REG_NAMES[rd]}, {REG_NAMES[rn]}"
        if imm_val is not None:
            op_s += f", #0x{imm_val:x}"
        return ArmInsn(
            address=address,
            length=4,
            thumb=False,
            mnemonic=mnem + cond_str,
            op_str=op_s,
            category=cat,
            imm=imm_val,
            is_cond=is_cond,
            cond=cond_str if is_cond else None,
            raw_bytes=raw,
        )

    # NOP / generic fallback
    if insn == 0xE320F000:
        return ArmInsn(address=address, length=4, thumb=False, mnemonic="nop", category=InsnCategory.OTHER, raw_bytes=raw)

    return ArmInsn(address=address, length=4, thumb=False, mnemonic="other", category=InsnCategory.OTHER, raw_bytes=raw)


# -----------------------------------------------------------------------------
# Thumb-16 and Thumb-32 (Thumb-2) Instruction Decoder
# -----------------------------------------------------------------------------

def decode_thumb(code: bytes, offset: int = 0, address: int = 0) -> ArmInsn:
    """Decodes a Thumb-16 (2-byte) or Thumb-32 (4-byte) instruction."""
    if offset + 2 > len(code):
        return ArmInsn(
            address=address,
            length=max(1, len(code) - offset),
            thumb=True,
            mnemonic="invalid",
            category=InsnCategory.OTHER,
            invalid=True,
            raw_bytes=code[offset:],
        )

    hw1 = struct.unpack_from("<H", code, offset)[0]

    # Check for Thumb-32 instruction
    if is_thumb32(hw1):
        if offset + 4 > len(code):
            return ArmInsn(
                address=address,
                length=2,
                thumb=True,
                mnemonic="invalid",
                category=InsnCategory.OTHER,
                invalid=True,
                raw_bytes=code[offset : offset + 2],
            )
        hw2 = struct.unpack_from("<H", code, offset + 2)[0]
        return _decode_thumb32(hw1, hw2, code[offset : offset + 4], address)

    return _decode_thumb16(hw1, code[offset : offset + 2], address)


def _decode_thumb16(hw: int, raw: bytes, address: int) -> ArmInsn:
    """Decodes a 2-byte Thumb-16 instruction."""
    # 1. PUSH / POP
    if (hw & 0xFE00) == 0xB400:
        has_lr = bool(hw & 0x0100)
        reglist = hw & 0xFF
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic="push",
            op_str="{r0-r7, lr}" if has_lr else "{r0-r7}",
            category=InsnCategory.MEMORY_STORE,
            is_prologue=has_lr,
            raw_bytes=raw,
        )

    if (hw & 0xFE00) == 0xBC00:
        has_pc = bool(hw & 0x0100)
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic="pop",
            op_str="{r0-r7, pc}" if has_pc else "{r0-r7}",
            category=InsnCategory.RETURN if has_pc else InsnCategory.MEMORY_LOAD,
            flow="ret" if has_pc else None,
            is_epilogue=has_pc,
            raw_bytes=raw,
        )

    # 2. SUB sp, #imm / ADD sp, #imm
    if (hw & 0xFF80) == 0xB080:
        imm7 = hw & 0x7F
        imm_val = imm7 << 2
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic="sub",
            op_str=f"sp, #0x{imm_val:x}",
            category=InsnCategory.ARITHMETIC,
            imm=imm_val,
            is_prologue=True,
            raw_bytes=raw,
        )

    if (hw & 0xFF80) == 0xB000:
        imm7 = hw & 0x7F
        imm_val = imm7 << 2
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic="add",
            op_str=f"sp, #0x{imm_val:x}",
            category=InsnCategory.ARITHMETIC,
            imm=imm_val,
            raw_bytes=raw,
        )

    # 3. BX / BLX <Rm>
    if (hw & 0xFF87) == 0x4700:
        rm = (hw >> 3) & 0x0F
        rm_name = REG_NAMES[rm]
        if rm == 14:  # lr
            return ArmInsn(
                address=address,
                length=2,
                thumb=True,
                mnemonic="bx",
                op_str=rm_name,
                category=InsnCategory.RETURN,
                flow="ret",
                is_epilogue=True,
                raw_bytes=raw,
            )
        else:
            return ArmInsn(
                address=address,
                length=2,
                thumb=True,
                mnemonic="bx",
                op_str=rm_name,
                category=InsnCategory.BRANCH_UNCOND,
                flow="jmp_ind",
                raw_bytes=raw,
            )

    if (hw & 0xFF87) == 0x4780:
        rm = (hw >> 3) & 0x0F
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic="blx",
            op_str=REG_NAMES[rm],
            category=InsnCategory.CALL,
            flow="call_ind",
            raw_bytes=raw,
        )

    # 4. CBZ / CBNZ
    if (hw & 0xF500) == 0xB100:
        op = (hw >> 11) & 1  # 0 = cbz, 1 = cbnz
        i = (hw >> 9) & 1
        imm5 = (hw >> 3) & 0x1F
        rn = hw & 7
        imm_disp = ((i << 5) | imm5) << 1
        target = (address + 4 + imm_disp) & 0xFFFFFFFF
        mnem = "cbnz" if op else "cbz"
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic=mnem,
            op_str=f"{REG_NAMES[rn]}, #{hex(target)}",
            category=InsnCategory.BRANCH_COND,
            flow="jcc",
            target=target,
            is_cond=True,
            raw_bytes=raw,
        )

    # 5. Conditional Branch B<cond>
    if (hw & 0xF000) == 0xD000 and ((hw >> 8) & 0x0F) < 0x0E:
        cond = (hw >> 8) & 0x0F
        imm8 = hw & 0xFF
        signed_imm8 = imm8 - 256 if (imm8 & 0x80) else imm8
        target = (address + 4 + (signed_imm8 << 1)) & 0xFFFFFFFF
        cond_str = COND_NAMES[cond]
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic="b" + cond_str,
            op_str=f"#{hex(target)}",
            category=InsnCategory.BRANCH_COND,
            flow="jcc",
            target=target,
            is_cond=True,
            cond=cond_str,
            raw_bytes=raw,
        )

    # 6. Unconditional Branch B
    if (hw & 0xF800) == 0xE000:
        imm11 = hw & 0x7FF
        signed_imm11 = imm11 - 2048 if (imm11 & 0x400) else imm11
        target = (address + 4 + (signed_imm11 << 1)) & 0xFFFFFFFF
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic="b",
            op_str=f"#{hex(target)}",
            category=InsnCategory.BRANCH_UNCOND,
            flow="jmp",
            target=target,
            is_cond=False,
            raw_bytes=raw,
        )

    # 7. Memory Accesses:
    # 7a. LDR / STR (5-bit immediate, word)
    if (hw & 0xF000) == 0x6000:
        is_load = bool(hw & 0x0800)
        imm5 = (hw >> 6) & 0x1F
        offset = imm5 << 2
        rn = (hw >> 3) & 7
        rt = hw & 7
        b_reg = REG_NAMES[rn]
        t_reg = REG_NAMES[rt]
        mnem = "ldr" if is_load else "str"
        cat = InsnCategory.MEMORY_LOAD if is_load else InsnCategory.MEMORY_STORE
        mem_op = ArmMemOperand(base=b_reg, disp=offset)
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic=mnem,
            op_str=f"{t_reg}, [{b_reg}, #0x{offset:x}]",
            category=cat,
            mem=mem_op,
            target_reg=t_reg,
            imm=offset,
            access_size=4,
            is_write=not is_load,
            raw_bytes=raw,
        )

    # 7b. LDRB / STRB (5-bit immediate, byte)
    if (hw & 0xF000) == 0x7000:
        is_load = bool(hw & 0x0800)
        imm5 = (hw >> 6) & 0x1F
        offset = imm5
        rn = (hw >> 3) & 7
        rt = hw & 7
        b_reg = REG_NAMES[rn]
        t_reg = REG_NAMES[rt]
        mnem = "ldrb" if is_load else "strb"
        cat = InsnCategory.MEMORY_LOAD if is_load else InsnCategory.MEMORY_STORE
        mem_op = ArmMemOperand(base=b_reg, disp=offset)
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic=mnem,
            op_str=f"{t_reg}, [{b_reg}, #0x{offset:x}]",
            category=cat,
            mem=mem_op,
            target_reg=t_reg,
            imm=offset,
            access_size=1,
            is_write=not is_load,
            raw_bytes=raw,
        )

    # 7c. LDRH / STRH (5-bit immediate, halfword)
    if (hw & 0xF000) == 0x8000:
        is_load = bool(hw & 0x0800)
        imm5 = (hw >> 6) & 0x1F
        offset = imm5 << 1
        rn = (hw >> 3) & 7
        rt = hw & 7
        b_reg = REG_NAMES[rn]
        t_reg = REG_NAMES[rt]
        mnem = "ldrh" if is_load else "strh"
        cat = InsnCategory.MEMORY_LOAD if is_load else InsnCategory.MEMORY_STORE
        mem_op = ArmMemOperand(base=b_reg, disp=offset)
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic=mnem,
            op_str=f"{t_reg}, [{b_reg}, #0x{offset:x}]",
            category=cat,
            mem=mem_op,
            target_reg=t_reg,
            imm=offset,
            access_size=2,
            is_write=not is_load,
            raw_bytes=raw,
        )

    # 7d. LDR / STR (SP-relative, 8-bit imm)
    if (hw & 0xF000) == 0x9000:
        is_load = bool(hw & 0x0800)
        imm8 = hw & 0xFF
        offset = imm8 << 2
        rt = (hw >> 8) & 7
        t_reg = REG_NAMES[rt]
        mnem = "ldr" if is_load else "str"
        cat = InsnCategory.MEMORY_LOAD if is_load else InsnCategory.MEMORY_STORE
        mem_op = ArmMemOperand(base="sp", disp=offset)
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic=mnem,
            op_str=f"{t_reg}, [sp, #0x{offset:x}]",
            category=cat,
            mem=mem_op,
            target_reg=t_reg,
            imm=offset,
            access_size=4,
            is_write=not is_load,
            raw_bytes=raw,
        )

    # 7e. LDR (PC-relative literal pool)
    if (hw & 0xF800) == 0x4800:
        imm8 = hw & 0xFF
        offset = imm8 << 2
        rt = (hw >> 8) & 7
        t_reg = REG_NAMES[rt]
        mem_op = ArmMemOperand(base="pc", disp=offset, is_literal=True)
        return ArmInsn(
            address=address,
            length=2,
            thumb=True,
            mnemonic="ldr",
            op_str=f"{t_reg}, [pc, #0x{offset:x}]",
            category=InsnCategory.MEMORY_LOAD,
            mem=mem_op,
            target_reg=t_reg,
            imm=offset,
            access_size=4,
            is_write=False,
            raw_bytes=raw,
        )

    # 8. Common Arithmetic / Move
    top_nib = (hw >> 12) & 0x0F
    if top_nib in (0x0, 0x1):
        # Shift or ADD/SUB
        op3 = (hw >> 9) & 0x7
        if (hw & 0xF800) == 0x1800:
            return ArmInsn(address=address, length=2, thumb=True, mnemonic="add", category=InsnCategory.ARITHMETIC, raw_bytes=raw)
        elif (hw & 0xF800) == 0x1A00:
            return ArmInsn(address=address, length=2, thumb=True, mnemonic="sub", category=InsnCategory.ARITHMETIC, raw_bytes=raw)
        return ArmInsn(address=address, length=2, thumb=True, mnemonic="shift", category=InsnCategory.LOGICAL, raw_bytes=raw)
    elif top_nib == 0x2:
        if (hw & 0xF800) == 0x2000:
            return ArmInsn(address=address, length=2, thumb=True, mnemonic="mov", category=InsnCategory.ARITHMETIC, imm=hw & 0xFF, raw_bytes=raw)
        elif (hw & 0xF800) == 0x2800:
            return ArmInsn(address=address, length=2, thumb=True, mnemonic="cmp", category=InsnCategory.COMPARE, imm=hw & 0xFF, raw_bytes=raw)
    elif top_nib == 0x3:
        if (hw & 0xF800) == 0x3000:
            return ArmInsn(address=address, length=2, thumb=True, mnemonic="add", category=InsnCategory.ARITHMETIC, imm=hw & 0xFF, raw_bytes=raw)
        elif (hw & 0xF800) == 0x3800:
            return ArmInsn(address=address, length=2, thumb=True, mnemonic="sub", category=InsnCategory.ARITHMETIC, imm=hw & 0xFF, raw_bytes=raw)

    if hw in (0xBF00, 0x46C0):
        return ArmInsn(address=address, length=2, thumb=True, mnemonic="nop", category=InsnCategory.OTHER, raw_bytes=raw)

    return ArmInsn(address=address, length=2, thumb=True, mnemonic="other", category=InsnCategory.OTHER, raw_bytes=raw)


def _decode_thumb32(hw1: int, hw2: int, raw: bytes, address: int) -> ArmInsn:
    """Decodes a 4-byte Thumb-32 instruction."""
    # 1. STMDB.W sp!, {..., lr} (PUSH.W) and LDMIA.W sp!, {..., pc} (POP.W)
    if hw1 == 0xE92D:
        has_lr = bool(hw2 & (1 << 14))
        return ArmInsn(
            address=address,
            length=4,
            thumb=True,
            mnemonic="push.w",
            op_str="{reglist}",
            category=InsnCategory.MEMORY_STORE,
            is_prologue=has_lr,
            raw_bytes=raw,
        )

    if hw1 == 0xE8BD:
        has_pc = bool(hw2 & (1 << 15))
        return ArmInsn(
            address=address,
            length=4,
            thumb=True,
            mnemonic="pop.w",
            op_str="{reglist}",
            category=InsnCategory.RETURN if has_pc else InsnCategory.MEMORY_LOAD,
            flow="ret" if has_pc else None,
            is_epilogue=has_pc,
            raw_bytes=raw,
        )

    # 2. Table Branches: TBB and TBH
    if (hw1 & 0xFFF0) == 0xE8D0 and (hw2 & 0xFFE0) == 0xF000:
        is_tbh = bool(hw2 & 0x0010)
        rn = hw1 & 0x0F
        rm = hw2 & 0x0F
        mnem = "tbh" if is_tbh else "tbb"
        return ArmInsn(
            address=address,
            length=4,
            thumb=True,
            mnemonic=mnem,
            op_str=f"[{REG_NAMES[rn]}, {REG_NAMES[rm]}]",
            category=InsnCategory.BRANCH_UNCOND,
            flow="jmp_ind",
            raw_bytes=raw,
        )

    # 3. LDRD / STRD (immediate)
    # hw1 top byte 0xE9 or 0xE8: bits [15:9] == 0b1110100
    if (hw1 & 0xFE40) == 0xE840 or (hw1 & 0xFF00) == 0xE900:
        nibble1 = (hw1 >> 4) & 0x0F
        if nibble1 in (0x4, 0x5, 0xC, 0xD):
            u = bool(hw1 & 0x0080)  # bit 7: 1 = add, 0 = subtract
            l = bool(hw1 & 0x0010)  # bit 4: 1 = ldrd, 0 = strd
            rn = hw1 & 0x0F
            rt = (hw2 >> 12) & 0x0F
            rt2 = (hw2 >> 8) & 0x0F
            imm8 = hw2 & 0xFF
            offset = (imm8 << 2) if u else -(imm8 << 2)

            b_reg = REG_NAMES[rn]
            t_reg = REG_NAMES[rt]
            t_str = f"{t_reg}, {REG_NAMES[rt2]}"
            mnem = "ldrd" if l else "strd"
            cat = InsnCategory.MEMORY_LOAD if l else InsnCategory.MEMORY_STORE
            mem_op = ArmMemOperand(base=b_reg, disp=offset, is_literal=(b_reg == "pc"))
            return ArmInsn(
                address=address,
                length=4,
                thumb=True,
                mnemonic=mnem,
                op_str=f"{t_str}, [{b_reg}, #0x{offset:x}]",
                category=cat,
                mem=mem_op,
                target_reg=t_reg,
                imm=offset,
                access_size=8,
                is_write=not l,
                raw_bytes=raw,
            )

    # 4. BL and BLX immediate
    if (hw1 & 0xF800) == 0xF000 and (hw2 & 0xD000) in (0xD000, 0xC000):
        s = (hw1 >> 10) & 1
        imm10 = hw1 & 0x3FF
        j1 = (hw2 >> 13) & 1
        j2 = (hw2 >> 11) & 1
        imm11 = hw2 & 0x7FF
        i1 = ~(j1 ^ s) & 1
        i2 = ~(j2 ^ s) & 1
        imm25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
        if imm25 & (1 << 24):
            imm25 -= (1 << 25)
        is_blx = bool((hw2 & 0x1000) == 0)
        target = (((address + 4 + imm25) & ~3) if is_blx else (address + 4 + imm25)) & 0xFFFFFFFF
        mnem = "blx" if is_blx else "bl"
        return ArmInsn(
            address=address,
            length=4,
            thumb=True,
            mnemonic=mnem,
            op_str=f"#{hex(target)}",
            category=InsnCategory.CALL,
            flow="call",
            target=target,
            is_cond=False,
            raw_bytes=raw,
        )

    # 5. B.W (unconditional 32-bit branch)
    if (hw1 & 0xF800) == 0xF000 and (hw2 & 0xD000) == 0x9000:
        s = (hw1 >> 10) & 1
        imm10 = hw1 & 0x3FF
        j1 = (hw2 >> 13) & 1
        j2 = (hw2 >> 11) & 1
        imm11 = hw2 & 0x7FF
        i1 = ~(j1 ^ s) & 1
        i2 = ~(j2 ^ s) & 1
        imm25 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
        if imm25 & (1 << 24):
            imm25 -= (1 << 25)
        target = (address + 4 + imm25) & 0xFFFFFFFF
        return ArmInsn(
            address=address,
            length=4,
            thumb=True,
            mnemonic="b.w",
            op_str=f"#{hex(target)}",
            category=InsnCategory.BRANCH_UNCOND,
            flow="jmp",
            target=target,
            is_cond=False,
            raw_bytes=raw,
        )

    # 6. B<cond>.W (conditional 32-bit branch)
    if (hw1 & 0xF800) == 0xF000 and (hw2 & 0xD000) == 0x8000:
        cond = (hw1 >> 6) & 0x0F
        if cond < 0x0E:
            s = (hw1 >> 10) & 1
            imm6 = hw1 & 0x3F
            j1 = (hw2 >> 13) & 1
            j2 = (hw2 >> 11) & 1
            imm11 = hw2 & 0x7FF
            imm21 = (s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1)
            if imm21 & (1 << 20):
                imm21 -= (1 << 21)
            target = (address + 4 + imm21) & 0xFFFFFFFF
            cond_str = COND_NAMES[cond]
            return ArmInsn(
                address=address,
                length=4,
                thumb=True,
                mnemonic="b" + cond_str + ".w",
                op_str=f"#{hex(target)}",
                category=InsnCategory.BRANCH_COND,
                flow="jcc",
                target=target,
                is_cond=True,
                cond=cond_str,
                raw_bytes=raw,
            )

    # 7. Thumb-32 Load/Store Single Item (LDR, STR, LDRB, STRB, LDRH, STRH)
    # hw1 starts with 0xF8..
    if (hw1 & 0xFE00) == 0xF800:
        nibble1 = (hw1 >> 4) & 0x0F
        rn = hw1 & 0x0F
        rt = (hw2 >> 12) & 0x0F
        b_reg = REG_NAMES[rn]
        t_reg = REG_NAMES[rt]

        # Literal loads (Rn = PC): always the 12-bit form, add/subtract in hw1 bit 7 (U),
        # size in hw1 bits 6:5, sign extension in hw1 bit 8 (LDR/LDRB/LDRH/LDRSB/LDRSH.W).
        if rn == 15 and (hw1 & 0x0010) and ((hw1 >> 5) & 3) != 3:
            imm12 = hw2 & 0x0FFF
            disp = imm12 if (hw1 & 0x0080) else -imm12
            size = (1, 2, 4)[(hw1 >> 5) & 3]
            signed = bool(hw1 & 0x0100)
            mnem = {1: "ldrsb.w" if signed else "ldrb.w", 2: "ldrsh.w" if signed else "ldrh.w", 4: "ldr.w"}[size]
            return ArmInsn(
                address=address,
                length=4,
                thumb=True,
                mnemonic=mnem,
                op_str=f"{t_reg}, [pc, #{disp}]",
                category=InsnCategory.MEMORY_LOAD,
                mem=ArmMemOperand(base="pc", disp=disp, is_literal=True),
                target_reg=t_reg,
                imm=disp,
                access_size=size,
                is_write=False,
                raw_bytes=raw,
            )

        # 12-bit unsigned immediate form: Nibble 1 in (8, 9, A, B, C, D)
        if nibble1 in (0x8, 0x9, 0xA, 0xB, 0xC, 0xD):
            imm12 = hw2 & 0x0FFF
            size_map = {
                0x8: ("strb.w", 1, True, InsnCategory.MEMORY_STORE),
                0x9: ("ldrb.w", 1, False, InsnCategory.MEMORY_LOAD),
                0xA: ("strh.w", 2, True, InsnCategory.MEMORY_STORE),
                0xB: ("ldrh.w", 2, False, InsnCategory.MEMORY_LOAD),
                0xC: ("str.w", 4, True, InsnCategory.MEMORY_STORE),
                0xD: ("ldr.w", 4, False, InsnCategory.MEMORY_LOAD),
            }
            mnem, size, is_w, cat = size_map[nibble1]
            mem_op = ArmMemOperand(base=b_reg, disp=imm12, is_literal=(b_reg == "pc"))
            return ArmInsn(
                address=address,
                length=4,
                thumb=True,
                mnemonic=mnem,
                op_str=f"{t_reg}, [{b_reg}, #0x{imm12:x}]",
                category=cat,
                mem=mem_op,
                target_reg=t_reg,
                imm=imm12,
                access_size=size,
                is_write=is_w,
                raw_bytes=raw,
            )

        # 8-bit signed/negative/indexed form: Nibble 1 in (0, 1, 2, 3, 4, 5)
        if nibble1 in (0x0, 0x1, 0x2, 0x3, 0x4, 0x5) and (hw2 & 0x0800):
            imm8 = hw2 & 0xFF
            u = bool(hw2 & 0x0200)  # bit 9: 1 = add, 0 = subtract
            disp = imm8 if u else -imm8
            size_map_8 = {
                0x0: ("strb", 1, True, InsnCategory.MEMORY_STORE),
                0x1: ("ldrb", 1, False, InsnCategory.MEMORY_LOAD),
                0x2: ("strh", 2, True, InsnCategory.MEMORY_STORE),
                0x3: ("ldrh", 2, False, InsnCategory.MEMORY_LOAD),
                0x4: ("str", 4, True, InsnCategory.MEMORY_STORE),
                0x5: ("ldr", 4, False, InsnCategory.MEMORY_LOAD),
            }
            mnem, size, is_w, cat = size_map_8[nibble1]
            mem_op = ArmMemOperand(base=b_reg, disp=disp, is_literal=(b_reg == "pc"))
            return ArmInsn(
                address=address,
                length=4,
                thumb=True,
                mnemonic=mnem,
                op_str=f"{t_reg}, [{b_reg}, #0x{disp:x}]",
                category=cat,
                mem=mem_op,
                target_reg=t_reg,
                imm=disp,
                access_size=size,
                is_write=is_w,
                raw_bytes=raw,
            )

    return ArmInsn(address=address, length=4, thumb=True, mnemonic="other.w", category=InsnCategory.OTHER, raw_bytes=raw)


# -----------------------------------------------------------------------------
# Unified Public API
# -----------------------------------------------------------------------------

def decode(code: bytes, offset: int = 0, address: int = 0, thumb: bool = False) -> ArmInsn:
    """Dispatches to ARM32 or Thumb decoder based on thumb flag."""
    if thumb:
        return decode_thumb(code, offset, address)
    return decode_arm(code, offset, address)


def iter_decode(
    code: bytes,
    address: int = 0,
    thumb: bool = False,
    start: int = 0,
    end: int | None = None,
) -> Iterator[ArmInsn]:
    """
    Linear sweep over code[start:end].
    Advances strictly by instruction length (2 or 4 bytes), recovering gracefully from errors.
    """
    pos = start
    stop = len(code) if end is None else min(end, len(code))
    while pos < stop:
        cur_addr = address + pos
        insn = decode(code, pos, cur_addr, thumb=thumb)
        yield insn
        pos += max(2 if thumb else 4, insn.length)


def decode_arm_thumb_memory_accesses(
    code_bytes: bytes,
    base_pc: int = 0,
    thumb: bool = False,
    include_sp: bool = True,
) -> List[Any]:
    """
    Sweeps instructions and extracts struct-field memory accesses with immediate displacement.
    Returns objects matching struct_shift_migrator.MemoryAccess.
    """
    try:
        from superghidra.diff.struct_shift_migrator import MemoryAccess
    except ImportError:
        # Fallback dataclass if imported outside SuperGhidra package
        from dataclasses import dataclass
        @dataclass(frozen=True)
        class MemoryAccess:  # type: ignore
            pc: int
            mnemonic: str
            base_reg: str
            target_reg: str
            displacement: int
            access_size: int
            is_write: bool
            raw_insn: int = 0
            instruction_text: str = ""

    accesses = []
    for insn in iter_decode(code_bytes, address=base_pc, thumb=thumb):
        if insn.mem is None:
            continue
        # Skip PC-relative literal pool loads
        if insn.mem.base == "pc" or insn.mem.is_literal:
            continue
        # Optionally skip SP-relative accesses if unwanted
        if not include_sp and insn.mem.base == "sp":
            continue

        raw_val = int.from_bytes(insn.raw_bytes, "little") if insn.raw_bytes else 0
        text = f"{insn.mnemonic.upper()} {insn.op_str}"
        accesses.append(
            MemoryAccess(
                pc=insn.address,
                mnemonic=insn.mnemonic.upper(),
                base_reg=insn.mem.base,
                target_reg=insn.target_reg or "r0",
                displacement=insn.mem.disp,
                access_size=insn.access_size or 4,
                is_write=insn.is_write,
                raw_insn=raw_val,
                instruction_text=text,
            )
        )
    return accesses
