"""
test_arm_thumb_decode.py - Comprehensive test suite for ARM32 / Thumb / Thumb-2 architecture decoding.

Verifies:
1. Thumb-16 and Thumb-32 instruction length decoding.
2. Memory access displacement extraction for both ARM32 and Thumb-2
   (LDR r0, [r1, #0x24], STR r2, [r3, #0x40], LDRD, STRD, byte/halfword, etc.).
3. Branch target resolution and CFG construction on synthetic ARM32 and Thumb-2 functions.
4. Struct shift migration on two versions of an ARM32 binary (raw bytes and ELF containers).
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest

from superghidra.diff import binary_diff_engine as D
from superghidra.diff import struct_shift_migrator as M
from superghidra.lifters import arm_thumb_decode as A

# Optional Capstone cross-verification if available
try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    capstone = None
    HAS_CAPSTONE = False


def make_arm_elf(text: bytes, thumb: bool = False, func_name: str = "FuncA") -> bytes:
    """Builds a minimal 32-bit little-endian ELF shared object for ARM."""
    e = "<"
    base_va = 0x10000
    ehsize, phentsize, shentsize, symsize = 52, 32, 40, 16
    text_off = 0x200
    dynstr = f"\x00{func_name}\x00".encode("latin-1")
    shstr = b"\x00.text\x00.dynsym\x00.dynstr\x00.dynamic\x00.shstrtab\x00"

    sym_val = (base_va + text_off + 1) if thumb else (base_va + text_off)
    dynsym = (b"\x00" * symsize) + struct.pack(e + "IIIBBH", 1, sym_val, len(text), 0x12, 0, 1)
    dynsym_off = text_off + len(text)
    dynstr_off = dynsym_off + len(dynsym)
    dynamic_off = (dynstr_off + len(dynstr) + 7) & ~7
    dynamic = (
        struct.pack(e + "iI", 5, base_va + dynstr_off)
        + struct.pack(e + "iI", 6, base_va + dynsym_off)
        + struct.pack(e + "iI", 10, len(dynstr))
        + struct.pack(e + "iI", 0, 0)
    )
    shstr_off = dynamic_off + len(dynamic)
    shoff = (shstr_off + len(shstr) + 7) & ~7

    out = bytearray(shoff + 6 * shentsize)
    out[0:4] = b"\x7fELF"
    out[4], out[5], out[6] = 1, 1, 1  # 32-bit, little-endian, EV_CURRENT
    struct.pack_into(e + "HHIIIIIHHHHHH", out, 16, 3, 0x28, 1, sym_val, 52, shoff, 0, 52, phentsize, 2, shentsize, 6, 5)
    struct.pack_into(e + "IIIIIIII", out, 52, 1, 0, base_va, base_va, len(out), len(out), 5, 0x1000)
    struct.pack_into(e + "IIIIIIII", out, 52 + phentsize, 2, dynamic_off, base_va + dynamic_off, 0, len(dynamic), len(dynamic), 6, 4)

    out[text_off : text_off + len(text)] = text
    out[dynsym_off : dynsym_off + len(dynsym)] = dynsym
    out[dynstr_off : dynstr_off + len(dynstr)] = dynstr
    out[dynamic_off : dynamic_off + len(dynamic)] = dynamic
    out[shstr_off : shstr_off + len(shstr)] = shstr

    def sh(i, name, typ, flags, addr, off, size, link=0, entsize=0):
        struct.pack_into(e + "IIIIIIIIII", out, shoff + i * shentsize, name, typ, flags, addr, off, size, link, 0, entsize, 0)

    n = lambda s: shstr.index(s)
    sh(1, n(b".text"), 1, 6, base_va + text_off, text_off, len(text))
    sh(2, n(b".dynsym"), 11, 2, base_va + dynsym_off, dynsym_off, len(dynsym), link=3, entsize=symsize)
    sh(3, n(b".dynstr"), 3, 2, base_va + dynstr_off, dynstr_off, len(dynstr))
    sh(4, n(b".dynamic"), 6, 3, base_va + dynamic_off, dynamic_off, len(dynamic), link=3)
    sh(5, n(b".shstrtab"), 3, 0, 0, shstr_off, len(shstr))

    return bytes(out)


class TestArmThumbLengths(unittest.TestCase):
    """Verifies Thumb-16, Thumb-32, and ARM32 instruction length decoding."""

    THUMB16_CASES = [
        ("0028", 2),  # cmp r0, #0
        ("0120", 2),  # movs r0, #1
        ("04e0", 2),  # b #target
        ("04d1", 2),  # bne #target
        ("08b1", 2),  # cbz r0, #target
        ("09b9", 2),  # cbnz r1, #target
        ("7047", 2),  # bx lr
        ("9847", 2),  # blx r3
        ("10b5", 2),  # push {r4, lr}
        ("10bd", 2),  # pop {r4, pc}
        ("84b0", 2),  # sub sp, #0x10
        ("886a", 2),  # ldr r0, [r1, #0x28]
        ("1a64", 2),  # str r2, [r3, #0x40]
        ("0898", 2),  # ldr r0, [sp, #0x20]
    ]

    THUMB32_CASES = [
        ("d1f82400", 4),  # ldr.w r0, [r1, #0x24]
        ("c3f84020", 4),  # str.w r2, [r3, #0x40]
        ("91f82400", 4),  # ldrb.w r0, [r1, #0x24]
        ("83f84020", 4),  # strb.w r2, [r3, #0x40]
        ("b1f82400", 4),  # ldrh.w r0, [r1, #0x24]
        ("a3f84020", 4),  # strh.w r2, [r3, #0x40]
        ("d2e90601", 4),  # ldrd r0, r1, [r2, #0x18]
        ("c2e90601", 4),  # strd r0, r1, [r2, #0x18]
        ("00f004f8", 4),  # bl #target
        ("00f004e8", 4),  # blx #target
        ("00f00490", 4),  # b.w #target
        ("2de91040", 4),  # push.w {r4, lr}
        ("bde81080", 4),  # pop.w {r4, pc}
    ]

    ARM32_CASES = [
        ("240091e5", 4),  # ldr r0, [r1, #0x24]
        ("402083e5", 4),  # str r2, [r3, #0x40]
        ("d801c2e1", 4),  # ldrd r0, r1, [r2, #0x18]
        ("f801c2e1", 4),  # strd r0, r1, [r2, #0x18]
        ("050000ea", 4),  # b #target
        ("050000eb", 4),  # bl #target
        ("1eff2fe1", 4),  # bx lr
        ("33ff2fe1", 4),  # blx r3
        ("f0402de9", 4),  # stmdb sp!, {r4-r7, lr}
        ("f080bde8", 4),  # ldmia sp!, {r4-r7, pc}
        ("10d04de2", 4),  # sub sp, sp, #0x10
    ]

    def test_thumb16_lengths(self):
        for hexstr, expected_len in self.THUMB16_CASES:
            data = bytes.fromhex(hexstr)
            self.assertEqual(A.get_insn_length(data, thumb=True), expected_len, hexstr)
            insn = A.decode(data, thumb=True)
            self.assertEqual(insn.length, expected_len, hexstr)
            self.assertFalse(insn.invalid, hexstr)

    def test_thumb32_lengths(self):
        for hexstr, expected_len in self.THUMB32_CASES:
            data = bytes.fromhex(hexstr)
            hw = struct.unpack_from("<H", data, 0)[0]
            self.assertTrue(A.is_thumb32(hw), f"Expected thumb32 prefix for {hexstr}")
            self.assertEqual(A.get_insn_length(data, thumb=True), expected_len, hexstr)
            insn = A.decode(data, thumb=True)
            self.assertEqual(insn.length, expected_len, hexstr)
            self.assertFalse(insn.invalid, hexstr)

    def test_arm32_lengths(self):
        for hexstr, expected_len in self.ARM32_CASES:
            data = bytes.fromhex(hexstr)
            self.assertEqual(A.get_insn_length(data, thumb=False), expected_len, hexstr)
            insn = A.decode(data, thumb=False)
            self.assertEqual(insn.length, expected_len, hexstr)
            self.assertFalse(insn.invalid, hexstr)

    def test_mixed_thumb_stream_synchronization(self):
        # Stream mixing Thumb-16 and Thumb-32 instructions:
        # push {r4, lr} (2B), ldr.w r0, [r1, #0x24] (4B), cmp r0, #0 (2B), b.w #target (4B), bx lr (2B)
        stream_hex = "10b5" + "d1f82400" + "0028" + "00f00490" + "7047"
        data = bytes.fromhex(stream_hex)
        decoded = list(A.iter_decode(data, address=0x1000, thumb=True))
        self.assertEqual(len(decoded), 5)
        lengths = [i.length for i in decoded]
        self.assertEqual(lengths, [2, 4, 2, 4, 2])
        addrs = [i.address for i in decoded]
        self.assertEqual(addrs, [0x1000, 0x1002, 0x1006, 0x1008, 0x100C])

    @unittest.skipUnless(HAS_CAPSTONE, "Capstone required for cross-verification")
    def test_capstone_thumb_cross_verification(self):
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        all_cases = self.THUMB16_CASES + self.THUMB32_CASES
        for hexstr, expected_len in all_cases:
            data = bytes.fromhex(hexstr)
            cs_insn = list(md.disasm(data, 0x1000))[0]
            my_insn = A.decode(data, 0, 0x1000, thumb=True)
            self.assertEqual(my_insn.length, cs_insn.size, f"Length mismatch on {hexstr}")


class TestArm32MemoryAccessDisplacement(unittest.TestCase):
    """Verifies memory access displacement extraction for ARM32."""

    def test_ldr_str_word(self):
        # LDR r0, [r1, #0x24]
        i1 = A.decode(bytes.fromhex("240091e5"), address=0x1000, thumb=False)
        self.assertEqual(i1.mnemonic, "ldr")
        self.assertEqual(i1.mem.base, "r1")
        self.assertEqual(i1.mem.disp, 0x24)
        self.assertEqual(i1.target_reg, "r0")
        self.assertEqual(i1.access_size, 4)
        self.assertFalse(i1.is_write)

        # STR r2, [r3, #0x40]
        i2 = A.decode(bytes.fromhex("402083e5"), address=0x1004, thumb=False)
        self.assertEqual(i2.mnemonic, "str")
        self.assertEqual(i2.mem.base, "r3")
        self.assertEqual(i2.mem.disp, 0x40)
        self.assertEqual(i2.target_reg, "r2")
        self.assertEqual(i2.access_size, 4)
        self.assertTrue(i2.is_write)

    def test_byte_and_halfword(self):
        # LDRB r0, [r1, #0x12]
        i1 = A.decode(bytes.fromhex("1200d1e5"), thumb=False)
        self.assertEqual(i1.mnemonic, "ldrb")
        self.assertEqual(i1.mem.disp, 0x12)
        self.assertEqual(i1.access_size, 1)
        self.assertFalse(i1.is_write)

        # STRB r2, [r3, #0x12]
        i2 = A.decode(bytes.fromhex("1220c3e5"), thumb=False)
        self.assertEqual(i2.mnemonic, "strb")
        self.assertEqual(i2.mem.disp, 0x12)
        self.assertEqual(i2.access_size, 1)
        self.assertTrue(i2.is_write)

        # LDRH r0, [r1, #0x10]
        i3 = A.decode(bytes.fromhex("b001d1e1"), thumb=False)
        self.assertEqual(i3.mnemonic, "ldrh")
        self.assertEqual(i3.mem.disp, 0x10)
        self.assertEqual(i3.access_size, 2)
        self.assertFalse(i3.is_write)

        # STRH r2, [r3, #0x10]
        i4 = A.decode(bytes.fromhex("b021c3e1"), thumb=False)
        self.assertEqual(i4.mnemonic, "strh")
        self.assertEqual(i4.mem.disp, 0x10)
        self.assertEqual(i4.access_size, 2)
        self.assertTrue(i4.is_write)

    def test_doubleword_ldrd_strd(self):
        # LDRD r0, r1, [r2, #0x18]
        i1 = A.decode(bytes.fromhex("d801c2e1"), thumb=False)
        self.assertEqual(i1.mnemonic, "ldrd")
        self.assertEqual(i1.mem.base, "r2")
        self.assertEqual(i1.mem.disp, 0x18)
        self.assertEqual(i1.access_size, 8)
        self.assertFalse(i1.is_write)

        # STRD r0, r1, [r2, #0x18]
        i2 = A.decode(bytes.fromhex("f801c2e1"), thumb=False)
        self.assertEqual(i2.mnemonic, "strd")
        self.assertEqual(i2.mem.base, "r2")
        self.assertEqual(i2.mem.disp, 0x18)
        self.assertEqual(i2.access_size, 8)
        self.assertTrue(i2.is_write)

    def test_negative_displacement(self):
        # LDR r0, [r1, #-0x20] (U=0: bit 23 is 0 -> 0x04100000 -> 200011e5)
        i = A.decode(bytes.fromhex("200011e5"), thumb=False)
        self.assertEqual(i.mnemonic, "ldr")
        self.assertEqual(i.mem.disp, -0x20)
        self.assertFalse(i.is_write)


class TestThumbMemoryAccessDisplacement(unittest.TestCase):
    """Verifies memory access displacement extraction for Thumb-16 and Thumb-32."""

    def test_thumb16_accesses(self):
        # LDR r0, [r1, #0x28]
        i1 = A.decode(bytes.fromhex("886a"), thumb=True)
        self.assertEqual(i1.mnemonic, "ldr")
        self.assertEqual(i1.mem.base, "r1")
        self.assertEqual(i1.mem.disp, 0x28)
        self.assertEqual(i1.access_size, 4)
        self.assertFalse(i1.is_write)

        # STR r2, [r3, #0x40]
        i2 = A.decode(bytes.fromhex("1a64"), thumb=True)
        self.assertEqual(i2.mnemonic, "str")
        self.assertEqual(i2.mem.base, "r3")
        self.assertEqual(i2.mem.disp, 0x40)
        self.assertEqual(i2.access_size, 4)
        self.assertTrue(i2.is_write)

        # LDRB r0, [r1, #5]
        i3 = A.decode(bytes.fromhex("4879"), thumb=True)
        self.assertEqual(i3.mnemonic, "ldrb")
        self.assertEqual(i3.mem.disp, 5)
        self.assertEqual(i3.access_size, 1)

        # STRB r2, [r3, #5]
        i4 = A.decode(bytes.fromhex("5a71"), thumb=True)
        self.assertEqual(i4.mnemonic, "strb")
        self.assertEqual(i4.mem.disp, 5)
        self.assertEqual(i4.access_size, 1)
        self.assertTrue(i4.is_write)

        # LDR r0, [sp, #0x20]
        i5 = A.decode(bytes.fromhex("0898"), thumb=True)
        self.assertEqual(i5.mem.base, "sp")
        self.assertEqual(i5.mem.disp, 0x20)

    def test_thumb32_accesses(self):
        # LDR.W r0, [r1, #0x24]
        i1 = A.decode(bytes.fromhex("d1f82400"), thumb=True)
        self.assertEqual(i1.mnemonic, "ldr.w")
        self.assertEqual(i1.mem.base, "r1")
        self.assertEqual(i1.mem.disp, 0x24)
        self.assertEqual(i1.access_size, 4)
        self.assertFalse(i1.is_write)

        # STR.W r2, [r3, #0x40]
        i2 = A.decode(bytes.fromhex("c3f84020"), thumb=True)
        self.assertEqual(i2.mnemonic, "str.w")
        self.assertEqual(i2.mem.base, "r3")
        self.assertEqual(i2.mem.disp, 0x40)
        self.assertEqual(i2.access_size, 4)
        self.assertTrue(i2.is_write)

        # LDRD r0, r1, [r2, #0x18]
        i3 = A.decode(bytes.fromhex("d2e90601"), thumb=True)
        self.assertEqual(i3.mnemonic, "ldrd")
        self.assertEqual(i3.mem.base, "r2")
        self.assertEqual(i3.mem.disp, 0x18)
        self.assertEqual(i3.access_size, 8)
        self.assertFalse(i3.is_write)

        # STRD r0, r1, [r2, #0x18]
        i4 = A.decode(bytes.fromhex("c2e90601"), thumb=True)
        self.assertEqual(i4.mnemonic, "strd")
        self.assertEqual(i4.mem.base, "r2")
        self.assertEqual(i4.mem.disp, 0x18)
        self.assertEqual(i4.access_size, 8)
        self.assertTrue(i4.is_write)

    def test_thumb32_negative_displacement(self):
        # LDR r0, [r1, #-0x4]
        i = A.decode(bytes.fromhex("51f8040c"), thumb=True)
        self.assertEqual(i.mnemonic, "ldr")
        self.assertEqual(i.mem.disp, -4)

        # LDRD r0, r1, [r1, #-0x20]
        i_d = A.decode(bytes.fromhex("51e90801"), thumb=True)
        self.assertEqual(i_d.mnemonic, "ldrd")
        self.assertEqual(i_d.mem.disp, -0x20)


class TestBranchAndCallTargetResolution(unittest.TestCase):
    """Verifies branch target resolution and call classification."""

    def test_arm32_branches(self):
        # B #0x101c from 0x1000
        b_insn = A.decode(bytes.fromhex("050000ea"), address=0x1000, thumb=False)
        self.assertEqual(b_insn.flow, "jmp")
        self.assertEqual(b_insn.target, 0x101c)
        self.assertFalse(b_insn.is_cond)

        # BEQ #0x101c from 0x1000
        beq_insn = A.decode(bytes.fromhex("0500000a"), address=0x1000, thumb=False)
        self.assertEqual(beq_insn.flow, "jcc")
        self.assertEqual(beq_insn.target, 0x101c)
        self.assertTrue(beq_insn.is_cond)

        # BL #0x101c from 0x1000
        bl_insn = A.decode(bytes.fromhex("050000eb"), address=0x1000, thumb=False)
        self.assertEqual(bl_insn.flow, "call")
        self.assertEqual(bl_insn.target, 0x101c)

        # BX lr
        bx_lr = A.decode(bytes.fromhex("1eff2fe1"), address=0x1000, thumb=False)
        self.assertEqual(bx_lr.flow, "ret")
        self.assertTrue(bx_lr.is_epilogue)

        # BLX r3
        blx_r3 = A.decode(bytes.fromhex("33ff2fe1"), address=0x1000, thumb=False)
        self.assertEqual(blx_r3.flow, "call_ind")

    def test_thumb16_branches(self):
        # B #0x200c from 0x2000
        b = A.decode(bytes.fromhex("04e0"), address=0x2000, thumb=True)
        self.assertEqual(b.flow, "jmp")
        self.assertEqual(b.target, 0x200c)

        # BNE #0x200c from 0x2000
        bne = A.decode(bytes.fromhex("04d1"), address=0x2000, thumb=True)
        self.assertEqual(bne.flow, "jcc")
        self.assertEqual(bne.target, 0x200c)
        self.assertTrue(bne.is_cond)

        # CBZ r0, #0x2006 from 0x2000 (0x2000 + 4 + 2 = 0x2006)
        cbz = A.decode(bytes.fromhex("08b1"), address=0x2000, thumb=True)
        self.assertEqual(cbz.flow, "jcc")
        self.assertEqual(cbz.target, 0x2006)
        self.assertTrue(cbz.is_cond)

        # CBNZ r1, #0x2006 from 0x2000
        cbnz = A.decode(bytes.fromhex("09b9"), address=0x2000, thumb=True)
        self.assertEqual(cbnz.flow, "jcc")
        self.assertEqual(cbnz.target, 0x2006)
        self.assertTrue(cbnz.is_cond)

        # BX lr
        bx = A.decode(bytes.fromhex("7047"), address=0x2000, thumb=True)
        self.assertEqual(bx.flow, "ret")
        self.assertTrue(bx.is_epilogue)

    def test_thumb32_branches(self):
        # BL #0x300c from 0x3000
        bl = A.decode(bytes.fromhex("00f004f8"), address=0x3000, thumb=True)
        self.assertEqual(bl.flow, "call")
        self.assertEqual(bl.target, 0x300c)

        # BLX #0x300c from 0x3000
        blx = A.decode(bytes.fromhex("00f004e8"), address=0x3000, thumb=True)
        self.assertEqual(blx.flow, "call")
        self.assertEqual(blx.target, 0x300c)

        # B.W #0xc0300c from 0x3000
        bw = A.decode(bytes.fromhex("00f00490"), address=0x3000, thumb=True)
        self.assertEqual(bw.flow, "jmp")
        self.assertEqual(bw.target, 0xc0300c)

        # TBB [r0, r1]
        tbb = A.decode(bytes.fromhex("d0e801f0"), address=0x3000, thumb=True)
        self.assertEqual(tbb.mnemonic, "tbb")
        self.assertEqual(tbb.flow, "jmp_ind")


class TestPrologueEpilogueDetection(unittest.TestCase):
    """Verifies function prologue and epilogue classification."""

    def test_arm32_prologue_epilogue(self):
        # STMDB sp!, {r4-r7, lr}
        prologue = A.decode(bytes.fromhex("f0402de9"), thumb=False)
        self.assertTrue(prologue.is_prologue)

        # SUB sp, sp, #0x10
        sub_sp = A.decode(bytes.fromhex("10d04de2"), thumb=False)
        self.assertTrue(sub_sp.is_prologue)

        # LDMIA sp!, {r4-r7, pc}
        epilogue = A.decode(bytes.fromhex("f080bde8"), thumb=False)
        self.assertTrue(epilogue.is_epilogue)
        self.assertEqual(epilogue.flow, "ret")

    def test_thumb_prologue_epilogue(self):
        # Thumb-16 PUSH {r4, lr}
        push = A.decode(bytes.fromhex("10b5"), thumb=True)
        self.assertTrue(push.is_prologue)

        # Thumb-16 POP {r4, pc}
        pop = A.decode(bytes.fromhex("10bd"), thumb=True)
        self.assertTrue(pop.is_epilogue)
        self.assertEqual(pop.flow, "ret")

        # Thumb-32 PUSH.W {r4, lr}
        push_w = A.decode(bytes.fromhex("2de91040"), thumb=True)
        self.assertTrue(push_w.is_prologue)

        # Thumb-32 POP.W {r4, pc}
        pop_w = A.decode(bytes.fromhex("bde81080"), thumb=True)
        self.assertTrue(pop_w.is_epilogue)
        self.assertEqual(pop_w.flow, "ret")


class TestCFGConstructionARM32AndThumb(unittest.TestCase):
    """Verifies CFG construction, edge wiring, and feature extraction."""

    def test_arm32_cfg_if_else(self):
        # Synthetic ARM32 function with if-else:
        # 0x1000: cmp r0, #0       (000050e3)
        # 0x1004: beq 0x1010       (0100000a)
        # 0x1008: mov r0, #1       (0100a0e3)
        # 0x100c: b 0x1014         (000000ea)
        # 0x1010: mov r0, #2       (0200a0e3)
        # 0x1014: bx lr            (1eff2fe1)
        code = bytes.fromhex("000050e3 0100000a 0100a0e3 000000ea 0200a0e3 1eff2fe1")
        cfgs = D.extract_cfgs_from_arm32_bytes(code, base_vaddr=0x1000, thumb_mode=False)
        self.assertEqual(len(cfgs), 1)
        cfg = cfgs[0]
        self.assertEqual(cfg.address, 0x1000)
        self.assertEqual(len(cfg.blocks), 4)
        self.assertEqual(len(cfg.edges), 4)

        # Check entry block branching:
        entry_b = cfg.blocks[0x1000]
        self.assertEqual(sorted(entry_b.successors), [0x1008, 0x1010])

        # Feature vector extraction:
        vec = D.CFGFeatureExtractor.extract_vector(cfg)
        self.assertEqual(vec.shape, (32,))
        self.assertGreater(float(vec[0]), 0.0)  # num_blocks > 0

    def test_thumb_cfg_if_else(self):
        # Synthetic Thumb function with if-else:
        # 0x2000: cmp r0, #0       (0028)
        # 0x2002: beq 0x2008       (01d0)
        # 0x2004: movs r0, #1      (0120)
        # 0x2006: b 0x200a         (00e0)
        # 0x2008: movs r0, #2      (0220)
        # 0x200a: bx lr            (7047)
        code = bytes.fromhex("0028 01d0 0120 00e0 0220 7047")
        cfgs = D.extract_cfgs_from_arm32_bytes(code, base_vaddr=0x2000, thumb_mode=True)
        self.assertEqual(len(cfgs), 1)
        cfg = cfgs[0]
        self.assertEqual(cfg.address, 0x2000)
        self.assertEqual(len(cfg.blocks), 4)
        self.assertEqual(len(cfg.edges), 4)

        entry_b = cfg.blocks[0x2000]
        self.assertEqual(sorted(entry_b.successors), [0x2004, 0x2008])

        # Check call graph and call tracking on BL inside a function:
        # cmp r0, #0 ; beq +3 ; movs r0, #1 ; b +2 ; bl #0x2012 ; bx lr
        code_with_call = bytes.fromhex("0028 02d0 0120 01e0 00f003f8 7047")
        cfgs_call = D.extract_cfgs_from_arm32_bytes(code_with_call, base_vaddr=0x2000, thumb_mode=True)
        self.assertEqual(len(cfgs_call), 1)
        self.assertIn("0x2012", cfgs_call[0].callees)

    def test_binary_diff_matcher_arm32(self):
        # Two identical ARM32 functions should have high similarity (~1.0)
        code = bytes.fromhex("000050e3 0100000a 0100a0e3 000000ea 0200a0e3 1eff2fe1")
        cfgs_a = D.extract_cfgs_from_arm32_bytes(code, base_vaddr=0x1000, thumb_mode=False)
        cfgs_b = D.extract_cfgs_from_arm32_bytes(code, base_vaddr=0x2000, thumb_mode=False)

        matcher = D.BatchedBinaryMatcher(threshold=0.85, use_gpu=False)
        diff_res = matcher.diff_binaries(cfgs_a, cfgs_b)
        self.assertEqual(len(diff_res.matches), 1)
        self.assertAlmostEqual(diff_res.matches[0].similarity, 1.0, places=2)

    def test_extract_cfgs_from_elf_container(self):
        code = bytes.fromhex("000050e3 0100000a 0100a0e3 000000ea 0200a0e3 1eff2fe1")
        raw_elf = make_arm_elf(code, thumb=False, func_name="ArmFunction")
        cfgs = D.extract_cfgs_from_binary(raw_elf)
        self.assertEqual(len(cfgs), 1)
        self.assertEqual(cfgs[0].name, "ArmFunction")
        self.assertEqual(len(cfgs[0].blocks), 4)


class TestStructShiftMigrationARM32(unittest.TestCase):
    """Verifies cross-version struct shift migration for ARM32 and Thumb binaries."""

    def test_shift_migration_arm32_bytes(self):
        # v1: reads [r1, #0x10] and [r1, #0x14]
        v1 = bytes.fromhex("100091e5 142091e5 1eff2fe1")
        # v2: a 4-byte field is inserted at 0x10, shifting 0x14 -> 0x18
        v2 = bytes.fromhex("100091e5 182091e5 1eff2fe1")

        mig = M.StructShiftMigrator()
        mig.load_from_arm32_bytes(v1, v2, thumb=False)
        report = mig.analyze_shifts(struct_name="ActorState")
        self.assertEqual(report.total_shifts_detected, 1)

        moved = {m.old_offset: (m.new_offset, m.delta, m.shift_type) for m in report.field_migrations}
        self.assertEqual(moved[0x10], (0x10, 0, "identical"))
        self.assertEqual(moved[0x14], (0x18, 4, "insertion_shift"))

    def test_shift_migration_thumb_bytes(self):
        # Thumb-16:
        # v1: ldr r0, [r1, #0x10] (0869), ldr r2, [r1, #0x14] (4a69), bx lr (7047)
        # v2: ldr r0, [r1, #0x10] (0869), ldr r2, [r1, #0x18] (8a69), bx lr (7047)
        v1 = bytes.fromhex("0869 4a69 7047")
        v2 = bytes.fromhex("0869 8a69 7047")

        mig = M.StructShiftMigrator()
        mig.load_from_arm32_bytes(v1, v2, thumb=True)
        report = mig.analyze_shifts(struct_name="ThumbEntity")
        self.assertEqual(report.total_shifts_detected, 1)

        moved = {m.old_offset: (m.new_offset, m.delta, m.shift_type) for m in report.field_migrations}
        self.assertEqual(moved[0x10], (0x10, 0, "identical"))
        self.assertEqual(moved[0x14], (0x18, 4, "insertion_shift"))

    def test_shift_migration_arm32_elf_containers(self):
        # Two versions of an ELF shared object (.so) containing an exported function
        v1_code = bytes.fromhex("100091e5 142091e5 1eff2fe1")
        v2_code = bytes.fromhex("100091e5 182091e5 1eff2fe1")

        v1_elf = make_arm_elf(v1_code, thumb=False, func_name="TickCombat")
        v2_elf = make_arm_elf(v2_code, thumb=False, func_name="TickCombat")

        with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as f1, \
             tempfile.NamedTemporaryFile(suffix=".so", delete=False) as f2:
            f1.write(v1_elf)
            f2.write(v2_elf)
            p1, p2 = f1.name, f2.name

        try:
            mig = M.StructShiftMigrator()
            mig.load_from_elf_binaries(p1, p2)
            self.assertIn("TickCombat", mig._v1_functions)
            self.assertIn("TickCombat", mig._v2_functions)

            report = mig.analyze_shifts(struct_name="CombatData")
            self.assertEqual(report.total_shifts_detected, 1)

            moved = {m.old_offset: (m.new_offset, m.delta) for m in report.field_migrations}
            self.assertEqual(moved[0x14], (0x18, 4))
        finally:
            if os.path.exists(p1):
                os.remove(p1)
            if os.path.exists(p2):
                os.remove(p2)

    def test_shift_migration_thumb_elf_containers(self):
        # Two versions of an ELF shared object with a Thumb exported function
        v1_code = bytes.fromhex("0869 4a69 7047")
        v2_code = bytes.fromhex("0869 8a69 7047")

        v1_elf = make_arm_elf(v1_code, thumb=True, func_name="TickUI")
        v2_elf = make_arm_elf(v2_code, thumb=True, func_name="TickUI")

        with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as f1, \
             tempfile.NamedTemporaryFile(suffix=".so", delete=False) as f2:
            f1.write(v1_elf)
            f2.write(v2_elf)
            p1, p2 = f1.name, f2.name

        try:
            mig = M.StructShiftMigrator()
            mig.load_from_elf_binaries(p1, p2)
            self.assertIn("TickUI", mig._v1_functions)
            self.assertIn("TickUI", mig._v2_functions)

            report = mig.analyze_shifts(struct_name="UIData")
            self.assertEqual(report.total_shifts_detected, 1)

            moved = {m.old_offset: (m.new_offset, m.delta) for m in report.field_migrations}
            self.assertEqual(moved[0x14], (0x18, 4))
        finally:
            if os.path.exists(p1):
                os.remove(p1)
            if os.path.exists(p2):
                os.remove(p2)


class TestThumb2LiteralLoads(unittest.TestCase):
    """Rn = PC loads always use the 12-bit literal form; U is hw1 bit 7 (Capstone-verified)."""

    CASES = [
        ("3ff8d66f", "ldrh.w", -0xFD6, 2),  # ldrh.w r6, [pc, #-0xfd6]
        ("1ff9e699", "ldrsb.w", -0x9E6, 1),  # ldrsb.w sb, [pc, #-0x9e6]
        ("5ff86670", "ldr.w", -0x66, 4),  # ldr.w r7, [pc, #-0x66]  (hw2 bit 11 clear)
        ("dff80420", "ldr.w", 0x4, 4),  # ldr.w r2, [pc, #4]
    ]

    def test_literal_forms(self):
        for hexbytes, mnem, disp, size in self.CASES:
            with self.subTest(hexbytes):
                insn = A.decode(bytes.fromhex(hexbytes), 0, 0x1000, thumb=True)
                self.assertEqual(insn.mnemonic, mnem)
                self.assertEqual((insn.mem.base, insn.mem.disp), ("pc", disp))
                self.assertTrue(insn.mem.is_literal)
                self.assertEqual(insn.access_size, size)
                self.assertFalse(insn.is_write)


if __name__ == "__main__":
    unittest.main()
