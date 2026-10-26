"""Tests for x86_decode: hand-checked encodings plus an optional Capstone cross-check."""

import importlib.util
import os
import unittest

from superghidra.lifters import x86_decode as X


def d(hexstr, mode=64, addr=0x1000):
    return X.decode(bytes.fromhex(hexstr.replace(" ", "")), 0, addr, mode)


class TestLengths64(unittest.TestCase):
    CASES = [
        ("c3", 1), ("55", 1), ("4889e5", 3), ("488b4720", 4), ("4c8d8780000000", 7),
        ("f30f1efa", 4), ("e800000000", 5), ("0f8400010000", 6), ("eb10", 2),
        ("48b88877665544332211", 10), ("66b83412", 4), ("c7400401000000", 7),
        ("48c7c0ffffffff", 7), ("f30f104424 20".replace(" ", ""), 6),  # movss xmm0,[rsp+20h]
        ("c5f877", 3),  # vzeroupper
        ("c4e27d18442408", 7),  # vbroadcastss ymm0,[rsp+8]
        ("62f17c48100424", 7),  # vmovups zmm0,[rsp]
        ("660f3a0fc108", 6),  # palignr xmm0,xmm1,8
        ("0f1f440000", 5), ("660f1f840000000000", 9),  # multi-byte nops
        ("f6c101", 3), ("f7c100010000", 6),  # test cl,1 / test ecx,100h
        ("a1efcdab8967452301", 9),  # mov eax,[moffs64]
        ("ff2500000000", 6), ("ff15f0000000", 6),  # jmp/call [rip+..]
        ("c20800", 3), ("cc", 1), ("f0480fb10a", 5),  # lock cmpxchg [rdx],rcx
    ]

    def test_lengths(self):
        for hexstr, length in self.CASES:
            with self.subTest(hexstr=hexstr):
                insn = d(hexstr)
                self.assertFalse(insn.invalid, hexstr)
                self.assertEqual(insn.length, length, hexstr)


class TestOperands(unittest.TestCase):
    def test_struct_load(self):
        insn = d("488b4720")  # mov rax,[rdi+20h]
        self.assertEqual((insn.mem.base, insn.mem.disp), ("rdi", 0x20))
        self.assertEqual(insn.reg_name(insn.reg, insn.operand_size), "rax")
        self.assertEqual(insn.memory_access_size(), 8)
        self.assertFalse(insn.is_memory_write())

    def test_struct_store_and_sib(self):
        insn = d("89448f10")  # mov [rdi+rcx*4+10h],eax
        self.assertEqual((insn.mem.base, insn.mem.index, insn.mem.scale, insn.mem.disp), ("rdi", "rcx", 4, 0x10))
        self.assertTrue(insn.is_memory_write())
        self.assertEqual(insn.memory_access_size(), 4)

    def test_rex_extended_registers(self):
        insn = d("4d8b4818")  # mov r9,[r8+18h]
        self.assertEqual(insn.mem.base, "r8")
        self.assertEqual(insn.reg_name(insn.reg, 8), "r9")

    def test_rip_relative(self):
        insn = d("488b0510000000", addr=0x140001000)  # mov rax,[rip+10h]
        self.assertTrue(insn.mem.rip_relative)
        self.assertIsNone(insn.mem.base)
        self.assertEqual(insn.mem.effective_address(insn.end), 0x140001017)

    def test_sse_double_store(self):
        insn = d("f20f114c2418")  # movsd [rsp+18h],xmm1
        self.assertEqual(insn.memory_access_size(), 8)
        self.assertTrue(insn.is_memory_write())

    def test_avx_load_size(self):
        insn = d("c5fc104708")  # vmovups ymm0,[rdi+8]
        self.assertEqual(insn.vex, "vex")
        self.assertEqual((insn.mem.base, insn.mem.disp), ("rdi", 8))
        self.assertEqual(insn.memory_access_size(), 32)

    def test_lea_is_not_an_access(self):
        self.assertIsNone(d("488d4f08").memory_access_size())

    def test_branch_targets(self):
        self.assertEqual(d("e8fb0f0000", addr=0x1000).target, 0x2000)
        self.assertEqual(d("75fe", addr=0x1000).flow, "jcc")
        self.assertEqual(d("75fe", addr=0x1000).target, 0x1000)
        self.assertEqual(d("ffd0").flow, "call_ind")
        self.assertEqual(d("c3").flow, "ret")


class TestMode32And16(unittest.TestCase):
    def test_inc_dec_are_not_rex_in_32bit(self):
        insn = d("40", mode=32)  # inc eax
        self.assertEqual((insn.length, insn.rex), (1, 0))
        self.assertEqual(d("488b4720", mode=32).length, 1)  # dec eax, then a new instruction

    def test_absolute_disp32(self):
        insn = d("a150301010", mode=32)
        self.assertEqual((insn.length, insn.mem.disp), (5, 0x10103050))
        insn = d("8b0d78563412", mode=32)  # mov ecx,[12345678h] (no RIP in 32-bit)
        self.assertFalse(insn.mem.rip_relative)
        self.assertEqual(insn.mem.effective_address(insn.end), 0x12345678)

    def test_les_vs_vex_in_32bit(self):
        self.assertIsNone(d("c4060000", mode=32).vex)  # les eax,[esi] (mod != 11)
        self.assertEqual(d("c5f877", mode=32).vex, "vex")

    def test_16bit_addressing(self):
        insn = d("678b4704", mode=32)  # mov eax,[bx+4] with 67 prefix
        self.assertEqual((insn.length, insn.mem.base, insn.mem.disp), (4, "bx", 4))

    def test_far_call_ptr(self):
        self.assertEqual(d("9a785634120800", mode=32).length, 7)


class TestRobustness(unittest.TestCase):
    def test_truncated_is_invalid_one_byte(self):
        insn = d("488b")
        self.assertTrue(insn.invalid)
        self.assertEqual(insn.length, 1)

    def test_sweep_always_advances(self):
        code = bytes(range(256)) * 4
        total = sum(i.length for i in X.iter_decode(code, 0x1000))
        self.assertEqual(total, len(code))


_CAPSTONE = importlib.util.find_spec("capstone") is not None
_DLLS = [p for p in (r"C:\Windows\System32\kernel32.dll", r"C:\Windows\SysWOW64\kernel32.dll") if os.path.exists(p)]


@unittest.skipUnless(_CAPSTONE and _DLLS, "needs capstone and Windows system DLLs")
class TestAgainstCapstone(unittest.TestCase):
    def test_lengths_match_capstone_on_real_code(self):
        import capstone

        from superghidra.formats import binary_loader as B

        for path in _DLLS:
            img = B.load_binary(path)
            mode = 64 if img.arch == "x86_64" else 32
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if mode == 64 else capstone.CS_MODE_32)
            checked = 0
            for fs in img.function_starts[:400]:
                sec = img.section_for_va(fs)
                if not sec or not sec.executable:
                    continue
                off = img.va_to_offset(fs)
                code = img.data[off : off + 1500]
                pos = 0
                for ci in cs.disasm(code, fs, 100):
                    if ci.address - fs != pos:
                        break
                    self.assertEqual(X.decode(code, pos, ci.address, mode).length, ci.size,
                                     f"{path} {ci.address:#x} {ci.mnemonic} {ci.op_str}")
                    pos += ci.size
                    checked += 1
            self.assertGreater(checked, 1000)


if __name__ == "__main__":
    unittest.main()
