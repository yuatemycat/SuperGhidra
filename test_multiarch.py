"""Multi-architecture paths: 32-bit x86, SSE/AVX struct accesses, PE/ELF/Mach-O dispatch."""

import os
import tempfile
import unittest

import binary_diff_engine as D
import struct_shift_migrator as M
from test_binary_loader import build_elf, build_macho64, build_pe


def pe_with_functions(func_a: bytes, func_b: bytes, bits=64, machine=0x8664) -> bytes:
    """PE whose exports FuncA/FuncB point at the given code (FuncB at +0x10)."""
    assert len(func_a) <= 0x10
    return build_pe(bits, machine, text=func_a.ljust(0x10, b"\xCC") + func_b)[0]


class TestX86StructAccesses(unittest.TestCase):
    def test_32bit_mode_inc_is_not_rex(self):
        # inc eax ; mov eax,[edi+20h] ; ret
        accs = M.decode_x86_64_memory_accesses(bytes.fromhex("408b4720c3"), 0x401000, mode=32)
        self.assertEqual(len(accs), 1)
        self.assertEqual((accs[0].pc, accs[0].base_reg, accs[0].target_reg, accs[0].displacement),
                         (0x401001, "edi", "eax", 0x20))

    def test_sse_double_and_vtable_call(self):
        code = bytes.fromhex(
            "f20f104718"   # movsd xmm0,[rdi+18h]
            "f20f114f20"   # movsd [rdi+20h],xmm1
            "c5fc104708"   # vmovups ymm0,[rdi+8]
            "488b01"       # mov rax,[rcx]       (vptr load, offset 0)
            "ff5018"       # call [rax+18h]      (vtable slot 3)
            "0fb64710"     # movzx eax,byte [rdi+10h]
            "c7471000000000"  # mov dword [rdi+10h],0
            "c3"
        )
        accs = M.decode_x86_64_memory_accesses(code, 0x1000)
        got = [(a.mnemonic, a.base_reg, a.displacement, a.access_size, a.is_write) for a in accs]
        self.assertEqual(got, [
            ("MOVSD", "rdi", 0x18, 8, False),
            ("MOVSD", "rdi", 0x20, 8, True),
            ("VMOVUPS", "rdi", 0x08, 32, False),
            ("MOV", "rcx", 0x00, 8, False),
            ("CALL", "rax", 0x18, 8, False),
            ("MOVZX", "rdi", 0x10, 1, False),
            ("MOV", "rdi", 0x10, 4, True),
        ])
        self.assertEqual(accs[0].target_reg, "xmm0")

    def test_sweep_survives_unknown_opcodes(self):
        # The old decoder resynced byte-by-byte on unknown opcodes and could invent accesses.
        code = bytes.fromhex("0f28c1" "660f6fc1" "488b4720" "c3")  # movaps xmm0,xmm1; movdqa; mov rax,[rdi+20h]
        accs = M.decode_x86_64_memory_accesses(code)
        self.assertEqual([(a.base_reg, a.displacement) for a in accs], [("rdi", 0x20)])


class TestCFGDispatch(unittest.TestCase):
    def test_pe32_cfgs_use_32bit_decoder_and_export_names(self):
        raw = pe_with_functions(bytes.fromhex("5589e5" "40" "8b4508" "5dc3"), bytes.fromhex("31c0c3"),
                                bits=32, machine=0x14C)
        cfgs = D.extract_cfgs_from_binary(raw)
        names = {c.name: c for c in cfgs}
        self.assertIn("FuncA", names)
        self.assertIn("FuncB", names)
        mnems = [i.mnemonic for bb in names["FuncA"].blocks.values() for i in bb.instructions]
        self.assertIn("inc", mnems)  # 0x40 decoded as INC, not swallowed as a REX prefix
        self.assertEqual(mnems[-1], "ret")

    def test_pe64_cfgs(self):
        cfgs = D.extract_cfgs_from_binary(build_pe(64)[0])
        self.assertEqual({c.name for c in cfgs} >= {"FuncA", "FuncB"}, True)

    def test_unsupported_arch_returns_empty_not_garbage(self):
        raw = build_elf(32, "big", 8)[0]  # MIPS
        with self.assertLogs("binary_diff_engine", level="WARNING"):
            self.assertEqual(D.extract_cfgs_from_binary(raw), [])

    def test_macho_arm64(self):
        cfgs = D.extract_cfgs_from_binary(build_macho64()[0])
        self.assertTrue(any(c.name == "_exported" for c in cfgs))


class TestStructShiftAcrossPEVersions(unittest.TestCase):
    def _write(self, data: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".dll")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        self.addCleanup(os.remove, path)
        return path

    def test_shift_detected_between_dll_versions(self):
        # FuncA reads [rcx+10h] and [rcx+18h]; in v2 a field was inserted -> [rcx+20h].
        v1 = pe_with_functions(bytes.fromhex("8b4110" "8b5118" "c3"), bytes.fromhex("31c0c3"))
        v2 = pe_with_functions(bytes.fromhex("8b4110" "8b5120" "c3"), bytes.fromhex("31c0c3"))
        mig = M.StructShiftMigrator()
        mig.load_from_elf_binaries(self._write(v1), self._write(v2))
        self.assertIn("FuncA", mig._v1_functions)
        report = mig.analyze_shifts(struct_name="Feature")
        moved = {m.old_offset: m.new_offset for m in report.field_migrations}
        self.assertEqual(moved.get(0x18), 0x20)
        self.assertEqual(moved.get(0x10), 0x10)

    def test_32bit_dll(self):
        v1 = pe_with_functions(bytes.fromhex("8b4110" "c3"), b"\xc3", bits=32, machine=0x14C)
        mig = M.StructShiftMigrator()
        funcs = mig._extract_binary_accesses(self._write(v1))
        self.assertEqual([(a.base_reg, a.displacement) for a in funcs["FuncA"]], [("ecx", 0x10)])


if __name__ == "__main__":
    unittest.main()
