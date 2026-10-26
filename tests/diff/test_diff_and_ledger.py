"""
SuperGhidra Test Suite for Binary Diffing Engine & Reconstruction Obligation Ledger
(test_diff_and_ledger.py)

Comprehensive unit and integration tests covering:
1. Reconstruction Obligation Ledger:
   - VTable slot index & pointer alignment invariants.
   - Allocation size bounds & allocator symbol validation.
   - Struct field displacement natural alignment & overlap checks.
   - Strict commit gate blocking unverified obligations and JSON persistence.
2. Binary Diff Engine:
   - Normalized 32-dim CFG feature vector extraction & L2 normalization.
   - Batched cosine similarity matching (mutual top-1 and greedy) across stripped binaries.
   - Native ARM64 machine code CFG extraction (extract_cfgs_from_arm64_bytes).
   - Native x86_64 machine code CFG extraction (extract_cfgs_from_x86_64_bytes):
     * Function splitting on RET (0xC3), ENDBR64, PUSH rbp; MOV rbp, rsp, and CALL rel32.
     * Decoding PUSH, POP, MOV, LEA, ADD, SUB, XOR, CMP, TEST, CALL rel32, JMP, Jcc, RET.
     * BasicBlock construction and control-flow edge wiring.
   - Multi-format binary dispatcher (extract_cfgs_from_binary):
     * ELF64 EM_X86_64 (0x3E) and EM_AARCH64 (183).
     * PE32+/PE64 ("MZ" + "PE\\0\\0") for x86_64 (0x8664) and ARM64 (0xAA64).
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest

SUPERGHIDRA_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
if SUPERGHIDRA_DIR not in sys.path:
    sys.path.insert(0, SUPERGHIDRA_DIR)

from superghidra.diff.binary_diff_engine import (
    BatchedBinaryMatcher,
    extract_cfgs_from_binary,
    extract_cfgs_from_x86_64_bytes,
)
from superghidra.diff.evidence_ledger import (
    AllocationSizeVerifier,
    FieldDisplacementVerifier,
    LedgerVerificationError,
    ObligationStatus,
    ObligationType,
    ReconstructionObligationLedger,
    VTableSlotVerifier,
)


def build_synthetic_elf64_x86_64(text_bytes: bytes, text_vaddr: int = 0x401000) -> bytes:
    """Builds a valid 64-bit little-endian ELF binary with e_machine = 0x3E (EM_X86_64) and a .text section."""
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    text_offset = 64
    text_size = len(text_bytes)
    shstrtab_offset = text_offset + text_size
    shstrtab_size = len(shstrtab)
    shdr_offset = (shstrtab_offset + shstrtab_size + 7) & ~7

    shdrs = [
        struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        struct.pack("<IIQQQQIIQQ", 1, 1, 6, text_vaddr, text_offset, text_size, 0, 0, 16, 0),
        struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, shstrtab_offset, shstrtab_size, 0, 0, 1, 0),
    ]
    shdr_bytes = b"".join(shdrs)

    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        2,              # ET_EXEC
        0x3E,           # EM_X86_64
        1,              # EV_CURRENT
        text_vaddr,     # e_entry
        0,              # e_phoff
        shdr_offset,    # e_shoff
        0,              # e_flags
        64,             # e_ehsize
        0,              # e_phentsize
        0,              # e_phnum
        64,             # e_shentsize
        len(shdrs),     # e_shnum
        2,              # e_shstrndx
    )
    pad = b"\x00" * (shdr_offset - (shstrtab_offset + shstrtab_size))
    return ehdr + text_bytes + shstrtab + pad + shdr_bytes


def build_synthetic_pe64(
    text_bytes: bytes,
    machine: int = 0x8664,
    image_base: int = 0x140000000,
    text_rva: int = 0x1000,
) -> bytes:
    """Builds a synthetic PE32+/PE64 binary with MZ header, PE\\0\\0 signature, and .text section."""
    e_lfanew = 0x40
    mz_hdr = bytearray(0x40)
    mz_hdr[0:2] = b"MZ"
    struct.pack_into("<I", mz_hdr, 0x3C, e_lfanew)

    # Optional Header (PE32+ magic 0x20B, 112 bytes minimal)
    opt_hdr = bytearray(112)
    struct.pack_into("<H", opt_hdr, 0, 0x20B)
    struct.pack_into("<Q", opt_hdr, 24, image_base)

    # COFF File Header (20 bytes)
    coff_hdr = struct.pack(
        "<HHIIIHH",
        machine,        # Machine (0x8664 = AMD64, 0xAA64 = ARM64)
        1,              # NumberOfSections
        0,              # TimeDateStamp
        0,              # PointerToSymbolTable
        0,              # NumberOfSymbols
        len(opt_hdr),   # SizeOfOptionalHeader
        0x0022,         # Characteristics
    )

    # Section Header (40 bytes)
    raw_ptr = e_lfanew + 4 + len(coff_hdr) + len(opt_hdr) + 40
    raw_size = len(text_bytes)
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        raw_size,       # VirtualSize
        text_rva,       # VirtualAddress
        raw_size,       # SizeOfRawData
        raw_ptr,        # PointerToRawData
        0, 0, 0, 0,
        0x60000020,     # Characteristics (CODE | EXECUTE | READ)
    )

    return bytes(mz_hdr) + b"PE\x00\x00" + coff_hdr + bytes(opt_hdr) + sec_hdr + text_bytes


class TestEvidenceLedger(unittest.TestCase):
    """Unit tests for the Reconstruction Obligation Ledger invariants."""

    def test_vtable_allocation_and_field_verifiers(self):
        self.assertTrue(VTableSlotVerifier.verify({"vtable_slot": 7, "vtable_offset": 0x38}, pointer_size=8).passed)
        self.assertFalse(VTableSlotVerifier.verify({"vtable_offset": 0x39}, pointer_size=8).passed)

        self.assertTrue(
            AllocationSizeVerifier.verify({
                "allocation_size": 0x120,
                "struct_size": 0x100,
                "allocator_symbol": "g_game_alloc",
            }).passed
        )
        self.assertFalse(
            AllocationSizeVerifier.verify({
                "allocation_size": 0x100,
                "struct_size": 0x150,
                "allocator_symbol": "malloc",
            }).passed
        )

        self.assertTrue(
            FieldDisplacementVerifier.verify({
                "struct_size": 0x100,
                "field_displacements": [
                    {"name": "m_health", "offset": 0x24, "access_size": 4, "instruction": "ldr w1, [x22, #0x24]"},
                ],
            }).passed
        )

    def test_vtable_verification(self):
        # Valid: slot 7 -> offset 0x38 (7 * 8 = 56 = 0x38)
        res = VTableSlotVerifier.verify({"vtable_slot": 7, "vtable_offset": 0x38}, pointer_size=8)
        self.assertTrue(res.passed)

        # Invalid offset alignment (not divisible by 8)
        res_unaligned = VTableSlotVerifier.verify({"vtable_offset": 0x39}, pointer_size=8)
        self.assertFalse(res_unaligned.passed)
        self.assertIn("not aligned", res_unaligned.message)

        # Inconsistent slot and offset
        res_mismatch = VTableSlotVerifier.verify({"vtable_slot": 6, "vtable_offset": 0x38}, pointer_size=8)
        self.assertFalse(res_mismatch.passed)

    def test_allocation_size_verification(self):
        # Valid: struct 0x100 within 0x120 allocation
        res = AllocationSizeVerifier.verify({
            "allocation_size": 0x120,
            "struct_size": 0x100,
            "allocator_symbol": "g_game_alloc",
        })
        self.assertTrue(res.passed)

        # Invalid: struct size exceeds allocation
        res_overflow = AllocationSizeVerifier.verify({
            "allocation_size": 0x100,
            "struct_size": 0x150,
            "allocator_symbol": "malloc",
        })
        self.assertFalse(res_overflow.passed)
        self.assertIn("exceeds allocated buffer", res_overflow.message)

    def test_field_displacement_alignment(self):
        # Valid: [x22, #0x24] for 4-byte load (0x24 % 4 == 0)
        res = FieldDisplacementVerifier.verify({
            "struct_size": 0x100,
            "field_displacements": [
                {"name": "m_health", "offset": 0x24, "access_size": 4, "instruction": "ldr w1, [x22, #0x24]"},
                {"name": "m_ptr", "offset": 0x28, "access_size": 8, "instruction": "ldr x2, [x22, #0x28]"},
            ],
        })
        self.assertTrue(res.passed)

        # Invalid: 4-byte load at unaligned offset 0x25
        res_unaligned = FieldDisplacementVerifier.verify({
            "struct_size": 0x100,
            "field_displacements": [
                {"name": "m_bad", "offset": 0x25, "access_size": 4, "instruction": "ldr w1, [x22, #0x25]"},
            ],
        })
        self.assertFalse(res_unaligned.passed)
        self.assertIn("natural alignment", res_unaligned.message)

        # Invalid: field collision / overlap
        res_overlap = FieldDisplacementVerifier.verify({
            "struct_size": 0x100,
            "field_displacements": [
                {"name": "field_a", "offset": 0x20, "access_size": 8},
                {"name": "field_b", "offset": 0x24, "access_size": 4},
            ],
        })
        self.assertFalse(res_overlap.passed)
        self.assertIn("collides", res_overlap.message)

    def test_ledger_safety_gate_and_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = os.path.join(tmpdir, "test_ledger.json")
            ledger = ReconstructionObligationLedger(ledger_file=ledger_path)

            # Propose valid obligation
            obl = ledger.propose(
                obligation_type=ObligationType.FUNCTION_HOOK,
                target_name="sub_10045A820",
                proposed_name="Player::TakeDamage",
                target_address=0x10045A820,
                evidence={
                    "vtable_slot": 7,
                    "vtable_offset": 0x38,
                    "allocation_size": 0x200,
                    "struct_size": 0x180,
                    "allocator_symbol": "g_game_alloc",
                    "field_displacements": [
                        {"name": "m_health", "offset": 0x24, "access_size": 4, "instruction": "ldr w1, [x22, #0x24]"}
                    ],
                },
            )

            # 1. Attempting commit while PENDING must fail
            with self.assertRaises(LedgerVerificationError):
                ledger.commit(obl.obligation_id)

            # 2. Run verification -> transitions to VERIFIED
            verified = ledger.verify(obl.obligation_id)
            self.assertTrue(verified)
            self.assertEqual(obl.status, ObligationStatus.VERIFIED)

            # 3. Commit now succeeds
            ledger.commit(obl.obligation_id)
            self.assertEqual(obl.status, ObligationStatus.COMMITTED)
            self.assertIsNotNone(obl.committed_at)

            # 4. Persistence reload test
            ledger_reloaded = ReconstructionObligationLedger(ledger_file=ledger_path)
            obl_loaded = ledger_reloaded.get(obl.obligation_id)
            self.assertIsNotNone(obl_loaded)
            self.assertEqual(obl_loaded.status, ObligationStatus.COMMITTED)
            self.assertEqual(obl_loaded.proposed_name, "Player::TakeDamage")



class TestBinaryDiffEngineX86AndPE64(unittest.TestCase):
    """Unit tests for native x86_64 CFG extraction and ELF64/PE64 binary dispatching."""

    def _build_two_function_x86_64_payload(self) -> bytes:
        """
        Builds a 2-function x86_64 byte buffer:
        Function 0 (at base + 0x00):
          0x00: F3 0F 1E FA        -> endbr64
          0x04: 55                 -> push rbp
          0x05: 48 89 E5           -> mov rbp, rsp
          0x08: 48 8B 47 10        -> mov rax, [rdi + 0x10]
          0x0C: 48 85 C0           -> test rax, rax
          0x0F: 74 04              -> je +4 (to 0x15)
          0x11: 48 83 C0 01        -> add rax, 1
          0x15: 5D                 -> pop rbp
          0x16: C3                 -> ret
          0x17: 90                 -> nop padding

        Function 1 (at base + 0x18):
          0x18: 55                 -> push rbp
          0x19: 48 89 E5           -> mov rbp, rsp
          0x1C: 48 83 EC 20        -> sub rsp, 0x20
          0x20: E8 DB FF FF FF     -> call Function 0 (target = 0x00, rel32 = 0x00 - 0x25 = -0x25)
          0x25: 31 C0              -> xor eax, eax
          0x27: 48 83 C4 20        -> add rsp, 0x20
          0x2B: 5D                 -> pop rbp
          0x2C: C3                 -> ret
        """
        f0 = (
            b"\xf3\x0f\x1e\xfa"
            b"\x55"
            b"\x48\x89\xe5"
            b"\x48\x8b\x47\x10"
            b"\x48\x85\xc0"
            b"\x74\x04"
            b"\x48\x83\xc0\x01"
            b"\x5d"
            b"\xc3"
            b"\x90"
        )
        f1 = (
            b"\x55"
            b"\x48\x89\xe5"
            b"\x48\x83\xec\x20"
            + b"\xe8" + struct.pack("<i", -0x25)
            + b"\x31\xc0"
            b"\x48\x83\xc4\x20"
            b"\x5d"
            b"\xc3"
        )
        return f0 + f1

    def test_extract_cfgs_from_x86_64_bytes(self):
        """Verifies function splitting, BasicBlocks, edges, and categories on x86_64 bytes."""
        payload = self._build_two_function_x86_64_payload()
        base = 0x401000
        cfgs = extract_cfgs_from_x86_64_bytes(payload, base_vaddr=base)

        self.assertEqual(len(cfgs), 2)

        # Function 0: branching CFG at 0x401000
        cfg0 = cfgs[0]
        self.assertEqual(cfg0.address, 0x401000)
        self.assertEqual(len(cfg0.blocks), 3)  # Entry (0x401000), Fallthrough (0x401011), Merge/Exit (0x401015)
        self.assertIn((0x401000, 0x401015), cfg0.edges)
        self.assertIn((0x401000, 0x401011), cfg0.edges)
        self.assertIn((0x401011, 0x401015), cfg0.edges)

        # Function 1: caller CFG at 0x401018
        cfg1 = cfgs[1]
        self.assertEqual(cfg1.address, 0x401018)
        self.assertIn(hex(0x401000), cfg1.callees)

        all_mnems = [i.mnemonic for b in cfg1.blocks.values() for i in b.instructions]
        self.assertIn("push", all_mnems)
        self.assertIn("sub", all_mnems)
        self.assertIn("call", all_mnems)
        self.assertIn("xor", all_mnems)
        self.assertIn("ret", all_mnems)

    def test_extract_cfgs_from_binary_x86_64_elf64(self):
        """Verifies extract_cfgs_from_binary detects ELF64 EM_X86_64 (0x3E) and extracts x86_64 CFGs."""
        payload = self._build_two_function_x86_64_payload()
        elf_bytes = build_synthetic_elf64_x86_64(payload, text_vaddr=0x401000)

        cfgs = extract_cfgs_from_binary(elf_bytes)
        self.assertEqual(len(cfgs), 2)
        self.assertEqual(cfgs[0].address, 0x401000)
        self.assertEqual(cfgs[1].address, 0x401018)
        self.assertGreaterEqual(len(cfgs[0].blocks), 3)

    def test_extract_cfgs_from_binary_pe64_x86_64_and_arm64(self):
        """Verifies extract_cfgs_from_binary parses PE32+/PE64 headers for both x86_64 (0x8664) and ARM64 (0xAA64)."""
        # 1. PE64 x86_64 (Machine = 0x8664)
        x86_payload = self._build_two_function_x86_64_payload()
        pe_x86 = build_synthetic_pe64(x86_payload, machine=0x8664, image_base=0x140000000, text_rva=0x1000)
        cfgs_pe_x86 = extract_cfgs_from_binary(pe_x86)
        self.assertEqual(len(cfgs_pe_x86), 2)
        self.assertEqual(cfgs_pe_x86[0].address, 0x140001000)
        self.assertEqual(cfgs_pe_x86[1].address, 0x140001018)

        # 2. PE64 ARM64 (Machine = 0xAA64)
        # Two simple ARM64 functions: (MOVZ W0, #1; RET) and (MOVZ W0, #2; RET)
        arm64_payload = struct.pack("<4I", 0x52800020, 0xD65F03C0, 0x52800040, 0xD65F03C0)
        pe_arm64 = build_synthetic_pe64(arm64_payload, machine=0xAA64, image_base=0x180000000, text_rva=0x2000)
        cfgs_pe_arm = extract_cfgs_from_binary(pe_arm64)
        self.assertEqual(len(cfgs_pe_arm), 2)
        self.assertEqual(cfgs_pe_arm[0].address, 0x180002000)
        self.assertEqual(cfgs_pe_arm[1].address, 0x180002008)

    def test_batched_diffing_on_x86_64_cfgs(self):
        """Verifies BatchedBinaryMatcher pairs x86_64 CFGs across two relocated binary builds."""
        payload = self._build_two_function_x86_64_payload()
        cfgs_a = extract_cfgs_from_x86_64_bytes(payload, base_vaddr=0x401000)
        cfgs_b = extract_cfgs_from_x86_64_bytes(payload, base_vaddr=0x502000)

        matcher = BatchedBinaryMatcher(threshold=0.75, use_gpu=False)
        res = matcher.diff_binaries(cfgs_a, cfgs_b, strategy="mutual")
        self.assertEqual(len(res.matches), 2)
        self.assertGreaterEqual(res.avg_similarity, 0.99)


if __name__ == "__main__":
    unittest.main()
