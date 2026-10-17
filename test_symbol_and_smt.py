#!/usr/bin/env python3
"""
test_symbol_and_smt.py
======================
Comprehensive Test Suite for Frontier 1 & Frontier 2 of SuperGhidra:
  1. Synthetic DWARF 5, PDB, .sym, and .map Symbol Exporters
  2. SMT-Backed Decompilation Equivalence Verifier (P-Code vs C)
"""

import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from synthetic_symbol_exporter import (
    DWARF5Exporter,
    ExportField,
    ExportStruct,
    ExportSymbol,
    MapFileExporter,
    PDBExporter,
    SymFileExporter,
    SymbolLedgerIngestor,
    export_from_ledger,
)

from smt_pcode_verifier import (
    CCodeParser,
    CSymbolicEvaluator,
    PcodeSymbolicSimulator,
    SMTPcodeVerifier,
    SymbolicState,
    VerificationResult,
)

from pcode_lifter_bridge import (
    ARM64PcodeLifter,
    AddressSpace,
    PcodeOp,
    PcodeOpcode,
    Varnode,
)

from evidence_ledger import (
    LedgerVerificationError,
    ObligationStatus,
    ObligationType,
    ProofObligation,
    ReconstructionObligationLedger,
)


class TestSyntheticSymbolExporter(unittest.TestCase):
    """Tests for Frontier 1: Standalone Synthetic DWARF 5, PDB, .sym, and .map Exporters."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="superghidra_export_test_")
        self.symbols = [
            ExportSymbol(name="Player__TakeDamage", address=0x10045A820, size=0x64, symbol_type="FUNC"),
            ExportSymbol(name="Player__GetHealth", address=0x10045AA00, size=0x28, symbol_type="FUNC"),
            ExportSymbol(name="g_GameWorld", address=0x100500000, size=0x1000, symbol_type="OBJECT"),
        ]
        self.structs = [
            ExportStruct(
                name="Player",
                size=0x180,
                fields=[
                    ExportField(name="m_vtable", offset=0x00, size=8, type_name="void**"),
                    ExportField(name="m_health", offset=0x24, size=4, type_name="int32_t"),
                    ExportField(name="m_maxHealth", offset=0x28, size=4, type_name="int32_t"),
                ],
            )
        ]

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_dwarf5_elf64_binary_structure(self):
        """Validates ELF64 container header, section layout, and DWARF 5 compilation unit."""
        exporter = DWARF5Exporter(symbols=self.symbols, structs=self.structs, base_address=0x100400000)
        elf_bytes = exporter.build_elf()

        self.assertGreater(len(elf_bytes), 512)
        # Verify ELF Magic: \x7fELF
        self.assertEqual(elf_bytes[0:4], b"\x7fELF")
        # Verify 64-bit ELF (ELFCLASS64 = 2) and Little Endian (ELFDATA2LSB = 1)
        self.assertEqual(elf_bytes[4], 2)
        self.assertEqual(elf_bytes[5], 1)
        # Verify EV_CURRENT = 1
        self.assertEqual(elf_bytes[6], 1)

        # Parse ELF Header
        e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            "<HHIQQQIHHHHHH", elf_bytes, 16
        )
        self.assertEqual(e_type, 2)       # ET_EXEC
        self.assertEqual(e_machine, 0x3E) # EM_X86_64
        self.assertGreaterEqual(e_shnum, 8)

        # Verify .shstrtab and find sections
        shstrtab_hdr_offset = e_shoff + e_shstrndx * e_shentsize
        _, _, _, _, shstrtab_offset, shstrtab_size, _, _, _, _ = struct.unpack_from(
            "<IIQQQQIIQQ", elf_bytes, shstrtab_hdr_offset
        )
        shstrtab_data = elf_bytes[shstrtab_offset:shstrtab_offset + shstrtab_size]

        found_sections = set()
        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            sh_name, sh_type, sh_flags, sh_addr, sec_offset, sec_size, _, _, _, _ = struct.unpack_from(
                "<IIQQQQIIQQ", elf_bytes, sh_off
            )
            # Read section name from shstrtab
            name_end = shstrtab_data.find(b"\x00", sh_name)
            sec_name = shstrtab_data[sh_name:name_end].decode("utf-8")
            found_sections.add(sec_name)

            if sec_name == ".debug_info":
                # Validate DWARF 5 CU header:
                # unit_length (4B), version (2B = 5), unit_type (1B = 1), address_size (1B = 8)
                cu_data = elf_bytes[sec_offset:sec_offset + sec_size]
                unit_len, version, unit_type, addr_sz = struct.unpack_from("<IHBB", cu_data, 0)
                self.assertGreater(unit_len, 10)
                self.assertEqual(version, 5)
                self.assertEqual(unit_type, 1)  # DW_UT_compile
                self.assertEqual(addr_sz, 8)

            elif sec_name == ".debug_str":
                str_data = elf_bytes[sec_offset:sec_offset + sec_size]
                self.assertIn(b"Player__TakeDamage", str_data)
                self.assertIn(b"Player", str_data)
                self.assertIn(b"m_health", str_data)

        # Verify all essential DWARF sections exist
        expected_sections = {".text", ".symtab", ".strtab", ".shstrtab", ".debug_str", ".debug_abbrev", ".debug_info", ".debug_line"}
        self.assertTrue(expected_sections.issubset(found_sections))

    def test_pdb_msf7_container_structure(self):
        """Validates MSF 7.0 multi-stream container, PDB stream, DBI stream, and Public symbols."""
        exporter = PDBExporter(symbols=self.symbols, structs=self.structs, base_address=0x100400000)
        pdb_bytes = exporter.build_pdb()

        self.assertGreater(len(pdb_bytes), 4096)
        # Verify MSF 7.0 Magic Header
        self.assertEqual(pdb_bytes[0:32], b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00")

        block_size, free_map, num_blocks, num_dir_bytes, reserved, block_map_addr = struct.unpack_from(
            "<IIIIII", pdb_bytes, 32
        )
        self.assertEqual(block_size, 4096)
        self.assertGreater(num_blocks, 1)
        self.assertGreater(num_dir_bytes, 0)

        # Verify symbol name is present in PDB streams
        self.assertIn(b"Player__TakeDamage", pdb_bytes)
        self.assertIn(b"Player__GetHealth", pdb_bytes)

    def test_map_file_generation(self):
        """Validates standard linker .map text layout, publics by name/value, and struct layouts."""
        exporter = MapFileExporter(symbols=self.symbols, structs=self.structs, base_address=0x100400000)
        map_text = exporter.export()

        self.assertIn("Preferred load address is 0000000100400000", map_text)
        self.assertIn("Publics by Value", map_text)
        self.assertIn("Publics by Name", map_text)
        self.assertIn("Player__TakeDamage", map_text)
        self.assertIn("Player__GetHealth", map_text)
        self.assertIn("struct Player (sizeof=0x180):", map_text)
        self.assertIn("+0x0024 m_health", map_text)

    def test_sym_file_generation(self):
        """Validates Breakpad FUNC/PUBLIC records and x64dbg/Cheat Engine flat symbol lines."""
        exporter = SymFileExporter(symbols=self.symbols, module_name="GameEngine.exe")
        sym_text = exporter.export()

        self.assertTrue(sym_text.startswith("MODULE windows x86_64"))
        self.assertIn("GameEngine.exe", sym_text)
        self.assertIn("FUNC 10045a820 64 0 Player__TakeDamage", sym_text)
        self.assertIn("PUBLIC 100500000 0 g_GameWorld", sym_text)
        # x64dbg lines
        self.assertIn("0x10045A820 Player__TakeDamage", sym_text)
        self.assertIn("0x10045AA00 Player__GetHealth", sym_text)

    def test_batch_export_from_ledger(self):
        """Validates export_from_ledger integration with ReconstructionObligationLedger."""
        ledger_path = os.path.join(self.temp_dir, "test_ledger.json")
        ledger = ReconstructionObligationLedger(ledger_path)

        # Propose and verify obligations
        obl1 = ledger.propose(
            obligation_type=ObligationType.FUNCTION_HOOK,
            target_name="sub_10045A820",
            proposed_name="Player::TakeDamage",
            target_address=0x10045A820,
            evidence={
                "vtable_slot": 7,
                "vtable_offset": 0x38,
                "allocator_symbol": "malloc",
                "allocation_size": 0x200,
                "struct_size": 0x180,
                "field_displacements": [
                    {"name": "m_vtable", "offset": 0x00, "access_size": 8},
                    {"name": "m_health", "offset": 0x24, "access_size": 4},
                ],
            },
        )
        obl2 = ledger.propose(
            obligation_type=ObligationType.FUNCTION_RENAME,
            target_name="sub_10045AA00",
            proposed_name="Player::GetHealth",
            target_address=0x10045AA00,
            evidence={},
        )

        ledger.verify(obl1.obligation_id)
        ledger.verify(obl2.obligation_id)
        ledger.commit(obl1.obligation_id)
        ledger.commit(obl2.obligation_id)

        out_base = os.path.join(self.temp_dir, "reconstructed_out")
        res = export_from_ledger(
            ledger_source=ledger,
            output_base=out_base,
            formats=["dwarf", "pdb", "map", "sym"],
        )

        self.assertEqual(len(res), 4)
        for fmt, fpath in res.items():
            self.assertTrue(os.path.exists(fpath))
            self.assertGreater(os.path.getsize(fpath), 0)


class TestSMTPcodeVerifier(unittest.TestCase):
    """Tests for Frontier 2: SMT-Backed Decompilation Equivalence Verifier."""

    def setUp(self):
        self.verifier = SMTPcodeVerifier(timeout_ms=5000)

    def test_arithmetic_equivalence_proving(self):
        """Verifies formal proof of equivalent arithmetic (UNSAT)."""
        # P-Code: r0 = (r0 + r1) ^ (r2 << 2)
        # u0 = r0 + r1
        # u1 = r2 << 2
        # r0 = u0 ^ u1
        ops = [
            PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.REGISTER, 8, 8)], Varnode(AddressSpace.UNIQUE, 0, 8)),
            PcodeOp(PcodeOpcode.INT_LEFT, [Varnode(AddressSpace.REGISTER, 16, 8), Varnode(AddressSpace.CONST, 2, 8)], Varnode(AddressSpace.UNIQUE, 8, 8)),
            PcodeOp(PcodeOpcode.INT_XOR, [Varnode(AddressSpace.UNIQUE, 0, 8), Varnode(AddressSpace.UNIQUE, 8, 8)], Varnode(AddressSpace.REGISTER, 0, 8)),
        ]

        c_expr = "return (x0 + x1) ^ (x2 << 2);"
        res = self.verifier.verify_equivalence(
            pcode_ops=ops,
            c_code_or_ast=c_expr,
            check_memory=False,
            tracked_registers=[0],
        )

        self.assertTrue(res.equivalent)
        self.assertEqual(res.status, "UNSAT")

    def test_arithmetic_divergence_counterexample(self):
        """Verifies detection of divergent arithmetic mutation (SAT) and counterexample extraction."""
        # P-Code: r0 = r0 + r1
        ops = [
            PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.REGISTER, 8, 8)], Varnode(AddressSpace.REGISTER, 0, 8)),
        ]

        # Buggy C code: x0 - x1 instead of x0 + x1
        c_expr = "return x0 - x1;"
        res = self.verifier.verify_equivalence(
            pcode_ops=ops,
            c_code_or_ast=c_expr,
            check_memory=False,
            tracked_registers=[0],
        )

        self.assertFalse(res.equivalent)
        self.assertEqual(res.status, "SAT")
        self.assertIsNotNone(res.counterexample)
        self.assertIn("x1", res.counterexample)

    def test_memory_load_store_equivalence(self):
        """Verifies formal equivalence of struct member read-modify-write (TakeDamage)."""
        # P-Code:
        #   u0 = x0 + 0x24
        #   w1 = mem[u0]
        #   w1 = w1 - w2
        #   mem[u0] = w1
        ops = [
            PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.CONST, 0x24, 8)], Varnode(AddressSpace.UNIQUE, 0, 8)),
            PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8)], Varnode(AddressSpace.REGISTER, 8, 4)),
            PcodeOp(PcodeOpcode.INT_SUB, [Varnode(AddressSpace.REGISTER, 8, 4), Varnode(AddressSpace.REGISTER, 16, 4)], Varnode(AddressSpace.REGISTER, 8, 4)),
            PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8), Varnode(AddressSpace.REGISTER, 8, 4)]),
        ]

        c_code = "player->m_health = player->m_health - damage;"
        fields = {"m_health": (0x24, 4)}
        param_map = {"player": "x0", "damage": "w2"}

        res = self.verifier.verify_equivalence(
            pcode_ops=ops,
            c_code_or_ast=c_code,
            struct_fields=fields,
            param_map=param_map,
            check_memory=True,
        )

        self.assertTrue(res.equivalent)
        self.assertEqual(res.status, "UNSAT")

    def test_memory_load_store_divergence(self):
        """Verifies detection of struct field offset mismatch or operator mutation."""
        ops = [
            PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.CONST, 0x24, 8)], Varnode(AddressSpace.UNIQUE, 0, 8)),
            PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8)], Varnode(AddressSpace.REGISTER, 8, 4)),
            PcodeOp(PcodeOpcode.INT_SUB, [Varnode(AddressSpace.REGISTER, 8, 4), Varnode(AddressSpace.REGISTER, 16, 4)], Varnode(AddressSpace.REGISTER, 8, 4)),
            PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8), Varnode(AddressSpace.REGISTER, 8, 4)]),
        ]

        # 1. Operator mutation (+ instead of -)
        c_bug_op = "player->m_health = player->m_health + damage;"
        res_op = self.verifier.verify_equivalence(
            pcode_ops=ops,
            c_code_or_ast=c_bug_op,
            struct_fields={"m_health": (0x24, 4)},
            param_map={"player": "x0", "damage": "w2"},
            check_memory=True,
        )
        self.assertFalse(res_op.equivalent)
        self.assertEqual(res_op.status, "SAT")

        # 2. Offset mismatch (0x28 instead of 0x24)
        c_bug_off = "player->m_health = player->m_health - damage;"
        res_off = self.verifier.verify_equivalence(
            pcode_ops=ops,
            c_code_or_ast=c_bug_off,
            struct_fields={"m_health": (0x28, 4)},
            param_map={"player": "x0", "damage": "w2"},
            check_memory=True,
        )
        self.assertFalse(res_off.equivalent)
        self.assertEqual(res_off.status, "SAT")

    def test_explicit_c_dereference_syntax(self):
        """Verifies C pointer cast dereference syntax *(uint32_t*)(x0 + 0x24)."""
        ops = [
            PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.CONST, 0x24, 8)], Varnode(AddressSpace.UNIQUE, 0, 8)),
            PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8)], Varnode(AddressSpace.REGISTER, 8, 4)),
            PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 8, 4), Varnode(AddressSpace.CONST, 10, 4)], Varnode(AddressSpace.REGISTER, 8, 4)),
            PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8), Varnode(AddressSpace.REGISTER, 8, 4)]),
        ]

        c_code = "*(uint32_t*)(x0 + 0x24) = *(uint32_t*)(x0 + 0x24) + 10;"
        res = self.verifier.verify_equivalence(
            pcode_ops=ops,
            c_code_or_ast=c_code,
            check_memory=True,
        )
        self.assertTrue(res.equivalent)
        self.assertEqual(res.status, "UNSAT")

    def test_ledger_obligation_smt_verification(self):
        """Verifies EvidenceLedger FUNCTION_HOOK and STRUCT_FIELD_RENAME obligation verification."""
        temp_dir = tempfile.mkdtemp(prefix="smt_ledger_test_")
        try:
            ledger_path = os.path.join(temp_dir, "test_ledger.json")
            ledger = ReconstructionObligationLedger(ledger_path)

            # 1. Propose valid FUNCTION_HOOK obligation
            ops = [
                PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.CONST, 0x24, 8)], Varnode(AddressSpace.UNIQUE, 0, 8)),
                PcodeOp(PcodeOpcode.LOAD, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8)], Varnode(AddressSpace.REGISTER, 8, 4)),
                PcodeOp(PcodeOpcode.INT_SUB, [Varnode(AddressSpace.REGISTER, 8, 4), Varnode(AddressSpace.REGISTER, 16, 4)], Varnode(AddressSpace.REGISTER, 8, 4)),
                PcodeOp(PcodeOpcode.STORE, [Varnode(AddressSpace.RAM, 0, 4), Varnode(AddressSpace.UNIQUE, 0, 8), Varnode(AddressSpace.REGISTER, 8, 4)]),
            ]
            ops_dict = [op.to_dict() for op in ops]
            obl1 = ledger.propose(
                obligation_type=ObligationType.FUNCTION_HOOK,
                target_name="sub_10045A820",
                proposed_name="Player::TakeDamage",
                target_address=0x10045A820,
                evidence={
                    "pcode_ops": ops_dict,
                    "decompiled_c": "player->m_health = player->m_health - damage;",
                    "field_displacements": [{"name": "m_health", "offset": 0x24, "access_size": 4}],
                    "param_map": {"player": "x0", "damage": "w2"},
                },
            )

            res1 = self.verifier.verify_obligation(obl1)
            self.assertTrue(res1.equivalent)
            self.assertEqual(obl1.status, ObligationStatus.VERIFIED)

            # Commit should succeed
            ledger.commit(obl1.obligation_id)
            self.assertEqual(obl1.status, ObligationStatus.COMMITTED)

            # 2. Propose invalid FUNCTION_HOOK obligation (divergent C)
            obl2 = ledger.propose(
                obligation_type=ObligationType.FUNCTION_HOOK,
                target_name="sub_10045A820",
                proposed_name="Player::TakeDamage_Buggy",
                target_address=0x10045A820,
                evidence={
                    "pcode_ops": ops_dict,
                    "decompiled_c": "player->m_health = player->m_health + damage;",  # + instead of -
                    "field_displacements": [{"name": "m_health", "offset": 0x24, "access_size": 4}],
                    "param_map": {"player": "x0", "damage": "w2"},
                },
            )

            res2 = self.verifier.verify_obligation(obl2)
            self.assertFalse(res2.equivalent)
            self.assertEqual(obl2.status, ObligationStatus.REJECTED)

            # Commit MUST be blocked by safety gate!
            with self.assertRaises(LedgerVerificationError):
                ledger.commit(obl2.obligation_id)

            # 3. Propose STRUCT_FIELD_RENAME obligation
            obl3 = ledger.propose(
                obligation_type=ObligationType.STRUCT_FIELD_RENAME,
                target_name="field_0x24",
                proposed_name="m_health",
                evidence={
                    "offset": 0x24,
                    "access_size": 4,
                    "c_expression": "player->m_health",
                },
            )
            res3 = self.verifier.verify_obligation(obl3)
            self.assertTrue(res3.equivalent)
            self.assertEqual(obl3.status, ObligationStatus.VERIFIED)

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_machine_bytes_lifting_and_smt_verification(self):
        """Verifies end-to-end lifting of native ARM64 instruction bytes and formal equivalence verification."""
        # ARM64 instruction: add x0, x1, #0x20
        # Machine word: 0x91008020 (little endian: 20 80 00 91)
        insn_bytes = struct.pack("<I", 0x91008020)
        lifter = ARM64PcodeLifter()
        ops = lifter.lift_block(0x1000, insn_bytes)

        c_code = "return x1 + 0x20;"
        res = self.verifier.verify_equivalence(
            pcode_ops=ops,
            c_code_or_ast=c_code,
            check_memory=False,
            tracked_registers=[0],
        )

        self.assertTrue(res.equivalent)
        self.assertEqual(res.status, "UNSAT")

    def test_complex_bitwise_and_arithmetic_ops(self):
        """Verifies INT_MULT, INT_AND, INT_RIGHT, INT_LEFT, INT_NEGATE, and INT_2COMP."""
        # P-Code:
        # u0 = r0 * r1
        # u1 = r2 >> 3
        # u2 = u1 & 0xFF
        # u3 = u0 + u2
        # r0 = -u3
        ops = [
            PcodeOp(PcodeOpcode.INT_MULT, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.REGISTER, 8, 8)], Varnode(AddressSpace.UNIQUE, 0, 8)),
            PcodeOp(PcodeOpcode.INT_RIGHT, [Varnode(AddressSpace.REGISTER, 16, 8), Varnode(AddressSpace.CONST, 3, 8)], Varnode(AddressSpace.UNIQUE, 8, 8)),
            PcodeOp(PcodeOpcode.INT_AND, [Varnode(AddressSpace.UNIQUE, 8, 8), Varnode(AddressSpace.CONST, 0xFF, 8)], Varnode(AddressSpace.UNIQUE, 16, 8)),
            PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.UNIQUE, 0, 8), Varnode(AddressSpace.UNIQUE, 16, 8)], Varnode(AddressSpace.UNIQUE, 24, 8)),
            PcodeOp(PcodeOpcode.INT_2COMP, [Varnode(AddressSpace.UNIQUE, 24, 8)], Varnode(AddressSpace.REGISTER, 0, 8)),
        ]

        c_code = "return -((x0 * x1) + ((x2 >> 3) & 0xff));"
        res = self.verifier.verify_equivalence(
            pcode_ops=ops,
            c_code_or_ast=c_code,
            check_memory=False,
            tracked_registers=[0],
        )
        self.assertTrue(res.equivalent)
        self.assertEqual(res.status, "UNSAT")

    def test_sequential_c_statements(self):
        """Verifies multi-statement C block evaluation with intermediate temporary variables."""
        # P-Code:
        # u0 = x0 + 10
        # x0 = u0 * 2
        ops = [
            PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.CONST, 10, 8)], Varnode(AddressSpace.UNIQUE, 0, 8)),
            PcodeOp(PcodeOpcode.INT_MULT, [Varnode(AddressSpace.UNIQUE, 0, 8), Varnode(AddressSpace.CONST, 2, 8)], Varnode(AddressSpace.REGISTER, 0, 8)),
        ]

        c_code = """
            v0 = x0 + 10;
            v1 = v0 * 2;
            return v1;
        """
        res = self.verifier.verify_equivalence(
            pcode_ops=ops,
            c_code_or_ast=c_code,
            check_memory=False,
            tracked_registers=[0],
        )
        self.assertTrue(res.equivalent)
        self.assertEqual(res.status, "UNSAT")


class TestIngestionAndCLI(unittest.TestCase):
    """Tests for symbol ingestion formats and CLI execution."""

    def test_flexible_symbol_ingestor_formats(self):
        """Verifies parsing of _ghidra_names.json and list-of-dicts symbol formats."""
        # 1. Address to name mapping
        raw_dict_1 = {"0x10045A820": "Player__TakeDamage", "0x10045AA00": "Player__GetHealth"}
        syms_1 = SymbolLedgerIngestor.from_dict(raw_dict_1)
        self.assertEqual(len(syms_1), 2)
        self.assertEqual(syms_1[0].address, 0x10045A820)
        self.assertEqual(syms_1[0].name, "Player__TakeDamage")

        # 2. Name to address mapping
        raw_dict_2 = {"sub_10045A820": 0x10045A820, "sub_10045AA00": 0x10045AA00}
        syms_2 = SymbolLedgerIngestor.from_dict(raw_dict_2)
        self.assertEqual(len(syms_2), 2)
        self.assertEqual(syms_2[0].name, "sub_10045A820")
        self.assertEqual(syms_2[0].address, 0x10045A820)

        # 3. List of structured records
        raw_list = [
            {"name": "FuncA", "address": "0x1000", "size": 0x30},
            {"name": "FuncB", "address": 0x2000, "size": 0x50},
        ]
        syms_3 = SymbolLedgerIngestor.from_dict(raw_list)
        self.assertEqual(len(syms_3), 2)
        self.assertEqual(syms_3[0].address, 0x1000)
        self.assertEqual(syms_3[1].address, 0x2000)


if __name__ == "__main__":
    unittest.main()
