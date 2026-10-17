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
import z3

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
    CIntrinsic,
    CSymbolicEvaluator,
    PcodeSymbolicSimulator,
    SMTPcodeVerifier,
    SymbolicState,
    VerificationResult,
)

from pcode_lifter_bridge import (
    ARM64PcodeLifter,
    AddressSpace,
    FLAG_C_OFFSET,
    FLAG_N_OFFSET,
    FLAG_V_OFFSET,
    FLAG_Z_OFFSET,
    PcodeOp,
    PcodeOpcode,
    Varnode,
    X86_64PcodeLifter,
)

from evidence_ledger import (
    LedgerVerificationError,
    ObligationStatus,
    ObligationType,
    ProofObligation,
    ReconstructionObligationLedger,
)

from dwarf_pdb_preindexer import (
    OffHeapTypeStore,
    StructMember,
    TypeDeduplicator,
    TypeKind,
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
        self.assertEqual(e_machine, 183)  # EM_AARCH64 (default)
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
            evidence={
                "vtable_slot": 8,
                "vtable_offset": 0x40,
            },
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

    def test_dwarf5_base_type_die_and_member_type_references(self):
        """Validates DW_TAG_base_type (Abbrev 5) DIE emission and DW_AT_type (DW_FORM_ref4) member references."""
        structs = [
            ExportStruct(
                name="Actor",
                size=0x40,
                fields=[
                    ExportField(name="m_id", offset=0x00, size=8, type_name="uint64_t"),
                    ExportField(name="m_scale", offset=0x08, size=4, type_name="float"),
                    ExportField(name="m_flags", offset=0x0C, size=4, type_name="uint32_t"),
                ],
            )
        ]
        exporter = DWARF5Exporter(symbols=self.symbols, structs=structs, base_address=0x100400000)
        elf_bytes = exporter.build_elf()

        self.assertGreater(len(elf_bytes), 512)
        # Parse into TypeDeduplicator to verify DIE tree validity and resolved member types
        dedup = TypeDeduplicator()
        stats = dedup.ingest_dwarf5_elf_bytes(elf_bytes)

        self.assertGreaterEqual(stats["structs"], 1)
        self.assertGreaterEqual(stats["members"], 3)
        self.assertIn("Actor", dedup.alias_map)

        actor_tid = dedup.alias_map["Actor"]
        actor_type = dedup.canonical_types[actor_tid]
        self.assertEqual(actor_type.name, "Actor")
        self.assertEqual(len(actor_type.members), 3)

        # Verify member types are resolved to the base type names rather than raw offsets
        m_id = next(m for m in actor_type.members if m.name == "m_id")
        m_scale = next(m for m in actor_type.members if m.name == "m_scale")
        m_flags = next(m for m in actor_type.members if m.name == "m_flags")

        self.assertEqual(m_id.size, 8)
        self.assertEqual(m_scale.size, 4)
        self.assertEqual(m_flags.size, 4)

        # Check resolved types in canonical store
        m_id_type = dedup.canonical_types.get(m_id.type_id)
        self.assertIsNotNone(m_id_type)
        self.assertEqual(m_id_type.name, "uint64_t")

        m_scale_type = dedup.canonical_types.get(m_scale.type_id)
        self.assertIsNotNone(m_scale_type)
        self.assertEqual(m_scale_type.name, "float")

        m_flags_type = dedup.canonical_types.get(m_flags.type_id)
        self.assertIsNotNone(m_flags_type)
        self.assertEqual(m_flags_type.name, "uint32_t")

    def test_pdb_tpi_stream_fieldlist_and_structure_records(self):
        """Validates CodeView LF_FIELDLIST (0x1203), LF_MEMBER (0x150D), and LF_STRUCTURE (0x1505) in PDB TPI."""
        exporter = PDBExporter(symbols=self.symbols, structs=self.structs, base_address=0x100400000)
        pdb_bytes = exporter.build_pdb()

        self.assertGreater(len(pdb_bytes), 4096)
        # Verify MSF header
        self.assertEqual(pdb_bytes[0:32], b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00")

        # Verify CodeView leaves are present in TPI stream
        self.assertIn(b"\x03\x12", pdb_bytes)  # LF_FIELDLIST (0x1203)
        self.assertIn(b"\x05\x15", pdb_bytes)  # LF_STRUCTURE (0x1505)
        self.assertIn(b"\x0D\x15", pdb_bytes)  # LF_MEMBER (0x150D)

        # Verify struct and member names embedded in TPI
        self.assertIn(b"Player", pdb_bytes)
        self.assertIn(b"m_vtable", pdb_bytes)
        self.assertIn(b"m_health", pdb_bytes)
        self.assertIn(b"m_maxHealth", pdb_bytes)

    def test_dwarf5_binary_roundtrip_preindexer(self):
        """End-to-end binary roundtrip from DWARF5Exporter into OffHeapTypeStore with layout queries."""
        exporter = DWARF5Exporter(symbols=self.symbols, structs=self.structs, base_address=0x100400000)
        elf_bytes = exporter.build_elf()

        store = OffHeapTypeStore(":memory:")
        stats = store.ingest_dwarf5_elf(elf_bytes)

        self.assertEqual(stats["structs"], 1)
        self.assertEqual(stats["members"], 3)
        self.assertGreaterEqual(stats["symbols"], 2)

        # Query struct layout
        layout = store.get_struct_layout("Player")
        self.assertEqual(len(layout), 3)
        self.assertEqual(layout[0]["name"], "m_vtable")
        self.assertEqual(layout[0]["offset"], 0)
        self.assertEqual(layout[1]["name"], "m_health")
        self.assertEqual(layout[1]["offset"], 0x24)
        self.assertEqual(layout[2]["name"], "m_maxHealth")
        self.assertEqual(layout[2]["offset"], 0x28)

        # Lookup symbols
        s_damage = store.lookup_symbol_by_address(0x10045A820)
        self.assertIsNotNone(s_damage)
        self.assertEqual(s_damage.name, "Player__TakeDamage")

        s_health = store.lookup_symbol_by_address(0x10045AA00)
        self.assertIsNotNone(s_health)
        self.assertEqual(s_health.name, "Player__GetHealth")

        # Render C declaration
        c_decl = store.render_c_declaration("Player")
        self.assertIn("struct Player", c_decl)
        self.assertIn("m_health", c_decl)
        self.assertIn("m_maxHealth", c_decl)

        store.close()


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

            # 3. Propose STRUCT_FIELD_RENAME obligation with real machine bytes
            insn_ldr_field = struct.pack("<I", 0xB9402401)  # ldr w1, [x0, #0x24]
            obl3 = ledger.propose(
                obligation_type=ObligationType.STRUCT_FIELD_RENAME,
                target_name="field_0x24",
                proposed_name="m_health",
                evidence={
                    "offset": 0x24,
                    "access_size": 4,
                    "c_expression": "player->m_health",
                    "machine_bytes": insn_ldr_field.hex(),
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


class TestARM64ExtendedLifterAndSMT(unittest.TestCase):
    """Tests for Upgraded ARM64 P-Code Lifter and Extended SMT Equivalence Verification."""

    def setUp(self):
        self.lifter = ARM64PcodeLifter()
        self.verifier = SMTPcodeVerifier(timeout_ms=5000)

    def test_xzr_vs_sp_semantics_and_z3_equivalence(self):
        """Validates register 31 differentiation (XZR/WZR const vs SP register) and SMT proof."""
        # 1. Helper semantics
        vn_xzr = self.lifter._gpr_varnode(31, 8, allow_sp=False)
        self.assertEqual(vn_xzr.space, AddressSpace.CONST)
        self.assertEqual(vn_xzr.offset, 0)

        vn_sp = self.lifter._gpr_varnode(31, 8, allow_sp=True)
        self.assertEqual(vn_sp.space, AddressSpace.REGISTER)
        self.assertEqual(vn_sp.offset, 31 * 8)

        vn_discard = self.lifter._gpr_varnode(31, 8, allow_sp=False, is_dest=True)
        self.assertEqual(vn_discard.space, AddressSpace.UNIQUE)

        # 2. CMP X0, X1 (SUBS XZR, X0, X1): destination is unique discard varnode, not SP
        # Encoding: sf=1, op=1, s=1, shift=0, rm=1, imm6=0, rn=0, rd=31
        insn_cmp = (1 << 31) | (1 << 30) | (1 << 29) | 0x0B000000 | (1 << 16) | (0 << 5) | 31
        cmp_ops = self.lifter.lift_instruction(0x1000, insn_cmp)
        self.assertEqual(len(cmp_ops), 1)
        self.assertEqual(cmp_ops[0].output.space, AddressSpace.UNIQUE)

        # 3. ADD X0, X1, XZR: operand 2 is const 0
        # Encoding: sf=1, op=0, s=0, shift=0, rm=31, imm6=0, rn=1, rd=0
        insn_add_xzr = (1 << 31) | 0x0B000000 | (31 << 16) | (1 << 5) | 0
        add_xzr_ops = self.lifter.lift_instruction(0x1000, insn_add_xzr)
        self.assertEqual(add_xzr_ops[0].inputs[1].space, AddressSpace.CONST)
        self.assertEqual(add_xzr_ops[0].inputs[1].offset, 0)

        res = self.verifier.verify_equivalence(add_xzr_ops, "return x1;", check_memory=False)
        self.assertTrue(res.equivalent)
        self.assertEqual(res.status, "UNSAT")

    def test_mov_movk_movn_lifting_and_smt_equivalence(self):
        """Validates MOVN, MOV alias (ORR Xd, XZR, Xm), and MOVK lane insertion."""
        # 1. MOVN x0, #0x1234, LSL #0
        insn_movn = (1 << 31) | 0x12800000 | (0x1234 << 5) | 0
        movn_ops = self.lifter.lift_instruction(0x1000, insn_movn)
        self.assertEqual(len(movn_ops), 1)
        self.assertEqual(movn_ops[0].opcode, PcodeOpcode.COPY)

        res_movn = self.verifier.verify_equivalence(movn_ops, "return ~0x1234;", check_memory=False)
        self.assertTrue(res_movn.equivalent)
        self.assertEqual(res_movn.status, "UNSAT")

        # 2. MOV x0, x1 via ORR x0, xzr, x1 (special fast-path COPY)
        insn_mov = (1 << 31) | (1 << 29) | 0x0A000000 | (1 << 16) | (31 << 5) | 0
        mov_ops = self.lifter.lift_instruction(0x1000, insn_mov)
        self.assertEqual(len(mov_ops), 1)
        self.assertEqual(mov_ops[0].opcode, PcodeOpcode.COPY)
        self.assertEqual(mov_ops[0].inputs[0].space, AddressSpace.REGISTER)
        self.assertEqual(mov_ops[0].inputs[0].offset, 8)  # x1

        res_mov = self.verifier.verify_equivalence(mov_ops, "return x1;", check_memory=False)
        self.assertTrue(res_mov.equivalent)
        self.assertEqual(res_mov.status, "UNSAT")

        # 3. MOVZ x0, #0x1234 followed by MOVK x0, #0x5678, LSL #16
        insn_movz = (1 << 31) | 0x52800000 | (0x1234 << 5) | 0
        insn_movk = (1 << 31) | 0x72800000 | (1 << 21) | (0x5678 << 5) | 0
        block_bytes = struct.pack("<2I", insn_movz, insn_movk)
        ops = self.lifter.lift_block(0x1000, block_bytes)

        res_movk = self.verifier.verify_equivalence(ops, "return 0x56781234;", check_memory=False)
        self.assertTrue(res_movk.equivalent)
        self.assertEqual(res_movk.status, "UNSAT")

    def test_logical_shifted_register_ops(self):
        """Validates AND, EOR, and ORR with shifted registers."""
        # 1. AND x0, x1, x2, LSL #3
        insn_and = (1 << 31) | 0x0A000000 | (2 << 16) | (3 << 10) | (1 << 5) | 0
        ops_and = self.lifter.lift_instruction(0x1000, insn_and)
        res_and = self.verifier.verify_equivalence(ops_and, "return x1 & (x2 << 3);", check_memory=False)
        self.assertTrue(res_and.equivalent)
        self.assertEqual(res_and.status, "UNSAT")

        # 2. EOR x0, x1, x2, LSR #2
        insn_eor = (1 << 31) | (2 << 29) | (1 << 22) | 0x0A000000 | (2 << 16) | (2 << 10) | (1 << 5) | 0
        ops_eor = self.lifter.lift_instruction(0x1000, insn_eor)
        res_eor = self.verifier.verify_equivalence(ops_eor, "return x1 ^ (x2 >> 2);", check_memory=False)
        self.assertTrue(res_eor.equivalent)
        self.assertEqual(res_eor.status, "UNSAT")

    def test_add_sub_shifted_register_ops(self):
        """Validates ADD and SUB with shifted registers."""
        # 1. ADD x0, x1, x2, LSL #4
        insn_add = (1 << 31) | 0x0B000000 | (2 << 16) | (4 << 10) | (1 << 5) | 0
        ops_add = self.lifter.lift_instruction(0x1000, insn_add)
        res_add = self.verifier.verify_equivalence(ops_add, "return x1 + (x2 << 4);", check_memory=False)
        self.assertTrue(res_add.equivalent)
        self.assertEqual(res_add.status, "UNSAT")

        # 2. SUB x0, x1, x2, LSR #1
        insn_sub = (1 << 31) | (1 << 30) | (1 << 22) | 0x0B000000 | (2 << 16) | (1 << 10) | (1 << 5) | 0
        ops_sub = self.lifter.lift_instruction(0x1000, insn_sub)
        res_sub = self.verifier.verify_equivalence(ops_sub, "return x1 - (x2 >> 1);", check_memory=False)
        self.assertTrue(res_sub.equivalent)
        self.assertEqual(res_sub.status, "UNSAT")

    def test_bitfield_and_shift_immediate_ops(self):
        """Validates UBFM (LSL, LSR, UXTB, UXTH) and SBFM (ASR)."""
        # 1. UBFM as LSL x0, x1, #5 (immr = 59, imms = 58)
        insn_lsl = (1 << 31) | 0x53000000 | (59 << 16) | (58 << 10) | (1 << 5) | 0
        ops_lsl = self.lifter.lift_instruction(0x1000, insn_lsl)
        res_lsl = self.verifier.verify_equivalence(ops_lsl, "return x1 << 5;", check_memory=False)
        self.assertTrue(res_lsl.equivalent)
        self.assertEqual(res_lsl.status, "UNSAT")

        # 2. UBFM as LSR x0, x1, #3 (immr = 3, imms = 63)
        insn_lsr = (1 << 31) | 0x53000000 | (3 << 16) | (63 << 10) | (1 << 5) | 0
        ops_lsr = self.lifter.lift_instruction(0x1000, insn_lsr)
        res_lsr = self.verifier.verify_equivalence(ops_lsr, "return x1 >> 3;", check_memory=False)
        self.assertTrue(res_lsr.equivalent)
        self.assertEqual(res_lsr.status, "UNSAT")

        # 3. UBFM as UXTB w0, w1 (sf=0, immr=0, imms=7)
        insn_uxtb = 0x53000000 | (0 << 16) | (7 << 10) | (1 << 5) | 0
        ops_uxtb = self.lifter.lift_instruction(0x1000, insn_uxtb)
        res_uxtb = self.verifier.verify_equivalence(ops_uxtb, "return w1 & 0xFF;", check_memory=False)
        self.assertTrue(res_uxtb.equivalent)
        self.assertEqual(res_uxtb.status, "UNSAT")

        # 4. SBFM as ASR x0, x1, #4 (immr=4, imms=63)
        insn_asr = (1 << 31) | 0x13000000 | (4 << 16) | (63 << 10) | (1 << 5) | 0
        ops_asr = self.lifter.lift_instruction(0x1000, insn_asr)
        res_asr = self.verifier.verify_equivalence(ops_asr, "return (int64_t)x1 >> 4;", check_memory=False)
        self.assertTrue(res_asr.equivalent)
        self.assertEqual(res_asr.status, "UNSAT")

    def test_mul_madd_msub_3source_ops(self):
        """Validates MUL (ra=31), MADD, and MSUB."""
        # 1. MUL x0, x1, x2 (ra == 31, o0 == 0)
        insn_mul = (1 << 31) | 0x1B000000 | (2 << 16) | (31 << 10) | (1 << 5) | 0
        ops_mul = self.lifter.lift_instruction(0x1000, insn_mul)
        self.assertEqual(len(ops_mul), 1)
        self.assertEqual(ops_mul[0].opcode, PcodeOpcode.INT_MULT)

        res_mul = self.verifier.verify_equivalence(ops_mul, "return x1 * x2;", check_memory=False)
        self.assertTrue(res_mul.equivalent)
        self.assertEqual(res_mul.status, "UNSAT")

        # 2. MADD x0, x1, x2, x3: x3 + (x1 * x2)
        insn_madd = (1 << 31) | 0x1B000000 | (2 << 16) | (3 << 10) | (1 << 5) | 0
        ops_madd = self.lifter.lift_instruction(0x1000, insn_madd)
        res_madd = self.verifier.verify_equivalence(ops_madd, "return x3 + (x1 * x2);", check_memory=False)
        self.assertTrue(res_madd.equivalent)
        self.assertEqual(res_madd.status, "UNSAT")

        # 3. MSUB x0, x1, x2, x3: x3 - (x1 * x2)
        insn_msub = (1 << 31) | 0x1B000000 | (2 << 16) | (1 << 15) | (3 << 10) | (1 << 5) | 0
        ops_msub = self.lifter.lift_instruction(0x1000, insn_msub)
        res_msub = self.verifier.verify_equivalence(ops_msub, "return x3 - (x1 * x2);", check_memory=False)
        self.assertTrue(res_msub.equivalent)
        self.assertEqual(res_msub.status, "UNSAT")

    def test_load_store_pair_ldp_stp(self):
        """Validates LDP and STP pair memory operations with separate varnodes."""
        # STP x1, x2, [x0, #16]: writes x1 to x0+16 and x2 to x0+24
        insn_stp = (2 << 30) | 0x28000000 | (2 << 15) | (2 << 10) | (0 << 5) | 1
        ops_stp = self.lifter.lift_instruction(0x1000, insn_stp)
        self.assertEqual(len(ops_stp), 4)

        c_stp = "*(uint64_t*)(x0 + 16) = x1; *(uint64_t*)(x0 + 24) = x2;"
        res_stp = self.verifier.verify_equivalence(ops_stp, c_stp, check_memory=True)
        self.assertTrue(res_stp.equivalent)
        self.assertEqual(res_stp.status, "UNSAT")

    def test_unscaled_load_store_ldur_stur(self):
        """Validates unscaled immediate LDUR and STUR with negative displacements."""
        # STUR x1, [x0, #-8]
        insn_stur = (3 << 30) | 0x38000000 | ((-8 & 0x1FF) << 12) | (0 << 5) | 1
        ops_stur = self.lifter.lift_instruction(0x1000, insn_stur)

        c_stur = "*(uint64_t*)(x0 - 8) = x1;"
        res_stur = self.verifier.verify_equivalence(ops_stur, c_stur, check_memory=True)
        self.assertTrue(res_stur.equivalent)
        self.assertEqual(res_stur.status, "UNSAT")

    def test_cbz_cbnz_and_diamond_branch_equivalence(self):
        """Validates CBZ, CBNZ lifting and diamond conditional execution equivalence against C ternary."""
        # 1. CBZ lifting
        insn_cbz = (1 << 31) | 0x34000000 | (2 << 5) | 1
        ops_cbz = self.lifter.lift_instruction(0x1000, insn_cbz)
        self.assertEqual(ops_cbz[0].opcode, PcodeOpcode.INT_EQUAL)
        self.assertEqual(ops_cbz[1].opcode, PcodeOpcode.CBRANCH)

        # 2. CBNZ lifting
        insn_cbnz = (1 << 31) | (1 << 24) | 0x34000000 | (2 << 5) | 1
        ops_cbnz = self.lifter.lift_instruction(0x1000, insn_cbnz)
        self.assertEqual(ops_cbnz[0].opcode, PcodeOpcode.INT_NOTEQUAL)
        self.assertEqual(ops_cbnz[1].opcode, PcodeOpcode.CBRANCH)

        # 3. Diamond basic block:
        # 0x1000: CBZ x1, 0x100C  (jump if x1 == 0)
        # 0x1004: MOVZ x0, 10
        # 0x1008: B 0x1010
        # 0x100C: MOVZ x0, 20
        # 0x1010: RET
        insn_cbz_diamond = (1 << 31) | 0x34000000 | (3 << 5) | 1
        insn_mov10 = (1 << 31) | 0x52800000 | (10 << 5) | 0
        insn_b = 0x14000000 | 2
        insn_mov20 = (1 << 31) | 0x52800000 | (20 << 5) | 0
        insn_ret = 0xD65F03C0

        block = struct.pack("<5I", insn_cbz_diamond, insn_mov10, insn_b, insn_mov20, insn_ret)
        ops_diamond = self.lifter.lift_block(0x1000, block)

        c_ternary = "return (x1 == 0) ? 20 : 10;"
        res_diamond = self.verifier.verify_equivalence(ops_diamond, c_ternary, check_memory=False)
        self.assertTrue(res_diamond.equivalent)
        self.assertEqual(res_diamond.status, "UNSAT")

    def test_c_ternary_parser_and_evaluator(self):
        """Validates C ternary expressions in both C syntax and Python ast.IfExp format."""
        parser = CCodeParser()
        c_code = "return (x0 > 5) ? (x1 + 10) : (x2 - 10);"
        ast_block = parser.parse(c_code)
        self.assertEqual(len(ast_block.statements), 1)

        evaluator = CSymbolicEvaluator()
        st = SymbolicState()
        st.get_register(0, 8)
        st.get_register(8, 8)
        st.get_register(16, 8)
        evaluator.execute_block(st, ast_block)
        self.assertIsNotNone(st.return_val)

    def test_arm64_adr_lifting(self):
        """Validates ADR instruction lifting and target PC computation."""
        # ADR x0, #16 at pc=0x1000 -> target = 0x1010
        # ADR encoding: immlo at [30:29], immhi at [23:5]
        imm21_pos = 16
        immlo_pos = imm21_pos & 3
        immhi_pos = (imm21_pos >> 2) & 0x7FFFF
        insn_adr = 0x10000000 | (immlo_pos << 29) | (immhi_pos << 5) | 0
        ops_adr = self.lifter.lift_instruction(0x1000, insn_adr)
        self.assertEqual(len(ops_adr), 1)
        self.assertEqual(ops_adr[0].opcode, PcodeOpcode.COPY)
        self.assertEqual(ops_adr[0].inputs[0].offset, 0x1010)
        self.assertEqual(ops_adr[0].output.offset, 0)
        self.assertEqual(ops_adr[0].output.size, 8)

        # ADR x1, #-8 at pc=0x1000 -> target = 0x0FF8
        imm21_neg = -8
        immlo_neg = imm21_neg & 3
        immhi_neg = (imm21_neg >> 2) & 0x7FFFF
        insn_adr_neg = 0x10000000 | (immlo_neg << 29) | (immhi_neg << 5) | 1
        ops_adr_neg = self.lifter.lift_instruction(0x1000, insn_adr_neg)
        self.assertEqual(ops_adr_neg[0].inputs[0].offset, 0x0FF8)
        self.assertEqual(ops_adr_neg[0].output.offset, 8)

    def test_arm64_tbz_tbnz_lifting(self):
        """Validates TBZ and TBNZ lifting across 32-bit and 64-bit registers."""
        # 1. TBZ x0, #5, #0x10 at pc=0x1000 (target 0x1010)
        insn_tbz64 = 0x36280080
        ops_tbz64 = self.lifter.lift_instruction(0x1000, insn_tbz64)
        self.assertEqual(len(ops_tbz64), 3)
        self.assertEqual(ops_tbz64[0].opcode, PcodeOpcode.INT_AND)
        self.assertEqual(ops_tbz64[0].inputs[1].offset, 1 << 5)
        self.assertEqual(ops_tbz64[1].opcode, PcodeOpcode.INT_EQUAL)
        self.assertEqual(ops_tbz64[2].opcode, PcodeOpcode.CBRANCH)
        self.assertEqual(ops_tbz64[2].inputs[0].offset, 0x1010)

        # 2. TBNZ x0, #40, #0x10 at pc=0x1000 (target 0x1010)
        insn_tbnz64 = 0xb7400080
        ops_tbnz64 = self.lifter.lift_instruction(0x1000, insn_tbnz64)
        self.assertEqual(len(ops_tbnz64), 3)
        self.assertEqual(ops_tbnz64[0].opcode, PcodeOpcode.INT_AND)
        self.assertEqual(ops_tbnz64[0].inputs[1].offset, 1 << 40)
        self.assertEqual(ops_tbnz64[1].opcode, PcodeOpcode.INT_NOTEQUAL)
        self.assertEqual(ops_tbnz64[2].opcode, PcodeOpcode.CBRANCH)

        # 3. TBZ w0, #3, #0x10 at pc=0x1000
        insn_tbz32 = 0x36180080
        ops_tbz32 = self.lifter.lift_instruction(0x1000, insn_tbz32)
        self.assertEqual(ops_tbz32[0].inputs[0].size, 4)
        self.assertEqual(ops_tbz32[1].opcode, PcodeOpcode.INT_EQUAL)

        # 4. TBNZ w0, #31, #0x10 at pc=0x1000
        insn_tbnz32 = 0x37f80080
        ops_tbnz32 = self.lifter.lift_instruction(0x1000, insn_tbnz32)
        self.assertEqual(ops_tbnz32[0].inputs[0].size, 4)
        self.assertEqual(ops_tbnz32[1].opcode, PcodeOpcode.INT_NOTEQUAL)

    def test_arm64_cmp_and_csel_symbolic_equivalence(self):
        """Validates SMT equivalence of CMP paired with CSEL, CSINC, CSINV, and CSNEG."""
        # 1. CMP x1, x2 + CSEL x0, x3, x4, eq: (x1 == x2) ? x3 : x4
        insn_cmp = 0xeb02003f  # cmp x1, x2 (subs xzr, x1, x2)
        insn_csel = (1 << 31) | 0x1a800000 | (4 << 16) | (0 << 12) | (3 << 5) | 0
        ops_csel = self.lifter.lift_instruction(0x1000, insn_cmp) + self.lifter.lift_instruction(0x1004, insn_csel)
        c_csel = "return (x1 == x2) ? x3 : x4;"
        res_csel = self.verifier.verify_equivalence(ops_csel, c_csel, check_memory=False)
        self.assertTrue(res_csel.equivalent)
        self.assertEqual(res_csel.status, "UNSAT")

        # 2. CMP x1, #10 + CSINC x0, x3, x4, ne: (x1 != 10) ? x3 : (x4 + 1)
        insn_cmp_imm = (1 << 31) | (1 << 29) | 0x51000000 | (10 << 10) | (1 << 5) | 31
        insn_csinc = (1 << 31) | 0x1a800000 | (4 << 16) | (1 << 12) | (1 << 10) | (3 << 5) | 0
        ops_csinc = self.lifter.lift_instruction(0x1000, insn_cmp_imm) + self.lifter.lift_instruction(0x1004, insn_csinc)
        c_csinc = "return (x1 != 10) ? x3 : (x4 + 1);"
        res_csinc = self.verifier.verify_equivalence(ops_csinc, c_csinc, check_memory=False)
        self.assertTrue(res_csinc.equivalent)
        self.assertEqual(res_csinc.status, "UNSAT")

        # 3. CMP x1, x2 + CSINV x0, x3, x4, lt: (x1 < x2) ? x3 : ~x4
        insn_csinv = (1 << 31) | (1 << 30) | 0x1a800000 | (4 << 16) | (0xB << 12) | (3 << 5) | 0
        ops_csinv = self.lifter.lift_instruction(0x1000, insn_cmp) + self.lifter.lift_instruction(0x1004, insn_csinv)
        c_csinv = "return (x1 < x2) ? x3 : ~x4;"
        res_csinv = self.verifier.verify_equivalence(ops_csinv, c_csinv, check_memory=False)
        self.assertTrue(res_csinv.equivalent)
        self.assertEqual(res_csinv.status, "UNSAT")

        # 4. CMP x1, x2 + CSNEG x0, x3, x4, gt: (x1 > x2) ? x3 : -x4
        insn_csneg = (1 << 31) | (1 << 30) | 0x1a800000 | (4 << 16) | (0xC << 12) | (1 << 10) | (3 << 5) | 0
        ops_csneg = self.lifter.lift_instruction(0x1000, insn_cmp) + self.lifter.lift_instruction(0x1004, insn_csneg)
        c_csneg = "return (x1 > x2) ? x3 : -x4;"
        res_csneg = self.verifier.verify_equivalence(ops_csneg, c_csneg, check_memory=False)
        self.assertTrue(res_csneg.equivalent)
        self.assertEqual(res_csneg.status, "UNSAT")

    def test_arm64_cmp_and_bcond_if_else_equivalence(self):
        """Validates CMP + B.cond diamond branching equivalence against structured C if/else."""
        # 0x1000: CMP x1, #100
        # 0x1004: B.GE 0x1010
        # 0x1008: MOVZ x0, 1
        # 0x100C: B 0x1014
        # 0x1010: MOVZ x0, 2
        # 0x1014: RET
        insn_cmp = (1 << 31) | (1 << 29) | 0x51000000 | (100 << 10) | (1 << 5) | 31
        insn_bge = 0x54000000 | (3 << 5) | 0xA  # imm19=3 (0x1004 + 12 = 0x1010), cond=GE (0xA)
        insn_mov1 = (1 << 31) | 0x52800000 | (1 << 5) | 0
        insn_b = 0x14000000 | 2  # B 0x1014
        insn_mov2 = (1 << 31) | 0x52800000 | (2 << 5) | 0
        insn_ret = 0xD65F03C0

        block = struct.pack("<6I", insn_cmp, insn_bge, insn_mov1, insn_b, insn_mov2, insn_ret)
        ops_diamond = self.lifter.lift_block(0x1000, block)

        # 1. Structured block if/else
        c_structured = """
        if (x1 < 100) {
            return 1;
        } else {
            return 2;
        }
        """
        res_struct = self.verifier.verify_equivalence(ops_diamond, c_structured, check_memory=False)
        self.assertTrue(res_struct.equivalent)
        self.assertEqual(res_struct.status, "UNSAT")

        # 2. Single-statement if/else
        c_single = "if (x1 < 100) return 1; else return 2;"
        res_single = self.verifier.verify_equivalence(ops_diamond, c_single, check_memory=False)
        self.assertTrue(res_single.equivalent)
        self.assertEqual(res_single.status, "UNSAT")

    def test_arm64_div_and_extr_lifting(self):
        """Validates UDIV, SDIV, and EXTR/ROR operations."""
        # 1. SDIV x0, x1, x2
        insn_sdiv = 0x9ac20c20
        ops_sdiv = self.lifter.lift_instruction(0x1000, insn_sdiv)
        self.assertEqual(len(ops_sdiv), 1)
        self.assertEqual(ops_sdiv[0].opcode, PcodeOpcode.INT_SDIV)
        res_sdiv = self.verifier.verify_equivalence(ops_sdiv, "return x1 / x2;", check_memory=False)
        self.assertTrue(res_sdiv.equivalent)
        self.assertEqual(res_sdiv.status, "UNSAT")

        # 2. UDIV x0, x1, x2
        insn_udiv = 0x9ac20820
        ops_udiv = self.lifter.lift_instruction(0x1000, insn_udiv)
        self.assertEqual(len(ops_udiv), 1)
        self.assertEqual(ops_udiv[0].opcode, PcodeOpcode.INT_DIV)
        res_udiv = self.verifier.verify_equivalence(ops_udiv, "return (uint64_t)x1 / x2;", check_memory=False)
        self.assertTrue(res_udiv.equivalent)
        self.assertEqual(res_udiv.status, "UNSAT")

        # 3. EXTR x0, x1, x2, #8
        insn_extr64 = (1 << 31) | 0x13800000 | (1 << 22) | (2 << 16) | (8 << 10) | (1 << 5) | 0
        ops_extr64 = self.lifter.lift_instruction(0x1000, insn_extr64)
        self.assertEqual(len(ops_extr64), 3)
        self.assertEqual(ops_extr64[0].opcode, PcodeOpcode.INT_RIGHT)
        self.assertEqual(ops_extr64[1].opcode, PcodeOpcode.INT_LEFT)
        self.assertEqual(ops_extr64[2].opcode, PcodeOpcode.INT_OR)

        # 4. EXTR w0, w1, w1, #4 (ROR w0, w1, #4)
        insn_ror32 = 0x13800000 | (1 << 16) | (4 << 10) | (1 << 5) | 0
        ops_ror32 = self.lifter.lift_instruction(0x1000, insn_ror32)
        self.assertEqual(len(ops_ror32), 3)
        self.assertEqual(ops_ror32[0].inputs[1].offset, 4)
        self.assertEqual(ops_ror32[1].inputs[1].offset, 28)

    def test_arm64_pre_post_index_and_ldrsw(self):
        """Validates Pre-index, Post-index loads/stores and sign-extended loads (LDRSW/LDRSH/LDRSB)."""
        # 1. LDR x0, [x1, #16]! (pre-indexed)
        insn_pre_ldr = 0xf8410c20
        ops_pre_ldr = self.lifter.lift_instruction(0x1000, insn_pre_ldr)
        self.assertTrue(any(op.opcode == PcodeOpcode.INT_ADD for op in ops_pre_ldr))
        self.assertTrue(any(op.opcode == PcodeOpcode.LOAD for op in ops_pre_ldr))
        self.assertEqual(ops_pre_ldr[-1].opcode, PcodeOpcode.LOAD)
        self.assertEqual(ops_pre_ldr[-1].output.offset, 0)

        # 2. LDR x0, [x1], #16 (post-indexed)
        insn_post_ldr = 0xf8410420
        ops_post_ldr = self.lifter.lift_instruction(0x1000, insn_post_ldr)
        self.assertEqual(ops_post_ldr[0].opcode, PcodeOpcode.LOAD)
        self.assertEqual(ops_post_ldr[1].opcode, PcodeOpcode.INT_ADD)
        self.assertEqual(ops_post_ldr[1].output.offset, 8)

        # 3. STR x0, [x1, #16]! (pre-indexed store)
        insn_pre_str = 0xf8010c20
        ops_pre_str = self.lifter.lift_instruction(0x1000, insn_pre_str)
        self.assertEqual(ops_pre_str[-1].opcode, PcodeOpcode.STORE)

        # 4. STR x0, [x1], #16 (post-indexed store)
        insn_post_str = 0xf8010420
        ops_post_str = self.lifter.lift_instruction(0x1000, insn_post_str)
        self.assertEqual(ops_post_str[0].opcode, PcodeOpcode.STORE)
        self.assertEqual(ops_post_str[1].opcode, PcodeOpcode.INT_ADD)

        # 5. LDRSW x0, [x1, #8] (unsigned immediate sign-extended 32-bit load to 64-bit reg)
        insn_ldrsw = 0xb9800820
        ops_ldrsw = self.lifter.lift_instruction(0x1000, insn_ldrsw)
        self.assertTrue(any(op.opcode == PcodeOpcode.LOAD and op.output.size == 4 for op in ops_ldrsw))
        self.assertTrue(any(op.opcode == PcodeOpcode.INT_SEXT and op.output.size == 8 for op in ops_ldrsw))
        self.assertEqual(ops_ldrsw[-1].output.offset, 0)

        # 6. LDRSH x0, [x1, #4] (sign-extended 16-bit to 64-bit)
        insn_ldrsh = 0x79800420
        ops_ldrsh = self.lifter.lift_instruction(0x1000, insn_ldrsh)
        self.assertTrue(any(op.opcode == PcodeOpcode.LOAD and op.output.size == 2 for op in ops_ldrsh))
        self.assertTrue(any(op.opcode == PcodeOpcode.INT_SEXT and op.output.size == 8 for op in ops_ldrsh))

        # 7. LDRSB w0, [x1, #2] (sign-extended 8-bit to 32-bit)
        insn_ldrsb32 = 0x39c00420
        ops_ldrsb32 = self.lifter.lift_instruction(0x1000, insn_ldrsb32)
        self.assertTrue(any(op.opcode == PcodeOpcode.LOAD and op.output.size == 1 for op in ops_ldrsb32))
        self.assertTrue(any(op.opcode == PcodeOpcode.INT_SEXT and op.output.size == 4 for op in ops_ldrsb32))

    def test_c_structured_if_else_nested(self):
        """Validates nested and else-if C block parsing and symbolic state evaluation."""
        parser = CCodeParser()
        evaluator = CSymbolicEvaluator()

        # 1. Nested if/else
        c_code_nested = """
        if (x0 > 0) {
            if (x1 > 0) {
                return 10;
            } else {
                return 20;
            }
        } else {
            return 30;
        }
        """
        ast_nested = parser.parse(c_code_nested)
        self.assertEqual(len(ast_nested.statements), 1)

        st1 = SymbolicState()
        st1.get_register(0, 8)
        st1.get_register(8, 8)
        evaluator.execute_block(st1, ast_nested)
        self.assertIsNotNone(st1.return_val)

        # 2. Else-if chain
        c_code_elseif = """
        if (x0 == 1) {
            return 100;
        } else if (x0 == 2) {
            return 200;
        } else {
            return 300;
        }
        """
        ast_elseif = parser.parse(c_code_elseif)
        self.assertEqual(len(ast_elseif.statements), 1)

        st2 = SymbolicState()
        st2.get_register(0, 8)
        evaluator.execute_block(st2, ast_elseif)
        self.assertIsNotNone(st2.return_val)

    def test_arm64_bitfield_manipulation(self):
        """Validates UBFM (UBFX, UBFIZ), SBFM (SBFX, SBFIZ), and BFM (BFI, BFXIL)."""
        # 1. UBFX x0, x1, #8, #16 (extract 16 bits starting at bit 8)
        insn_ubfx = (1 << 31) | 0x53000000 | (1 << 22) | (8 << 16) | (23 << 10) | (1 << 5) | 0
        ops_ubfx = self.lifter.lift_instruction(0x1000, insn_ubfx)
        self.assertEqual(ops_ubfx[0].opcode, PcodeOpcode.INT_RIGHT)
        self.assertEqual(ops_ubfx[1].opcode, PcodeOpcode.INT_AND)
        self.assertEqual(ops_ubfx[1].inputs[1].offset, 0xFFFF)
        res_ubfx = self.verifier.verify_equivalence(ops_ubfx, "return (x1 >> 8) & 0xffff;", check_memory=False)
        self.assertTrue(res_ubfx.equivalent)

        # 2. UBFIZ x0, x1, #8, #16 (insert 16 bits at bit 8, zero-extended)
        insn_ubfiz = (1 << 31) | 0x53000000 | (1 << 22) | (56 << 16) | (15 << 10) | (1 << 5) | 0
        ops_ubfiz = self.lifter.lift_instruction(0x1000, insn_ubfiz)
        self.assertEqual(ops_ubfiz[0].opcode, PcodeOpcode.INT_AND)
        self.assertEqual(ops_ubfiz[0].inputs[1].offset, 0xFFFF)
        self.assertEqual(ops_ubfiz[1].opcode, PcodeOpcode.INT_LEFT)
        self.assertEqual(ops_ubfiz[1].inputs[1].offset, 8)
        res_ubfiz = self.verifier.verify_equivalence(ops_ubfiz, "return (x1 & 0xffff) << 8;", check_memory=False)
        self.assertTrue(res_ubfiz.equivalent)

        # 3. SBFX x0, x1, #8, #16 (signed extract 16 bits)
        insn_sbfx = (1 << 31) | 0x13000000 | (1 << 22) | (8 << 16) | (23 << 10) | (1 << 5) | 0
        ops_sbfx = self.lifter.lift_instruction(0x1000, insn_sbfx)
        self.assertEqual(ops_sbfx[0].opcode, PcodeOpcode.INT_LEFT)
        self.assertEqual(ops_sbfx[1].opcode, PcodeOpcode.INT_SRIGHT)

        # 4. SBFIZ x0, x1, #8, #16 (signed insert 16 bits at bit 8)
        insn_sbfiz = (1 << 31) | 0x13000000 | (1 << 22) | (56 << 16) | (15 << 10) | (1 << 5) | 0
        ops_sbfiz = self.lifter.lift_instruction(0x1000, insn_sbfiz)
        self.assertEqual(ops_sbfiz[0].opcode, PcodeOpcode.INT_LEFT)
        self.assertEqual(ops_sbfiz[1].opcode, PcodeOpcode.INT_SRIGHT)
        self.assertEqual(ops_sbfiz[2].opcode, PcodeOpcode.INT_LEFT)

        # 5. BFXIL x0, x1, #8, #16 (extract into Rd at bit 0 in-place)
        insn_bfxil = (1 << 31) | 0x33000000 | (1 << 22) | (8 << 16) | (23 << 10) | (1 << 5) | 0
        ops_bfxil = self.lifter.lift_instruction(0x1000, insn_bfxil)
        self.assertTrue(any(op.opcode == PcodeOpcode.INT_OR for op in ops_bfxil))
        self.assertEqual(ops_bfxil[-1].output.offset, 0)  # x0

        # 6. BFI x0, x1, #8, #16 (insert into Rd at bit 8 in-place)
        insn_bfi = (1 << 31) | 0x33000000 | (1 << 22) | (56 << 16) | (15 << 10) | (1 << 5) | 0
        ops_bfi = self.lifter.lift_instruction(0x1000, insn_bfi)
        self.assertTrue(any(op.opcode == PcodeOpcode.INT_OR for op in ops_bfi))
        self.assertEqual(ops_bfi[-1].output.offset, 0)  # x0

    def test_arm64_widening_and_high_multiply(self):
        """Validates SMADDL, SMULL, UMADDL, UMULL, SMULH, UMULH and SUBPIECE/PIECE execution."""
        # 1. SMULL x0, w1, w2 (0x9B227C20)
        insn_smull = 0x9B200000 | (2 << 16) | (31 << 10) | (1 << 5) | 0
        ops_smull = self.lifter.lift_instruction(0x1000, insn_smull)
        self.assertEqual(ops_smull[0].opcode, PcodeOpcode.INT_SEXT)
        self.assertEqual(ops_smull[1].opcode, PcodeOpcode.INT_SEXT)
        self.assertEqual(ops_smull[2].opcode, PcodeOpcode.INT_MULT)

        # 2. SMADDL x0, w1, w2, x3
        insn_smaddl = 0x9B200000 | (2 << 16) | (3 << 10) | (1 << 5) | 0
        ops_smaddl = self.lifter.lift_instruction(0x1000, insn_smaddl)
        self.assertEqual(ops_smaddl[-1].opcode, PcodeOpcode.INT_ADD)

        # 3. UMULL x0, w1, w2
        insn_umull = 0x9BA00000 | (2 << 16) | (31 << 10) | (1 << 5) | 0
        ops_umull = self.lifter.lift_instruction(0x1000, insn_umull)
        self.assertEqual(ops_umull[0].opcode, PcodeOpcode.INT_ZEXT)
        self.assertEqual(ops_umull[1].opcode, PcodeOpcode.INT_ZEXT)
        self.assertEqual(ops_umull[2].opcode, PcodeOpcode.INT_MULT)

        # 4. SMULH x0, x1, x2 (High 64-bit multiply signed)
        insn_smulh = 0x9B407C00 | (2 << 16) | (1 << 5) | 0
        ops_smulh = self.lifter.lift_instruction(0x1000, insn_smulh)
        self.assertTrue(any(op.opcode == PcodeOpcode.SUBPIECE for op in ops_smulh))
        self.assertEqual(ops_smulh[-1].output.offset, 0)

        # 5. UMULH x0, x1, x2 (High 64-bit multiply unsigned)
        insn_umulh = 0x9BC07C00 | (2 << 16) | (1 << 5) | 0
        ops_umulh = self.lifter.lift_instruction(0x1000, insn_umulh)
        self.assertTrue(any(op.opcode == PcodeOpcode.SUBPIECE for op in ops_umulh))

        # 6. Execute SUBPIECE & PIECE in PcodeSymbolicSimulator
        sim = PcodeSymbolicSimulator()
        st = SymbolicState()
        st.set_register(8, z3.BitVecVal(0x1122334455667788, 64))
        st.set_register(16, z3.BitVecVal(0xAABBCCDDEEFF0011, 64))

        # PIECE u0:16 = Concat(r16, r8)
        op_piece = PcodeOp(
            opcode=PcodeOpcode.PIECE,
            inputs=[Varnode(AddressSpace.REGISTER, 16, 8), Varnode(AddressSpace.REGISTER, 8, 8)],
            output=Varnode(AddressSpace.UNIQUE, 0, 16),
            pc=0x1000
        )
        sim.step(st, op_piece)
        u0_val = st.uniques[0]
        self.assertEqual(u0_val.size(), 128)

        # SUBPIECE r0 = u0:16, offset 8 (upper 64 bits)
        op_subpiece = PcodeOp(
            opcode=PcodeOpcode.SUBPIECE,
            inputs=[Varnode(AddressSpace.UNIQUE, 0, 16), Varnode(AddressSpace.CONST, 8, 4)],
            output=Varnode(AddressSpace.REGISTER, 0, 8),
            pc=0x1004
        )
        sim.step(st, op_subpiece)
        sol = z3.Solver()
        sol.add(st.get_register(0, 8) != z3.BitVecVal(0xAABBCCDDEEFF0011, 64))
        self.assertEqual(sol.check(), z3.unsat)

    def test_arm64_byte_reverse(self):
        """Validates REV (32/64-bit), REV16 (32/64-bit), and REV32."""
        # 1. REV w0, w1 (32-bit byte reverse)
        insn_rev32 = 0x5AC00800 | (1 << 5) | 0
        ops_rev32 = self.lifter.lift_instruction(0x1000, insn_rev32)
        sim = PcodeSymbolicSimulator()
        st32 = SymbolicState()
        st32.set_register(8, z3.BitVecVal(0x12345678, 32), size=4)
        sim.execute_block(st32, ops_rev32)
        sol = z3.Solver()
        sol.add(st32.get_register(0, 4) != z3.BitVecVal(0x78563412, 32))
        self.assertEqual(sol.check(), z3.unsat)

        # 2. REV x0, x1 (64-bit byte reverse)
        insn_rev64 = (1 << 31) | 0x5AC00C00 | (1 << 5) | 0
        ops_rev64 = self.lifter.lift_instruction(0x1000, insn_rev64)
        st64 = SymbolicState()
        st64.set_register(8, z3.BitVecVal(0x0123456789ABCDEF, 64), size=8)
        sim.execute_block(st64, ops_rev64)
        sol64 = z3.Solver()
        sol64.add(st64.get_register(0, 8) != z3.BitVecVal(0xEFCDAB8967452301, 64))
        self.assertEqual(sol64.check(), z3.unsat)

        # 3. REV16 w0, w1
        insn_rev16 = 0x5AC00400 | (1 << 5) | 0
        ops_rev16 = self.lifter.lift_instruction(0x1000, insn_rev16)
        st16 = SymbolicState()
        st16.set_register(8, z3.BitVecVal(0x12345678, 32), size=4)
        sim.execute_block(st16, ops_rev16)
        sol16 = z3.Solver()
        sol16.add(st16.get_register(0, 4) != z3.BitVecVal(0x34127856, 32))
        self.assertEqual(sol16.check(), z3.unsat)

        # 4. REV32 x0, x1
        insn_rev32_64 = (1 << 31) | 0x5AC00800 | (1 << 5) | 0
        ops_rev32_64 = self.lifter.lift_instruction(0x1000, insn_rev32_64)
        st32_64 = SymbolicState()
        st32_64.set_register(8, z3.BitVecVal(0x123456789ABCDEF0, 64), size=8)
        sim.execute_block(st32_64, ops_rev32_64)
        sol32_64 = z3.Solver()
        sol32_64.add(st32_64.get_register(0, 8) != z3.BitVecVal(0x78563412F0DEBC9A, 64))
        self.assertEqual(sol32_64.check(), z3.unsat)

    def test_arm64_conditional_compare_ccmp_ccmn(self):
        """Validates CCMP / CCMN short-circuit condition evaluation."""
        lifter = ARM64PcodeLifter()

        # 1. CMP x0, #10 (SUBS xzr, x0, #10)
        insn_cmp = (1 << 31) | (1 << 29) | 0x11000000 | (10 << 10) | (0 << 5) | 31
        ops_cmp = lifter.lift_instruction(0x1000, insn_cmp)

        # 2. CCMP x1, #20, #0, GT (0x3A400000 pattern)
        # sf=1, op=0, cond=12(GT), is_imm=1, imm5=20, rn=1, nzcv=0
        insn_ccmp = (1 << 31) | 0x3A400000 | (20 << 16) | (12 << 12) | (1 << 11) | (1 << 5) | 0
        ops_ccmp = lifter.lift_instruction(0x1004, insn_ccmp)

        # 3. B.GT 0x1020
        # cond = 12 (GT)
        insn_b_gt = 0x54000000 | (7 << 5) | 12
        ops_b = lifter.lift_instruction(0x1008, insn_b_gt)

        all_ops = ops_cmp + ops_ccmp + ops_b
        self.assertTrue(any(op.opcode == PcodeOpcode.CBRANCH for op in all_ops))

        # Simulate execution
        sim = PcodeSymbolicSimulator()
        st = SymbolicState()
        # Case A: x0 = 15 (> 10), x1 = 25 (> 20) -> should take branch
        st.set_register(0, z3.BitVecVal(15, 8))
        st.set_register(8, z3.BitVecVal(25, 8))
        sim.execute_block(st, all_ops)
        branch_cond = st.branches[-1][0]
        s = z3.Solver()
        s.add(z3.Not(branch_cond))
        self.assertEqual(s.check(), z3.unsat)

    def test_smt_loop_unrolling_and_c_parser_extensions(self):
        """Validates while, for, switch, compound assignment parsing, and bounded loop unrolling."""
        parser = CCodeParser()
        evaluator = CSymbolicEvaluator()

        # 1. While loop
        c_while = """
        int i = 0;
        int s = 0;
        while (i < 5) {
            s += i;
            i++;
        }
        return s;
        """
        ast_while = parser.parse(c_while)
        st_while = SymbolicState()
        evaluator.execute_block(st_while, ast_while)
        # 0 + 1 + 2 + 3 + 4 = 10
        sol = z3.Solver()
        sol.add(st_while.return_val != z3.BitVecVal(10, 64))
        self.assertEqual(sol.check(), z3.unsat)

        # 2. For loop
        c_for = """
        int s = 0;
        for (int i = 1; i <= 4; i++) {
            s *= 10;
            s += i;
        }
        return s;
        """
        ast_for = parser.parse(c_for)
        st_for = SymbolicState()
        evaluator.execute_block(st_for, ast_for)
        # 1, 12, 123, 1234
        sol_for = z3.Solver()
        sol_for.add(st_for.return_val != z3.BitVecVal(1234, 64))
        self.assertEqual(sol_for.check(), z3.unsat)

        # 3. Switch / Case statement
        c_switch = """
        int r = 0;
        switch (x0) {
            case 1:
                r = 100;
                break;
            case 2:
                r = 200;
                break;
            default:
                r = 300;
                break;
        }
        return r;
        """
        ast_switch = parser.parse(c_switch)
        st_sw = SymbolicState()
        st_sw.set_register(0, z3.BitVecVal(2, 8))
        evaluator.execute_block(st_sw, ast_switch)
        sol_sw = z3.Solver()
        sol_sw.add(st_sw.return_val != z3.BitVecVal(200, 64))
        self.assertEqual(sol_sw.check(), z3.unsat)

        # 4. Compound assignment operators
        c_ops = """
        int a = 10;
        a += 5;
        a -= 3;
        a *= 4;
        a <<= 1;
        a >>= 2;
        a &= 0xFF;
        a |= 0x1;
        a ^= 0x3;
        return a;
        """
        ast_ops = parser.parse(c_ops)
        st_ops = SymbolicState()
        evaluator.execute_block(st_ops, ast_ops)
        # 10 + 5 = 15; 15 - 3 = 12; 12 * 4 = 48; 48 << 1 = 96; 96 >> 2 = 24; 24 & 0xFF = 24; 24 | 1 = 25; 25 ^ 3 = 26
        sol_ops = z3.Solver()
        sol_ops.add(st_ops.return_val != z3.BitVecVal(26, 64))
        self.assertEqual(sol_ops.check(), z3.unsat)

        # 5. P-code simulator bounded backward branch loop unrolling
        # Loop: x0 = 0; loop: x0 = x0 + 1; CBRANCH loop, (x0 < 5); RETURN x0
        ops_loop = [
            PcodeOp(PcodeOpcode.COPY, [Varnode(AddressSpace.CONST, 0, 8)], Varnode(AddressSpace.REGISTER, 0, 8), pc=0x1000),
            # Loop body at 0x1004
            PcodeOp(PcodeOpcode.INT_ADD, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.CONST, 1, 8)], Varnode(AddressSpace.REGISTER, 0, 8), pc=0x1004),
            PcodeOp(PcodeOpcode.INT_LESS, [Varnode(AddressSpace.REGISTER, 0, 8), Varnode(AddressSpace.CONST, 5, 8)], Varnode(AddressSpace.UNIQUE, 0, 1), pc=0x1008),
            PcodeOp(PcodeOpcode.CBRANCH, [Varnode(AddressSpace.CONST, 0x1004, 8), Varnode(AddressSpace.UNIQUE, 0, 1)], pc=0x100C),
            # Exit at 0x1010
            PcodeOp(PcodeOpcode.RETURN, [Varnode(AddressSpace.REGISTER, 0, 8)], pc=0x1010),
        ]
        sim_loop = PcodeSymbolicSimulator(max_loop_unroll=16)
        st_pcode_loop = SymbolicState()
        sim_loop.execute_block(st_pcode_loop, ops_loop)
        sol_loop = z3.Solver()
        sol_loop.add(st_pcode_loop.return_val != z3.BitVecVal(5, 64))
        self.assertEqual(sol_loop.check(), z3.unsat)

    def test_arm64_fp_simd_lifting_and_smt_verification(self):
        """Verifies ARM64 scalar FP/NEON instruction lifting and Z3 SMT equivalence."""
        lifter = ARM64PcodeLifter()
        verifier = SMTPcodeVerifier()

        # FADD D0, D0, D1 (0x1E612800), FMUL D0, D0, D2 (0x1E620800), RET (0xD65F03C0)
        code = struct.pack("<III", 0x1E612800, 0x1E620800, 0xD65F03C0)
        ops = lifter.lift_block(0x4000, code)
        opcodes = [op.opcode for op in ops]
        self.assertIn(PcodeOpcode.FLOAT_ADD, opcodes)
        self.assertIn(PcodeOpcode.FLOAT_MULT, opcodes)

        res = verifier.verify_equivalence(
            ops,
            "return (d0 + d1) * d2;",
            check_memory=False,
            tracked_registers=[0x400],
        )
        # Soundness: bitvector SMT domain cannot soundly verify IEEE 754 float arithmetic
        self.assertFalse(res.equivalent)
        self.assertEqual(res.status, "UNKNOWN")

        # Test FCMP D0, D1 (0x1E612000), FCSEL D0, D2, D3, EQ (0x1E630C40), FABS D0, D0 (0x1E60C000)
        code_fcsel = struct.pack("<III", 0x1E612000, 0x1E630C40, 0x1E60C000)
        ops_fcsel = lifter.lift_block(0x4100, code_fcsel)
        fcsel_opcodes = [op.opcode for op in ops_fcsel]
        self.assertIn(PcodeOpcode.FLOAT_ABS, fcsel_opcodes)
        res_fcsel = verifier.verify_equivalence(
            ops_fcsel,
            "d0 = (d0 == d1) ? d2 : d3; d0 = FABS(d0);",
            check_memory=False,
            tracked_registers=[0x400],
        )
        self.assertFalse(res_fcsel.equivalent)
        self.assertEqual(res_fcsel.status, "UNKNOWN")

        # Test SCVTF D0, X0 (0x9E620000) and FCVTZS X1, D0 (0x9E780001) and FP LDR/STR
        # STR D0, [X2, #8] (0xFD000440), LDR D1, [X2, #8] (0xFD400441)
        code_conv = struct.pack("<IIII", 0x9E620000, 0x9E780001, 0xFD000440, 0xFD400441)
        ops_conv = lifter.lift_block(0x4200, code_conv)
        conv_opcodes = [op.opcode for op in ops_conv]
        self.assertIn(PcodeOpcode.FLOAT_INT2FLOAT, conv_opcodes)
        self.assertIn(PcodeOpcode.FLOAT_TRUNC, conv_opcodes)
        self.assertIn(PcodeOpcode.STORE, conv_opcodes)
        self.assertIn(PcodeOpcode.LOAD, conv_opcodes)

    def test_x86_64_pcode_lifter_and_smt_verification(self):
        """Verifies zero-JVM X86_64PcodeLifter decoding and Z3 SMT equivalence against C."""
        x86_lifter = X86_64PcodeLifter()
        verifier = SMTPcodeVerifier()

        # ENDBR64 (F3 0F 1E FA)
        # PUSH rbp (55)
        # MOV rbp, rsp (48 89 E5)
        # ADD rdi, rsi (48 01 F7)
        # MOV rax, rdi (48 89 F8)
        # SUB rax, 5 (48 83 E8 05)
        # POP rbp (5D)
        # RET (C3)
        x86_bytes = bytes([
            0xF3, 0x0F, 0x1E, 0xFA,
            0x55,
            0x48, 0x89, 0xE5,
            0x48, 0x01, 0xF7,
            0x48, 0x89, 0xF8,
            0x48, 0x83, 0xE8, 0x05,
            0x5D,
            0xC3,
        ])
        ops = x86_lifter.lift_block(0x401000, x86_bytes)
        self.assertGreaterEqual(len(ops), 6)

        res = verifier.verify_equivalence(
            ops,
            "return (rdi + rsi) - 5;",
            check_memory=False,
            tracked_registers=[0],  # rax is offset 0
        )
        self.assertTrue(res.equivalent)

    def test_explicit_nzcv_flag_varnodes_standalone_branch(self):
        """Verifies explicit architectural NZCV flag varnodes when lifting standalone B.cond."""
        lifter = ARM64PcodeLifter()
        # Lift B.EQ +0x20 (0x54000100) without a prior CMP in the same lift_block call
        code_beq = struct.pack("<I", 0x54000100)
        ops_beq = lifter.lift_block(0x5000, code_beq)
        # Ensure it reads FLAG_Z_OFFSET (0x201) rather than emitting a hardcoded constant 1
        reads_flag_z = any(
             any(inp.space == AddressSpace.REGISTER and inp.offset == FLAG_Z_OFFSET for inp in op.inputs)
            for op in ops_beq
        )
        self.assertTrue(reads_flag_z, "Standalone B.EQ must read architectural FLAG_Z varnode (0x201)")

        # Lift B.LT +0x20 (0x5400010B) without a prior CMP
        code_blt = struct.pack("<I", 0x5400010B)
        ops_blt = lifter.lift_block(0x5004, code_blt)
        reads_n_and_v = (
            any(any(inp.space == AddressSpace.REGISTER and inp.offset == FLAG_N_OFFSET for inp in op.inputs) for op in ops_blt)
            and any(any(inp.space == AddressSpace.REGISTER and inp.offset == FLAG_V_OFFSET for inp in op.inputs) for op in ops_blt)
        )
        self.assertTrue(reads_n_and_v, "Standalone B.LT must compare architectural FLAG_N (0x200) and FLAG_V (0x203)")

    def test_ghidra_macro_intrinsics_smt_verification(self):
        """Verifies Ghidra decompiler macro intrinsics (CONCAT44, SUB84, ZEXT48, SEXT48, CARRY8, SCARRY8, SBORROW8) in Z3."""
        verifier = SMTPcodeVerifier()
        w0 = Varnode(AddressSpace.REGISTER, 0, 4)
        w1 = Varnode(AddressSpace.REGISTER, 8, 4)
        x0 = Varnode(AddressSpace.REGISTER, 0, 8)
        x1 = Varnode(AddressSpace.REGISTER, 8, 8)

        # 1. CONCAT44(w0, w1) vs PIECE
        ops_concat = [PcodeOp(PcodeOpcode.PIECE, [w0, w1], x0, pc=0x1000)]
        res_concat = verifier.verify_equivalence(ops_concat, "return CONCAT44(w0, w1);", check_memory=False)
        self.assertTrue(res_concat.equivalent)

        # 2. SUB84(x1, 2) vs SUBPIECE(x1, 2)
        ops_sub = [PcodeOp(PcodeOpcode.SUBPIECE, [x1, Varnode(AddressSpace.CONST, 2, 4)], w0, pc=0x1004)]
        res_sub = verifier.verify_equivalence(ops_sub, "return SUB84(x1, 2);", check_memory=False)
        self.assertTrue(res_sub.equivalent)

        # 3. ZEXT48(w1) vs INT_ZEXT and SEXT48(w1) vs INT_SEXT
        ops_zext = [PcodeOp(PcodeOpcode.INT_ZEXT, [w1], x0, pc=0x1008)]
        self.assertTrue(verifier.verify_equivalence(ops_zext, "return ZEXT48(w1);", check_memory=False).equivalent)

        ops_sext = [PcodeOp(PcodeOpcode.INT_SEXT, [w1], x0, pc=0x100C)]
        self.assertTrue(verifier.verify_equivalence(ops_sext, "return SEXT48(w1);", check_memory=False).equivalent)

        # 4. CARRY8, SCARRY8, SBORROW8 vs INT_CARRY, INT_SCARRY, INT_SBORROW
        ops_carry = [PcodeOp(PcodeOpcode.INT_CARRY, [x0, x1], x0, pc=0x1010)]
        self.assertTrue(verifier.verify_equivalence(ops_carry, "return CARRY8(x0, x1);", check_memory=False).equivalent)

        ops_scarry = [PcodeOp(PcodeOpcode.INT_SCARRY, [x0, x1], x0, pc=0x1014)]
        self.assertTrue(verifier.verify_equivalence(ops_scarry, "return SCARRY8(x0, x1);", check_memory=False).equivalent)

        ops_sborrow = [PcodeOp(PcodeOpcode.INT_SBORROW, [x0, x1], x0, pc=0x1018)]
        self.assertTrue(verifier.verify_equivalence(ops_sborrow, "return SBORROW8(x0, x1);", check_memory=False).equivalent)


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
