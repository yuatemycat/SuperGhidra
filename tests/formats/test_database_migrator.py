"""
tests/formats/test_database_migrator.py
=======================================
Full Project Database Migrator Test Suite.
Tests IDA Pro (.idb/.i64) and Binary Ninja (.bndb) migration to SuperGhidra IR,
WriteOverlay, .ghidra-delta.jsonl, and EvidenceLedger obligations.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sqlite3
import struct
import tempfile
import unittest
import zipfile

from superghidra.formats import database_migrator as root_migrator
from superghidra.formats.database_migrator import (
    BinaryNinjaDatabaseMigrator,
    DatabaseMigrator,
    IdaDatabaseMigrator,
    MigratedComment,
    MigratedField,
    MigratedFunction,
    MigratedProject,
    MigratedSegment,
    MigratedStruct,
    MigratedSymbol,
    MigratedXref,
    create_synthetic_bndb_database,
    create_synthetic_ida_database,
)


class TestDatabaseMigratorShims(unittest.TestCase):
    """Test backward-compatibility root shim and package exports."""

    def test_root_shim_exports(self):
        self.assertTrue(hasattr(root_migrator, "DatabaseMigrator"))
        self.assertTrue(hasattr(root_migrator, "IdaDatabaseMigrator"))
        self.assertTrue(hasattr(root_migrator, "BinaryNinjaDatabaseMigrator"))
        self.assertTrue(hasattr(root_migrator, "MigratedProject"))
        self.assertTrue(hasattr(root_migrator, "create_synthetic_ida_database"))
        self.assertTrue(hasattr(root_migrator, "create_synthetic_bndb_database"))


class TestIdaDatabaseMigrator(unittest.TestCase):
    """Tests for IDA Pro .idb (32-bit) and .i64 (64-bit) extraction."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ida_64bit_synthetic_extraction(self):
        """Construct synthetic .i64 database and verify all extracted entities."""
        idb_path = self.dir_path / "target_x64.i64"
        create_synthetic_ida_database(
            filepath=idb_path,
            bitness=64,
            architecture="x86_64",
        )

        project = DatabaseMigrator.load(idb_path)
        self.assertEqual(project.source_format, "IDA_PRO_I64")
        self.assertEqual(project.bitness, 64)
        self.assertEqual(project.architecture, "x86_64")

        # Verify Segments
        self.assertEqual(len(project.segments), 3)
        seg_names = [s.name for s in project.segments]
        self.assertIn(".text", seg_names)
        self.assertIn(".rdata", seg_names)
        self.assertIn(".data", seg_names)

        text_seg = [s for s in project.segments if s.name == ".text"][0]
        self.assertEqual(text_seg.start_address, 0x140001000)
        self.assertEqual(text_seg.end_address, 0x140005000)
        self.assertTrue(text_seg.is_code)

        # Verify Functions & Local Variables
        self.assertEqual(len(project.functions), 2)
        fn_map = {f.name: f for f in project.functions}
        self.assertIn("MainEntry", fn_map)
        self.assertIn("ProcessPacket", fn_map)

        main_fn = fn_map["MainEntry"]
        self.assertEqual(main_fn.address, 0x140001020)
        self.assertEqual(main_fn.size, 0x80)
        self.assertTrue(main_fn.is_entry)
        self.assertIn("MainEntry", main_fn.prototype)
        self.assertEqual(len(main_fn.local_variables), 2)
        self.assertEqual(main_fn.local_variables[0], ("int", "argc", -8))

        # Verify Entry Points
        self.assertIn(0x140001020, project.entry_points)

        # Verify Symbols
        self.assertEqual(len(project.symbols), 2)
        sym_names = [s.name for s in project.symbols]
        self.assertIn("g_ConfigurationState", sym_names)
        self.assertIn("g_ActiveSessionKey", sym_names)

        # Verify Comments
        self.assertEqual(len(project.comments), 2)
        comm_map = {c.address: c for c in project.comments}
        self.assertIn(0x140001020, comm_map)
        self.assertEqual(comm_map[0x140001020].text, "Program entry point dispatcher")
        self.assertEqual(comm_map[0x140001020].comment_type, "plate")

        # Verify Structs and natural layout
        self.assertEqual(len(project.structs), 1)
        st = project.structs[0]
        self.assertEqual(st.name, "NetworkPacket")
        self.assertEqual(st.size, 32)
        self.assertEqual(st.alignment, 8)
        self.assertEqual(len(st.fields), 5)
        self.assertEqual(st.fields[0].name, "magic")
        self.assertEqual(st.fields[0].offset, 0)
        self.assertEqual(st.fields[2].name, "payload_ptr")
        self.assertEqual(st.fields[2].offset, 8)
        self.assertEqual(st.fields[2].size, 8)

        # Verify Cross References
        self.assertEqual(len(project.xrefs), 2)
        xref0 = project.xrefs[0]
        self.assertEqual(xref0.from_address, 0x140001035)
        self.assertEqual(xref0.to_address, 0x140001100)
        self.assertEqual(xref0.xref_type, "call")

    def test_ida_32bit_synthetic_extraction(self):
        """Construct synthetic .idb 32-bit database and verify bitness & addresses."""
        idb_path = self.dir_path / "target_x86.idb"
        create_synthetic_ida_database(
            filepath=idb_path,
            bitness=32,
            architecture="x86",
            segments=[
                {"name": ".text", "start": 0x401000, "end": 0x403000, "perms": "r-x"},
                {"name": ".data", "start": 0x403000, "end": 0x405000, "perms": "rw-"},
            ],
            functions=[
                {
                    "addr": 0x401050,
                    "size": 0x30,
                    "name": "SubHandler32",
                    "prototype": "int __stdcall SubHandler32(void* ctx)",
                    "flags": 1,
                    "local_vars": [("void*", "ctx", 8)],
                }
            ],
            symbols=[{"addr": 0x403020, "name": "g_Counter", "type": "OBJECT"}],
            comments=[{"addr": 0x401050, "text": "32-bit entry handler", "type": "user"}],
            structs=[
                {
                    "name": "Point32",
                    "size": 8,
                    "alignment": 4,
                    "fields": [
                        {"name": "x", "offset": 0, "size": 4, "type": "int32_t"},
                        {"name": "y", "offset": 4, "size": 4, "type": "int32_t"},
                    ],
                }
            ],
            xrefs=[],
        )

        project = DatabaseMigrator.load(idb_path)
        self.assertEqual(project.source_format, "IDA_PRO_IDB")
        self.assertEqual(project.bitness, 32)
        self.assertEqual(len(project.segments), 2)
        self.assertEqual(len(project.functions), 1)
        self.assertEqual(project.functions[0].name, "SubHandler32")
        self.assertEqual(project.functions[0].address, 0x401050)
        self.assertEqual(len(project.structs), 1)
        self.assertEqual(project.structs[0].name, "Point32")

    def test_ida_zip_container_migration(self):
        """Test migrating a zip-compressed IDA bundle containing idb_metadata.json."""
        zip_path = self.dir_path / "ida_bundle.i64"
        meta_content = {
            "architecture": "arm64",
            "bitness": 64,
            "endianness": "little",
            "base_address": "0x100000000",
            "segments": [
                {"name": "__TEXT", "start_address": "0x100001000", "end_address": "0x100005000", "permissions": "r-x", "is_code": True}
            ],
            "functions": [
                {"name": "arm64_entry", "address": "0x100001000", "size": 0x40, "is_entry": True, "prototype": "void arm64_entry()"}
            ],
            "symbols": [
                {"name": "_kVersionString", "address": "0x100004000", "symbol_type": "OBJECT"}
            ],
            "comments": [
                {"address": "0x100001000", "text": "ARM64 main bootstrap", "comment_type": "plate"}
            ],
            "structs": [
                {
                    "name": "HeaderArm",
                    "size": 16,
                    "alignment": 8,
                    "fields": [
                        {"name": "magic", "offset": "0x0", "size": 8, "type_name": "uint64_t"},
                        {"name": "flags", "offset": "0x8", "size": 8, "type_name": "uint64_t"},
                    ],
                }
            ],
        }

        with zipfile.ZipFile(str(zip_path), "w") as zf:
            zf.writestr("idb_metadata.json", json.dumps(meta_content))
            zf.writestr(".id0", b"DUMMY_ID0_DATA")

        project = DatabaseMigrator.load(zip_path)
        self.assertEqual(project.architecture, "arm64")
        self.assertEqual(project.bitness, 64)
        self.assertEqual(len(project.functions), 1)
        self.assertEqual(project.functions[0].name, "arm64_entry")
        self.assertEqual(len(project.structs), 1)
        self.assertEqual(project.structs[0].fields[1].name, "flags")


class TestBinaryNinjaDatabaseMigrator(unittest.TestCase):
    """Tests for Binary Ninja SQLite .bndb project database extraction."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_bndb_synthetic_extraction(self):
        """Construct synthetic .bndb SQLite database and verify full schema parsing."""
        bndb_path = self.dir_path / "analysis.bndb"
        create_synthetic_bndb_database(
            filepath=bndb_path,
            bitness=64,
            architecture="x86_64",
        )

        project = DatabaseMigrator.load(bndb_path)
        self.assertEqual(project.source_format, "BINARY_NINJA_BNDB")
        self.assertEqual(project.bitness, 64)
        self.assertEqual(project.architecture, "x86_64")

        # Verify Segments
        self.assertEqual(len(project.segments), 3)
        seg_map = {s.name: s for s in project.segments}
        self.assertIn(".text", seg_map)
        self.assertEqual(seg_map[".text"].start_address, 0x140001000)
        self.assertEqual(seg_map[".text"].end_address, 0x140005000)

        # Verify Functions and HLIL / MLIL Tags
        self.assertEqual(len(project.functions), 2)
        fn_map = {f.name: f for f in project.functions}
        self.assertIn("BnMainEntry", fn_map)
        self.assertIn("BnParseBuffer", fn_map)

        entry_fn = fn_map["BnMainEntry"]
        self.assertEqual(entry_fn.address, 0x140001000)
        self.assertTrue(entry_fn.is_entry)
        self.assertIn("HLIL", entry_fn.tags)
        self.assertIn("SecurityCritical", entry_fn.tags)  # Attached from tags table
        self.assertEqual(len(entry_fn.local_variables), 2)

        # Verify Symbols
        self.assertEqual(len(project.symbols), 2)
        sym_map = {s.name: s for s in project.symbols}
        self.assertIn("g_GlobalTelemetry", sym_map)
        self.assertEqual(sym_map["g_GlobalTelemetry"].namespace, "Global")

        # Verify Comments
        self.assertEqual(len(project.comments), 2)
        c_map = {c.address: c for c in project.comments}
        self.assertIn(0x140001000, c_map)
        self.assertEqual(c_map[0x140001000].text, "Entry routine for service")

        # Verify Types / Structs
        self.assertEqual(len(project.structs), 1)
        st = project.structs[0]
        self.assertEqual(st.name, "BnConnectionState")
        self.assertEqual(st.size, 24)
        self.assertEqual(st.alignment, 8)
        self.assertEqual(len(st.fields), 4)
        self.assertEqual(st.fields[0].name, "socket_fd")
        self.assertEqual(st.fields[0].offset, 0)
        self.assertEqual(st.fields[2].name, "rx_buffer_ptr")
        self.assertEqual(st.fields[2].offset, 8)
        self.assertEqual(st.fields[2].size, 8)

        # Verify Cross References
        self.assertEqual(len(project.xrefs), 2)
        x_map = {(x.from_address, x.to_address): x for x in project.xrefs}
        self.assertIn((0x140001025, 0x140001200), x_map)
        self.assertEqual(x_map[(0x140001025, 0x140001200)].xref_type, "call")


class TestUniversalMigrationConverters(unittest.TestCase):
    """Tests for downstream SuperGhidra conversions: WriteOverlay, .ghidra-delta.jsonl, EvidenceLedger."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def _build_test_project(self) -> MigratedProject:
        p = MigratedProject(
            source_format="TEST_PROJECT",
            architecture="x86_64",
            bitness=64,
            base_address=0x140000000,
            segments=[
                MigratedSegment(name=".text", start_address=0x140001000, end_address=0x140003000, permissions="r-x", is_code=True),
                MigratedSegment(name=".data", start_address=0x140003000, end_address=0x140005000, permissions="rw-", is_data=True),
            ],
            functions=[
                MigratedFunction(
                    address=0x140001050,
                    name="CalculateHash",
                    size=0x64,
                    prototype="uint64_t __fastcall CalculateHash(const void* buf, size_t len)",
                    return_type="uint64_t",
                    parameters=[("const void*", "buf"), ("size_t", "len")],
                    calling_convention="__fastcall",
                    tags=["HLIL"],
                    is_entry=False,
                )
            ],
            symbols=[
                MigratedSymbol(address=0x140003010, name="g_MasterSalt", symbol_type="OBJECT"),
            ],
            structs=[
                MigratedStruct(
                    name="CryptoContext",
                    size=32,
                    alignment=8,
                    fields=[
                        MigratedField(name="salt", offset=0, size=8, type_name="uint64_t"),
                        MigratedField(name="rounds", offset=8, size=4, type_name="uint32_t"),
                        MigratedField(name="flags", offset=12, size=4, type_name="uint32_t"),
                        MigratedField(name="key_ptr", offset=16, size=8, type_name="void*"),
                        MigratedField(name="digest", offset=24, size=8, type_name="uint64_t"),
                    ],
                )
            ],
            comments=[
                MigratedComment(address=0x140001050, text="Core cryptographic hashing function", comment_type="plate"),
            ],
            xrefs=[
                MigratedXref(from_address=0x140001050, to_address=0x140003010, xref_type="data"),
            ],
        )
        return p

    def test_export_to_write_overlay(self):
        """Verify symbols, comments, and prototypes populate the WriteOverlay."""
        project = self._build_test_project()
        overlay_file = self.dir_path / "test_overlay.json"

        overlay = project.to_write_overlay(filepath=str(overlay_file))
        overlay.save()

        self.assertTrue(overlay_file.exists())
        with open(overlay_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        renames = data.get("renames", {})
        comments = data.get("comments", {})
        prototypes = data.get("prototypes", {})

        # Verify normalized hex keys in overlay
        self.assertIn("0x140001050", renames)
        self.assertEqual(renames["0x140001050"], "CalculateHash")
        self.assertIn("0x140003010", renames)
        self.assertEqual(renames["0x140003010"], "g_MasterSalt")

        self.assertIn("0x140001050", comments)
        self.assertEqual(comments["0x140001050"], "Core cryptographic hashing function")

        self.assertIn("0x140001050", prototypes)
        self.assertIn("CalculateHash", prototypes["0x140001050"])

    def test_export_to_ghidra_delta_jsonl(self):
        """Verify .ghidra-delta.jsonl events have deterministic proof hashes and valid fields."""
        project = self._build_test_project()
        delta_file = self.dir_path / "delta.ghidra-delta.jsonl"

        events = project.to_ghidra_delta_jsonl(output_path=str(delta_file))
        self.assertTrue(delta_file.exists())

        evt_types = [e["event_type"] for e in events]
        self.assertIn("RenameSymbol", evt_types)
        self.assertIn("SetFunctionSignature", evt_types)
        self.assertIn("SetComment", evt_types)
        self.assertIn("DefineStructField", evt_types)

        # Check proof hash format and event IDs
        for evt in events:
            self.assertTrue(evt["event_id"].startswith("EVT-"))
            self.assertEqual(len(evt["proof_hash"]), 64)
            self.assertTrue(evt["verified"])

        # Check struct field event details
        struct_evts = [e for e in events if e["event_type"] == "DefineStructField"]
        self.assertEqual(len(struct_evts), 5)
        field_names = [e["payload"]["field_name"] for e in struct_evts]
        self.assertEqual(field_names, ["salt", "rounds", "flags", "key_ptr", "digest"])

    def test_export_to_evidence_ledger(self):
        """Verify EvidenceLedger obligations are generated and invariants pass verification."""
        project = self._build_test_project()
        ledger_file = self.dir_path / "test_ledger.json"

        ledger = project.to_evidence_ledger(ledger_file=str(ledger_file))
        ledger.save()

        self.assertTrue(ledger_file.exists())
        self.assertGreater(len(ledger.obligations), 0)

        # Struct obligation should be verified by FieldDisplacementVerifier
        struct_obls = [o for o in ledger.obligations.values() if o.obligation_type.value == "STRUCT_DEFINITION"]
        self.assertEqual(len(struct_obls), 1)
        st_obl = struct_obls[0]
        self.assertEqual(st_obl.proposed_name, "CryptoContext")
        self.assertEqual(st_obl.status.value, "VERIFIED")

    def test_export_to_synthetic_symbols_and_containers(self):
        """Verify conversion to ExportSymbol/ExportStruct and synthetic container outputs."""
        project = self._build_test_project()
        symbols, structs = project.to_synthetic_symbols()

        self.assertEqual(len(symbols), 2)  # 1 function + 1 object symbol
        self.assertEqual(len(structs), 1)
        self.assertEqual(structs[0].name, "CryptoContext")

        containers = project.export_synthetic_containers(
            output_dir=str(self.dir_path),
            base_name="crypto_target",
            formats=("sym", "map", "dwarf", "pdb"),
        )

        self.assertIn("sym", containers)
        self.assertIn("map", containers)
        self.assertTrue(Path(containers["sym"]).exists())
        self.assertTrue(Path(containers["map"]).exists())

    def test_export_to_all_manifest(self):
        """Verify DatabaseMigrator.export_to_all produces complete artifact manifest."""
        project = self._build_test_project()
        manifest = DatabaseMigrator.export_to_all(
            project=project,
            output_dir=self.dir_path / "all_out",
            base_name="full_export",
        )

        self.assertIn("artifacts", manifest)
        self.assertIn("overlay", manifest["artifacts"])
        self.assertIn("delta_log", manifest["artifacts"])
        self.assertIn("evidence_ledger", manifest["artifacts"])
        self.assertIn("containers", manifest["artifacts"])


class TestDatabaseMigratorEdgeCases(unittest.TestCase):
    """Test boundary conditions, errors, and invalid inputs."""

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            DatabaseMigrator.load("non_existent_file_xyz.idb")

    def test_unsupported_format(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tf:
            tf.write(b"NOT A DATABASE FILE")
            tf.flush()
            tmp_name = tf.name
        try:
            with self.assertRaises(ValueError):
                DatabaseMigrator.load(tmp_name)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def test_empty_bytes_ida(self):
        with self.assertRaises(ValueError):
            IdaDatabaseMigrator.parse_bytes(b"")

    def test_invalid_bndb_bytes(self):
        with self.assertRaises(ValueError):
            BinaryNinjaDatabaseMigrator.parse_bytes(b"NOT_SQLITE_DATABASE")


if __name__ == "__main__":
    unittest.main()
