#!/usr/bin/env python3
"""
test_pdb_tpi_export.py
======================
Unit and regression tests for SuperGhidra PDB Type Program Info (TPI) stream export:
- Verification of CodeView leaf record serialization helpers:
    - LF_POINTER (0x1002)
    - LF_PROCEDURE (0x1008)
    - LF_ARGLIST (0x1201)
    - LF_FIELDLIST (0x1203)
    - LF_MEMBER (0x150D)
    - LF_STRUCTURE (0x1505)
- Verification of MSF 7.0 PDB container emission with valid 56-byte TPI_HEADER (V80: 20040203)
- Sequential parsing and validation of emitted CodeView leaf records
- Verification of off-heap ingestion via dwarf_pdb_preindexer (TypeDeduplicator / OffHeapTypeStore)
"""

import os
import struct
import tempfile
import unittest
from typing import List, Tuple

from superghidra.formats.dwarf_pdb_preindexer import (
    OffHeapTypeStore,
    TypeDeduplicator,
)
from superghidra.formats.synthetic_symbol_exporter import (
    LF_ARGLIST,
    LF_FIELDLIST,
    LF_MEMBER,
    LF_POINTER,
    LF_PROCEDURE,
    LF_STRUCTURE,
    ExportField,
    ExportStruct,
    ExportSymbol,
    PDBExporter,
)


class TestPDBTPIExport(unittest.TestCase):
    """Test suite for CodeView TPI leaf record serialization and PDB export."""

    def _unpack_msf_streams(self, pdb_bytes: bytes) -> List[bytes]:
        """Helper to unpack streams from MSF 7.0 binary container."""
        self.assertGreaterEqual(len(pdb_bytes), 64)
        self.assertEqual(
            pdb_bytes[:32],
            b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00",
        )
        block_size, free_map, num_blocks, num_dir_bytes, reserved, block_map_addr = struct.unpack_from(
            "<IIIIII", pdb_bytes, 32
        )
        num_dir_blocks = (num_dir_bytes + block_size - 1) // block_size
        dir_blocks = [
            struct.unpack_from("<I", pdb_bytes, block_map_addr * block_size + i * 4)[0]
            for i in range(num_dir_blocks)
        ]

        dir_bytes = bytearray()
        for b_num in dir_blocks:
            dir_bytes.extend(pdb_bytes[b_num * block_size : (b_num + 1) * block_size])
        dir_bytes = dir_bytes[:num_dir_bytes]

        num_streams, = struct.unpack_from("<I", dir_bytes, 0)
        cur_off = 4
        stream_sizes = []
        for _ in range(num_streams):
            sz, = struct.unpack_from("<I", dir_bytes, cur_off)
            stream_sizes.append(sz)
            cur_off += 4

        streams: List[bytes] = []
        for sz in stream_sizes:
            if sz == 0xFFFFFFFF or sz == 0:
                streams.append(b"")
                continue
            n_blocks = (sz + block_size - 1) // block_size
            s_blocks = []
            for _ in range(n_blocks):
                b_idx, = struct.unpack_from("<I", dir_bytes, cur_off)
                s_blocks.append(b_idx)
                cur_off += 4

            s_data = bytearray()
            for b_idx in s_blocks:
                s_data.extend(pdb_bytes[b_idx * block_size : (b_idx + 1) * block_size])
            streams.append(bytes(s_data[:sz]))

        return streams

    def test_leaf_record_serialization_helpers(self):
        """Verifies individual CodeView leaf serialization helpers."""
        # 1. LF_POINTER (0x1002)
        ptr_rec = PDBExporter.serialize_lf_pointer(pointee_ti=0x1000, ptr_size=8, is_const=True)
        self.assertEqual(len(ptr_rec), 12)  # 2B length + 10B body
        rec_len, leaf, pointee_ti, attrs = struct.unpack_from("<HHII", ptr_rec, 0)
        self.assertEqual(rec_len, 10)
        self.assertEqual(leaf, LF_POINTER)
        self.assertEqual(pointee_ti, 0x1000)
        # Check pointer attributes: near64 (0x0A), const (bit 10), flat (bit 8), size 8 (8 << 13)
        self.assertEqual(attrs & 0x1F, 0x0A)
        self.assertTrue(bool(attrs & (1 << 10)))
        self.assertEqual((attrs >> 13) & 0x3F, 8)

        # 2. LF_ARGLIST (0x1201)
        arg_indices = [0x0074, 0x0040, 0x0603]  # int32, float, void*
        arg_rec = PDBExporter.serialize_lf_arglist(arg_indices)
        self.assertEqual(len(arg_rec), 20)  # 2B len + 2B leaf + 4B count + 12B indices
        rec_len, leaf, count = struct.unpack_from("<HHI", arg_rec, 0)
        self.assertEqual(rec_len, 18)
        self.assertEqual(leaf, LF_ARGLIST)
        self.assertEqual(count, 3)
        parsed_indices = list(struct.unpack_from("<3I", arg_rec, 8))
        self.assertEqual(parsed_indices, arg_indices)

        # 3. LF_PROCEDURE (0x1008)
        proc_rec = PDBExporter.serialize_lf_procedure(
            return_type_ti=0x0074,
            arg_list_ti=0x1001,
            calling_conv=0x03,
            param_count=3,
        )
        self.assertEqual(len(proc_rec), 16)  # 2B len + 14B body
        rec_len, leaf, ret_ti, call_conv, func_attr, p_count, arg_ti = struct.unpack_from(
            "<HHIBBHI", proc_rec, 0
        )
        self.assertEqual(rec_len, 14)
        self.assertEqual(leaf, LF_PROCEDURE)
        self.assertEqual(ret_ti, 0x0074)
        self.assertEqual(call_conv, 0x03)
        self.assertEqual(p_count, 3)
        self.assertEqual(arg_ti, 0x1001)

        # 4. LF_MEMBER (0x150D) - small offset (< 0x8000)
        m_entry = PDBExporter.serialize_lf_member(name="health", type_ti=0x0075, offset=16)
        # leaf (2B) + attr (2B) + type (4B) + offset (2B) + name ("health\0" = 7B) + pad (3B) = 20B
        self.assertEqual(len(m_entry), 20)
        self.assertEqual(len(m_entry) % 4, 0)
        sub_leaf, attr, m_type, m_off = struct.unpack_from("<HHIH", m_entry, 0)
        self.assertEqual(sub_leaf, LF_MEMBER)
        self.assertEqual(attr, 3)  # public
        self.assertEqual(m_type, 0x0075)
        self.assertEqual(m_off, 16)
        self.assertEqual(m_entry[10:17], b"health\0")
        # Check LF_PAD bytes
        self.assertEqual(m_entry[17:], b"\xf3\xf2\xf1")

        # 5. LF_MEMBER (0x150D) - large offset (>= 0x8000)
        m_large = PDBExporter.serialize_lf_member(name="buf", type_ti=0x0077, offset=0x10000)
        sub_leaf, attr, m_type, marker, large_off = struct.unpack_from("<HHIHI", m_large, 0)
        self.assertEqual(sub_leaf, LF_MEMBER)
        self.assertEqual(marker, 0x8004)
        self.assertEqual(large_off, 0x10000)

        # 6. LF_FIELDLIST (0x1203)
        fields = [
            ExportField(name="x", offset=0, size=4, type_name="float"),
            ExportField(name="y", offset=4, size=4, type_name="float"),
        ]
        flist_rec = PDBExporter.serialize_lf_fieldlist(fields)
        rec_len, leaf = struct.unpack_from("<HH", flist_rec, 0)
        self.assertEqual(leaf, LF_FIELDLIST)
        self.assertEqual(rec_len, len(flist_rec) - 2)

        # 7. LF_STRUCTURE (0x1505)
        st_rec = PDBExporter.serialize_lf_structure(
            name="Vec2",
            size=8,
            field_list_ti=0x1000,
            field_count=2,
        )
        rec_len, leaf, count, prop, flist_ti, derived, vshape = struct.unpack_from(
            "<HHHHIII", st_rec, 0
        )
        self.assertEqual(leaf, LF_STRUCTURE)
        self.assertEqual(count, 2)
        self.assertEqual(flist_ti, 0x1000)
        self.assertEqual(rec_len, len(st_rec) - 2)

    def test_pdb_tpi_header_and_stream_records(self):
        """Verifies that emitted PDB contains a valid TPI stream with ti_min=0x1000 and ti_max > 0x1000."""
        syms = [
            ExportSymbol(name="Player__Attack", address=0x140010000, size=0x40, symbol_type="FUNC",
                         demangled_name="int Player::Attack(float, int)"),
            ExportSymbol(name="Player__Heal", address=0x140010040, size=0x30, symbol_type="FUNC",
                         demangled_name="void Player::Heal(int)"),
        ]
        structs = [
            ExportStruct(
                name="Actor",
                size=32,
                fields=[
                    ExportField(name="id", offset=0, size=4, type_name="uint32_t"),
                    ExportField(name="health", offset=4, size=4, type_name="float"),
                    ExportField(name="pos", offset=8, size=16, type_name="void*"),
                ],
            )
        ]

        exporter = PDBExporter(symbols=syms, structs=structs, base_address=0x140000000)
        pdb_bytes = exporter.export_pdb()

        streams = self._unpack_msf_streams(pdb_bytes)
        self.assertGreaterEqual(len(streams), 6)
        tpi_stream = streams[2]
        self.assertGreaterEqual(len(tpi_stream), 56)

        # Check 56-byte TPI Header
        version, hdr_sz, ti_min, ti_max, records_len = struct.unpack_from("<IIIII", tpi_stream, 0)
        self.assertEqual(version, 20040203)  # V80
        self.assertEqual(hdr_sz, 56)
        self.assertEqual(ti_min, 0x1000)
        self.assertGreater(ti_max, 0x1000)
        self.assertEqual(records_len, len(tpi_stream) - 56)

        hash_stream_idx, = struct.unpack_from("<H", tpi_stream, 20)
        self.assertEqual(hash_stream_idx, 0xFFFF)

    def test_tpi_sequential_leaf_parsing(self):
        """Verifies all emitted CodeView leaf records parse back correctly without corruption."""
        structs = [
            ExportStruct(
                name="Character",
                size=24,
                fields=[
                    ExportField(name="uuid", offset=0, size=8, type_name="uint64_t"),
                    ExportField(name="level", offset=8, size=4, type_name="uint32_t"),
                ],
            )
        ]
        syms = [
            ExportSymbol(name="Character__Update", address=0x140020000, size=0x50, symbol_type="FUNC",
                         demangled_name="void Character::Update(float)"),
        ]

        exporter = PDBExporter(symbols=syms, structs=structs, base_address=0x140000000)
        pdb_bytes = exporter.build_pdb()

        streams = self._unpack_msf_streams(pdb_bytes)
        tpi_stream = streams[2]

        version, hdr_sz, ti_min, ti_max, records_len = struct.unpack_from("<IIIII", tpi_stream, 0)
        end_off = hdr_sz + records_len

        parsed_leaves: List[Tuple[int, int]] = []  # (type_index, leaf_type)
        rec_off = hdr_sz
        curr_ti = ti_min

        while rec_off + 4 <= end_off:
            rec_len, = struct.unpack_from("<H", tpi_stream, rec_off)
            self.assertGreaterEqual(rec_len, 2)
            self.assertLessEqual(rec_off + 2 + rec_len, len(tpi_stream))

            leaf, = struct.unpack_from("<H", tpi_stream, rec_off + 2)
            parsed_leaves.append((curr_ti, leaf))

            curr_ti += 1
            rec_off += 2 + rec_len

        self.assertEqual(curr_ti, ti_max)
        leaf_types = [l for _, l in parsed_leaves]

        # Ensure all required leaves were emitted and parsed:
        self.assertIn(LF_FIELDLIST, leaf_types)
        self.assertIn(LF_STRUCTURE, leaf_types)
        self.assertIn(LF_POINTER, leaf_types)
        self.assertIn(LF_ARGLIST, leaf_types)
        self.assertIn(LF_PROCEDURE, leaf_types)

    def test_dwarf_pdb_preindexer_verification(self):
        """Verifies that exported PDB is fully ingested and indexed by dwarf_pdb_preindexer."""
        structs = [
            ExportStruct(
                name="InventorySlot",
                size=16,
                fields=[
                    ExportField(name="item_id", offset=0, size=4, type_name="uint32_t"),
                    ExportField(name="quantity", offset=4, size=4, type_name="uint32_t"),
                    ExportField(name="durability", offset=8, size=4, type_name="float"),
                ],
            )
        ]
        syms = [
            ExportSymbol(name="Slot_Use", address=0x140030000, size=0x20, symbol_type="FUNC",
                         demangled_name="int Slot_Use(int)"),
        ]

        exporter = PDBExporter(symbols=syms, structs=structs, base_address=0x140000000)
        pdb_bytes = exporter.export_pdb()

        dedup = TypeDeduplicator()
        stats = dedup.ingest_pdb_bytes(pdb_bytes, base_address=0x140000000)

        self.assertGreaterEqual(stats["structs"], 1)
        self.assertGreaterEqual(stats["members"], 3)
        self.assertGreaterEqual(stats["symbols"], 1)
        self.assertGreaterEqual(stats["types"], 2)

        # Off-heap SQLite store verification
        store = OffHeapTypeStore(":memory:")
        store.ingest_from_deduplicator(dedup)

        t_slot = store.find_type_by_name("InventorySlot")
        self.assertIsNotNone(t_slot)
        self.assertEqual(t_slot.byte_size, 16)
        self.assertEqual(len(t_slot.members), 3)

        layout = store.get_struct_layout("InventorySlot")
        self.assertEqual(len(layout), 3)
        self.assertEqual(layout[0]["name"], "item_id")
        self.assertEqual(layout[0]["offset"], 0)
        self.assertEqual(layout[1]["name"], "quantity")
        self.assertEqual(layout[1]["offset"], 4)
        self.assertEqual(layout[2]["name"], "durability")
        self.assertEqual(layout[2]["offset"], 8)

    def test_empty_symbols_and_structs(self):
        """Verifies that an exporter with empty inputs emits a safe, minimal valid TPI stream."""
        exporter = PDBExporter(symbols=[], structs=[], base_address=0x140000000)
        pdb_bytes = exporter.export_pdb()

        streams = self._unpack_msf_streams(pdb_bytes)
        tpi_stream = streams[2]
        self.assertEqual(len(tpi_stream), 56)

        version, hdr_sz, ti_min, ti_max, records_len = struct.unpack_from("<IIIII", tpi_stream, 0)
        self.assertEqual(version, 20040203)
        self.assertEqual(hdr_sz, 56)
        self.assertEqual(ti_min, 0x1000)
        self.assertEqual(ti_max, 0x1000)
        self.assertEqual(records_len, 0)

    def test_export_pdb_to_file(self):
        """Verifies writing exported PDB directly to a file matches returned bytes."""
        syms = [ExportSymbol(name="main", address=0x140001000, size=0x10, symbol_type="FUNC")]
        exporter = PDBExporter(symbols=syms, structs=[], base_address=0x140000000)

        with tempfile.NamedTemporaryFile(suffix=".pdb", delete=False) as tf:
            temp_path = tf.name

        try:
            pdb_bytes = exporter.export_pdb(output_path=temp_path)
            with open(temp_path, "rb") as f:
                disk_bytes = f.read()
            self.assertEqual(pdb_bytes, disk_bytes)
            self.assertEqual(disk_bytes[:32], PDBExporter.MSF_MAGIC)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


if __name__ == "__main__":
    unittest.main()
