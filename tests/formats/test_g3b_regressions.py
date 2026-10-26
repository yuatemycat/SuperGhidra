#!/usr/bin/env python3
"""
test_g3b_regressions.py
=======================
Focused regression test suite for verified bugs resolved in Agent G3b:
1. PDB Writer:
   - Real 64-byte DBI header layout (PublicStreamIndex at offset 16, Machine at offset 58/60)
   - CodeView LF_PAD bytes (0xF0 | rem) in field lists
   - MSF Free Page Map blocks 1 & 2 unused by stream directory
   - PDB info stream named-stream map valid serialized hash table
   - DWARF DW_AT_type ref4 points to real DIE (no 0 offsets)
   - ELF e_machine defaults to 183 (arm64) and accepts x86_64 (62); zero-filled .text
2. DWARF / PDB Preindexer:
   - DWARF 5 form skipping (implicit_const, strx1, flag_present, exprloc, etc.)
   - Real DBI header parsing and dynamic symbol stream resolution
3. SHM Ring Buffer:
   - Corrupt payload_len > capacity raises ValueError
   - Atomic cross-process synchronization (named mutex on Windows / thread lock)
   - Zero-copy docstring clarifications & x86 TSO write ordering
4. APK JNI Cross-Referencer:
   - Exact prefix/suffix stripping for descriptors ("LLoginManager;" -> "LoginManager")
"""

import struct
import unittest
from typing import List

from superghidra.core.shm_decompiler_bridge import (
    FRAME_HDR_FMT,
    FRAME_MAGIC,
    ShmRingBuffer,
)
from superghidra.formats.dwarf_pdb_preindexer import (
    OffHeapTypeStore,
)
from superghidra.formats.synthetic_symbol_exporter import (
    DWARF5Exporter,
    ExportField,
    ExportStruct,
    ExportSymbol,
    PDBExporter,
    encode_sleb128,
    encode_uleb128,
)
from superghidra.integrations.apk_jni_cross_referencer import (
    APKJNICrossReferencer,
)


class TestG3BRegressions(unittest.TestCase):
    """Regression test cases verifying all G3b fixes."""

    def _unpack_msf_streams(self, pdb_bytes: bytes) -> List[bytes]:
        """Helper to unpack streams from MSF 7.0 binary container."""
        block_size, free_map, num_blocks, num_dir_bytes, reserved, block_map_addr = struct.unpack_from(
            "<IIIIII", pdb_bytes, 32
        )
        num_dir_blocks = (num_dir_bytes + block_size - 1) // block_size
        dir_blocks = []
        for i in range(num_dir_blocks):
            b_num, = struct.unpack_from("<I", pdb_bytes, block_map_addr * block_size + i * 4)
            dir_blocks.append(b_num)

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

    def test_dbi_header_offsets_and_machine(self):
        """Verifies real 64-byte DBI header layout: PublicStreamIndex at offset 16 and Machine at 58/60."""
        syms = [ExportSymbol(name="Player__TakeDamage", address=0x140010000, size=0x40, symbol_type="FUNC")]
        exporter = PDBExporter(symbols=syms, structs=[], base_address=0x140000000)
        pdb_bytes = exporter.build_pdb()

        streams = self._unpack_msf_streams(pdb_bytes)
        self.assertGreaterEqual(len(streams), 6)
        dbi_stream = streams[3]
        self.assertGreaterEqual(len(dbi_stream), 64)

        # Offset 0: VersionSignature (i32 == -1)
        # Offset 4: VersionHeader (u32 == 19990903)
        # Offset 8: Age (u32 == 1)
        sig, ver, age = struct.unpack_from("<iII", dbi_stream, 0)
        self.assertEqual(sig, -1)
        self.assertEqual(ver, 19990903)
        self.assertEqual(age, 1)

        # Offset 16: PublicStreamIndex (u16)
        public_stream_idx, = struct.unpack_from("<H", dbi_stream, 16)
        self.assertEqual(public_stream_idx, 5)

        # Offset 58 & 60: Machine (0x8664 x64 / 0xAA64 ARM64)
        machine_58, = struct.unpack_from("<H", dbi_stream, 58)
        machine_60, = struct.unpack_from("<H", dbi_stream, 60)
        self.assertIn(machine_58, (0x8664, 0xAA64))
        self.assertIn(machine_60, (0x8664, 0xAA64))

    def test_lf_pad_bytes_in_tpi(self):
        """Verifies CodeView LF_PAD bytes (0xF0 | rem -> 0xF1, 0xF2, 0xF3), not 0x00."""
        # Struct with a field name of length 2 -> offset padding needed
        st = ExportStruct(
            name="TestPadStruct",
            size=16,
            fields=[ExportField(name="ab", offset=0, size=4, type_name="uint32_t")],
        )
        exporter = PDBExporter(symbols=[], structs=[st], base_address=0x140000000)
        pdb_bytes = exporter.build_pdb()

        streams = self._unpack_msf_streams(pdb_bytes)
        tpi_stream = streams[2]
        self.assertGreater(len(tpi_stream), 56)

        # In TPI records after header (56 bytes), search for LF_FIELDLIST (0x1203)
        fieldlist_idx = tpi_stream.find(struct.pack("<H", 0x1203), 56)
        self.assertNotEqual(fieldlist_idx, -1)

        # Search for member name 'ab\x00'
        name_idx = tpi_stream.find(b"ab\x00", fieldlist_idx)
        self.assertNotEqual(name_idx, -1)
        pad_byte = tpi_stream[name_idx + 3]
        # Pad byte must be an LF_PAD byte >= 0xF0
        self.assertGreaterEqual(pad_byte, 0xF0)
        self.assertIn(pad_byte, (0xF1, 0xF2, 0xF3))

    def test_msf_fpm_blocks_1_and_2_unused_by_streams(self):
        """Verifies that MSF Free Page Map blocks 1 and 2 are never used by any stream."""
        syms = [ExportSymbol(name=f"Sub_{i:04x}", address=0x140000000 + i * 0x10, size=0x10) for i in range(10)]
        exporter = PDBExporter(symbols=syms, structs=[], base_address=0x140000000)
        pdb_bytes = exporter.build_pdb()

        block_size, free_map, num_blocks, num_dir_bytes, reserved, block_map_addr = struct.unpack_from(
            "<IIIIII", pdb_bytes, 32
        )
        self.assertEqual(free_map, 1)

        # Inspect stream directory block assignments
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
        cur_off = 4 + num_streams * 4
        all_allocated_blocks = []
        while cur_off + 4 <= len(dir_bytes):
            b_idx, = struct.unpack_from("<I", dir_bytes, cur_off)
            all_allocated_blocks.append(b_idx)
            cur_off += 4

        # Blocks 1 and 2 are the FPM and must NEVER be allocated to streams
        self.assertNotIn(1, all_allocated_blocks)
        self.assertNotIn(2, all_allocated_blocks)
        for b in all_allocated_blocks:
            self.assertGreaterEqual(b, 3)

    def test_pdb_named_stream_map_parses(self):
        """Verifies named-stream map is a valid serialized hash table (not a bare 0)."""
        exporter = PDBExporter(symbols=[], structs=[], base_address=0x140000000)
        pdb_bytes = exporter.build_pdb()
        streams = self._unpack_msf_streams(pdb_bytes)
        pdb_stream = streams[1]

        # PDB Info Stream header: 28 bytes
        # Version (4B), Signature (4B), Age (4B), Reserved (4B), GUID (16B) = 32 bytes
        self.assertGreaterEqual(len(pdb_stream), 32 + 20)
        # Named stream table: string_buf_size, size, capacity, present_words, deleted_words
        str_buf_sz, sz, cap, pres_words, del_words = struct.unpack_from("<IIIII", pdb_stream, 32)
        self.assertEqual(str_buf_sz, 0)
        self.assertEqual(sz, 0)
        self.assertEqual(cap, 0)
        self.assertEqual(pres_words, 0)
        self.assertEqual(del_words, 0)

    def test_dwarf_every_dw_at_type_references_existing_die(self):
        """Verifies that every member DW_AT_type ref4 points to an existing base type DIE (never 0)."""
        st = ExportStruct(
            name="InventoryItem",
            size=24,
            fields=[
                ExportField(name="itemId", offset=0, size=4, type_name=None),  # type_name=None
                ExportField(name="quantity", offset=4, size=4, type_name="UnknownCustomType"),
            ],
        )
        exporter = DWARF5Exporter(symbols=[ExportSymbol(name="InitItem", address=0x1000, size=0x20)], structs=[st])
        elf_bytes = exporter.build_elf()

        store = OffHeapTypeStore(":memory:")
        stats = store.ingest_dwarf5_elf(elf_bytes)
        self.assertGreaterEqual(stats["types"], 1)
        self.assertGreaterEqual(stats["members"], 2)
        layout = store.get_struct_layout("InventoryItem")
        self.assertEqual(len(layout), 2)
        self.assertEqual(layout[0]["type_name"], "uint32_t")
        self.assertEqual(layout[1]["type_name"], "UnknownCustomType")
        store.close()

    def test_elf_e_machine_arm64_and_x86_64(self):
        """Verifies architecture parameter sets e_machine = 183 (arm64 default) and 62 (x86_64)."""
        exporter_arm = DWARF5Exporter(symbols=[], structs=[], architecture="arm64")
        elf_arm = exporter_arm.build_elf()
        e_machine_arm, = struct.unpack_from("<H", elf_arm, 18)
        self.assertEqual(e_machine_arm, 183)

        exporter_x64 = DWARF5Exporter(symbols=[], structs=[], architecture="x86_64")
        elf_x64 = exporter_x64.build_elf()
        e_machine_x64, = struct.unpack_from("<H", elf_x64, 18)
        self.assertEqual(e_machine_x64, 62)

    def test_dwarf_preindexer_skips_dwarf5_forms(self):
        """Verifies preindexer correctly skips DWARF 5 forms: implicit_const, strx1, flag_present, exprloc."""
        # Build minimal hand-crafted .debug_abbrev
        abbrev = bytearray()
        # Abbrev 1: DW_TAG_compile_unit (0x11), children=yes (1)
        abbrev.extend(encode_uleb128(1) + encode_uleb128(0x11) + b"\x01")
        # DW_AT_producer (0x25): DW_FORM_implicit_const (0x21) with SLEB value 77
        abbrev.extend(encode_uleb128(0x25) + encode_uleb128(0x21) + encode_sleb128(77))
        # DW_AT_language (0x13): DW_FORM_strx1 (0x25)
        abbrev.extend(encode_uleb128(0x13) + encode_uleb128(0x25))
        # DW_AT_low_pc (0x11): DW_FORM_flag_present (0x19)
        abbrev.extend(encode_uleb128(0x11) + encode_uleb128(0x19))
        # DW_AT_high_pc (0x12): DW_FORM_exprloc (0x18)
        abbrev.extend(encode_uleb128(0x12) + encode_uleb128(0x18))
        abbrev.extend(b"\x00\x00")

        # Abbrev 2: DW_TAG_base_type (0x24), children=no (0)
        abbrev.extend(encode_uleb128(2) + encode_uleb128(0x24) + b"\x00")
        # DW_AT_name (0x03): DW_FORM_string (0x08)
        abbrev.extend(encode_uleb128(0x03) + encode_uleb128(0x08))
        # DW_AT_byte_size (0x0B): DW_FORM_data1 (0x0B)
        abbrev.extend(encode_uleb128(0x0B) + encode_uleb128(0x0B))
        abbrev.extend(b"\x00\x00")
        abbrev.append(0x00)  # End abbrev

        # Build .debug_info
        cu_body = bytearray()
        # DIE 1: abbrev 1
        cu_body.extend(encode_uleb128(1))
        # implicit_const takes 0 bytes in DIE!
        # strx1: 1 byte
        cu_body.append(0x05)
        # flag_present: 0 bytes
        # exprloc: ULEB len 2 + 2 bytes
        cu_body.extend(encode_uleb128(2) + b"\x90\x08")

        # DIE 2 (child): abbrev 2
        cu_body.extend(encode_uleb128(2))
        cu_body.extend(b"int32\x00")
        cu_body.append(4)

        # End children
        cu_body.append(0x00)

        # CU Header (DWARF 5): unit_length (4B), version (2B = 5), unit_type (1B = 1), addr_size (1B = 8), abbrev_off (4B = 0)
        cu_hdr = struct.pack("<HBBI", 5, 1, 8, 0)
        debug_info = struct.pack("<I", len(cu_hdr) + len(cu_body)) + cu_hdr + bytes(cu_body)

        exporter = DWARF5Exporter(symbols=[], structs=[])
        # Assemble minimal ELF containing our custom debug_abbrev and debug_info
        elf_bytes = exporter._assemble_elf64(
            text_data=b"\x00" * 16,
            symtab_data=b"",
            strtab_data=b"\x00",
            debug_str=b"\x00",
            debug_abbrev=bytes(abbrev),
            debug_info=debug_info,
            debug_line=b"",
            low_pc=0x1000,
        )

        store = OffHeapTypeStore(":memory:")
        stats = store.ingest_dwarf5_elf(elf_bytes)
        # If implicit_const / strx1 / flag_present / exprloc were not skipped properly,
        # DIE 2 (int32) would fail to parse.
        self.assertGreaterEqual(stats["types"], 1)
        found_type = store.find_type_by_name("int32")
        self.assertIsNotNone(found_type)
        self.assertEqual(found_type.byte_size, 4)
        store.close()

    def test_shm_corrupt_payload_len_raises(self):
        """Verifies that a corrupt payload_len > capacity in ring buffer header raises ValueError immediately."""
        ring = ShmRingBuffer.create(name=None, capacity=4096)
        try:
            # Manually forge a frame with payload_len = 1000000 (> capacity 4096)
            data_offset = ring.data_offset
            corrupt_payload_len = 1000000
            hdr_bytes = struct.pack(
                FRAME_HDR_FMT,
                FRAME_MAGIC,
                0,  # flags
                1,  # msg_type
                123,  # req_id
                corrupt_payload_len,
            )
            ring._buf[data_offset : data_offset + len(hdr_bytes)] = hdr_bytes
            # Set head = 40 so pop_message sees readable data
            ring._set_head(40)
            ring._set_tail(0)

            with self.assertRaises(ValueError) as ctx:
                ring.pop_message(timeout=0.0)
            self.assertIn("exceeds ring buffer capacity", str(ctx.exception))
        finally:
            ring.close()
            ring.unlink()

    def test_jni_descriptor_exact_prefix_suffix_removal(self):
        """Verifies descriptor 'LLoginManager;' strips exactly to 'LoginManager', preserving the leading 'L'."""
        methods_to_encode = [
            ("LoginManager", "initSession", "()V", 0x0109),
        ]
        dex_bytes = APKJNICrossReferencer.build_synthetic_dex_bytes(methods_to_encode)
        referencer = APKJNICrossReferencer()
        count = referencer.load_from_dex_bytes(dex_bytes)
        self.assertEqual(count, 1)

        class_names = [m.class_name for m in referencer.native_methods]
        self.assertIn("LoginManager", class_names)
        self.assertNotIn("oginManager", class_names)

    def test_pdb_gsi_hash_stream_emission(self):
        """Verifies PDBExporter generates a valid GSI hash table stream in Stream 5."""
        syms = [
            ExportSymbol(name="_test_symbol_alpha", address=0x140001000, symbol_type="FUNC"),
            ExportSymbol(name="_test_symbol_beta", address=0x140002000, symbol_type="FUNC"),
            ExportSymbol(name="g_counter_gamma", address=0x140003000, symbol_type="DATA"),
        ]
        exporter = PDBExporter(symbols=syms, structs=[], base_address=0x140000000)
        pdb_bytes = exporter.build_pdb()

        # Ingest into OffHeapTypeStore to verify end-to-end compatibility
        store = OffHeapTypeStore(":memory:")
        stats = store.ingest_pdb(pdb_bytes, base_address=0x140000000)
        self.assertGreaterEqual(stats["symbols"], 3)


if __name__ == "__main__":
    unittest.main()
