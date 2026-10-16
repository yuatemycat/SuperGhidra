#!/usr/bin/env python3
"""Comprehensive Verification Test Suite for SuperGhidra.

Validates:
  1. Storage Compression Layer (LZ4 & Zstandard L3, 64-bit slot directory, bit-exact roundtrip, >75% reduction)
  2. Headless Analyzer Tuner (cascade shield, option verification, script generation, command line building)
  3. PyGhidra integration and analyzer options consistency
"""

import io
import os
import random
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from storage_compression_prototype import (
    GHIDRA_BLOCK_SIZE,
    GHIDRA_BUFFER_SIZE,
    GHIDRA_HEADER_SIZE,
    SLOT_ENTRY_SIZE,
    CompressedLocalManagedBufferFile,
    DataBuffer,
    GhidraPageSimulator,
    SlotDirectory,
    SlotDirectoryEntry,
    StorageCompressionBenchmark,
)

from headless_analyzer_tuner import (
    AnalyzerConfiguration,
    AnalyzerProfileName,
    HeadlessCommandBuilder,
    ScriptGenerator,
    get_profile_config,
)


class TestStorageCompressionLayer(unittest.TestCase):
    """Tests for the storage compression layer and 64-bit slot directory format."""

    def test_slot_directory_entry_pack_unpack(self):
        """Verifies 20-byte [block_id: uint32, offset: uint64, comp_len: uint32, orig_len: uint32] layout."""
        self.assertEqual(SLOT_ENTRY_SIZE, 20)
        entry = SlotDirectoryEntry(block_id=1024, offset=0x0000000100004000, comp_len=1850, orig_len=16389)
        packed = entry.pack()
        self.assertEqual(len(packed), 20)

        unpacked = SlotDirectoryEntry.unpack(packed)
        self.assertEqual(unpacked.block_id, 1024)
        self.assertEqual(unpacked.offset, 0x0000000100004000)
        self.assertEqual(unpacked.comp_len, 1850)
        self.assertEqual(unpacked.orig_len, 16389)

    def test_slot_directory_serialization(self):
        """Tests serializing and deserializing multiple slot directory records."""
        sd = SlotDirectory()
        for i in range(50):
            sd.set_entry(SlotDirectoryEntry(
                block_id=i,
                offset=i * 2048,
                comp_len=1500 + i,
                orig_len=GHIDRA_BLOCK_SIZE
            ))
        serialized = sd.serialize()
        self.assertEqual(len(serialized), 50 * SLOT_ENTRY_SIZE)

        sd_restored = SlotDirectory.deserialize(serialized)
        self.assertEqual(len(sd_restored), 50)
        for i in range(50):
            entry = sd_restored.get_entry(i)
            self.assertIsNotNone(entry)
            self.assertEqual(entry.block_id, i)
            self.assertEqual(entry.offset, i * 2048)
            self.assertEqual(entry.comp_len, 1500 + i)

    def test_data_buffer_serialization(self):
        """Tests DataBuffer raw Ghidra block layout (flags + id + data)."""
        raw_data = bytearray(os.urandom(GHIDRA_BUFFER_SIZE))
        buf = DataBuffer(buffer_id=42, data=raw_data, empty=False)
        serialized = buf.serialize()
        self.assertEqual(len(serialized), GHIDRA_BLOCK_SIZE)

        restored = DataBuffer.deserialize(serialized)
        self.assertEqual(restored.buffer_id, 42)
        self.assertFalse(restored.empty)
        self.assertEqual(restored.data, raw_data)

        # Empty buffer test
        empty_buf = DataBuffer(buffer_id=99, empty=True)
        serialized_empty = empty_buf.serialize()
        self.assertEqual(len(serialized_empty), GHIDRA_HEADER_SIZE)
        restored_empty = DataBuffer.deserialize(serialized_empty)
        self.assertEqual(restored_empty.buffer_id, 99)
        self.assertTrue(restored_empty.empty)

    def test_compressed_buffer_file_lz4_roundtrip(self):
        """Tests LZ4 backend put() and get() random access with lossless fidelity."""
        stream = io.BytesIO()
        backend = CompressedLocalManagedBufferFile(backing_stream=stream, codec="lz4")

        # Generate 20 diverse pages
        pages = GhidraPageSimulator.generate_database_corpus(num_pages=20, seed=123)
        for i, page in enumerate(pages):
            backend.put(page, i)

        backend.finalize_file()
        self.assertEqual(len(backend.slot_directory), 20)

        # Test random access retrieval in non-sequential order
        order = list(range(20))
        random.Random(999).shuffle(order)
        for idx in order:
            restored = backend.get(None, idx)
            self.assertEqual(restored.buffer_id, pages[idx].buffer_id)
            self.assertEqual(restored.data, pages[idx].data)

    def test_compressed_buffer_file_zstd_roundtrip(self):
        """Tests ZSTD Level 3 backend put() and get() with lossless fidelity."""
        stream = io.BytesIO()
        backend = CompressedLocalManagedBufferFile(backing_stream=stream, codec="zstd")

        pages = GhidraPageSimulator.generate_database_corpus(num_pages=20, seed=456)
        for i, page in enumerate(pages):
            backend.put(page, i)

        backend.finalize_file()
        self.assertEqual(len(backend.slot_directory), 20)

        for idx in range(20):
            restored = backend.get(None, idx)
            self.assertEqual(restored.buffer_id, pages[idx].buffer_id)
            self.assertEqual(restored.data, pages[idx].data)

    def test_compression_ratio_meets_target(self):
        """Verifies that both LZ4 and ZSTD achieve > 75% reduction on Ghidra B-tree pages."""
        pages = GhidraPageSimulator.generate_database_corpus(num_pages=100, seed=777)
        res_lz4 = StorageCompressionBenchmark.run_codec_benchmark(pages, codec="lz4")
        res_zstd = StorageCompressionBenchmark.run_codec_benchmark(pages, codec="zstd")

        print(f"\n[Test] LZ4 Reduction: {res_lz4.reduction_pct:.2f}% (Ratio: {res_lz4.compression_ratio:.2f}x)")
        print(f"[Test] ZSTD Reduction: {res_zstd.reduction_pct:.2f}% (Ratio: {res_zstd.compression_ratio:.2f}x)")

        self.assertGreater(res_lz4.reduction_pct, 75.0, "LZ4 must achieve > 75% reduction")
        self.assertGreater(res_zstd.reduction_pct, 75.0, "Zstandard L3 must achieve > 75% reduction")
        self.assertTrue(res_lz4.verified_lossless)
        self.assertTrue(res_zstd.verified_lossless)
        self.assertGreater(res_lz4.compress_mb_per_sec, 200.0)
        self.assertGreater(res_lz4.decompress_mb_per_sec, 400.0)


class TestHeadlessAnalyzerTuner(unittest.TestCase):
    """Tests for the headless auto-analysis tuning and cascade shield."""

    def test_cascade_shield_invariants(self):
        """Guarantees that Non-Returning Functions - Discovered and Repair Flow Damage are always FALSE."""
        for profile in [AnalyzerProfileName.LEAN, AnalyzerProfileName.DECOMP_READY, AnalyzerProfileName.FULL_GUARDED]:
            cfg = get_profile_config(profile)
            opts = cfg.to_ghidra_options_map()

            # Cascade shield invariants
            self.assertEqual(opts["Non-Returning Functions - Discovered"], "false",
                             f"Profile {profile.value} must disable Non-Returning Functions - Discovered")
            self.assertEqual(opts["Repair Flow Damage"], "false",
                             f"Profile {profile.value} must disable Repair Flow Damage")

            # Safe static detection invariant
            self.assertEqual(opts["Non-Returning Functions - Known"], "true",
                             f"Profile {profile.value} must retain Non-Returning Functions - Known")

    def test_prescript_java_generation(self):
        """Verifies generated Java PreScript syntax and option bindings."""
        cfg = get_profile_config(AnalyzerProfileName.DECOMP_READY)
        java_code = ScriptGenerator.generate_prescript_java(cfg, "SuperGhidraTestPreScript")

        self.assertIn("public class SuperGhidraTestPreScript extends GhidraScript", java_code)
        self.assertIn('setAnalysisOption(currentProgram, "Non-Returning Functions - Discovered", "false");', java_code)
        self.assertIn('setAnalysisOption(currentProgram, "Repair Flow Damage", "false");', java_code)
        self.assertIn('setAnalysisOption(currentProgram, "Non-Returning Functions - Known", "true");', java_code)
        self.assertIn('setAnalysisOption(currentProgram, "Decompiler Switch Analysis", "true");', java_code)

    def test_lazy_noreturn_postscript_safety(self):
        """Verifies that the Lazy NoReturn PostScript does NOT invoke ClearFlowAndRepairCmd."""
        java_code = ScriptGenerator.generate_lazy_noreturn_postscript_java()
        py_code = ScriptGenerator.generate_lazy_noreturn_postscript_python()

        # Must NOT call ClearFlowAndRepairCmd
        self.assertNotIn("ClearFlowAndRepairCmd", java_code)
        self.assertNotIn("clearFlowAndRepair", java_code)
        self.assertNotIn("ClearFlowAndRepairCmd", py_code)

        # Must set noReturn safely
        self.assertIn("fn.setNoReturn(true);", java_code)
        self.assertIn("fn.setNoReturn(True)", py_code)

        # Must use transactions
        self.assertIn("currentProgram.startTransaction", java_code)
        self.assertIn("currentProgram.endTransaction", java_code)

    def test_headless_command_builder(self):
        """Tests analyzeHeadless CLI argument construction."""
        builder = HeadlessCommandBuilder(
            ghidra_install_dir="E:\\03_Devops\\Ghidra",
            project_location="E:\\02_Projects\\SuperGhidra\\workspace",
            project_name="TestProject",
            import_target="E:\\03_Devops\\libc_arm64.so",
            pre_script="SuperGhidraPreScript.java",
            post_script="SuperGhidraLazyNoReturnPostScript.java",
            script_dir="E:\\02_Projects\\SuperGhidra\\scripts",
            timeout_seconds=300,
            max_cpu=8,
            read_only=True,
            delete_project=False,
        )
        args = builder.build_command_args()
        cli_str = builder.build_cli_string()

        self.assertIn("-import", args)
        self.assertIn("E:\\03_Devops\\libc_arm64.so", args)
        self.assertIn("-preScript", args)
        self.assertIn("SuperGhidraPreScript.java", args)
        self.assertIn("-postScript", args)
        self.assertIn("SuperGhidraLazyNoReturnPostScript.java", args)
        self.assertIn("-analysisTimeoutPerFile", args)
        self.assertIn("300", args)
        self.assertIn("-max-cpu", args)
        self.assertIn("8", args)
        self.assertIn("-readOnly", args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
