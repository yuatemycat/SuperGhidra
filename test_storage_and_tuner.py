#!/usr/bin/env python3
"""Comprehensive Verification Test Suite for SuperGhidra Storage Codec & Headless Tuner.

Validates:
  1. Storage Compression Layer (LZ4 & Zstandard L3, 64-bit slot directory, bit-exact roundtrip, >75% reduction)
  2. Python <-> Java SGDB Binary Container Interoperability (export_java_sgdb_file -> Java SuperGhidraBufferFileAdapter -> sync() -> load_java_sgdb_file)
  3. Headless Analyzer Tuner (cascade shield, option verification, script generation, command line building)
"""

import io
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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
    """Tests for the storage compression layer, 64-bit slot directory format, and Python <-> Java SGDB interoperability."""

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
        # Throughput depends on the machine and its current load; only assert on request.
        if os.environ.get("SUPERGHIDRA_PERF_TESTS") == "1":
            self.assertGreater(res_lz4.compress_mb_per_sec, 100.0)
            self.assertGreater(res_lz4.decompress_mb_per_sec, 200.0)

    @unittest.skipUnless(
        (shutil.which("javac") or os.path.isfile(r"E:\03_Devops\JDK\bin\javac.exe"))
        and (shutil.which("java") or os.path.isfile(r"E:\03_Devops\JDK\bin\java.exe"))
        and (
            (Path(os.environ.get("GHIDRA_INSTALL_DIR", r"E:\03_Devops\Ghidra")) / "Ghidra" / "Extensions" / "SuperGhidraCodec" / "lib" / "SuperGhidraCodec.jar").is_file()
            or (Path(__file__).resolve().parent / "ghidra_extension_skeleton" / "build" / "lib" / "SuperGhidraCodec.jar").is_file()
        )
        and (Path(os.environ.get("GHIDRA_INSTALL_DIR", r"E:\03_Devops\Ghidra")) / "Ghidra" / "Framework" / "DB" / "lib" / "DB.jar").is_file(),
        "Requires Java/JDK and Ghidra framework jars",
    )
    def test_python_java_sgdb_interoperability_roundtrip(self):
        """Proves 100% bit-exact Python <-> Java .sgdb container interoperability.

        1. Writes a .sgdb file in Python via export_java_sgdb_file().
        2. Opens and reads it in Java via SuperGhidraBufferFileAdapter, verifies blocks/parameters/freeIndexes,
           modifies block 3, updates parameters & freeIndexes, and calls sync().
        3. Loads the modified .sgdb file back in Python via load_java_sgdb_file() and verifies 100% bit-exact
           contents across all blocks, parameters, and freeIndexes.
        """
        javac_bin = shutil.which("javac") or r"E:\03_Devops\JDK\bin\javac.exe"
        java_bin = shutil.which("java") or r"E:\03_Devops\JDK\bin\java.exe"
        self.assertTrue(os.path.isfile(javac_bin), f"javac not found at {javac_bin}")
        self.assertTrue(os.path.isfile(java_bin), f"java not found at {java_bin}")

        ghidra_dir = Path(os.environ.get("GHIDRA_INSTALL_DIR", r"E:\03_Devops\Ghidra"))
        codec_jar = ghidra_dir / "Ghidra" / "Extensions" / "SuperGhidraCodec" / "lib" / "SuperGhidraCodec.jar"
        if not codec_jar.exists():
            codec_jar = Path(__file__).resolve().parent / "ghidra_extension_skeleton" / "build" / "lib" / "SuperGhidraCodec.jar"
        self.assertTrue(codec_jar.is_file(), f"SuperGhidraCodec.jar not found at {codec_jar}")

        jars = [
            codec_jar,
            ghidra_dir / "Ghidra" / "Framework" / "DB" / "lib" / "DB.jar",
            ghidra_dir / "Ghidra" / "Framework" / "Generic" / "lib" / "Generic.jar",
            ghidra_dir / "Ghidra" / "Framework" / "Utility" / "lib" / "Utility.jar",
            ghidra_dir / "Ghidra" / "Framework" / "Docking" / "lib" / "Docking.jar",
            ghidra_dir / "Ghidra" / "Framework" / "Project" / "lib" / "Project.jar",
            ghidra_dir / "Ghidra" / "Features" / "Base" / "lib" / "Base.jar",
        ]
        cp_sep = ";" if sys.platform == "win32" else ":"

        with tempfile.TemporaryDirectory() as tmpdir:
            sgdb_path = os.path.join(tmpdir, "interop_test.1.sgdb")
            pages = GhidraPageSimulator.generate_database_corpus(num_pages=10, seed=2026)

            # Step 1: Export .sgdb file in Python
            py_bf = CompressedLocalManagedBufferFile(codec="lz4")
            for idx, page in enumerate(pages):
                py_bf.put(page, idx)

            init_params = {"SchemaVersion": 1, "TableCount": 7}
            init_free = [10, 11]
            written_bytes = py_bf.export_java_sgdb_file(
                sgdb_path,
                parameters=init_params,
                free_indexes=init_free,
            )
            self.assertGreater(written_bytes, 64)
            self.assertTrue(os.path.isfile(sgdb_path))

            # Step 2: Open, verify, modify block 3, and sync() in Java
            java_src = Path(tmpdir) / "SgdbInteropDriver.java"
            java_src.write_text(
                """
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import db.buffers.BufferFileManager;
import db.buffers.DataBuffer;
import superghidra.codec.CompressionAlgorithm;
import superghidra.codec.SuperGhidraBufferFileAdapter;
import superghidra.codec.SuperGhidraExtensionPlugin;

public class SgdbInteropDriver {
    public static void main(String[] args) throws Exception {
        File sgdbFile = new File(args[0]);
        byte expectedByte0 = Byte.parseByte(args[1]);
        byte expectedByte3 = Byte.parseByte(args[2]);

        // Verify BufferFileManager factory & version resolution
        BufferFileManager mgr = SuperGhidraExtensionPlugin.createBufferFileManager(sgdbFile.getParentFile(), "interop_test");
        if (mgr.getCurrentVersion() != 1 || !mgr.getBufferFile(1).equals(sgdbFile)) {
            throw new RuntimeException("BufferFileManager failed to resolve version 1 .sgdb file");
        }
        mgr.versionCreated(2, "Java sync v2", 99L);
        mgr.updateEnded(99L);
        if (mgr.getCurrentVersion() != 2) {
            throw new RuntimeException("BufferFileManager versionCreated did not advance version");
        }

        // Verify FLAG_ZSTD_DEFLATE_FALLBACK in CompressionAlgorithm
        byte[] sample = "SuperGhidra Zstd Fallback Verification Payload".repeat(32).getBytes(StandardCharsets.UTF_8);
        byte[] zstdFrame = CompressionAlgorithm.compressFrame(sample, 0, sample.length, CompressionAlgorithm.ZSTD);
        if (!CompressionAlgorithm.isZstdAvailable()) {
            if ((zstdFrame[7] & CompressionAlgorithm.FLAG_ZSTD_DEFLATE_FALLBACK) == 0) {
                throw new RuntimeException("Expected FLAG_ZSTD_DEFLATE_FALLBACK at frame offset 7");
            }
        }
        byte[] zstdRestored = CompressionAlgorithm.decompressFrame(zstdFrame, 0, zstdFrame.length);
        if (!Arrays.equals(sample, zstdRestored)) {
            throw new RuntimeException("ZSTD frame roundtrip mismatch");
        }

        // Open Python-exported .sgdb in Java SuperGhidraBufferFileAdapter
        SuperGhidraBufferFileAdapter adapter = new SuperGhidraBufferFileAdapter(
                sgdbFile, CompressionAlgorithm.LZ4, SuperGhidraBufferFileAdapter.DEFAULT_BUFFER_SIZE, false);
        try {
            if (adapter.getSlotCount() != 10) {
                throw new RuntimeException("Expected 10 slots, got " + adapter.getSlotCount());
            }
            if (adapter.getParameter("SchemaVersion") != 1 || adapter.getParameter("TableCount") != 7) {
                throw new RuntimeException("Parameter mismatch in Java");
            }
            int[] free = adapter.getFreeIndexes();
            if (!Arrays.equals(free, new int[]{10, 11})) {
                throw new RuntimeException("FreeIndexes mismatch in Java: " + Arrays.toString(free));
            }

            DataBuffer b0 = adapter.get(null, 0);
            if (b0 == null || b0.length() != 16384 || b0.getByte(0) != expectedByte0) {
                throw new RuntimeException("Block 0 verification failed in Java");
            }

            DataBuffer b3 = adapter.get(null, 3);
            if (b3 == null || b3.length() != 16384 || b3.getByte(0) != expectedByte3) {
                throw new RuntimeException("Block 3 verification failed in Java");
            }

            // Modify block 3 at offsets 128 and 4096
            byte[] patchA = "JAVA_SGDB_MUTATION_MARKER_ALPHA".getBytes(StandardCharsets.UTF_8);
            byte[] patchB = "JAVA_SGDB_MUTATION_MARKER_OMEGA".getBytes(StandardCharsets.UTF_8);
            b3.put(128, patchA, 0, patchA.length);
            b3.put(4096, patchB, 0, patchB.length);
            adapter.put(b3, 3);

            // Update parameters and freeIndexes and call sync()
            adapter.setParameter("TableCount", 8);
            adapter.setFreeIndexes(new int[]{12, 15});
            adapter.sync();
        } finally {
            adapter.close();
        }
    }
}
""".strip(),
                encoding="utf-8",
            )

            classpath = cp_sep.join([str(tmpdir)] + [str(j) for j in jars if j.exists()])
            compile_proc = subprocess.run(
                [javac_bin, "-encoding", "UTF-8", "-cp", classpath, str(java_src)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                compile_proc.returncode,
                0,
                f"Java test driver compilation failed:\n{compile_proc.stderr}\n{compile_proc.stdout}",
            )

            b0_first = struct.unpack("b", bytes([pages[0].data[0]]))[0]
            b3_first = struct.unpack("b", bytes([pages[3].data[0]]))[0]
            run_proc = subprocess.run(
                [java_bin, "-cp", classpath, "SgdbInteropDriver", sgdb_path, str(b0_first), str(b3_first)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                run_proc.returncode,
                0,
                f"Java test driver execution failed:\n{run_proc.stderr}\n{run_proc.stdout}",
            )

            # Step 3: Load modified .sgdb file back in Python and verify 100% bit-exactness
            loaded_bf = CompressedLocalManagedBufferFile.load_java_sgdb_file(sgdb_path)
            self.assertEqual(len(loaded_bf.slot_directory), 10)
            self.assertEqual(loaded_bf.java_parameters, {"SchemaVersion": 1, "TableCount": 8})
            self.assertEqual(loaded_bf.java_free_indexes, [12, 15])

            expected_b3 = bytearray(pages[3].data)
            patch_a = b"JAVA_SGDB_MUTATION_MARKER_ALPHA"
            patch_b = b"JAVA_SGDB_MUTATION_MARKER_OMEGA"
            expected_b3[128 : 128 + len(patch_a)] = patch_a
            expected_b3[4096 : 4096 + len(patch_b)] = patch_b

            for idx in range(10):
                restored_page = loaded_bf.get(None, idx)
                if idx == 3:
                    self.assertEqual(restored_page.data, expected_b3, "Modified block 3 mismatch after Java sync()")
                else:
                    self.assertEqual(
                        restored_page.data,
                        pages[idx].data,
                        f"Untouched block {idx} mismatch after Java sync()",
                    )


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
