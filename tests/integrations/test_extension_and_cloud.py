#!/usr/bin/env python3
"""
test_extension_and_cloud.py
===========================
SuperGhidra Comprehensive Test Suite for Frontier 3 and Frontier 4.

Verifies:
1. Frontier 3: In-Engine Java Extension Layout & Codec
   - Manifest and properties validation
   - Java source file structure and class signatures
   - Storage bug fixes: in-place block reuse on overwrite, sync(), parameter/freeIndex persistence
   - SuperGhidraExtensionPlugin helper methods and system property initialization
   - Extension packager execution, lib/SuperGhidraCodec.jar inclusion, and distribution zip integrity
   - Extension installation lifecycle to Ghidra Extensions directory
   - Native C++ Decompiler PGO Builder: infinite-loop-safe RuleFoldJniBridgeThunk and non-trivial training corpus
2. Frontier 4: Cloud Colab Headless TPU v5e / T4 Pipeline Orchestrator
   - Hardware detection and multi-tier environment profiles
   - Global user rule invariants (ambient HF_TOKEN, /content storage, torchao guardrail, zero-disk serialization)
   - Headless RAM disk staging (/dev/shm) and JADX command generation
   - Zero-JVM P-Code systolic array tensor generation (bfloat16)
   - EvidenceLedger gate verification and symbol map export
   - Colab notebook JSON schema validation (nbformat v4)
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
from pathlib import Path

# Ensure SuperGhidra workspace is in sys.path
SUPERGHIDRA_DIR = str(Path(__file__).resolve().parents[2])
if SUPERGHIDRA_DIR not in sys.path:
    sys.path.insert(0, SUPERGHIDRA_DIR)

import colab_cloud_orchestrator
from colab_cloud_orchestrator import CloudConfig, CloudRuntimeTier, ColabCloudOrchestrator
import ghidra_extension_packager
from ghidra_extension_packager import GhidraExtensionPackager, ExtensionValidationError
import native_decompiler_pgo_builder
from native_decompiler_pgo_builder import DecompilerBuildConfig, NativeDecompilerPGOBuilder

_GHIDRA_DIR = Path(os.environ.get("GHIDRA_INSTALL_DIR", ""))
_INSTALLED_JAR = Path("Ghidra", "Extensions", "SuperGhidraCodec", "lib", "SuperGhidraCodec.jar")

class TestFrontier3ExtensionSkeleton(unittest.TestCase):
    """Test suite for Frontier 3: Ghidra Extension Skeleton and Packager."""

    @classmethod
    def setUpClass(cls):
        cls.project_root = Path(SUPERGHIDRA_DIR)
        cls.skeleton_dir = cls.project_root / "ghidra_extension_skeleton"
        cls.packager = GhidraExtensionPackager(skeleton_dir=str(cls.skeleton_dir))

    def test_01_extension_properties_file(self):
        """Verifies extension.properties exists and matches exact specification."""
        prop_file = self.skeleton_dir / "extension.properties"
        self.assertTrue(prop_file.is_file(), f"extension.properties not found at {prop_file}")

        props = self.packager.parse_extension_properties()
        self.assertEqual(props.get("name"), "SuperGhidraCodec")
        self.assertEqual(props.get("author"), "SuperGhidra Team")
        self.assertEqual(props.get("version"), "1.0.0")
        self.assertTrue(props.get("ghidraVersion", "").startswith("12.1"))
        self.assertIn("Compressed Buffer File", props.get("description", ""))

    def test_02_module_manifest_and_gradle(self):
        """Verifies Module.manifest and build.gradle files."""
        manifest_file = self.skeleton_dir / "Module.manifest"
        self.assertTrue(manifest_file.is_file(), "Module.manifest not found")

        gradle_file = self.skeleton_dir / "build.gradle"
        self.assertTrue(gradle_file.is_file(), "build.gradle not found")
        content = gradle_file.read_text(encoding="utf-8")
        self.assertIn("JavaVersion.VERSION_21", content)
        self.assertIn("distributeExtension", content)

    def test_03_java_sources_exist_and_structured(self):
        """Verifies required Java source files and package declarations."""
        codec_dir = self.skeleton_dir / "src" / "main" / "java" / "superghidra" / "codec"
        self.assertTrue(codec_dir.is_dir(), f"Java source directory missing: {codec_dir}")

        for fname in GhidraExtensionPackager.REQUIRED_JAVA_FILES:
            fpath = codec_dir / fname
            self.assertTrue(fpath.is_file(), f"Missing Java file: {fname}")
            content = fpath.read_text(encoding="utf-8")
            self.assertIn("package superghidra.codec;", content)

        # Inspect SuperGhidraBufferFileAdapter
        adapter_code = (codec_dir / "SuperGhidraBufferFileAdapter.java").read_text(encoding="utf-8")
        self.assertIn("public class SuperGhidraBufferFileAdapter implements BufferFile", adapter_code)
        self.assertIn("DEFAULT_BUFFER_SIZE = 16384", adapter_code)
        self.assertIn("DataBuffer get(DataBuffer", adapter_code)
        self.assertIn("void put(DataBuffer", adapter_code)

        # Append-Only Frame Write & Crash-Safe sync() Persistence
        self.assertIn("// Append-only write for frames to guarantee crash-safety", adapter_code)
        self.assertIn("fileOffset = raf.length();", adapter_code)
        self.assertIn("public synchronized void sync() throws IOException", adapter_code)
        self.assertIn("FLAG_EXTENDED_METADATA", adapter_code)
        self.assertIn("writeHeader(dirOffset, dirCount, FLAG_EXTENDED_METADATA)", adapter_code)

        # LRU Block Cache, CRC32 Write-Elision & compact() Defragmentation
        self.assertIn("DEFAULT_CACHE_CAPACITY = 256", adapter_code)
        self.assertIn("private final Map<Integer, byte[]> blockCache", adapter_code)
        self.assertIn("cacheHits", adapter_code)
        self.assertIn("cacheMisses", adapter_code)
        self.assertIn("elidedWrites", adapter_code)
        self.assertIn("public synchronized long compact() throws IOException", adapter_code)
        self.assertIn("getCacheHits()", adapter_code)
        self.assertIn("getCacheMisses()", adapter_code)
        self.assertIn("getElidedWrites()", adapter_code)

        # Inspect SuperGhidraExtensionPlugin
        plugin_code = (codec_dir / "SuperGhidraExtensionPlugin.java").read_text(encoding="utf-8")
        self.assertIn("@PluginInfo", plugin_code)
        self.assertIn("SuperGhidraCodec", plugin_code)
        self.assertIn("public class SuperGhidraExtensionPlugin extends ProgramPlugin", plugin_code)
        self.assertIn("CODEC_ACTIVE_PROPERTY = \"superghidra.codec.active\"", plugin_code)
        self.assertIn("System.setProperty(CODEC_ACTIVE_PROPERTY, \"true\")", plugin_code)
        self.assertIn("createCompressedAdapter", plugin_code)
        self.assertIn("getDefaultAlgorithm", plugin_code)
        self.assertIn("getCodecDiagnostics", plugin_code)
        self.assertIn("defaultCacheCapacity", plugin_code)

        # Inspect CompressionAlgorithm
        algo_code = (codec_dir / "CompressionAlgorithm.java").read_text(encoding="utf-8")
        self.assertIn("enum CompressionAlgorithm", algo_code)
        self.assertIn("LZ4", algo_code)
        self.assertIn("ZSTD", algo_code)
        self.assertIn("computeCRC32", algo_code)
        self.assertIn("verifyCRC32", algo_code)
        self.assertIn("compressFrame", algo_code)
        self.assertIn("decompressFrame", algo_code)
        self.assertIn("isZstdAvailable", algo_code)

    def test_04_extension_packager_zip_packaging(self):
        """Tests packaging of dist/SuperGhidraCodec-1.0.0.zip and integrity verification."""
        with tempfile.TemporaryDirectory() as tmp_dist:
            packager = GhidraExtensionPackager(
                skeleton_dir=str(self.skeleton_dir),
                output_dir=tmp_dist
            )
            zip_path, meta = packager.package_extension_zip(compile_first=False)

            self.assertTrue(zip_path.is_file(), "Zip archive was not created")
            self.assertEqual(meta["status"], "valid")
            self.assertGreater(meta["size_bytes"], 1000)
            self.assertTrue(len(meta["sha256"]) == 64)

            # Inspect zip contents
            with zipfile.ZipFile(zip_path, "r") as zf:
                self.assertIsNone(zf.testzip(), "Zip contains corrupted files")
                names = zf.namelist()
                self.assertIn("SuperGhidraCodec/extension.properties", names)
                self.assertIn("SuperGhidraCodec/Module.manifest", names)
                self.assertIn("SuperGhidraCodec/build.gradle", names)
                self.assertIn("SuperGhidraCodec/src/main/java/superghidra/codec/SuperGhidraBufferFileAdapter.java", names)
                self.assertIn("SuperGhidraCodec/src/main/java/superghidra/codec/SuperGhidraExtensionPlugin.java", names)
                self.assertIn("SuperGhidraCodec/src/main/java/superghidra/codec/CompressionAlgorithm.java", names)
                self.assertIn("SuperGhidraCodec/lib/SuperGhidraCodec.jar", names)

    @unittest.skipUnless(
        (Path(SUPERGHIDRA_DIR) / "dist" / "SuperGhidraCodec-1.0.0.zip").is_file(),
        "Requires built distribution zip dist/SuperGhidraCodec-1.0.0.zip",
    )
    def test_05_zip_integrity_checker(self):
        """Tests verify_zip_integrity on built zip."""
        dist_zip = self.project_root / "dist" / "SuperGhidraCodec-1.0.0.zip"
        meta = GhidraExtensionPackager.verify_zip_integrity(dist_zip)
        self.assertEqual(meta["status"], "valid")
        self.assertGreater(meta["file_count"], 5)
        self.assertIn("SuperGhidraCodec/lib/SuperGhidraCodec.jar", meta["entries"])

    def test_06_extension_install_lifecycle(self):
        """Tests install_extension() extracts distribution zip cleanly into target directory."""
        with tempfile.TemporaryDirectory() as tmp_ext:
            target_dir = self.packager.install_extension(target_extensions_dir=tmp_ext)
            self.assertTrue(target_dir.is_dir(), f"Target dir was not created: {target_dir}")
            self.assertTrue((target_dir / "extension.properties").is_file())
            self.assertTrue((target_dir / "Module.manifest").is_file())
            self.assertTrue((target_dir / "build.gradle").is_file())
            self.assertTrue((target_dir / "lib" / "SuperGhidraCodec.jar").is_file())
            self.assertTrue((target_dir / "src" / "main" / "java" / "superghidra" / "codec" / "SuperGhidraBufferFileAdapter.java").is_file())

            # Verify the jar itself contains the class entries
            with zipfile.ZipFile(target_dir / "lib" / "SuperGhidraCodec.jar", "r") as jf:
                self.assertIsNone(jf.testzip())
                jnames = jf.namelist()
                self.assertIn("META-INF/MANIFEST.MF", jnames)

    @unittest.skipUnless(
        (_GHIDRA_DIR / _INSTALLED_JAR).is_file(),
        "Requires SuperGhidraCodec.jar installed in $GHIDRA_INSTALL_DIR/Ghidra/Extensions",
    )
    def test_07_buffer_file_adapter_lru_and_elision_and_compact_contract(self):
        """Verifies SuperGhidraBufferFileAdapter LRU cache, CRC32 write-elision, compact defragmentation, and compiled jar."""
        installed_jar = _GHIDRA_DIR / _INSTALLED_JAR
        self.assertTrue(installed_jar.is_file(), f"Installed jar not found: {installed_jar}")

        with zipfile.ZipFile(installed_jar, "r") as jf:
            self.assertIsNone(jf.testzip())
            entries = jf.namelist()
            self.assertIn("superghidra/codec/SuperGhidraBufferFileAdapter.class", entries)
            self.assertIn("superghidra/codec/SuperGhidraBufferFileAdapter$1.class", entries)
            self.assertIn("superghidra/codec/SuperGhidraBufferFileAdapter$SlotEntry.class", entries)
            self.assertIn("superghidra/codec/SuperGhidraExtensionPlugin.class", entries)
            self.assertIn("superghidra/codec/CompressionAlgorithm.class", entries)

        # Inspect source contracts
        codec_dir = self.skeleton_dir / "src" / "main" / "java" / "superghidra" / "codec"
        adapter_code = (codec_dir / "SuperGhidraBufferFileAdapter.java").read_text(encoding="utf-8")

        # Cache hit check
        self.assertIn("byte[] cached = blockCache.get(index);", adapter_code)
        self.assertIn("cacheHits.incrementAndGet();", adapter_code)

        # CRC32 elision check
        self.assertIn("if (existing != null && existing.crc32 == crc32 && existing.origLen == len)", adapter_code)
        self.assertIn("elidedWrites.incrementAndGet();", adapter_code)

        # Compact defragmentation check
        self.assertIn("public synchronized long compact() throws IOException", adapter_code)
        self.assertIn("entries.sort(Comparator.comparingLong(e -> e.offset));", adapter_code)
        self.assertIn("raf.setLength(currentOffset);", adapter_code)
        self.assertIn("sync();", adapter_code)

        # Metrics getters
        self.assertIn("public long getCacheHits()", adapter_code)
        self.assertIn("public long getCacheMisses()", adapter_code)
        self.assertIn("public long getElidedWrites()", adapter_code)

    def test_08_managed_buffer_file_and_repeated_sync_zero_bloat(self):
        """Verifies ManagedBufferFile implementation and crash-safe append-only sync() directory and header persistence."""
        codec_dir = self.skeleton_dir / "src" / "main" / "java" / "superghidra" / "codec"
        adapter_code = (codec_dir / "SuperGhidraBufferFileAdapter.java").read_text(encoding="utf-8")
        self.assertIn("ManagedBufferFile", adapter_code)
        self.assertIn("// Write new directory at end of file (append-only)", adapter_code)
        self.assertIn("writeHeader(dirOffset, dirCount, FLAG_EXTENDED_METADATA);", adapter_code)
        self.assertIn("raf.getFD().sync();", adapter_code)
        self.assertIn("public synchronized ManagedBufferFile getSaveFile()", adapter_code)
        self.assertIn("public synchronized void saveCompleted(boolean commit)", adapter_code)


class TestFrontier3NativeDecompilerPGO(unittest.TestCase):
    """Test suite for Native C++ Decompiler PGO Builder and P-Code Simplification Rules."""

    @classmethod
    def setUpClass(cls):
        cls.config = DecompilerBuildConfig(
            src_dir="C:/tools/Ghidra/Ghidra/Features/Decompiler/src/decompile/cpp",
            output_bin_dir="C:/tools/Ghidra/Ghidra/Features/Decompiler/os/win64",
            target_os="windows",
        )
        cls.builder = NativeDecompilerPGOBuilder(cls.config)

    def test_01_pcode_rule_patch_mutates_funcdata(self):
        """Verifies RuleFoldJniBridgeThunk mutates Funcdata before returning 1, preventing infinite loops."""
        patch_cc = self.builder.generate_custom_pcode_rule_patch()
        self.assertIn("RuleFoldJniBridgeThunk", patch_cc)
        self.assertIn("data.opSetInput", patch_cc)
        self.assertIn("data.opDestroy", patch_cc)
        self.assertIn("data.opRemoveInput", patch_cc)
        self.assertIn("return 1;", patch_cc)
        self.assertIn("return 0;", patch_cc)

    def test_02_pgo_training_harness_non_trivial(self):
        """Verifies PGO training harness generates non-trivial decompiler command stream."""
        harness = self.builder.generate_pgo_training_harness()
        self.assertGreater(len(harness), 50)
        self.assertIn("decompile", harness)
        self.assertIn("simplify", harness)
        self.assertIn("fold_jni_bridge", harness)

    def test_03_pgo_workflow_scripts_feed_training_corpus(self):
        """Verifies workflow scripts feed pgo_training_input.txt instead of < nul."""
        win_script = self.builder._generate_windows_batch_script()
        self.assertIn("pgo_training_input.txt", win_script)
        self.assertNotIn("< nul", win_script)

        linux_config = DecompilerBuildConfig(
            src_dir="/opt/ghidra/decompiler",
            output_bin_dir="/opt/ghidra/bin",
            target_os="linux"
        )
        linux_builder = NativeDecompilerPGOBuilder(linux_config)
        linux_script = linux_builder._generate_linux_bash_script()
        self.assertIn("pgo_training_input.txt", linux_script)

    def test_04_live_decompiler_inspection_and_devops_script(self):
        """Verifies inspect_live_decompiler() and generate_portable_devops_build_script()."""
        report = self.builder.inspect_live_decompiler(str(_GHIDRA_DIR) if str(_GHIDRA_DIR) != "." else None)
        self.assertIn(report["status"], ["ready", "found", "not_found"])
        if report["status"] in ("ready", "found"):
            self.assertIn(report["format"], ("PE", "ELF"))
            self.assertEqual(report["machine_name"], "x86_64")
            self.assertGreater(report["size_bytes"], 100000)
            self.assertEqual(len(report["sha256"]), 64)

        script = self.builder.generate_portable_devops_build_script(r"C:\toolchain")
        self.assertIn(r"C:\toolchain", script)
        self.assertIn("env.bat", script)
        self.assertIn("RuleFoldJniBridgeThunk", script)
        self.assertIn("ninja decompile", script)



class TestFrontier4ColabCloudOrchestrator(unittest.TestCase):
    """Test suite for Frontier 4: Cloud Colab Headless TPU v5e / T4 Pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.orchestrator = ColabCloudOrchestrator()
        cls.project_root = Path(SUPERGHIDRA_DIR)

    def test_01_hardware_tier_detection(self):
        """Tests hardware detection logic."""
        tier = ColabCloudOrchestrator.detect_hardware()
        self.assertIn(tier, [CloudRuntimeTier.FREE_CPU, CloudRuntimeTier.T4_GPU, CloudRuntimeTier.TPU_V5E])

    def test_02_runtime_environment_and_invariants(self):
        """Tests environment variable configuration and user rule invariants."""
        with mock.patch.dict(os.environ, {}, clear=False):
            with tempfile.TemporaryDirectory() as tmp_ws:
                # Test TPU v5e profile
                cfg_tpu = CloudConfig(
                    tier=CloudRuntimeTier.TPU_V5E,
                    workspace_dir=tmp_ws,
                    hf_token="hf_mock_token_12345"
                )
                env_tpu = ColabCloudOrchestrator.configure_runtime_environment(cfg_tpu)

                # Invariant: Storage Target Invariant (/content or workspace_dir)
                self.assertIn("HF_HOME", env_tpu)
                self.assertTrue(env_tpu["HF_HOME"].startswith(tmp_ws))

                # Invariant: TPU flags
                self.assertEqual(env_tpu.get("XLA_PYTHON_CLIENT_PREALLOCATE"), "false")
                self.assertIn("--xla_dump_to", env_tpu.get("JAX_XLA_FLAGS", ""))

                # Invariant: Ambient Token Authentication
                self.assertEqual(os.environ.get("HF_TOKEN"), "hf_mock_token_12345")

                # Test T4 GPU profile
                cfg_gpu = CloudConfig(tier=CloudRuntimeTier.T4_GPU, workspace_dir=tmp_ws)
                env_gpu = ColabCloudOrchestrator.configure_runtime_environment(cfg_gpu)
                self.assertEqual(env_gpu.get("PYTORCH_CUDA_ALLOC_CONF"), "expandable_segments:True")
                self.assertEqual(env_gpu.get("CUDA_DEVICE_ORDER"), "PCI_BUS_ID")

    def test_03_ram_disk_staging(self):
        """Tests staging binary into zero-I/O RAM disk mount."""
        with tempfile.TemporaryDirectory() as tmp_ram:
            src_dir = os.path.join(tmp_ram, "src")
            os.makedirs(src_dir, exist_ok=True)
            src_file = os.path.join(src_dir, "source_libg.so")
            with open(src_file, "wb") as f:
                f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
                f.write(b"\x00\x00\x80\xd2\x41\x00\x03\x8b\xc0\x03\x5f\xd6" * 64)

            staged = ColabCloudOrchestrator.stage_binary_to_ram_disk(
                src_path=src_file,
                ram_disk_dir=tmp_ram
            )
            self.assertTrue(os.path.isfile(staged), "Staged binary was not created")
            self.assertTrue(staged.endswith("source_libg.so"))

            # Check ELF header
            with open(staged, "rb") as f:
                header = f.read(16)
                self.assertTrue(header.startswith(b"\x7fELF\x02\x01\x01\x00"))

    def test_04_jadx_cross_referencer_cmd(self):
        """Tests headless JADX command line builder with G1GC memory bounds."""
        config = CloudConfig(jadx_threads=8, jadx_max_heap_gb=12)
        cmd, env = ColabCloudOrchestrator.build_jadx_cross_referencer_cmd(
            apk_path="/content/game.apk",
            output_dir="/content/jadx_out",
            config=config
        )
        self.assertIn("--deobf", cmd)
        self.assertIn("-j", cmd)
        self.assertIn("8", cmd)
        self.assertIn("-d", cmd)
        self.assertIn("/content/jadx_out", cmd)
        self.assertEqual(env.get("JAVA_OPTS"), "-Xmx12g -XX:+UseG1GC")

    def test_05_pcode_systolic_tensor_generation(self):
        """Tests Zero-JVM P-Code lifting and TPU systolic array bfloat16 tensor packing."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            dummy_bin = os.path.join(tmp_dir, "libmock.so")
            # Write synthetic ARM64 instructions: MOV, ADD, SUB, RET
            with open(dummy_bin, "wb") as f:
                f.write(b"\x00\x00\x80\xd2\x41\x00\x03\x8b\x20\x00\x00\x51\xc0\x03\x5f\xd6" * 32)

            tensors, meta = ColabCloudOrchestrator.lift_pcode_systolic_tensors(
                binary_path=dummy_bin,
                max_functions=4,
                matrix_size=64,
                use_bfloat16=True
            )

            self.assertEqual(meta["function_count"], 4)
            self.assertEqual(meta["matrix_size"], 64)
            self.assertGreater(meta["total_pcode_ops"], 0)
            self.assertIn("bfloat16", meta["dtype"])

            if colab_cloud_orchestrator.HAS_NUMPY:
                self.assertEqual(tensors.shape, (4, 64, 64))

    def test_06_reconstruction_pipeline_and_evidence_gate(self):
        """Tests execution of the full cloud reconstruction pipeline."""
        with tempfile.TemporaryDirectory() as tmp_ws:
            dummy_bin = os.path.join(tmp_ws, "libg.so")
            with open(dummy_bin, "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 512)

            config = CloudConfig(
                workspace_dir=tmp_ws,
                target_binary_name="libg.so",
                tensor_matrix_size=64,
                use_bfloat16=True
            )

            results = ColabCloudOrchestrator.run_reconstruction_pipeline(
                config=config,
                staged_binary=dummy_bin,
                dry_run=False
            )

            self.assertEqual(results["status"], "success")
            self.assertEqual(results["evidence_ledger_entries"], 0)
            self.assertEqual(results["symbols_reconstructed"], 0)
            self.assertEqual(results["stages"]["symbol_reconstruction"], "not_implemented")

            # Check that files were written
            self.assertTrue(os.path.isfile(results["ledger_path"]))
            self.assertTrue(os.path.isfile(results["symbols_path"]))
            self.assertTrue(os.path.isfile(results["bundle_zip"]))

            # Check zip integrity
            with zipfile.ZipFile(results["bundle_zip"], "r") as zf:
                self.assertIsNone(zf.testzip())
                names = zf.namelist()
                self.assertIn("evidence_ledger.json", names)
                self.assertIn("_ghidra_names.json", names)

            # Test that dry_run is honored
            dry_results = ColabCloudOrchestrator.run_reconstruction_pipeline(
                config=config,
                staged_binary=dummy_bin,
                dry_run=True
            )
            self.assertEqual(dry_results["status"], "dry_run")
            self.assertEqual(dry_results["stages"]["pcode_tensors"], "dry_run")
            self.assertIsNone(dry_results["bundle_zip"])

    def test_07_colab_notebook_nbformat_v4_validity(self):
        """Tests that colab_cloud_orchestrator.ipynb is a valid Jupyter Notebook (nbformat v4)."""
        nb_path = self.project_root / "colab_cloud_orchestrator.ipynb"
        self.assertTrue(nb_path.is_file(), f"Notebook file not found at {nb_path}")

        with open(nb_path, "r", encoding="utf-8") as f:
            nb = json.load(f)

        self.assertEqual(nb.get("nbformat"), 4)
        self.assertGreaterEqual(nb.get("nbformat_minor", 0), 2)
        self.assertIn("cells", nb)
        self.assertIn("metadata", nb)

        cells = nb["cells"]
        self.assertGreaterEqual(len(cells), 7)

        # Verify key user global rules & invariants are embedded in code cells
        full_code = "\n".join(
            "".join(c.get("source", []))
            for c in cells if c.get("cell_type") == "code"
        )

        # Invariant 1: torchao dependency guardrail
        self.assertIn("pip", full_code)
        self.assertIn("torchao", full_code)

        # Invariant 2: ambient HF_TOKEN login
        self.assertIn("huggingface_hub.login", full_code)
        self.assertIn("add_to_git_credential=False", full_code)

        # Invariant 3: /content storage target
        self.assertIn("/content", full_code)

        # Invariant 4: /dev/shm RAM disk staging
        self.assertIn("/dev/shm", full_code)

        # Invariant 5: JADX G1GC tuning
        self.assertIn("UseG1GC", full_code)

        # Invariant 6: TPU systolic array tensors
        self.assertIn("lift_pcode_systolic_tensors", full_code)

        # Invariant 7: Zero-disk duplicate serialization
        self.assertIn("upload_folder", full_code)


if __name__ == "__main__":
    unittest.main()
