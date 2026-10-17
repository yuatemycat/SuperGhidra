"""
test_spec_reformation_suite.py
==============================
SuperGhidra Full Test Suite for GHIDRA_REFORMATION_ARCHITECTURAL_SPEC.md (Sections 5, 6, 7).

Tests all 5 newly implemented modules:
1. `apk_jni_cross_referencer.py` (Section 5.1):
   - JNI name mangling and signature long/short export symbol construction.
   - DEX method registration and ELF dynamic export symbol matching.
   - 64-bit and 32-bit `RegisterNatives` array parsing (`JNINativeMethod` layout).
   - Ghidra Python post-script generation.
2. `cross_platform_headless_harness.py` (Section 5.1 & 5.2):
   - PE Loader & ELF Loader optimal argument generation.
   - Core allocation, RAM disk `/dev/shm` detection, and timeout options.
   - JADX deobfuscation command building with G1GC memory bounds.
   - Colab T4 GPU and Cloud TPU v5e environment configuration.
3. `pcode_lifter_bridge.py` (Section 6 & 7):
   - Zero-JVM ARM64 instruction lifting (RET, BL, B, MOVZ, ADRP, ADD, SUB, LDR, STR).
   - Contiguous block disassembly into structured P-Code IR.
   - Fixed-shape CFG adjacency matrix generation for GNNs / TPU systolic arrays.
4. `native_decompiler_pgo_builder.py` (Section 6):
   - CMakeLists.txt generation with -O3, LTO, and 2-phase PGO flags.
   - C++ P-Code `RuleFoldJniBridgeThunk` simplification patch generation.
   - Tuned `DecompileOptions` XML configuration.
5. `neural_decompiler_pipeline.py` (Section 7):
   - Phase-A Skeleton Extraction (variable normalization, displacement recovery).
   - Phase-B Neural Prediction simulation.
   - EvidenceLedger verification gate preventing hallucinated field offsets.
"""

from __future__ import annotations

import os
import struct
import sys
import unittest

# Ensure local SuperGhidra directory is first in sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from apk_jni_cross_referencer import (
    APKJNICrossReferencer,
    construct_static_jni_symbol,
    mangle_jni_identifier,
)
from cross_platform_headless_harness import (
    HeadlessEnvironmentConfigurator,
    HeadlessProfile,
)
from native_decompiler_pgo_builder import (
    DecompilerBuildConfig,
    NativeDecompilerPGOBuilder,
)
from neural_decompiler_pipeline import (
    NeuralDecompilerPipeline,
    SkeletonExtractor,
)
from pcode_lifter_bridge import (
    AddressSpace,
    ARM64PcodeLifter,
    PcodeGraphBuilder,
    PcodeOpcode,
)


class TestAPKJNICrossReferencer(unittest.TestCase):
    """Verifies Section 5.1 JNI cross-referencing capabilities."""

    def test_jni_name_mangling(self):
        # Package with underscores and dots
        raw = "com/example/my_test_app/MainActivity"
        mangled = mangle_jni_identifier(raw)
        self.assertEqual(mangled, "com_example_my_1test_1app_MainActivity")

        # Static export symbol generation
        sym_short = construct_static_jni_symbol("com.supercell.titan.NativeDialog", "showDialog")
        self.assertEqual(sym_short, "Java_com_supercell_titan_NativeDialog_showDialog")

        # Overloaded signature symbol generation
        sym_long = construct_static_jni_symbol(
            "com.supercell.titan.NativeDialog",
            "showDialog",
            signature="(ILjava/lang/String;)V",
            is_overloaded=True
        )
        self.assertTrue(sym_long.startswith("Java_com_supercell_titan_NativeDialog_showDialog__"))

    def test_static_and_dynamic_cross_referencing(self):
        ref = APKJNICrossReferencer(image_base=0x100000, is_64bit=True)

        # 1. Register Java DEX native methods
        ref.add_java_method("com.supercell.titan.NativeDialog", "dismiss", "()V")
        ref.add_java_method("com.supercell.titan.NativeDialog", "onClick", "(I)V")

        # 2. Add static ELF export for dismiss
        ref.add_elf_export("Java_com_supercell_titan_NativeDialog_dismiss", 0x00150240)

        # 3. Synthesize .rodata memory containing JNINativeMethod array for onClick
        # JNINativeMethod { const char *name, const char *sig, void *fnPtr }
        string_table = {
            0x200100: "onClick",
            0x200120: "(I)V",
        }
        # Pack 64-bit struct: name_ptr, sig_ptr, fn_ptr (0x00150500 in .text)
        rodata_chunk = struct.pack("<QQQ", 0x200100, 0x200120, 0x00150500)

        discovered = ref.scan_register_natives_table(
            rodata_bytes=rodata_chunk,
            rodata_vaddr=0x200000,
            string_table=string_table,
            text_vaddr_start=0x00100000,
            text_vaddr_end=0x00300000,
            class_context="com.supercell.titan.NativeDialog"
        )
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0].method_name, "onClick")
        self.assertEqual(discovered[0].fn_ptr, 0x00150500)

        # 4. Resolve cross-references
        matches = ref.resolve_cross_references()
        self.assertEqual(len(matches), 2)

        match_map = {m.java_method.method_name: m for m in matches}
        self.assertEqual(match_map["dismiss"].binding_type, "STATIC_EXPORT")
        self.assertEqual(match_map["dismiss"].target_address, 0x00150240)
        self.assertEqual(match_map["dismiss"].target_rva, 0x00050240)

        self.assertEqual(match_map["onClick"].binding_type, "REGISTER_NATIVES")
        self.assertEqual(match_map["onClick"].target_address, 0x00150500)
        self.assertEqual(match_map["onClick"].target_rva, 0x00050500)

        # 5. Check script generation
        script = ref.export_ghidra_python_script()
        self.assertIn("JNI_NativeDialog_dismiss", script)
        self.assertIn("JNI_NativeDialog_onClick", script)


class TestCrossPlatformHeadlessHarness(unittest.TestCase):
    """Verifies Section 5.1 & 5.2 headless execution flags and environment helpers."""

    def test_elf_and_pe_loader_flag_generation(self):
        # ELF Profile
        elf_profile = HeadlessProfile(
            os_target="linux",
            binary_format="elf",
            ghidra_install_dir="/opt/ghidra",
            project_location="/dev/shm/projects",
            project_name="elf_test",
            target_binary_path="/dev/shm/libg.so",
            max_cpu_cores=8,
            analysis_timeout_seconds=180
        )
        elf_args = elf_profile.to_command_args()
        self.assertIn("-loader", elf_args)
        self.assertIn("ElfLoader", elf_args)
        self.assertIn("-loader-applyDataImageBase", elf_args)
        self.assertIn("-loader-libraryLoadDepth", elf_args)
        self.assertIn("-max-cpu", elf_args)
        self.assertIn("8", elf_args)
        self.assertIn("-readOnly", elf_args)
        self.assertIn("-deleteProject", elf_args)

        # PE Profile
        pe_profile = HeadlessProfile(
            os_target="windows",
            binary_format="pe",
            ghidra_install_dir=r"C:\Ghidra",
            project_location=r"C:\Temp\proj",
            project_name="pe_test",
            target_binary_path=r"C:\Temp\target.exe"
        )
        pe_args = pe_profile.to_command_args()
        self.assertIn("analyzeHeadless.bat", pe_args[0])
        self.assertIn("PeLoader", pe_args)
        self.assertIn("-loader-parseCliHeaders", pe_args)
        self.assertIn("-loader-ordinalLookup", pe_args)

    def test_environment_and_colab_tuning(self):
        jadx_cmd, jadx_env = HeadlessEnvironmentConfigurator.generate_jadx_deobf_command(
            "app.apk", "out_src", threads=6, max_heap_gb=12
        )
        self.assertIn("--deobf", jadx_cmd)
        self.assertIn("6", jadx_cmd)
        self.assertEqual(jadx_env["JAVA_OPTS"], "-Xmx12g -XX:+UseG1GC")

        colab_gpu_env = HeadlessEnvironmentConfigurator.build_colab_t4_gpu_environment()
        self.assertEqual(colab_gpu_env["PYTORCH_CUDA_ALLOC_CONF"], "expandable_segments:True")

        colab_tpu_env = HeadlessEnvironmentConfigurator.build_colab_tpu_v5e_environment()
        self.assertEqual(colab_tpu_env["XLA_PYTHON_CLIENT_PREALLOCATE"], "false")


class TestPcodeLifterBridge(unittest.TestCase):
    """Verifies Section 6 & 7 zero-JVM P-Code IR lifting and CFG graph emission."""

    def setUp(self):
        self.lifter = ARM64PcodeLifter()

    def test_lift_core_instructions(self):
        # 1. RET (0xD65F03C0)
        ret_ops = self.lifter.lift_instruction(0x1000, 0xD65F03C0)
        self.assertEqual(len(ret_ops), 1)
        self.assertEqual(ret_ops[0].opcode, PcodeOpcode.RETURN)
        self.assertEqual(ret_ops[0].inputs[0].space, AddressSpace.REGISTER)

        # 2. MOVZ x0, #0x42 (0xD2800840) -> opcode 0x52800000 pattern
        movz_ops = self.lifter.lift_instruction(0x1004, 0xD2800840)
        self.assertEqual(len(movz_ops), 1)
        self.assertEqual(movz_ops[0].opcode, PcodeOpcode.COPY)
        self.assertEqual(movz_ops[0].output.offset, 0)  # x0

        # 3. ADD x1, x2, #0x20
        # (insn & 0x7F000000) == 0x11000000
        # rd=1, rn=2, imm=0x20 -> 0x91008041
        add_ops = self.lifter.lift_instruction(0x1008, 0x91008041)
        self.assertEqual(len(add_ops), 1)
        self.assertEqual(add_ops[0].opcode, PcodeOpcode.INT_ADD)
        self.assertEqual(add_ops[0].output.offset, 8)  # x1

        # 4. BL +0x100 (target: 0x100C + 0x100 = 0x110C)
        # imm26 = 0x100 >> 2 = 0x40 -> insn = 0x94000040
        bl_ops = self.lifter.lift_instruction(0x100C, 0x94000040)
        self.assertEqual(len(bl_ops), 2)
        self.assertEqual(bl_ops[0].opcode, PcodeOpcode.COPY)  # LR = pc + 4
        self.assertEqual(bl_ops[1].opcode, PcodeOpcode.CALL)
        self.assertEqual(bl_ops[1].inputs[0].offset, 0x110C)

    def test_block_lifting_and_adjacency_graph(self):
        # Sequence:
        # 0x1000: MOVZ x0, #10
        # 0x1004: ADD x0, x0, #5
        # 0x1008: RET
        block_bytes = struct.pack("<III", 0xD2800140, 0x91001400, 0xD65F03C0)
        ops = self.lifter.lift_block(0x1000, block_bytes)
        self.assertEqual(len(ops), 3)

        adj, meta = PcodeGraphBuilder.build_adjacency_matrix(ops, max_nodes=16)
        self.assertEqual(meta["connected_nodes"], 3)
        # Edge 0 -> 1 exists
        self.assertEqual(adj[0][1] if not hasattr(adj, "shape") else adj[0, 1], 1.0)
        # Edge 1 -> 2 exists
        self.assertEqual(adj[1][2] if not hasattr(adj, "shape") else adj[1, 2], 1.0)


class TestNativeDecompilerPGOBuilder(unittest.TestCase):
    """Verifies Section 6 C++ decompiler PGO building and patch generation."""

    def test_cmakelists_and_patch_generation(self):
        cfg = DecompilerBuildConfig(
            src_dir="/src/decompile",
            output_bin_dir="/bin",
            target_os="linux",
            enable_lto=True,
            enable_pgo=True
        )
        builder = NativeDecompilerPGOBuilder(cfg)

        cmake = builder.generate_cmakelists()
        self.assertIn("CMAKE_INTERPROCEDURAL_OPTIMIZATION", cmake)
        self.assertIn("-fprofile-generate", cmake)
        self.assertIn("-fprofile-use", cmake)

        script = builder.generate_pgo_workflow_script()
        self.assertIn("PGO_GENERATE=ON", script)
        self.assertIn("PGO_USE=ON", script)

        rule_patch = builder.generate_custom_pcode_rule_patch()
        self.assertIn("RuleFoldJniBridgeThunk", rule_patch)
        self.assertIn("CPUI_CALL", rule_patch)

        opts_xml = builder.generate_tuned_decompile_options_xml()
        self.assertIn("eliminate_unreachable_blocks", opts_xml)
        self.assertIn("simplify_predicates", opts_xml)


class TestNeuralDecompilerPipeline(unittest.TestCase):
    """Verifies Section 7 two-phase neural decompilation and EvidenceLedger gating."""

    def test_skeleton_extraction_and_evidence_gate(self):
        raw_code = """
        void LogicCommand_process(long this, int tick) {
            int uVar1;
            uVar1 = *(int *)(this + 0x20);
            *(int *)(this + 0x24) = uVar1 + 1;
            g_game_free(this);
            return;
        }
        """
        pipeline = NeuralDecompilerPipeline()

        # Phase A: Extract Skeleton
        skeleton = pipeline.run_phase_a(raw_code, function_address=0x00CF2D80)
        self.assertEqual(skeleton.function_rva, 0x00BF2D80)
        self.assertIn(0x20, skeleton.memory_displacements)
        self.assertIn(0x24, skeleton.memory_displacements)
        self.assertNotIn("uVar1", skeleton.skeleton_source)
        self.assertIn("v0", skeleton.skeleton_source)

        # Phase B: Neural Prediction Simulation
        prediction = pipeline.mock_neural_inference(skeleton)
        self.assertEqual(prediction.predicted_function_name, "LogicPlantCropCommand_execute")
        self.assertEqual(prediction.predicted_return_type, "bool")
        self.assertIn(0x20, prediction.predicted_struct_fields)
        self.assertIn(0x24, prediction.predicted_struct_fields)

        # Invariant Verification Gate
        commit = pipeline.verify_and_commit(skeleton, prediction)
        self.assertTrue(commit.is_safe_to_commit)
        self.assertEqual(commit.function_name, "LogicPlantCropCommand_execute")
        self.assertIn(0x20, commit.verified_struct_fields)
        self.assertIn(0x24, commit.verified_struct_fields)
        self.assertEqual(len(commit.evidence_proof_hashes), 2)


if __name__ == "__main__":
    unittest.main()
