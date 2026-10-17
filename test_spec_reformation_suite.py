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

import json
import tempfile
from unittest.mock import MagicMock, patch

from apk_jni_cross_referencer import (
    APKJNICrossReferencer,
    construct_static_jni_symbol,
    mangle_jni_identifier,
)
from colab_cloud_orchestrator import ColabCloudOrchestrator
from cross_platform_headless_harness import (
    HeadlessEnvironmentConfigurator,
    HeadlessProfile,
)
import evidence_ledger
from native_decompiler_pgo_builder import (
    DecompilerBuildConfig,
    NativeDecompilerPGOBuilder,
)
from neural_decompiler_pipeline import (
    DecompiledSkeleton,
    LLMDecompilerClient,
    NeuralDecompilerPipeline,
    NeuralPrediction,
    SkeletonExtractor,
)
from pcode_lifter_bridge import (
    AddressSpace,
    ARM64PcodeLifter,
    PcodeGraphBuilder,
    PcodeOpcode,
)
from semantic_delta_log import (
    DeltaEventType,
    DeltaMigrationEngine,
    SemanticEvent,
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
        self.assertEqual(prediction.predicted_function_name, "sub_cf2d80")
        self.assertEqual(prediction.predicted_return_type, "void")
        self.assertIn(0x20, prediction.predicted_struct_fields)
        self.assertIn(0x24, prediction.predicted_struct_fields)

        # Invariant Verification Gate
        commit = pipeline.verify_and_commit(skeleton, prediction)
        self.assertTrue(commit.is_safe_to_commit)
        self.assertEqual(commit.function_name, "sub_cf2d80")
        self.assertIn(0x20, commit.verified_struct_fields)
        self.assertIn(0x24, commit.verified_struct_fields)
        self.assertEqual(len(commit.evidence_proof_hashes), 2)

    def test_skeleton_vtable_and_displacements(self):
        """Verifies SkeletonExtractor extracts VTable offsets, struct field tokens, and array subscripts."""
        raw_code = """
        void VirtualDispatch_handler(long *param_1, int tick) {
            int uVar1;
            uVar1 = *(int *)(param_1 + 0x24);
            *((int64_t *)param_1 + 4) = uVar1;
            param_1->field_0x24 = 10;
            param_1->offset_0x18 = 5;
            param_1[9] = 12;
            (**(code **)(*param_1 + 0x38))(param_1, tick);
            return;
        }
        """
        skeleton = SkeletonExtractor.extract_skeleton(raw_code, function_address=0x100000)
        self.assertIn(0x24, skeleton.memory_displacements)
        self.assertIn(0x18, skeleton.memory_displacements)
        self.assertIn(0x20, skeleton.memory_displacements)  # 4 * 8 = 32 = 0x20
        self.assertIn(0x38, skeleton.memory_displacements)
        self.assertIn(0x38, skeleton.vtable_call_offsets)
        self.assertEqual(skeleton.vtable_call_offsets, [0x38])

    def test_llm_client_prompt_and_json_parsing(self):
        """Verifies LLMDecompilerClient prompt construction and JSON response parsing."""
        client = LLMDecompilerClient(
            endpoint_url="http://mock-llm.local/v1/chat/completions",
            api_key="mock_key_abc",
            model_name="llm4decompile-9b-v2"
        )
        skeleton = DecompiledSkeleton(
            function_address=0x102040,
            function_rva=0x2040,
            raw_source="void test() {}",
            skeleton_source="void test() {}",
            variable_mapping={"uVar1": "v0"},
            parameter_count=2,
            call_targets=["crypto_sha256"],
            memory_displacements=[0x20, 0x24],
            vtable_call_offsets=[0x38]
        )
        sys_prompt, user_prompt = client.build_prompt(skeleton)
        self.assertIn("reverse engineering", sys_prompt.lower())
        self.assertIn("0x102040", user_prompt)
        self.assertIn("0x38", user_prompt)
        self.assertIn("crypto_sha256", user_prompt)

        # Mock urllib response
        mock_response_payload = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "predicted_function_name": "PlayerSession_dispatchPacket",
                        "predicted_return_type": "bool",
                        "predicted_parameters": [["PlayerSession*", "pSession"], ["int32_t", "packetId"]],
                        "predicted_struct_fields": {"0x20": ["int32_t", "m_state"], "0x24": ["int32_t", "m_packetLen"]},
                        "confidence": 0.94
                    })
                }
            }]
        }

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_response_payload).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp

        with patch("urllib.request.urlopen", return_value=mock_resp):
            pred = client.predict(skeleton)
            self.assertEqual(pred.predicted_function_name, "PlayerSession_dispatchPacket")
            self.assertEqual(pred.predicted_return_type, "bool")
            self.assertEqual(len(pred.predicted_parameters), 2)
            self.assertIn(0x20, pred.predicted_struct_fields)
            self.assertEqual(pred.confidence, 0.94)
            self.assertEqual(pred.model_identifier, "llm4decompile-9b-v2")

    def test_predict_skin_online_and_fallback(self):
        """Verifies predict_skin uses online LLM predictions and falls back cleanly on failure."""
        pipeline = NeuralDecompilerPipeline()
        skeleton = DecompiledSkeleton(
            function_address=0x102040,
            function_rva=0x2040,
            raw_source="void test() {}",
            skeleton_source="void test() {}",
            variable_mapping={},
            parameter_count=1,
            call_targets=[],
            memory_displacements=[0x20, 0x24],
            vtable_call_offsets=[]
        )

        # 1. Fallback when llm_client is None
        pred_fallback_none = pipeline.predict_skin(skeleton, llm_client=None)
        self.assertEqual(pred_fallback_none.predicted_function_name, "sub_102040")
        self.assertEqual(pred_fallback_none.model_identifier, "heuristic-fallback")
        self.assertEqual(pred_fallback_none.source, "heuristic")
        self.assertLessEqual(pred_fallback_none.confidence, 0.3)

        # 2. Fallback when llm_client throws an exception (offline endpoint)
        mock_client_fail = LLMDecompilerClient(endpoint_url="http://nonexistent.invalid")
        with patch.object(mock_client_fail, "predict", side_effect=RuntimeError("Connection refused")):
            pred_fallback_err = pipeline.predict_skin(skeleton, llm_client=mock_client_fail)
            self.assertEqual(pred_fallback_err.predicted_function_name, "sub_102040")
            self.assertEqual(pred_fallback_err.source, "heuristic")
            self.assertIsNotNone(pred_fallback_err.error)
            self.assertIn("Connection refused", pred_fallback_err.error)

        # 3. Successful online prediction
        mock_client_ok = LLMDecompilerClient()
        online_pred = NeuralPrediction(
            predicted_function_name="CustomOnline_handler",
            predicted_return_type="int",
            predicted_parameters=[("void*", "ctx")],
            predicted_struct_fields={0x20: ("int", "fld")},
            confidence=0.99,
            model_identifier="online-model"
        )
        with patch.object(mock_client_ok, "predict", return_value=online_pred):
            pred_ok = pipeline.predict_skin(skeleton, llm_client=mock_client_ok)
            self.assertEqual(pred_ok.predicted_function_name, "CustomOnline_handler")
            self.assertEqual(pred_ok.confidence, 0.99)

    def test_mock_neural_inference_domains(self):
        """Verifies generic neutral heuristic fallback for vtable, crypto, and network skeletons."""
        pipeline = NeuralDecompilerPipeline()

        # Domain A: VTable dispatch
        vtable_skel = DecompiledSkeleton(
            function_address=0x1000,
            function_rva=0x1000,
            raw_source="void vcall() {}",
            skeleton_source="void vcall() {}",
            variable_mapping={},
            parameter_count=2,
            call_targets=[],
            memory_displacements=[0x38],
            vtable_call_offsets=[0x38]
        )
        pred_vtable = pipeline.mock_neural_inference(vtable_skel)
        self.assertEqual(pred_vtable.predicted_function_name, "sub_1000")
        self.assertEqual(pred_vtable.model_identifier, "heuristic-fallback")
        self.assertEqual(pred_vtable.source, "heuristic")
        self.assertLessEqual(pred_vtable.confidence, 0.3)
        self.assertIn(0x38, pred_vtable.predicted_struct_fields)

        # Domain B: Crypto / Hash
        crypto_skel = DecompiledSkeleton(
            function_address=0x2000,
            function_rva=0x2000,
            raw_source="void sha256_process(uint8_t *in) {}",
            skeleton_source="void sha256_process(v0) {}",
            variable_mapping={},
            parameter_count=3,
            call_targets=["sha256_transform"],
            memory_displacements=[0x10],
            vtable_call_offsets=[]
        )
        pred_crypto = pipeline.mock_neural_inference(crypto_skel)
        self.assertEqual(pred_crypto.predicted_function_name, "sub_2000")
        self.assertEqual(pred_crypto.model_identifier, "heuristic-fallback")
        self.assertEqual(pred_crypto.source, "heuristic")
        self.assertLessEqual(pred_crypto.confidence, 0.3)
        self.assertIn(0x10, pred_crypto.predicted_struct_fields)
        self.assertEqual(pred_crypto.predicted_struct_fields[0x10][1], "field_0x10")

        # Domain C: JNI / Network packet
        net_skel = DecompiledSkeleton(
            function_address=0x3000,
            function_rva=0x3000,
            raw_source="int readPacket(JNIEnv *env, jobject thiz) {}",
            skeleton_source="int readPacket(v0, v1) {}",
            variable_mapping={},
            parameter_count=3,
            call_targets=["recv"],
            memory_displacements=[0x10],
            vtable_call_offsets=[]
        )
        pred_net = pipeline.mock_neural_inference(net_skel)
        self.assertEqual(pred_net.predicted_function_name, "sub_3000")
        self.assertEqual(pred_net.model_identifier, "heuristic-fallback")
        self.assertEqual(pred_net.source, "heuristic")
        self.assertLessEqual(pred_net.confidence, 0.3)
        self.assertIn(0x10, pred_net.predicted_struct_fields)
        self.assertEqual(pred_net.predicted_struct_fields[0x10][1], "field_0x10")

    def test_evidence_ledger_registration_in_verify_and_commit(self):
        """Verifies formal obligation registration and cryptographic proof hashes when ledger is provided."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            ledger_path = os.path.join(tmp_dir, "test_ledger.json")
            ledger = evidence_ledger.ReconstructionObligationLedger(ledger_file=ledger_path)
            pipeline = NeuralDecompilerPipeline(ledger=ledger)

            skeleton = DecompiledSkeleton(
                function_address=0x100000,
                function_rva=0x1000,
                raw_source="void test() {}",
                skeleton_source="void test() {}",
                variable_mapping={},
                parameter_count=2,
                call_targets=[],
                memory_displacements=[0x20, 0x24],
                vtable_call_offsets=[]
            )
            prediction = pipeline.mock_neural_inference(skeleton)

            commit = pipeline.verify_and_commit(skeleton, prediction)
            self.assertTrue(commit.is_safe_to_commit)
            self.assertIn(0x20, commit.verified_struct_fields)
            self.assertIn(0x24, commit.verified_struct_fields)

            # Check that ledger proof hashes were added
            self.assertGreater(len(commit.evidence_proof_hashes), 2)
            has_ledger_proof = any("LEDGER_" in h for h in commit.evidence_proof_hashes)
            self.assertTrue(has_ledger_proof)

            # Check obligations in ledger
            self.assertGreaterEqual(len(ledger.obligations), 2)
            committed_obls = ledger.list_obligations(evidence_ledger.ObligationStatus.COMMITTED)
            self.assertGreaterEqual(len(committed_obls), 2)

    def test_extract_elf_executable_slice(self):
        """Verifies ColabCloudOrchestrator.extract_elf_executable_slice strips synthetic ELF headers."""
        # 1. 16-byte synthetic ELF header + ARM64 instructions (RET = \xc0\x03\x5f\xd6)
        synthetic_elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" + (b"\xc0\x03\x5f\xd6" * 8)
        base_vaddr, code_bytes = ColabCloudOrchestrator.extract_elf_executable_slice(synthetic_elf)
        self.assertEqual(code_bytes, b"\xc0\x03\x5f\xd6" * 8)
        self.assertFalse(code_bytes.startswith(b"\x7fELF"))
        first_word = struct.unpack("<I", code_bytes[:4])[0]
        self.assertNotEqual(first_word, 0x464c457f)  # \x7fELF little-endian uint32
        self.assertEqual(first_word, 0xd65f03c0)      # ARM64 RET

        # 2. Raw binary without ELF header
        raw_code = b"\x00\x00\x80\xd2\xc0\x03\x5f\xd6"
        base_vaddr2, code_bytes2 = ColabCloudOrchestrator.extract_elf_executable_slice(raw_code)
        self.assertEqual(code_bytes2, raw_code)


class TestEvidenceLedgerHardwareVerifiers(unittest.TestCase):
    """Verifies direct ARM64 machine instruction verifiers in EvidenceLedger."""

    def test_vtable_slot_verifier_arm64(self):
        # LDR X1, [X0, #0]       -> 0xF9400001
        # LDR X2, [X1, #0x28]    -> 0xF9401422 (slot 5 = 0x28)
        # BLR X2                 -> 0xD63F0040
        # RET                    -> 0xD65F03C0
        code = struct.pack("<IIII", 0xF9400001, 0xF9401422, 0xD63F0040, 0xD65F03C0)
        res = evidence_ledger.VTableSlotVerifier.extract_and_verify_arm64(code, expected_slot_offset=0x28)
        self.assertTrue(res.passed)
        self.assertIn("0x28", res.message)

        # Mismatched slot offset
        res_fail = evidence_ledger.VTableSlotVerifier.extract_and_verify_arm64(code, expected_slot_offset=0x30)
        self.assertFalse(res_fail.passed)

        # Empty stream
        res_empty = evidence_ledger.VTableSlotVerifier.extract_and_verify_arm64(b"", expected_slot_offset=0x28)
        self.assertFalse(res_empty.passed)

    def test_allocation_size_verifier_arm64(self):
        # MOVZ W0, #0x120 -> 0x52802400
        # BL +8           -> 0x94000002
        # RET             -> 0xD65F03C0
        code = struct.pack("<III", 0x52802400, 0x94000002, 0xD65F03C0)
        res = evidence_ledger.AllocationSizeVerifier.extract_and_verify_arm64(
            code, struct_size=0x100, max_field_end=0x100
        )
        self.assertTrue(res.passed)
        self.assertIn("0x120", res.message)

        # Struct size / field boundary exceeds allocation buffer
        res_fail = evidence_ledger.AllocationSizeVerifier.extract_and_verify_arm64(
            code, struct_size=0x150, max_field_end=0x150
        )
        self.assertFalse(res_fail.passed)
        self.assertIn("exceeds hardware allocation size", res_fail.message)

        # Stream without allocation call
        code_no_call = struct.pack("<II", 0x52802400, 0xD65F03C0)
        res_no_call = evidence_ledger.AllocationSizeVerifier.extract_and_verify_arm64(code_no_call, struct_size=0x100)
        self.assertFalse(res_no_call.passed)

    def test_field_displacement_verifier_arm64(self):
        # LDR W1, [X0, #0x20] -> 0xB9402001
        # STR X2, [X0, #0x28] -> 0xF9001402
        # RET                 -> 0xD65F03C0
        code = struct.pack("<III", 0xB9402001, 0xF9001402, 0xD65F03C0)
        claimed = [
            {"name": "m_fieldA", "offset": 0x20, "access_size": 4},
            {"name": "m_fieldB", "offset": 0x28, "access_size": 8},
        ]
        res = evidence_ledger.FieldDisplacementVerifier.extract_and_verify_arm64(code, claimed)
        self.assertTrue(res.passed)

        # Unaligned field
        claimed_unaligned = [
            {"name": "m_badAlign", "offset": 0x21, "access_size": 4},
        ]
        res_unaligned = evidence_ledger.FieldDisplacementVerifier.extract_and_verify_arm64(code, claimed_unaligned)
        self.assertFalse(res_unaligned.passed)
        self.assertIn("violates natural alignment", res_unaligned.message)

        # Unbacked hallucinated offset
        claimed_hallucinated = [
            {"name": "m_hallucinated", "offset": 0x50, "access_size": 4},
        ]
        res_hallucinated = evidence_ledger.FieldDisplacementVerifier.extract_and_verify_arm64(code, claimed_hallucinated)
        self.assertFalse(res_hallucinated.passed)
        self.assertIn("no matching ARM64 memory access instruction", res_hallucinated.message)


class TestNeuralPipelineHardwareSMT(unittest.TestCase):
    """Verifies NeuralDecompilerPipeline integration with ARM64 bytes and SMT verification."""

    def test_verify_and_commit_arm64_hardware_verification(self):
        pipeline = NeuralDecompilerPipeline()
        # ARM64: LDR W1, [X0, #0x20] (0xB9402001), LDR W2, [X0, #0x24] (0xB9402402), RET (0xD65F03C0)
        code = struct.pack("<III", 0xB9402001, 0xB9402402, 0xD65F03C0)

        skeleton = DecompiledSkeleton(
            function_address=0x1000,
            function_rva=0x1000,
            raw_source="void test() {}",
            skeleton_source="void test() {}",
            variable_mapping={},
            parameter_count=1,
            call_targets=[],
            memory_displacements=[0x20, 0x24],
            vtable_call_offsets=[],
        )
        prediction = NeuralPrediction(
            predicted_function_name="LogicPlantCropCommand_execute",
            predicted_return_type="bool",
            predicted_parameters=[("void*", "this")],
            predicted_struct_fields={0x20: ("int32_t", "m_turnTick"), 0x24: ("int32_t", "m_cropType")},
            confidence=0.92,
            model_identifier="test",
        )

        commit = pipeline.verify_and_commit(skeleton, prediction, arm64_bytes=code)
        self.assertTrue(commit.is_safe_to_commit)
        self.assertIn(0x20, commit.verified_struct_fields)
        self.assertIn(0x24, commit.verified_struct_fields)
        self.assertTrue(any("PROOF_ARM64_FIELDS_" in h for h in commit.evidence_proof_hashes))

        # Divergent code (offset not in hardware)
        divergent_code = struct.pack("<II", 0xB9401001, 0xD65F03C0)  # offset 0x10 only
        commit_divergent = pipeline.verify_and_commit(skeleton, prediction, arm64_bytes=divergent_code)
        self.assertFalse(commit_divergent.is_safe_to_commit)

    def test_verify_and_commit_z3_smt_proof_generation(self):
        pipeline = NeuralDecompilerPipeline()
        # ARM64: MOVZ X0, #0x42 (0xD2800840), RET (0xD65F03C0)
        code = struct.pack("<II", 0xD2800840, 0xD65F03C0)
        c_code_snippet = "return 0x42;"

        skeleton = DecompiledSkeleton(
            function_address=0x2000,
            function_rva=0x2000,
            raw_source="int getValue() { return 0x42; }",
            skeleton_source="int getValue() { return 0x42; }",
            variable_mapping={},
            parameter_count=1,
            call_targets=[],
            memory_displacements=[],
            vtable_call_offsets=[],
        )
        prediction = NeuralPrediction(
            predicted_function_name="getValue",
            predicted_return_type="int",
            predicted_parameters=[("void*", "this")],
            predicted_struct_fields={},
            confidence=0.95,
            model_identifier="test",
        )

        commit = pipeline.verify_and_commit(
            skeleton, prediction, arm64_bytes=code, c_code_snippet=c_code_snippet
        )
        self.assertTrue(commit.is_safe_to_commit)
        has_smt_proof = any("SMT_PROOF_" in h for h in commit.evidence_proof_hashes)
        self.assertTrue(has_smt_proof)


class TestDeltaMigrationBetweenBinaries(unittest.TestCase):
    """Verifies cross-binary semantic delta migration with struct shifts and symbol renaming."""

    def test_migrate_between_binaries_with_struct_shift_and_rename(self):
        engine = DeltaMigrationEngine()

        # Binary A: function at 0x100000 with LDR W1, [X0, #0x20] (0xB9402001) -> RET (0xD65F03C0)
        code_a = struct.pack("<II", 0xB9402001, 0xD65F03C0)
        # Binary B: function at 0x100000 with LDR W1, [X0, #0x28] (0xB9402801) -> RET (0xD65F03C0)
        code_b = struct.pack("<II", 0xB9402801, 0xD65F03C0)

        evt_field = SemanticEvent.create_define_struct_field(
            struct_name="PlantData",
            field_name="m_cropId",
            offset=0x20,
            size=4,
            type_name="int32_t",
            evidence={
                "struct_size": 0x40,
                "field_displacements": [{"name": "m_cropId", "offset": 0x20, "access_size": 4}],
            },
        )
        evt_rename = SemanticEvent.create_rename_symbol(
            old_name="sub_100000",
            new_name="PlantCrop_Execute",
            target_address=0x100000,
        )

        report, migrated = engine.migrate_between_binaries(code_a, code_b, [evt_field, evt_rename])
        self.assertEqual(len(migrated), 2)
        self.assertEqual(report.migrated_verified_count, 1)
        self.assertEqual(report.migrated_unverified_count, 1)
        self.assertEqual(report.migration_rate_pct, 100.0)

        # Verify struct field shift translation
        migrated_field = [e for e in migrated if e.event_type == DeltaEventType.DEFINE_STRUCT_FIELD][0]
        self.assertEqual(migrated_field.payload["offset"], 0x28)
        self.assertEqual(migrated_field.metadata["shift_delta"], 8)
        self.assertEqual(migrated_field.metadata["old_offset"], 0x20)
        self.assertEqual(migrated_field.metadata["new_offset"], 0x28)
        self.assertTrue(migrated_field.verified)

        # Verify symbol rename translation
        migrated_rename = [e for e in migrated if e.event_type == DeltaEventType.RENAME_SYMBOL][0]
        self.assertEqual(migrated_rename.target_address, 0x100000)
        self.assertEqual(migrated_rename.payload["new_name"], "PlantCrop_Execute")
        self.assertTrue(migrated_rename.verified)


if __name__ == "__main__":
    unittest.main()
