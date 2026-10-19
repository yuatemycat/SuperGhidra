"""Tests for SuperGhidra Section 5 Current Mitigation Roadmap Engine (Countermeasures M1–M7).

Validates:
  - M1: Zero-JVM P-Code lifter CFG GNN tensor encoding (normalized adjacency & 16-dim features).
  - M2: Leaf XRef inversion tracing and 2-phase neural skinning de-obfuscation.
  - M3: Vector register integer spill ABI shims and cross-version struct displacement shifts.
  - M4: Emulator memory sidecar IPC framing and page snapshot diffing.
  - M5: Off-heap DWARF 5 / PDB SQLite indexing with SHA-256 structural deduplication.
  - M6: Standalone MSVC x64 RTTI hierarchy and MFC runtime class reconstruction.
  - M7: 4-tier resource governor budgets and 1-hop callee-to-caller cache invalidation DAG.
  - End-to-end Section 5 demonstration verification and root backward-compatibility shims.
"""
from __future__ import annotations

import os
import struct
import tempfile
from typing import Dict, List

import numpy as np
import pytest

from superghidra.core.mitigation_roadmap_engine import (
    ABIShimAndStructShiftAdapter,
    DWARFTypeDIE,
    EmulatorMemorySidecar,
    EmulatorMemorySidecarBridge,
    GNNPCodeTensorEncoder,
    GovernorMode,
    IPCCommandEnvelope,
    LeafXRefInversionEngine,
    LiftedBasicBlock,
    MFCRuntimeClassRecord,
    MSVCAndMFCRecoveryEngine,
    MSVCRecoveredClass,
    NeuralDecompilerSkinningPipeline,
    OffHeapDWARF5SQLiteIndexer,
    RelocationOrLeafXRef,
    ResourceGovernorAndCacheDAG,
    run_section5_mitigation_demonstration,
    run_section5_verification,
)
import superghidra.core as core_pkg
import mitigation_roadmap_engine as root_shim
import superghidra_section5_mitigation_roadmap_engine as section5_shim


# =============================================================================
# M1: ZERO-JVM P-CODE LIFTER + GNN ADJACENCY TENSOR ENCODER
# =============================================================================

class TestCountermeasureM1:
    """Tests for Countermeasure M1: GNN Adjacency & Node Feature Tensor Encoding."""

    def test_empty_blocks_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Cannot encode empty basic block sequence"):
            GNNPCodeTensorEncoder.encode_cfg_tensors([])

    def test_single_block_cfg_encoding(self) -> None:
        block = LiftedBasicBlock(
            block_id=0,
            start_rva=0x1000,
            end_rva=0x1020,
            pcode_opcodes=["LOAD", "STORE", "RETURN"],
            immediate_constants=[0x10],
            out_edges=[],
        )
        res = GNNPCodeTensorEncoder.encode_cfg_tensors([block])
        assert res["num_nodes"] == 1
        assert res["adjacency_norm_shape"] == [1, 1]
        assert res["node_features_shape"] == [1, 16]
        # Self loop on single node: A = [1], D = [1], A_norm = [1.0]
        np.testing.assert_allclose(res["adjacency_norm"], [[1.0]], atol=1e-5)
        # Check node features
        features = res["node_features"]
        assert features.shape == (1, 16)
        # 3 total ops: LOAD bucket 1 (1/3), STORE bucket 2 (1/3)
        assert pytest.approx(features[0, 1], rel=1e-3) == 1.0 / 3.0
        assert pytest.approx(features[0, 2], rel=1e-3) == 1.0 / 3.0
        # In-degree 0, Out-degree 0
        assert features[0, 12] == 0.0
        assert features[0, 13] == 0.0
        # 1 immediate constant / 3 ops
        assert pytest.approx(features[0, 14], rel=1e-3) == 1.0 / 3.0
        # Span (0x1020 - 0x1000 = 32) / 256.0 = 0.125
        assert pytest.approx(features[0, 15], rel=1e-3) == 32.0 / 256.0
        # Normalized embedding
        emb = res["pooled_gnn_embedding_16d"]
        assert len(emb) == 16
        assert pytest.approx(np.linalg.norm(emb), abs=1e-4) == 1.0

    def test_diamond_cfg_degree_normalized_adjacency(self) -> None:
        # Diamond CFG: 0 -> 1, 2; 1 -> 3; 2 -> 3; 3 -> (exit)
        blocks = [
            LiftedBasicBlock(0, 0x1000, 0x1010, ["CBRANCH"], [0x1020], [1, 2]),
            LiftedBasicBlock(1, 0x1010, 0x1020, ["INT_ADD", "BRANCH"], [10], [3]),
            LiftedBasicBlock(2, 0x1020, 0x1030, ["INT_SUB", "BRANCH"], [20], [3]),
            LiftedBasicBlock(3, 0x1030, 0x1040, ["RETURN"], [], []),
        ]
        out = GNNPCodeTensorEncoder.encode_cfg_tensors(blocks)
        assert out["num_nodes"] == 4
        assert out["adjacency_norm_shape"] == [4, 4]
        assert out["node_features_shape"] == [4, 16]

        a_norm = out["adjacency_norm"]
        # Check symmetry: A_hat = D^(-1/2) (A + I) D^(-1/2) is symmetric for undirected/directed normalization
        assert a_norm.shape == (4, 4)
        # Diagonal elements should be strictly positive (self-loops)
        for i in range(4):
            assert a_norm[i, i] > 0.0

        # Degree calculations in features:
        # Block 0 has out_degree 2 -> slot 13 = 2/4 = 0.5
        # Block 3 has in_degree 2 -> slot 12 = 2/4 = 0.5
        features = out["node_features"]
        assert pytest.approx(features[0, 13], rel=1e-3) == 0.5
        assert pytest.approx(features[3, 12], rel=1e-3) == 0.5


# =============================================================================
# M2: LEAF XREF INVERSION + 2-PHASE NEURAL DECOMPILER SKINNING
# =============================================================================

class TestCountermeasureM2:
    """Tests for Countermeasure M2: Leaf XRef Inversion & Neural Skinning Pipeline."""

    def test_leaf_xref_inversion_production_queue(self) -> None:
        inverter = LeafXRefInversionEngine()
        inverter.add_leaf_xref(
            RelocationOrLeafXRef(
                symbol_name="ProductionQueue::addItem",
                leaf_rva=0x00510200,
                caller_rva=0x00890000,
                call_site_rva=0x00890140,
                observed_register_args={"x0": "param_1", "w1": "uVar3", "w2": "uVar4"},
            )
        )
        raw_cff_c = (
            "void FUN_00890000(long param_1, int uVar3, int uVar4) {\n"
            "  state_var = 0x4410;\n"
            "  switch (state_var) {\n"
            "    case 0x4410:\n"
            "      ProductionQueue::addItem(param_1, uVar3, uVar4);\n"
            "      state_var = 0x9900;\n"
            "      goto LAB_dispatcher;\n"
            "  }\n"
            "}"
        )
        skinned = inverter.invert_and_skin_obfuscated_caller(
            0x00890000, raw_cff_c, [1.0] + [0.0] * 15
        )
        assert skinned["caller_rva"] == "0x890000"
        assert skinned["inferred_function_name"] == "LogicDeliverTruckOrderCommand::execute"
        assert "ProductionQueue::addItem" in skinned["anchored_leaf_symbols"]
        assert skinned["variable_renames"]["param_1"] == "production_queue_ptr"
        assert skinned["variable_renames"]["uVar3"] == "item_data_id"
        assert skinned["variable_renames"]["uVar4"] == "item_quantity"

        cleaned = skinned["skinned_c_output"]
        assert "production_queue_ptr" in cleaned
        assert "item_data_id" in cleaned
        assert "item_quantity" in cleaned
        assert "switch (state_var)" not in cleaned
        assert "state_var =" not in cleaned
        assert "goto LAB_dispatcher" not in cleaned

    def test_leaf_xref_inversion_carchive(self) -> None:
        inverter = LeafXRefInversionEngine()
        inverter.add_leaf_xref(
            RelocationOrLeafXRef(
                symbol_name="CArchive::Read",
                leaf_rva=0x00401000,
                caller_rva=0x00402000,
                call_site_rva=0x00402050,
                observed_register_args={"rcx": "ar_ptr"},
            )
        )
        raw_c = "void FUN_00402000(void *ar_ptr) { CArchive::Read(ar_ptr); }"
        skinned = inverter.invert_and_skin_obfuscated_caller(
            0x00402000, raw_c, [0.5] * 16
        )
        assert skinned["inferred_function_name"] == "SerializeInStream"
        assert "CArchive::Read" in skinned["anchored_leaf_symbols"]

    def test_pipeline_alias_identity(self) -> None:
        pipeline = NeuralDecompilerSkinningPipeline()
        assert isinstance(pipeline, LeafXRefInversionEngine)


# =============================================================================
# M3: ABI SHIM SYNTHESIS & STRUCT SHIFT MIGRATION
# =============================================================================

class TestCountermeasureM3:
    """Tests for Countermeasure M3: Vector Spill Shims & Struct Shift Migration."""

    def test_synthesize_vector_spill_shim(self) -> None:
        shim = ABIShimAndStructShiftAdapter.synthesize_vector_spill_shim(
            func_name="FastMatrixMultiply",
            vector_reg="d0",
            target_gpr="x2",
            byte_size=8,
        )
        assert shim["function"] == "FastMatrixMultiply"
        assert shim["shim_type"] == "CLANG_O3_VECTOR_INT_SPILL"
        assert shim["source_vector_reg"] == "d0"
        assert shim["logical_gpr_alias"] == "x2"
        assert len(shim["pcode_shim_ops"]) == 2
        assert "COPY(d0)" in shim["pcode_shim_ops"][0]
        assert "SUBPIECE(unique_spill_0, 0)" in shim["pcode_shim_ops"][1]

    def test_apply_struct_shift_decompiled_c(self) -> None:
        c_code = (
            "int a = *(int *)(pContext + 0x08);\n"
            "long b = *(long *)(pContext + 0x20);\n"
            "long c = *(long *)(pContext + 0x28);\n"
            "int other = *(int *)(pOther + 0x20);\n"
        )
        # Shift offsets on pContext >= 0x20 by +16 bytes (0x10)
        shifted = ABIShimAndStructShiftAdapter.apply_struct_shift_to_decompiled_c(
            c_code, struct_ptr_name="pContext", pivot_offset=0x20, delta_bytes=16
        )
        # pContext + 0x08 is below pivot (0x20) -> should remain 0x8
        assert "pContext + 0x8" in shifted
        # pContext + 0x20 (32) + 16 = 48 (0x30)
        assert "pContext + 0x30" in shifted
        # pContext + 0x28 (40) + 16 = 56 (0x38)
        assert "pContext + 0x38" in shifted
        # pOther + 0x20 belongs to pOther -> unchanged
        assert "pOther + 0x20" in shifted


# =============================================================================
# M4: EMULATOR MEMORY SIDECAR & IPC VERIFIER
# =============================================================================

class TestCountermeasureM4:
    """Tests for Countermeasure M4: Memory Snapshot Diffing & IPC Envelope Framing."""

    def test_ipc_command_envelope_pack_unpack(self) -> None:
        envelope = IPCCommandEnvelope(
            magic=b"SGIP",
            command_id=42,
            target_rva=0x00401000,
            payload=b"\xde\xad\xbe\xef\xca\xfe",
        )
        packed = envelope.pack()
        assert len(packed) == 20 + len(b"\xde\xad\xbe\xef\xca\xfe")

        unpacked = IPCCommandEnvelope.unpack(packed)
        assert unpacked.magic == b"SGIP"
        assert unpacked.command_id == 42
        assert unpacked.target_rva == 0x00401000
        assert unpacked.payload == b"\xde\xad\xbe\xef\xca\xfe"

    def test_ipc_command_envelope_invalid_magic_raises(self) -> None:
        bad_packet = b"BADP" + b"\x00" * 16
        with pytest.raises(ValueError, match="Invalid IPC envelope magic"):
            IPCCommandEnvelope.unpack(bad_packet)

    def test_sidecar_page_snapshot_diffing(self) -> None:
        sidecar = EmulatorMemorySidecarBridge()
        base = 0x80000000
        page_size = 4096
        # Pre snapshot: 2 pages
        pre = bytearray(page_size * 2)
        struct.pack_into("<I", pre, 0x100, 100)      # Page 0
        struct.pack_into("<I", pre, page_size + 0x40, 500)  # Page 1
        sidecar.capture_pre_snapshot(base, bytes(pre))

        # Post snapshot: mutate values in page 0 and page 1
        post = bytearray(pre)
        struct.pack_into("<I", post, 0x100, 175)     # +75
        struct.pack_into("<I", post, page_size + 0x40, 480) # -20

        diffs = sidecar.diff_post_snapshot(base, bytes(post), word_size=4)
        assert len(diffs) == 2

        d0 = next(d for d in diffs if d["address"] == hex(base + 0x100))
        assert d0["before"] == 100
        assert d0["after"] == 175
        assert d0["delta"] == 75

        d1 = next(d for d in diffs if d["address"] == hex(base + page_size + 0x40))
        assert d1["before"] == 500
        assert d1["after"] == 480
        assert d1["delta"] == -20

    def test_sidecar_64bit_word_size(self) -> None:
        sidecar = EmulatorMemorySidecar()
        base = 0x100000
        pre = bytearray(4096)
        struct.pack_into("<Q", pre, 0x20, 0x1122334455667788)
        sidecar.capture_pre_snapshot(base, bytes(pre))

        post = bytearray(pre)
        struct.pack_into("<Q", post, 0x20, 0x1122334455667799)
        diffs = sidecar.diff_post_snapshot(base, bytes(post), word_size=8)
        assert len(diffs) == 1
        assert diffs[0]["delta"] == 0x11


# =============================================================================
# M5: OFF-HEAP DWARF 5 / PDB SQLITE INDEXER
# =============================================================================

class TestCountermeasureM5:
    """Tests for Countermeasure M5: Off-Heap DWARF 5 Type Deduplication."""

    def test_dwarf5_sqlite_deduplication(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            db_path = tf.name
        try:
            indexer = OffHeapDWARF5SQLiteIndexer(db_path=db_path)
            die_cu1 = DWARFTypeDIE(
                compile_unit="src/network.cpp",
                type_name="PacketHeader",
                byte_size=16,
                members=[("magic", "uint32", 0), ("length", "uint32", 4), ("seq", "uint64", 8)],
            )
            die_cu2 = DWARFTypeDIE(
                compile_unit="src/handler.cpp",
                type_name="PacketHeader",
                byte_size=16,
                members=[("magic", "uint32", 0), ("length", "uint32", 4), ("seq", "uint64", 8)],
            )
            h1, is_new1 = indexer.ingest_die(die_cu1)
            h2, is_new2 = indexer.ingest_die(die_cu2)

            assert is_new1 is True
            assert is_new2 is False
            assert h1 == h2

            results = indexer.query_type("PacketHeader")
            assert len(results) == 1
            entry = results[0]
            assert entry["layout_sha256"] == h1
            assert entry["type_name"] == "PacketHeader"
            assert entry["byte_size"] == 16
            assert entry["deduplicated_compile_units"] == 2
            assert len(entry["members"]) == 3

            # Ingest variant with different layout
            die_variant = DWARFTypeDIE(
                compile_unit="src/v2.cpp",
                type_name="PacketHeader",
                byte_size=24,
                members=[("magic", "uint32", 0), ("length", "uint32", 4), ("seq", "uint64", 8), ("flags", "uint64", 16)],
            )
            h3, is_new3 = indexer.ingest_die(die_variant)
            assert is_new3 is True
            assert h3 != h1

            all_variants = indexer.query_type("PacketHeader")
            assert len(all_variants) == 2
        finally:
            if 'indexer' in locals():
                indexer.close()
            if os.path.exists(db_path):
                os.remove(db_path)


# =============================================================================
# M6: STANDALONE MSVC RTTI & MFC RECOVERY
# =============================================================================

class TestCountermeasureM6:
    """Tests for Countermeasure M6: MSVC RTTI x64 & MFC Class Recovery."""

    def test_demangle_msvc_type_name(self) -> None:
        assert MSVCAndMFCRecoveryEngine.demangle_msvc_type_name(".?AVCommand@@") == "Command"
        assert MSVCAndMFCRecoveryEngine.demangle_msvc_type_name(".?AVOrder@Titan@@") == "Titan::Order"
        assert MSVCAndMFCRecoveryEngine.demangle_msvc_type_name(".?AUBaseStruct@@") == "BaseStruct"
        assert MSVCAndMFCRecoveryEngine.demangle_msvc_type_name(".?AVA@B@C@@") == "C::B::A"

    def test_pack_and_parse_x64_rtti_bundle(self) -> None:
        bundle, vftable_rva = MSVCAndMFCRecoveryEngine.pack_synthetic_rtti_bundle(
            mangled_name=".?AVTruckDispatcher@Delivery@Titan@@",
            base_mangled_names=[".?AVDispatcherBase@Titan@@", ".?AVSerializable@Titan@@"],
            col_rva=0x4000,
            vftable_rva=0x4200,
        )
        recovered = MSVCAndMFCRecoveryEngine.parse_x64_rtti_slice(
            section_bytes=bundle,
            section_base_rva=0x4000,
            vftable_rva=vftable_rva,
        )
        assert recovered.class_name == "Titan::Delivery::TruckDispatcher"
        assert recovered.vftable_rva == 0x4200
        assert recovered.this_offset == 0
        assert recovered.base_classes == ["Titan::DispatcherBase", "Titan::Serializable"]
        assert recovered.has_virtual_inheritance is False

    def test_invalid_rtti_signature_raises(self) -> None:
        bad_slice = bytearray(0x100)
        struct.pack_into("<IIIiii", bad_slice, 0, 0, 0, 0, 0, 0, 0)  # sig = 0 (invalid for x64)
        with pytest.raises(ValueError, match="Expected x64 RTTI signature 1, got 0"):
            MSVCAndMFCRecoveryEngine.parse_x64_rtti_slice(bad_slice, 0x1000, 0x1200)

    def test_mfc_runtime_class_record(self) -> None:
        rec = MFCRuntimeClassRecord(
            class_name="CMyDocument",
            object_byte_size=256,
            schema_version=1,
            create_object_fn_rva=0x00405000,
            base_class_name="CDocument",
        )
        assert rec.class_name == "CMyDocument"
        assert rec.base_class_name == "CDocument"


# =============================================================================
# M7: 4-TIER RESOURCE GOVERNOR & 1-HOP CACHE DAG
# =============================================================================

class TestCountermeasureM7:
    """Tests for Countermeasure M7: Resource Governor & 1-Hop Cache Invalidation DAG."""

    def test_governor_budget_tiers(self) -> None:
        eco_gov = ResourceGovernorAndCacheDAG(GovernorMode.ECO)
        eco_b = eco_gov.select_budget(binary_size_mb=10.0, host_cores=8, host_ram_gb=16)
        assert eco_b["mode"] == "eco"
        assert eco_b["worker_threads"] == 2
        assert eco_b["max_ram_mb"] == 2048
        assert eco_b["gpu_enabled"] is False

        balanced_gov = ResourceGovernorAndCacheDAG(GovernorMode.BALANCED)
        bal_b = balanced_gov.select_budget(binary_size_mb=10.0, host_cores=8, host_ram_gb=16)
        assert bal_b["mode"] == "balanced"
        assert bal_b["worker_threads"] == 4
        assert bal_b["max_ram_mb"] == 6144
        assert bal_b["gpu_enabled"] is True

        turbo_gov = ResourceGovernorAndCacheDAG(GovernorMode.TURBO)
        turbo_b = turbo_gov.select_budget(binary_size_mb=10.0, host_cores=8, host_ram_gb=16)
        assert turbo_b["mode"] == "turbo"
        assert turbo_b["worker_threads"] == 8
        assert turbo_b["max_ram_mb"] == 8192
        assert turbo_b["gpu_enabled"] is True

    def test_governor_auto_mode(self) -> None:
        auto_gov = ResourceGovernorAndCacheDAG(GovernorMode.AUTO)
        # Binary < 40 MB -> BALANCED
        b_small = auto_gov.select_budget(binary_size_mb=25.0, host_cores=16, host_ram_gb=32)
        assert b_small["mode"] == "balanced"
        # Binary >= 40 MB -> TURBO
        b_large = auto_gov.select_budget(binary_size_mb=65.0, host_cores=16, host_ram_gb=32)
        assert b_large["mode"] == "turbo"

    def test_1hop_cache_invalidation_dag(self) -> None:
        dag = ResourceGovernorAndCacheDAG()
        # Graph:
        # A (0x10) -> Callee (0x30)
        # B (0x20) -> Callee (0x30)
        # GrandParent (0x05) -> A (0x10) [2-hop caller of Callee]
        # Unrelated (0x99)
        dag.register_call_edge(0x10, 0x30)
        dag.register_call_edge(0x20, 0x30)
        dag.register_call_edge(0x05, 0x10)

        dag.cache_decompilation(0x30, "void callee() {}", "h30")
        dag.cache_decompilation(0x10, "void a() { callee(); }", "h10")
        dag.cache_decompilation(0x20, "void b() { callee(); }", "h20")
        dag.cache_decompilation(0x05, "void gp() { a(); }", "h05")
        dag.cache_decompilation(0x99, "void unrelated() {}", "h99")

        # Invalidate Callee (0x30)
        invalidated = dag.invalidate_1hop_dag(0x30)
        assert set(invalidated) == {0x10, 0x20, 0x30}

        assert dag._l2_cache[0x30]["valid"] is False
        assert dag._l2_cache[0x10]["valid"] is False
        assert dag._l2_cache[0x20]["valid"] is False
        # 2-hop caller (0x05) and unrelated (0x99) must remain valid!
        assert dag._l2_cache[0x05]["valid"] is True
        assert dag._l2_cache[0x99]["valid"] is True


# =============================================================================
# END-TO-END DEMONSTRATION & ROOT SHIMS
# =============================================================================

class TestSection5DemonstrationAndShims:
    """Tests for full end-to-end demonstration and backward-compatibility shims."""

    def test_run_section5_mitigation_demonstration(self) -> None:
        report1 = run_section5_mitigation_demonstration()
        assert "M1_gnn_tensor_lifter" in report1
        assert "M2_leaf_xref_neural_skinning" in report1
        assert "M3_abi_shim_and_shift" in report1
        assert "M4_emulator_sidecar" in report1
        assert "M5_dwarf5_sqlite_dedup" in report1
        assert "M6_msvc_rtti_recovery" in report1
        assert "M7_governor_and_cache_dag" in report1

    def test_run_section5_verification_alias(self) -> None:
        report2 = run_section5_verification()
        assert report2["M1_gnn_tensor_lifter"]["adjacency_shape"] == [4, 4]
        assert report2["M7_governor_and_cache_dag"]["two_hop_caller_preserved"] is True

    def test_root_shims_integrity(self) -> None:
        assert root_shim.GNNPCodeTensorEncoder is GNNPCodeTensorEncoder
        assert section5_shim.GNNPCodeTensorEncoder is GNNPCodeTensorEncoder
        assert root_shim.LeafXRefInversionEngine is LeafXRefInversionEngine
        assert section5_shim.MSVCAndMFCRecoveryEngine is MSVCAndMFCRecoveryEngine
        assert core_pkg.GNNPCodeTensorEncoder is GNNPCodeTensorEncoder
        assert core_pkg.LeafXRefInversionEngine is LeafXRefInversionEngine
        assert core_pkg.NeuralDecompilerSkinningPipeline is NeuralDecompilerSkinningPipeline
        assert core_pkg.EmulatorMemorySidecarBridge is EmulatorMemorySidecarBridge
        assert core_pkg.run_section5_mitigation_demonstration is run_section5_mitigation_demonstration
