"""Exhaustive test suite for SuperGhidra Section 3 (Parity Engine).

Tests the 7 Critical Gaps Against IDA Pro & the Parity Engine:
  - Gap 1: Staged P-Code Pass Manager, Zero-Copy SHM Serialization & Nested Pointer Folding
  - Gap 2: Symbolic CFG Deflattening, Dominance Analysis & Opaque Predicate Elimination
  - Gap 3: Declarative __usercall Prototype Parser, Vector-Register Spill & .cspec Generator
  - Gap 4: Target-Agnostic Appcall Marshaller, Scratch Stack Allocator & Struct Mutation Diffing
  - Gap 5: PIC-Masked ARM64 Prologue Hasher & 32-Dimensional CFG Cosine Signature Index
  - Gap 6: C++14/17/20 Clang Header Importer, Inheritance, Bitfields & .sgdb Type Exporter
  - Gap 7: High-Density 16 KB SGDB Block Store, 20-Byte Slot Index & Vectorized ARM64 ADRP Scanner
  - Section 7.3: SparseMatrixDatalogEngine Whole-Binary Inter-Procedural Taint & Sanitizer Blocking
  - Unified SuperGhidraSection3MCPServer Tool Dispatcher
  - Backward-compatibility shims (`parity_engine.py` and `superghidra_section3_parity_engine.py`)
"""
from __future__ import annotations

import os
import struct
import unittest
import numpy as np

import parity_engine as shim_parity_engine
from superghidra.core import (
    ARM64ADRPScanner,
    AppcallExecutionFrame,
    AppcallMarshaller,
    ArchitectureRegisterBank,
    BasicBlock,
    CFGSignatureIndex,
    ClangHeaderImporter,
    CompiledUsercallPrototype,
    FuncdataGraph,
    FunctionSignatureRecord,
    PCodeCFG,
    PCodeMaturity,
    PCodeOp,
    PCodeOpcode,
    ParsedCompositeType,
    ParsedFieldRecord,
    RegisterDescriptor,
    SGDBBlockStore,
    SGDBSlotEntry,
    SHMVarnodeBuffer,
    SparseMatrixDatalogEngine,
    StagedPCodePassManager,
    StructFieldSpec,
    StructLayoutSpec,
    SuperGhidraSection3MCPServer,
    SymbolicCFGDeflattener,
    UsercallPrototypeCompiler,
    VariableStorageBinding,
    Varnode,
    run_self_verification,
)
from superghidra.core import parity_engine as canonical_parity_engine


class TestBackwardCompatibilityShims(unittest.TestCase):
    """Verifies non-breaking root backward-compatibility shims."""

    def test_shim_exports_match_canonical(self):
        self.assertIs(shim_parity_engine.StagedPCodePassManager, canonical_parity_engine.StagedPCodePassManager)
        self.assertIs(shim_parity_engine.SymbolicCFGDeflattener, canonical_parity_engine.SymbolicCFGDeflattener)
        self.assertIs(shim_parity_engine.ARM64ADRPScanner, canonical_parity_engine.ARM64ADRPScanner)


class TestSelfVerificationSuite(unittest.TestCase):
    """Verifies that the built-in self-verification suite executes end-to-end without assertion errors."""

    def test_run_self_verification_e2e(self):
        results = run_self_verification()
        self.assertIn("gap1_staged_pcode", results)
        self.assertIn("gap2_cff_deflattener", results)
        self.assertIn("gap3_usercall_dsl", results)
        self.assertIn("gap4_appcall_marshaller", results)
        self.assertIn("gap5_signature_index", results)
        self.assertIn("gap6_clang_header_importer", results)
        self.assertIn("gap7_storage_and_adrp_scanner", results)
        self.assertIn("section7_3_sparse_datalog", results)

        self.assertEqual(results["gap1_staged_pcode"]["folded_expression"], "result = a1->field_18[(v4 & 0x1f)]")
        self.assertTrue(results["gap2_cff_deflattener"]["deflattened"])
        self.assertTrue(results["gap3_usercall_dsl"]["vector_spill_detected"])
        self.assertEqual(results["gap4_appcall_marshaller"]["struct_mutations"]["executed_tick"]["after"], 987654321)
        self.assertTrue(results["gap5_signature_index"]["exact_pic_hash_match"])
        self.assertEqual(results["gap6_clang_header_importer"]["alignment"], 16)
        self.assertEqual(results["gap7_storage_and_adrp_scanner"]["sgdb_slot_directory_bytes"], 20)
        self.assertTrue(results["section7_3_sparse_datalog"]["sanitized_blocked"])


class TestGap1StagedPCodePipeline(unittest.TestCase):
    """Tests Gap 1: Staged P-Code Pass Manager, Zero-Copy SHM Buffer & Expression Folding."""

    def setUp(self):
        self.a1 = Varnode("register", 0x4000, 8, ssa_version=1, symbol_name="a1")
        self.v4 = Varnode("register", 0x4008, 8, ssa_version=1, symbol_name="v4")
        self.t0 = Varnode("unique", 0x100, 8, ssa_version=1)
        self.t1 = Varnode("unique", 0x108, 8, ssa_version=1)
        self.t2 = Varnode("unique", 0x110, 8, ssa_version=1)
        self.t3 = Varnode("unique", 0x118, 8, ssa_version=1)
        self.t4 = Varnode("unique", 0x120, 8, ssa_version=1)
        self.dead_tmp = Varnode("unique", 0x999, 8, ssa_version=1)
        self.out_vn = Varnode("register", 0x4000, 8, ssa_version=2, symbol_name="result")

        self.graph = FuncdataGraph(
            function_name="ProductionQueue_getSlot",
            entry_rva=0x00C06750,
            ops=[
                PCodeOp(1, 0x00C06750, PCodeOpcode.INT_ADD, self.t0, [self.a1, Varnode("const", 0x18, 8)]),
                PCodeOp(2, 0x00C06754, PCodeOpcode.LOAD, self.t1, [Varnode("const", 3, 8), self.t0]),
                PCodeOp(3, 0x00C06758, PCodeOpcode.INT_AND, self.t2, [self.v4, Varnode("const", 0x1F, 8)]),
                PCodeOp(4, 0x00C0675C, PCodeOpcode.INT_MULT, self.t3, [self.t2, Varnode("const", 8, 8)]),
                PCodeOp(5, 0x00C06760, PCodeOpcode.INT_ADD, self.t4, [self.t1, self.t3]),
                PCodeOp(6, 0x00C06764, PCodeOpcode.INT_XOR, self.dead_tmp, [self.a1, self.v4]),
                PCodeOp(7, 0x00C06768, PCodeOpcode.LOAD, self.out_vn, [Varnode("const", 3, 8), self.t4]),
            ],
        )

    def test_shm_varnode_buffer_roundtrip(self):
        buf = SHMVarnodeBuffer.serialize_to_shm(self.graph)
        self.assertGreater(len(buf), 16)
        magic, version, op_count = struct.unpack_from("<4sII", buf, 0)
        self.assertEqual(magic, b"SGVN")
        self.assertEqual(version, 1)
        self.assertEqual(op_count, 7)

        reconstructed = SHMVarnodeBuffer.deserialize_from_shm(buf, "ProductionQueue_getSlot")
        self.assertEqual(reconstructed.function_name, "ProductionQueue_getSlot")
        self.assertEqual(len(reconstructed.ops), 7)
        self.assertEqual(reconstructed.ops[0].opcode, PCodeOpcode.INT_ADD)
        self.assertEqual(reconstructed.ops[1].opcode, PCodeOpcode.LOAD)
        self.assertEqual(reconstructed.ops[6].opcode, PCodeOpcode.LOAD)

    def test_staged_pipeline_transformation_and_dce(self):
        buf = SHMVarnodeBuffer.serialize_to_shm(self.graph)
        deserialized = SHMVarnodeBuffer.deserialize_from_shm(buf, "ProductionQueue_getSlot")
        deserialized.ops[0].inputs[0].symbol_name = "a1"
        deserialized.ops[2].inputs[0].symbol_name = "v4"
        deserialized.ops[-1].output.symbol_name = "result"

        pm = StagedPCodePassManager()
        pm.run_pipeline(deserialized, target_maturity=PCodeMaturity.LVARS)

        self.assertEqual(deserialized.maturity, PCodeMaturity.LVARS)
        self.assertEqual(len(deserialized.ops), 6)  # Op #6 (dead XOR) eliminated
        rendered = deserialized.ops[-1].render_c_like()
        self.assertEqual(rendered, "result = a1->field_18[(v4 & 0x1f)]")

    def test_custom_pass_hook(self):
        custom_hook_called = False

        def my_pass(g: FuncdataGraph) -> None:
            nonlocal custom_hook_called
            custom_hook_called = True
            g.annotations.append("custom_pass_ran")

        pm = StagedPCodePassManager()
        pm.register_pass(PCodeMaturity.PRE_SSA, "custom_test_pass", my_pass)
        pm.run_pipeline(self.graph, target_maturity=PCodeMaturity.PRE_SSA)

        self.assertTrue(custom_hook_called)
        self.assertIn("custom_pass_ran", self.graph.annotations)


class TestGap2SymbolicCFGDeflattener(unittest.TestCase):
    """Tests Gap 2: Symbolic CFG Deflattening, Dominance Analysis & Opaque Predicate Elimination."""

    def setUp(self):
        self.deflattener = SymbolicCFGDeflattener()

    def test_evaluate_opaque_predicate_tautology_and_contradiction(self):
        # Invariant tautology: x*(x+1) is always even
        self.assertIs(self.deflattener.evaluate_opaque_predicate("((x * (x + 1)) % 2) == 0"), True)
        # Contradiction: 2*x is never odd
        self.assertIs(self.deflattener.evaluate_opaque_predicate("((x * 2) % 2) == 1"), False)
        # Invariant bitwise property: (x & ~x) == 0
        self.assertIs(self.deflattener.evaluate_opaque_predicate("(x & (~x & mask)) == 0"), True)
        # Dynamic expression: x > 5 is NOT an invariant (depends on runtime value)
        self.assertIsNone(self.deflattener.evaluate_opaque_predicate("x > 5"))

    def test_eliminate_opaque_predicate_prunes_dead_branch(self):
        cfg = PCodeCFG(
            entry_block=0,
            blocks={
                0: BasicBlock(
                    0, 0x1000,
                    successors=[1, 99],
                    opaque_predicate_expr="((x * (x + 1)) % 2) == 0",
                ),
                1: BasicBlock(1, 0x1010, successors=[]),
                99: BasicBlock(99, 0x1FF0, successors=[]),
            },
        )
        report = self.deflattener.eliminate_opaque_predicates(cfg)
        self.assertEqual(len(report), 1)
        self.assertEqual(report[0]["kept_target"], 1)
        self.assertEqual(report[0]["pruned_dead_target"], 99)
        self.assertEqual(cfg.blocks[0].successors, [1])
        self.assertNotIn(0, cfg.blocks[99].predecessors)

    def test_deflatten_state_machine_full(self):
        cfg = PCodeCFG(
            entry_block=0,
            blocks={
                0: BasicBlock(
                    0, 0x1000,
                    successors=[1, 99],
                    state_assignment=0x1001,
                    opaque_predicate_expr="((x * (x + 1)) % 2) == 0",
                ),
                1: BasicBlock(1, 0x1010, successors=[2, 3, 4]),
                2: BasicBlock(
                    2, 0x1020,
                    successors=[1],
                    state_guard=0x1001,
                    conditional_states=("slot_idx < max_slots", 0x1002, 0x1003),
                ),
                3: BasicBlock(3, 0x1040, successors=[1], state_guard=0x1002, state_assignment=0x1003),
                4: BasicBlock(4, 0x1060, successors=[], state_guard=0x1003),
                99: BasicBlock(99, 0x1FF0, successors=[]),
            },
        )
        report = self.deflattener.deflatten_state_machine(cfg)
        self.assertTrue(report["deflattened"])
        self.assertEqual(report["dispatcher_removed"], 1)
        self.assertEqual(cfg.blocks[0].successors, [2])
        self.assertEqual(cfg.blocks[2].successors, [3, 4])
        self.assertEqual(cfg.blocks[3].successors, [4])

    def test_non_flattened_cfg_handling(self):
        simple_cfg = PCodeCFG(
            entry_block=0,
            blocks={
                0: BasicBlock(0, 0x1000, successors=[1]),
                1: BasicBlock(1, 0x1010, successors=[]),
            },
        )
        report = self.deflattener.deflatten_state_machine(simple_cfg)
        self.assertFalse(report["deflattened"])

    def test_deflatten_affine_state_transformation(self):
        # OLLVM/Promon dispatcher: state = (state * C1 + C2) & MASK
        cfg = PCodeCFG(
            entry_block=0,
            blocks={
                0: BasicBlock(0, 0x1000, successors=[1], state_assignment=0x100),
                1: BasicBlock(1, 0x1010, successors=[2, 3]),
                2: BasicBlock(
                    2, 0x1020,
                    successors=[1],
                    state_guard=0x100,
                    state_transform=(3, 0x54, 0xFFFFFFFF),  # 0x100 * 3 + 0x54 = 0x354
                ),
                3: BasicBlock(3, 0x1040, successors=[], state_guard=0x354),
            },
        )
        report = self.deflattener.deflatten_state_machine(cfg)
        self.assertTrue(report["deflattened"])
        self.assertEqual(cfg.blocks[0].successors, [2])
        self.assertEqual(cfg.blocks[2].successors, [3])

    def test_deflatten_xor_chain_state_transformation(self):
        # XOR chain dispatcher: state = state ^ K1 ^ K2
        cfg = PCodeCFG(
            entry_block=0,
            blocks={
                0: BasicBlock(0, 0x1000, successors=[1], state_assignment=0x200),
                1: BasicBlock(1, 0x1010, successors=[2, 3]),
                2: BasicBlock(
                    2, 0x1020,
                    successors=[1],
                    state_guard=0x200,
                    state_xor_chain=[0x1337, 0xCAFE],  # 0x200 ^ 0x1337 ^ 0xcafe = 0xdbc9
                ),
                3: BasicBlock(3, 0x1040, successors=[], state_guard=0xDBC9),
            },
        )
        report = self.deflattener.deflatten_state_machine(cfg)
        self.assertTrue(report["deflattened"])
        self.assertEqual(cfg.blocks[0].successors, [2])
        self.assertEqual(cfg.blocks[2].successors, [3])

    def test_deflatten_symbolic_formula_state_transformation(self):
        cfg = PCodeCFG(
            entry_block=0,
            blocks={
                0: BasicBlock(0, 0x1000, successors=[1], state_assignment=10),
                1: BasicBlock(1, 0x1010, successors=[2, 3]),
                2: BasicBlock(
                    2, 0x1020,
                    successors=[1],
                    state_guard=10,
                    state_formula="(state * 7 + 13) & mask",  # 10 * 7 + 13 = 83
                ),
                3: BasicBlock(3, 0x1040, successors=[], state_guard=83),
            },
        )
        report = self.deflattener.deflatten_state_machine(cfg)
        self.assertTrue(report["deflattened"])
        self.assertEqual(cfg.blocks[0].successors, [2])
        self.assertEqual(cfg.blocks[2].successors, [3])

    def test_deflatten_multi_condition_dispatcher(self):
        cfg = PCodeCFG(
            entry_block=0,
            blocks={
                0: BasicBlock(0, 0x1000, successors=[1], state_assignment=0x1000),
                1: BasicBlock(1, 0x1010, successors=[2, 3, 4, 5, 6]),
                2: BasicBlock(
                    2, 0x1020,
                    successors=[1],
                    state_guard=0x1000,
                    multi_conditional_states=[
                        ("tag == 1", 0x1001),
                        ("tag == 2", 0x1002),
                        ("tag == 3", 0x1003),
                        ("default", 0x1004),
                    ],
                ),
                3: BasicBlock(3, 0x1030, successors=[], state_guard=0x1001),
                4: BasicBlock(4, 0x1040, successors=[], state_guard=0x1002),
                5: BasicBlock(5, 0x1050, successors=[], state_guard=0x1003),
                6: BasicBlock(6, 0x1060, successors=[], state_guard=0x1004),
            },
        )
        report = self.deflattener.deflatten_state_machine(cfg)
        self.assertTrue(report["deflattened"])
        self.assertEqual(cfg.blocks[0].successors, [2])
        self.assertEqual(cfg.blocks[2].successors, [3, 4, 5, 6])

    def test_deflatten_eliminates_dead_trampoline_basic_blocks(self):
        cfg = PCodeCFG(
            entry_block=0,
            blocks={
                0: BasicBlock(0, 0x1000, successors=[10], state_assignment=0x100),
                10: BasicBlock(10, 0x1008, successors=[1], is_trampoline=True),  # entry trampoline
                1: BasicBlock(1, 0x1010, successors=[2, 3]),                      # switch dispatcher
                2: BasicBlock(
                    2, 0x1020,
                    successors=[20],
                    state_guard=0x100,
                    state_assignment=0x200,
                ),
                20: BasicBlock(20, 0x1028, successors=[1], is_trampoline=True), # return trampoline
                3: BasicBlock(3, 0x1040, successors=[], state_guard=0x200),
            },
        )
        report = self.deflattener.deflatten_state_machine(cfg)
        self.assertTrue(report["deflattened"])
        self.assertEqual(cfg.blocks[0].successors, [2])
        self.assertEqual(cfg.blocks[2].successors, [3])
        # Dead trampolines and dispatcher eliminated
        self.assertNotIn(1, cfg.blocks)
        self.assertNotIn(10, cfg.blocks)
        self.assertNotIn(20, cfg.blocks)
        self.assertIn(10, report["dead_trampolines_removed"])
        self.assertIn(20, report["dead_trampolines_removed"])


class TestGap3UsercallPrototypeCompiler(unittest.TestCase):
    """Tests Gap 3: Declarative __usercall DSL with Vector Integer Spill & .cspec Compilation."""

    def test_arm64_usercall_with_vector_integer_spill(self):
        decl = (
            "LogicCommand* __usercall LogicDeliverTruckOrderCommand::ctor@<x0>("
            "LogicCommand *this@<x0>, int slot_idx@<w1>, uint64_t session_tick@<x21>, "
            "void *caller_context@<x8>, int64_t bulk_mask@<d0>) __spoils<x9, x10>;"
        )
        compiler = UsercallPrototypeCompiler("arm64")
        proto = compiler.parse_usercall(decl)

        self.assertEqual(proto.function_name, "LogicDeliverTruckOrderCommand::ctor")
        self.assertEqual(proto.calling_convention, "__usercall")
        self.assertIsNotNone(proto.return_binding)
        self.assertEqual(proto.return_binding.registers, ["x0"])
        self.assertEqual(len(proto.parameters), 5)

        # Check parameter bindings
        p0, p1, p2, p3, p4 = proto.parameters
        self.assertEqual(p0.name, "this")
        self.assertEqual(p0.registers, ["x0"])
        self.assertEqual(p1.name, "slot_idx")
        self.assertEqual(p1.registers, ["w1"])
        self.assertEqual(p2.name, "session_tick")
        self.assertEqual(p2.registers, ["x21"])
        self.assertEqual(p3.name, "caller_context")
        self.assertEqual(p3.registers, ["x8"])

        # Parameter 4 is int64_t placed into d0 (vector floating-point register) -> vector spill
        self.assertEqual(p4.name, "bulk_mask")
        self.assertEqual(p4.registers, ["d0"])
        self.assertTrue(p4.vector_integer_spill)

        # Check spoils
        self.assertEqual(proto.spoiled_registers, ["x9", "x10"])

        # Check XML and JSON-RPC payload
        self.assertIn("<prototype", proto.cspec_xml)
        self.assertIn('<register name="x0"/>', proto.cspec_xml)
        self.assertIn("<!-- Clang -O3 vector integer spill -->", proto.cspec_xml)
        rpc = proto.ghidra_rpc_payload
        self.assertEqual(rpc["function_name"], "LogicDeliverTruckOrderCommand::ctor")
        self.assertEqual(len(rpc["parameters"]), 5)

    def test_x86_64_usercall(self):
        decl = "int __usercall compute_hash@<eax>(const char *buf@<rdi>, int len@<esi>, int seed@<edx>);"
        compiler = UsercallPrototypeCompiler("x86_64")
        proto = compiler.parse_usercall(decl)

        self.assertEqual(proto.function_name, "compute_hash")
        self.assertEqual(proto.return_binding.registers, ["eax"])
        self.assertEqual(len(proto.parameters), 3)
        self.assertEqual(proto.parameters[0].registers, ["rdi"])
        self.assertEqual(proto.parameters[1].registers, ["esi"])
        self.assertEqual(proto.parameters[2].registers, ["edx"])

    def test_stack_location_parsing(self):
        decl = "void __usercall parse_args(int a@<x0>, int b@<sp+0x10>);"
        compiler = UsercallPrototypeCompiler("arm64")
        proto = compiler.parse_usercall(decl)
        p1 = proto.parameters[1]
        self.assertEqual(p1.storage_space, "stack")
        self.assertEqual(p1.stack_offset, 0x10)

    def test_malformed_syntax_errors(self):
        compiler = UsercallPrototypeCompiler("arm64")
        with self.assertRaises(ValueError):
            compiler.parse_usercall("invalid signature syntax")
        with self.assertRaises(ValueError):
            compiler.parse_usercall("void func(int missing_binding);")


class TestGap4AppcallMarshaller(unittest.TestCase):
    """Tests Gap 4: Target-Agnostic Appcall Marshaller & Struct Mutation Diffing."""

    def setUp(self):
        self.cmd_spec = StructLayoutSpec(
            name="LogicCommand",
            byte_size=24,
            alignment=8,
            fields=[
                StructFieldSpec("vptr", "void*", 0, 8, "ptr"),
                StructFieldSpec("command_type", "int32_t", 8, 4, "<i"),
                StructFieldSpec("slot_idx", "int32_t", 12, 4, "<i"),
                StructFieldSpec("executed_tick", "uint64_t", 16, 8, "<Q"),
            ],
        )
        self.marshaller = AppcallMarshaller({"LogicCommand": self.cmd_spec})

    def test_pack_and_unpack_struct(self):
        values = {"vptr": 0x00E01000, "command_type": 7, "slot_idx": 3, "executed_tick": 123456789}
        packed = self.marshaller.pack_struct(self.cmd_spec, values)
        self.assertEqual(len(packed), 24)

        unpacked = self.marshaller.unpack_struct(self.cmd_spec, packed)
        self.assertEqual(unpacked["vptr"], 0x00E01000)
        self.assertEqual(unpacked["command_type"], 7)
        self.assertEqual(unpacked["slot_idx"], 3)
        self.assertEqual(unpacked["executed_tick"], 123456789)

    def test_prepare_appcall_frame_and_mutation_diff(self):
        frame = self.marshaller.prepare_appcall_frame(
            target_rva=0x00412000,
            args=[
                {"__struct__": "LogicCommand", "vptr": 0x00E01000, "command_type": 7, "slot_idx": 3, "executed_tick": 0},
                42,
            ],
            arg_types=["LogicCommand*", "int"],
        )

        this_ptr = frame.registers["x0"]
        self.assertLess(this_ptr, self.marshaller.SCRATCH_STACK_TOP)
        self.assertEqual(this_ptr % 16, 0)  # SP 16-byte alignment invariant
        self.assertEqual(frame.registers["lr"], self.marshaller.RETURN_TRAP_ADDR)
        self.assertEqual(frame.registers["x1"], 42)

        # Simulate target execution mutating memory
        mutated_bytes = self.marshaller.pack_struct(
            self.cmd_spec,
            {"vptr": 0x00E01000, "command_type": 7, "slot_idx": 99, "executed_tick": 88888888},
        )
        diff = self.marshaller.diff_post_execution(frame, {this_ptr: mutated_bytes})

        self.assertIn("arg_0", diff)
        self.assertEqual(diff["arg_0"]["slot_idx"]["before"], 3)
        self.assertEqual(diff["arg_0"]["slot_idx"]["after"], 99)
        self.assertEqual(diff["arg_0"]["executed_tick"]["before"], 0)
        self.assertEqual(diff["arg_0"]["executed_tick"]["after"], 88888888)
        self.assertNotIn("vptr", diff["arg_0"])  # Unchanged field omitted


_IDA_DIR = os.environ.get("IDA_DIR") or os.environ.get("IDADIR")
_BC31CLS_SIG = os.path.join(_IDA_DIR, "sig", "pc", "bc31cls.sig") if _IDA_DIR else None


class TestGap5CFGSignatureIndex(unittest.TestCase):
    """Tests Gap 5: Dual-Engine PIC-Masked Prologue Hashes & 32-Dim CFG Cosine Index."""

    def test_arm64_pic_masking_invariance(self):
        # Two instructions differing only in ADRP page offsets and BL offsets
        prologue_a = (
            struct.pack("<I", ARM64ADRPScanner.encode_adrp(16, 0x1000, 0x45000))
            + struct.pack("<I", ARM64ADRPScanner.encode_add_imm12(16, 16, 0x80))
            + struct.pack("<I", 0x94000100)  # BL +0x400
        )
        prologue_b = (
            struct.pack("<I", ARM64ADRPScanner.encode_adrp(16, 0x9000, 0xEE000))
            + struct.pack("<I", ARM64ADRPScanner.encode_add_imm12(16, 16, 0x80))
            + struct.pack("<I", 0x94000888)  # BL +0x2220
        )
        hash_a = CFGSignatureIndex.compute_arm64_pic_masked_hash(prologue_a)
        hash_b = CFGSignatureIndex.compute_arm64_pic_masked_hash(prologue_b)
        self.assertEqual(hash_a, hash_b)

    def test_extract_32d_cfg_embedding_and_cosine_query(self):
        sig_index = CFGSignatureIndex()
        vec = CFGSignatureIndex.extract_32d_cfg_embedding(
            block_out_degrees=[2, 2, 1, 0],
            block_in_degrees=[0, 1, 2, 2],
            pcode_opcode_counts={PCodeOpcode.LOAD: 6, PCodeOpcode.STORE: 4, PCodeOpcode.INT_ADD: 8, PCodeOpcode.CBRANCH: 2},
            loop_back_edges=1,
            pointer_stride_constants=[8, 24],
        )
        self.assertEqual(vec.shape, (32,))
        self.assertGreater(np.linalg.norm(vec), 0.0)

        prologue = struct.pack("<I", ARM64ADRPScanner.encode_adrp(8, 0x1000, 0x5000))
        sig_index.index_function("test_func", "libtest.so", "O2", prologue, vec)

        # Query with exact vector and identical PIC prologue
        matches = sig_index.query_function(prologue, vec, top_k=1)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["symbol_name"], "test_func")
        self.assertAlmostEqual(matches[0]["cosine_similarity"], 1.0, places=5)
        self.assertTrue(matches[0]["exact_pic_hash_match"])

    @unittest.skipUnless(_BC31CLS_SIG and os.path.isfile(_BC31CLS_SIG), "bc31cls.sig required (set IDA_DIR)")
    def test_load_flirt_signatures_integration(self):
        sig_index = CFGSignatureIndex()
        count = sig_index.load_flirt_signatures(_BC31CLS_SIG)
        self.assertGreater(count, 50)
        self.assertIsNotNone(sig_index.flirt_index)

        # Match known prologue
        code = bytes.fromhex("558BEC56578B46060B46087514B8080050AABBCCDDEE598956088946060BC274")
        sym = sig_index.match_flirt(code)
        self.assertIsNotNone(sym)
        self.assertIn("VectorImp", sym)


class TestGap6ClangHeaderImporter(unittest.TestCase):
    """Tests Gap 6: C++14/17/20 Header Parser, Virtual Vtables, Bitfields & .sgdb Records."""

    def test_parse_cxx_inheritance_and_alignment(self):
        header = """
        struct BaseEntity {
            virtual void tick();
            uint32_t entity_id;
            uint16_t flags : 4;
            uint16_t team_id : 12;
        };

        class __attribute__((aligned(16))) ProductionBuilding : public BaseEntity {
        public:
            virtual void produce();
            std::vector<void*> queue_slots;
            uint64_t finish_timestamp;
        };
        """
        importer = ClangHeaderImporter()
        types = importer.parse_header(header)

        self.assertIn("BaseEntity", types)
        self.assertIn("ProductionBuilding", types)

        be = types["BaseEntity"]
        self.assertTrue(be.has_vtable)
        self.assertEqual(be.fields[0].name, "__vptr")
        self.assertEqual(be.fields[0].byte_offset, 0)
        self.assertEqual(be.fields[0].byte_size, 8)

        pb = types["ProductionBuilding"]
        self.assertTrue(pb.has_vtable)
        self.assertEqual(pb.alignment, 16)
        self.assertEqual(pb.byte_size % 16, 0)

        # Test .sgdb binary record serialization
        record = pb.to_sgdb_binary_record()
        self.assertGreater(len(record), 32)
        magic, byte_size, alignment, flags, f_count, name_len = struct.unpack_from("<4sIIBBH", record, 0)
        self.assertEqual(magic, b"SGTY")
        self.assertEqual(byte_size, pb.byte_size)
        self.assertEqual(alignment, 16)
        self.assertEqual(flags & 2, 2)  # has_vtable flag
        self.assertEqual(f_count, len(pb.fields))


class TestGap7SGDBBlockStoreAndADRPScanner(unittest.TestCase):
    """Tests Gap 7: High-Density 16 KB SGDB Block Store & Vectorized ARM64 ADRP Scanner."""

    def test_sgdb_block_store_read_write_directory(self):
        store = SGDBBlockStore()
        payload = b"A" * 1024
        entry = store.write_block(42, payload, is_fork_delta=True)

        self.assertEqual(entry.slot_id, 42)
        self.assertTrue(entry.flags & 0x2)  # dirty_fork flag
        self.assertEqual(store.read_block(42), payload)

        dir_bytes = store.serialize_directory()
        self.assertEqual(len(dir_bytes), 20)  # Exactly 20 bytes per slot
        slot_id, offset, c_size, flags = struct.unpack("<QQHH", dir_bytes)
        self.assertEqual(slot_id, 42)
        self.assertEqual(offset, entry.byte_offset)
        self.assertEqual(c_size, entry.compressed_size)
        self.assertEqual(flags, entry.flags)

    def test_sgdb_block_store_size_limit_guard(self):
        store = SGDBBlockStore()
        oversized = b"X" * (16 * 1024 + 1)
        with self.assertRaises(ValueError):
            store.write_block(1, oversized)

    def test_vectorized_adrp_scanner(self):
        stream = bytearray()
        # ADRP X8, target page 0x490000 from 0x401000 + ADD X8, X8, #0x340 -> 0x490340
        stream.extend(struct.pack("<I", ARM64ADRPScanner.encode_adrp(8, 0x401000, 0x490000)))
        stream.extend(struct.pack("<I", ARM64ADRPScanner.encode_add_imm12(8, 8, 0x340)))
        # ADRP X9, target page 0x520000 from 0x401008 + LDR X9, [X9, #0x128] -> 0x520128
        stream.extend(struct.pack("<I", ARM64ADRPScanner.encode_adrp(9, 0x401008, 0x520000)))
        stream.extend(struct.pack("<I", ARM64ADRPScanner.encode_ldr_uimm12_64(9, 9, 0x128)))

        hits = ARM64ADRPScanner.scan_adrp_pairs(bytes(stream), 0x401000)
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0]["target_address"], 0x490340)
        self.assertEqual(hits[0]["kind"], 1)  # ADD
        self.assertEqual(hits[1]["target_address"], 0x520128)
        self.assertEqual(hits[1]["kind"], 2)  # LDR


class TestSection7_3SparseMatrixDatalog(unittest.TestCase):
    """Tests Section 7.3: Sparse Matrix Datalog Engine for Inter-Procedural Whole-Binary Dataflow."""

    def setUp(self):
        self.dlog = SparseMatrixDatalogEngine()
        self.dlog.add_dataflow_edge("JNI_OnLoad:arg_env", "RegisterNatives:table_ptr")
        self.dlog.add_dataflow_edge("RegisterNatives:table_ptr", "native_dispatchCommand:x0")
        self.dlog.add_dataflow_edge("native_dispatchCommand:x0", "CommandParser::parse:this")
        self.dlog.add_dataflow_edge("CommandParser::parse:this", "ProductionQueue::addItem:slot")

    def test_reachability_and_witness_path(self):
        res = self.dlog.query_binary_dataflow("JNI_OnLoad:arg_env", "ProductionQueue::addItem:slot")
        self.assertTrue(res["reachable"])
        self.assertEqual(len(res["witness_path"]), 5)
        self.assertEqual(res["witness_path"][0], "JNI_OnLoad:arg_env")
        self.assertEqual(res["witness_path"][-1], "ProductionQueue::addItem:slot")

    def test_sanitizer_node_blocking(self):
        blocked = self.dlog.query_binary_dataflow(
            "JNI_OnLoad:arg_env",
            "ProductionQueue::addItem:slot",
            additional_sanitizers=["CommandParser::parse:this"],
        )
        self.assertFalse(blocked["reachable"])
        self.assertEqual(blocked["witness_path"], [])

    def test_disconnected_subgraphs(self):
        self.dlog.add_dataflow_edge("IsolatedNodeA", "IsolatedNodeB")
        res = self.dlog.query_binary_dataflow("JNI_OnLoad:arg_env", "IsolatedNodeB")
        self.assertFalse(res["reachable"])


class TestSuperGhidraSection3MCPServer(unittest.TestCase):
    """Tests Unified SuperGhidraSection3MCPServer tool registration and dispatch."""

    def setUp(self):
        self.server = SuperGhidraSection3MCPServer()

    def test_list_tools(self):
        tools = self.server.list_tools()
        self.assertIn("parse_usercall", tools)
        self.assertIn("import_cxx_header", tools)
        self.assertIn("scan_arm64_adrp_xrefs", tools)
        self.assertIn("query_binary_dataflow", tools)

    def test_call_tool_parse_usercall(self):
        decl = "int __usercall foo@<x0>(int a@<x0>, int b@<x1>);"
        res = self.server.call_tool("parse_usercall", {"declaration": decl, "arch": "arm64"})
        self.assertEqual(res["function_name"], "foo")
        self.assertEqual(len(res["parameters"]), 2)

    def test_call_tool_scan_adrp(self):
        stream = bytearray()
        stream.extend(struct.pack("<I", ARM64ADRPScanner.encode_adrp(8, 0x1000, 0x5000)))
        stream.extend(struct.pack("<I", ARM64ADRPScanner.encode_add_imm12(8, 8, 0x100)))
        res = self.server.call_tool("scan_arm64_adrp_xrefs", {"code_hex": stream.hex(), "base_vaddr": 0x1000})
        self.assertEqual(len(res["matches"]), 1)
        self.assertEqual(res["matches"][0]["target_address"], 0x5100)

    def test_call_tool_unknown_raises(self):
        with self.assertRaises(KeyError):
            self.server.call_tool("non_existent_tool", {})


if __name__ == "__main__":
    unittest.main()
