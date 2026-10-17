"""
SuperGhidra IPC Bridge & GPU Function Seeder Test Suite (test_ipc_and_seeder.py)

Comprehensive verification for:
1. ShmBinaryView:
   - Creation, section registration, cacheline-aligned memory layout.
   - Zero-copy view / NumPy ndarray mapping.
   - Virtual address translation and bounds checking.
   - Cross-handle attachment, reads, writes, and clean resource cleanup without leaks.
2. ShmRingBuffer & ShmChannel:
   - Lock-free SPSC framing protocol (magic, req_id, msg_type, payload).
   - Buffer wrap-around geometry handling.
   - Multi-producer thread safety.
   - Bidirectional client/server channel query/response pairing.
   - Latency benchmark satisfaction: < 50 us latency for block reads and round-trips.
3. GPUFunctionSeeder:
   - ARM64 instruction classification (PACIASP, STP x29 x30, SUB sp sp, BL, RET, BTI).
   - Equivalence across WGPU, PyTorch CUDA, and NumPy CPU fallbacks.
   - BL target calculation with forward, backward, and sign-extended jumps.
   - Prologue stack displacement and immediate decoding.
   - Vectorized .rodata / .data.rel.ro pointer scanning.
   - Full function seeding pipeline with multi-source confidence scoring.
   - Structured JSON and Ghidra Java batch registration script export.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
from typing import List

import numpy as np

# Ensure SuperGhidra directory is in sys.path
SUPERGHIDRA_DIR = os.path.dirname(os.path.abspath(__file__))
if SUPERGHIDRA_DIR not in sys.path:
    sys.path.insert(0, SUPERGHIDRA_DIR)

from shm_decompiler_bridge import (
    CACHELINE_SIZE,
    RING_MODE_MPMC,
    RING_MODE_SPSC,
    SEC_EXEC,
    SEC_READ,
    SEC_WRITE,
    SectionInfo,
    ShmBinaryView,
    ShmChannel,
    ShmMessage,
    ShmRingBuffer,
    benchmark_shm_bridge,
)
from gpu_function_seeder import (
    HAS_CUDA,
    HAS_WGPU,
    KIND_BL,
    KIND_PACIASP,
    KIND_RET,
    KIND_STP_FP_LR,
    KIND_SUB_SP,
    FunctionSeed,
    GPUFunctionSeeder,
    NumPyFunctionSeederEngine,
)


class TestShmBinaryView(unittest.TestCase):
    """Unit tests for the Shared Memory Binary View."""

    def setUp(self):
        self.base_vaddr = 0x100000000
        # Synthetic sections
        self.text_bytes = bytes([0x1F, 0x20, 0x03, 0xD5] * 256)  # 1024 bytes of NOPs
        self.rodata_bytes = bytes([0xAA, 0xBB, 0xCC, 0xDD] * 128)  # 512 bytes
        self.data_bytes = bytearray([0x00] * 256)  # 256 bytes writable

        self.view = ShmBinaryView.create(
            name=None,
            base_vaddr=self.base_vaddr,
            sections_data={
                ".text": self.text_bytes,
                ".rodata": self.rodata_bytes,
                ".data": self.data_bytes,
            },
        )

    def tearDown(self):
        self.view.close()
        self.view.unlink()

    def test_section_metadata_and_layout(self):
        self.assertIn(".text", self.view.sections)
        self.assertIn(".rodata", self.view.sections)
        self.assertIn(".data", self.view.sections)

        text_sec = self.view.sections[".text"]
        self.assertEqual(text_sec.vaddr, self.base_vaddr)
        self.assertEqual(text_sec.size, len(self.text_bytes))
        self.assertTrue(text_sec.is_executable)
        self.assertFalse(text_sec.is_writable)

        data_sec = self.view.sections[".data"]
        self.assertTrue(data_sec.is_writable)

    def test_address_translation(self):
        # Translate start of .text
        sec = self.view.vaddr_to_section(self.base_vaddr)
        self.assertIsNotNone(sec)
        self.assertEqual(sec.name, ".text")

        # Translate offset within .text
        offset = self.view.vaddr_to_shm_offset(self.base_vaddr + 16)
        self.assertIsNotNone(offset)
        self.assertEqual(offset, sec.shm_offset + 16)

        # Out-of-bounds address
        self.assertIsNone(self.view.vaddr_to_section(0x999999999))

    def test_reads_and_writes(self):
        # Read exact bytes from .text
        chunk = self.view.read_bytes(self.base_vaddr, 8)
        self.assertEqual(chunk, self.text_bytes[:8])

        # Read u32
        u32_val = self.view.read_u32(self.base_vaddr)
        self.assertEqual(u32_val, 0xD503201F)

        # Read zero-copy memoryview
        mv = self.view.read_memoryview(self.base_vaddr, 16)
        self.assertEqual(bytes(mv), self.text_bytes[:16])

        # Write to writable section (.data)
        data_sec = self.view.sections[".data"]
        test_payload = b"SUPERGHIDRA_TEST"
        self.view.write_bytes(data_sec.vaddr + 32, test_payload)
        read_back = self.view.read_bytes(data_sec.vaddr + 32, len(test_payload))
        self.assertEqual(read_back, test_payload)

        # Attempt write to read-only section (.text) -> PermissionError
        with self.assertRaises(PermissionError):
            self.view.write_bytes(self.base_vaddr, b"\x00\x00\x00\x00")

    def test_zero_copy_numpy_view(self):
        np_arr = self.view.get_section_numpy(".text", dtype=np.uint32)
        self.assertEqual(len(np_arr), len(self.text_bytes) // 4)
        self.assertEqual(np_arr[0], 0xD503201F)

    def test_cross_handle_attach(self):
        attached = ShmBinaryView.attach(self.view.name)
        try:
            self.assertEqual(len(attached.sections), len(self.view.sections))
            self.assertEqual(attached.base_vaddr, self.view.base_vaddr)

            # Mutate in creator view and verify reflected in attached view
            data_sec = self.view.sections[".data"]
            self.view.write_bytes(data_sec.vaddr, b"SHARED_MEMORY_SYNC")
            self.assertEqual(attached.read_bytes(data_sec.vaddr, 18), b"SHARED_MEMORY_SYNC")
        finally:
            attached.close()


class TestShmRingBuffer(unittest.TestCase):
    """Unit tests for the lock-free shared memory ring buffer and channel."""

    def test_spsc_ring_buffer_basic(self):
        ring = ShmRingBuffer.create(name=None, capacity=64 * 1024, mode=RING_MODE_SPSC)
        try:
            # Buffer starts empty
            self.assertIsNone(ring.pop_message(timeout=0.0))

            # Push messages
            p1 = b"HELLO_SUPERGHIDRA"
            p2 = b"ARM64_GPU_SEEDER_PAYLOAD"
            success1 = ring.push_message(msg_type=101, req_id=1, payload=p1)
            success2 = ring.push_message(msg_type=102, req_id=2, payload=p2)
            self.assertTrue(success1)
            self.assertTrue(success2)

            # Pop messages in FIFO order
            m1 = ring.pop_message(timeout=0.01)
            self.assertIsNotNone(m1)
            self.assertEqual(m1.msg_type, 101)
            self.assertEqual(m1.req_id, 1)
            self.assertEqual(m1.payload, p1)

            m2 = ring.pop_message(timeout=0.01)
            self.assertIsNotNone(m2)
            self.assertEqual(m2.msg_type, 102)
            self.assertEqual(m2.req_id, 2)
            self.assertEqual(m2.payload, p2)

            # Now empty again
            self.assertIsNone(ring.pop_message(timeout=0.0))
        finally:
            ring.close()
            ring.unlink()

    def test_ring_buffer_wrap_around(self):
        """Pushes more total data than buffer capacity to verify circular wrap-around."""
        capacity = 4096  # Small capacity to trigger wrap-around quickly
        ring = ShmRingBuffer.create(name=None, capacity=capacity, mode=RING_MODE_SPSC)
        try:
            packet_size = 256
            iterations = 100  # Total bytes ~ 25,600 > 4,096 capacity

            for i in range(iterations):
                payload = bytes([(i + j) % 256 for j in range(packet_size)])
                pushed = ring.push_message(msg_type=200, req_id=i, payload=payload, timeout=0.1)
                self.assertTrue(pushed, f"Failed pushing packet {i}")

                # Read immediately
                msg = ring.pop_message(timeout=0.1)
                self.assertIsNotNone(msg)
                self.assertEqual(msg.req_id, i)
                self.assertEqual(msg.payload, payload)
        finally:
            ring.close()
            ring.unlink()

    def test_multithreaded_mpmc(self):
        """Verifies multi-producer concurrent writes in RING_MODE_MPMC."""
        capacity = 256 * 1024
        ring = ShmRingBuffer.create(name=None, capacity=capacity, mode=RING_MODE_MPMC)

        num_threads = 4
        messages_per_thread = 250
        total_expected = num_threads * messages_per_thread

        received_req_ids = []

        def producer_worker(thread_id: int):
            for i in range(messages_per_thread):
                req_id = thread_id * 10000 + i
                payload = f"THREAD_{thread_id}_MSG_{i}".encode("utf-8")
                while not ring.push_message(msg_type=300, req_id=req_id, payload=payload, timeout=0.01):
                    time.sleep(0.0001)

        try:
            threads = [threading.Thread(target=producer_worker, args=(t,)) for t in range(num_threads)]
            for t in threads:
                t.start()

            # Consumer
            start = time.perf_counter()
            while len(received_req_ids) < total_expected and (time.perf_counter() - start) < 5.0:
                msg = ring.pop_message(timeout=0.005)
                if msg is not None:
                    received_req_ids.append(msg.req_id)

            for t in threads:
                t.join(timeout=1.0)

            self.assertEqual(len(received_req_ids), total_expected)
            self.assertEqual(len(set(received_req_ids)), total_expected)
        finally:
            ring.close()
            ring.unlink()

    def test_shm_channel_query_reply(self):
        prefix = f"sg_chan_test_{os.getpid()}"
        client, server = ShmChannel.create_pair(prefix, capacity=64 * 1024)
        try:
            query = b"GET_FUNCTION_INFO:0x100004000"
            req_id = client.send_query(msg_type=1, payload=query)

            # Server receives query
            srv_msg = server.recv_query(timeout=0.1)
            self.assertIsNotNone(srv_msg)
            self.assertEqual(srv_msg.req_id, req_id)
            self.assertEqual(srv_msg.payload, query)

            # Server replies
            reply = b"STATUS:OK_SIZE:0x120"
            server.send_reply(req_id=srv_msg.req_id, msg_type=2, payload=reply)

            # Client receives reply
            cli_reply = client.recv_reply(expected_req_id=req_id, timeout=0.1)
            self.assertIsNotNone(cli_reply)
            self.assertEqual(cli_reply.req_id, req_id)
            self.assertEqual(cli_reply.payload, reply)
        finally:
            client.close()
            server.close()
            client.unlink()

    def test_benchmark_latency_satisfaction(self):
        """Verifies that block read and round-trip latencies satisfy the < 50 us constraint."""
        bench_result = benchmark_shm_bridge(num_read_iterations=3000, num_ipc_iterations=1000)

        # Verify block read stats
        for bsize, stats in bench_result["block_reads"].items():
            self.assertLess(stats["avg_us"], 50.0, f"Block read {bsize} avg latency {stats['avg_us']} us >= 50 us")
            self.assertLess(stats["median_us"], 50.0)

        # Verify round-trip stats
        ipc_stats = bench_result["query_roundtrip"]
        self.assertLess(ipc_stats["avg_us"], 50.0, f"Query roundtrip avg latency {ipc_stats['avg_us']} us >= 50 us")
        self.assertTrue(ipc_stats["target_pass"])


class TestGPUFunctionSeeder(unittest.TestCase):
    """Unit tests for ARM64 instruction classification and function seeding."""

    def test_instruction_decoders(self):
        # 1. BL forward: PC = 0x1000, target = 0x1800 (+0x800 bytes = +512 instructions = imm26: 0x200)
        # BL insn: 0x94000000 | 0x200
        insn_bl_fwd = 0x94000000 | 0x200
        target = GPUFunctionSeeder.decode_bl_target(0x1000, insn_bl_fwd)
        self.assertEqual(target, 0x1800)

        # 2. BL backward: PC = 0x2000, target = 0x1000 (-0x1000 bytes = -1024 instructions)
        # imm26 = (-1024) & 0x03FFFFFF = 0x03FFFC00
        insn_bl_bwd = 0x94000000 | ((-1024) & 0x03FFFFFF)
        target_bwd = GPUFunctionSeeder.decode_bl_target(0x2000, insn_bl_bwd)
        self.assertEqual(target_bwd, 0x1000)

        # 3. STP x29, x30, [sp, #-32]!
        # imm7 for -32 is (-4) & 0x7F = 0x7C
        # insn: 0xA9807BFD | (0x7C << 15) = 0xA9BF7BFD
        insn_stp = 0xA9807BFD | (0x7C << 15)
        offset = GPUFunctionSeeder.decode_stp_stack_offset(insn_stp)
        self.assertEqual(offset, -32)

        # 4. SUB sp, sp, #0x40 (64 bytes)
        # insn: 0xD10003FF | (0x40 << 10) = 0xD10103FF
        insn_sub = 0xD10003FF | (0x40 << 10)
        sub_imm = GPUFunctionSeeder.decode_sub_sp_imm(insn_sub)
        self.assertEqual(sub_imm, 0x40)

    def test_backends_equivalence(self):
        """Verifies that WGPU, CUDA, and NumPy backends produce identical classification results."""
        # Craft a deterministic sequence of instructions
        insns = np.array(
            [
                0xD503233F,  # 0: PACIASP
                0xA9BF7BFD,  # 1: STP x29, x30, [sp, #-32]!
                0xD10103FF,  # 2: SUB sp, sp, #0x40
                0x94000010,  # 3: BL +16
                0xD503201F,  # 4: NOP (unmatched)
                0xD65F03C0,  # 5: RET
                0xD503245F,  # 6: BTI c
                0x52800020,  # 7: MOV w0, #1 (unmatched)
            ],
            dtype=np.uint32,
        )

        res_numpy = NumPyFunctionSeederEngine.scan(insns)
        # Sort by index
        idx_numpy = sorted(res_numpy, key=lambda x: (x & 0x0FFFFFFF))

        # Expected matches: indices 0, 1, 2, 3, 5, 6
        expected_indices = [0, 1, 2, 3, 5, 6]
        matched_indices = [(x & 0x0FFFFFFF) for x in idx_numpy]
        self.assertEqual(matched_indices, expected_indices)

        # Check WGPU if available
        if HAS_WGPU:
            seeder_wgpu = GPUFunctionSeeder(backend="wgpu")
            res_wgpu = seeder_wgpu.classify_instructions(insns)
            idx_wgpu = sorted(res_wgpu, key=lambda x: (x & 0x0FFFFFFF))
            self.assertEqual([(x & 0x0FFFFFFF) for x in idx_wgpu], expected_indices)

        # Check CUDA if available
        if HAS_CUDA:
            seeder_cuda = GPUFunctionSeeder(backend="cuda")
            res_cuda = seeder_cuda.classify_instructions(insns)
            idx_cuda = sorted(res_cuda, key=lambda x: (x & 0x0FFFFFFF))
            self.assertEqual([(x & 0x0FFFFFFF) for x in idx_cuda], expected_indices)

    def test_data_pointer_scanner(self):
        seeder = GPUFunctionSeeder(backend="numpy")
        text_start = 0x100000000
        text_end = 0x100010000
        rodata_base = 0x200000000

        # Construct synthetic rodata with 64-bit values:
        # 1. In-bounds aligned: 0x100002000 (valid)
        # 2. In-bounds misaligned: 0x100002003 (invalid, & 3 != 0)
        # 3. Out-of-bounds low: 0x0FFFFFFF0 (invalid)
        # 4. Out-of-bounds high: 0x200000000 (invalid)
        # 5. In-bounds aligned: 0x100004000 (valid)
        qwords = [
            0x100002000,
            0x100002003,
            0x0FFFFFFF0,
            0x200000000,
            0x100004000,
        ]
        rodata_bytes = struct.pack(f"<{len(qwords)}Q", *qwords)

        matches = seeder.scan_data_pointers(
            rodata_bytes=rodata_bytes,
            rodata_base_vaddr=rodata_base,
            text_vaddr_start=text_start,
            text_vaddr_end=text_end,
        )

        self.assertEqual(len(matches), 2)
        ref1, target1 = matches[0]
        self.assertEqual(ref1, rodata_base + 0)
        self.assertEqual(target1, 0x100002000)

        ref2, target2 = matches[1]
        self.assertEqual(ref2, rodata_base + 32)
        self.assertEqual(target2, 0x100004000)

    def test_end_to_end_seeding_and_export(self):
        text_base = 0x100000000
        rodata_base = 0x200000000

        # Construct synthetic binary with 5 functions:
        # Func 0 at 0x100000000: PACIASP + STP x29, x30, [sp, #-32]! + RET
        # Func 1 at 0x100000020: STP x29, x30, [sp, #-16]! + BL to Func 0 + RET
        # Func 2 at 0x100000040: Leaf function: SUB sp, sp, #32 + RET
        # Func 3 at 0x100000060: Exported via rodata pointer only! NOP + RET
        # Caller at 0x100000080: BL to Func 1 and BL to Func 2

        insns = np.full(64, 0xD503201F, dtype=np.uint32)  # fill with NOPs

        # Func 0 (offset 0 -> 0x100000000)
        insns[0] = 0xD503233F  # PACIASP
        insns[1] = 0xA9BF7BFD  # STP x29, x30, [sp, #-32]!
        insns[2] = 0xD65F03C0  # RET

        # Func 1 (offset 8 -> 0x100000020)
        # STP x29, x30, [sp, #-16]! -> imm7 = -2 & 0x7F = 0x7E
        insns[8] = 0xA9807BFD | (0x7E << 15)
        # BL to Func 0: PC = 0x100000024 (idx 9). Target = 0x100000000. offset = -0x24 bytes = -9 insns
        insns[9] = 0x94000000 | ((-9) & 0x03FFFFFF)
        insns[10] = 0xD65F03C0  # RET

        # Func 2 (offset 16 -> 0x100000040)
        # SUB sp, sp, #32
        insns[16] = 0xD10003FF | (0x20 << 10)
        insns[17] = 0xD65F03C0  # RET

        # Func 3 (offset 24 -> 0x100000060)
        insns[24] = 0xD503201F  # NOP
        insns[25] = 0xD65F03C0  # RET

        # Caller (offset 32 -> 0x100000080)
        # BL to Func 1: PC = 0x100000080 (idx 32). Target = 0x100000020. offset = -0x60 = -24 insns
        insns[32] = 0x94000000 | ((-24) & 0x03FFFFFF)
        # BL to Func 2: PC = 0x100000084 (idx 33). Target = 0x100000040. offset = -0x44 = -17 insns
        insns[33] = 0x94000000 | ((-17) & 0x03FFFFFF)

        # Rodata pointing to Func 3 (0x100000060)
        rodata_bytes = struct.pack("<Q", 0x100000060)

        seeder = GPUFunctionSeeder(backend="auto")
        seeds = seeder.seed_functions(
            text_instructions=insns,
            text_base_vaddr=text_base,
            rodata_bytes=rodata_bytes,
            rodata_base_vaddr=rodata_base,
        )

        discovered_addrs = {s.entry_vaddr for s in seeds}
        self.assertIn(0x100000000, discovered_addrs)  # Func 0
        self.assertIn(0x100000020, discovered_addrs)  # Func 1
        self.assertIn(0x100000040, discovered_addrs)  # Func 2
        self.assertIn(0x100000060, discovered_addrs)  # Func 3

        # Func 0 has both prologue and BL caller -> confidence 1.0
        s0 = next(s for s in seeds if s.entry_vaddr == 0x100000000)
        self.assertEqual(s0.confidence, 1.0)
        self.assertIn("prologue_paciasp", s0.sources)
        self.assertIn("bl_target", s0.sources)

        # Func 3 has source rodata_pointer
        s3 = next(s for s in seeds if s.entry_vaddr == 0x100000060)
        self.assertIn("rodata_pointer", s3.sources)

        # Test JSON Export
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_json:
            json_path = tmp_json.name

        try:
            GPUFunctionSeeder.export_seeds_to_json(
                seeds=seeds,
                filepath=json_path,
                binary_name="libtest.so",
                text_base_vaddr=text_base,
            )
            with open(json_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["total_seeds"], len(seeds))
            self.assertEqual(loaded["binary_name"], "libtest.so")
            self.assertGreater(len(loaded["functions"]), 0)
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)

        # Test Java Script Export
        with tempfile.NamedTemporaryFile(suffix=".java", delete=False) as tmp_java:
            java_path = tmp_java.name

        try:
            GPUFunctionSeeder.export_ghidra_java_script(
                seeds=seeds,
                filepath=java_path,
                script_name="TestRegistrarScript",
            )
            with open(java_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("public class TestRegistrarScript extends GhidraScript", content)
            self.assertIn("0x100000000L", content)
            self.assertIn("startTransaction", content)
            self.assertIn("createFunction", content)
        finally:
            if os.path.exists(java_path):
                os.remove(java_path)


if __name__ == "__main__":
    unittest.main()
