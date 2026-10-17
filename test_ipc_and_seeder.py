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
from pathlib import Path
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
    KIND_BTI,
    KIND_PACIASP,
    KIND_RET,
    KIND_STP_FP_LR,
    KIND_SUB_SP,
    FunctionSeed,
    GPUFunctionSeeder,
    NumPyFunctionSeederEngine,
    pack_seeder_match,
    unpack_seeder_match,
)
from gpu_adrp_scanner import (
    GPUAdrpScanner,
    pack_gpu_match,
    unpack_gpu_match,
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

    def _create_synthetic_elf64(self) -> bytes:
        """Helper to create a valid synthetic 64-bit little-endian ELF binary."""
        text_content = b"\x1f\x20\x03\xd5" * 32  # 128 bytes
        rodata_content = b"SuperGhidra-Synthetic-ELF64\x00" + b"\x00" * 35  # 64 bytes
        data_content = struct.pack("<QQQQ", 0x1122334455667788, 0x99AABBCCDDEEFF00, 0, 0)  # 32 bytes
        shstrtab = b"\x00.text\x00.rodata\x00.data\x00.shstrtab\x00"

        text_offset = 64
        text_size = len(text_content)
        text_vaddr = 0x401000

        rodata_offset = text_offset + text_size
        rodata_size = len(rodata_content)
        rodata_vaddr = 0x402000

        data_offset = rodata_offset + rodata_size
        data_size = len(data_content)
        data_vaddr = 0x403000

        shstrtab_offset = data_offset + data_size
        shstrtab_size = len(shstrtab)

        shdr_offset = (shstrtab_offset + shstrtab_size + 7) & ~7

        shdrs = [
            struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            struct.pack("<IIQQQQIIQQ", 1, 1, 6, text_vaddr, text_offset, text_size, 0, 0, 16, 0),
            struct.pack("<IIQQQQIIQQ", 7, 1, 2, rodata_vaddr, rodata_offset, rodata_size, 0, 0, 8, 0),
            struct.pack("<IIQQQQIIQQ", 15, 1, 3, data_vaddr, data_offset, data_size, 0, 0, 8, 0),
            struct.pack("<IIQQQQIIQQ", 21, 3, 0, 0, shstrtab_offset, shstrtab_size, 0, 0, 1, 0),
        ]
        shdr_bytes = b"".join(shdrs)
        shnum = len(shdrs)
        shstrndx = 4

        e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        ehdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            e_ident,
            2,  # ET_EXEC
            183,  # EM_AARCH64
            1,  # EV_CURRENT
            text_vaddr,  # e_entry
            0,  # e_phoff
            shdr_offset,  # e_shoff
            0,  # e_flags
            64,  # e_ehsize
            0,  # e_phentsize
            0,  # e_phnum
            64,  # e_shentsize
            shnum,  # e_shnum
            shstrndx,  # e_shstrndx
        )

        pad = b"\x00" * (shdr_offset - (shstrtab_offset + shstrtab_size))
        return ehdr + text_content + rodata_content + data_content + shstrtab + pad + shdr_bytes

    def test_from_elf_bytes_synthetic_elf64(self):
        elf_bytes = self._create_synthetic_elf64()
        elf_view = ShmBinaryView.from_elf_bytes(name=None, elf_bytes=elf_bytes)
        try:
            self.assertIn(".text", elf_view.sections)
            self.assertIn(".rodata", elf_view.sections)
            self.assertIn(".data", elf_view.sections)

            # Check .text flags (SEC_READ | SEC_EXEC = 5)
            t_sec = elf_view.sections[".text"]
            self.assertEqual(t_sec.vaddr, 0x401000)
            self.assertTrue(t_sec.is_executable)
            self.assertFalse(t_sec.is_writable)
            self.assertTrue(t_sec.is_readable)

            # Check .rodata flags (SEC_READ = 1)
            r_sec = elf_view.sections[".rodata"]
            self.assertEqual(r_sec.vaddr, 0x402000)
            self.assertFalse(r_sec.is_executable)
            self.assertFalse(r_sec.is_writable)
            self.assertTrue(r_sec.is_readable)

            # Check .data flags (SEC_READ | SEC_WRITE = 3)
            d_sec = elf_view.sections[".data"]
            self.assertEqual(d_sec.vaddr, 0x403000)
            self.assertFalse(d_sec.is_executable)
            self.assertTrue(d_sec.is_writable)
            self.assertTrue(d_sec.is_readable)

            # Verify memory reading
            self.assertEqual(elf_view.read_bytes(0x401000, 4), b"\x1f\x20\x03\xd5")
            self.assertTrue(elf_view.read_bytes(0x402000, 11).startswith(b"SuperGhidra"))
        finally:
            elf_view.close()
            elf_view.unlink()

    def test_from_elf_file_synthetic_elf64(self):
        elf_bytes = self._create_synthetic_elf64()
        with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as tmp:
            tmp.write(elf_bytes)
            tmp_path = tmp.name

        try:
            file_view = ShmBinaryView.from_elf_file(name=None, elf_path=tmp_path)
            try:
                self.assertIn(".text", file_view.sections)
                self.assertIn(".rodata", file_view.sections)
                self.assertIn(".data", file_view.sections)
                self.assertEqual(file_view.sections[".text"].vaddr, 0x401000)
            finally:
                file_view.close()
                file_view.unlink()
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_from_elf_fallback_raw_binary(self):
        raw_bytes = b"\x90\x90\x90\x90" * 32
        fallback_view = ShmBinaryView.from_elf_bytes(name=None, elf_bytes=raw_bytes, default_base_vaddr=0x200000)
        try:
            self.assertIn(".text", fallback_view.sections)
            self.assertEqual(len(fallback_view.sections), 1)
            t_sec = fallback_view.sections[".text"]
            self.assertEqual(t_sec.vaddr, 0x200000)
            self.assertTrue(t_sec.is_executable)
            self.assertEqual(fallback_view.read_bytes(0x200000, 4), b"\x90\x90\x90\x90")
        finally:
            fallback_view.close()
            fallback_view.unlink()


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
        idx_numpy = sorted(res_numpy, key=lambda x: (x & 0x1FFFFFFF))

        # Expected matches: indices 0, 1, 2, 3, 5, 6
        expected_indices = [0, 1, 2, 3, 5, 6]
        matched_indices = [(x & 0x1FFFFFFF) for x in idx_numpy]
        self.assertEqual(matched_indices, expected_indices)

        # Check WGPU if available
    def test_classify_instructions_wgpu(self):
        if not HAS_WGPU:
            self.skipTest("WGPU backend not available on this machine")
        insns = np.array([0xD503233F, 0xA9BF7BFD, 0xD10103FF, 0x94000010, 0xD503201F, 0xD65F03C0, 0xD503245F, 0x52800020], dtype=np.uint32)
        expected_indices = [0, 1, 2, 3, 5, 6]
        seeder_wgpu = GPUFunctionSeeder(backend="wgpu")
        res_wgpu = seeder_wgpu.classify_instructions(insns)
        idx_wgpu = sorted(res_wgpu, key=lambda x: (x & 0x1FFFFFFF))
        self.assertEqual([(x & 0x1FFFFFFF) for x in idx_wgpu], expected_indices)

    def test_classify_instructions_cuda(self):
        if not HAS_CUDA:
            self.skipTest("CUDA backend not available on this machine")
        insns = np.array([0xD503233F, 0xA9BF7BFD, 0xD10103FF, 0x94000010, 0xD503201F, 0xD65F03C0, 0xD503245F, 0x52800020], dtype=np.uint32)
        expected_indices = [0, 1, 2, 3, 5, 6]
        seeder_cuda = GPUFunctionSeeder(backend="cuda")
        res_cuda = seeder_cuda.classify_instructions(insns)
        idx_cuda = sorted(res_cuda, key=lambda x: (x & 0x1FFFFFFF))
        self.assertEqual([(x & 0x1FFFFFFF) for x in idx_cuda], expected_indices)

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


@unittest.skipUnless(
    Path("E:/03_Devops/Ghidra/support/launch.properties").is_file(),
    "Requires local Ghidra installation at E:/03_Devops/Ghidra",
)
class TestGhidraStockInstallationTuning(unittest.TestCase):
    """Unit tests for stock Ghidra installation tuning configs in E:\\03_Devops\\Ghidra\\support\\."""

    def test_launch_properties_tuning(self):
        launch_prop_path = Path("E:/03_Devops/Ghidra/support/launch.properties")
        self.assertTrue(launch_prop_path.is_file(), f"launch.properties not found at {launch_prop_path}")

        content = launch_prop_path.read_text(encoding="utf-8")
        self.assertIn("JAVA_HOME_OVERRIDE=E:/03_Devops/JDK", content)
        self.assertIn("VMARGS=-XX:+UseZGC", content)
        self.assertIn("VMARGS=-XX:+ZGenerational", content)
        self.assertIn("VMARGS=-XX:+UseStringDeduplication", content)
        self.assertIn("VMARGS=-Dapplication.cachedir=E:/03_Devops/Ghidra/.cache", content)
        self.assertIn("VMARGS=-Dapplication.tempdir=E:/03_Devops/Ghidra/.temp", content)
        self.assertIn("VMARGS=-Dsuperghidra.codec.active=true", content)

        # Cache & Temp directories existence
        self.assertTrue(Path("E:/03_Devops/Ghidra/.cache").is_dir(), "E:/03_Devops/Ghidra/.cache does not exist")
        self.assertTrue(Path("E:/03_Devops/Ghidra/.temp").is_dir(), "E:/03_Devops/Ghidra/.temp does not exist")

    def test_analyze_headless_bat_tuning(self):
        headless_bat_path = Path("E:/03_Devops/Ghidra/support/analyzeHeadless.bat")
        self.assertTrue(headless_bat_path.is_file(), f"analyzeHeadless.bat not found at {headless_bat_path}")

        content = headless_bat_path.read_text(encoding="utf-8")
        self.assertIn("set MAXMEM_DEFAULT=8G", content)


class TestGPUAdrpMatchPacking(unittest.TestCase):
    """
    Unit tests for 29-bit instruction index and step mask packing/unpacking
    in gpu_adrp_scanner.py (supporting up to 2.14 GB / 536,870,911 instructions).
    """

    def test_pack_unpack_roundtrip_all_step_masks(self):
        """Verifies lossless round-trip packing/unpacking for all valid step masks."""
        # Valid steps: 1, 2, 3 -> step masks with combinations of (1<<1), (1<<2), (1<<3)
        valid_masks = [
            (1 << 1),                           # 2: step 1 only
            (1 << 2),                           # 4: step 2 only
            (1 << 3),                           # 8: step 3 only
            (1 << 1) | (1 << 2),               # 6: steps 1, 2
            (1 << 1) | (1 << 3),               # 10: steps 1, 3
            (1 << 2) | (1 << 3),               # 12: steps 2, 3
            (1 << 1) | (1 << 2) | (1 << 3),    # 14: steps 1, 2, 3
        ]

        test_indices = [
            0,
            1,
            42,
            1000,
            0x00FFFFFF,     # Old 24-bit boundary limit (16,777,215 instructions = 64 MB)
            0x01500000,     # 22,020,096 instructions = ~88 MB (exceeds old 24-bit limit)
            0x04000000,     # 67,108,864 instructions = 256 MB
            0x10000000,     # 268,435,456 instructions = 1 GB
            0x1FFFFFFF,     # 29-bit max boundary (536,870,911 instructions = 2.14 GB)
        ]

        for idx in test_indices:
            for mask in valid_masks:
                # Test module-level helpers
                packed = pack_gpu_match(idx, mask)
                self.assertIsInstance(packed, int)
                self.assertGreaterEqual(packed, 0)
                self.assertLessEqual(packed, 0xFFFFFFFF)

                unpacked_idx, unpacked_mask = unpack_gpu_match(packed)
                self.assertEqual(
                    unpacked_idx,
                    idx,
                    f"Instruction index {hex(idx)} did not round-trip losslessly! Got {hex(unpacked_idx)}",
                )
                self.assertEqual(
                    unpacked_mask,
                    mask,
                    f"Step mask {bin(mask)} did not round-trip losslessly for idx {hex(idx)}! Got {bin(unpacked_mask)}",
                )

                # Test class staticmethod helpers
                cls_packed = GPUAdrpScanner.pack_gpu_match(idx, mask)
                self.assertEqual(cls_packed, packed)
                cls_idx, cls_mask = GPUAdrpScanner.unpack_gpu_match(packed)
                self.assertEqual(cls_idx, idx)
                self.assertEqual(cls_mask, mask)

    def test_packing_bit_layout(self):
        """Verifies exact bit-level layout: bits 0..28 = instruction index, bits 29..31 = shifted mask."""
        idx = 0x1FFFFFFF
        mask = 0  # no step bits
        packed = pack_gpu_match(idx, mask)
        self.assertEqual(packed, 0x1FFFFFFF)

        # Set step 3 only (mask = 1 << 3 = 8, mask >> 1 = 4, 4 << 29 = 0x80000000)
        packed_step3 = pack_gpu_match(0, 1 << 3)
        self.assertEqual(packed_step3, 0x80000000)

        # Set all steps 1, 2, 3 (mask = 14, mask >> 1 = 7, 7 << 29 = 0xE0000000)
        packed_all = pack_gpu_match(0, (1 << 1) | (1 << 2) | (1 << 3))
        self.assertEqual(packed_all, 0xE0000000)

        # Combined max idx + all steps = 0xFFFFFFFF
        packed_full = pack_gpu_match(0x1FFFFFFF, (1 << 1) | (1 << 2) | (1 << 3))
        self.assertEqual(packed_full, 0xFFFFFFFF)
        unp_idx, unp_mask = unpack_gpu_match(packed_full)
        self.assertEqual(unp_idx, 0x1FFFFFFF)
        self.assertEqual(unp_mask, (1 << 1) | (1 << 2) | (1 << 3))


class TestGPUSeeder29BitPackingAndX86Seeding(unittest.TestCase):
    """
    Unit tests for 29-bit pack_seeder_match/unpack_seeder_match (up to 2.14 GB)
    and x86_64 function seeding (ENDBR64, PUSH rbp; MOV rbp, rsp, SUB rsp, imm8, CALL rel32).
    """

    def test_seeder_29bit_pack_unpack_roundtrip(self):
        """Verifies lossless round-trip packing/unpacking for kinds 1..6 and 29-bit indices."""
        kinds = [KIND_PACIASP, KIND_STP_FP_LR, KIND_SUB_SP, KIND_BL, KIND_RET, KIND_BTI]
        indices = [
            0,
            1,
            128,
            0x0FFFFFFF,  # Old 28-bit max (1.07 GB)
            0x10000000,  # 268,435,456 instructions = 1.07 GB
            0x18000000,  # 1.61 GB
            0x1FFFFFFF,  # 29-bit max (536,870,911 instructions = 2.14 GB)
        ]

        for kind in kinds:
            for idx in indices:
                packed = GPUFunctionSeeder.pack_seeder_match(idx, kind)
                self.assertEqual(packed, pack_seeder_match(idx, kind))
                self.assertGreaterEqual(packed, 0)
                self.assertLessEqual(packed, 0xFFFFFFFF)

                unp_idx, unp_kind = GPUFunctionSeeder.unpack_seeder_match(packed)
                self.assertEqual(unp_idx, idx)
                self.assertEqual(unp_kind, kind)
                self.assertEqual(unpack_seeder_match(packed), (idx, kind))

    def test_seed_x86_64_functions(self):
        """
        Verifies seed_x86_64_functions detects:
          1. ENDBR64 (F3 0F 1E FA) + PUSH rbp; MOV rbp, rsp (55 48 89 E5) at 0x401000
          2. Standalone PUSH rbp; MOV rbp, rsp (55 48 89 E5) at 0x401010
          3. Standalone SUB rsp, 0x28 (48 83 EC 28) at 0x401020
          4. Leaf function at 0x401030 discovered via CALL rel32 (E8) from 0x401040
        """
        base = 0x401000
        buf = bytearray(b"\x90" * 0x60)

        # Func 0 at +0x00 (0x401000): ENDBR64 + PUSH rbp; MOV rbp, rsp + RET
        buf[0x00:0x09] = b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5\xc3"

        # Func 1 at +0x10 (0x401010): PUSH rbp; MOV rbp, rsp + RET
        buf[0x10:0x15] = b"\x55\x48\x89\xe5\xc3"

        # Func 2 at +0x20 (0x401020): SUB rsp, 0x28 + RET
        buf[0x20:0x25] = b"\x48\x83\xec\x28\xc3"

        # Func 3 at +0x30 (0x401030): MOV eax, 1; RET (discovered via CALL rel32)
        buf[0x30:0x36] = b"\xb8\x01\x00\x00\x00\xc3"

        # Caller at +0x40 (0x401040):
        # CALL 0x401000 (rel32 = 0x401000 - (0x401040 + 5) = -0x45)
        buf[0x40:0x45] = b"\xe8" + struct.pack("<i", -0x45)
        # CALL 0x401030 from +0x45 (0x401045): rel32 = 0x401030 - (0x401045 + 5) = -0x1A
        buf[0x45:0x4A] = b"\xe8" + struct.pack("<i", -0x1A)
        buf[0x4A] = 0xC3

        seeder = GPUFunctionSeeder(backend="numpy")
        seeds = seeder.seed_x86_64_functions(bytes(buf), text_base_vaddr=base)
        seed_map = {s.entry_vaddr: s for s in seeds}

        self.assertIn(0x401000, seed_map)
        self.assertIn(0x401010, seed_map)
        self.assertIn(0x401020, seed_map)
        self.assertIn(0x401030, seed_map)

        # Func 0 has both ENDBR64+PUSH_RBP prologue and CALL caller -> confidence 1.0
        self.assertEqual(seed_map[0x401000].confidence, 1.0)
        self.assertIn("prologue_endbr64", seed_map[0x401000].sources)
        self.assertIn("call_target", seed_map[0x401000].sources)

        # Func 3 discovered via CALL rel32
        self.assertIn("call_target", seed_map[0x401030].sources)
        self.assertIn(0x401045, seed_map[0x401030].callers)


if __name__ == "__main__":
    unittest.main()
